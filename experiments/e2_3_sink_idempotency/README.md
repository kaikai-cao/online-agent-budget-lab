# E2.3 — 工具端幂等与崩溃恢复实验

## 目标

回答 E2.2 留下的问题：当 Executor 因崩溃无法确定第一次工具调用是否已产生副作用时，工具端能否用稳定幂等键 + 原子去重，在允许重试的前提下避免重复副作用。

**严格区分四种性质，不混为 exactly-once：**

| 性质 | 含义 | 本实验观测 |
|---|---|---|
| Dispatch at-most-once | 工具最多调用一次 | `dispatch_events` 行数——E2.3 允许重复 dispatch |
| Effect at-most-once | 同一操作最多一次已提交副作用 | `sink_effects` 行数——V1 要压住的目标 |
| Retry result consistency | 重试返回首次操作对应的结果 | V1 返回 Sink 保存的原始结果；V2 参数冲突被拒 |
| Receipt continuity | 重试能否恢复崩溃前的原始 Executor Receipt | F2 无持久化原件，不声称恢复 |

## 三域隔离架构

- **A Journal Service**：独立 OS 进程，真实 Named Pipe IPC + 独立 journal/idem SQLite + 真 Ed25519 签名。行为与 E1.9 一致。
- **B Executor Worker**：独立子进程，真实 `JournalBackedExecutor` + `ExecutionStore` + `E1CLocalState`（同库满足 A1）。
- **C External Tool Sink**：独立 SQLite，同时保存幂等记录 + 副作用 + 原始结果。本阶段唯一新增核心机制。与 A、B 的数据库分离——幂等记录不放在 Executor 的 `ExecutionStore` 中。

工具只模拟可观察的持久化副作用（写 Sink SQLite），不调用真实第三方 API。

## 幂等键与请求摘要

```
idempotency_key = digest({domain:"e2-3-sink-idempotency-v1", executor_id, operation_id})
request_digest  = digest({domain:"e2-3-sink-request-v1", executor_id, operation_id,
                          tool_name, tool_schema_hash, arguments})
```

- 幂等键**不含 arguments / binding_digest**：否则换参数会产生新 key，绕过去重。
- `request_digest` 由 Sink 按**自身收到的实际参数**用仓库现有 `canonical_json_bytes()` 重算，不盲信调用者摘要；同 key 异参 → `IDEMPOTENCY_KEY_CONFLICT`。
- 键由可信 Executor 侧从 binding 派生，经工具适配器内部元数据传入；不改工具公开参数、不改 D10/D11 Binding、不改 Receipt 格式。

## 原子去重事务（Sink）

```
BEGIN IMMEDIATE
  key 不存在      → 插入 key + 请求摘要 + 副作用 + 原始结果；COMMIT；EXECUTED
  key 存在且摘要相同 → 不产生新副作用；COMMIT；返回原始结果；DEDUP_HIT
  key 存在但摘要不同 → 不产生新副作用；COMMIT；IDEMPOTENCY_KEY_CONFLICT
END
```

幂等记录、副作用、结果在**同一事务提交**——不先提交 key 再调用副作用（那会在工具端重造一个 F2 窗口）。

## 崩溃点（唯一）

`F2_AFTER_DISPATCH_BEFORE_RESULT`，位于 Gate 的 `before_commit` 首行：Receipt 已签名、Journal RESULT 尚未追加、Sink 副作用已提交。父进程确认 marker `{point,pid,ts}` 后 `proc.kill()`（Windows TerminateProcess），记录 PID 与退出码，从不写 release 文件。无异常注入。

## 三组对照（各 N=10）

| 场景 | Sink 行为 | 预期 |
|---|---|---|
| V0 无幂等 | 不做去重，每次 dispatch 都产生副作用 | dispatch 1→2，effect 1→2（复现 E2.2 F2） |
| V1 有幂等 | 同 key 同参重试 | dispatch 1→2，effect 1→1，DEDUP_HIT 10/10 |
| V2 同 key 异参 | retry 传不同 arguments | effect 保持 1，`IDEMPOTENCY_KEY_CONFLICT` |

专项：`并发重复请求`（8 个同 key 同参请求，仅 1 个副作用提交）、`Sink 事务回滚`（key + 副作用一起回滚，之后重试成功）。

## 复现命令（Git Bash）

```bash
# smoke (N=1)
PYTHONPATH="src;tests;experiments/e2_3_sink_idempotency" .venv/Scripts/python \
  experiments/e2_3_sink_idempotency/run_experiment.py --trials 1 \
  --output-dir experiments/e2_3_sink_idempotency/results/smoke

# 正式 (N=10)
PYTHONPATH="src;tests;experiments/e2_3_sink_idempotency" .venv/Scripts/python \
  experiments/e2_3_sink_idempotency/run_experiment.py --trials 10 \
  --output-dir experiments/e2_3_sink_idempotency/results/run-001

# 专项测试
PYTHONPATH="src;tests" .venv/Scripts/python -m unittest tests.test_e2_3_tool_idempotency -v
```

重复执行请用新的 `--output-dir`，不覆盖已有 run。无法建立预期故障点的轮次标 `INVALID` 并保留原因，不静默删除补造。

## 输出

`results/run-001/{trials.csv, summary.json, raw.json}`。每轮字段含：variant / trial_id / operation_id / worker_pid / worker_exit_code / crash_point_confirmed / 三方状态 / dispatch 与 effect 前后计数 / sink_outcomes / Receipt 签名·绑定·结果一致性 / recovery_classification / error_code。

## 边界与局限

- **Receipt 连续性**：F2 崩溃时 Receipt 只在 Worker 内存、未写 Journal/ExecutionStore，强杀后丢失。即使 V1 压住重复副作用，重试 Executor 仍为「Sink 返回的原始结果」重新签发一份**新** Receipt。验证其签名有效、绑定正确 operation_id/binding_digest、result 与 Sink 原始结果一致；**不声称**首次 Receipt 被恢复或字节级连续。
- N=10 是机制重复验证，非形式化或统计性安全证明；受控 Sink ≠ 真实第三方 API。
- 不声称：所有窗口自动恢复、G1b、外部 exactly-once、Journal 单独证明执行真实性、已解决跨存储原子性。
- 幂等键作用域 = 本实验域标签；真实部署须逐服务核对供应商幂等范围与保留期限（如 AWS EC2 区分 Regional / Zonal）。
- 本实验自包含于 E2.3 目录，不依赖 E2.1/E2.2 分支；生产代码、E0/E1.8/E1.9 冻结文档、E2.1/E2.2 数据零改动。
