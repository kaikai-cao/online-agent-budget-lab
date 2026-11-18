# E2.3 可行性记录（工具端幂等与崩溃恢复）

基线：`main = 467fa249c2c7f6971dd9f217ce0827e6f7bfc995`。本分支 `exp/e2.3-sink-idempotency` 从该提交创建，不含 E2.1/E2.2 内容。

## 1. 要验证的核心命题

E2.2 已证明：真实 Worker 进程在「副作用已提交、Journal RESULT 未写入」的 F2 窗口被强杀后，重试会再次 dispatch，产生第二次副作用。E2.3 用受控工具端幂等（Sink）回答：当 Executor 无法确定首次调用是否已产生副作用时，工具端能否用稳定幂等键 + 原子去重，在允许重试的前提下阻止第二次副作用。

严格区分四种性质，不混为 exactly-once：

| 性质 | 本实验如何观测 |
|---|---|
| Dispatch at-most-once | Sink 的 `dispatch_events` 行数（工具被调用次数）——E2.3 允许再次 dispatch |
| Effect at-most-once | Sink 的 `sink_effects` 行数（真正提交的副作用次数）——这是 V1 要压住的目标 |
| Retry result consistency | 重试返回值是否与首次保存的结果一致（V2 用参数冲突单独验证不一致被拒） |
| Receipt continuity | 重试 Executor Receipt 是否等于崩溃前原件——F2 无持久化原件，不声称 |

## 2. 幂等键与请求摘要（基于现有 API，不另造规范）

仓库现有原语（`src/online_budget/canonical.py`）：
- `canonical_json_bytes(value)`：`sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False` → UTF-8。
- `digest(value)` → `"sha256:" + hex`，满足 `is_sha256` 格式。
- `arguments_digest(args)`（`tool_binding.py:67`）：`digest({"domain": "agent-tool-arguments-v1", "canonicalization_version": ..., "arguments": snapshot})`。

E2.3 的派生（实验专用域标签，不进生产、不改冻结格式）：

```
idempotency_key = digest({
    "domain": "e2-3-sink-idempotency-v1",
    "executor_id": binding.executor_id,
    "operation_id": binding.operation_id,
})
request_digest = digest({
    "domain": "e2-3-sink-request-v1",
    "executor_id": executor_id,
    "operation_id": operation_id,
    "tool_name": tool_name,
    "tool_schema_hash": tool_schema_hash,
    "arguments": <canonical snapshot of ACTUAL arguments>,
})
```

关键约束：
- **幂等键不含 arguments / binding_digest**——否则同一 operation 换参数会得到新键，绕过去重。
- **request_digest 由 Sink 按自身收到的实际参数重算**——不盲信调用者传来的摘要。这样「同 key 不同参数」（V2）能被检出并返回 `IDEMPOTENCY_KEY_CONFLICT`。
- 二者都用 `digest()` + `canonical_json_bytes()`，与 E1.5 binding 链、Receipt v2 字段共用同一规范化语义，无新增不兼容 JSON 规范。

## 3. 工具端原子去重（唯一新增核心机制）

External Tool Sink = 独立 SQLite（与 Journal DB、ExecutionStore DB 三者分离），单表 `sink_records(idem_key PK, request_digest, result_json, effect_json, created_at)`。

```
BEGIN IMMEDIATE
  row = SELECT by idem_key
  if row is None:
      INSERT idem_key + request_digest + 副作用 + 原始结果
      COMMIT                      # 幂等记录/副作用/结果 同事务提交
      return EXECUTED
  elif row.request_digest == request_digest:
      COMMIT                      # 不产生新副作用
      return DEDUP_HIT            # 读取并返回首次保存的原始结果
  else:
      COMMIT                      # 不产生新副作用
      return IDEMPOTENCY_KEY_CONFLICT
```

禁止把幂等记录与副作用分开提交——否则在工具端重新制造一个 F2 窗口。事务中途回滚测试验证两者一起回滚、之后重试可正常完成。

## 4. 崩溃与进程边界（复用 E2.2 范式，E2.3 目录内自包含重写）

沿用 E2.2 已验证的机制，不在 E2.3 import E2.2 模块：
- A Journal Service：独立 OS 进程，`python -m online_budget.journal_service_main`，Named Pipe，真签名；就绪探测 `verify_integrity()`。
- B Executor Worker：独立子进程，真 `JournalBackedExecutor` + `ExecutionStore` + `E1CLocalState`（同库满足 A1）。
- C External Tool Sink：独立 SQLite，受控副作用，硬杀后计数保留。
- 屏障：`_barrier` 写 marker `{point,pid,ts}`；父进程 20ms 轮询确认后 `proc.kill()`（TerminateProcess），记录 PID/退出码，从不写 release。
- 唯一崩溃点：`F2_AFTER_DISPATCH_BEFORE_RESULT`，位于 `ControlledSinkGate.before_commit` 首行，`before_store_commit`（真 RESULT append）之前。此时 Receipt 已签名、Journal RESULT 未写、Sink 副作用已提交。

## 5. V0 / V1 / V2 与专项

| 场景 | Sink 行为 | 预期 |
|---|---|---|
| V0 无幂等 | Sink 不做去重，每次 dispatch 都产生副作用（复现 E2.2 F2） | dispatch 1→2，effect 1→2 |
| V1 有幂等 | 同 key 同参重试 | dispatch 1→2，effect 1→1，dedup 命中 10/10 |
| V2 同 key 异参 | retry 传不同 arguments，key 不变 | 返回 IDEMPOTENCY_KEY_CONFLICT，effect 保持 1 |

专项：并发重复请求（多个请求同 key 同参，仅一个副作用提交）；Sink 事务中途回滚（幂等记录与副作用一起回滚，重试可完成）。

## 6. Receipt 连续性边界（必须保留）

F2 崩溃时 Receipt 只在 Worker 内存、未写 Journal/ExecutionStore，强杀后丢失。即使 V1 压住了重复副作用，重试 Executor 仍会为「Sink 返回的原始结果」生成一份**新的** Receipt：
- 必须验证：新 Receipt 签名有效、绑定正确 `operation_id`/`binding_digest`、result 与 Sink 保存的原始结果一致。
- 不得声称：首次 Receipt 被恢复、Receipt 字节级连续、外部 exactly-once、G1b、跨存储原子性、Journal 单独证明执行真实性。

## 7. 自包含性与改动边界

- `_e1b_helpers`（receipt_v2/make_binding_payload/make_config 等）是 `tests/` 下的 main 基线辅助，E2.3 从 `tests/` 取用，不依赖 E2.2 分支。E2.2 的进程范式在 E2.3 目录内重写。
- 零改：`src/online_budget/*`、D10/D11、Halo2、Receipt 格式、E0/E1.9 冻结文档、E2.1/E2.2 数据与报告。
- 受控 Sink ≠ 真实第三方 API；N=10 是机制重复验证，非形式化/统计性安全证明。
