# E2.2 — Journal 崩溃恢复与可靠性实验

## 1. 实验目标

回答一个问题：当 Agent 工具执行链在 INTENT、DISPATCH、SIGNED RECEIPT、JOURNAL RESULT、LOCAL COMMIT 等关键阶段发生**真实进程终止**时，系统能否识别持久化状态、恢复原始 Receipt，是否存在重复 dispatch？

本实验补充 E1.9 现有 W01–W04 **进程内异常注入**之外的证据：Executor 运行在**独立 OS 子进程**，在精确屏障处由父进程**强制杀进程**，再由新进程重试。

## 2. 三个独立持久化域（A/B/C）

| 域 | 实现 | 独立点 |
|---|---|---|
| A Journal Service | `python -m online_budget.journal_service_main --config`，真实 Named Pipe + 独立 journal.sqlite3 / idem.sqlite3 + 真实 Ed25519 签名 | 独立 OS 进程 |
| B Executor Worker | `e2_2_worker.py`，真实 `JournalBackedExecutor.execute_with_journal` + 真实 `ExecutionStore` + `E1CLocalState`（同库，A1） | 独立 OS 子进程、独立 exec-store.sqlite3 |
| C External Effect Counter | 受控工具在真实 dispatch 时写入并提交的独立 `external-effects.sqlite3`（`effects` / `dispatch_events` 两表） | 独立 DB，不与 A/B 共用；Worker 被杀后计数保留 |

**受控工具只记录持久化副作用，不调用真实第三方 API。** 这三域的分离是「副作用是否真的发生」可被独立观测的前提。

## 3. 四个故障场景（F1–F4 是场景编号，不是新门禁）

| 场景 | 强制终止位置 | 屏障确认点（marker.point） |
|---|---|---|
| F1 | INTENT 已持久化，DISPATCH 前 | `F1_AFTER_INTENT_BEFORE_DISPATCH` |
| F2 | DISPATCH 副作用已发生，RESULT 前 | `F2_AFTER_DISPATCH_BEFORE_RESULT` |
| F3 | Journal RESULT 已持久化，本地 COMMIT 前 | `F3_AFTER_RESULT_BEFORE_LOCAL_COMMIT` |
| F4 | 本地 COMMIT 已完成，响应返回前 | `F4_AFTER_LOCAL_COMMIT_BEFORE_RESPONSE` |

屏障由测试专用包装器实现（`BarrierChannel` 包 `Channel.call`、`ControlledGate.before_commit`、Worker main 位于 `execute_with_journal` 返回后）。子进程到屏障即写 marker（含 point/PID），父进程 20 ms 轮询，**确认 marker 后才 kill**（`proc.kill()`，Windows 下为 TerminateProcess，不依赖进程内 handler）。不使用 Python 异常代替真实进程终止。每次记录 worker PID、退出码、屏障确认布尔值。

## 4. 观测指标与数据格式

每轮记录字段见 `results/run-001/trials.csv`：scenario / trial_id / operation_id / worker_pid / worker_exit_code / crash_point_confirmed / journal_intent_count / journal_result_count / execution_store_record_exists / external_effect_count_before_retry / external_effect_count_after_retry / retry_returned / receipt_signature_valid / receipt_identical_to_original / dispatch_count_before_retry / dispatch_count_after_retry / recovery_classification / error_code。

`summary.json` 为分组汇总，`raw.json` 含 meta + 逐条 records + metrics。原始记录不得人工改写。

## 5. 运行环境与复现命令

需要先构建真实 Rust e1_service（本实验的 gate 是测试替身，不调用真四门禁；Rust 全量回归单独执行）。仓库根目录执行（Git Bash）：

```bash
PYTHONPATH="src;tests" .venv/Scripts/python experiments/e2_2_journal_crash_recovery/run_experiment.py --trials 3 --output-dir experiments/e2_2_journal_crash_recovery/results/smoke
PYTHONPATH="src;tests" .venv/Scripts/python experiments/e2_2_journal_crash_recovery/run_experiment.py --trials 10 --output-dir experiments/e2_2_journal_crash_recovery/results/run-001
PYTHONPATH="src;tests" .venv/Scripts/python -m unittest tests.test_e2_2_journal_crash_recovery -v
```

重复执行请换用新的 `--output-dir`（如 `run-002`），不要覆盖已有 run。Windows PowerShell 把 `PYTHONPATH="src;tests"` 换成 `$env:PYTHONPATH = "$(Get-Location)\src;$(Get-Location)\tests"`。

## 6. 统计与结论口径

本实验是受控工程机制实验，**不是统计性安全证明**：

- **N=10 是机制重复验证**，不是形式化证明；每场景独立 operation_id、独立 Journal 服务进程、独立 Worker、独立 Effect DB。
- 必须区分：故障前已持久化的 Journal 状态 / 本地状态 / 已发生的外部副作用 / 重启后的恢复结果 / 是否重复 dispatch。
- **严禁**声称：所有崩溃窗口都能自动恢复；系统具备 G1b；系统具备外部 exactly-once；Journal 单独证明外部工具执行真实性；本实验解决跨存储原子性。
- **E1.9 W01–W04 是进程内异常注入证据；E2.2 新增真实 Executor 进程终止证据。** 两者是不同证据层。
- 受控副作用计数器不等同于真实第三方 API；测试 gate 是驱动真实 ExecutionStore 路径的替身，不是完整四门禁。
- 若某轮无法建立预期故障点，标 `INVALID` 并保留原因，不静默删除补造数据。
