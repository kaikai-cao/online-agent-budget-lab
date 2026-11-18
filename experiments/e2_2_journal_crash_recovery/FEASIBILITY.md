# E2.2 可行性核查记录（feasibility note）

> 本记录在写实验代码前形成，基于对 E1.9 冻结实现与现有恢复测试的只读核查。基线 `467fa24`。
> 目的：确认 F1–F4 四个故障点能否在**完全不改生产代码**的前提下，用「测试专用包装器 + 真实子进程强制终止」实现。

## 1. 已核查文件
`journal_backed_executor.py`、`execution_store.py`、`journal_client.py`、`journal_service.py`、`journal_ipc.py`、`journal_service_main.py`、`journal_service_config.py`、`_e1b_helpers.py`、`test_e1_9_c_integration.py`（含 W01–W04 与 P01 真进程）、`test_e1_9_b_service_process.py`、`process_crash_consume_worker.py`、`E1.9_FINAL_ACCEPTANCE.md`。

## 2. 现有 W01–W04 的性质（不足以满足 E2.2）
`test_e1_9_c_integration.py` 的 W01–W04 用 `_StubGateExecutor` 的布尔标志在**测试进程内**抛 `RuntimeError` 模拟崩溃：
- W01 `fail_gate`（`journal_backed_executor.py:99-100` 对应位置）：INTENT 前拒绝；
- W02 `crash_after_dispatch_before_result`（`:115-117` before_commit 抛错）；
- W03 `crash_after_result_before_local`（`:120-121` RESULT 后本地 INSERT 前抛错）；
- W04 本地提交相关。

这些是**进程内异常注入，不是真实进程终止**，SQLite 事务由 Python `with` 正常回滚，不经过 OS 杀进程与连接重建。E2.2 的增量证据必须是跨进程 kill。

## 3. 真实进程边界（可实现）
- Journal Service：`python -m online_budget.journal_service_main --config <cfg>`（前台阻塞，`journal_service_main.py:123-130`）。配置由 `_e1b_helpers.make_config` 生成；同账户多进程用 `allowed_sid=current_process_identity().sid` + `os_identity=account` 即可连，无需管理员 ACL。就绪用 `NamedPipeClient(pipe, connect_retries=200).call("verify_integrity")`。
- Executor Worker：仓库现成范式 `process_crash_consume_worker.py` + `test_online_coordinator_adversarial.py:310-375` 的 marker/release 文件屏障：子进程写 marker 确认到达屏障并轮询 release；父进程 20 ms 轮询 marker，看到后 `proc.terminate()/kill()`（Windows terminate 即 TerminateProcess 硬杀，**不依赖进程内 handler**）。父超时 20 s < 子 60 s。
- 全仓库**无**进程内 Executor 的真进程测试；E2.2 是首次组合，属新增证据而非重跑。

## 4. 四个故障点的最小注入方案（均不改生产代码）
`JournalBackedExecutor` 的 executor/client/store/state/public_key 全部构造注入（`journal_backed_executor.py:331-332`），`JournalClient` 的 channel 是单方法 Protocol（`journal_client.py:30-31`），registry 可注入（`executor.py:125,153`）。据此：

| 场景 | 精确窗口（源码位置） | 测试专用注入点（包装器，不改生产顺序） |
|---|---|---|
| F1 INTENT 后/DISPATCH 前 | `:509-514` append_intent 返回后 → `execution_store.py:117` dispatch 前 | 包装 `Channel.call`：在 `append_intent` 返回后、进入 `execute_e1` 前写 marker + 等待；**或**包装 executor.execute_e1 入口 |
| F2 DISPATCH 后/RESULT 前 | `execution_store.py:117` dispatch 返回后 → `:128-129` before_commit(RESULT) 前 | 受控工具的 `dispatch()` 写独立 Effect DB 并 commit 后写 marker + 等待；再用 before_store_commit 包装确认 RESULT 未写 |
| F3 RESULT 后/本地 COMMIT 前 | `journal.py:332` RESULT 落盘 → `execution_store.py:74` commit 前 | 包装 Channel：在 `append_result` 返回后（RESULT 已持久化）写 marker + 等待；本地 INSERT/put_status/set_sync 尚未 commit |
| F4 本地 COMMIT 后/响应前 | `execution_store.py:74` commit → `journal_backed_executor.py:545` return 前 | 包装 store.write_transaction 退出后写 marker + 等待，再向父进程返回结果 |

屏障统一用文件 marker/release（跨进程可靠，`threading.Event` 不可用）。子到屏障确认 = 写含点位的 marker 文件；父进程 kill 前记录 marker 内容，证明 kill 位于指定阶段而非随机时刻。

## 5. 三个持久化域（相互隔离）
- A Journal：独立进程 + 独立 journal.sqlite3 / idem.sqlite3 + 真实签名（现有机制）。
- B Executor Worker：独立进程 + 独立 ExecutionStore SQLite（同库含 E1CLocalState，满足 `:339-345` 的 A1_DB_MISMATCH 校验）。
- C External Effect Counter：单独 SQLite，由受控工具在真实 dispatch 时写并提交；**不与 A/B 共用 DB**，进程被杀后计数保留。

## 6. gate executor 的选择
`JournalBackedExecutor` 无生产装配点。复用 `test_e1_9_c_integration.py::_StubGateExecutor` 的模式（真实 ExecutionStore + 真实 Receipt v2 签名 + 计数 dispatch），把它的 `do_dispatch()` 改为向独立 Effect DB 写一条副作用并提交。这仍是「真实 JournalBackedExecutor 编排 + 真实 ExecutionStore 事务 + 真实 Journal IPC + 真实签名」，只有四门禁工具体本身是受控替身（与 W01–W04 同口径），报告如实说明。受控工具只记录持久化效果，不调用真实第三方 API。

## 7. 结论
**四个故障点均可在不修改 `src/online_budget/` 任何生产代码、不改 E0/E1.8/E1.9 冻结设计、不改 D10/D11、不改 E1.9 既有测试、不改 E2.1 的前提下实现。** 采用「测试包装器 + 文件屏障 + 真实子进程 kill + 独立 Effect DB」。无需最小生产改造；若实现中发现某屏障无法可靠建立，将标该场景 INVALID 并保留原因，不用异常注入冒充真实进程终止。
