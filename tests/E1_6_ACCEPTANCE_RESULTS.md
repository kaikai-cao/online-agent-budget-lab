# E1.6 系统级端到端验收结果记录

- 基线：`ecba8ecd93069620b61142243155698d8d24a7a1`（E1.5 二轮回修，已冻结）
- 日期：2026-11-17
- 范围：只新增 `tests/test_e1_system.py`（本记录同为新增文件）。**未修改任何生产代码、协议文档、摘要/签名/计量规则或 Rust crate。** Rust 侧复核后确认现有 `tests/e1.rs`（l01 线程竞争、s01/s02 作用域冲突、c01–c03 事务崩溃/回滚、i01–i03 幂等）与 `tests/concurrency.rs`（c14/c15）已覆盖计划 §F.6 要求的 Rust 并发/隔离/崩溃场景，故不复制测试；进程级 kill/恢复缺口由 Python 系统测试以真实 `e1_service` 子进程补齐。

## 1. 先审计、后补缺口（不重复实现）

已有覆盖直接复用，未重写：E1.4 的 Bridge EOF/超时/重启 gate、`STATE_CONFLICT`/`STORE_ERROR` 幂等查询（`test_cross_layer_bridge.py`、`test_e1_runtime.py`）；E1.5 的 19 项单项凭据篡改与一次性 capability（`test_e1_execution.py`）；Rust 层的真实 Halo2 prove/verify、CAS 回滚、重启后原回执恢复（`tests/e1.rs`、`tests/e1_service.rs`）。

E1.6 新增的系统级缺口：

| 维度 | 新增测试 | 系统级观测方式 |
| --- | --- | --- |
| A 完整成功 | `test_s01_full_chain_success_single_dispatch_and_single_charge` | 真 D10 HTTP + 真 Rust Halo2 + E1.5 Executor + 真 dispatch；直接读 SQLite |
| B 工具失败 | `test_s02_tool_failure_persists_failed_v2_receipt_without_replay` | 确定性工具 dispatch 后抛异常，留存签名 FAILED v2 回执 |
| C 准入前失败 | `test_s03_failure_before_d10_admission_charges_nothing` | 坏策略签名→两侧 DB 均 0 计数 |
| C D11 未提交 | `test_s04_process_kill_before_d11_commit_recovers_with_original_credentials` | **真 kill e1_service 子进程**，重启+原 Attestation/`D_E` 重证重提 |
| C 已提交未响应 | `test_s05_process_kill_after_d11_commit_restores_exact_stored_receipt` | **真 kill after commit**，`get_operation` 原样恢复回执 |
| C Attestation 过期 | `test_s06_expired_original_attestation_after_kill_fails_closed` | 恢复时时钟越界，断言不重签、单边扣费、失败关闭 |
| C 门禁失败 | `test_s07_final_gate_failure_never_dispatches_or_seals_receipt` | D11 签名篡改后 dispatch=0、无执行回执落库 |
| D 并发竞争 | `test_s08_two_threads_same_c_old_exactly_one_state_transition` | 两线程+真服务同 `C_old`，DB 版本/nullifier/操作行数恰为 1 |
| D 幂等/冲突/隔离 | `s09`/`s10`/`s11`/`s12` | 相同请求原回执、不同摘要 `IDEMPOTENCY_CONFLICT`、作用域 `SCOPE_CONFLICT`、跨 `period_id` 互不影响 |
| E 凭据篡改 | `test_s13_full_chain_credential_mismatches_never_dispatch` | 完整链路 5 类字段错配全部 `dispatch_count==0` |

## 2. 端到端成功与失败的实测结果

所有 13 项系统测试通过（`Ran 13 tests ... OK`）。关键断言结果：

- **成功路径**：工具 dispatch 恰好 1 次；D10 `global_used_count=1`、`operations=1`、`lease.used_count=1`；D11 `current_version=1`、`used_nullifiers=1`、`budget_operations=1`，`new_commitment` 与回执一致；Execution Receipt `receipt_version=2`、`status=SUCCEEDED`、`budget_receipt_digest == BudgetReceipt.receipt_digest`、`executor_authorization_digest` 与授权一致；prove witness `u_new-u_old=c=20`（加权消费，非 D10 的操作次数）。
- **工具失败路径**：dispatch 进入 1 次后抛异常，生成可验签的 `status=FAILED` v2 回执（`result_digest` 与 `result` 重算一致）；D10 已扣 1 次、D11 版本=1，均不退款；重复 `execute_e1` 返回逐字节相同回执、dispatch 仍为 1。区分了「工具执行失败」与「预算提交失败」。
- **重启/Saga**：
  - 准入前坏策略：D10/D11 计数全 0，无 dispatch。
  - kill-before-commit：D10 已扣 1 次，服务重启后 `get_operation` 未命中→用原 Attestation/`D_E`/operation 重证重提，D11 版本=1、nullifier=1；两次提交的 Attestation 与 quote digest 逐字节相同；随后门禁放行且 dispatch 1 次。
  - kill-after-commit：D11 已提交但响应丢失，`get_operation` 恢复的回执与留存 receipt 完全一致，D10 仍仅 1 次扣费；无二次状态推进。
  - Attestation 过期：恢复时不重签（签发计数=1），D10 已扣 1 次、D11 版本=0，失败关闭、无 dispatch。
  - D11 签名篡改：门禁拒绝、无 Execution Receipt 落库、D11 原回执不受影响。
- **并发/隔离**：两线程同 `C_old`，恰一成功一失败；DB 版本=1/nullifier=1/操作行=1；两笔 D10 操作均已计费（Saga 不退款），胜者 dispatch 1 次。幂等重提返回相同回执；不同摘要返回 `IDEMPOTENCY_CONFLICT`；同 scope 不同 budget 返回 `SCOPE_CONFLICT` 且无部分写入；不同 `period_id` 两条实例各自版本=1、承诺互异、D10 共 2 次计费。
- **凭据篡改**：Attestation 字段、D10 `request_digest≠D_E`、D11 签名、operation_id 错配、可信公钥表不匹配 5 类全部 `ToolExecutionDenied` 且 dispatch=0、无执行回执。

## 3. 全量回归

| 命令 | 结果 |
| --- | --- |
| `python -m unittest discover -s tests -p "test_e1_system.py" -v`（`PYTHONPATH=src .venv/Scripts/python`） | 13/13 OK（208s） |
| `python -m unittest discover -s tests -v` | **191/191 OK**（400s；原有 178 + 新增 13） |
| `cargo test --manifest-path experiments/d11_3_c_coordinator/Cargo.toml --all-targets` | 各 target `test result: ok`，合计 **62** 用例 |
| `cargo build --manifest-path experiments/d11_3_c_coordinator/Cargo.toml --bin e1_service` | Finished（仅增量锁文件 benign warning） |
| `cargo fmt --manifest-path experiments/d11_3_c_coordinator/Cargo.toml -- --check` | 通过 |
| `git diff --check` | 通过（无尾随空格/冲突标记） |

> Python 测试运行期间出现来自既有 `coordinator.py`/`adapter.py` 的 `ResourceWarning: unclosed database`（SQLite 连接在 HTTP 线程中的历史行为），不影响测试结果；E1.6 未改生产代码，故不在本阶段处理。

## 4. 关键问题回答

> 当 D10 已扣费、D11 状态可能已提交、Rust 服务可能崩溃、Executor 可能重启时，系统是否仍能保证：没有两份回执和最终绑定验证就绝不执行工具；同一操作不会被重复计费或重复执行？

**在本次验收覆盖的确定性本地工具与真实进程故障条件下：是。** 证据：`s04`/`s05` 证明 D11 提交前后进程被真杀后，恢复只沿「原凭据 + `get_operation` 原回执」路径推进，不重新计费、不伪造回执；`s01`/`s07`/`s13` 证明 Executor 只有在同时通过 D10 Budget Receipt（`request_digest==D_E`）与 D11 Transition Receipt（独立验签+字段比对）后才 dispatch，否则 dispatch=0；`s02` 证明工具失败后重试不二次执行；`s08`/`s09`/`s10` 证明同一操作在状态层幂等且冲突被拒。

边界（不得越界表述）：这是**系统行为验收记录，不是形式化安全证明**；`c` 是 Issuer 签名策略下的加权费用，不证明真实物理资源消耗；D10 与 D11 是不同 SQLite 库、无跨库原子事务，Saga 语义为「D10 已准入即计费、不退款、失败关闭」；确定性本地工具的结果不能外推为任意外部 API 的安全保证。
