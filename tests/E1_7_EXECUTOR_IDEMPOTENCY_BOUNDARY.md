# E1.7 Executor 执行幂等边界与状态回滚 — 实验结果记录

阶段：E1.7（E1.6 冻结后，设计与攻击面核查）
基线提交：`02b26ef`（E1.6 已公开）
性质：**攻击面验证实验，不是修复，不是协议变更，不是形式化安全证明。**

## 1. 研究问题与范围

在 E1.5 四道凭据门禁保持不变的前提下，Executor 的**本地持久化状态**是否足以支撑跨实例、重启和数据库恢复场景下的执行防重放？

本轮只做三组实验，不改任何生产代码：

- 不修改 `executor.py` / `execution_store.py`；
- 不修改 E0/E1.0 冻结协议与设计文档；
- 不修改 E1.1–E1.6 已冻结测试；
- 不修改 Rust Halo2 电路与 Coordinator；
- 密钥轮换按计划不纳入本阶段。

测试文件：`tests/test_e1_executor_state_scope.py`。它复用 E1.6 的 `_SystemHarness` 产出**真链路签发的 `PendingExecution`**（真 D10 Coordinator + 真 Rust `e1_service` + 真 Halo2 证明 + D10 准入 + D11 状态提交），只在最终 dispatch 阶段切换为两个受控 Executor 实例。

## 2. 被测代码事实（只读审查结论）

| 事实 | 位置 |
| --- | --- |
| 四道门禁全过后才进入 dispatch | `executor.py::execute_e1` → `_dispatch_and_seal` |
| dispatch 实际调用 `self.registry.dispatch(...)` | `executor.py::_dispatch_and_seal` 的 `execute` 回调 |
| 去重仅靠单库 `operation_id` 主键 + `BEGIN IMMEDIATE` 事务 | `execution_store.py::execute_once` |
| 每个 Executor 实例自建 `ExecutionStore(database_path)` | `executor.py::__init__` |
| 无跨 Executor 共享的执行去重状态；无外部单调锚点 | 同上（代码内不存在该结构） |
| 回执签名验证只验证自身合法性 + 期望字段，不查询执行历史 | `execution_receipts.py::verify_execution_receipt` |

这确认了冻结审查的判断：E1.5 门禁回答“本次调用是否获授权”，**不构成全局一次性执行机制**；D11 防止预算状态重复消费，不等于 Executor 防止工具调用重复执行。

## 3. 三组实验的实测结果

所有 dispatch 次数均由计数 registry（`_CountingRegistry.dispatch_count`）实测，并由 `executions` 表行数与回执验签双重确认；并发用 `threading.Barrier` 同步起跑。

### T01 共享数据库双实例 — 通过（单次 dispatch）

- 前提：两实例相同 `executor_id`、相同私钥、**相同 SQLite 文件**，并发处理同一 `PendingExecution`。
- **实测：`reg_a.dispatch_count + reg_b.dispatch_count == 1`**；两实例各自看到的 `executions` 行数均为 1。
- 两份回执规范化字节完全相同，`status=SUCCEEDED`、`receipt_version=2`、`budget_receipt_digest` 与 D10 回执一致，且都能被各自 Executor 验签通过。
- 结论：共享库场景下，`BEGIN IMMEDIATE` 把“查重 + dispatch + 落库 + 回执”包进同一事务，串行化后仅一个实例真正 dispatch。这是 **SQLite 事务属性**，不是 Executor 层面的全局保证。

### T02 独立数据库双实例 — 通过（实测两次 dispatch）

- 前提：两实例相同身份与私钥、**不同 SQLite 文件**，并发处理同一 `PendingExecution`。
- **实测：两实例各 dispatch 1 次，合计 2 次**；每个库各 1 行执行记录。
- 两份回执逐字节相同、各自验签通过、`budget_receipt_digest`/`executor_authorization_digest` 都正确绑定。
- 结论：**“回执有效且相同”不能证明只执行一次。** 四道门禁不查询跨 Executor 状态，两实例各自认为自己是合法的一次执行。这正是当前设计的真实边界。

### T03 数据库回滚 — 通过（实测重放 dispatch，签名无法识别）

- 前提：首次执行前用 `sqlite3.backup` 真实快照 SQLite 文件；执行成功后删除 `-wal`/`-shm` 并用文件字节恢复旧库；再用同一 `PendingExecution` 重试。
- **实测：dispatch 从 1 增至 2**；回滚后 `executions` 行数为 0，重试后又变回 1（库看起来仍像“干净的一次执行”）。
- 第一次与第二次回执逐字节相同，均通过验签；`receipt_version=2`、`budget_receipt_digest` 绑定正确。
- D11 预算状态版本保持 1（Executor 侧回滚不触碰 D11 已提交状态）。
- 结论：**没有任何外部单调锚点能识别该回滚。** 回执签名只证明自身一致性与绑定关系，不证明“此前从未执行过”。恢复旧的内部一致数据库快照无法通过内部检查检测——与 E0 §8 的既有说明一致。

## 4. 攻击前提（诚实列出）

- T02 要求攻击者能让两个持有**相同 Executor 身份与私钥**的实例处理同一 pending（如配置错误、进程克隆、密钥复制）。本实验证明此时无全局去重。
- T03 要求攻击者能**回滚 Executor 的 SQLite 文件**（文件层快照/备份恢复）。本实验证明此时会产生第二次 dispatch 且内部检查无感。
- 三组实验的 dispatch 都是**确定性本地工具**（`invoice_review`），无外部副作用。本实验不声称对任意外部 API 构成 exactly-once 违背或成功的双重外部攻击，只证明执行边界本身。

## 5. 验收命令与结果

在仓库根目录执行（Windows PowerShell 设置 `PYTHONPATH` 后）：

| 命令 | 结果 |
| --- | --- |
| `python -m unittest discover -s tests -p "test_e1_executor_state_scope.py" -v` | **3/3 OK** |
| 同一命令连续再跑两轮 | **3/3 OK × 2**（稳定性确认） |
| `python -m unittest discover -s tests -v` | **194/194 OK**（191 原有 + 3 新增） |
| `cargo test --manifest-path experiments/d11_3_c_coordinator/Cargo.toml --all-targets` | **62 通过 / 0 失败**（各二进制合计） |
| `cargo fmt --manifest-path experiments/d11_3_c_coordinator/Cargo.toml -- --check` | **通过**（退出码 0） |
| `git diff --check` | **通过**（无输出） |

> 测试基建备注：首轮 T01 曾出现一次 Windows SQLite WAL 文件锁 timing 导致的偶发 `readonly database`。将测试侧只读 DB 检查改为 `immutable=1` 只读 URI 连接、并显式关闭所有检查连接后，连续三轮（定向 + 两轮稳定性）全部通过。该现象属测试侧文件句柄竞争，非生产代码或协议问题；生产 `ExecutionStore` 未被修改。

## 6. 对关键问题的回答

> Executor 的本地持久化状态，是否足以支撑跨实例、重启和数据库恢复下的执行防重放？

- **同一 Executor / 同一共享库**：是（T01，SQLite 事务串行化）。
- **跨独立库、相同身份**：否（T02，实测双 dispatch）。
- **数据库回滚到旧快照**：否（T03，实测双 dispatch 且签名无法识别）。

因此当前系统的真实保证是**单库/共享库内的幂等**，不是跨 Executor 或抗回滚的全局防重放。这与 E0 §2.4 / §7.3–7.4 / §8 的冻结边界一致，未发现与冻结设计相矛盾的缺陷。

## 7. 研究价值与后续

- 结论一已得到实测支撑：共享库能防重复执行、独立库不能，边界被精确限定为“单 SQLite 状态”。
- 结论二已得到实测支撑：数据库回滚能造成重复执行，且现有签名/状态检查无法识别，构成对“外部单调状态锚点 / 可信存储 / 执行侧防重放机制”需求的实证论据。
- 是否进入 E1.8 设计防重放机制，由冻结审查后决定；本阶段不预设结论、不提前改动协议。
