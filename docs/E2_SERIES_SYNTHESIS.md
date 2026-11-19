# E2 系列实验综合报告 — Cross-Experiment Synthesis

> **文档性质**：E2.1 / E2.2 / E2.3 三组**独立冻结实验**的跨实验证据综合，不是新实验，不是新机制的验证，也不是形式化安全证明。本文只把三组已有原始材料放到同一分析框架下，回答「它们分别解决什么、提供什么证据、留下什么边界、彼此如何衔接且不能互相替代」。
> **生产基线**：`main` = `467fa249c2c7f6971dd9f217ce0827e6f7bfc995`（E1.9 Final Acceptance 后 HEAD）。三组实验均从此基线各自建分支，**互不合并、互不包含、不修改生产代码**。
> **本分支**：`docs/e2-series-synthesis`（从 `main` 467fa24 创建，仅新增本文档）。
> **边界声明优先级**：如本文表述与三份冻结实验报告有出入，以各实验报告及其 `results/run-001/` 原始数据为准。

---

## 0. 来源与核对（本文所有数字的追溯）

本文**不依据 README 或历史总结转述数字**。每个关键数字均从下列冻结 commit 的 `results/run-001/{trials.csv, summary.json, raw.json}` 直接读取并交叉核对：

| 实验 | 冻结 commit | 报告 | 原始数据文件 | 逐轮记录数（已核对） |
|---|---|---|---|---|
| E2.1 请求绑定 | `750ffba43fbff81582c37431786f48fd7c45b9de` | `docs/E2.1_REQUEST_BINDING_EXPERIMENT_REPORT.md` | `experiments/e2_1_request_binding/results/run-001/{trials.csv,summary.json,raw.json}` | CSV 80 行 |
| E2.2 崩溃恢复 | `d05114396679fab542767855bbad53ea4ba16159` | `docs/E2.2_JOURNAL_CRASH_RECOVERY_EXPERIMENT_REPORT.md` | `experiments/e2_2_journal_crash_recovery/results/run-001/{trials.csv,summary.json,raw.json}` | CSV 40 行 |
| E2.3 工具端幂等 | `903f12847aa1bbf3d23d391b37e0c2c0e67be37e` | `docs/E2.3_TOOL_IDEMPOTENCY_EXPERIMENT_REPORT.md` | `experiments/e2_3_sink_idempotency/results/run-001/{trials.csv,summary.json,raw.json}` | CSV 30 行 |

核对结论：`summary.json` 的汇总值与 `trials.csv` 逐行统计一致，`raw.json.meta` 的进程隔离标记与三份报告声明一致。三个实验的 `baseline_commit` 字段均为 `467fa249...`，与生产基线一致。

---

## 1. 研究问题与总体设计

### 1.1 E2 系列要回答什么

E1 系列（至 E1.9 Final Acceptance）解决的是**本地执行链的可信化**：授权签名、预算准入（D10）、状态转移（D11）、Receipt 签发、Journal 权威记录与恢复。E2 系列把这些机制放到**对抗与故障**条件下，检验它们是否真的挡住了预期风险。E2 系列不是 E1 的功能延续，而是 E1 机制的**有效性检验**。

三组实验分别针对三个不同层次的问题，彼此不能替代：

| 层次 | 实验 | 核心问题 |
|---|---|---|
| 授权正确性 | E2.1 | 一份已签发的授权，能否阻止授权后被替换成未绑定的参数？ |
| 崩溃一致性 | E2.2 | 执行中途真实进程终止，重试会不会产生重复副作用？哪些窗口能恢复原件？ |
| 外部副作用治理 | E2.3 | 在无法确定副作用是否已发生的不确定重试下，工具端幂等能否压住重复副作用？ |

### 1.2 必须区分的四类问题（贯穿全文）

1. **请求授权正确性**：授权签名本身是否有效、由谁签发（E1/D10 的职责）。
2. **实际执行与授权请求的一致性**：真正 dispatch 的参数是否等于被授权绑定的参数（E2.1 的职责）。授权正确 ≠ 执行一致——这是 E2.1 揭示的核心差距。
3. **崩溃恢复与重复副作用**：持久化状态不足以判定时，重试是否安全（E2.2 的职责）。
4. **工具端幂等与冲突检测**：把「副作用至多一次」放到真正产生副作用的资源处能否成立（E2.3 的职责）。

### 1.3 统一的方法学边界

- 三组都是**受控机制实验**，每个预设场景或对照单元 N=10。E2.1 包含多个独立实验单元，CSV 共 80 行；E2.2 四个场景各 10 轮；E2.3 三个变体各 10 轮。这些是确定性机制重复验证，**不是统计性或形式化安全证明**；`0/10` 不等于统计意义上的概率为零。
- 受控工具（本地 `StatefulEffectRegistry` / 副作用计数器 / SQLite Sink）**只持久化副作用事件，不调用真实第三方 API**。
- 实验中的 gate 是驱动真实 `ExecutionStore` 路径的**测试替身**，不是完整四门禁；不得描述为生产完整执行链。
- 本文对「成功」的表述一律分层：**请求被拒 / 未发生 dispatch / 未发生外部副作用 / 恢复原件**是不同判定，不互相替代。

---

## 2. E2.1：请求绑定实验

**来源**：commit `750ffba`，报告 `docs/E2.1_REQUEST_BINDING_EXPERIMENT_REPORT.md`，`run-001/trials.csv`（80 行）+ `summary.json` + `raw.json`。

### 2.1 实验组与对照组设计

- 受保护工具 `invoice_review`；正常参数 `INV-E16-SYSTEM`，攻击参数 `INV-E16-ATTACK`。两者工具名相同、Schema 结构相同、都通过 `registry.validate()`——**仅参数值不同**，排除了「Schema 校验拦截攻击」的干扰。
- 副作用观察：`StatefulEffectRegistry` 继承生产 `LocalToolRegistry`，schema/validate 不变，只在真实 dispatch 后记录实际参数。观察的是攻击参数是否真到达工具，不是异常类型或 DENY 返回值。
- 三组机制：

| 组 | 机制 | 实现性质 |
|---|---|---|
| G1 | Static ACL + Schema | 工具白名单 + `registry.validate()`，无参数值绑定 |
| G2 | Signed Tool-Scope (v1) | 真实 `issue_executor_authorization()` 不传 arguments 签 v1；验签不启用 `require_argument_binding` |
| G3 | Full E1 (strict v2) | 真实 `TrustedToolExecutor(e1_required=True)` + 四门禁 + 真实 Rust `e1_service` |

G1/G2 是**隔离比较授权绑定性质的实验参考实现，不是完整竞争系统，更不是真实商业产品对比**。

### 2.2 各组 N 值与攻击输入

- A 正常：每组 10 次（授权参数 = 执行参数）。
- B 授权后参数替换：G1/G2 各 10 次（授权 `SYSTEM`、执行 `ATTACK`）。
- C1 Admission 前篡改（G3）：10 次，签 v2 授权后改 `ctx.arguments` 再 `h.run()`。
- C2 Admission 后、最终门禁前篡改（G3）：10 次，正常得 `PendingExecution` 后 `replace(arguments=ATTACK)` 交 `execute_e1()`。
- D exact replay（G3）：10 次。
- 每样本唯一 `operation_id`、独立 harness（独立 D10 lease / D11 DB / Rust 服务）。`N=10`，不做显著性或置信区间推断。

### 2.3 主对照结果（同源攻击时机、相同样本数）

主对照**只用** G1、G2 各 10 次参数替换样本，与 **G3-C2 的 10 次 Admission 后篡改样本**比较。数据来自 `summary.json` 与 CSV 分组统计：

| 组（主对照） | Benign Acceptance | Attack Accepted | Attack Rejection | Unauthorized Effect Rate | 攻击侧 dispatch |
|---|---|---|---|---|---|
| G1 Static ACL + Schema | 10/10 (1.00) | 10/10 | 0/10 (0.00) | 10/10 = 1.00 | 10 |
| G2 Signed v1 (tool-scope) | 10/10 (1.00) | 10/10 | 0/10 (0.00) | 10/10 = 1.00 | 10 |
| **G3-C2 Full E1 (strict v2)** | 10/10 (1.00) | **0/10** | 10/10 (1.00) | **0/10 = 0.00** | **0** |

- G2 的 v1 授权 payload 版本为 `1` 且**不含 `arguments_digest`**（专项测试 `test_04` 直接断言），因此无法区分两个 invoice 值；攻击参数真实写入工具状态。
- G3-C2 攻击 10/10 在最终门禁被拒，拒绝原因为 `ToolExecutionDenied: ... actual dispatch arguments differ from ToolCallBinding`，dispatch=0、未授权副作用=0。

**C1 单独报告，不并入主对照**（两者攻击时机不同，合并会破坏可比性）：

| 场景 | 尝试 | 拒绝 | 拒绝阶段 | D10 Admission | D11 Transition | dispatch | Receipt |
|---|---|---|---|---|---|---|---|
| C1 Admission 前 | 10 | 10 | Runtime 预检查（`ExecutorAuthorizationError`，授权摘要与当前请求不符） | 未发生 | 未发生 | 0 | 无 |
| C2 Admission 后 | 10 | 10 | Executor 最终门禁（`ToolExecutionDenied`，实际参数与 binding 不符） | 已提交 | 已提交（version=1 保持） | 0 | 无（`NO_RECEIPT`） |

C1/C2 的差异本身是证据：篡改发生在 Admission 前还是后，决定 D10/D11 是否已提交；但两者都在 dispatch 前被拒。**禁止把 C1+C2=20 与 G1/G2 各 10 放进同一主对照列。**

### 2.4 结论及证据边界

- **观察支持**：在「同工具、同 Schema、同授权身份、仅替换参数值」这一具体场景，精确参数绑定提供了工具范围级授权所没有的保护——G3-C2 10/10 在副作用前拦截，G1/G2 10/10 放行。
- **Saga 窗口（不弱化）**：C2 的 D10/D11 Admission 在最终门禁拒绝后**不自动回滚、不自动退款**（生产与 Rust 服务中无 refund 逻辑），已消耗的预算单位不会返还。**Admission 成功不等于工具执行完成**；不能写成「所有资源消耗均未发生」。
- **不外推**：exact replay 10/10 返回完全相同的原始 Receipt、且 replay 未增加 dispatch，只说明本地确定性工具路径的行为，**不外推为任意外部系统的 exactly-once**。G1/G2 非商业产品；本实验只验证一个具体替换场景，不是形式化证明，不是普遍比较，不声称全面抵御 Prompt Injection。

---

## 3. E2.2：崩溃恢复实验

**来源**：commit `d051143`，报告 `docs/E2.2_JOURNAL_CRASH_RECOVERY_EXPERIMENT_REPORT.md`，`run-001/trials.csv`（40 行）+ `summary.json` + `raw.json`。

### 3.1 相对 E1.9 的增量证据

E1.9 的 W01–W04 是**进程内异常注入**（测试进程里抛 `RuntimeError`，SQLite 经 `with` 正常回滚）。E2.2 让 Executor 运行在**独立 OS 子进程**，在精确屏障处由父进程 `proc.kill()`（Windows TerminateProcess 硬杀，不依赖进程内 handler），再启新进程观察恢复。两者是**不同证据层，不互相替代**。

### 3.2 三域隔离与真实进程终止

| 域 | 实现 | 隔离证明 |
|---|---|---|
| A Journal Service | 独立进程，真实 Named Pipe + 独立 sqlite + 真实 Ed25519 签名 | `journal_service_is_standalone_process=true` |
| B Executor Worker | 独立子进程，真实 `JournalBackedExecutor` + `ExecutionStore` + `E1CLocalState` | `worker_is_standalone_process=true` |
| C External Effect Counter | 受控工具 dispatch 时写入并 commit 的独立 DB | `effect_db_is_independent=true` |

子进程到屏障写 marker（含 point/PID），父进程 20 ms 轮询、**确认 marker 后才 kill**。40 轮全部 `crash_point_confirmed=true`，worker PID 全部不同，退出码均为 1，`kill_is_real_process_termination=true`。受控工具不调用真实第三方 API，gate 不是完整四门禁。

### 3.3 F1–F4：崩溃位置、三方状态与重试行为

故障前三方状态（各场景 10/10 一致，来自 CSV / summary）：

| 场景 | 强制终止位置 | Journal INTENT | Journal RESULT | 本地记录 | 外部副作用 |
|---|---|---|---|---|---|
| F1 | INTENT 已持久化、DISPATCH 前 | 1 | 0 | 无 | 0 |
| F2 | DISPATCH 副作用已发生、RESULT 前 | 1 | 0 | 无 | 1 |
| F3 | RESULT 已持久化、本地 COMMIT 前 | 1 | 1 | 无 | 1 |
| F4 | 本地 COMMIT 已完成、响应返回前 | 1 | 1 | 有 | 1 |

重试后结果（副作用/dispatch 为 10 轮合计）：

| 场景 | 副作用 before→after | dispatch before→after | 恢复分类 | Receipt 验签 | 与原件一致 |
|---|---|---|---|---|---|
| F1 | 0 → 10 | 0 → 10 | `CONTINUED_AFTER_INTENT` 10/10 | 10/10 有效 | N/A（崩溃时无原件） |
| **F2** | **10 → 20** | **10 → 20** | `REPEATED_EFFECT_UNCERTAIN` 10/10 | 10/10 有效 | `N/A_NO_ORIGINAL_AT_CRASH` |
| F3 | 10 → 10 | 10 → 10 | `RECOVERED_ORIGINAL_FROM_JOURNAL` 10/10 | 10/10 有效 | 10/10 完全相同 |
| F4 | 10 → 10 | 10 → 10 | `LOCAL_IDEMPOTENT_RETURN` 10/10 | 10/10 有效 | 10/10 完全相同 |

### 3.4 F2 重点解释（不弱化）

F2 的崩溃点在**外部副作用已提交、Journal RESULT 尚未写入**之间。此时 Journal 与本地都显示「无 RESULT / 无记录」，但外部计数已 +1；系统在重试时**无法从持久化状态判断副作用是否已发生**，于是再次 dispatch，每个 operation 累计 2 次副作用（10 轮 10→20，`REPEATED_EFFECT_UNCERTAIN` 10/10）。实验**未采取任何人为阻止第二次 dispatch 的措施**，如实记录这一结果不确定窗口。

F2 Receipt 口径（来自冻结报告 §4.2）：屏障位于 Receipt 生成签名之后、RESULT 写入之前；崩溃时 Receipt 已在 Worker 内存完成签名，但尚未持久化；进程被强杀后内存对象丢失，故 `N/A_NO_ORIGINAL_AT_CRASH` 表示**没有可持久化恢复的原件**，**不表示 Receipt 从未生成**。

F3/F4 则相反：RESULT 或本地提交已持久化，重试命中恢复路径，**返回原始 Receipt（非重签）**，dispatch 不增、副作用不增。

### 3.5 结论与边界

- **观察支持**：Journal RESULT 持久化（F3/F4）能恢复原件且不重复执行；INTENT-only 但副作用未发生（F1）可安全继续。
- **明确风险**：DISPATCH 已发生而 RESULT 未持久化（F2）存在重复副作用风险，这是 E1.9 已声明的 Saga 窗口在真实进程终止下的直接观测，**本实验不修复它**。
- **严禁声称**：所有崩溃窗口自动恢复、系统具备 G1b、外部 exactly-once、Journal 单独证明外部工具执行真实性、已解决跨存储原子性。`N=10` 是机制重复验证，非统计/形式化证明。

---

## 4. E2.3：工具端幂等实验

**来源**：commit `903f128`，报告 `docs/E2.3_TOOL_IDEMPOTENCY_EXPERIMENT_REPORT.md`，`run-001/trials.csv`（30 行）+ `summary.json` + `raw.json`。

### 4.1 要回答的问题与架构

E2.2 证明 F2 窗口重试会重复副作用。E2.3 问：当 Executor 无法确定首次调用是否已产生副作用时，让**真正产生副作用的工具端**接收稳定幂等标识并做原子去重，能否在允许重试的前提下压住重复副作用？

三域隔离同 E2.2，第三域换为 **External Tool Sink**（独立 SQLite，同时保存幂等记录 + 副作用 + 原始结果；不与 A/B 共用库）。崩溃点为唯一 `F2_AFTER_DISPATCH_BEFORE_RESULT`，`kill_is_real_process_termination=true`、`sink_db_is_independent=true`。30 轮均确认到达屏障。

### 4.2 幂等键、原子去重与 V0/V1/V2 结果

```
idempotency_key = digest({domain:"e2-3-sink-idempotency-v1", executor_id, operation_id})
request_digest  = digest({domain:"e2-3-sink-request-v1", executor_id, operation_id,
                          tool_name, tool_schema_hash, arguments})
```

- 幂等键**不含 arguments / binding_digest**（`idempotency_key_excludes_arguments_and_binding_digest=true`）；`request_digest` 由 Sink 按**自身收到的实际参数**重算（`sink_recomputes_request_digest_from_actual_arguments=true`），不盲信调用者摘要。
- Sink 用 `BEGIN IMMEDIATE` 把「key + 摘要 + 副作用 + 原始结果」在**同一事务提交**；同 key 同摘要返回原始结果（`DEDUP_HIT`），同 key 异摘要拒绝（`IDEMPOTENCY_KEY_CONFLICT`）。

正式结果（各组 N=10，副作用/dispatch 为 10 轮合计，来自 CSV / summary）：

| 变体 | 副作用 before→after | dispatch before→after | sink outcome | 恢复分类 | result 与 Sink 一致 |
|---|---|---|---|---|---|
| V0 无幂等 | 10 → **20** | 10 → 20 | EXECUTED | `EFFECT_REPEATED` 10/10 | 0/10（重新执行） |
| V1 有幂等 | 10 → **10** | 10 → **20** | DEDUP_HIT | `SINK_DEDUP_NO_REPEAT` 10/10 | 10/10 |
| V2 同 key 异参 | 10 → **10** | 10 → 20 | IDEMPOTENCY_KEY_CONFLICT | `IDEMPOTENCY_CONFLICT_REJECTED` 10/10 | 0/10（冲突返回错误） |

三组重试 Receipt 均 10/10 返回、签名有效、绑定正确 `operation_id` + `binding_digest`。V1 是核心证据：**dispatch 照旧增长到 2，副作用计数停在 1**——工具端去重允许再次 dispatch、同时阻止第二次外部效果。

### 4.3 四种性质分离（不合并为 exactly-once）

| 性质 | V0 | V1 | V2 |
|---|---|---|---|
| Dispatch at-most-once | 否（1→2） | **否（1→2，允许重复 dispatch）** | 否（1→2） |
| Effect at-most-once | 否（1→2） | **是（1→1）** | 是（1→1） |
| Retry result consistency | 否 | **是（返回 Sink 原始结果 10/10）** | 否（冲突返回错误） |
| Receipt continuity | 否 | **否（新签名 Receipt，不恢复原件）** | 否 |

### 4.4 专项结果（来自 summary.json `special_checks`）

- **并发**（8 个并发、同 key 同参）：`executed=1`、`dedup_hits=7`、`committed_effects=1`、`dispatch_count=8`、`passed=true` —— 仅一个副作用提交。
- **事务回滚**：首次 `ROLLED_BACK`，回滚后 key 不存在、副作用=0，正常重试 `EXECUTED`、副作用=1、`passed=true` —— 幂等记录与副作用同事务回滚，之后可正常完成。

### 4.5 V2 注入边界（必须原样保留）

V2 通过**测试专用 `ControlledSinkGate`**，在**复用首次 binding payload / `binding_digest`** 的情况下，向 Sink 注入**不同的实际 `arguments`**，以隔离验证工具端的同 key 异参冲突检测。该实验**不经过完整四门禁参数绑定验证**，因此**不代表生产执行链允许参数替换**，也**不构成对 Request Binding 安全性的绕过证明**。真实 Request Binding 检查本应在请求到达 Sink 之前阻止此类参数变化；V2 只验证「工具端在看到同一幂等键对应不同参数时能独立拒绝」这一 Sink 契约，不是对授权绑定层的攻击结论。

### 4.6 Receipt 与边界

- V1 返回的是 **Sink 保存的原始结果**，但重试 Executor 会为其**重新签发一份新 Receipt**——**不是恢复崩溃前丢失的原 Receipt**。签名有效、绑定正确、result 一致；不声称原件恢复、字节级连续、`receipt_identical_to_original=true`（该字段统一为 `N/A_NO_ORIGINAL_AT_CRASH`，含义是「无可持久化恢复的原件」，不是「从未生成」）。
- V2 冲突返回 FAILED Receipt，签名仍有效、绑定仍正确，但不返回 Sink 原始结果。
- 幂等键作用域 = 实验域标签 `e2-3-sink-idempotency-v1`；真实部署须逐服务核对供应商幂等范围与保留期限。**受控 SQLite Sink ≠ 真实第三方 API**，未接入任何真实服务、未使用第三方 API Key。

---

## 5. 跨实验对比

### 5.1 统一对比表

| 维度 | E2.1 | E2.2 | E2.3 |
|---|---|---|---|
| 核心问题 | 请求绑定：授权是否等于实际执行 | 崩溃恢复：重试是否重复副作用 | 工具端幂等：不确定重试能否压住重复副作用 |
| 威胁/故障模型 | 授权后参数值替换（同工具、同 Schema） | 真实进程终止于 F1–F4 四个窗口（无异常注入） | 真实进程终止于 F2 + 同 key 异参 + 并发 + 事务回滚 |
| 关键机制 | v2 `arguments_digest` + 四门禁 + Rust `e1_service` | Journal RESULT / 本地提交 / 原件恢复；F2 不修复 | 稳定幂等键 + Sink 原子去重 + 异参冲突检测 |
| 实验规模 | benign 每组 10；攻击 G1/G2 各 10、G3 C1/C2 各 10、replay 10（CSV 80 行） | F1–F4 各 10（CSV 40 行） | V0/V1/V2 各 10（CSV 30 行）；并发 8、回滚 1 |
| 核心指标 | Unauthorized Effect Rate、Attack Rejection、dispatch | 副作用/dispatch before→after、恢复分类、Receipt 原件一致 | Effect/Dispatch at-most-once、result consistency、Receipt continuity |
| 主要结果 | G1/G2 攻击 10/10 接受、10 次未授权副作用；G3-C2 0/10 接受、0 dispatch、0 副作用；C1 单独 10/10 拒绝 | F1 0→10 可继续；**F2 10→20 重复（10/10）**；F3/F4 10→10 且原件一致 10/10 | V0 10→20；**V1 eff 10→10 / dispatch 10→20、DEDUP 10/10**；V2 冲突 10/10；并发 1 effect、回滚通过 |
| 保证边界 | 仅一个替换场景；C2 不退款 Saga 窗口；G1/G2 是参考实现非商业产品；replay 不外推 exactly-once | F2 重复未解决；N=10 非形式化；Journal 不独立证明外部副作用；无 G1b | Sink 幂等≠全局 exactly-once；无全局 dispatch at-most-once；V2 是 Gate 注入非四门禁；V1 新签 Receipt 非原件 |

### 5.2 互补关系（不是同一个端到端实验）

三组实验**从 main 各自建分支、互不合并、互不包含**，攻击面、故障模型与观测指标都不同，不能连写成一个「端到端系统实验」：

1. **E2.1 是入口门禁**：决定「一个请求在到达工具之前，是否被授权精确绑定」。它不测试进程崩溃，也不测试工具端去重。
2. **E2.2 是故障剖面**：在 E1 执行链上真实杀进程，定位哪类窗口安全（F1/F3/F4）、哪类窗口危险（F2）。它不测试参数替换攻击，也不提供工具端缓解。
3. **E2.3 是缓解验证**：针对 E2.2 的 F2，验证「若工具端提供原子幂等契约」能把 Effect at-most-once 放在副作用资源处。它不验证完整四门禁参数绑定（V2 明确是 Gate 注入），也不恢复 Receipt 原件。

论证链是**问题递进、机制互补**，而非性能递进：E2.1 回答「授权是否绑得准」，E2.2 回答「绑准之后崩溃会不会重复」，E2.3 回答「重复风险能否由外部工具兜住」。三者的安全结论各自独立成立，任一组的结论都不能替代另外两组。

---

## 6. 总体安全保证与未解决问题

### 6.1 三类结论严格分离

**（A）已由实验观察支持的结论**（受控条件、N=10）
- E2.1：在参数值替换场景中，G3-C2（Admission 后、最终门禁前篡改）通过完整 E1 v2 执行链在 dispatch 前拦截 10/10；G3-C1（Admission 前篡改）另行在 Runtime 预检查阶段拒绝 10/10；工具范围级授权（G1/G2）放行 10/10。
- E2.2：F1 可安全继续、F3/F4 恢复原件且不重复、**F2 重复副作用 10/10**。
- E2.3：V1 在受控 Sink 下实现 Effect at-most-once（eff 10→10）但 dispatch 仍重复（10→20）；V2 同 key 异参被工具端独立拒绝 10/10；并发 8 请求仅 1 effect；事务回滚一致。

**（B）依赖部署条件的工程保证**
- 「重试携带同一操作身份」依赖 Agent/Executor 侧稳定派生 `operation_id`（密码学 Binding 提供身份连续性）。
- 「重复请求不产生第二次副作用」**必须由外部工具服务真正支持幂等键与原子去重**，且幂等范围/保留期限按供应商核对——不能假定所有第三方 API 都提供这种能力。
- 上述保证在受控 SQLite Sink 下成立；迁移到真实服务需逐服务验证其幂等语义。

**（C）尚未实现或验证的能力**
- 全局（跨工具、跨服务）的 exactly-once；全局 dispatch at-most-once。
- Receipt 作为外部副作用的独立真实性证明；Journal 单独证明外部副作用是否发生。
- F2 窗口的自动修复；C2 预算的自动退款；跨存储原子性；G1b；抗管理员联合控制 DB + 私钥的回滚。
- 任意真实第三方 API 上的幂等效果（受控结果不可直接外推）。

### 6.2 必须明确坚持的边界

- **Sink 幂等不等于全局 exactly-once**：V1 只压住「同一操作身份的第二次副作用」，dispatch 仍可能重复，Receipt 仍非原件。
- **Receipt 的性质**：它是 Executor 签名的**执行记录**，不是外部副作用的独立真实性证明；签名有效 ≠ 外部副作用确实发生。
- **Journal 的性质**：Journal 负责记录与恢复，**不独立证明外部副作用是否发生**；F2 正是这一边界的直接观测。
- **不假设第三方能力**：不能假设所有外部 API 提供幂等键与原子去重；受控 SQLite Sink 的结果不能直接外推到任意真实第三方服务。
- **不提供全局 dispatch at-most-once**：E2.2 与 E2.3 的 F2 故障重试实验显示 dispatch 可以重复；E2.1 的 exact replay 实验则观察到 10/10 未增加 dispatch。现有实现不提供跨场景、跨工具的全局 dispatch at-most-once 保证。
- 三组实验均非形式化证明；`0/10` 不等于概率为零；N=10 是机制验证。

---

## 7. 总结与后续研究问题

### 7.1 主要研究结论

E2 系列用三组独立受控实验，把 E1 可执行链的信任问题拆成三个**相互衔接但不可互相替代**的环节并逐一取证：

1. **E2.1** 证明「授权正确」与「执行一致」是两件事：工具范围级授权挡不住参数替换，精确参数绑定（v2 + 四门禁）能在副作用前拦截；同时暴露 C2 不退款的 Saga 窗口。
2. **E2.2** 用真实跨进程 kill 定位崩溃窗口，证明 RESULT/本地提交已持久化时可恢复原件且不重复，而 **F2（副作用已发生、RESULT 未写）无法从持久化状态判定、重试重复副作用 10/10**。
3. **E2.3** 证明若外部工具提供原子幂等契约，可在允许重复 dispatch 的前提下把 Effect at-most-once 放在副作用资源处（V1 eff 10→10），并验证同 key 异参冲突检测（V2 10/10）——但不恢复 Receipt 原件、不提供全局 dispatch 去重。

综合价值不在于「实现了一个 SQLite 去重模块」，而在于厘清责任边界：**稳定操作身份由 Agent/Executor 维持，密码学 Binding 约束授权请求的身份与内容，外部工具服务承担真正的副作用去重，Journal 负责记录与恢复但不能单独证明外部副作用发生与否**。这比笼统宣称「用 ZKP 或签名实现 Agent exactly-once」更严谨。

### 7.2 有证据基础的后续研究问题

只列出三组数据直接引出、且可被下一步实验检验的问题，不引入无关功能：

1. **真实服务上的幂等语义验证**：受控 Sink 的原子去重成立，但真实第三方 API 的幂等键范围、保留期与并发语义各异——如何在具体供应商上复现 V1/V2 的保证？（由 E2.3 §11 边界引出）
2. **F2 窗口的形式化刻画**：当前 F2 重复是 N=10 机制观测，能否给出该窗口的精确状态机与不可能性/可行性条件，而非依赖样本？（由 E2.2 §7 边界引出）
3. **全局 dispatch 去重的代价评估**：E2.3 明确不提供 dispatch at-most-once；若要引入跨工具去重协调，其可用性与故障代价是否可接受？（由 E2.3 四性质分离引出）
4. **Receipt 与外部副作用的绑定**：当前 Receipt 是 Executor 签名记录、不证明外部效果；能否在不假设第三方配合的前提下，把外部副作用证据纳入可验证链路？（由 E2.2/E2.3 Receipt 边界引出）
5. **C2 Saga 窗口的资源口径**：Admission 已提交但执行被拒时不退款，是否应在协议层定义可声明的消耗上界与状态语义？（由 E2.1 §4.2 边界引出）

---

## 附录：来源对应关系速查

| 本文结论 | 直接来源（commit:path） |
|---|---|
| G1/G2 攻击 10/10 接受、10 次未授权副作用 | `750ffba:experiments/e2_1_request_binding/results/run-001/summary.json`（G1/G2 `attack_accepted=10`、`unauthorized_effects=10`） |
| G3-C2 0/10、0 dispatch、0 副作用；C1 单独 | 同上（`c2`/`c1` 子对象）+ `trials.csv` 按 group/scenario 分组统计 |
| exact replay 10/10 原件一致 | 同上（`exact_replay.identical_receipt=10`）+ E2.1 报告 §4.3 |
| F2 副作用 10→20、dispatch 10→20 | `d051143:experiments/e2_2_journal_crash_recovery/results/run-001/summary.json`（F2）+ `trials.csv` |
| F1/F3/F4 结果与原件一致 | 同上（F1/F3/F4）+ E2.2 报告 §4.2 |
| 真实进程终止 / 三域隔离 | `d051143`/`903f128`:`raw.json.meta`（`kill_is_real_process_termination`、`*_is_standalone_process`、`*_db_is_independent`） |
| V0/V1/V2 副作用与 dispatch | `903f128:experiments/e2_3_sink_idempotency/results/run-001/summary.json`（V0/V1/V2）+ `trials.csv` |
| 并发 1 effect、回滚通过 | 同上（`special_checks.concurrency` / `special_checks.rollback`） |
| V2 注入边界 / V1 新签 Receipt 非原件 | `903f128:docs/E2.3_TOOL_IDEMPOTENCY_EXPERIMENT_REPORT.md` §6 / §8 |
