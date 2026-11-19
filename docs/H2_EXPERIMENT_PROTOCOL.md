# H2.0 实验协议：离线授权下的撤销可见性与有效性控制

> 阶段性质：**实验协议冻结**。本文件冻结 H2.1 实现与 H2.2 实验必须遵循的分组、参数、场景矩阵、数据字段、指标计算与判定纪律。配套设计见 `docs/H2_REVOCATION_DESIGN.md`。
> 纪律：本阶段**不写代码、不改 H1/E1/E2/E3-0、不接真实 MCP、不提前实现机制**。
> 核心立场：**设计一个能够让 C2 输掉的实验**。C2 只有在"以远低于 B2 的在线成本显著降低撤销风险窗口，且不牺牲离线可用性"时才值得进入 H2 后续阶段；否则按本文件第 7 节 NO-GO。

---

## 1. 研究问题与可证伪假设

协议必须回答五个问题（对应任务包五个指标），并为每个问题给出**可计算**指标（第 6 节）：

| 编号 | 研究问题 | 关键指标（第 6 节定义） |
|---|---|---|
| Q1 | 授权服务离线时，哪些方案还能执行？ | `offline_exec_success_rate`、`fail_closed_count` |
| Q2 | 凭证撤销后，Executor 多久能够发现？ | `w_risk_ms`（撤销风险窗口）、`d_prop_ms`（撤销传播延迟，仅 C2） |
| Q3 | 撤销快照过期后会发生什么？ | `expired_snapshot_reject_rate`、`false_allow_count` |
| Q4 | 快照同步需要多少成本？ | `sync_duration_ms`、`snapshot_payload_bytes`、`snapshot_verify_ms` |
| Q5 | 并发请求会不会绕过撤销或重复执行？ | `revoked_reject_rate`、`duplicate_effect_count` |

### 1.1 主假设（H2 的中心，可证伪）

> **H2-main**：在目标离线可用性 `A` 固定的前提下，C2（签名版本化撤销快照）相对 C1（短 TTL）能显著降低撤销风险窗口 `W_risk`，且所需的在线刷新频率远低于 B2 的"每次执行都在线"。

- **证伪方向**：若 C2 的 `W_risk` 与 C1 的 `TTL` 上界无实质差距，或 C2 为击败 C1 必须把刷新间隔 `R` 压到接近"每次执行都在线"（即 B2 级别），则 H2-main 被证伪。
- **判定纪律**：先冻结 C2 失败条件（第 7 节），再运行实验；**不得**为得到正向结论而弱化 C1 或放松 C2 的失败门槛。

### 1.2 四个辅助假设（机制正确性，任一失败即阻断 H2.1）

- **H2-a（四组安全条件一致）**：四组共用同一动作绑定、同一受控 Sink、同一撤销触发；除"授权验证 + 撤销处理"层外无差异（设计文档 §2.2）。
- **H2-b（快照抗回滚/抗伪造）**：旧版本、错误密钥、过期、未生效、畸形快照一律被拒且缓存不变（设计文档 §5.2）。
- **H2-c（过期 fail closed、无错误放行）**：快照过期且无法刷新时拒绝执行；缓存明确列出撤销时绝不因过期而放行（设计文档 §6.2）。
- **H2-d（并发与重放不绕过）**：撤销 jti 在并发下不被放行；同一 jti 最多一次副作用（H1 原子消费层不变）。

---

## 2. 分组与冻结参数

四组定义见设计文档 §2。下表冻结**组内参数**；组数固定为四，参数扫描不是新分组。

| 分组 | 授权方式 | 冻结参数 | 取值 / 扫描网格 | 说明 |
|---|---|---|---|---|
| B2 | 在线查询 | 通道 | TCP+TLS，服务器证书指纹固定 | H1 基线，每次执行 1 次在线查询 |
| C0 | Ed25519 离线凭证 | 凭证 TTL | `300 s`（固定） | H1 的 C 基线，长 TTL，无撤销列表 |
| C1 | Ed25519 离线凭证（短 TTL） | `τ`（短 TTL） | `{5, 15, 60} s` 扫描 | 风险窗口上界 = τ；离线窗口也 = τ |
| C2 | Ed25519 离线凭证 + 撤销快照 | 凭证 TTL | `300 s`（固定，与 C0 同） | 离线窗口不由凭证 TTL 限制 |
| C2 | 同上 | 快照有效时长 `S` | `120 s`（固定） | `valid_until - generated_at` |
| C2 | 同上 | 刷新间隔 `R` | `{5, 30, 120} s` 扫描 | `R = 120 = S` 为"仅到期才刷新"的边界臂 |
| 通用 | 目标离线可用性 `A` | 头对头固定量 | `60 s` | 判 C2/C1 时的共同可用性目标（第 7 节） |
| 通用 | 机制重复次数 `N` | 每(场景,组,臂)单元 | `10` | 机制验证，非统计显著性 |

**时间控制**：逻辑时间（`t_issue/t_revoke/t_exec_attempt/t_snapshot_*/t_first_reject`）全部由**单一测试进程的可控时钟注入**产生（沿用 H1 `now` 注入风格），不用 `sleep`；`D_prop/W_risk` 由注入时间戳计算。成本类指标（`sync_duration_ms/snapshot_verify_ms`）用真实 `perf_counter` 测量墙钟耗时，与逻辑时间分离记录。

---

## 3. 安全条件一致性（防"不同组不同条件"）

以下各项四组**必须一致**，否则该实验单元判为无效：

1. 同一 `ActionRequest` 五个身份字段、同一 `action_digest` 算法与域 `h1-action-binding-v1`。
2. 同一 `jti` 一次性语义、同一受控 Sink 与消费存储（`jti` 主键 + `BEGIN IMMEDIATE`，消费与副作用同事务，H1 不变）。
3. 同一 `confirm()` 用户确认语义、同一 `revoke(jti)` 触发语义。
4. 同一预置信任锚：`key_id -> 公钥`、`issuer`、`audience`；绝不读请求携带的公钥/状态。
5. 撤销一律为**签发后撤销**（ACTIVE 时签发，之后 revoke），与 H1 架构权衡实验口径一致；签发前撤销/过期由 H1 `CredentialIssuanceError` 处理，不属 H2 变量。
6. 同一 `now` 注入时钟；同一套拒绝判定码命名（设计文档 §6.3）。

---

## 4. 场景矩阵（H2.1 必须实现，H2.2 必须运行）

每个场景对**适用组**分别运行，每单元 `N=10`。"预期"列为机制正确性断言；`W_risk/D_prop` 等延迟值由实际时间戳计算，不预判。

| 场景 ID | 描述 | 适用组 | 预期结果 | 喂给 |
|---|---|---|---|---|
| M01 `legal_exec` | 合法授权、合法请求、服务在线 | 全部 | 均 EXECUTED，各 1 副作用 | 基线 |
| M02 `offline_exec` | 服务不可达，凭证/快照仍有效 | 全部 | B2 REJECT（fail closed）；C0 EXECUTED；C1 τ 内 EXECUTED；C2 FRESH 未命中 EXECUTED | Q1 |
| M03 `offline_expired` | 服务不可达且已越过 TTL/快照有效期 | 全部 | C1 REJECT `C_EXPIRED`（短 TTL 到）；C2 REJECT `SNAPSHOT_UNAVAILABLE`；C0 超长 TTL 后 REJECT `C_EXPIRED`；B2 REJECT `AUTH_SERVICE_UNREACHABLE` | Q1/Q3 |
| M04 `revoke_then_online` | 签发后撤销，服务在线，允许刷新 | 全部 | B2 REJECT（即时）；C0 EXECUTED；C1 τ 内 EXECUTED；C2 刷新后 `REVOKED_BY_SNAPSHOT` REJECT | Q2 |
| M05 `revoke_then_offline` | 签发后撤销，服务离线，持有 FRESH 旧快照 | 全部 | B2 REJECT（fail closed）；C0/C1/C2 在各自有效期内仍 EXECUTED（即风险窗口） | Q2 |
| M06 `stale_snapshot_expiry` | C2 缓存 EXPIRED 且离线、无刷新 | C2 | REJECT `SNAPSHOT_UNAVAILABLE`，0 错误放行 | Q3 |
| M07 `rollback_snapshot` | 注入合法签名但旧版本的快照 | C2 | 候选 REJECT `SNAPSHOT_VERSION_STALE`；缓存不变；若缓存已列该 jti 则仍拒绝执行 | Q3/Q5 |
| M08 `forged_snapshot` | 注入错误密钥签名的高版本快照 | C2 | 候选 REJECT `SNAPSHOT_SIGNATURE_INVALID`；缓存不变 | Q5 |
| M09 `malformed_snapshot` | 注入过期 / 未生效 / 畸形（乱序 jti、非有限浮点）快照 | C2 | 分别 REJECT `SNAPSHOT_EXPIRED` / `SNAPSHOT_NOT_YET_VALID` / `SNAPSHOT_MALFORMED`；缓存不变 | Q3 |
| M10 `concurrent_revoked` | 撤销 jti + 有效快照列出该 jti，N 并发执行 | 全部 | 全部 REJECT（C2 命中撤销）；新增副作用 0 | Q5 |
| M11 `concurrent_legal` | 合法 jti，N 并发执行 | 全部 | 恰 1×EXECUTED、其余 DEDUP_HIT；新增副作用 1 | Q5 |
| M12 `claim_tamper` | 篡改参数/Schema/Server/Executor/issuer/audience/key_id | 全部 | 全部 REJECT（绑定/信任锚，与 H1 一致） | 一致性 |
| M13 `sync_cost_scaling` | 撤销集合规模 `K ∈ {1,10,100,1000}` 下测同步成本 | C2（B2 参考） | 记录耗时/字节/验签耗时，观察是否随 K 近似线性 | Q4 |
| M14 `head_to_head_c1_c2` | 头对头：纯离线 vs 间歇可达，固定可用性目标 `A=60s` | C1,C2 | 见第 7 节判据 | NO-GO |

> M14 是判定 H2-main 的关键场景，须同时覆盖两种连通性：
> - **纯离线**（全程无刷新）：C1 `τ=A=60s` 给 `W_risk ≤ 60s`；C2 设 `S=120s ≥ A`，无刷新时 `W_risk ≤ S` 后 fail closed。此臂 C2 **可能输**。
> - **间歇可达**（每 `R` 可刷新一次，但执行本身不在线）：C1 仍 `W_risk ≤ τ`；C2 可做到 `W_risk ≈ R`，且在线查询率 `1/R` 远低于 B2 的每次执行。此臂 C2 **可能赢**。

---

## 5. 统一数据字段（逐 trial 记录，实际观测非预填）

每次 trial 写入 `trials.csv`；聚合写 `summary.json`；细节（快照/时间戳/缓存前后）写 `raw.json`。字段如下（不适用组填 `NA`，未发生填 `NULL`）：

### 5.1 标识与配置

| 字段 | 含义 |
|---|---|
| `run_id` / `scenario_id` / `group` / `arm` / `trial_idx` | 运行、场景（M01…）、分组（B2/C0/C1/C2）、参数臂（如 `tau=15` / `R=30`）、重复序号 |
| `jti` / `action_digest` | 一次性授权标识、动作摘要 |
| `ttl_s` / `tau_s` / `snapshot_validity_s` / `refresh_interval_s` | 凭证 TTL、C1 短 TTL、C2 快照有效时长 `S`、刷新间隔 `R` |
| `revocation_set_size` | 快照中撤销 jti 数量 `K`（M13 用） |

### 5.2 逻辑时间戳（注入时钟，单位 s）

| 字段 | 含义 |
|---|---|
| `t_issue` / `t_revoke` | 签发 / 撤销时刻（`t_revoke` 未撤销为 `NULL`） |
| `t_exec_attempt` | 执行验证时刻 |
| `t_snapshot_generated` / `t_snapshot_obtained` | 服务生成快照 / Executor 取得含该撤销记录的快照时刻（C2） |
| `t_first_reject` | 撤销后首次拒绝该 jti 的时刻（用于 `W_risk`） |
| `service_online` / `refresh_allowed` | 服务是否可达 / 本次是否允许刷新（bool） |

### 5.3 结果与实际观测量

| 字段 | 含义 |
|---|---|
| `actual_outcome` | `EXECUTED` / `REJECTED` / `DEDUP_HIT` / `ROLLED_BACK` / `NA` |
| `actual_reason` | 冻结判定码（如 `REVOKED_BY_SNAPSHOT`、`SNAPSHOT_UNAVAILABLE`、`SNAPSHOT_VERSION_STALE`） |
| `effects_added` | 本次 trial 新增副作用数（实际计数） |
| `snapshot_version_cached` / `snapshot_version_candidate` / `snapshot_valid_until` | C2 缓存/候选版本与缓存有效期 |
| `snapshot_accepted` | 候选是否被接受（C2，bool） |
| `d_prop_ms` / `w_risk_ms` | 传播延迟 / 风险窗口（第 6 节计算；`NA`/`NULL` 按定义填） |
| `sync_duration_ms` / `snapshot_payload_bytes` / `snapshot_verify_ms` | 同步耗时、快照字节数、验签耗时（墙钟实测） |
| `expected_outcome` / `pass` | 机制预期与是否通过（用于正确性断言，不用于延迟指标） |

---

## 6. 指标计算定义（逐字段可复算）

记某单元（场景,组,臂）的 trials 集合为 `T`，`|T| = N = 10`。

### 6.1 Q1 离线可执行性

```
offline_exec_success_rate = |{t ∈ T : t.actual_outcome == "EXECUTED"}| / |T|      （M02）
fail_closed_count         = |{t ∈ T : t.actual_reason ∈ FAIL_CLOSED_REASONS}|      （M02/M03）
FAIL_CLOSED_REASONS = {AUTH_SERVICE_UNREACHABLE, SNAPSHOT_UNAVAILABLE, C_EXPIRED}
（C0/C1/C2 凭证到期统一用 `C_EXPIRED`，与设计文档 §6.3 / H1 判定码一致；C1 短 TTL 只是取值更小，不新增判定码。）
```

### 6.2 Q2 撤销可见延迟（严格分离两个概念）

```
W_risk(t) = (t.t_first_reject - t.t_revoke) * 1000   ms   （t.t_first_reject ≠ NULL）
D_prop(t) = (t.t_snapshot_obtained - t.t_revoke) * 1000 ms （C2，仅当取得含撤销的快照）
```

- `W_risk`：撤销后 Executor **首次拒绝**该 jti 的时间差。若整个观测窗内从未拒绝，`W_risk` 记为 `>` 观测窗上界并单列（不得填成有限值）。
- `D_prop`：仅 C2；若 Executor 始终未取得含该撤销的快照，记 `D_prop = NA_UNOBTAINED`（不得记 0，也不得与 `W_risk` 混用）。
- 单元聚合报告中同时给 `W_risk` 与 `D_prop` 的 median / min / max；**禁止**用其中一个代替另一个。
- 正确性约束：`false_allow`（定义见 6.3）必须单独统计，不能隐藏在延迟值里。

### 6.3 Q3 过期与错误放行

```
expired_snapshot_reject_rate = |{t ∈ M06 : outcome REJECTED ∧ reason SNAPSHOT_UNAVAILABLE}| / |M06|
false_allow_count = |{t : outcome EXECUTED ∧ (
                        (缓存已明确列出该 jti) ∨
                        (缓存 EXPIRED ∧ 未成功刷新) ∨
                        (凭证已过 expires_at) )}|
```

- `false_allow_count` 必须恒为 `0`。非 0 表示正确性缺陷（不是权衡），直接触发第 7 节 NO-GO。
- 区分：旧快照仍 FRESH、未命中撤销时的 EXECUTED **不是** `false_allow`，而是定义内的风险窗口（设计文档 §6.2 / §7）。

### 6.4 Q4 同步成本

```
sync_duration_ms    = median/min/max of perf_counter 测得的一次快照获取+解析耗时
snapshot_payload_bytes = len(canonical_json_bytes(snapshot_payload))
snapshot_verify_ms  = median/min/max of Ed25519 验签墙钟耗时
```

- M13 按 `K ∈ {1,10,100,1000}` 分组报告，观察是否随 `K` 近似线性（线性 = 可接受的累积集合设计；超线性增长触发成本 NO-GO 讨论）。
- B2 每执行 1 次在线查询作为在线成本参照；C2 的在线查询率 = `1/R` 次/单位时间，**必须**显著低于 B2 才能满足 H2-main。

### 6.5 Q5 并发与重复副作用

```
revoked_reject_rate     = |{t ∈ M10 : outcome REJECTED}| / |M10|
duplicate_effect_count  = Σ_t effects_added - (M11 中应为 1；M10 中应为 0)
```

- M10 `revoked_reject_rate` 必须为 `1.0`，`duplicate_effect_count` 必须为 `0`。
- M11 新增副作用必须恰为 `1`（其余 DEDUP_HIT）。违反即 H1 共享消费层被破坏，阻断后续阶段。

---

## 7. C2 失败条件（先冻结判据，再跑实验）——"让 C2 输掉"

> 本节先于任何实验结果写定。以下任一条件成立即 **NO-GO（C2 不值得进入 H2 后续阶段）**；全部不满足且 H2-main 被数据支持，才 **GO**。

### 7.1 NO-GO 条件（C2 输掉的情形）

1. **零在线预算臂**：若部署要求执行端全程零在线查询（纯 air-gap），C2 无法刷新，`W_risk` 退化到 `≤ S` 且必须取 `S ≥ A=60s`；此时 C2 上界不优于 C1（`τ=A=60s`），却多出同步/验签成本 → C2 无价值。
2. **无实质窗口优势**：即使在"间歇可达"臂，C2 的 `W_risk` 相对 C1 的 `τ` 上界**无实质缩小**（判定阈值：`median(W_risk_C2) ≥ 0.5 × τ`，即改善不足 2 倍），不足以抵消其复杂度 → NO-GO。
3. **在线成本塌缩**：若 C2 必须把 `R` 压到接近"每次执行都在线"（即在线查询率接近 B2）才能击败 C1，则 C2 的核心优势（不按次在线）不成立 → NO-GO。
4. **正确性缺陷**：出现任何 `false_allow_count > 0`（M03/M05/M06），或抗回滚/抗伪造/过期 fail closed 任一机制断言失败（H2-b/c/d），属缺陷而非权衡 → 修复前 NO-GO。
5. **成本不可扩展**：`snapshot_payload_bytes` 或 `sync_duration_ms` 随 `K` 超线性增长（如 K 从 100→1000 增长远超 10 倍），在目标规模下不可接受 → NO-GO。

### 7.2 GO 条件（C2 赢的情形，全部满足）

- `false_allow_count == 0`，H2-a/b/c/d 全部通过；
- 在固定 `A=60s` 下，C2 在"间歇可达"臂 `median(W_risk_C2) < 0.5 × τ`（改善 ≥ 2 倍）且 `W_risk` 随 `R` 单调下降可测；
- C2 在线查询率 `1/R` 显著低于 B2 的每次执行查询（判据：`R ≥ 5 s` 且执行间隔 < `R` 时仍满足窗口目标）；
- C2 离线可用窗口 `≥ A`（FRESH 快照下无需在线查询即可执行）；
- 同步成本在目标 `K` 规模下可接受（近似线性）。

### 7.3 诚实结论边界

- 若 C1 的短 TTL 在目标可用性下已足够，应如实给出 **C1 足够 / C2 无增量** 的结论，不得包装成 C2 成功。
- 若两臂结果分叉（纯离线 C1 胜、间歇可达 C2 胜），结论必须表述为**部署条件依赖的权衡**，并指明哪种连通性假设下 C2 才有价值，而非笼统"C2 更好"。
- 一切结论不得外推为全局即时撤销、`exactly-once`、真实第三方 API 行为或真实 Agent 行为（见第 9 节）。

---

## 8. 执行流程、判定纪律与产出

### 8.1 阶段顺序（本阶段只做 0，其余是后续阶段的冻结约定）

- **H2.0（本阶段）**：冻结设计文档 + 本协议；提交推送设计分支。**不写代码**。
- **H2.1（后续）**：按本协议实现 B2/C0/C1/C2 机制（复用 H1 组件、新增可控时钟与快照层），先通过 H2-a/b/c/d 正确性断言，再运行矩阵。
- **H2.2（后续）**：运行 M01–M14，产出 `results/run-001/`，按第 7 节判据给 GO/NO-GO。

### 8.2 判定纪律

- 每单元 `N=10` 为**机制验证**，非统计显著性实验；报告只给描述性统计（median/min/max），不宣称 p 值/置信区间。
- 所有 outcome/reason/effects 均为**实际调用模块后记录**，不得预填预期值；`expected_outcome` 只用于 `pass` 断言。
- C1 不得被弱化（τ 网格与 `A=60s` 固定）；C2 失败门槛不得放松（第 7 节先冻结）。
- 若某场景因机制未实现无法运行，如实标记 `NA_NOT_IMPLEMENTED`，不得跳过或伪造数据。

### 8.3 产出路径（H2.1/H2.2 阶段创建，本阶段不创建）

```
experiments/h2_revocation_management/
  h2_snapshot.py            # 撤销快照构造/规范化/验签/缓存更新（H2.1）
  h2_executor.py            # 复用 H1 execute_c + C2 撤销检查 + 可控时钟（H2.1）
  run_experiment.py         # M01-M14 矩阵（H2.2）
  results/run-001/{trials.csv,summary.json,raw.json}
tests/test_h2_revocation_management.py
docs/H2_REVOCATION_EXPERIMENT_REPORT.md   # H2.2 报告，按第 7 节给 GO/NO-GO
```

### 8.4 复现命令（H2.1/H2.2 阶段生效）

```bash
PYTHONPATH="src;tests;experiments/h2_revocation_management" \
  .venv/Scripts/python experiments/h2_revocation_management/run_experiment.py \
  --output-dir experiments/h2_revocation_management/results/run-001

PYTHONPATH="src;tests;experiments/h2_revocation_management" \
  .venv/Scripts/python -m unittest tests.test_h2_revocation_management -v
```

---

## 9. 边界与禁令（一切汇报/文档必守）

1. 不修改 H1 代码与数据（`ad66150` 冻结）；不修改 E1.9、E2、E3-0 任何冻结成果。
2. 不接入真实 MCP、第三方 API、真实 Agent；只用受控 Sink。
3. 不宣称 C2 实现全局即时撤销、`exactly-once` 或跨执行器全局消费。
4. 不把 `D_prop` 与 `W_risk` 混为一谈；不把"旧快照 FRESH 未命中时的 EXECUTED"伪装成正确放行。
5. 不声称"测试通过 = 形式化证明"；`N=10` 为机制验证，非统计显著性。
6. 不因追求正向结论弱化 C1、放松 C2 失败门槛或预填数据。
7. 本阶段不实现任何机制、不创建实验代码/数据——只冻结本协议与设计文档。

---

**协议冻结结论**：五问已映射到可计算指标，四组参数与场景矩阵已定，统一数据字段已列，`D_prop/W_risk/false_allow` 计算已明确，C2 失败条件（NO-GO 五条）与 GO 条件已先行写定。H2.1 实现与 H2.2 实验按此执行；若 C1 已足够或 C2 无实质增量，将如实给出 NO-GO。
