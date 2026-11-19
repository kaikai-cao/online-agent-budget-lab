# H2.0 实验协议：离线授权下的撤销可见性与有效性控制

> 阶段性质：**实验协议冻结**。本文件冻结 H2.1 实现与 H2.2 实验必须遵循的分组、参数、场景矩阵、数据字段、指标计算与判定纪律。配套设计见 `docs/H2_REVOCATION_DESIGN.md`。
> 纪律：本阶段**不写代码、不改 H1/E1/E2/E3-0、不接真实 MCP、不提前实现机制**。
> 核心立场：**设计一个能够让 C2 输掉的实验**。C2 只有在"以远低于 B2 的在线成本显著降低撤销风险窗口，且不牺牲离线可用性"时才值得进入 H2 后续阶段；否则按本文件第 7 节 NO-GO。
> **H2.0.2 定向补充**（同一分支，仅修订这两份文档，不扩范围）：根据用户第二轮独立核查的三项发现——① HWM 首次启动初始化未定义；② `1/R` 不代表实际在线查询成本；③ 风险窗口公式混用注入逻辑时钟与墙钟、变量无复算口径。补充点分布于 §1.2/§2/§4/§5/§6/§7/§8/§9。**四组机制、C1 TTL 语义、C2 快照格式、NO-GO 五条判据与实验分组均不改变**；H2.0.1 已认可的全部结论继续保留。

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

### 1.2 辅助假设（机制正确性，任一失败即阻断 H2.1）

- **H2-a（四组安全条件一致）**：四组共用同一动作绑定、同一受控 Sink、同一撤销触发；除"授权验证 + 撤销处理"层外无差异（设计文档 §2.2）。
- **H2-b（快照抗回滚/抗伪造，含重启）**：旧版本（含 Executor 重启后重放）、错误密钥、过期、未生效、畸形快照一律被拒且缓存/ HWM 不变；重启后 HWM 从持久状态恢复，状态不可确认时 fail closed（设计文档 §5.2/§5.4）。
- **H2-c（过期 fail closed、无错误放行）**：快照过期且无法刷新时拒绝执行；所用快照明确列出撤销时绝不因陈旧而放行（设计文档 §6.2）。
- **H2-d1（C2 撤销状态检查）**：C2 中，只要所用快照明确列出该 jti（已知撤销），任何执行（含并发）都不得放行。仅限 C2。
- **H2-d2（四组共享原子消费）**：同一 jti 并发执行最多产生一次副作用（H1 原子消费层不变）。四组均适用，与撤销检查无关。
- **H2-e（B2 竞态被如实测量）**：B2 撤销检查线性化于查询响应时刻；查询通过后撤销仍可能产生一次副作用，该窗口须由 M15 记录，不得描述为"即时拒绝"（设计文档 §6.4）。
- **H2-f（首次信任建立正确）**：首次启动须经可信 bootstrap 建立初始快照/HWM/`initialized`（默认 BOOT-ONLINE，可选 BOOT-OFFLINE 可信预置）；新鲜度不由验签单独建立；初始化后重启只恢复、不自动重建；已初始化而状态不可确认时 fail closed。M07d 验证首次启动不被陈旧快照欺骗（设计文档 §5.5）。
- **H2-g（刷新成本如实计量）**：实际在线请求数用独立计数器记录，不以 `1/R` 代替；刷新失败且缓存未过期时重试导致的高请求率必须计入成本（设计文档 §5.3.5 / 本协议 §6.4）。

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
| C2 | 同上 | 刷新间隔 `R` | `{5, 30, 120} s` 扫描 | `R <= S` 硬约束；`R = 120 = S` 为"仅到期才刷新"的边界臂 |
| C2 | 同上 | 持久化 HWM | 启用（默认） | 高水位版本持久化 + 重启恢复；状态不可确认时 fail closed（设计 §5.4） |
| C2 | 同上 | 首次信任建立 | `BOOT_ONLINE`（默认）/ `BOOT_OFFLINE`（可选） | 三态 bootstrap；`initialized` 一次性；默认不新分组，仅两种初始化路径（设计 §5.5） |
| 通用 | 目标离线可用性 `A` | 头对头固定量 | `60 s` | 判 C2/C1 时的共同可用性目标（第 7 节） |
| 通用 | 机制重复次数 `N` | 每(场景,组,臂)单元 | `10` | 机制验证，非统计显著性 |

**两个时间体系（禁止跨体系相加，设计 §7.1 / §8.3）**：
- **逻辑时间（注入时钟，s）**：`t_issue/t_revoke/t_exec_attempt/t_snapshot_generated/t_snapshot_obtained/t_first_reject/t_last_refresh_local/t_query/t_consume` 及快照 `generated_at/valid_from/valid_until`。由**单一测试进程的可控时钟注入**产生（沿用 H1 `now` 注入风格），不用 `sleep`；**所有窗口与延迟指标（`W_risk`/`D_prop`/`age`）只由此体系计算**。
- **墙钟时间（`perf_counter`，ms）**：`sync_duration_ms/snapshot_verify_ms/refresh_latency_ms/observation_wall_seconds`，仅用于成本类指标（§6.4）。**不得与逻辑时间量相加得到窗口数值**；刷新墙钟耗时不进入 `W_risk` 公式（实测口径见 §6.2，理论上界见设计 §7.1）。

**刷新语义（与执行路径衔接，设计 §5.3）**：C2 每次执行前先判断 `age = now - t_last_refresh_local` 与 `R`、`valid_until`；`refresh_due`（无缓存 / `age>=R` / 已过期）时才在线刷新，每次执行**最多一次刷新尝试**。刷新结果分为 `REFRESH_SUCCESS` / `REFRESH_FAILED_STALE_CONTINUE`（缓存未过期，沿用旧快照但窗口受 S 约束）/ `REFRESH_FAILED_FAIL_CLOSED` / `NO_REFRESH_NEEDED` 四类，**分别记录**。失败路径均**不更新** `t_last_refresh_local`，也不做进程内即时重试；下一次执行重新判断，因此服务持续不可用时实际请求率可远高于 `1/R`（设计 §5.3.5）。`R` 不得直接当作风险窗口，也**不得当作实际请求率**（设计 §7.1 / §6.4）。

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
| M02 `offline_exec` | 服务不可达，凭证/快照仍有效 | 全部 | B2 REJECT（fail closed）；C0 EXECUTED；C1 τ 内 EXECUTED；C2 `age<R` 或刷新失败但缓存未过期、未命中撤销 → EXECUTED | Q1 |
| M03 `offline_expired` | 服务不可达且已越过 TTL/快照有效期 | 全部 | C1 REJECT `C_EXPIRED`（短 TTL 到）；C2 REJECT `SNAPSHOT_UNAVAILABLE`；C0 超长 TTL 后 REJECT `C_EXPIRED`；B2 REJECT `AUTH_SERVICE_UNREACHABLE` | Q1/Q3 |
| M04 `revoke_then_online` | 签发后撤销，服务在线，允许刷新 | 全部 | B2 REJECT（**仅当撤销发生在查询响应前**；见 M15）；C0 EXECUTED；C1 τ 内 EXECUTED；C2 刷新成功后 `REVOKED_BY_SNAPSHOT` REJECT | Q2 |
| M05 `revoke_then_offline` | 签发后撤销，服务离线，持有未过期旧快照 | 全部 | B2 REJECT（fail closed）；C0/C1 有效期内 EXECUTED；C2 走 `REFRESH_FAILED_STALE_CONTINUE` 且未命中 → EXECUTED（即路径 B 风险窗口） | Q2 |
| M06 `stale_snapshot_expiry` | C2 缓存 EXPIRED 且离线、无刷新 | C2 | REJECT `SNAPSHOT_UNAVAILABLE`，0 错误放行 | Q3 |
| M07a `rollback_restart_inprocess` | 进程内注入合法签名但旧版本的快照 | C2 | 候选 REJECT `SNAPSHOT_VERSION_STALE`（`version <= HWM`）；缓存/HWM 不变；若所用快照已列该 jti 则仍拒绝执行 | Q3/Q5/H2-b |
| M07b `rollback_after_restart` | 接受 v11（含 jti-B 撤销）→ 重启（持久 HWM=11）→ 重放合法签名 v10（不含 jti-B） | C2 | v10 REJECT `SNAPSHOT_VERSION_STALE`；jti-B 撤销保持；对 jti-B 执行被 `REVOKED_BY_SNAPSHOT` 拒绝 | H2-b |
| M07c `state_unreadable` | 已初始化后重启（`initialized=1`），持久状态缺失 / 损坏 / 摘要不符（S2） | C2 | Fail Closed `SNAPSHOT_STATE_UNAVAILABLE`；HWM 不得置 0；**不自动重新 bootstrap**；0 副作用 | H2-b/H2-f |
| M07d `bootstrap_replay` | 首次启动（S0，`initialized` 未设置）时经不可信通道注入合法签名但陈旧的快照 | C2 | 不可信通道 → `SNAPSHOT_UNTRUSTED`，**不得作为初始状态**；BOOT-ONLINE 只认可信 TLS 拉取的当前快照；初始化成功后原子落 `initialized=1`、HWM、摘要；其后重启重放陈旧快照 → `SNAPSHOT_VERSION_STALE` | H2-b/H2-f |
| M08 `forged_snapshot` | 注入错误密钥签名的高版本快照 | C2 | 候选 REJECT `SNAPSHOT_SIGNATURE_INVALID`；缓存不变 | Q5 |
| M09 `malformed_snapshot` | 注入过期 / 未生效 / 畸形（乱序 jti、非有限浮点）快照 | C2 | 分别 REJECT `SNAPSHOT_EXPIRED` / `SNAPSHOT_NOT_YET_VALID` / `SNAPSHOT_MALFORMED`；缓存不变 | Q3 |
| M10 `concurrent_revoked` | 撤销 jti + N 并发执行（**分组预期见下**） | 全部 | B2 REJECT（查询时刻已撤销）；C0 EXECUTED；C1 EXECUTED；C2 快照命中撤销 REJECT；**四组均最多 1 副作用** | Q5/H2-d1/d2 |
| M11 `concurrent_legal` | 合法 jti，N 并发执行 | 全部 | 恰 1×EXECUTED、其余 DEDUP_HIT；新增副作用 1 | Q5/H2-d2 |
| M12 `claim_tamper` | 篡改参数/Schema/Server/Executor/issuer/audience/key_id | 全部 | 全部 REJECT（绑定/信任锚，与 H1 一致） | 一致性 |
| M13 `sync_cost_scaling` | 撤销集合规模 `K ∈ {1,10,100,1000}` 下测同步成本 | C2（B2 参考） | 记录耗时/字节/验签耗时，观察是否随 K 近似线性 | Q4 |
| M14 `head_to_head_c1_c2` | 头对头：纯离线 vs 间歇可达，固定可用性目标 `A=60s` | C1,C2 | 见第 7 节判据；`W_risk` **分臂、分刷新结果类别**报告 | NO-GO |
| M15 `b2_query_consume_race` | B2 查询通过后暂停 → revoke → 恢复 → 观察 | B2 | `ALLOW` 已返回则执行仍完成（记录 `b2_race_effect_count` 与 `t_consume-t_query`）；**已知边界，非缺陷** | H2-e |

> **M10 分组预期（纠正 H2.0 冲突）**：C0/C1 没有撤销快照，定义上允许"签发后、凭证过期前继续执行"（见 M05），因此它们**不应**被要求识别撤销——执行是设计限制，不是实现缺陷。合理预期：
>
> | 分组 | M10 合理预期 | 副作用 |
> |---|---|---|
> | B2 | 在线查询时刻撤销已发生 → REJECT | 0 |
> | C0 | 有效凭证仍可能 EXECUTED | ≤ 1（原子消费） |
> | C1 | 有效凭证仍可能 EXECUTED | ≤ 1（原子消费） |
> | C2 | 所用快照列出该 jti → `REVOKED_BY_SNAPSHOT` REJECT | 0 |
>
> 因此 Q5 的 `revoked_reject_rate` **不再要求四组都为 1.0**；只有 B2/C2 的撤销检查性质（H2-d1 对 C2、查询时刻语义对 B2）要求拒绝，C0/C1 只受 H2-d2 原子消费约束。

> M14 是判定 H2-main 的关键场景，须同时覆盖两种连通性（`W_risk` 按设计 §7.1 分路径推导，不得用单一 `R` 代替）：
> - **纯离线 / 刷新失败但缓存未过期（路径 B）**：C1 `τ=A=60s` 给 `W_risk ≤ 60s`；C2 设 `S=120s ≥ A`，走 `REFRESH_FAILED_STALE_CONTINUE` 直到过期 fail closed，`W_risk ≤ S - (t_revoke - t_snapshot_generated)`（最坏趋近 `S=120s`）。此臂 C2 **可能输**。
> - **间歇可达且刷新成功（路径 A）**：C1 仍 `W_risk ≤ τ`；C2 在 `age>=R` 的执行前刷新中拉到含撤销快照。路径 A 预期风险窗口随 `R` 缩小，但**不提供任何上界表达式**；具体 `W_risk = t_first_reject - t_revoke` 一律实测（§6.2）。此臂 C2 **可能赢**，但必须用实测 `actual_refresh_request_rate`（而非 `1/R`）证明在线成本低于 B2（§6.4）。
> - 报告须按 `REFRESH_SUCCESS` / `REFRESH_FAILED_STALE_CONTINUE` 分别统计 `W_risk` 的 median/min/max；合并统计会掩盖两条路径的相反结论。

---

## 5. 统一数据字段（逐 trial 记录，实际观测非预填）

每次 trial 写入 `trials.csv`；聚合写 `summary.json`；细节（快照/时间戳/缓存前后）写 `raw.json`。字段如下（不适用组填 `NA`，未发生填 `NULL`）：

### 5.1 标识与配置

| 字段 | 含义 |
|---|---|
| `run_id` / `scenario_id` / `group` / `arm` / `trial_idx` | 运行、场景（M01…）、分组（B2/C0/C1/C2）、参数臂（如 `tau=15` / `R=30`）、重复序号 |
| `jti` / `action_digest` | 一次性授权标识、动作摘要 |
| `ttl_s` / `tau_s` / `snapshot_validity_s` / `refresh_interval_s` | 凭证 TTL、C1 短 TTL、C2 快照有效时长 `S`、刷新间隔 `R` |
| `bootstrap_mode` | C2 首次信任建立方式：`BOOT_ONLINE` / `BOOT_OFFLINE` / `NA`（非 C2）；默认 BOOT-ONLINE（设计 §5.5） |
| `revocation_set_size` | 快照中撤销 jti 数量 `K`（M13 用） |

### 5.2 逻辑时间戳（注入时钟，单位 s）

| 字段 | 含义 |
|---|---|
| `t_issue` / `t_revoke` | 签发 / 撤销时刻（`t_revoke` 未撤销为 `NULL`） |
| `t_exec_attempt` | 执行验证时刻 |
| `t_snapshot_generated` / `t_snapshot_obtained` | 服务生成快照 / Executor 取得含该撤销记录的快照时刻（C2） |
| `t_first_reject` | 撤销后首次拒绝该 jti 的时刻（用于 `W_risk`） |
| `t_last_refresh_local` / `age_at_exec` | 上次成功刷新的本地时刻 / `t_exec_attempt - t_last_refresh_local`（设计 §5.3） |
| `t_query` / `t_consume` | B2 查询响应时刻 / Sink 原子消费时刻（M15，设计 §6.4） |
| `service_online` / `refresh_allowed` | 服务是否可达 / 本次是否允许刷新（bool） |

### 5.3 结果与实际观测量

| 字段 | 含义 |
|---|---|
| `actual_outcome` | `EXECUTED` / `REJECTED` / `DEDUP_HIT` / `ROLLED_BACK` / `NA` |
| `actual_reason` | 冻结判定码（如 `REVOKED_BY_SNAPSHOT`、`SNAPSHOT_UNAVAILABLE`、`SNAPSHOT_VERSION_STALE`） |
| `effects_added` | 本次 trial 新增副作用数（实际计数） |
| `snapshot_version_cached` / `snapshot_version_candidate` / `snapshot_valid_until` | C2 缓存/候选版本与缓存有效期（`snapshot_valid_until` 为**注入逻辑时钟**秒，等于 `t_snapshot_generated + S`，可复算） |
| `high_water_version` / `executor_restarted` / `snapshot_state_ok` | 持久化高水位版本 / 本次是否跨重启 / 持久状态是否可确认（M07b/c，设计 §5.4） |
| `initialized` / `bootstrap_snapshot_version` | 持久层初始化标记 / bootstrap 建立的初始 HWM（M07d，设计 §5.5）；非 C2 或非首次填 `NA` |
| `snapshot_accepted` | 候选是否被接受（C2，bool） |
| `refresh_outcome` | `REFRESH_SUCCESS` / `REFRESH_FAILED_STALE_CONTINUE` / `REFRESH_FAILED_FAIL_CLOSED` / `NO_REFRESH_NEEDED` / `NA`（非 C2） |
| `refresh_attempts` | 本次执行实际发起的在线刷新尝试次数（整数，0 表示 `NO_REFRESH_NEEDED`；失败重试计入，设计 §5.3.5） |
| `refresh_latency_ms` | 本次刷新的 `perf_counter` 墙钟耗时（**仅成本 §6.4，不进入 `W_risk`**）；未刷新填 `NULL` |
| `w_risk_path` | `ONLINE_REFRESH_OK`（路径 A）/ `OFFLINE_STALE_CONTINUE`（路径 B）/ `NO_FURTHER_EXEC` / `NA` |
| `b2_race_effect_count` | M15 中查询通过后撤销、恢复执行是否仍产生副作用（0/1，仅 B2） |
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

**唯一复算口径（实验数据、median/min/max、第 7 节判定一律用此式；均为注入逻辑时钟）**：

```
W_risk(t) = (t.t_first_reject - t.t_revoke) * 1000   ms   （t.t_first_reject ≠ NULL）
D_prop(t) = (t.t_snapshot_obtained - t.t_revoke) * 1000 ms （C2，仅当取得含撤销的快照）
```

- `W_risk`：撤销后 Executor **首次拒绝**该 jti 的时间差。若整个观测窗内从未拒绝，`W_risk` 记为 `>` 观测窗上界并单列（不得填成有限值、不得填 0）。
- `D_prop`：仅 C2；若 Executor 始终未取得含该撤销的快照，记 `D_prop = NA_UNOBTAINED`（不得记 0，也不得与 `W_risk` 混用）。
- **C2 必须按 `w_risk_path` 分层报告**（设计 §7.1）：
  - `ONLINE_REFRESH_OK`（路径 A，对应 `refresh_outcome=REFRESH_SUCCESS`）；
  - `OFFLINE_STALE_CONTINUE`（路径 B，对应 `REFRESH_FAILED_STALE_CONTINUE` 或全程无刷新）；
  - 分别给 median / min / max；**禁止**跨路径合并成一个"C2 风险窗口"，也**禁止**用 `R` 直接作为 C2 的风险窗口。
- **上界口径（不参与复算 / 判定）**：设计 §7.1 仅为路径 B 保留一个**同属注入逻辑时钟**的上界 `min(snapshot_valid_until, t_snapshot_obtained) - t_revoke`（纯逻辑量、可复算，但只作趋势分析）；**路径 A 不提供任何上界表达式**——在线刷新成功时风险窗口预期随 `R` 缩小，具体数值只能由 `t_first_reject - t_revoke` 实测。墙钟 `refresh_latency_ms` 只用于成本，**不得与逻辑时间量相加得到报告用的 `W_risk`**，也不得据任何表达式反推报告值。判定与结论只用上面的实测式。
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
- 区分：旧快照未过期、未命中撤销时的 EXECUTED（含 `REFRESH_FAILED_STALE_CONTINUE`）**不是** `false_allow`，而是定义内的路径 B 风险窗口（设计 §6.2 / §7.1）；但"所用快照已明确列出该 jti 仍 EXECUTED"、或"快照已过期仍 EXECUTED"、或"凭证已过期仍 EXECUTED"都是 `false_allow`。
- `SNAPSHOT_STATE_UNAVAILABLE`（重启后持久状态不可确认）必须 fail closed；若此时产生副作用，计入 `false_allow_count`。

### 6.4 Q4 同步成本与实际在线请求负担

**单次同步成本（墙钟，`perf_counter`）**：

```
sync_duration_ms       = median/min/max of perf_counter 测得的一次快照获取+解析耗时
snapshot_payload_bytes = len(canonical_json_bytes(snapshot_payload))
snapshot_verify_ms     = median/min/max of Ed25519 验签墙钟耗时
```

**实际在线请求成本（五个独立指标，禁止用 `1/R` 代替）**：

```
refresh_attempt_count       = Σ_t t.refresh_attempts                    （单元内实际刷新尝试总次数）
refresh_success_count       = |{t : refresh_outcome == REFRESH_SUCCESS}|
refresh_failure_count       = |{t : refresh_outcome ∈ {REFRESH_FAILED_STALE_CONTINUE,
                                   REFRESH_FAILED_FAIL_CLOSED}}|
actual_refresh_request_rate = refresh_attempt_count / observation_wall_seconds  （次/秒，墙钟）
successful_refresh_interval = 相邻两次 REFRESH_SUCCESS 的 t_last_refresh_local 差（注入逻辑时钟，s；与 R 同体系）
```

其中 `observation_wall_seconds` 为该单元从首个 trial 到末个 trial 的 `perf_counter` 墙钟时长（实测）。

- **冻结的失败重试策略（保证可复现）**：每次执行前若 `refresh_due` 则**最多尝试一次**在线刷新；失败不更新 `t_last_refresh_local`、不做进程内即时重试，下一次执行重新判断（设计 §5.3.5）。该策略使实际请求数直接由执行频率与可用性决定，如实计量；本阶段不引入退避设施。
- `1/R` 仅是"刷新每次都成功"时的目标频率；服务持续不可用时 `actual_refresh_request_rate` 可远高于 `1/R`（`R=5 s`、每秒一次执行、全程不可达时接近 1 次/秒）。**成本判定一律用实测计数器**。
- `refresh_attempts` 与 `refresh_latency_ms` 逐 trial 记录；`refresh_latency_ms` 为墙钟量，**不参与 `W_risk` 计算**（§6.2）。
- `successful_refresh_interval` 用注入逻辑时钟，与 `R` 同体系便于对照；`actual_refresh_request_rate` 用墙钟反映真实资源消耗；两者不得混用。
- M13 按 `K ∈ {1,10,100,1000}` 分组报告单次同步成本，观察是否随 `K` 近似线性（线性 = 可接受的累积集合设计；超线性增长触发成本 NO-GO 讨论）。
- B2 每执行 1 次在线查询作为在线成本参照；判 C2 是否"远低于 B2"必须用 `actual_refresh_request_rate` 与 B2 实测查询率对照，**不是** `1/R`。

### 6.5 Q5 并发、撤销状态检查与重复副作用（按 H2-d 拆分）

```
revoked_reject_rate_C2  = |{t ∈ M10, group=C2 : outcome REJECTED}| / |M10(C2)|     -- 须为 1.0（H2-d1）
revoked_reject_rate_B2  = |{t ∈ M10, group=B2 : outcome REJECTED}| / |M10(B2)|     -- 须为 1.0（撤销在查询响应前）
revoked_exec_rate_C0_C1 = |{t ∈ M10, group∈{C0,C1} : outcome EXECUTED}| / |...|     -- 允许 >0（设计限制，非缺陷）
duplicate_effect_count  = 每个 jti 的 effects_added（M10/M11 均须 ≤ 1）            -- H2-d2，四组通用
b2_race_effect_count    = M15 中查询通过后撤销、恢复执行的副作用数（0 或 1）          -- H2-e，记录非断言
```

- **纠正 H2.0 冲突**：M10 不再要求"全部组 REJECT"。C0/C1 无撤销快照，按定义仍可能执行有效凭证（与 M05 一致），记入 `revoked_exec_rate_C0_C1`，**不计为缺陷**；只有 C2（已知撤销不得放行，H2-d1）与 B2（撤销在查询时刻已发生）要求 `revoked_reject_rate = 1.0`。
- `duplicate_effect_count`：M10 四组都须 ≤ 1（C2/B2 应为 0，C0/C1 最多 1）；M11 新增副作用必须恰为 1（其余 DEDUP_HIT）。违反即 H1 共享消费层被破坏，阻断后续阶段。
- M15 的 `b2_race_effect_count = 1` 是**已记录的已知边界**（设计 §6.4），不触发 NO-GO；若观测为 0 也须如实记录并解释（如屏障时机差异）。

---

## 7. C2 失败条件（先冻结判据，再跑实验）——"让 C2 输掉"

> 本节先于任何实验结果写定。以下任一条件成立即 **NO-GO（C2 不值得进入 H2 后续阶段）**；全部不满足且 H2-main 被数据支持，才 **GO**。

### 7.1 NO-GO 条件（C2 输掉的情形）

1. **零在线预算 / 纯离线臂（路径 B）**：若部署要求执行端全程零在线查询，C2 只能走 `REFRESH_FAILED_STALE_CONTINUE`，理论上界 `W_risk ≲ min(snapshot_valid_until, t_snapshot_obtained) - t_revoke`（主要由 `S` 决定，设计 §7.1）且须 `S ≥ A=60s`；判定仍用实测 `W_risk`（§6.2）。此时 C2 上界不优于 C1（`τ=A=60s`），却多出同步/验签成本 → C2 无价值。
2. **无实质窗口优势**：即使在"间歇可达 + 刷新成功（路径 A）"臂，C2 的 `ONLINE_REFRESH_OK` 类 `W_risk` 相对 C1 的 `τ` 上界**无实质缩小**（判定阈值：`median(W_risk_C2, ONLINE_REFRESH_OK) ≥ 0.5 × τ`，即改善不足 2 倍），不足以抵消其复杂度 → NO-GO。禁止用路径 B 的较大值或跨路径合并值参与此判定。
3. **在线成本塌缩**：若 C2 的实测 `actual_refresh_request_rate` 接近 B2 的每次执行查询率（**含刷新失败重试带来的额外请求**）才能击败 C1，则 C2 的核心优势（不按次在线）不成立 → NO-GO。判据以实测计数器为准，**不以 `1/R` 理论值代替**；须在"间歇可达"臂的可用时段计量，并在"全程不可达"臂单列 `refresh_failure_count` 与 `actual_refresh_request_rate`，不得隐藏重试成本。
4. **正确性缺陷**：出现任何 `false_allow_count > 0`（M03/M05/M06/M07c），或抗回滚/抗伪造/重启重放/**首次启动注入**/过期 fail closed 任一机制断言失败（H2-b/c/d1/f），属缺陷而非权衡 → 修复前 NO-GO。**注意**：C0/C1 在 M10 执行有效凭证、B2 在 M15 竞态产生副作用，均为设计限制/已知边界，**不计入**本条。
5. **成本不可扩展**：`snapshot_payload_bytes` 或 `sync_duration_ms` 随 `K` 超线性增长（如 K 从 100→1000 增长远超 10 倍），在目标规模下不可接受 → NO-GO。

### 7.2 GO 条件（C2 赢的情形，全部满足）

- `false_allow_count == 0`，H2-a/b/c/d1/d2/e/f/g 全部通过（H2-e 为"如实测量即通过"，非"无副作用"；H2-g 为"如实计量请求数即通过"，非"请求数必须低"）；
- 在固定 `A=60s` 下，C2 在"间歇可达 + 刷新成功（路径 A）"臂 `median(W_risk_C2 | ONLINE_REFRESH_OK) < 0.5 × τ`（改善 ≥ 2 倍）且该值随 `R` 单调下降可测；
- C2 实测 `actual_refresh_request_rate` 显著低于 B2 的每次执行查询率（判据：`R ≥ 5 s` 且执行间隔 < `R` 时仍满足窗口目标；**失败重试请求一并计入**，不以 `1/R` 理论值代替）；
- C2 离线可用窗口 `≥ A`（`age<R` 或 `REFRESH_FAILED_STALE_CONTINUE` 且 `now<valid_until` 时无需在线查询即可执行，窗口由 `S` 决定）；
- 重启后 HWM 正确恢复（M07b/c 通过），旧快照重放被拒；首次启动经可信 bootstrap 建立初始状态、不可信通道注入被拒（M07d 通过，H2-f）；
- 同步成本在目标 `K` 规模下可接受（近似线性）。

### 7.3 诚实结论边界

- 若 C1 的短 TTL 在目标可用性下已足够，应如实给出 **C1 足够 / C2 无增量** 的结论，不得包装成 C2 成功。
- 若两臂结果分叉（纯离线 C1 胜、间歇可达 C2 胜），结论必须表述为**部署条件依赖的权衡**，并指明哪种连通性假设下 C2 才有价值，而非笼统"C2 更好"。
- 一切结论不得外推为全局即时撤销、`exactly-once`、真实第三方 API 行为或真实 Agent 行为（见第 9 节）。

---

## 8. 执行流程、判定纪律与产出

### 8.1 阶段顺序（本阶段只做 0，其余是后续阶段的冻结约定）

- **H2.0 / H2.0.1 / H2.0.2（本阶段）**：冻结设计文档 + 本协议，完成四项有边界回修与三项定向补充；提交推送设计分支。**不写代码**。
- **H2.1（后续）**：按本协议实现 B2/C0/C1/C2 机制（复用 H1 组件、新增可控时钟、快照层、持久化 HWM 与 bootstrap、B2 屏障钩子、刷新计数器），先通过 H2-a/b/c/d1/d2/e/f/g 正确性断言，再运行矩阵。
- **H2.2（后续）**：运行 M01–M15（M07 含 a/b/c/d 子场景），产出 `results/run-001/`，按第 7 节判据给 GO/NO-GO。

### 8.2 判定纪律

- 每单元 `N=10` 为**机制验证**，非统计显著性实验；报告只给描述性统计（median/min/max），不宣称 p 值/置信区间。
- 所有 outcome/reason/effects 均为**实际调用模块后记录**，不得预填预期值；`expected_outcome` 只用于 `pass` 断言。
- C1 不得被弱化（τ 网格与 `A=60s` 固定）；C2 失败门槛不得放松（第 7 节先冻结）。
- C2 的 `W_risk` 必须按 `w_risk_path` / `refresh_outcome` 分层记录与报告；缺失分层字段的 trial 视为数据不完整。
- `W_risk/D_prop` 只由注入逻辑时钟时间戳计算；墙钟 `refresh_latency_ms` 只进成本统计，**不得**与逻辑时间相加或从理论上界反推一个"报告值"（§6.2）。
- 在线成本必须用实测 `refresh_attempts` / `actual_refresh_request_rate` 报告，**不得以 `1/R` 代替**；M07d 须如实记录 `bootstrap_mode` 与 `initialized`（§6.4 / 设计 §5.5）。
- 若某场景因机制未实现无法运行，如实标记 `NA_NOT_IMPLEMENTED`，不得跳过或伪造数据。

### 8.3 产出路径（H2.1/H2.2 阶段创建，本阶段不创建）

```
experiments/h2_revocation_management/
  h2_snapshot.py            # 撤销快照构造/规范化/验签/缓存更新（H2.1）
  h2_snapshot_state.py      # 持久化 HWM + 缓存摘要 + initialized + 三态恢复/bootstrap（H2.1，设计 §5.4/§5.5）
  h2_executor.py            # 复用 H1 execute_c + C2 执行前刷新/撤销检查 + 可控时钟 + 刷新计数器（H2.1）
  run_experiment.py         # M01-M15 矩阵（含 M07a/b/c/d、M15；H2.2）
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
3. 不宣称 C2 或 B2 实现全局即时撤销、`exactly-once` 或跨执行器全局消费；B2 存在查询—消费 TOCTOU 窗口（M15），不得描述为"即时拒绝"。
4. 不把 `D_prop` 与 `W_risk` 混为一谈；不把 `R` 当作 C2 统一风险窗口；不把"旧快照未过期、未命中撤销时的 EXECUTED（含 `REFRESH_FAILED_STALE_CONTINUE`）"伪装成正确放行，也不把它误判为 `false_allow`。
5. 不声称"测试通过 = 形式化证明"；`N=10` 为机制验证，非统计显著性。
6. 不因追求正向结论弱化 C1、放松 C2 失败门槛、跨路径合并 `W_risk` 或预填数据。
7. 不把 C0/C1 在 M10 执行有效凭证当作实现缺陷（设计限制）；不把 B2 在 M15 竞态产生副作用当作 NO-GO 缺陷（已知边界）。
8. 本阶段不实现任何机制、不创建实验代码/数据——只冻结本协议与设计文档。
9. 不把 S0 首次初始化与 S2 状态损坏混为一谈：不因"数据库无 `snapshot_state`"就自动重新 bootstrap，也不不加区分地直接 fail closed（§5.5 / M07c/d）。
10. 不以 `1/R` 代表实际在线成本，不把墙钟刷新耗时与注入逻辑时钟量相加得到 `W_risk`（§6.2 / §6.4 / 设计 §7.1）。

---

**协议冻结结论（H2.0.2 补充版）**：五问已映射到可计算指标，四组参数与场景矩阵（M01–M15，M07 含 a/b/c/d）已定，统一数据字段（含刷新结果分类、HWM/重启、**bootstrap 三态**、**刷新尝试计数与墙钟耗时**、B2 竞态字段）已列；`W_risk/D_prop` **统一用注入逻辑时钟实测计算**并按 `w_risk_path` 分层，理论上界只作趋势分析不参与复算/判定；`false_allow` 计算明确，五个实际刷新成本指标（§6.4）与失败重试策略已冻结；C2 失败条件（NO-GO 五条）与 GO 条件**未改变**，仅把其中"在线成本"口径由 `1/R` 收敛为实测计数器；H2-d 拆为 d1/d2、H2-e（B2 竞态如实测量）、**H2-f（首次信任建立）/H2-g（刷新成本如实计量）** 已列。设计文档与本协议相互一致，四项 + 三项独立核查发现已全部落地。H2.1 实现与 H2.2 实验按此执行；若 C1 已足够或 C2 无实质增量，将如实给出 NO-GO。
