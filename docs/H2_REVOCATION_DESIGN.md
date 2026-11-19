# H2.0 撤销管理设计冻结：离线授权下的撤销可见性与有效性控制

> 阶段性质：**设计冻结（Revocation Design Freeze）**。本阶段只定义撤销语义、失败行为与实验边界，**不修改任何生产代码、不修改 H1 代码与数据、不接入真实 MCP / 第三方 API、不提前实现未经定义的机制**。
> 冻结基线：从 H1 最终提交 `ad66150f43a46e70ad956b6e0b676f328eb549d8`（`research/h1-authorization-binding` 分支）创建独立分支 `research/h2-revocation-management`；本设计以 H1 报告 `docs/H1_MINIMUM_FEASIBILITY.md` 与 `experiments/h1_authorization_binding/` 为事实来源。
> 配套文档：`docs/H2_EXPERIMENT_PROTOCOL.md`（实验矩阵、指标计算、可证伪判据）。

---

## 0. 一句话问题与冻结立场

**唯一研究问题**：在授权服务不可用时，能否让 Executor 继续离线验证授权，同时把"授权撤销的可见性延迟"控制在一个**可测量、可配置**的范围内？

冻结立场（贯穿全文，禁止在后续阶段漂移）：

1. H2 **不消除**撤销延迟，只把延迟变成可观测、可配置的系统参数。
2. C2 的撤销快照是一个**状态分发机制**，不是"全局即时撤销"，不是 `exactly-once`，也不改变 H1 已冻结的"消费与副作用同事务、一次性消费仅限单一 Executor 本地存储"边界。
3. 本阶段的目标**不是证明 C2 更好**，而是冻结一个**能让 C2 输掉**的设计——因此 C1 短 TTL 对照必须保留，且 C2 的失败条件必须先写死（见实验协议第 7 节）。

---

## 1. H1 现状复查（事实基线，仅引用不修改）

下表是 H2 设计所依赖的 H1 现有实现，逐项来自冻结提交 `ad66150` 的源码，H2 **不改动**其中任何一行。

| 组件 | 文件 | 与 H2 相关的事实 |
|---|---|---|
| 授权对象 | `h1_protocol.py` | `AuthorizationObject` 字段：`executor_id/server_uri/tool_name/schema_hash/arguments/action_digest/jti/issued_at/expires_at`；`action_digest` 只绑定五个身份字段，`jti/issued_at/expires_at` 是授权元数据、在 C 凭证中单独签名。 |
| 凭证载荷 | `h1_protocol.py` | `credential_payload()` = `{domain:"h1-authorization-credential-v1", version:1, issuer, audience, key_id, ...授权对象全部字段}`；域分离靠固定 `domain` 字段。 |
| 规范化与摘要 | `src/online_budget/canonical.py` | `canonical_json_bytes()`（`sort_keys`、紧凑分隔符、`ensure_ascii=False`、`allow_nan=False`）；`digest()` 返回 `"sha256:"+hex`；`b64encode/b64decode`；`Ed25519` 验签。 |
| 授权服务 | `h1_authorization_service.py` | `confirm()` 生成 `issued_at`/`expires_at=issued_at+ttl_seconds`；`revoke(jti)` 把记录置 `REVOKED`；`query_online()` 检查存在/撤销/过期/digest/executor；`issue_credential()` 有**签发入口约束**（`UNKNOWN_JTI`/`REVOKED`/`EXPIRED` 拒绝签发，见 `CredentialIssuanceError`）。 |
| B2 验证 | `h1_authorization_service.py` | `B2OnlineVerifier.verify()` 走真实 localhost TCP + TLS、固定**服务器证书指纹**、不可达/指纹不符即 fail closed；B2 **不签发应用层凭证**。 |
| C 验证入口 | `h1_executor.py` | `Executor.execute_c()`：校验 domain/version/issuer/audience/key_id、用**预置** `trusted_keys[key_id]` 验签、检查 `expires_at`/`issued_at`、重算 `action_digest` 与签名声明比对；拒绝请求携带的公钥。 |
| 一次性消费 | `h1_sink.py` | `ControlledSink.consume_and_effect()`：`jti` 主键 + `BEGIN IMMEDIATE`，消费与受控副作用**同一事务**；顺序/并发/崩溃回滚下最多一次副作用。 |
| 测试框架 | `tests/test_h1_authorization_binding.py` | `unittest`（23 项，含 4 项签发约束）；runner `run_experiment.py` 以每场景独立 `Harness`（各自 service/TLS/sink）、注入 `now` 参数做时间控制；输出 `trials.csv/summary.json/raw.json`。 |

**H1 已冻结的核心权衡（H2 的出发点）**：C 相对 B2 唯一可归因增量是"授权服务不可达时仍可离线验签执行"；对称代价是"签发后撤销无法即时感知"（H1 报告 §6/§8）。H2 的全部工作就是在该代价上做**受控改进与量化**，不推翻、不重写 H1 结论。

**H2 对 H1 时间控制的沿用**：H1 已在 `confirm()/issue_credential()` 支持 `now` 注入，但 `Executor.execute_c()` 内部仍用 `time.time()`。为保证 H2 的延迟/窗口指标可归因、可复现，**H2.1 实现阶段**须在 Executor 的验证入口注入可控时钟（与 H1 现有注入风格一致）；本设计只冻结语义，不在此阶段改代码。

---

## 2. 四组机制定义与区分

四组固定，不再增加方案。它们共用**同一个动作绑定与同一个受控 Sink**（与 H1 一致），差别只在"授权验证 + 撤销处理"这一层。

| 分组 | 授权方式 | 撤销处理方式 | 服务离线时行为 | 在线查询负担 |
|---|---|---|---|---|
| **B2** | 在线授权查询（TCP+TLS、服务器证书指纹固定） | 每次执行查询服务当前状态，撤销即时可见 | **Fail Closed**（拒绝） | 每次执行 1 次在线查询 |
| **C0** | Ed25519 离线凭证（H1 的 C） | 仅检查凭证有效期 `expires_at`，无撤销列表 | 凭证有效期内可执行 | 0（纯本地） |
| **C1** | Ed25519 离线凭证（短 TTL） | 通过**缩短凭证有效期**限制风险窗口；无撤销列表 | 凭证 TTL 内可执行；TTL 过期后拒绝 | 0（纯本地） |
| **C2** | Ed25519 离线凭证（正常 TTL） | 签名、版本化**撤销快照**：Executor 缓存带签名/版本/有效期的撤销集合 | 快照有效且未命中撤销集合时可执行；快照过期且无法更新时拒绝 | 仅快照刷新时在线（可跨多次执行摊销） |

### 2.1 C1 与 C2 的本质区别（必须保持）

- **C1 缩短"凭证寿命"**：风险窗口上界被 TTL 约束，但**离线可用窗口也被 TTL 约束**——服务离线超过 TTL 后，C1 同样拒绝。它不获取任何撤销状态。
- **C2 同步"撤销状态"**：凭证寿命保持正常（离线可用窗口不因撤销控制而缩短），通过获取带签名的撤销快照提高撤销可见性；其风险窗口取决于**快照刷新节奏与可得性**，而非凭证 TTL。

两组解决的是同一问题的不同变量：C1 用"时间"换"风险"，C2 用"状态同步"换"风险"。因此**不能预先假定 C2 优于 C1**（详见实验协议第 7 节的 C2 失败条件）。

### 2.2 公平性约束（四组必须使用相同安全条件）

为防止"不同分组不同安全条件"的混淆，四组在以下方面必须一致：

- 相同动作请求（同一 `ActionRequest` 五个身份字段）、相同 `action_digest` 算法与域分离。
- 相同的 `jti` 语义（一次性授权标识）、相同的受控 Sink 与消费存储（同事务原子消费）。
- 相同的用户确认入口（H1 `confirm()` 语义）、相同的撤销触发（`revoke(jti)` 语义）。
- 相同的 Ed25519 信任模型：Executor 只信任**预置** `key_id -> 公钥`，绝不读取请求携带的公钥/状态。
- 撤销一律指**签发后撤销**（credential signed while ACTIVE, then revoked），与 H1 的架构权衡实验口径一致；"签发前已撤销"由 H1 的 `CredentialIssuanceError` 签发入口约束处理，不属 H2 变量。

---

## 3. C1 TTL 语义

C1 复用 H1 凭证结构，**仅改变 TTL 的取值与语义解释**，不引入新字段、不改变验签算法。

### 3.1 字段与时刻定义

| 符号 | 定义 | 来源 |
|---|---|---|
| `t_issue` | 授权服务确认动作的时刻，即 `issued_at` | `confirm()` 写入 |
| `TTL` | 凭证有效期长度（C1 为**短** TTL，取值在实验协议中冻结） | `confirm(ttl_seconds=...)` |
| `expires_at` | `t_issue + TTL` | `confirm()` 计算 |
| `now` | Executor 验证时刻（H2.1 注入可控时钟） | 验证入口 |

### 3.2 边界时刻（严格，与 H1 实现一致）

C1 凭证在时间上**有效**当且仅当：

```
issued_at <= now < expires_at
```

- `now == issued_at`：**有效**（H1 `execute_c` 仅在 `now < issued_at` 时拒绝 `C_NOT_YET_VALID`）。
- `now == expires_at`：**无效**，拒绝 `C_EXPIRED`（H1 用 `now >= expires_at`，闭区间上界排除）。
- `now > expires_at`：无效，拒绝 `C_EXPIRED`。

撤销风险窗口（C1）：若凭证在 `t_revoke` 被撤销（`t_issue <= t_revoke < expires_at`），则 C1 的接受持续到 `expires_at`，故

```
W_risk(C1) = expires_at - t_revoke  <= TTL
```

即 C1 把风险窗口**上界**约束为 TTL；代价是离线可用窗口同样 ≤ TTL。这个"上界"是确定性的，不依赖任何在线状态——这是 C1 的确定性优势，也是 C2 必须击败的基线。

---

## 4. C2 撤销快照格式（冻结）

### 4.1 字段定义

撤销快照是由授权服务签名、Executor 可离线验证的数据结构。其签名字段（除 `signature` 外全部参与签名）如下：

| 字段 | 类型 | 含义 | 约束 |
|---|---|---|---|
| `domain` | string | 域分离常量 | 固定 `"h2-revocation-snapshot-v1"`，与凭证域 `h1-authorization-credential-v1` 不同 |
| `version` | int | 快照版本号 | 正整数，严格单调递增；允许跳号，禁止回退 |
| `issuer` | string | 签发者 | 必须等于 Executor 预置的受信任 issuer |
| `key_id` | string | 签名密钥标识 | 必须命中 Executor 预置 `trusted_keys` |
| `generated_at` | number | 快照生成时刻（服务侧） | 有限实数 |
| `valid_from` | number | 生效起始时刻 | `valid_from <= generated_at` |
| `valid_until` | number | 失效时刻 | `valid_until > valid_from`；`now >= valid_until` 视为快照过期 |
| `revoked_jtis` | list[string] | 截至 `generated_at` 已撤销的凭证 jti 集合 | 去重后按字典序排序（保证规范化稳定）；可为空列表 |
| `signature` | string(base64) | Ed25519 签名 | 对上述全部字段的 `canonical_json_bytes` 签名 |

### 4.2 规范化和签名

```
snapshot_payload = {domain, version, issuer, key_id, generated_at,
                    valid_from, valid_until, revoked_jtis}
signature        = b64encode( signing_key.sign( canonical_json_bytes(snapshot_payload) ) )
```

- 规范化复用 H1 同一函数 `online_budget.canonical.canonical_json_bytes`（`sort_keys`、紧凑分隔符、`ensure_ascii=False`、`allow_nan=False`）；非有限浮点数 / 非 JSON 值直接拒绝。
- 签名密钥与 C 凭证使用**同一** Ed25519 信任锚（按 `key_id` 索引预置公钥），不引入新的密钥体系；是否使用独立 snapshot 密钥留作 H2.1 实现选择，但**不改变"公钥只来自预置集合"的信任规则**。
- `revoked_jtis` 是"累积撤销集合"语义（自快照体系建立以来所有被撤销且仍在记录中的 jti），**不是增量差集**——避免 Executor 因错过某一个增量快照而永久漏掉某条撤销。是否做过期 jti 的垃圾回收属实现细节，但回收不得导致一个仍可能被使用的有效凭证从集合中消失（回收策略须在 H2.1 冻结，本阶段只冻结"不得因此产生错误放行"的约束）。

### 4.3 快照与凭证的关系

- 快照验证的是"某个 jti 是否已被撤销"，**不重新验证凭证签名**——凭证签名/有效期/动作绑定仍由 C0/C1/C2 共用的 `execute_c` 路径完成（见 §6.1）。
- 快照**不绑定具体动作的 `action_digest`**：撤销的单位是 `jti`（一次性授权标识）。这样撤销快照的语义保持最小、可审计，且与 H1 的 `revoke(jti)` 语义一致。

---

## 5. C2 快照更新规则（冻结）

Executor 维护一份**本地缓存快照** `cached`。一份"候选快照" `cand` 只有在下列**全部**条件满足时才允许覆盖 `cached`：

### 5.1 接受更新的必要条件（全部满足才接受）

1. **结构合法**：`cand` 含 §4.1 全部字段，类型正确，`revoked_jtis` 为字符串列表且已按字典序无重复排序。
2. **域正确**：`cand.domain == "h2-revocation-snapshot-v1"`。
3. **信任锚命中**：`cand.key_id ∈ trusted_keys`，且 `cand.issuer == trusted_issuer`。
4. **签名有效**：用 `trusted_keys[cand.key_id]` 对 `canonical_json_bytes(cand_payload)` 验签通过。
5. **时间自洽**：`valid_from <= generated_at < valid_until` 且 `now < valid_until`（候选快照在接收时尚未过期）；`now >= valid_from`（不接受尚未生效的快照）。
6. **版本前进**：`cand.version > cached.version`（无缓存时视为 `cached.version = 0`）。

### 5.2 拒绝更新的情形与处理（必须拒绝，且缓存不变）

| 失败情形 | 判定码（冻结） | 处理 |
|---|---|---|
| 签名错误 / 公钥不匹配 | `SNAPSHOT_SIGNATURE_INVALID` | 拒绝候选；`cached` 不变 |
| 未知 `key_id` / 错误 `issuer` / 错误 `domain` | `SNAPSHOT_UNTRUSTED` | 拒绝候选；`cached` 不变 |
| 版本回退或相同（`version <= cached.version`） | `SNAPSHOT_VERSION_STALE` | 拒绝候选；`cached` 不变（防回滚） |
| 候选已过期（`now >= valid_until`） | `SNAPSHOT_EXPIRED` | 拒绝候选；`cached` 不变 |
| 候选尚未生效（`now < valid_from`） | `SNAPSHOT_NOT_YET_VALID` | 拒绝候选；`cached` 不变 |
| 结构 / 规范化非法（非有限浮点、乱序/重复 jti 等） | `SNAPSHOT_MALFORMED` | 拒绝候选；`cached` 不变 |

**关键不变量（Poisoning 防护）**：**任何**候选快照被拒绝时，`cached` 必须逐字段保持不变。因此攻击者即使注入"合法签名但旧版本"的快照（回滚），也不能抹掉缓存中已有的撤销记录；用错误密钥签名的"高版本"快照也不能替换缓存。这条不变量是 C2 的核心安全性质，H2.1 必须实现并测试。

### 5.3 刷新触发与版本单调

- 刷新触发（冻结，H2.1 实现）：满足任一条件即尝试在线获取最新快照——
  (a) 本地无有效缓存（`NO_SNAPSHOT` 或缓存已过期）；
  (b) 距上次成功刷新已超过配置间隔 `R`（`now - t_last_refresh >= R`）。
- `R` 是实验自变量（见协议第 6 节），**不是新分组**：它在 C2 组内扫描，用于刻画 C2 的"风险窗口 vs 在线成本"前沿。
- 版本单调性完全由 Executor 本地比较 `version` 保证；授权服务负责生成严格递增版本。Executor **不信任**服务"应给新版本"的承诺，只信自己验证过的候选。

---

## 6. Executor 离线/失败行为（冻结）

### 6.1 共用验证链（C0/C1/C2 一致，H1 不修改）

凭证侧（与 H1 `execute_c` 相同）：

1. 校验凭证形状、domain、version==1、`key_id ∈ trusted_keys`、`issuer`/`audience` 匹配。
2. 用预置公钥验签（签名覆盖全部声明）。
3. 校验 `issued_at <= now < expires_at`（C0/C2 为正常 TTL，C1 为短 TTL，边界见 §3.2）。
4. 对实际请求重算 `action_digest`，与签名声明比对。

以上任一步失败 → 拒绝，**不进入撤销检查、不进入消费**（与 H1 一致）。

### 6.2 C2 撤销检查（在凭证验证通过后）

记缓存状态为 `S`：

- `NO_SNAPSHOT`：无缓存。
- `FRESH`：`now < cached.valid_until`。
- `EXPIRED`：`now >= cached.valid_until`。

判定顺序（冻结）：

1. **缓存命中撤销**：若 `cached` 存在且 `jti ∈ cached.revoked_jtis` → **拒绝** `REVOKED_BY_SNAPSHOT`。
   - 注意：此判定**不因缓存过期而失效**。即便缓存已过期，只要它明确列出了该 jti，就拒绝执行——忽略一条已知撤销比"过期即放行"更糟。
2. **缓存 FRESH 且未命中**：→ **允许**进入消费与副作用。此路径**不触发在线查询**（这正是 C2 相对 B2 的开销优势）。
3. **NO_SNAPSHOT 或 EXPIRED 且未命中**：尝试在线刷新——
   - 刷新成功且候选按 §5.1 被接受 → 更新 `cached`，回到第 1 步重新判定（此时用新缓存）。
   - 刷新失败（服务不可达 / 超时 / 证书不符 / 候选按 §5.2 被拒）→ **拒绝** `SNAPSHOT_UNAVAILABLE`（无法建立新鲜的撤销状态时 fail closed）。

### 6.3 失败情形判定表（每种情形都有确定的接受/拒绝行为）

| 情形 | C0 | C1 | C2 | B2 |
|---|---|---|---|---|
| 合法授权、合法请求、服务在线 | 执行 | 执行 | 执行（FRESH 快照或可刷新） | 执行 |
| 凭证签名被篡改 | 拒绝 | 拒绝 | 拒绝（凭证链先失败） | 不受凭证影响（B2 不用凭证） |
| 参数/Schema/Server/Executor 被篡改 | 拒绝 | 拒绝 | 拒绝 | 拒绝 |
| 未知 `key_id` / 错 `issuer` / 错 `audience` | 拒绝 | 拒绝 | 拒绝 | 不适用 |
| 凭证已过期（`now >= expires_at`） | 拒绝 | 拒绝（TTL 更短） | 拒绝 | 拒绝（在线查过期） |
| 凭证尚未生效（`now < issued_at`） | 拒绝 | 拒绝 | 拒绝 | 拒绝 |
| **授权服务不可达 + 凭证/snapshot 仍有效** | 执行 | 执行（TTL 内） | **执行**（FRESH 且未命中；无在线查询） | **拒绝** fail closed |
| 授权服务不可达 + 凭证 TTL 已过（C1）/ 快照已过期且未命中（C2） | 凭证有效才执行 | **拒绝**（TTL 过期） | **拒绝** `SNAPSHOT_UNAVAILABLE` | 拒绝 |
| **签发后撤销 + Executor 在线且可刷新** | 执行（不知撤销） | 执行（TTL 内） | **刷新后** `REVOKED_BY_SNAPSHOT` 拒绝（延迟取决于刷新节奏） | 拒绝（即时） |
| **签发后撤销 + Executor 离线/旧快照仍 FRESH** | 执行 | 执行（TTL 内） | **执行**（旧快照未命中；这就是风险窗口） | 拒绝（fail closed） |
| 注入"合法签名但旧版本"快照（版本回退） | 不适用 | 不适用 | **拒绝候选**、缓存不变；若缓存已列出该 jti 则仍拒绝执行 | 不适用 |
| 注入"错误密钥签名的高版本"快照 | 不适用 | 不适用 | **拒绝候选**、缓存不变 | 不适用 |
| 注入过期快照 / 未生效快照 / 畸形快照 | 不适用 | 不适用 | **拒绝候选**、缓存不变 | 不适用 |
| 快照过期且无法获取更新 | 不适用 | 不适用 | **拒绝** `SNAPSHOT_UNAVAILABLE`（不错误放行） | 不适用 |
| 同一 jti 顺序/并发重放、崩溃回滚 | 最多一次副作用（共用 Sink，H1 不变） | 同左 | 同左 | 同左 |

> "不适用"表示该组没有这一机制层，**不是**放宽安全条件；四组在共用验证链与消费层完全一致。

---

## 7. 撤销延迟的两个概念（严格分离，禁止混用）

| 概念 | 定义 | 公式 | 适用 |
|---|---|---|---|
| **撤销传播延迟** `D_prop` | 从服务撤销凭证，到 Executor **获得**包含该撤销记录的快照，经过的时间 | `D_prop = t_snapshot_obtained - t_revoke` | 仅 C2（依赖分发/刷新）；若 Executor 始终离线未获得，`D_prop` 记为正无穷 / 未定义 |
| **撤销风险窗口** `W_risk` | 从凭证被撤销，到 Executor **不再接受**该凭证，经过的时间 | `W_risk = t_first_reject - t_revoke` | 四组均可定义；C0 受长 TTL 约束，C1 受短 TTL 约束，C2 取"快照拒绝/快照过期 fail closed/凭证过期"三者最早 |

**为什么二者不同**：C2 的快照可能**很快被发布**（`D_prop` 小），但如果 Executor 处于离线、缓存的旧快照仍在有效期内，它仍会接受该凭证——此时 `W_risk` 可以远大于 `D_prop`。反过来，若缓存快照先过期而 Executor 无法刷新，它会以 `SNAPSHOT_UNAVAILABLE` fail closed，此时 `W_risk` 可能**小于** `D_prop`（甚至 `D_prop` 未定义）。因此**必须用两个独立字段分别测量**，不得用一个代替另一个。

**C1 的定位**：C1 没有快照层，`D_prop` 记为"不适用（无传播机制）"；它只有 `W_risk ≤ TTL` 这一确定性上界。这正是 C1 与 C2 对比的关键——C2 只有在"以更低在线成本获得明显小于 C1 的 `W_risk`，且不牺牲离线可用性"时才证明自身价值。

---

## 8. 威胁模型与信任假设

### 8.1 信任（Trusted）

- **授权方 / Authorization Service**：持有 Ed25519 私钥，按可信界面展示的规范化动作签发凭证与撤销快照，维护撤销记录与快照版本。
- **可信确认界面**：展示规范化动作，用户确认（H1 语义，测试用 harness 代替 UI）。
- **Executor 预置信任锚**：`key_id -> 公钥`、`issuer`、`audience`；**绝不**从请求或快照内容之外获取公钥。
- **B2 通道信任锚**：服务器证书指纹固定（H1 已有）。

### 8.2 不信任（Untrusted / 对抗）

- **不可信 Planner**：提交工具请求、授权引用、凭证、候选快照；可篡改参数、伪造字段、注入快照、重放。
- **网络（服务↔Executor）**：可延迟、丢弃、重放凭证与快照；**不能伪造有效签名**（依赖信任假设），但可注入无效/过期/旧版本快照（由 §5.2 拦截）。
- **同一受控 Sink 并发调用方**：可并发提交同一 jti（由 H1 原子消费层拦截，H2 不改动）。

### 8.3 时钟假设（明确）

- H2 的延迟/窗口指标依赖时间测量。实验阶段使用**单一测试进程的可控时钟注入**（复用 H1 `now` 注入风格），以消除时钟偏斜这一混杂变量，使 `D_prop/W_risk` 可归因。
- **真实部署中的时钟偏斜 / 恶意时间源不在本实验覆盖范围**；若 `generated_at/valid_from/valid_until` 来自服务而 `now` 来自 Executor 本地时钟，则两者偏斜会影响有效性判定——这是 H2 明确记录的未验证假设，不在本阶段解决。

---

## 9. 不能保证的性质（边界与禁令，汇报必守）

1. **不是全局即时撤销**：C2 在旧快照仍有效时可能接受已撤销凭证；撤销可见性延迟是参数，不是零。
2. **不是全局 `exactly-once`**：消费与副作用的原子性只覆盖实验 SQLite 受控 Sink；一次性消费仅限单一 Executor 本地存储（H1 边界不变）。
3. **不抵抗签名私钥失陷**：若授权服务私钥被攻破，攻击者可同时伪造凭证与高版本快照；本设计不处理密钥轮换/撤销的在线分发。
4. **不抵抗 Executor / TCB 整体失陷**，也不抵抗"管理员联合控制 DB 与签名密钥"的回滚（本机只验快照签名与自洽，不验新鲜度的可信时间源）。
5. **快照真实性 ≠ 撤销完整性**：有效签名的快照只反映服务在 `generated_at` 写入 `revoked_jtis` 的内容；若服务遗漏某条撤销，Executor 无法从快照本身发现。
6. **版本单调只防"旧快照回滚"**，不防"持签名权的签发方主动签一个省略条目的高版本快照"（授权方本身在信任集内，属信任假设边界）。
7. **不声称 C2 一定优于 C1**：是否值得采用取决于实验结果与部署权衡；C2 的失败条件已在实验协议中先行冻结。
8. **机制验证 ≠ 形式化证明**：H2 为机制可行性实验（重复 N=10 量级），非统计显著性实验，测试通过不等于形式化安全证明。
9. **不接入真实 MCP / 第三方 API / 真实 Agent**；不修改 H1、E1.9、E2、E3-0 任何冻结成果。

---

## 10. 冻结决定清单与尚存问题

### 10.1 本阶段冻结的决定

- 四组机制定义（§2）与公平性约束（§2.2）。
- C1 TTL 语义与边界时刻（§3）。
- C2 快照字段、规范化、签名、累积集合语义（§4）。
- C2 快照接受/拒绝规则与"拒绝时缓存不变"不变量（§5）。
- Executor 在离线/失败/撤销未更新情形下的判定顺序与判定码（§6）。
- `D_prop` 与 `W_risk` 的分离定义（§7）。
- 威胁模型、信任假设、不能保证的性质（§8/§9）。

### 10.2 留给 H2.1 实现阶段定义（语义已冻结，仅实现选择待定）

- C0/C2 的正常 TTL 具体取值、C1 短 TTL 的扫描取值、快照有效时长、刷新间隔 `R` 的扫描网格——在实验协议中冻结，不在设计文档指定具体数值。
- Executor 可控时钟的注入接口（沿用 H1 `now` 风格）。
- 快照是否使用独立密钥、过期 jti 垃圾回收的具体策略（须满足 §4.2 不产生错误放行的约束）。
- 在线刷新失败的重试次数/退避（只影响 `W_risk` 测量值，不改变语义）。

### 10.3 尚存问题（不阻断本阶段冻结，进入 H2.1 前需明确）

1. B2 自身存在"查询通过→消费前"的撤销窗口（H1 报告 §6 已记录）；H2 是否量化该窗口并与 C2 对照，交由实验协议决定。
2. 若 C1 的短 TTL 在目标离线可用性下已经足够，`W_risk` 上界确定性且零在线成本，则 C2 可能无价值——这正是 H2 必须保留并认真运行的对照组（见实验协议第 7 节 C2 失败条件）。
3. 快照分发通道与 B2 在线查询通道是否共用同一 TLS 连接/信任锚，属实现优化，不改变本设计的信任语义。

---

**冻结结论**：H2.0 已完成设计冻结。四组机制、C1 TTL 语义、C2 快照格式与更新规则、Executor 全情形接受/拒绝行为、两个撤销延迟概念、威胁模型与边界均已明确且无相互矛盾。本阶段未修改 H1 / E1.9 / E2 / E3-0 任何成果，未接入真实 MCP，未实现任何机制。下一步（H2.1 实现与实验）须严格按 `docs/H2_EXPERIMENT_PROTOCOL.md` 的矩阵与判据执行，且以"C2 能被证伪"为纪律。
