# H1 最小可行性实验报告：跨信任域动作授权 B2（在线）vs C（本地凭证）

> 阶段性质：机制可行性验证（mechanism feasibility），**不是**形式化安全证明、**不是**论文级统计实验、**不是**生产级 MCP 集成。
> 基于 E3-0.4 冻结结论与 `research/h1-authorization-binding` 分支（`692e841` 的直系后继）。
> 实验代码：`experiments/h1_authorization_binding/`；原始数据：`results/run-001/{trials.csv,summary.json,raw.json}`。

---

## 1. 实验问题与假设

**唯一问题**：在**相同跨信任域条件**下，C 组的本地可验证授权凭证，相比 B2 组的可信在线授权验证，究竟增加了什么能力？

据此定义四个可证伪假设：

- **H1-a（绑定可行性）**：能把用户确认的具体动作（工具 + 规范化参数 + 执行器 + Schema + Server）绑定到授权记录（B2）或签名凭证（C），且两组绑定字段与摘要算法完全一致。
- **H1-b（篡改检测）**：不可信 Planner 修改参数 / Schema / Server URI / 目标 Executor 后，Executor 自行重算摘要，两组均拒绝执行。
- **H1-c（公平防重放）**：两组共用同一 Executor 本地消费存储，靠原子消费（而非签名、而非在线查询）阻止同一 jti 重复产生副作用；顺序、并发、崩溃回滚下最多一次副作用。
- **H1-d（可归因增量）**：在授权服务不可达 / 授权撤销 / 凭证篡改 / 信任锚错误时，两组表现的差异可以被观察并归因——C 的增量是否真实存在且可测。

**判定纪律**：不为得到正向结论而弱化 B2；若 C 无可归因增量，如实报告架构权衡或 NO-GO。

---

## 2. 架构图与两条协议

### 2.1 架构

```
不可信 Planner ──工具请求 + 授权引用──> Executor
                                          │ ① 重算 action_digest（不信 Planner 提供的）
用户确认(可信界面) ──> Authorization Service
                        ├─ B2：在线授权记录查询（真实 TLS + 证书固定）
                        └─ C ：Ed25519 签发一次性凭证
                                          │ ② 验证：B2 在线查询 / C 本地验签
                                          │ ③ 共同下游：绑定检查 → 原子消费 jti
                                          │              → 受控 Sink 副作用 → 结果记录
```

Authorization Service 与 Executor 分属两个信任域：**B2 的 Executor 在线信任服务的当前授权状态；C 的 Executor 仅凭预置公钥本地验证，不信任请求携带的任何公钥/状态。**

### 2.2 B2：在线授权验证

1. 用户通过可信确认入口确认动作 → 服务保存授权记录（状态 `ACTIVE`）。
2. Planner 提交 `approval_id`(jti) 与工具请求给 Executor。
3. Executor 对实际请求重算 `action_digest`，连同 `jti`、`executor_id` 经**真实 TLS 通道**（客户端证书固定）查询服务。
4. 服务校验：jti 存在、未撤销、未过期、`action_digest` 匹配、目标执行器匹配。
5. 通过 → Executor 原子消费 jti 并提交受控副作用。
6. **服务不可达 / 证书固定失败 → fail closed（拒绝）**。
7. B2 **不签发任何应用层 Ed25519 动作授权凭证**。

### 2.3 C：本地签名凭证验证

1. 用户通过**同一**可信确认入口确认**同一**动作。
2. 服务对完整授权对象签发 Ed25519 凭证（含 issuer/audience/key_id/version）。
3. Planner 提交凭证与工具请求给 Executor。
4. Executor 用**预置可信公钥**（按 `key_id` 索引）本地验签，检查 domain/version/issuer/audience/key_id/jti/有效期。
5. Executor 对实际请求重算 `action_digest` 并与签名声明比对。
6. 通过 → 与 B2 **完全相同**的原子消费 + 受控副作用路径。
7. 服务不可达时，已签发且有效的凭证仍可本地验证；但**无法感知签名后发生的撤销**。

---

## 3. 授权对象与摘要规范（两组唯一事实来源）

| 字段 | 含义 | 参与 action_digest |
|---|---|---|
| `executor_id` | 目标执行器身份 | 是 |
| `server_uri` | MCP Server 标识 | 是 |
| `tool_name` | 工具名称 | 是 |
| `schema_hash` | 工具 Schema 摘要 | 是 |
| `arguments` | 规范化工具参数 | 是 |
| `action_digest` | 完整动作摘要 | 派生结果 |
| `jti` | 一次性授权标识 | 否（授权元数据，C 中单独签名） |
| `issued_at` / `expires_at` | 有效期 | 否（授权元数据，C 中单独签名） |

- `action_digest = SHA256( canonical_json({ "domain": "h1-action-binding-v1", "action": <上述五个身份字段> }) )`，前缀 `sha256:`。
- 规范化复用 `online_budget.canonical.canonical_json_bytes`（`sort_keys`、紧凑分隔符、`ensure_ascii=False`、`allow_nan=False`），**拒绝非有限浮点数与不支持的 JSON 值**（实测 H1ProtocolError）。
- 域分离靠固定 `domain` 字段；实测 `action_digest != digest(BASE_REQUEST)`，确认不是裸摘要。
- Executor **始终重算**，不信任 Planner 提供的 `action_digest`（实测：Planner 注入伪造顶层 `action_digest` 字段不改变结果，B2/C 均按真实身份字段执行）。
- C 的签名覆盖全部授权声明（身份、摘要、jti、时间、issuer/audience/key_id/version）。

---

## 4. 信任假设与密钥管理边界

- **授权方可信**：可信授权界面展示规范化动作、用户确认；Authorization Service 持有 Ed25519 私钥。
- **B2 信任锚**：客户端固定服务证书指纹；未知/不匹配证书 → fail closed。TLS 仅为传输信道保护，**不是应用层动作签名凭证**。
- **C 信任锚**：Executor 预置 `key_id -> 公钥` 映射；**绝不读取请求携带的公钥**。未知 key_id、错误 audience、错误 issuer、签名篡改均拒绝（四项实测均 REJECTED）。
- **未覆盖**：密钥轮换/撤销的在线分发、PKI、授权服务的可用性工程、多执行器间的全局消费状态——均属后续研究问题，本实验未实现。

---

## 5. 测试矩阵及实际结果

运行：`PYTHONPATH="src;tests;experiments/h1_authorization_binding" .venv/Scripts/python experiments/h1_authorization_binding/run_experiment.py --output-dir .../results/run-001`
结果：**29 项检查全部通过**（`summary.json`: total 29 / passed 29 / failed 0）。专项 unittest **19 项通过**。逐行数据见 `trials.csv`，原始细节见 `raw.json`。

| 场景 | B2 实际 | C 实际 | 说明 |
|---|---|---|---|
| 合法授权 + 合法请求 | EXECUTED（1 副作用） | EXECUTED（1 副作用） | 两组均放行；用不同 jti 独立测量 |
| 修改工具参数 | REJECTED `ACTION_DIGEST_MISMATCH` | REJECTED `ACTION_DIGEST_MISMATCH` | 重算摘要检测 |
| 修改工具 Schema | REJECTED | REJECTED | 同上 |
| 修改 Server URI | REJECTED | REJECTED | 同上 |
| 目标 Executor 不匹配 | REJECTED `EXECUTOR_TARGET_MISMATCH` | REJECTED `EXECUTOR_TARGET_MISMATCH` | 执行器身份检查 |
| 授权过期 | REJECTED `EXPIRED` | REJECTED `C_EXPIRED` | 有效期检查 |
| 凭证签名被篡改 | EXECUTED（B2 不使用凭证，不受影响） | REJECTED `C_SIGNATURE_INVALID` | C 验签 |
| C 未知 key_id / 错 audience / 错 issuer | EXECUTED | REJECTED（三类均拒） | **C 信任锚仅在预置集合** |
| **授权服务不可达** | **REJECTED `AUTH_SERVICE_UNREACHABLE`（fail closed）** | **EXECUTED（离线验签）** | **核心架构差异** |
| **授权被提前撤销** | **REJECTED `REVOKED`（在线可见）** | **EXECUTED（离线不知撤销）** | **核心架构权衡** |
| 同一 jti 顺序重放 | — | EXECUTED → DEDUP_HIT，1 副作用 | 原子消费 |
| 同一 jti 并发重放（8 线程） | — | 1×EXECUTED / 7×DEDUP_HIT，1 副作用 | `BEGIN IMMEDIATE` 串行化 |
| 提交前崩溃回滚后可重试 | — | ROLLED_BACK → EXECUTED → DEDUP_HIT，1 副作用 | 消费与副作用同事务回滚 |
| 提交后重放无第二次副作用 | — | 多次调用仍 1 副作用 | jti 主键唯一约束 |
| Planner 伪造 action_digest 字段 | EXECUTED（伪造字段被忽略） | EXECUTED（伪造字段被忽略） | Executor 重算，不信 Planner |
| 两组共用消费存储 | B2 执行同 jti → C 同 jti = DEDUP_HIT，1 副作用 | | **消费公平性证据** |

> 所有结果为 runner 实际调用模块后记录（`trials.csv` 的 `actual_outcome`/`actual_reason`/`effects_added`），非预填预期值。
> B2 认真实现：真实 localhost TLS 服务、客户端证书固定、在线查询服务当前状态；不是硬编码放行的弱对照。

---

## 6. 不可达 / 撤销 / 过期 / 重放对比

| 维度 | B2（在线） | C（本地凭证） |
|---|---|---|
| 授权服务不可达 | fail closed，拒绝执行 | 有效凭证仍可本地验证并执行 |
| 授权提前撤销 | 在线查询即时可见并拒绝 | 不感知，凭证到期前仍可用 |
| 过期 | 在线拒绝 | 本地按 `expires_at` 拒绝 |
| 重放 / 并发 | 靠共用本地消费存储 | 靠共用本地消费存储（同机制） |
| 防重放来源 | 本地原子消费状态 | 本地原子消费状态（**不是签名**） |

**关键结论**：唯一可归因于"本地签名凭证"的增量是——**授权服务不可达时仍可独立验证并执行**（实测 B2 REJECTED / C EXECUTED）。其代价是**撤销可见性下降**（实测撤销后 B2 REJECTED / C 仍 EXECUTED）。这是一个**可用性 vs 撤销新鲜度的架构权衡**，不是"C 全面更安全"。

另需记录的限制：B2 在线查询与 Executor 本地消费之间存在时间窗——查询通过后、消费前发生的撤销，Executor 不一定能及时发现；**不声称撤销与副作用之间有全局原子性**。

---

## 7. 已验证事实 / 未验证假设 / 实现限制

**已验证事实（有实测数据）**
- 两组动作绑定字段与摘要算法一致；篡改四类身份字段两组均拒。
- C 信任锚仅在预置公钥集合；四类信任锚错误均拒。
- 两组共用消费存储；顺序/并发/崩溃回滚下最多一次副作用。
- B2 不可达 fail closed；C 不可达仍可验签；撤销后 B2 拒、C 仍执行。

**未验证假设**
- 真实 MCP Host / 第三方工具服务上的同等行为（本实验用受控 Sink）。
- 真实授权服务的可用性工程、密钥轮换与跨执行器撤销分发。
- 授权服务与执行方之间更细粒度信任隔离下的行为。

**实现限制**
- 受控 Sink 的同事务原子性只覆盖实验 SQLite，**不代表真实第三方 API 的 exactly-once**；一次性消费限定单一 Executor 本地存储，**不是全局**。
- 撤销在 C 中只靠有效期兜底（无撤销列表/在线校验）；B2 撤销可见性也有查询-消费时间窗。
- 机制验证规模（机制重复与负向注入），非统计显著性实验；测试通过不等于形式化安全证明。

---

## 8. B2 与 C 是否存在可测量增量

**存在，但单一且双向**：C 相对 B2 的可测增量是「授权服务不可达时的本地可验证与执行能力」（B2 fail closed / C EXECUTED，实测确认）。该增量**伴随一项对称代价**：授权撤销后 C 无法及时感知（C 仍 EXECUTED / B2 REJECTED，实测确认）。

因此不能说「C 比 B2 更安全」，只能说：**在授权服务不可达与撤销可见性之间，C 与 B2 提供了不同的可用性/新鲜度权衡；本地密码学凭证把信任从"在线服务状态"转移到"预置公钥 + 有效期"**。是否值得采用，取决于具体部署中"离线可用性"与"撤销即时性"哪个更重要。

---

## 9. H1 GO / NO-GO 初步判断

**有条件 GO，但仅进入下一步实验设计，不进入 MCP 生产集成。**

- GO 依据：H1-a/b/c 全部验证；H1-d 得到可归因（且双向）的架构差异——C 的增量真实存在、可测、且能归因于本地可验证凭证，同时其撤销代价也被清楚测量。这满足 E3-0"只有 B2 vs C 可用于密码学归因"的纪律，且**没有弱化 B2**。
- 保留的 NO-GO 条件：若后续在真实多信任域部署中证明「B2 的在线可用性足够、撤销即时性更重要，且离线凭证的撤销代价不可接受」，则按 E3-0 停止门槛接受 NO-GO。
- 下一步（**本阶段不做**）：独立的撤销机制设计（短 TTL / 撤销列表 / 在线校验混合）与真实 MCP Host 对照实验设计；在此之前不接入真实 Agent、不扩展到其他框架。

---

## 10. 复现命令

```bash
PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
  .venv/Scripts/python experiments/h1_authorization_binding/run_experiment.py \
  --output-dir experiments/h1_authorization_binding/results/run-001

PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
  .venv/Scripts/python -m unittest tests.test_h1_authorization_binding -v
```
