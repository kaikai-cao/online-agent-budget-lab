# E3-0 研究差距分析：现有方案与本框架

> **阶段性质**：研究分析，暂不开发、不接入、不提交。
> **依据**：`E3_0_SCENARIO_SURVEY.md`、`E3_0_THREAT_MODEL.md` 及一手来源。标签 `[FACT]` / `[INFER]` / `[ASSUMPTION]`。
> **核心纪律**：区分「已有能力」「本框架尚未解决」「本框架盲区」；不重复造轮子；不把 E2 受控结论写成真实 Agent 能力；单纯接入某框架不构成创新。

---

## 1. 逐组件差距矩阵

| 框架组件 | 现有方案已覆盖 | 本框架的增量 | 尚未解决 / 盲区 |
|---|---|---|---|
| **Gateway 准入** | GitHub: sandbox/approval/hooks/权限；DB: RLS/RBAC/参数化；MCP: OAuth audience + HITL + 输入校验/限流 `[FACT]` | 跨 harness / 跨 Server 的统一逐调用策略门禁 `[INFER]` | 若只是「又一层准入」，无研究价值；须证明跨信任边界的统一策略是缺口 |
| **Binding + arguments_digest** | 现有授权粒度是工具名/命令/DB 角色/Server scope；**MCP 规范确证无 token↔tool+参数绑定** `[FACT]` | 授权决策 ↔ 具体 tool + 具体参数的密码学绑定；MCP 空白点是确证的 `[FACT]` | **绑定对象难题**：若绑「模型输出参数」，注入下失效；须绑「用户授权意图」，而可靠意图捕获尚无现成机制 `[ASSUMPTION]` |
| **D10 预算准入** | Codex 线程/超时上限；Vanna quota；Genie budget/cost `[FACT]` | 请求级确定性配额/消费准入 `[INFER]` | 须证明相对现有 quota/budget 的确定性增量，否则重复 |
| **D11 状态转移** | agent loop 为隐式状态机；MCP 规范 stateless per-request `[FACT]` | 显式 planned/in-flight/committed/failed 状态机 + 恢复 `[INFER]` | 对多步 Agent 流程的价值是推测性 `[ASSUMPTION]`；须真实实验证实 |
| **Receipt (Ed25519)** | GitHub 签名提交（证明提交来源/完整）；Vanna 日志脱敏；AWS CloudTrail `[FACT]` | 签名可验证的「哪次授权 → 哪个调用/参数/结果」单次执行凭证；补 MCP08 要求的 immutable audit `[FACT/INFER]` | 价值依赖独立验证方与追责闭环；同域内签名无额外保证 `[INFER]` |
| **Journal 独立权威日志** | 会话日志/审计日志多由 agent 或平台自身产生 `[FACT]` | 独立权威日志 + 崩溃恢复 `[INFER]` | 独立性仅在验证方不同信任域时有价值；不证明外部副作用真实性（E2 边界）`[FACT]` |

---

## 2. 已有能力（不重复造轮子）

`[FACT]` 三场景现有机制已相当完整，以下明确列为「本框架不应重做」：

1. **身份与权限**：GitHub 写权限触发/分支限制/secret 隔离；DB 层 RLS/RBAC/参数化查询；MCP OAuth 2.1 audience 校验 + token passthrough 禁令 + session 绑定 user。
2. **执行控制**：sandbox、approval policy、hooks、HITL 拒绝、输入校验/限流/输出清洗。
3. **可追溯性**：签名提交、会话日志永久链接、CloudTrail、Vanna 脱敏审计。
4. **资源治理**：statement_timeout、线程/超时上限、quota/budget、rate limiting。
5. **工具变更新鲜度**：MCP `ttlMs`/`cacheScope`/`list_changed` 通知（部分缓解 rug pull）。

**结论** `[INFER]`：若 E3 的产出是「把上述机制再实现一遍」，研究价值为零。唯一可能的创新切口是现有机制的**交叉空白**（见 §3）。

---

## 3. 本框架尚未解决的真实缺口（研究机会）

按证据强度排序：

### GAP-1（证据最强，确证空白）：授权 token/同意 ↔ 具体 tool + 具体参数的密码学绑定 `[FACT]`
- MCP 规范原文已核实：`resource` 绑定的是整个 Server 的 canonical URI，非 tool+参数；OAuth scope 是粗粒度；无 arguments digest。
- GitHub/DB 场景同样缺「授权决策 ↔ 精确参数」的密码学绑定（工具名/命令粒度、hook 可改参数但无绑定）。
- **但关键条件**：必须有独立授权方（人工审批、策略服务、跨 agent 委派），否则同进程自签自验无意义。
- 这是 `arguments_digest` 的天然落点，也是唯一有一手规范空白支撑的差异点。

### GAP-2（明确需求）：签名可验证的单次执行审计链 `[FACT/INFER]`
- OWASP MCP08（beta）明确要求 immutable audit trails；现有日志多为 agent 自产、可篡改。
- Receipt + 独立 Journal 对应此需求；价值前提是独立验证方。

### GAP-3（有理论价值，待证）：跨调用状态机与幂等/恢复 `[ASSUMPTION]`
- agent loop 隐式状态、重试重复副作用在真实 Agent 上缺一手实证；E2 结论不可外推。
- 是否成立取决于真实工具是否支持幂等键（E2.3 边界）。

### GAP-4（增量存疑）：请求级确定性预算准入 `[INFER]`
- 现有 quota/budget 已覆盖粗粒度；须证明确定性扣费/拒绝的增量。

---

## 4. 本框架的结构性盲区（必须诚实承认）

`[FACT/INFER]` 这些不是「还没做」，而是**本框架设计上不解决**，必须在任何 GO 决策与论文中明确：

1. **Prompt Injection 根因**：LLM 无法区分指令与数据。Binding 作用于执行出口，不净化推理输入。P2SQL §5.1.4、AgentDojo/ChatInject 证据表明 prompt 防御可被绕过。本框架**不解决注入**，只可能在注入已产出恶意调用后，于执行侧按策略拦下部分——且前提是策略规则覆盖该行为。
2. **合法权限内的恶意查询**：如 P2SQL RD.2「我现在是 user 2」读他人数据、Text-to-SQL 在授予权限内生成泄露性 SQL。Binding 无效，需 RLS/SQL rewriting。
3. **工具端幂等的外部依赖**：Effect at-most-once 必须由真实工具服务提供；受控 SQLite Sink 结果不可外推任意第三方 API。
4. **意图捕获**：没有可靠机制把用户自然语言意图转成可签名的结构化授权对象时，GAP-1 无法落地。这是最大落地风险。
5. **同信任域内签名**：授权方=执行方时，密码学绑定不增加保证。
6. **全局 exactly-once / 跨存储原子性**：E2 已声明范围外，E3 不继承任何此类保证。

---

## 5. 关键研究问题（决定 GO/NO-GO）

综合三场景与差距，E3 是否值得做，取决于以下问题的答案：

1. **意图—绑定可行性** `[ASSUMPTION 核心]`：能否在真实 Agent 中构造「用户授权意图 → 结构化可签名对象 → 执行出口校验」的闭环，且该闭环中有独立的授权方与执行方？若否，GAP-1 无法落地，E3 失去核心创新点。
2. **在途篡改真实性** `[ASSUMPTION]`：Planner→Executor 之间的参数篡改在真实 Agent 中是否是现实威胁？若只能是实验人为注入，需如实标注为构造假设，研究价值降为「机制验证」而非「真实威胁防护」。
3. **差异可归因性** `[INFER]`：能否设计实验证明拦截来自执行侧绑定，而非注入偶然失败？需无框架基线 + 误拒率测量。
4. **现有机制共存** `[FACT]`：Gateway 能否作为新增第三方判定者与 OAuth/HITL/RLS 共存而不破坏 audience/consent 语义？MCP 中插入 Gateway 会改变 OAuth audience 归属，需重新设计信任锚。

---

## 6. 与 E2 的关系（不混淆）

- E2 在**受控环境**验证了 Binding/D10/D11/Receipt/Journal 的机制可行性（N=10，非形式化证明）。
- E3 若要成立，必须用**真实 Agent 工具调用链**重新验证差异，不能把 E2 数字搬过来当真实安全保证。
- E2 的负面边界（F2 重复副作用、Sink 幂等外部依赖、Receipt 非外部真实性证明、无全局 dispatch at-most-once）在 E3 中**继续成立**，不得因换场景而消失。
