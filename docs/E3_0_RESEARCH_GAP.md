# E3-0.1 研究差距分析：现有方案与本框架

> **阶段性质**：研究分析，暂不开发、不接入、不提交。
> **依据**：`E3_0_SCENARIO_SURVEY.md`、`E3_0_THREAT_MODEL.md` 及一手来源；E3-0.1 补充 OWASP AI Agent Security Cheat Sheet、OWASP Transaction Authorization Cheat Sheet、MCPS Internet-Draft、MCP Specification 2026-07-28。标签 `[FACT]` / `[INFER]` / `[ASSUMPTION]`。
> **核心纪律**：区分「已有能力」「本框架尚未解决」「本框架盲区」；不重复造轮子；不把 E2 受控结论写成真实 Agent 能力；单纯接入某框架不构成创新。
> **★E3-0.1 修订（重要）**：审查指出原 GAP-1「arguments_digest 是 MCP 唯一确证空白」的论据**过强**。参数级审批、签名消息、重放保护均已有相关工作（OWASP 两份 Cheat Sheet、MCPS）。本版把 GAP-1 重写为「独立授权方的动作批准如何成为跨信任边界可验证、不可替换/重放的一次性凭证」，并新增相关工作比较（§5）。

---

## 1. 逐组件差距矩阵

| 框架组件 | 现有方案已覆盖 | 本框架的增量 | 尚未解决 / 盲区 |
|---|---|---|---|
| **Gateway 准入** | GitHub: sandbox/approval/hooks/权限；DB: RLS/RBAC/参数化；MCP: OAuth audience + HITL(SHOULD) + 输入校验/限流 `[FACT]` | 跨 harness / 跨 Server 的统一逐调用策略门禁 `[INFER]` | 若只是「又一层准入」，无研究价值；须证明跨信任边界的统一策略是缺口 |
| **Binding + arguments_digest** | 现有授权粒度是工具名/命令/DB 角色/Server scope；**MCP 2026-07-28 规范 `resource` 仍绑 Server canonical URI，无 token↔tool+参数绑定** `[FACT]`；**但参数级审批原则已由 OWASP Cheat Sheets 明确提出** `[FACT]` | 授权决策 ↔ 具体 tool + 具体参数的密码学绑定，且由**独立授权方签发、跨信任边界可验证、一次性消费** `[INFER]` | **绑定对象难题**：若绑「模型输出参数」，注入下失效；须绑「用户确认的具体动作」，而要证明其相对 B 组的独立增量（见 GO_NO_GO §4） `[ASSUMPTION]` |
| **D10 预算准入** | Codex 线程/超时上限；Vanna quota；Genie budget/cost `[FACT]` | 请求级确定性配额/消费准入 `[INFER]` | 须证明相对现有 quota/budget 的确定性增量，否则重复 |
| **D11 状态转移** | agent loop 为隐式状态机；MCP 核心无协议级跨调用状态，但允许 Server 通过显式 handle（如 Tasks 扩展的 durable handles）在应用层管理状态 `[FACT]` | 显式 planned/in-flight/committed/failed 状态机 + 恢复 `[INFER]` | 对多步 Agent 流程的价值是推测性 `[ASSUMPTION]`；须真实实验证实 |
| **Receipt (Ed25519)** | GitHub 签名提交（证明提交来源/完整）；Vanna 日志脱敏；AWS CloudTrail；**MCPS 已提供逐消息签名与工具定义签名** `[FACT]` | 签名可验证的「哪次授权 → 哪个调用/参数/结果」单次执行凭证 `[FACT/INFER]` | 价值依赖独立验证方与追责闭环；同域内签名无额外保证；**不可仅以「现有日志不可信」立论**（见 §4.3） `[INFER]` |
| **Journal 独立权威日志** | 会话日志/审计日志多由 agent 或平台自身产生；OWASP 已推荐集中式审计与日志完整性保护 `[FACT]` | 独立权威日志 + 崩溃恢复 `[INFER]` | 独立性仅在验证方不同信任域时有价值；不证明外部副作用真实性（E2 边界） `[FACT]` |

---

## 2. 已有能力（不重复造轮子）

`[FACT]` 三场景现有机制已相当完整，以下明确列为「本框架不应重做」：

1. **身份与权限**：GitHub 写权限触发/分支限制/secret 隔离；DB 层 RLS/RBAC/参数化查询；MCP OAuth 2.1 audience 校验 + token passthrough 禁令 + session 绑定 user。
2. **执行控制**：sandbox、approval policy、hooks、HITL 拒绝、输入校验/限流/输出清洗。
3. **可追溯性**：签名提交、会话日志永久链接、CloudTrail、Vanna 脱敏审计；MCPS 逐消息签名与工具定义签名。
4. **资源治理**：statement_timeout、线程/超时上限、quota/budget、rate limiting。
5. **工具变更新鲜度**：MCP `ttlMs`/`cacheScope`/`list_changed` 通知（部分缓解 rug pull）。
6. **★参数级审批与原子消费（E3-0.1 新增）**：OWASP AI Agent Security Cheat Sheet 已要求执行组件在 agent context 之外授权、`user_confirmed` 标志不足、审批绑定 actor/tool name/target resource/normalized parameters/timestamp/expiry、target 或参数变更需重新批准、执行前原子 check-and-consume；OWASP Transaction Authorization Cheat Sheet 已要求服务端强制、事务数据授权后不可改、每操作唯一凭证、执行前原子检查并标记已用。[^W1][^W2]

**结论** `[INFER]`：若 E3 的产出是「把上述机制再实现一遍」，研究价值为零。创新切口必须从现有安全设计**已提出的原则之外**寻找，并用强对照证明增量（见 §3、§5）。

---

## 3. 本框架尚未解决的真实缺口（研究机会）

按证据强度排序；E3-0.1 已重写 GAP-1。

### GAP-1（★重写）：独立授权方的动作批准 → 跨信任边界可验证、不可替换/重放的一次性凭证 `[FACT 规范事实 / INFER 研究切口]`

**规范层事实（原始事实，仍成立）** `[FACT]`：MCP 2026-07-28 authorization 页原文要求 `resource` MUST 标识 "the MCP server that the client intends to use the token with"、MUST 用 server canonical URI（如 `https://mcp.example.com/mcp`）；该页无 token↔tool+arguments 绑定文本。GitHub/DB 场景同样缺「授权决策 ↔ 精确参数」的密码学绑定。

**但该事实不再等价于「研究空白」** `[FACT]`：OWASP 两份 Cheat Sheet 已明确提出精确动作审批与一次性消费（§2 第 6 项）；MCPS 已提供消息签名、工具定义签名与 nonce+timestamp 防重放（§5）。因此「把用户审批绑定到精确工具参数」**本身不是原创思路**，不能作为创新点。

**重写后的研究问题（审查建议口径）**：

> 在 MCP 工具调用链中，如何将**独立授权方对特定动作的批准**，转化为可**跨信任边界验证**、不可被**替换或重放**的**一次性密码学授权凭证**？

需区分三个层次（不混为一谈）：

| 层次 | 判断 | 标签 |
|---|---|---|
| MCP OAuth 是否绑定具体 tool + arguments | **没有**，规范层事实 | `[FACT]` |
| Agent 安全设计是否已提出精确动作审批 | **已经提出**（OWASP Agent Security / Transaction Authorization Cheat Sheet），不能声称是原创思路 | `[FACT]` |
| 是否存在「独立授权方签发、跨信任域验证、可验证且一次性消费的密码学授权凭证」 | **值得继续研究，但尚未证明有足够创新性**——须用强对照（GO_NO_GO §4 的 A/B/C）测出独立增量 | `[INFER]` |

**★必须区分两个不同保证，不可混为一谈**（E3-0.2 补充）：

| 保证 | 定义 | 是否已由已有工作覆盖 |
|---|---|---|
| **跨信任域验证** | 执行方能验证「凭证由独立授权方签发」且「凭证内容与当前调用一致」，而不必信任授权方的内部状态/数据库 | `[INFER]` 尚待证：这是候选增量所在（见下） |
| **一次性消费（防重放）** | 凭证不能被重复使用，需要共享状态、原子操作或等价机制 | `[FACT]` **OWASP Transaction Authorization CS §1.5 已明确提出**共享状态下执行前原子 check-and-consume；把内部记录换成 Ed25519 签名**不等于**获得新的防重放能力 |

**真正待答的问题（研究假设，非结论）** `[ASSUMPTION]`：当 B 组已具备**可信审批服务 + 共享状态 + 原子消费**时，C 组的密码学凭证究竟增加什么？可能的增量是——**当授权服务与执行服务不共享同一个应用信任域、不能直接信任对方数据库或内部状态时，凭证允许执行方独立验证授权来源及授权内容**。这仍是待验证假设，不是已证明结论；实验必须明确模拟授权服务与执行服务之间的**信任隔离**，否则 C 组只是把 B 组内部授权记录换成签名，研究价值不清楚。

**关键条件** `[ASSUMPTION]`：必须有独立授权方（可信授权界面/策略服务/跨 agent 委派的授权服务），且授权签名方与执行验证方处于不同信任域；否则同进程自签自验无意义。

**与 E1/E2 组件的关系** `[INFER]`：Binding/arguments_digest 可作为凭证中「规范化参数绑定」的载体，Receipt 可作授权→执行→结果的关联记录，Journal 可作一次性消费的共享状态与恢复依据；但**这些组件的组合本身不是创新**，创新必须落在「独立授权凭证跨信任域的可验证性与一次性消费」这一可测差异上。

### GAP-2（明确需求）：签名可验证的单次执行审计链 `[FACT/INFER]`
- OWASP MCP08（beta）建议 immutable audit trails；OWASP 同时已推荐结构化日志、完整工具调用参数记录、日志完整性保护与集中式审计。**因此 Receipt+Journal 的价值必须落到「独立验证者究竟能验证什么」**，不能只说现有日志不可信。[^W3]
- 价值前提是独立验证方；同域内签名无额外保证。

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
4. **意图捕获 vs 动作展示（E3-0.1 调整）**：不把 H1 设为「自动把用户自然语言意图转成结构化授权对象」（那引入自然语言理解这一独立难题）。改为**可信授权界面展示具体动作（Server + tool + 规范化参数 + 有效期），用户确认该动作，独立授权服务签发凭证**；研究对象是**动作授权的可信传递**，不是让另一个 LLM 判断用户想做什么。
5. **同信任域内签名**：授权方=执行方时，密码学绑定不增加保证。
6. **全局 exactly-once / 跨存储原子性**：E2 已声明范围外，E3 不继承任何此类保证。

---

## 5. 相关工作比较（★E3-0.1 新增，不可省略）

后续实验**不能只与「无 Binding 的 MCP」比较**。以下三类现有工作必须作为基线或对照：

| 工作 | 已提供的保证（原文要点） | 与本方向的区别 | 对我们的约束 |
|---|---|---|---|
| **OWASP AI Agent Security Cheat Sheet**[^W1] | 授权在执行组件中、agent context 之外执行；`user_confirmed` 标志不足，须验证审批属于当前 actor 与精确 tool call、仍有效且未被消费；target/参数变更需重新审批；执行前原子 check-and-consume；high-impact 审批记录绑定 actor、tool name、target resource、normalized parameters、timestamp、expiry | 这是**应用层安全设计原则**，未规定跨信任域的密码学凭证形式 | 「精确参数审批」不是原创；须证明密码学凭证相对普通应用层审批的独立增量 |
| **OWASP Transaction Authorization Cheat Sheet**[^W2] | WYSIWYS：用户确认重要交易数据；授权服务端强制、不可由客户端篡改数据影响结果；所有重要交易数据服务端生成并无篡改传给授权组件；每操作唯一凭证；**"Expiration ... and per-operation uniqueness ... do not prevent replay of the same transaction ... Before execution, atomically check that the credential is unused and mark it used, using state shared by all accepting servers."** | 银行交易授权场景的成熟原则；「一次性消费 + 共享状态」已被明确提出 | 一次性消费与唯一凭证不是原创；Journal 的共享状态角色须与「所有接收服务器共享状态」对齐比较 |
| **MCPS: Cryptographic Security Layer for MCP**[^W4]（`draft-sharif-mcps-secure-mcp-01`, 2026-08-21, **个人 Internet-Draft，非已采纳标准**） | Agent Passport（ECDSA P-256 身份+origin 绑定）；逐消息 ECDSA 签名（JCS 规范化覆盖完整 JSON-RPC，故 `tools/call` 的 name/arguments 被覆盖）；工具定义签名覆盖 description 以防 poisoning/rug pull；nonce + timestamp 防重放。§1.2 原文："Authorization: This document does not replace OAuth-based access control."；§11.2 原文："MCPS provides provenance (WHO authored a tool or sent a message), not safety analysis." | **MCPS 证明「消息由谁发出、是否被修改」；本方向应证明「这次调用是否经过独立授权方批准」**。Agent 可以合法签署一条恶意工具调用——消息签名不能自动证明用户批准。§1.3：MCPS 与 OAuth 互补，server MAY 同时要求两者 | 后续对照须加入 MCPS 作为相关工作/扩展对照，区分「调用消息没被改」与「调用确实被授权」；不得把消息签名当作授权证明 |

`[FACT]` 三者的定位小结：
- **OWASP 两份 Cheat Sheet**：已提出「审批绑定到精确动作 + 执行前原子消费」的**原则**。
- **MCPS**：已提供「Agent 身份 + 消息/工具定义完整性 + 防重放」的**密码学机制**，但明确不替代授权、不提供 safety 分析。
- **本方向的候选增量**（待测）：「独立授权方签发的动作批准凭证 → 跨信任域验证 → 一次性消费」的**授权信任关系**，而非消息完整性本身。
- **★两类保证必须分开断言** `[FACT/INFER]`：防重放/一次性消费已由 OWASP 的共享状态原子消费覆盖，签名凭证本身不新增该能力；唯一可能的新增是**跨信任域验证**——执行方在不共享应用信任域、不信任对方内部状态时仍能独立验证授权来源与内容。若 B 组已共享信任域且已有原子消费，**不得**把「换成 Ed25519 签名」声称为新的防重放增量（见 §3 的保证区分表）。

**MCP 新版本的一处须严格区分的表述** `[FACT]`：2026-07-28 authorization 页出现 "The required scopes may be determined dynamically based on the specific request arguments and context, but once determined, they should be emitted together."——这是 **Server 决定 challenge 中返回哪些 scope**，不是「OAuth token 绑定到具体参数」。不得据前者声称规范已支持参数级绑定，也不得据后者忽略前者而过度简化。

---

## 6. 关键研究问题（决定 GO/NO-GO）

综合三场景、差距与相关工作，E3 是否值得做，取决于以下问题的答案：

1. **独立授权凭证的可行性** `[ASSUMPTION 核心]`：能否构造「可信授权界面展示具体动作 → 用户确认 → 独立授权服务签发一次性凭证 → 执行方跨信任域验证并原子消费」的闭环，且授权方与执行方真正分离？若否，GAP-1 无法落地。
2. **相对 B 组的独立增量** `[ASSUMPTION 核心]`：在「普通应用层精确参数审批 + 原子消费（B 组）」已存在的条件下，密码学凭证（C 组）是否带来**可测量**的额外收益？若无，按 GO_NO_GO 判定停止，不为保留密码学框架而继续。
3. **在途篡改真实性** `[ASSUMPTION]`：Planner→Executor 之间的参数篡改在真实 Agent 中是否是现实威胁，还是仅实验构造？须明确攻击者位于哪个信任边界（见 THREAT_MODEL C2）。
4. **差异可归因性** `[INFER]`：能否设计实验证明拦截来自独立授权凭证，而非注入偶然失败或普通审批已能拦下？需 A/B/C 三组 + 误拒率测量。
5. **现有机制共存** `[FACT]`：Gateway 能否作为第三方验证者与 OAuth/HITL/MCPS 共存而不破坏 audience/consent/签名语义？MCP 中插入 Gateway 会改变 OAuth audience 归属，需重新设计信任锚。

---

## 7. 与 E2 的关系（不混淆）

- E2 在**受控环境**验证了 Binding/D10/D11/Receipt/Journal 的机制可行性（N=10，非形式化证明）。
- E3 若要成立，必须用**真实 Agent 工具调用链**重新验证差异，不能把 E2 数字搬过来当真实安全保证。
- E2 的负面边界（F2 重复副作用、Sink 幂等外部依赖、Receipt 非外部真实性证明、无全局 dispatch at-most-once）在 E3 中**继续成立**，不得因换场景而消失。

---

## 来源

[^W1]: OWASP Cheat Sheet Series, "AI Agent Security Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html（§1 Tool Authorization Middleware、§4 High-Impact Action Integrity Controls，逐字核实）
[^W2]: OWASP Cheat Sheet Series, "Transaction Authorization Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html（§1.1、§1.5、§2.1、§2.3、§2.6、§2.8、§2.10，逐字核实）
[^W3]: OWASP, "MCP Top 10" (beta / Phase 3) — owasp.org/www-project-mcp-top-10（MCP08 immutable audit trails 为实践建议，非协议强制）
[^W4]: R. Sharif, "MCPS: Cryptographic Security Layer for the Model Context Protocol", `draft-sharif-mcps-secure-mcp-01`, 2026-08-21 — datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/（§1.2、§1.3、§3、§4、§5、§6、§7、§11.1、§11.2 逐字核实；个人 Internet-Draft，"work in progress"，非已采纳标准）
