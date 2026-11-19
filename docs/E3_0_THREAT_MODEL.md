# E3-0 威胁模型：候选 Agent 工具调用场景

> **阶段性质**：研究与威胁建模，暂不开发、不接入、不提交。
> **依据**：`E3_0_SCENARIO_SURVEY.md` 的三场景调研与一手来源。标签 `[FACT]` / `[INFER]` / `[ASSUMPTION]` 同前。
> **核心纪律**：威胁必须锚定真实 Agent 工具调用链；**Prompt Injection 的存在不等于本框架能解决它**；E2 受控实验结论不外推为真实 Agent 上已成立的安全保证。
> **★E3-0.1 修订（重要）**：C2「在途参数篡改」原表述过于笼统——TLS 已提供传输完整性，普通网络攻击者无法修改已受 TLS 保护的 MCP 请求。本版明确 C2 攻击者位于 **TLS 终止之后**的具体信任边界，标注其为**实验构造能力而非已观察现实攻击**，并要求说明为什么 TLS、Host 审批与 MCP Server 输入校验都不能解决它、授权签名方与执行验证方如何真正独立。否则实验只能证明「数字签名能检测参数修改」，而非一个真实 Agent 安全问题。

---

## 1. 通用模型：Agent 工具调用链的信任结构

三个场景共享同一抽象链条（粒度不同）：

```
用户意图 U
   ↓ (自然语言)
LLM / Planner  →  工具调用请求 (tool_name, arguments)
   ↓ (harness / client 路由)
执行边界 E  ←── 现有授权检查（OAuth / RBAC / approval / sandbox）
   ↓
外部工具 / DB / API  →  副作用 S
   ↓
结果回灌 LLM → 下一轮
```

关键观察 `[FACT]`：
- LLM 决定工具名与参数（三场景均成立）；
- 现有授权检查位于执行边界 E，但粒度是**工具名/命令/DB 角色/Server 级 scope**，不是「具体 tool + 具体参数值」；
- 结果回灌形成多轮循环，注入可经工具输出（间接注入）进入下一轮 Planner 输入。

我们的框架作用于**执行边界 E 及其前后**（Gateway 门禁、Binding 绑定、D10/D11 状态、Receipt 记录、Journal 恢复）。它**不作用于** LLM 推理过程，也**不消除**被污染 Planner 产生的「看起来合法」的调用。这一定位决定了下面所有威胁哪些可覆盖、哪些不可覆盖。

---

## 2. 资产（Assets）

| 资产 | 说明 | 三场景相关性 |
|---|---|---|
| A1 用户授权意图 | 用户真正允许的操作范围（目标、参数、预算） | 全部；Binding 应绑定此对象 |
| A2 外部副作用 S | 仓库写、SQL 写、API 调用、邮件/消息等真实状态变化 | 全部；Effect at-most-once 关注对象 |
| A3 凭据与令牌 | OAuth token、PAT、SSH key、API Key | GitHub / MCP 尤甚 |
| A4 私有数据 | 私有仓库内容、DB 行、上下文窗口 | 全部；外泄攻击目标 |
| A5 执行记录与审计链 | 谁在何时基于哪次授权调用了什么、得到什么结果 | 全部；Receipt / Journal 目标 |
| A6 预算与配额状态 | 已消耗额度、调用次数、成本 | D10/D11 关注对象 |

---

## 3. 信任边界（Trust Boundaries）

| 边界 | 两侧 | 现有主控方 | 对我们框架的意义 |
|---|---|---|---|
| TB1 用户 ↔ Planner | 用户意图 → 自然语言 prompt | 用户 / Agent 前端 | 注入在此进入；框架不覆盖 |
| TB2 Planner ↔ 执行边界 E | 模型输出的工具调用 → harness | LLM / harness | **Binding 的唯一有效切入点**，但须绑定 U 而非模型输出 |
| TB3 执行边界 E ↔ 工具 | 授权判定 → 真实副作用 | 平台权限 / OAuth / RBAC | Gateway/D10/D11 与现有机制在此叠加 |
| TB4 工具 ↔ 结果回灌 | 工具输出 → 下一轮 LLM 上下文 | 工具 / 数据源 | 间接注入在此进入；框架不覆盖 |
| TB5 记录 ↔ 验证方 | 执行记录 → 独立验证/追责 | 现有多由 agent 自身产生日志 | Receipt / Journal 独立性价值所在 |

`[INFER]` 我们框架真正能提供新增保证的边界是 **TB2（参数级绑定）、TB3（门禁/状态/预算）、TB5（独立可验证记录）**；TB1/TB4 是注入主战场，框架结构上不覆盖。

---

## 4. 攻击者能力（Attacker Capabilities）

按能力递增分层，明确每层对应哪些真实证据：

- **C1 内容注入者** `[FACT]`：能在 PR 描述 / issue / DB 记录 / 工具 description 中放置恶意文本，诱导 Planner 产生非预期工具调用。证据：CamoLeak、P2SQL 间接注入、Invariant tool poisoning。
- **C2 参数篡改者（TLS 终止之后）** `[ASSUMPTION]`：**不是**网络传输中的普通攻击者——TLS 已为 MCP 请求提供传输完整性，线路窃听/中间人不能修改已受保护的请求（MCPS §1.2 亦明示 MCP-over-HTTP 靠 TLS 提供传输机密性）。C2 必须是**在 TLS 终止之后**能改写的主体，位于以下某个具体信任边界（须在实验中明确选其一并论证真实性）：
  - (a) **被攻陷的 Host / Client  middleware**：`tools/call` 在被签名批准之后、发出之前，于 Host 内部被改写；
  - (b) **不可信的工具路由 / 网关组件**：多 Agent 委派或代理链中，中间执行方改写下游调用参数；
  - (c) **被篡改的本地执行链**：stdio 传输下 host 与 server 之间的本地进程被控制。
  - **定位** `[ASSUMPTION]`：以上能力在真实 Agent 中的普遍性**尚无一手实证**，属实验构造能力；若只能人为构造，研究价值降为「机制验证」而非「真实威胁防护」。
  - **为什么不能假定现有机制一定解决** `[FACT/INFER]`（区分规范要求、行业建议、真实实现三层，不从规范等级推断产品行为）：①**TLS** 只保护传输、不保护 TLS 终止后的端内数据（此层为 `[FACT]`）；②**MCP 规范**建议人工参与（2026-07-28 tools 页 human-in-the-loop 为 SHOULD），但**未统一规定所有 Host 的确认界面必须展示并绑定完整规范化参数**——这是规范覆盖面的事实，不代表任何具体 Host 的实现缺陷；③**OWASP 已明确提出**参数级审批与参数变化后重新批准原则（AI Agent Security / Transaction Authorization Cheat Sheet）[^W1][^W2]；④**具体 Host 是否落实、确认界面是否覆盖实际生效参数，须针对选定实现单独核实**，不能从规范 SHOULD 等级直接推断其未落实；⑤**MCP Server 输入校验**做 schema/类型校验而非语义合法性校验。OWASP MCP 安全指南讨论 TLS 终止后的消息完整性，并指出 MCP 核心传输规范不要求每条 JSON-RPC 消息都签名。[^M1][^W1]
  - **独立性要求** `[ASSUMPTION]`：授权签名方（可信授权服务/用户界面）与执行验证方（Gateway/Executor）必须在不同信任域；若同一主体既签又验，C2 能同时改写两者，机制失效。
- **C3 越权调用者** `[FACT]`：利用过宽 scope / confused deputy 调用本不应调用的工具或参数。证据：MCP02 scope creep、CVE-2025-49596。
- **C4 重放/重试者** `[FACT]`：能触发同一 `tools/call` 的重复执行（网络超时重试、at-least-once runtime）。证据：工程实践中 at-least-once 重试导致重复副作用；MCP 规范无幂等强制机制 `[ASSUMPTION]`。
- **C5 记录篡改者 / 内部威胁** `[INFER]`：能修改 agent 自身产生的日志或 harness 状态。若验证方与被验证方同一信任域，独立性失效——这是 Journal/Receipt 价值的前提条件。
- **C6 服务端变更者（rug pull）** `[FACT]`：工具经用户批准后变更 description 或行为。证据：Invariant rug pull。

**能力—资产映射**：C1→A4/A3（外泄）；C2→A1/A2（执行非授权操作）；C3→A2/A4（越权）；C4→A2/A6（重复副作用/预算）；C5→A5（伪造审计）；C6→A1（批准后语义漂移）。

---

## 5. 攻击路径（Attack Paths）

### AP-1 间接注入 → 数据外泄（TB1/TB4）
恶意文本存于 PR 描述或 DB 记录 → 被查询/读取回灌 Planner → Planner 产生外泄型工具调用（如读取 SSH key 经 `sidenote` 外传）→ 执行边界放行（因调用「看起来合法」）。`[FACT]` CamoLeak、P2SQL RI.1/RI.2、Invariant `add(sidenote)`。
**框架覆盖判断** `[INFER]`：**不覆盖根因**。Binding 签的是模型输出参数，注入产生的恶意参数会被合法签名；只有出口策略（若定义了敏感参数禁止规则）可能拦下部分外泄，但这属于 Gateway 策略而非 Binding 的密码学保证。

### AP-2 TLS 终止后的参数篡改（TB2，C2）
用户经可信授权界面确认具体动作 `send_email(to=A)` → 独立授权服务签发一次性凭证（绑定规范化参数）→ **在 TLS 终止之后**，被攻陷的 Host middleware / 不可信路由 / 本地执行链将生效 arguments 改为 `to=B`（C2 的 (a)/(b)/(c) 之一）→ 执行方若无凭证校验则按 `to=B` 放行。`[ASSUMPTION]` 此攻击能力为实验构造，须明确攻击者所在信任边界并论证现实性；不是线路中间人（TLS 已保护传输）。
**框架覆盖判断** `[FACT/INFER]`：这是一次性授权凭证 + 参数绑定的**目标威胁**。若凭证在篡改前签发、执行方跨信任域校验参数摘要并原子消费，则篡改被拒。但三个前提缺一不可：①签名对象是**用户确认的具体动作 A1**而非模型输出参数（否则 AP-1 下无效）；②授权方与执行验证方处于**不同信任域**（否则 C2 可同时改写两边）；③校验发生在**TLS 终止之后、副作用提交之前**的执行边界。若只证明「签名能检测参数变化」而未满足以上三点，则实验价值有限。

### AP-3 越权 / confused deputy（TB3）
过宽 scope 或 token passthrough → MCP Server 以错误的 authority 调用下游 → 下游误信。`[FACT]` MCP02、token passthrough 禁令（规范原文已核实）。
**框架覆盖判断** `[INFER]`：部分覆盖。D10/D11 可提供请求级预算与状态约束，但身份/audience 问题是 OAuth 的职责，不应由本框架重复解决。

### AP-4 重试重复副作用（TB3/TB4）
写操作成功但响应超时 → runtime 重试 → 第二次副作用。`[FACT/INFER]` E2.2 F2 已在受控跨进程 kill 下证明重复副作用 10/10；真实 Agent 上的对应风险 `[ASSUMPTION]` 需实验验证。
**框架覆盖判断** `[FACT]`：E2.3 证明工具端幂等（受控 Sink）可在允许重复 dispatch 下压住第二副作用——但该结论**不能外推**为真实第三方 API 上已成立；真实工具必须自身支持幂等键。Journal 单独不证明外部副作用是否发生。

### AP-5 记录伪造 / 审计缺失（TB5）
agent 自身日志被篡改或缺失 → 无法追责。`[FACT]` OWASP MCP08（beta）要求 immutable audit trails。
**框架覆盖判断** `[INFER]`：Receipt（Ed25519）+ Journal（独立权威）是针对性设计，但价值依赖「验证方在独立信任域」这一部署条件（C5）。

### AP-6 Rug pull / 批准后语义漂移（TB1/TB2）
工具经审批后服务端变更 description 或行为 → 用户以为调用可信工具，实际调用恶意版本。`[FACT]` Invariant rug pull。
**框架覆盖判断** `[INFER]`：若 Binding 绑定工具描述/版本哈希并变更即复审，可部分缓解；但这是设计扩展，非现有 E1/E2 能力。

---

## 6. 安全目标（Security Goals）

| 目标 | 定义 | 现有机制覆盖 | 本框架可贡献 |
|---|---|---|---|
| G1 授权一致性 | 执行的 tool+参数 == 用户授权意图 | 部分（工具名/scope 粒度） | **核心**：参数级密码学绑定（前提：绑 U 不绑模型输出） |
| G2 副作用至多一次 | 重试不产生第二外部效果 | 部分（工具幂等，非普遍） | 受控条件下成立；依赖工具端幂等，非全局保证 |
| G3 越权最小化 | 不调用未授权工具/数据 | 强（OAuth/RBAC/RLS/sandbox） | 增量有限，不重复造轮子 |
| G4 审计可验证 | 独立可验证的授权→执行→结果链 | 弱（日志多为 agent 自产） | **核心**：签名 Receipt + 独立 Journal（前提：独立验证方） |
| G5 外部泄露防护 | 私有数据不被注入外泄 | 弱（LLM 侧防御可被绕过） | **不声称覆盖根因**；仅出口策略可能部分拦下 |
| G6 预算可控 | 调用成本/次数有确定性上限 | 部分（quota/budget） | 请求级确定性准入（须证明增量） |

---

## 7. 威胁模型的关键约束与诚实边界

1. **绑定对象的根本约束** `[INFER]`：Binding 若绑定「模型输出参数」，则在 AP-1（注入）下失效——恶意参数会被合法签名。要有意义，必须绑定**用户授权意图 A1**，而这要求存在可靠的意图捕获机制（人工审批服务、结构化授权请求）。这是 GO/NO-GO 的决定性问题。
2. **注入 ≠ 可解决** `[FACT]`：P2SQL §5.1.4 明确指出辅助 LLM Guard 属检测型、可被绕过；AgentDojo/ChatInject 显示 prompt 防御基本无效。本框架不解决注入根因，只约束执行侧。
3. **E2 不外推** `[FACT]`：E2.1/E2.2/E2.3 的 N=10 受控结论证明的是机制可行性，不是真实 Agent 上已成立的安全保证；真实验证需重新设计实验（见 RESEARCH_GAP / GO_NO_GO）。
4. **独立性前提** `[INFER]`：Journal/Receipt 的独立性价值仅在「验证方与执行方不同信任域」时成立；同域内签名无额外保证。
5. **在途篡改能力待证** `[ASSUMPTION]`：C2 是正向实验的核心假设，但**不是线路中间人**——TLS 已保护传输完整性。真实 Agent 中必须明确攻击者位于 TLS 终止之后的哪个信任边界（被攻陷 Host middleware / 不可信工具路由 / 本地执行链），并说明为何 TLS、Host HITL（SHOULD 级）、MCP Server 输入校验都不能解决。该能力须在 E3 实验中明确构造并标注为实验假设，不得写成已观察到的事实；否则实验只能证明「数字签名能检测参数修改」。[^M1][^W1]
6. **消息签名 ≠ 用户批准** `[FACT]`：MCPS 逐消息签名（含 `tools/call` name/arguments）证明「消息由谁发、是否被改」，但其 §1.2 明示 "does not replace OAuth-based access control"、§11.2 明示提供 provenance 而非 safety analysis。**Agent 可以合法签署一条恶意工具调用**——消息完整性不自动等于该调用经过用户授权。本威胁模型不得把 MCPS 的消息签名当作授权保证，也不得把本方向的一次性授权凭证当作消息完整性机制。[^W4]

## 来源补充（E3-0.1）

[^M1]: MCP Specification 2026-07-28, "Tools" / "Security Best Practices" — modelcontextprotocol.io/specification/2026-07-28/server/tools（human-in-the-loop 为 SHOULD；annotations MUST 不可信；"MCP itself cannot enforce these security principles at the protocol level"）
[^W1]: OWASP Cheat Sheet Series, "AI Agent Security Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html（§1 Tool Authorization Middleware：user_confirmed 不足、target/参数变更需重新批准、执行前原子消费）
[^W2]: OWASP Cheat Sheet Series, "Transaction Authorization Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html（§1.5：共享状态下执行前原子 check-and-consume；每操作唯一凭证）
[^W4]: R. Sharif, "MCPS: Cryptographic Security Layer for the Model Context Protocol", `draft-sharif-mcps-secure-mcp-01`, 2026-08-21 — datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/（个人 Internet-Draft，非已采纳标准；§1.2、§11.2 逐字核实）
