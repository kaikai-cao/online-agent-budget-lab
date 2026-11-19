# E3-0 场景调研：三个真实 Agent 工具调用场景的比较

> **阶段性质**：E3-0 是研究与威胁建模阶段，暂不开发、不接入真实 Agent、不新增密码学机制、不提交推送。
> **目标**：找到一个真实存在、可复现、且确实需要 E1/E2 可信执行机制的 Agent 工具调用场景，并判断现有框架是否值得接入。
> **方法**：调研官方文档、真实代码仓库、原始论文与安全公告；每项判断标注 `[FACT]` 已证实 / `[INFER]` 合理推测 / `[ASSUMPTION]` 待验证假设。
> **核心纪律**：不预设哪个场景最好；不把「Prompt Injection 存在」等同于「本方案能解决它」；不把 E2 受控实验结果写成真实 Agent 上已成立的安全保证；单纯把 Gateway 接到某框架不构成研究创新。
> **证据核对时间**：2026-11（E3-0.1 于同月修订）。关键一手来源已二次核实（见各节脚注与文末来源清单）。
> **★E3-0.1 修订**：MCP 规范版本从 2025-06-18 更新为 **2026-07-28**（Server 级 `resource` 语义与无 tool+参数绑定仍成立）；Tools 页 human-in-the-loop 为 **SHOULD** 级建议而非 MUST；「stateless」表述改为「无协议级跨调用状态与幂等保证，但允许 Server 通过显式 handle 在应用层管理状态」；补充 OWASP 两份 Cheat Sheet 与 MCPS draft 相关工作，论证重心从「arguments_digest 是规范空白」调整为「独立授权凭证跨信任域的可验证性与一次性消费」。

---

## 0. 判定框架：什么算「真实缺口」

对我们框架（Gateway / Request Binding `arguments_digest` / D10 预算准入 / D11 状态转移 / Receipt / Journal）而言，只有满足以下条件的场景才值得进入 E3：

1. **存在独立信任边界**：授权决策方与工具执行方分离，或执行方不可信/可被攻陷。若同进程自签自验，密码学绑定无额外保证 `[INFER]`。
2. **缺口是结构性的**：现有框架/协议已覆盖的部分不重复建设；只补「独立授权方的动作批准 ↔ 跨信任边界可验证的一次性凭证」、独立权威记录、确定性状态与恢复等待证缺口。**注意**：参数级审批原则（OWASP Cheat Sheets）与消息签名/防重放（MCPS）已有相关工作，「给 MCP 加 arguments_digest」本身不是创新（见 §3.8、RESEARCH_GAP §5）。
3. **攻击可复现且有对照**：能设计「无框架基线 vs 启用框架」的可复现实验，且能量化检出率与误拒率（可用性代价）。
4. **差异可归因**：实验成功必须来自执行侧的绑定/门禁，而非「注入被偶然挡住」。

三个场景按此框架比较，而非按流行度或接入难度。

---

## 1. 场景一：GitHub Agent

### 1.1 真实框架与工具调用链 `[FACT]`

真实产品已规模化落地：GitHub Copilot coding agent（云代理，从 issue/PR 评论触发，探索仓库、写代码、过测试、开 PR）、Copilot CLI / SDK、Agent HQ（集成 Anthropic / OpenAI / Google / Cognition / xAI 第三方 agent）；另有 OpenAI Codex（CLI/IDE/Cloud）、Claude Code 等。工具调用采用标准 agent loop：每轮 LLM 决定是否请求工具 → harness 机械执行 → 结果回灌下一轮。Copilot SDK 文档明确「CLI is purely mechanical: model asked for tools → execute → call model again」。[^G1][^G2]

### 1.2 LLM 能否决定工具名与参数 `[FACT]`

能。LLM 每轮直接输出 tool request（含工具名与参数），harness 按请求执行。Claude Code 权限文档以 `tool_name` + `tool_input` 为判定对象，并支持 hook 用 `updatedInput` 改写参数——反证参数由模型产出、执行前可见。GitHub 生态 2025-11 起弃用 GitHub App 版 Copilot Extensions，全面转向 MCP 作为工具协议。[^G2][^G3] `[INFER]` `arguments_digest` 的威胁模型（planner 输出可被注入污染）在架构上成立，但「参数由 LLM 决定」≠「参数未经校验即执行」（见 1.3）。

### 1.3 执行前的独立授权检查 `[FACT]`

存在且多层。判定主体分两侧：
- **平台侧身份/权限**：写权限触发、fine-grained PAT / GitHub App permissions、环境 secret 隔离、仅能推 `copilot/` 分支或现有 PR 分支（不能推 main）、无法访问 Actions org/repo secrets、过滤隐藏字符。
- **harness 侧策略**：Copilot App 三档工具权限（每次询问 / Assisted / 全部批准）、Plan 模式审阅；Codex `sandbox_mode`（read-only/workspace-write/danger-full-access）+ `approval_policy` + 独立 reviewer agent；Claude Code 六步权限流水线（Hooks → Deny → Ask → Permission mode → Allow → canUseTool）。[^G1][^G2][^G4]

`[INFER]` 授权检查并非空白，框架必须定位为「跨 harness 的统一策略与密码学绑定层」，而非替代既有权限模型。

### 1.4 风险证据 `[FACT] + [ASSUMPTION]`

- **真实在野案例**：CamoLeak（隐藏 Markdown 注释注入 PR 描述 → Copilot Chat 摄取 → 以受害者权限读私有仓库 → Camo 签名图片 URL 逐字符外泄），据 Legit Security 披露、GitHub 2025-08 禁用 Chat 图片渲染；CVE 编号在二手来源间冲突（有称 CVE-2025-59145、有称无 CVE），**需以 NVD/MITRE 原条目核实** `[ASSUMPTION]`。[^G5]
- **CVE-2025-62453**：MSRC，Copilot 与 VS Code 安全功能绕过，CWE-1426（Improper Validation of Generative AI Output）+ CWE-693，Important，2025-11-12。[^G6]
- **学术**：AgentVigil 黑盒红队在 AgentDojo / VWA-adv 对 o3-mini / GPT-4o 达 71% / 70% ASR；ChatInject 将 AgentDojo ASR 5.18%→32.05%、InjecAgent 15.13%→45.90%，基于 prompt 的防御基本无效。[^G7]
- **OWASP**：LLM01 Prompt Injection、LLM07 Insecure Plugin Design、LLM08 Excessive Agency。[^G8]

`[ASSUMPTION]` GitHub Agent 上「重试重复副作用、参数在传输中被篡改」尚缺一手实证；公开案例主要是**注入 → 读取/外泄**与**策略绕过**，而非授权签名缺失直接导致的越权。**严禁将「注入存在」推导为「本框架能解决注入」**：注入根因是 LLM 无法区分指令与数据，Gateway/Binding 只约束执行侧，不消除被污染 planner 产出「看起来合法」的工具调用。

### 1.5 现有机制（不要重复造轮子）`[FACT]`

sandbox、approval、hooks、权限模型、分支保护、CodeQL / secret scanning、签名提交、每提交会话日志永久链接均已有。框架的「通用准入 + 授权」若按现有形态直接落地，重复度高。

### 1.6 本框架可补缺口 `[INFER]`

| 组件 | 判断 |
|---|---|
| Gateway | 大致重复；仅「跨 harness 统一策略」或第三方 agent 一致性未知时有价值 |
| **Binding + arguments_digest** | **最有潜力**：现有规则是工具名/命令粒度（如 `Bash(npm test)`），hook 可改参数但无「授权决策 ↔ 精确参数」的密码学绑定；价值仅在存在独立签名方/验证方（人工审批服务、策略服务、跨 agent 委派）时成立；同进程自签自验无额外保证 |
| D10 预算 | 部分重复：Codex 已有线程/超时上限，但无「授权绑定的每工具预算」 |
| D11 状态转移 | 推测性：agent loop 隐式状态机，对 Plan→Edit→PR 多步流程有理论价值 `[ASSUMPTION]` |
| Receipt | 与提交签名不同维度：Verified 签名证明「提交来自 Copilot 且未改」，不证明「哪次授权允许哪个工具调用/参数/结果」；价值依赖验证者与追责闭环 |
| Journal | 会话日志由 agent/harness 自身产生、非独立权威；若威胁模型含 harness 被攻陷，独立性有价值 |

### 1.7 可设计实验

A 注入→越权工具调用（PR 描述植入隐藏注释诱导越权 `gh api`）；B 参数篡改（`arguments_digest` 开关对照）；C 重试重复副作用（API 超时后重试，Journal 幂等对照）；D Receipt 可验证性（独立验证方重建授权→调用→结果链）。**注意**：注入成功≠框架成功，只有执行侧阻断且不影响合法任务才算有效。

---

## 2. 场景二：数据访问 Agent

### 2.1 真实框架与工具调用链 `[FACT]`

真实产品形态清晰：LangChain `create_sql_query_chain` / SQL agent、Vanna 2.0（自述 user-aware AI agent framework）、Databricks AI/BI Genie、Microsoft Copilot Studio 经 MCP 接入 Genie。工具调用链：LLM 生成 SQL → tool 在 DB 执行 → 结果回灌 LLM → 生成回答。P2SQL 论文（ICSE 2025）区分 SQL chain（一次一条）与 SQL agent（一次多条、多步）。[^D1][^D2]

`[INFER]` 这类 Agent 的「工具」粒度是**整条 SQL 字符串**而非结构化 API 参数——这决定 Binding 的对象是 SQL 文本，对 `arguments_digest` 的语义提出新问题。

### 2.2 谁决定 SQL 与参数 `[FACT]`

SQL 由模型生成，非纯模板。P2SQL 论文 §3.2.1 证实 LLM 可被诱导生成 `DROP TABLE users CASCADE`、`UPDATE ...` 等任意 SQL；但存在模板化/检索约束（Vanna 用 DDL/文档/question-SQL 对做 RAG；Genie 用 example SQL + Unity Catalog 元数据约束）。`[INFER]` 混合模式：SQL 由模型自由生成，精度靠示例/元数据引导。[^D2]

### 2.3 执行前的独立授权检查 `[FACT]`

授权主要下移到数据库层：P2SQL 防御方案建独立 `MODE_CHATBOT` 角色仅授 SELECT；Genie 用双凭证——计算凭证由作者嵌入、数据访问按终端用户自身 Unity Catalog 身份评估，「row filters and column masks are automatically enforced per user」；Vanna 2.0 有 RBAC（per-tool `access_groups`）、per-user quota、会话隔离；MCP Authorization（OAuth 2.1）强制 audience 校验但**未定义 per-tool / per-parameter 授权**。[^D1][^D3][^M1]

`[FACT/INFER]` 分四层看，避免把已有工作误写成空白：①数据库层 RLS/RBAC 主要控制**数据访问权限**（谁可读哪些行/列），不覆盖「哪次批准对应哪条查询」；②应用层**参数级审批已有成熟设计原则**（OWASP AI Agent Security / Transaction Authorization Cheat Sheet 要求审批绑定规范化参数、参数变化后重新批准、执行前原子消费）[^W1][^W2]；③尚待验证的是——**当独立授权方与数据库执行方分离时，密码学授权凭证能否带来额外保证**，这是研究假设而非已证缺口；④**不能仅凭 MCP OAuth 的 Server 级 `resource` 语义，就推导出 Text-to-SQL 场景也存在同样的协议缺口**——两者协议与应用结构不同。

### 2.4 风险证据 `[FACT]`

- **P2SQL 攻击**（arXiv:2308.01990, ICSE 2025，LangChain，7 个 LLM）：直接注入 DROP / 篡改记录 / dump users；提示加固后仍绕过（写限制绕过、「我现在是 user 2」读他人数据）；**间接注入**（恶意文本存于 DB 记录被回灌）：答案操纵、SQL agent 多步攻击；多数基础攻击成功率 1.0。[^D2]
- arXiv:2211.15363（ISSRE 2023）证实商业黑盒 Baidu-UNIT、Ai2sql 可被诱导生成恶意 SQL；ToxicSQL（arXiv:2503.05445）用投毒生成可执行恶意 SQL。[^D4]
- OWASP LLM01 / LLM02 / LLM06 / LLM10；MCP Top 10（beta）MCP2 scope creep / MCP5 命令注入 / MCP8 缺乏审计遥测。[^G8][^M3]

**重要边界** `[FACT]`：P2SQL 论文 §5.1.4 指出辅助 LLM Guard 本身仍属检测型、可被绕过；注入存在 ≠ 任何特定方案能解决。`[INFER]` 最危险的 Text-to-SQL 注入是「LLM 在合法权限内生成泄露性 SQL」，Binding 对此无效——需 RLS / SQL rewriting。

### 2.5 现有机制 `[FACT]`

PostgreSQL RLS（default-deny、按 user/role/命令、security-barrier qual）；`statement_timeout` / `lock_timeout`；OWASP 首选参数化查询/ORM；Vanna 审计日志（敏感参数 `[REDACTED]`）、rate limiting；Genie per-user 查询归属、budget/cost controls。数据权限、超时、参数化、审计已有较强覆盖。[^D5]

### 2.6 本框架可补缺口 `[INFER]`

Binding（候选：把独立授权方的批准绑定到规范化 SQL 参数；**参数级审批原则本身已有，不是空白**；待证增量仅在授权方与 DB 执行方跨信任域分离时）；D11 状态机（planned/in-flight/committed/failed，缓解重试重复副作用）；Receipt（不可抵赖执行记录，补 MCP8 建议的 immutable audit；价值须落到独立验证者能验证什么）；Journal（独立权威日志与恢复）；D10 请求级配额（须证明相对 Vanna quota / Genie budget 的确定性增量）。**本节不沿用「MCP 规范只绑 Server、故 Text-to-SQL 也有协议缺口」的推论**（见 §2.3）。

**明确不做** `[FACT]`：不声称解决 Prompt Injection；绑定能防「参数被改」，不能防「LLM 在已授予权限内生成泄露性 SQL」。

### 2.7 可设计实验

复现 P2SQL U.1/U.3/RD.2/RI.1/RI.2 测 ASR；无框架 vs Gateway+Binding+Receipt 对照；参数篡改（Planner→Executor 改 SQL）检验 digest；timeout-after-success 写操作检验 D11+Receipt 去重；无界 join 检验 D10；RLS 开/关证明框架不替代 DB 层授权；篡改 Journal 检验 Receipt 完整性。

---

## 3. 场景三：MCP 工具调用 Agent

### 3.1 真实框架与工具调用链 `[FACT]`

真实生态为 Host → 多个 Client → 各自 Server 的星型结构；工具调用是 JSON-RPC 2.0 的 `tools/list` → `tools/call` 两阶段。传输层现为 stdio + Streamable HTTP（SSE 已并入 Streamable HTTP）。`tools/call.params.name` 必须与发现响应精确匹配，`arguments` 按 `inputSchema` 填写；Host 合并所有 Server 工具为统一 registry，LLM 依描述选择，Host 拦截后路由。真实产品如 AWS MCP Server（2025-11 预览，覆盖 15000+ AWS API，IAM 鉴权 + CloudTrail 审计）。**规范版本已更新至 2026-07-28**（本轮核对版本；该版新增 Extensions 概念与 per-request capability negotiation，Server 级 `resource` 语义与无 tool+参数 token 绑定仍成立）。[^M1][^M2]

`[INFER]` Gateway 放在 Client↔Server 之间在协议上可截获 `tools/list`/`tools/call`，但会改变 OAuth audience 归属，需作为资源方重新设计。

### 3.2 LLM 能否决定工具名与参数 `[FACT]`

能，且是 MCP 设计意图（"Tools are designed to be model-controlled"）。`inputSchema` 是 JSON Schema（默认 2020-12，MUST 是合法 object），仅做结构与类型校验，不校验语义。规范明确：工具 annotations/descriptions 除非来自可信 Server 否则客户端 MUST 视为不可信；"MCP itself cannot enforce these security principles at the protocol level"。[^M2] 新版 2026-07-28 tools 页原文：human in the loop 为 **SHOULD**（"there SHOULD always be a human in the loop with the ability to deny tool invocations"），confirmation prompts 列为 Applications SHOULD 项——**不是协议 MUST 强制**，不可写成强制门禁。

`[INFER]` schema 合法 ≠ 意图合法：被注入后生成的参数仍是 schema 合法值。这是 Binding 最直接的切入点，但**若只绑定「LLM 最终产生的参数」，注入产生的恶意参数同样会被合法签名**——必须绑定「用户授权意图」。

### 3.3 执行前的独立授权检查 `[FACT]`

有 OAuth 授权但**粒度是 Server 级/粗 scope，不是 tool + 参数级**（2026-07-28 版原文已二次核实）：
- `resource` 参数（RFC 8707）MUST 标识「the MCP server that the client intends to use the token with」、MUST 用 server 的 canonical URI（如 `https://mcp.example.com/mcp`）——**绑定对象是整个 MCP Server，不是具体 tool + 参数**。[^M1]
- Token passthrough / 非本 Server audience 的 token 明令禁止（MUST NOT send / MUST NOT accept or transit；Security Considerations 将 confused deputy 列为 MUST 遵循的安全主题）。[^M1][^M4]
- 新版 tools 页："For trust & safety and security, there SHOULD always be a human in the loop with the ability to deny tool invocations"，confirmation prompts 为 Applications SHOULD；主页 Key Principles 有 "Hosts must obtain explicit user consent before invoking any tool" 的表述（原则层 must，非 tools 页强制门禁）。[^M1][^M2]

`[FACT]` 规范中不存在把 token 绑定到具体 tool + 具体 arguments（更无 arguments digest）的机制。**须严格区分一处易混表述** `[FACT]`：2026-07-28 authorization 页出现 "The required scopes may be determined dynamically based on the specific request arguments and context, but once determined, they should be emitted together."——这是 **Server 在 challenge 中动态决定返回哪些 scope**，不是「token 绑定到具体参数」，不得据此声称规范已支持参数级绑定。

`[FACT/INFER]` 规范空白是事实，但**不等于研究创新**：OWASP Agent Security / Transaction Authorization Cheat Sheet 已提出精确动作审批与原子消费，MCPS draft 已提供消息签名与防重放（见 §3.8）。本方向的重心是「独立授权方签发的动作批准凭证能否跨信任域验证并一次性消费」。`[INFER]` 「谁判定权限」现有已是 Server（OAuth）与用户（HITL，SHOULD），Gateway 是新增第三方验证者，需明确信任锚。

### 3.4 风险证据 `[FACT] + [ASSUMPTION]`

- **Invariant Labs（2025-04）**：恶意 `add` 工具在隐藏 description 中指示读取 `~/.cursor/mcp.json`、`~/.ssh/id_rsa` 并经 `sidenote` 外传，Cursor 确认框未展示完整参数；**Rug pull**（批准后服务端改描述）、**跨 Server tool shadowing**（恶意描述改写可信 `send_email` 收件人，用户仍以为调用可信工具）。[^M5]
- **OWASP MCP Top 10（2025 beta，Phase 3）**：MCP01 令牌管理、MCP02 scope creep、MCP03 Tool Poisoning、MCP04 供应链、MCP05 命令注入、MCP06 上下文 Prompt Injection、MCP07 认证授权不足、MCP08 Lack of Audit and Telemetry（原文建议 "immutable audit trails"）、MCP09 Shadow Servers、MCP10 上下文过度共享。**定位说明** `[FACT]`：MCP Top 10 仍标注 beta，MCP08 是**安全实践建议、非 MCP 协议强制要求**；OWASP 另已推荐结构化日志、完整工具调用参数记录、日志完整性保护与集中式审计，因此 Receipt+Journal 不能仅以「现有日志不可信」立论。[^M3]
- **CVE-2025-49596**：MCP Inspector <0.14.1 客户端与 proxy 间缺认证，未认证请求可经 stdio 启动任意命令 → RCE，CVSS 9.4，CWE-306（**二手转引，需以 NVD 原条目核实** `[ASSUMPTION]`）。[^M6]
- arXiv:2503.23278（4 类攻击者、16 威胁场景）、arXiv:2504.03767（实测恶意代码执行、凭据窃取）。[^M7]

`[FACT/警示]` 这些只证明攻击面真实，**不证明**本框架能防御；E2 受控结论不可外推。`[INFER]` tool poisoning / shadowing 主要污染**模型推理输入**，Binding 作用于**调用出口**，两者错位——出口签名无法阻止被注入的参数产生，除非授权对象是用户意图而非模型输出。

### 3.5 现有机制 `[FACT]`

OAuth audience 校验、token passthrough 禁令、per-client consent、consent UI、HITL 拒绝、输入校验/限流/输出清洗、session 绑定 user、scope minimization、审计日志建议；新规范 `tools/list` 支持 `ttlMs`/`cacheScope` 与 `notifications/tools/list_changed`（部分缓解 rug pull）；AWS IAM + CloudTrail、MCP-Scan / MCPSafetyScanner。[^M1][^M2][^M3]

`[ASSUMPTION]` 未找到 OpenAI/Anthropic 在协议层提供「按 tool+参数签名的授权 receipt」的证据，需进一步核实其 Agents SDK / Claude Code 实现。

**stateless 的准确表述** `[FACT]`：MCP 2026-07-28 主页 Key Details 写 "Stateless, self-contained requests / Per-request capability negotiation"，核心协议无协议级隐式跨调用 Session State；但规范**明确允许 Server 通过显式 handle 在应用层管理状态**（如 Tasks 扩展的 durable handles、server/discover 的 capability 声明）。因此正确说法是「**MCP 不提供通用的协议级跨调用事务状态与幂等保证，但允许 Server 通过应用层机制管理状态**」，而非「协议完全没有跨调用状态机制」。

### 3.6 本框架可补缺口 `[FACT/INFER]`

Gateway（缺独立逐调用集中策略门禁与跨 Server 统一视图）`[INFER]`；**Binding + arguments_digest（规范层事实：只绑 Server audience/粗 scope，不绑 tool + 参数；但参数级审批原则与消息签名已有相关工作，见 §3.8）`[FACT]`**；D10（规范仅 rate limit 建议，缺累计预算/成本/副作用准入）`[INFER]`；D11（核心协议无通用跨调用事务状态与幂等保证，缺跨调用状态机与幂等去重；Server 可在应用层自建）`[INFER]`；Receipt（MCP08 beta 建议审计，缺独立可验证单次凭证）`[INFER]`；Journal（缺独立权威日志与恢复语义）`[INFER]`。

### 3.7 可设计实验

① 参数篡改（用户批准 `send_email(to=A)` 后途中改 `to=B`，digest 开关对照——但须先按 THREAT_MODEL C2 明确攻击者位于 TLS 终止之后的哪个信任边界，否则只是验证「签名能检测参数修改」）；② Rug pull（描述哈希 pin + 变更复审 vs 按名缓存审批）；③ 跨 Server shadowing（per-server 命名空间 + 用户意图绑定 vs 共享 registry）；④ Tool poisoning 外泄（复现 Invariant `add(sidenote)`，**如实记录出口签名无法阻断的负面结果**）；⑤ token passthrough / confused deputy（audience 校验对照）；⑥ D11 去重 + D10 预算（重放 `tools/call`、循环触发）。**强对照按 GO_NO_GO §4 的 A/B/C 三组设置**（A 普通 Host/HITL、B 精确参数审批+原子消费无密码学、C 独立授权方签名+一次性消费），并加入 MCPS 消息签名作扩展对照；记录检出率、重放成功率、并发重复消费率、可验证性与误拒率。

### 3.8 相关工作（★E3-0.1 新增：不能只与「无 Binding MCP」比较）

`[FACT]` 三项已有工作，均直接触及原 GAP-1 论据，必须在研究中作为基线或对照：

| 工作 | 已提供 | 与本方向的关系 |
|---|---|---|
| **OWASP AI Agent Security Cheat Sheet**[^W1] | 授权在 agent context 之外执行；`user_confirmed` 不足、须验证属于当前 actor 与精确 tool call；target/参数变更重新审批；执行前原子 check-and-consume；high-impact 审批记录绑定 actor/tool name/target resource/normalized parameters/timestamp/expiry | 「精确参数审批」已是既有设计原则，不可声称为原创 |
| **OWASP Transaction Authorization Cheat Sheet**[^W2] | 服务端强制、事务数据授权后不可改、每操作唯一凭证、执行前原子消费且用「所有接收服务器共享的状态」防重放 | 「一次性凭证 + 原子消费」已被明确提出；Journal 的共享状态角色须与此对齐比较 |
| **MCPS**[^W4] `draft-sharif-mcps-secure-mcp-01`（2026-08-21，个人 Internet-Draft，**非已采纳标准**） | Agent Passport、逐消息 ECDSA 签名（JCS 覆盖完整 JSON-RPC，含 `tools/call` name/arguments）、工具定义签名覆盖 description、nonce+timestamp 防重放；§1.2 "does not replace OAuth-based access control"；§11.2 "provides provenance (WHO...), not safety analysis" | **MCPS 证明「消息由谁发、是否被改」，本方向应证明「调用是否经独立授权方批准」**；Agent 可合法签恶意调用，消息签名不能自动证明用户批准。二者互补，不可互相替代 |

`[INFER]` 结论：MCP 场景仍值得优先研究，但**不是因为它有一个别人没发现的 arguments_digest 空白**，而是因为它适合研究「Agent 生成 / 用户批准 / 可信执行三者间能否建立独立且可验证的授权关系」。

---

## 4. 三场景比较（不预设结论）

| 维度 | GitHub Agent | 数据访问 Agent | MCP 工具调用 Agent |
|---|---|---|---|
| 工具粒度 | 命令/API 调用（工具名+参数） | 整条 SQL 字符串 | `tools/call` name + arguments |
| LLM 决定工具/参数 | 是 `[FACT]` | 是（SQL 自由生成）`[FACT]` | 是（model-controlled）`[FACT]` |
| 现有执行前授权 | 多层（平台权限+sandbox+approval+hooks）`[FACT]` | DB 层 RLS/RBAC + 框架粗 RBAC `[FACT]` | OAuth（Server 级）+ HITL `[FACT]` |
| 现有机制成熟度 | 高（分支保护、签名提交、审计） | 高（RLS、参数化、超时、审计） | 中（beta 安全实践，协议层不强制） |
| 结构性空白 | 授权决策↔精确参数的密码学绑定（需独立签名方） | token/授权↔SQL 文本的绑定；跨调用状态机 | **独立授权批准↔跨信任域一次性凭证（规范无 token↔tool+参数绑定是事实，但参数审批/消息签名已有相关工作）** `[FACT/INFER]` |
| Binding 有效性前提 | 需授权方≠执行方 | SQL 文本能否提取授权语义待验证 | **需绑定用户意图而非模型输出** |
| 最危险风险 | 注入→读取/外泄、策略绕过 | 合法权限内生成泄露性 SQL（Binding 无效） | tool poisoning / shadowing（推理侧，出口签名错位） |
| 一手攻击证据 | CamoLeak、CVE-2025-62453、AgentDojo ASR | P2SQL (ICSE'25)、arXiv:2211.15363、ToxicSQL | Invariant tool poisoning、CVE-2025-49596、arXiv:2503.23278 |
| 对框架适配性 | 中（重复度高，需独立信任边界才成立） | 中（DB 层已强，Binding 对 SQL 语义存疑） | **相对最高**（规范无 token↔tool+参数绑定是事实、注入点明确；但相关工作已多，须靠 A/B/C 强对照证明增量） |

**初判（待后续威胁模型与差距分析确认）**：MCP 场景仍相对优先，但**不再因为「arguments_digest 是唯一规范空白」**——参数级审批（OWASP Cheat Sheets）与消息签名/防重放（MCPS）已有相关工作。真正的研究问题是「独立授权方的动作批准能否成为跨信任边界可验证、不可替换/重放的一次性凭证」。三场景共同的关键约束：Binding 必须绑定**用户确认的具体动作**而非**模型输出参数**，否则注入产生的恶意参数会被合法签名；且须证明 C 组相对 B 组（普通应用层审批）有可测增量。这些将在 `E3_0_RESEARCH_GAP.md` 与 `E3_0_GO_NO_GO.md` 中展开。

---

## 来源清单

[^G1]: GitHub Blog, "Welcome home, agents!" — github.blog/news-insights/company-news/welcome-home-agents/ ; GitHub Docs, "About agents" — docs.github.com/en/copilot/concepts/agent-capabilities
[^G2]: GitHub Docs, "Use the Copilot SDK — agent loop" — docs.github.com/en/copilot/how-tos/copilot-sdk/use-copilot-sdk/agent-loop ; Anthropic Docs, "Agent SDK permissions" — docs.anthropic.com/en/docs/agent-sdk/permissions
[^G3]: GitHub Changelog, "Deprecate GitHub Copilot Extensions (GitHub Apps)" — github.blog/changelog/2025-09-24-... ; Anthropic Docs, "Claude Code hooks" — docs.anthropic.com/en/docs/claude-code/hooks
[^G4]: GitHub Docs, "Responsible use of agents / risks and mitigations" — docs.github.com/en/copilot/responsible-use/agents ; OpenAI Developers, "Codex approvals & security" — developers.openai.com/codex/agent-approvals-security
[^G5]: Legit Security, "CamoLeak"（经 genaisecuritylab.com/incidents/camoleak-github-copilot-exfiltration 等转引）；CVE 编号冲突待 NVD 核实 `[ASSUMPTION]`
[^G6]: Microsoft MSRC, CVE-2025-62453 — msrc.microsoft.com/update-guide/vulnerability/CVE-2025-62453
[^G7]: arXiv:2505.05849 (AgentVigil)、arXiv:2509.22830 (ChatInject)、arXiv:2506.01055（数据外泄研究）
[^G8]: OWASP Top 10 for LLM Applications — owasp.org/projects/top-10-for-large-language-model-applications
[^D1]: LangChain Docs, "create_sql_query_chain / SQL agent" — python.langchain.com ; Vanna Docs — vanna.ai/docs, vanna.ai/data-security ; Microsoft Learn, "AI/BI Genie agents" — learn.microsoft.com/.../genie-agents/concepts
[^D2]: Pedro et al., "From Prompt Injections to SQL Injection Attacks...", arXiv:2308.01990 (ICSE 2025) — arxiv.org/abs/2308.01990（摘要已二次核实）
[^D3]: Microsoft Learn, "Genie setup / Unity Catalog" — learn.microsoft.com/.../genie-agents/set-up
[^D4]: arXiv:2211.15363 (ISSRE 2023)；arXiv:2503.05445 (ToxicSQL)
[^D5]: PostgreSQL Docs, "Row Security Policies" — postgresql.org/docs/current/ddl-rowsecurity ; "Client Connection Defaults" — postgresql.org/docs/current/runtime-config-client.html ; OWASP A05:2025-Injection
[^M1]: MCP Specification **2026-07-28**, "Authorization" — modelcontextprotocol.io/specification/2026-07-28/basic/authorization（E3-0.1 已按新版二次核实：resource MUST = server canonical URI；无 token↔tool+参数绑定；token 发送/接受/转发禁令与 confused deputy 列入 Security Considerations；"scopes may be determined dynamically based on specific request arguments" 指 challenge 的 scope 决定，非 token 参数绑定）
[^M2]: MCP Specification **2026-07-28**, "Tools" — modelcontextprotocol.io/specification/2026-07-28/server/tools（E3-0.1 已按新版二次核实：model-controlled；inputSchema 2020-12 必为合法 object；annotations MUST 视为不可信；human-in-the-loop 与 confirmation prompts 为 **SHOULD**；"MCP itself cannot enforce these security principles at the protocol level" 见主页 2026-07-28）
[^M3]: OWASP MCP Top 10 (2025, **beta / Phase 3**) — owasp.org/www-project-mcp-top-10（十类名称与 MCP08 "immutable audit trails" 建议已二次核实；beta 实践建议，非 MCP 协议强制）
[^M4]: MCP Specification, "Security Best Practices" — modelcontextprotocol.io/specification/.../security_best_practices
[^M5]: Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks" — invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks (2025-04-01)
[^M6]: CVE-2025-49596 (MCP Inspector RCE, CVSS 9.4) — NVD 条目（二手转引 avd.aliyun.com/detail?id=AVD-2025-49596，待 NVD 原条目核实 `[ASSUMPTION]`）
[^W1]: OWASP Cheat Sheet Series, "AI Agent Security Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html（§1 Tool Authorization Middleware、§4 High-Impact Action Integrity Controls，逐字核实；原文用 "normalized parameters" 与小写 "actor"）
[^W2]: OWASP Cheat Sheet Series, "Transaction Authorization Cheat Sheet" — cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html（§1.1、§1.5、§2.1、§2.3、§2.6、§2.8、§2.10，逐字核实）
[^W4]: R. Sharif, "MCPS: Cryptographic Security Layer for the Model Context Protocol", `draft-sharif-mcps-secure-mcp-01`, 2026-08-21 — datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/（个人 Internet-Draft，"work in progress"，非已采纳标准；§1.2/§1.3/§5/§6/§7/§11.1/§11.2 逐字核实）
[^M7]: arXiv:2503.23278；arXiv:2504.03767 (MCPSafetyScanner)
