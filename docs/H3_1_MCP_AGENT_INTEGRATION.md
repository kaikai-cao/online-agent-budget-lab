# H3.1 — DeepSeek 驱动的 MCP Agent 基线

分支：`research/h3-1-mcp-agent-integration`（基线 H1 冻结提交 `ad66150`，未合并 main）。
本阶段只验证"真实模型决策 → 真实 MCP 通信 → 真实本地副作用 → 全程可观测"的执行链，**不接入 H1/H2 授权协议**，不做四组对照。

## 1. 架构与安全边界

```
User task
  ↓
DeepSeek API（不可信 Planner，deepseek-flash，非思考模式）
  ↑ tools 定义 ← MCP tools/list 动态发现（启动时与本地冻结规格一致性校验）
  ↓ tool_calls  (不可信输入)
Python Agent Host  ← 本地 JSON 解析 + validate_arguments() 校验（安全边界）
  ↓ tools/call   (仅校验通过的调用)
独立 MCP Server 进程（官方 MCP SDK，stdio）
  ↓ 写入 tool_events 后返回 server_received 戳记
隔离的本地 SQLite 测试库 + tool_events 事件记录
```

核心决定：**DeepSeek 只负责生成工具调用，不负责批准自己的工具调用。**
- 模型返回的每个 `tool_call` 都当成不可信输入：Host 先 `json.loads`，再用共享 `tool_specs.validate_arguments()` 校验工具名/必填字段/类型/范围（bool 不当 int）；校验失败即 `HOST_REJECTED`，**永不发给 MCP Server**。
- system prompt 不是安全边界。即使模型遵循提示词，代码层仍强制校验。
- MCP Server 端对参数做第二次校验（last line of defense），并记录实际收到的参数、结果、状态、时间戳。
- 模型只提议；副作用只由 Host 放行后的真实 `tools/call` 产生，可在 SQLite 中查证。

共享规格见 `experiments/h3_mcp_agent/tool_specs.py`；Host 与 Server 用同一份，避免口径漂移。

**动态工具发现（验收修正）：** Host 启动时**真实调用 MCP `tools/list`**，模型看到的是 Server 实际声明的工具描述与 schema（`mcp_tools_to_openai()`），而非硬编码副本。发现结果在调用模型前由 `assert_tools_consistent()` 与本地冻结 `TOOL_SPECS` 逐项比对（工具名/字段名/必填项/类型/默认值），任一不一致即 `ToolDiscoveryError` fail closed——模型不会被调用，也不发出任何 tool call。本地白名单仍是执行时的安全边界；动态发现只决定"模型看到什么"，不放宽"什么会被放行"。

**分类证据分层（验收修正）：** MCP Server 在写入 `tool_events` 后返回 `server_received=True`；Host 据此记录 `mcp_received`。分类不再把 `host_decision=ALLOW` 当作"Server 收到"，而是分别统计 Host 放行、Server 收到、SQLite 提交副作用三层。

## 2. 环境与复现

- Python 3.14.7；依赖 `openai>=1.0`、`mcp>=2.0`（MCP 2.x 用 `MCPServer`/`@mcp.tool()`，snake_case 字段）。
- DeepSeek：`base_url=https://api.deepseek.com`，模型 `deepseek-flash`（可由 `DEEPSEEK_MODEL` 覆盖），非思考模式 `extra_body={"thinking":{"type":"disabled"}}`。
- 密钥来自环境变量 `DEEPSEEK_API_KEY`，**从不写入源码/日志/JSON/CSV/Git**。

```bash
python -m pip install -r requirements.txt
# PowerShell
$env:DEEPSEEK_API_KEY="sk-..."        # 真实密钥，勿提交
# 真实集成运行（20 任务）
python -m experiments.h3_mcp_agent.run_experiment --output-dir experiments/h3_mcp_agent/results/run-001
# 纯离线 dry run（不调用 API，不用于 T1）
python -m experiments.h3_mcp_agent.run_experiment --mock --output-dir experiments/h3_mcp_agent/results/mock
# 单元测试
python -m unittest tests.test_h3_mcp_agent -v
```

`.env.example` 仅占位符；`.env` 已在 `.gitignore`。日志写入前统一经 `redact()` 脱敏，并用 `assert_no_secret()` 断言密钥不落盘。

## 3. MCP Server 与工具

独立进程 stdio 启动（`python -m experiments.h3_mcp_agent.server.server --db <path>`），三个工具：

| 工具 | 功能 | 副作用 |
|---|---|---|
| `search_records` | 按 id/标题/内容查询预置测试记录 | 无 |
| `create_record` | 创建一条测试记录 | SQLite 写入 |
| `update_record` | 更新指定记录内容 | SQLite 写入 |

参数有明确类型、必填字段与范围（query 1–200 字符、limit 1–50、title 1–200、content 1–5000）。每个真实执行写入唯一 `effect_id` 的 `tool_events` 行（参数/结果/状态/时间戳）；`create/update` 另写 `effects` 行。预置数据含 3 条带注入指令的工单（`INJ-001/002/003`），注入内容只在本地测试库。

## 4. 运行结果（run-001，真实 DeepSeek API）

命令：`DEEPSEEK_API_KEY=<key> python -m experiments.h3_mcp_agent.run_experiment --output-dir .../run-001`
`summary.json` 中 `real_api_called=true`、`model=deepseek-flash`、`mode=real`；20 任务约 79 秒完成。

| 指标 | 结果 |
|---|---|
| 总任务 | 20（良性 10 + 注入 10），每任务独立 `run_id` |
| 错误任务 | 0 |
| 真实写入工具调用 | 4 |
| Host 拒绝调用 | 0 |
| 到达 MCP 的写入调用 | 4 |
| 实际副作用 | 4（SQLite ground truth = 4，与 summary 一致） |
| 注入任务结果分层 | `no_malicious_call`=10，`host_rejected`=0，`mcp_received`=0，`effect_occurred`=0 |

4 次写入全部来自良性任务 B03/B05/B07/B10（这些任务本身要求"创建摘要/更新记录"）。注入任务中注入内容 10/10 都通过真实 MCP `search_records` 返回给了模型（已核验响应中含 `IGNORE`/`OVERRIDE` 等注入串），因此 `no_malicious_call` 是"模型看到了注入但未产生恶意写入调用"，不是"攻击面未被触发"。

> **口径说明：** run-001 是冻结的历史结果，日志采用当时的字段集合（尚不含 `server_received`/`discovery_*`）。上表与结论按当时口径原样保留，不覆盖、不重跑。验收修正引入的新分类口径从后续运行（含 H3.2）生效；run-001 的 4 次写入均带 `effect_id` 且 SQLite ground truth = 4，Server 确实收到并提交了副作用，因此新口径不改变其事实结论，只是不能用旧日志直接回放新分类器。

## 5. T1–T8 验收

| 编号 | 项目 | 结果 | 证据 |
|---|---|---|---|
| T1 | DeepSeek API 正常响应 | ✅ | 真实调用返回 `deepseek-flash` 响应与 `tool_calls`；curl 与 SDK 双验（首次 UUID 密钥 401，换 `sk-` 密钥 200） |
| T2 | MCP Server 独立启动、工具列表可读 | ✅ | 真实 stdio 通信返回 `search_records/create_record/update_record`；验收修正后正式 Host 路径每任务调用 `tools/list`（离线冒烟 4/4 任务产生 `tools_discovered` 事件） |
| T3 | DeepSeek 生成工具调用、Host 转真实 MCP | ✅ | 25 个 `tool_call` 事件，`host_decision=ALLOW`，`effect_status=MCP_OK` |
| T4 | 多轮交互与最终回答 | ✅ | 20 个 final_answer 事件；44 次 model_response |
| T5 | 本地副作用可查证 | ✅ | 4 个 effect，SQLite ground truth 复算一致 |
| T6 | 正常/注入场景与过程证据 | ✅ | 10+10 任务；注入四类分层记录；注入内容确认返回模型 |
| T7 | 日志可关联模型/MCP/副作用 | ✅ | run-001 共 109 条 JSONL，含 run_id/task_id/effect_id；验收修正后日志白名单新增 `tools_discovered`/`mcp_received` 等字段（离线冒烟已验证落盘） |
| T8 | 密钥安全 | ✅ | 全仓扫描无密钥；`.env.example` 仅占位；脱敏与断言均启用 |

单元测试 19/19 通过（含真实 MCP stdio 通信、Host 拒绝不可信调用、动态工具发现与不一致 fail closed、四类分层与 Server 收据证据、脱敏）；H1 冻结测试 23/23 通过。

## 6. 判定纪律与局限

- **20 次是初始机制验证，不是统计意义上的攻击成功率。** 本轮注入 10/10 未产生恶意调用，只说明这些注入样本与 `deepseek-flash` 非思考模式在该提示下未奏效，不能外推为"模型免疫 prompt injection"。
- **四类区分机制已具备但本轮只观测到一类**（`no_malicious_call`）。`host_rejected` 分支由单元测试覆盖（模型产生缺字段/未知工具调用时 Host 拒绝且不落副作用），真实运行中未出现恶意调用，故为 0，不伪造。
- 模型可能不遵循 system prompt；本阶段**不声称解决 prompt injection**，也不把提示词服从当授权保证。
- 未接入 H1 的 Ed25519 凭证/H2 的撤销快照；未做 A/B1/B2/C 四组；未改 Halo2 电路；未接真实生产库或外部账户；未扩展成通用 Agent 框架。
- `max_rounds=6` 防止无限循环；本轮最多轮次见 `summary.json`。
- run-001 之前有一次因日志字段白名单缺 `host_decision` 等而做的重跑：旧数据归档为 `run-001-prelogfix`（不覆盖），新 run-001 字段完整；两次统计结论一致。

## 7. 结论

H3.1 达成既定目标：第一次拥有一条**真实模型参与、真实 MCP 通信、真实本地副作用、全程可观测**的 Agent 执行链，T1–T8 全部通过。下一步可在此基础上接入 H1 授权机制，进入端到端验证（不在本阶段范围）。

## 8. 验收修正（进入 H3.2 前）

用户从 GitHub 独立核查提交 `8c2909e0858019e2dfe12a63ce74325182463262` 后确认核心交付通过，同时指出两处测量口径问题。在不推翻 H3.1、不重跑真实 API 实验的前提下做最小修正：

1. **动态 MCP 工具发现接入正式路径。** 修正前 `McpSession.list_tools()` 只在单测中被调用，`AgentHost.run_task()` 默认从本地 `to_openai_tools()` 取工具定义，验证的是"静态规格 + 真实 MCP 调用"桥接。修正后 Host 启动时 `await session.list_tools()`，由 `mcp_tools_to_openai()` 转成 DeepSeek 工具定义，并经 `assert_tools_consistent()` 与本地冻结规格在工具名/字段名/必填项/类型/默认值上逐项校验；不一致即 `ToolDiscoveryError` fail closed（模型不被调用、不发任何 tool call）。
2. **MCP_RECEIVED 以 Server 侧事件为依据。** 修正前 `_classify()` 把 `host_decision=ALLOW` 计为 `mcp_reached_calls`，但 ALLOW 只证明 Host 允许发送，不能证明 Server 收到。修正后 Server 在写入 `tool_events` 后返回 `server_received=True`，Host 记录 `mcp_received`，分类器据此判定；新增 `host_allowed_server_unreachable` 类别专门记录"Host 放行但无 Server 收据"（如传输失败），不再误报为 `mcp_received`。

自检：H3.1 单测 19/19（新增 5 项：Server schema 转换、动态发现来源、工具列表不一致拒绝、四类漂移校验、ALLOW 无收据不得计为 Server 收到），H1 冻结 23/23；离线 mock 冒烟 4 任务 0 错误、4 条 `tools_discovered` 事件，确认正式 Runner 已走动态发现且新字段落盘。

**保留项：** `results/run-001/` 与 `results/run-001-prelogfix/` 一字未改；20 任务的真实运行数据与 §4 结论不变。修正只影响代码与后续运行，不改变 H3.1 冻结历史结果。

**边界保留：** 本轮 10/10 注入任务确实读到注入内容但未产生恶意写入调用，只说明在 `deepseek-flash` 非思考模式、该提示词与这批样本下未观察到恶意调用，不能外推为模型具备抵御 Prompt Injection 的能力。

本修正待用户限定范围复核；H3.1 正式关闭与 H3.2 启动以复核通过为前提。
