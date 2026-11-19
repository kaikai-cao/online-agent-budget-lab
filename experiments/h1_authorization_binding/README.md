# H1 — 跨信任域动作授权最小可行性验证

B2（在线授权验证）与 C（Ed25519 本地凭证验证）的可运行对照原型。
对应研究问题见 `docs/H1_MINIMUM_FEASIBILITY.md` 与 E3-0 系列文档。

## 目录

- `h1_protocol.py`：两组共用的授权对象与 `action_digest` 规范（唯一事实来源）
- `h1_authorization_service.py`：Authorization Service + B2 的真实 TCP + TLS 在线查询服务（服务器证书指纹固定）+ C 的 Ed25519 签发入口约束
- `h1_executor.py`：Executor 的 B2/C 两条验证路径 + 共用绑定检查/消费/副作用
- `h1_sink.py`：两组共用的 Executor 本地消费存储 + 受控 Sink（SQLite 同事务）
- `run_experiment.py`：实验矩阵 runner，写 `results/run-001/{trials.csv,summary.json,raw.json}`
- `results/run-001/`：本次实际运行结果

## 运行

```bash
# 矩阵实验
PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
  .venv/Scripts/python experiments/h1_authorization_binding/run_experiment.py \
  --output-dir experiments/h1_authorization_binding/results/run-001

# 专项测试
PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
  .venv/Scripts/python -m unittest tests.test_h1_authorization_binding -v
```

Windows 下 `PYTHONPATH` 用分号 `;`。

## 架构与公平性不变量

```
不可信 Planner ──(工具请求 + 授权引用)──> Executor
                                           │ 重算 action_digest（不信 Planner）
用户确认 ──> Authorization Service ──┬── B2: TCP + TLS 在线查询（服务器证书指纹固定，fail closed）
                                      └── C: Ed25519 签发凭证（Executor 预置公钥本地验签）
                                           │
                                   共用消费存储 + 受控 Sink
                                   （jti 主键 + BEGIN IMMEDIATE，消费与副作用同事务）
```

- **两组绑定完全相同的授权对象**：executor_id / server_uri / tool_name /
  schema_hash / arguments / action_digest / jti / issued_at / expires_at；摘要算法一致。
- **B2 是真实验证**：真实 localhost TCP + TLS 服务 + 固定服务器证书指纹；不使用
  应用层签名凭证；服务不可达 fail closed。B2 的"非密码学"仅指没有应用层签名
  授权凭证。传输是 TCP + TLS + 服务器证书指纹固定，**不是 HTTPS，也不是 mTLS**
  （无客户端证书认证）；TLS 只是传输信道保护，不是动作签名凭证。
- **C 的信任锚真实成立**：Executor 只信任按 `key_id` 预置的公钥，绝不读取请求
  携带的公钥；未知 key_id / 错误 audience / 错误 issuer / 签名篡改均拒绝。
- **消费公平**：两组共用同一消费存储与受控 Sink；防重放来自 Executor 本地原子
  消费状态，不来自 Ed25519 签名，也不来自 B2 在线查询。

## 边界（不得外推）

- 受控 Sink 的同事务原子性只覆盖实验内的 SQLite，不代表真实第三方 API 的
  exactly-once；一次性消费限定单一 Executor 的本地存储，不是全局。
- C 离线可验签，但无法及时感知授权撤销（本实验实测：撤销后 C 仍执行，
  B2 拒绝）——这是架构权衡，不是"C 更安全"的普遍结论。
- B2 在线查询与本地消费之间存在时间窗：查询后发生的撤销，Executor 不一定
  能及时发现；不声称撤销与副作用之间有全局原子性。
- 这是机制可行性验证（mechanism feasibility），不是形式化安全证明，不是
  论文级统计实验，也不是生产级 MCP 集成。测试通过不等于安全证明。
