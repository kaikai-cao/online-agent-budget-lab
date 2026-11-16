# D11.3-C — Coordinator 状态验证与防重放（实验原型）

本 crate 是**独立的链下状态管理原型**，只新增 `experiments/d11_3_c_coordinator/`。
它复用 D11.3-B.1 已冻结电路，不修改 D9 生产 Coordinator、D10 授权/回执、
D11.3-A 协议文档或 B.0 参数冻结文档。

## 本阶段实现什么

- **Issuer 签名注册**（`registration.rs`）：授权绑定
  `(budget_id, period_id, Q, P, C_0)`，固定域前缀
  `D11.3-C-REGISTRATION-v1` + 5 个规范 32 字节小端字段表示；
  拒绝无效签名、字段与签名不匹配、非规范字段编码、重复注册。
- **真实 Halo2 验证**（`proof_verifier.rs`）：直接复用 B.1
  `StateTransitionCircuit` / `StateWitness`，`k = 10`、`Params` / VK 与 B.1
  一致；唯一的证明接收路径调用 `plonk::verify_proof`，不使用 `MockProver`，
  也不接受调用方传入的 `verified` 标志。
- **SQLite 持久化**（`state_store.rs`）：`budget_instances` 与
  `used_nullifiers` 两表，联合主键/唯一约束按任务包定义；字段用规范
  32 字节十六进制文本存储，`from_repr` 拒绝非规范编码。
- **原子接收流程**（`coordinator.rs`）：公开输入格式与 uint32 域检查 →
  实例已注册与留存授权有效性 → Q/P 与注册值一致 → 真实证明验证 →
  `BEGIN IMMEDIATE` 事务内重读当前状态、检查 `C_old`、检查 `N` 未使用、
  插入 `N`、更新 `C_new` 与 `version += 1` → 提交；任一步失败整体回滚。
  每次操作新开连接，所以并发请求真实竞争数据库写锁。

## 字段编码与依赖说明

- 字段为 Pallas `Fp`（`halo2_proofs::pasta::Fp`）。规范编码取
  `PrimeField::to_repr()` 的 32 字节小端表示；DB 存其十六进制文本。
- 任务包建议 `ff = "=0.13.1"`，但 B.1 使用的 `pasta_curves 0.6.3` /
  `halo2_proofs 0.4.0` 实现的是 **`ff` 0.14**；为取得该 `Fp` 的
  `PrimeField` trait，本 crate 声明 `ff = "=0.14.0"`。Halo2 版本未变。
- `rusqlite =0.38.0`（bundled）、`ed25519-dalek =2.2.0`、
  `rand =0.10.4`（与 B.1 一致，供实验性 prover 侧使用）。

## 参数与密钥管理边界

`experimental_proof_assets()` 在进程首次使用时生成 `Params`、`ProvingKey`
和 `VerifyingKey`，进程内复用以避免每个测试重复 keygen。第一版 `k=10`
参数与 VK 是**实验原型配置**：没有可信 setup、密钥分发、轮换或持久化 VK，
不能当作生产密钥管理方案。Issuer Ed25519 密钥由测试固定种子构造，同样
只是实验输入。

## 测试对照

| 测试 | 覆盖 |
| --- | --- |
| `tests/registration.rs` | C01 合法注册；C02 签名篡改；C03 字段与签名不匹配；C04 重复/冲突注册 |
| `tests/state_transition.rs` | C05 未注册；C06 真实证明接受；C07 无效证明字节；C08 篡改 `C_new`；C09 篡改 `P`；C12 实例隔离；C13 周期隔离 |
| `tests/replay.rs` | C10 已用 Nullifier（预置 N 且 `C_old` 仍为当前值，隔离检查）；C11 过期 `C_old`；C16 重启恢复 |
| `tests/concurrency.rs` | C14 两个 OS 线程 + 起跑栅栏竞争同一 `C_old`，最多一个成功；C15 用 SQLite 触发器在 `N` 插入后让 UPDATE 失败，验证完整回滚 |

C08 与 C10/C11/C16 的负例均在真实 `verify_proof` 通过后或状态层完成，
不是靠 host 端提前拒绝替代电路/事务检查。

## 本阶段**不能**声称

- Executor 实际计量的 `c` 一定真实（未接 Executor 计量与计量签名）；
- D10 授权与 D11 预算证明已经联合执行；
- 注册时验证了 Prover 知道 `C_0` 的开口（方案 B 只签授权，属可用性而非安全性质）；
- 实现了并发双花的生产级防护、分布式共识或高可用；
- 隐藏了公开消费量 `c`；完成了形式化安全证明；可部署到任意 Agent 场景。

## 验收命令

在仓库根目录：

```bash
cargo check --manifest-path experiments/d11_3_c_coordinator/Cargo.toml
cargo test  --manifest-path experiments/d11_3_c_coordinator/Cargo.toml -- --nocapture
cargo fmt   --manifest-path experiments/d11_3_c_coordinator/Cargo.toml -- --check
git diff --check
git status --short
```
