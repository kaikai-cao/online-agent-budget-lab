# D11.3-D — Python 参考状态机

独立实验目录，只新增本目录；不修改 D9、D10、D11.3-A/B/C 与 D11.1。用途是**独立验证协议语义**并与 Rust D11.3-C Coordinator 交叉对照，不是生产系统，也不是新的证明系统。

## 边界（先读这一节）

- `proof_verifier.py` 的 `TestProofVerifier` **只是测试替身**：它把不透明测试 token 绑定到完整 8 行公开输入；公开输入任意一行变化即拒绝。它**不是 Halo2、不是 ZKP、不提供可靠性**。真实证明由 B.1 电路与 C 阶段 Rust `verify_proof` 负责。
- `verify()` 没有 `verified=True` 之类的旁路参数；Coordinator 唯一接受路径是 `verify(proof, instance)`。
- 本模型**不计算状态承诺或 Nullifier**：`C_old / C_new / N` 当作不透明 Pallas 场元素，由测试直接给出。没有用 SHA-256 或其他哈希冒充 Poseidon，因此也不声称与 B.0 冻结的 Poseidon 实现兼容。承诺开口关系由 Rust 电路约束。
- 注册授权按 C 阶段完全相同的规则编码，但本阶段**不验证** Prover 知道 `C_0` 开口（D11.3-A §4.1 方案 B 的既定边界）。

## 模块

| 模块 | 内容 |
| --- | --- |
| `model.py` | Pallas `Fp` 模数 `0x4000…0001`、规范 32 字节小端编解码、uint32 与 `bool` 拒绝、`StateWitness` 两条整数等式、`Transition`、持久化 `BudgetState` |
| `registration.py` | Ed25519（项目已有 `cryptography`）注册授权；签名消息 `D11.3-C-REGISTRATION-v1 || budget_id || period_id || Q || P || C_0`，字段均为规范 32 字节小端；验签、字段匹配、重复注册拒绝 |
| `proof_verifier.py` | `ProofVerifier` 协议 + `TestProofVerifier`；token 由验证器私有记录绑定到 8 行公开输入 |
| `coordinator.py` | 注册、转移检查、Q/P 比对、证明验证、锁内二次检查与原子更新；`seed_used_nullifier` 与 `fault_hook` 仅用于测试 |

字段编码与 Rust C 阶段一致：`fp_to_bytes` 等价于 `Fp::to_repr()`（小端、固定 32 字节），`fp_from_bytes` 拒绝长度错误与 `>= modulus` 的非规范编码。注册签名字节序、域前缀与 C 阶段 `RegistrationFields::encode()` 相同，并由 `test_encoding_mirrors_rust_c_field_order_and_endianness` 固定。

## 双检查的语义

证明验证可能耗时。Coordinator 先在锁外检查注册、留存授权、Q/P、`C_old` 与 `N`，再调用验证接口；随后在同一把锁内**重新读取**当前状态与 Nullifier 集合，全部通过后才一次性更新 `used_nullifiers`、`current_commitment` 与 `version`。这保证验证期间有其他请求提交时，旧状态不会被再次消费。

## 测试对照

| 文件 | 覆盖 |
| --- | --- |
| `test_registration.py` | D01 合法注册、D02 签名篡改、D03 字段篡改、D04 重复/冲突注册；编码规则固定；`bool`/负数/超 uint32/超模数/非规范编码边界 |
| `test_transition.py` | D05 未注册、D06 合法转移、D07 无效证明、D08 公开输入篡改（C_old/C_new/N）、D09 Q 不匹配、D10 P 不匹配、D13 实例隔离、D14 周期隔离；见证与两条等式边界 |
| `test_replay.py` | D11 重复 Nullifier（预置 N 且 C_old 仍当前）、D12 过期 C_old、D16 更新失败时状态和 Nullifier 均不变 |
| `test_concurrency.py` | D15 两个 OS 线程 + Barrier 竞争同一 C_old，恰好一个成功 |

## 验收命令

在项目根目录、已激活项目虚拟环境（`.venv`，内含 `cryptography>=41.0`）下：

```bash
python -m unittest discover -s experiments/d11_3_d_reference/tests -v
python -m unittest discover -s experiments/d11_1_quota_relation -v
git diff --check
git status --short
```

D11.1 回归用于确认数学基准未受影响。本阶段不扩大为生产系统、不接 D10、不实现分布式 Coordinator、不隐藏公开消费量 `c`。
