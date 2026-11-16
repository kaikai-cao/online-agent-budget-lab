# D11.2 — Halo2 最小预算约束电路

> 独立 Rust 实验,不属于生产代码(`src/online_budget/` 未作任何修改)。
> 本 crate 把 D11.1 已验证的整数关系真正实现为可生成/验证证明的 Halo2 0.4.0 电路。

## 1. 固定数学关系

D11.1 的关系是 `0 ≤ u, 1 ≤ c, u + c ≤ Q`。本电路采用等价的 slack 形式:

\[
\boxed{u + c + s = Q},\qquad s = Q - u - c \ge 0
\]

所有量都是 32 位无符号整数 `0 ≤ Q,c,u,s ≤ 2^32 - 1`。

**为什么用 slack 而不是直接约束 `u+c≤Q`?** 若用中间和 `u+c`,它最大可到 `2^33-2`,需要 33 位范围约束。引入非负 slack `s` 后,四个量各自都可在 32 位范围内分解,省掉一个 33 位范围约束。

**为什么有限域等式等价于整数等式?** 电路在 Pasta 标量域 `Fp` 上验证 `u+c+s-Q=0`。因为 `3·(2^32-1) < 2^34 << |Fp|`(约 2^255),等式两侧的整数和不可能发生模数回绕,因此域内成立 ⟺ 整数成立。这正是 D11.1 强调的"不能只写域内等式"这里通过显式 32 位范围约束来满足。

## 2. 公开输入与私有见证

**公开输入**(单一 Instance Column,固定顺序):

```
instance[0] = Q   (配额上限)
instance[1] = c   (本次消费量)
```

**私有见证**(Advice Column):

- `u`:消费前累计消费量(隐藏)。
- `s`:剩余额度 slack(隐藏)。
- `Q^{-1}`, `c^{-1}`:非零检查用的辅助见证。
- 32 位分解的每一bit:电路内部辅助,不是公开输入。

`u` 与 `s` **从不**进入 Instance Column。真实证明测试中,即使改动公开输入 Q 或 c,证明也会验证失败,证明绑定的是公开输入而非仅 witness。

## 3. 电路约束设计(`src/quota_circuit.rs`)

四组约束全部在 Halo2 gate 内部,没有用 Rust `if` 在 host 端替代:

1. **32 位范围约束**:对 Q、c、u、s 各自做 bit decomposition,`x = Σ bᵢ·2ⁱ (i=0..31)`,并约束每个 `bᵢ·(1−bᵢ)=0`,保证每位是 0 或 1,从而 `x ≤ 2^32−1`。
2. **配额非零**:`Q · Q⁻¹ = 1`,通过辅助见证 `Q⁻¹` 证明 `Q ≥ 1`。
3. **消费量非零**:`c · c⁻¹ = 1`,证明 `c ≥ 1`。
4. **预算关系**:`Q − u − c − s = 0`(即 `u+c+s=Q`),四个值被 copy 到同一行的连续四个 cell 后在 gate 内相加。

`without_witnesses()` 只清除见证数值、保持电路结构不变,用于 keygen。

## 4. 测试(`tests/quota_circuit.rs`)

**MockProver 约束测试**(T01–T14):

| 编号 | Q | c | u | s | 预期 |
| --- | --- | --- | --- | --- | --- |
| T01 | 100 | 20 | 60 | 20 | 通过 |
| T02 | 100 | 40 | 60 | 0 | 通过(恰好用尽) |
| T03 | 100 | 41 | 60 | 0/1 | 拒绝(超额) |
| T04 | 100 | 1 | 99 | 0 | 通过 |
| T05 | 100 | 1 | 100 | 0 | 拒绝 |
| T06 | 0 | 1 | 0 | 0 | 拒绝(Q 非零) |
| T07 | 100 | 0 | 0 | 100 | 拒绝(c 非零) |
| T08 | 2^32−1 | 1 | 2^32−2 | 0 | 通过 |
| T09 | 2^32 | 1 | 0 | 0 | 拒绝(超 32 位) |
| T10 | 100 | 2^32 | 0 | 0 | 拒绝 |
| T11 | 100 | 20 | 2^32 | 0 | 拒绝 |
| T12 | 100 | 20 | 60 | 2^32 | 拒绝 |
| T13 | 100 | 20 | 60 | 19 | 拒绝(slack 不符) |
| T14 | witness Q=100,c=20 但 instance 声称 Q=101 | | | | 拒绝(公开输入被篡改) |

**真实证明测试**(3 项):固定 witness `Q=100, c=20, u=60, s=20`,用 `Params` → `keygen_vk` → `keygen_pk` → `create_proof` → `verify_proof` 走完整流程:

1. 正确公开输入 `(100, 20)` → 验证成功。
2. 同一证明,公开输入改为 `(101, 20)` → 验证失败。
3. 同一证明,公开输入改为 `(100, 21)` → 验证失败。

这三项区分布尔约束检查(MockProver)与真实零知识证明流程;后者才绑定公开输入。RNG 用 `rand 0.10` 的 `SysRng` 配 `rand_core::UnwrapErr`,对应 Halo2 0.4.0 的新 `Rng` 接口。

## 5. 本阶段边界

- **不是完整隐私系统**:无状态承诺、Poseidon、Nullifier、配额凭证签名、Executor 计量凭据、预算状态连续性或 Coordinator 集成。这些留待 D11.3+。
- **证明绑定什么**:本电路证明"存在隐藏的 u、s 使 u+c+s=Q 且都在 32 位范围、Q/c 非零",针对公开输入的 Q、c。它尚不证明授权有效或工具确实执行——与 D11.0 的边界一致。
- **MockProver ≠ 零知识证明**:本 crate 同时完成了真实的 prove/verify,不是只跑 MockProver。

## 6. 验收命令

```bash
cargo check --manifest-path experiments/d11_2_halo2_quota/Cargo.toml
cargo test  --manifest-path experiments/d11_2_halo2_quota/Cargo.toml -- --nocapture
cargo fmt   --manifest-path experiments/d11_2_halo2_quota/Cargo.toml -- --check
git diff --check
git status --short
```

依赖版本:`halo2_proofs =0.4.0`、`pasta_curves 0.6`(经 halo2 re-export)、`rand 0.10 (sys_rng)`、`rand_core 0.10`,Rust ≥ 1.88(本机 1.98.1)。
