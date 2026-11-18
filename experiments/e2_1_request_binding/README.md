# E2.1 — Agent Exec Binding 安全有效性实验

## 1. 实验目标

回答一个具体问题：

> 一份已经签发的工具授权，能否阻止攻击者在授权之后替换参数，使工具执行一个未被该授权精确绑定的操作？

实验只做受控对照，不新增生产功能。**核心观察对象是攻击参数是否真的进入了工具并造成受保护状态变化**，而不是异常类型或 Gateway 的 DENY 返回值。

## 2. 受保护工具与攻击输入

复用仓库真实工具 `invoice_review`（Schema：`{"invoice_id": <非空字符串>}`，`additionalProperties: False`）。

| 项 | 值 |
|---|---|
| 授权/正常参数 | `invoice_review({"invoice_id": "INV-E16-SYSTEM"})` |
| 攻击参数 | `invoice_review({"invoice_id": "INV-E16-ATTACK"})` |

两个请求工具名相同、参数结构相同、都通过 Schema，**只有参数值不同**。这排除了「Schema 校验拦截攻击」这一干扰因素。

## 3. 实际副作用观察器

`StatefulEffectRegistry` 继承生产 `LocalToolRegistry`，schema/validate 完全不变，只在 `dispatch()` 中记录：

```
{"operation": "invoice_review", "invoice_id": <实际到达工具的值>}
```

并维护 `dispatch_count` 与 `effects` 列表。每组使用独立实例，互不污染。记录的副作用是**真实 dispatch 之后**的状态变化，不是授权判定结果。

## 4. 三个对照组

| 组 | 机制 | 实现 | 定位 |
|---|---|---|---|
| G1 | Static ACL + Schema | 工具白名单 + `registry.validate()`，不绑定参数值 | 实验参考基线 |
| G2 | Signed Tool-Scope (v1) | 真实 `issue_executor_authorization()` **不传 arguments** 签 v1；`verify_executor_authorization()` 不启用 `require_argument_binding` | 受控消融对照，非 E1 可部署配置 |
| G3 | Full E1 (strict v2) | 真实 `TrustedToolExecutor(e1_required=True)` + `authorization_policy="authorization_required"` + `execute_e1()` 四门禁 + 真实 Rust `e1_service` | 当前严格生产路径 |

**G1/G2 是用于隔离比较授权绑定性质的实验参考实现，不是完整竞争系统。** 本实验不对四组做端到端性能优劣结论。

**主对照口径**：主对照只在**相同攻击时机、相同样本数**的组之间比较——G1、G2 各 10 次参数替换样本，分别与 **G3-C2 的 10 次 Admission 后篡改样本**比较。G3-C1（Admission 前篡改，10 次）单独报告，**不并入主对照**，禁止把 C1+C2 共 20 次直接与 G1/G2 各 10 次放在同一主对照列中（两者攻击时机不同，合并会破坏可比性）。

## 5. 实验场景

- **A 正常请求**：授权参数 = 执行参数 = `INV-E16-SYSTEM`，预期三组均 dispatch。
- **B 授权后参数替换**：授权 `INV-E16-SYSTEM`，执行 `INV-E16-ATTACK`。预期 G1/G2 接受并产生副作用，G3 拒绝。
- **C1 Admission 前篡改**（仅 G3）：先签 v2 授权，改 `ctx.arguments`，再 `h.run()`。预期 Runtime 预检查拒绝，D10/D11 均未发生。
- **C2 Admission 后、最终门禁前篡改**（仅 G3）：先正常 `h.run()` 得 `PendingExecution`，再 `dataclasses.replace(pending, arguments=ATTACK)` 交 `execute_e1()`。预期 D10/D11 已提交，但最终门禁拒绝，工具 dispatch=0。**预算不回滚**，如实记录。
- **D exact replay**：正常操作重复提交返回原始 Receipt，dispatch 不增。

## 6. 指标定义

| 指标 | 定义 |
|---|---|
| Unauthorized Effect Rate | `Unauthorized Effects / Attack Attempts`（最重要） |
| Attack Rejection Rate | `Denied Attack Attempts / Attack Attempts` |
| Benign Acceptance Rate | `Accepted Benign Requests / Benign Requests` |
| Dispatch Count | 每组真实进入工具 dispatch 的次数（与副作用事件分别记录） |
| Admission 状态 | D10 Admission / D11 Transition 是否提交（C1 vs C2 必须区分） |

Admission 与 Tool Dispatch **不合并**为单一指标。「请求被拒绝」「未发生 dispatch」「未发生外部副作用」三者也分别记录，不混为一个指标。

## 7. 运行环境与复现命令

在仓库根目录执行（Windows PowerShell）：

```powershell
# 基线确认
git status --short
git rev-parse HEAD   # 应为 467fa249c2c7f6971dd9f217ce0827e6f7bfc995

# 编译真实 Rust e1_service
Push-Location .\experiments\d11_3_c_coordinator
cargo build
Pop-Location
Test-Path .\experiments\d11_3_c_coordinator\target\debug\e1_service.exe

# Python 路径（脚本也会自动注入 src/tests）
$env:PYTHONPATH = "$(Get-Location)\src;$(Get-Location)\tests"

# smoke test
python experiments\e2_1_request_binding\run_experiment.py --trials 3 --output-dir experiments\e2_1_request_binding\results\smoke

# 正式实验
python experiments\e2_1_request_binding\run_experiment.py --trials 10 --output-dir experiments\e2_1_request_binding\results\run-001

# 实验逻辑测试
python -m unittest discover -s tests -p "test_e2_1_request_binding_experiment.py" -v

# 原项目回归
python -m unittest discover -s tests -v
git diff --check
git status --short
```

Git Bash 环境等价命令把 `PYTHONPATH` 换成 `PYTHONPATH=src:tests python ...`；脚本本身已通过 `sys.path` 注入 `src/` 与 `tests/`，不依赖外部设置。

## 8. 样本与预算

- 每个条件基准 `N = 10`，smoke 允许 `N = 3`。
- 每次完整操作使用唯一 `operation_id` 与独立 harness（独立 D10 lease、D11 DB、Rust 服务进程），**不把同一 operation_id 的重复调用伪装成独立样本**。
- G1/G2 不消耗 D10 Admission；C1 在 Admission 前失败不消耗；G3 正常/C2 每次各消耗 1 个 D10 单位。
- 本实验是确定性机制实验，`N = 10`，**不做统计显著性或置信区间推断**；`0/10` 不等于统计意义上的攻击成功概率为零。
- 本实验是具体场景的受控机制实验，**不是形式化安全证明**，也**不是对所有 ACL / Capability 系统的普遍比较**。

## 9. 输出

`run_experiment.py` 统一用标准库 CSV/JSON 写出：

- `trials.csv`：逐样本原始记录（组、场景、operation_id、实际执行参数、accept/reject、拒绝阶段与原因、dispatch 计数、副作用、D10/D11 状态、授权版本、Receipt 验签）。
- `summary.json`：按组汇总的指标。
- `raw.json`：含元数据的完整原始数据。

报告 `docs/E2.1_REQUEST_BINDING_EXPERIMENT_REPORT.md` 的所有数据来自 `run-001`，不预填期望值。

## 10. 边界与局限

- 不开展性能基准；不引入真实 LLM / AgentDojo；不做多实例唯一执行；不实现抗回滚；不改 Halo2/D11 电路；不改 Journal Service。
- 不声称 exactly-once；不声称全面抵御 Prompt Injection；不新增生产代码功能。
- C2 的 D10/D11 Admission 在最终门禁拒绝后**不自动回滚、不自动退款**（实现中不存在退款机制，只有 SQLite 事务 rollback）；**Admission 成功不等于工具执行完成**。这是已记录的 Saga 窗口，不是「所有资源消耗均未发生」。
- exact replay 只说明本次本地确定性工具测试中未增加 dispatch，**不扩展为任意外部系统的 exactly-once 保证**。
- G1/G2 是实验参考基线，不代表真实竞争系统的完整防护能力。
