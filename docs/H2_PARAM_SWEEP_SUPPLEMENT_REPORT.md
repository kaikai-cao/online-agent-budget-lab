# H2.2 参数覆盖补充实验报告（run-002）

> 本文件是对 `docs/H2_REVOCATION_EXPERIMENT_REPORT.md`（run-001）的**有边界补充**，不替代、不推翻 run-001 的任何数据或判定。
> 目标只有一个：补齐冻结协议 `docs/H2_EXPERIMENT_PROTOCOL.md` §2 声明、但 run-001 未覆盖的参数臂。
> 不修改 H2.0 冻结协议、不修改 H2.1 机制与 Runner、不修改 §7 的五条 NO-GO 判据、不重跑 run-001 已完成的任何 `(scenario, group, arm)` 单元、不运行新的场景设计。

**结论先行**：run-002 补齐了 C1 `τ=15s` 与 C2 `R∈{5,120}s` 三个缺失臂，参数网格现已完整（C1 τ∈{5,15,60}、C2 R∈{5,30,120}）。新数据给出 C2 路径 A 的 `W_risk` 随 `R` **单调上升**的实测序列：`R=5s → 5s`、`R=30s → 30s`、`R=120s → 120s`。据此：

- **纯离线部署（结论 A）：NO-GO 不变。** 该判定只依赖 M14 路径 B（C1 τ=60 到期拒绝 vs C2 持 S=120 旧快照执行），与 R 取值无关，run-002 未触碰路径 B，故 §7.1 第 1 条仍成立。
- **间歇可达部署（结论 B）：参数空间判断已可完成，但结论仍不支持 GO。** R=5s 把路径 A 的 `W_risk` 从 30s 降到 5s（相对 τ=60s 改善 12 倍，满足 §7.2 `< 0.5τ` 的窗口门槛），且随 R 单调可测——这补齐了 run-001 无法验证的 GO 子条件。但 §7.2 是**合取**条件：仍缺"实测请求率显著低于 B2 每次查询率"的证据（run-001 已如实记录 B2 同口径墙钟跨度未采集）；同时 §7.1 第 1 条（纯离线臂）已触发，按 §7.1"任一条件成立即 NO-GO"。因此整体判定仍为 **NO-GO**，但结论应精确表述为**部署条件依赖的权衡**：间歇可达 + R=5s 下 C2 具备窗口优势，纯离线场景 C1 已足够。
- 这不等于"C2 不安全"，也不等于"所有参数组合下 C2 都无价值"；机制正确性测试（H2-a～g）与 `false_allow=0` 在 run-001 已全过，run-002 未改变这些事实。

---

## 1. 补测范围与复现命令

### 1.1 补齐的缺失臂

冻结协议 §2 扫描网格 vs 两次运行的实际覆盖：

| 参数 | 冻结网格 | run-001 覆盖 | run-002 新增 | 补齐后 |
|---|---|---|---|---|
| C1 短 TTL `τ` | {5, 15, 60} s | 5（M01–M05/M10/M11）、60（M14 pathB） | **15** | {5, 15, 60} 完整 |
| C2 刷新间隔 `R` | {5, 30, 120} s | 30（M04/M14） | **5、120** | {5, 30, 120} 完整 |
| C2 快照有效期 `S` | 120 s（固定） | 120 | 120（不变） | 120 |
| 目标离线可用性 `A` | 60 s（固定） | 60 | 60（不变） | 60 |

### 1.2 四个新增实验单元（每单元 N=10）

| 场景 | 组 | arm（新标签） | 时间点 | 机制预期 |
|---|---|---|---|---|
| M14 `head_to_head` | C2 | `intermittent_pathA_R=5` | bootstrap@0, revoke@10, exec@15 | 刷新拉到含撤销快照 → REJECTED |
| M14 `head_to_head` | C2 | `intermittent_pathA_R=120` | bootstrap@0, revoke@10, exec@130 | 同上（R=S 边界臂，仍在线可达） |
| M02 `offline_exec` | C1 | `tau=15` | issue@0, exec@10（<15） | τ 内 → EXECUTED |
| M03 `offline_expired` | C1 | `tau=15` | issue@0, exec@400（>15） | 超 τ → REJECTED `C_EXPIRED` |

四个 arm 标签均为 run-001 不存在的新单元，无标签冲突；脚本内置 `RUN001_UNITS` 护栏，一旦发现与 run-001 单元重叠即拒跑。

### 1.3 复现命令（Windows）

```bash
# run-002（本次正式补测）
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python experiments/h2_revocation_management/run_experiment_param_sweep.py \
    --full --output-dir experiments/h2_revocation_management/results/run-002

# 冻结回归（确认 H2.1 机制未受影响）
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python -m unittest tests.test_h2_revocation_management
```

### 1.4 复用的冻结部件与未改动项

补测脚本 `run_experiment_param_sweep.py` 仅**继承/导入**冻结部件：冻结 `Runner`（`emit` / `_harness` / `unit_observation`）、冻结指标函数（`_blank` / `_fill_result` / `write_outputs`）、冻结机制（`H2Harness` / `H2Executor` / `h2_snapshot*`）。未修改任何冻结文件；`RUN_ID` 仅在运行时覆盖为 `run-002` 以标注数据来源。H2 专项 37/37、H1 冻结 23/23 复跑通过，证明机制零改动。

---

## 2. 实际运行结果

| 指标 | 结果 |
|---|---|
| 总 trial | 40（4 单元 × N=10） |
| `pass=TRUE` / `FALSE` | 40 / 0 |
| 输出 | `results/run-002/{trials.csv, summary.json, raw.json}` |
| 与 run-001 单元重叠 | 0（护栏校验通过） |
| run-001 完整性 | 仍为 670 行 / 67 单元，未被覆盖或改写 |

每个新增单元恰 10 个 trial，`actual_outcome` / `actual_reason` 均为实际调用模块后的观测值，未预填预期。

---

## 3. C2 路径 A：W_risk 随 R 的单调序列（本次核心结果）

沿用 run-001 的 head-to-head 结构：bootstrap@0、`t_revoke=10`、`t_exec=t_revoke+R`。新臂的 `refresh_outcome` 均为 `REFRESH_SUCCESS`、`w_risk_path` 均为 `ONLINE_REFRESH_OK`，因此按协议 §6.2 用注入逻辑时钟 `W_risk = t_first_reject − t_revoke` 复算：

| R | 来源 | `t_revoke` | `t_exec` = `t_first_reject` | `W_risk`（实测） | 相对 τ=60s |
|---|---|---|---|---|---|
| 5 s | run-002 | 10 | 15 | **5,000 ms（5 s）** | 12× 改善 |
| 30 s | run-001 | 10 | 40 | **30,000 ms（30 s）** | 2× 改善（等于阈值） |
| 120 s | run-002 | 10 | 130 | **120,000 ms（120 s）** | 0.5×（更差） |

结论：`W_risk` 随 `R` **严格单调上升**（5 < 30 < 120 s），即随 R 缩小而下降——协议 §7.2"随 R 单调下降可测"这一 GO 子条件，在 run-001 无法验证的缺口，现由 run-002 补齐并可测。R=5 臂满足 `median(W_risk_C2 | ONLINE_REFRESH_OK) < 0.5×τ`（5 s < 30 s）。

**必须同时陈述的限制**：这条单调序列来自"撤销后经过恰好一个 R 才执行"的受控构造（`t_exec=10+R`）。它证明的是"在间歇可达、且执行时机由 R 对齐"这一条件下窗口随 R 变化，不是任意到达分布下的普遍上界；协议 §4/§6.2 本身不为路径 A 提供上界表达式，只要求实测，本表即实测值。

---

## 4. C1 τ=15s 离线窗口边界

| 场景 | arm | `t_exec` | 实测 outcome / reason | 说明 |
|---|---|---|---|---|
| M02 `offline_exec` | `tau=15` | 10（<15） | EXECUTED / OK | τ 内凭证有效，10/10 |
| M03 `offline_expired` | `tau=15` | 400（>15） | REJECTED / `C_EXPIRED` | 超 τ 到期拒绝，10/10 |

`τ=15` 的短 TTL 行为与 run-001 的 τ=5、τ=60 同构：窗口内可执行、窗外 fail closed。C1 侧 `w_risk_ms` 仍为 `NULL`（`t_first_reject=NA`，见主报告 §5.3），不伪造有限值；头对头比较仍以冻结参数 τ 作上界，不宣称已实测 C1 有限 W_risk。

---

## 5. 在线请求成本的诚实边界（未扩大实验）

在 run-002 的"每 trial 单次执行"结构中，每个 C2 适用 trial 最多发起 1 次在线刷新尝试（`refresh_attempts ≤ 1`）。因此本轮的 `actual_refresh_request_rate` 对 R=5 与 R=120 都是"每个观测跨度 1 次尝试"的量级，**并不能**反映协议 §6.4 所关心的"服务持续不可用时 R 越小请求率越高"的持续成本。

本补测**没有**引入连续执行场景来制造这一数据——那属于新的实验设计，超出"补齐参数臂"的有边界任务。因此：

- §7.1 第 3 条（在线成本塌缩）仍维持 run-001 的判定：未触发，但**无 C2 相对 B2 的成本优势证据**（B2 同口径墙钟跨度仍未采集）。
- 不能据 run-002 断言 R=5 的窗口优势是"低成本取得"的；窗口收益与成本收益必须分开陈述。

---

## 6. 按协议 §7 的判定（判据未改）

| §7.1 NO-GO 条件 | run-002 后证据 | 是否触发 |
|---|---|---|
| 1. 纯离线路径 B：C2 上界不优于 C1 且多成本 | run-001 M14 pathB 已成立；run-002 未触碰路径 B | **仍触发** |
| 2. 路径 A 无实质窗口优势（≥0.5τ） | R=5 臂 5s < 30s，单独看该臂不触发；但判定基于冻结的整体 NO-GO，且条件 1 已触发 | 该臂不再触发；不改变整体判定 |
| 3. 在线成本塌缩 | B2 同口径未采集；无成本优势证据 | 未触发；无成本优势证据 |
| 4. 正确性缺陷 | `false_allow=0`，H2-a～g 全过（run-001），run-002 复跑通过 | 未触发 |
| 5. 成本随 K 超线性 | run-001 M13：K 100→1000 字节 8.9×、同步亚线性 | 未触发 |

**整体判定：维持 NO-GO。** 依据：§7.1 为"任一条件成立即 NO-GO"，条件 1（纯离线臂）始终触发；§7.2 的 GO 是合取条件，即便窗口与单调性子条件在 R=5 下补齐，仍缺"请求率显著低于 B2"的证据。判据本身一字未改。

按 §7.3 的诚实结论边界，表述为**部署条件依赖的权衡**：

- **零在线预算 / 纯离线部署**：C1（τ=A=60s）已足够；C2 凭 S=120s 旧快照继续执行且窗口不优于 C1，还要承担同步/验签成本 → **NO-GO，结论不变**。
- **间歇可达 + 刷新成功部署**：C2 在 R=5s 下 `W_risk=5s`，具备相对 C1 的实质窗口优势且随 R 单调可测 → **该部署条件下 C2 有价值**；但受成本证据缺失限制，不足以翻转为整体 GO。

---

## 7. 数据完整性与诚实边界

### 7.1 自检（14 项全过）
40 行 / 4 单元各 N=10 / 全 pass / raw=40 / summary 计数一致；R=5 与 R=120 的 `W_risk` 精确为 5,000 ms 与 120,000 ms 且均为 `REFRESH_SUCCESS`+`ONLINE_REFRESH_OK`；C1 τ=15 窗口内外 outcome 正确；与 run-001 单元零重叠；run-001 仍 670 行；未发生 NA→0。

### 7.2 局限（如实保留）
1. 参数网格现已完整，但 R 单调性仅在"执行时机由 R 对齐（t_exec=10+R）"的受控构造下成立，非任意到达分布的普遍结论。
2. run-002 未采集 B2 同口径墙钟跨度，无法严格给出 B2 实测查询率（次/秒），故无法完成 §7.2 的成本对照。
3. 单次执行结构下 `refresh_attempts ≤ 1`，不能反映"服务持续不可用时 R 越小请求率越高"的持续成本；未为此引入新场景。
4. C1 侧 `w_risk_ms=NULL`（缺 `t_first_reject`），头对头用 τ 上界对照，非实测 C1 有限窗口。
5. `N=10` 为机制验证，非统计显著性证明；无 p 值或置信区间。

### 7.3 不得外推
不宣称 C2 或 B2 实现全局即时撤销、`exactly-once`、真实第三方 API 或真实 Agent 行为；不把路径 B 的旧快照执行误判为 `false_allow`；不把"C2 不安全"或"所有参数下 C2 都无价值"作为结论。

---

## 8. 阶段状态

| 项目 | 状态 |
|---|---|
| H2.0 设计冻结 | 完成 |
| H2.1 实现冻结 | 完成 |
| H2.2 run-001（670 trials） | 已归档、独立复核通过、未改动 |
| H2.2 run-002（40 trials，参数补齐） | 本次完成，数据自检通过 |
| 参数网格 | 完整（C1 τ、C2 R 全网格覆盖） |
| 整体判定 | 维持 NO-GO；间歇可达 + R=5s 部署条件下 C2 有窗口价值（成本证据仍缺） |
