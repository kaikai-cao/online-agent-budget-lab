# H2.2 撤销可见性实验报告（run-001）

**结论先行：NO-GO（C2 不值得进入 H2 后续阶段）。** 在冻结协议 `docs/H2_EXPERIMENT_PROTOCOL.md` §7 的五条判据中，第 1 条（零在线预算/纯离线路径 B）与第 2 条（路径 A 无实质窗口优势）成立；其余三条未触发。该结论是实验决定的结果，不是预设结论；`N=10` 为机制验证，不是统计显著性证明。

---

## 1. 实验环境与复现命令

### 1.1 环境

| 项 | 值 |
| --- | --- |
| 仓库 / 分支 | `online-agent-budget-lab` / `research/h2-revocation-management` |
| 机制基线 HEAD | `0a3ae2f57107e4f51a5cb1abc46f089d1669373a`（H2.1-R2.2 冻结） |
| 操作系统 / Shell | Windows / Git Bash |
| Python | `.venv/Scripts/python`，Python 3.14.7 |
| Git | 2.55.0.windows.3 |
| 依赖组件 | `cryptography` Ed25519；本地 SQLite（`ControlledSink` + `SnapshotStateStore`）；真实 localhost TCP+TLS + 服务器证书指纹固定（B2 授权查询、C2 快照分发） |
| 时间体系 | 窗口类（`W_risk`/`D_prop`/`age`）用注入逻辑时钟；成本类（`perf_counter`）只用墙钟；二者不相加 |
| 外部依赖 | 无真实 MCP、无第三方 API、无真实 Agent；只用受控 Sink |
| 运行日期 / 时长 | 2026-11-19；`run_wall_seconds = 282.290579`（约 4 分 43 秒） |
| 输出目录 | `experiments/h2_revocation_management/results/run-001/` |

### 1.2 复现命令

执行前确认（本轮已执行并全部通过）：

```bash
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python -m unittest tests.test_h2_revocation_management   # 37/37 OK
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python -m unittest tests.test_h1_authorization_binding   # 23/23 OK
```

协议 §8.4 的正式运行命令，以及本轮实际使用的等价命令（显式 `--full`）：

```bash
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python experiments/h2_revocation_management/run_experiment.py \
  --output-dir experiments/h2_revocation_management/results/run-001

# 本轮实际执行：
PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
  .venv/Scripts/python experiments/h2_revocation_management/run_experiment.py \
  --full --output-dir experiments/h2_revocation_management/results/run-001
```

### 1.3 元数据说明（如实记录）

`summary.json` 的 `run_id` 字段为 `smoke-001`，这是冻结的 H2.1 Runner 中的固定字符串，并非本轮实际模式。本轮真实模式由同文件的 `mode="full"`、`n_per_cell=10`、`total_trials=670` 与输出目录 `run-001` 共同确定。H2.2 不修改 H2.1 实现，故保留该字段并在报告中标注，不静默改写产物。

---

## 2. 实际运行矩阵与每单元 trial 数量

- 适用实验单元：**67 个**，每个单元 **N=10**，合计 **670** trials；`trials.csv` 671 行（含表头），`raw.json` 为 670 条逐 trial 记录。
- `passed_trials=670`、`failed_trials=0`、`all_pass=true`；`expected_outcome` 只用于 `pass` 断言，所有 outcome/reason/effects 均为实际调用模块后记录。
- 实际覆盖：M01–M15 全部场景；M07 拆为 a/b/c/d（M07d 含 `boot_online`/`untrusted`/`after_boot_replay` 三臂）；M13 含 K=1/10/100/1000；M14 含 C1 路径 B、C2 路径 B、C2 路径 B 过期、C2 路径 A；M15 为 B2 查询—消费竞态。

**参数网格的实际覆盖与缺口**（不得掩饰）：

| 参数 | 协议要求 | 本轮实际值 | 说明 |
| --- | --- | --- | --- |
| C1 τ | {5, 15, 60}s | 5s（M03/M04）、60s（M14） | **τ=15s 未运行**；冻结 Runner 未构造该臂 |
| C2 R | {5, 30, 120}s | 30s（M04/M14） | **R=5s、120s 未运行**；冻结 Runner 未构造该臂 |
| C2 S | 120s | 120s | 符合 |
| C0/C2 ttl | 300s | 300s | 符合 |

因此 §7.2 中"C2 随 R 单调下降可测"这一 GO 条件在本轮数据上**无法验证**。该缺口不改变当前数据下 §7.1 第 1、2 条已成立的事实；若未来重开 H2，应先补齐参数网格，而不是从现有数据外推。

---

## 3. 各场景通过率、拒绝原因与副作用

所有场景 `pass=100%`（每单元 10/10）。下表按场景给出实际 outcome 与副作用（`effects_added`）。

| 场景 | 实际结果（每单元 N=10） | 副作用 |
| --- | --- | --- |
| M01 合法执行 | B2/C0/C1/C2 全部 `EXECUTED`，reason `OK` | 各 1 |
| M02 离线执行 | B2 `REJECTED:B2_DENIED:AUTH_SERVICE_UNREACHABLE`；C0/C1/C2 `EXECUTED`（离线成功 10/10） | B2 0；C 组各 1 |
| M03 离线过期 | 四组全 `REJECTED`（B2 服务不可达；C0/C1/C2 均 `C_EXPIRED`） | 全 0 |
| M04 撤销后在线 | B2 `B2_DENIED:REVOKED`；C2 `REVOKED_BY_SNAPSHOT`；C0/C1 `EXECUTED`（无快照，设计限制） | B2/C2 0；C0/C1 各 1 |
| M05 撤销后离线 | B2 不可达；C1 `C_EXPIRED`；C0/C2 `EXECUTED`（C2 为定义内路径 B 风险窗口，非 false_allow） | B2/C1 0；C0/C2 各 1 |
| M06 陈旧快照过期 | C2 `REJECTED:SNAPSHOT_UNAVAILABLE`（10/10 fail closed） | 0 |
| M07a 进程内回滚 | base `CANDIDATE_REJECTED:SNAPSHOT_VERSION_STALE`；post `EXECUTED` | 0 / 1 |
| M07b 重启后回滚 | base `CANDIDATE_REJECTED:SNAPSHOT_VERSION_STALE`；post `REJECTED:REVOKED_BY_SNAPSHOT` | 全 0 |
| M07c 状态不可读 | C2 `REJECTED:SNAPSHOT_STATE_UNAVAILABLE` | 0 |
| M07d 首次信任 | `boot_online`→`INITIALIZED`（`initialized=TRUE`、`bootstrap_mode=BOOT_ONLINE`、版本 1）；`untrusted`→`SNAPSHOT_UNTRUSTED`；`after_boot_replay`→`SNAPSHOT_VERSION_STALE` | 全 0 |
| M08 伪造快照 | C2 `CANDIDATE_REJECTED:SNAPSHOT_SIGNATURE_INVALID` | 0 |
| M09 畸形快照 | `expired`、`not_yet_valid`、`malformed_jtis`、`nonfinite` 四类各 10，全部 `CANDIDATE_REJECTED` | 全 0 |
| M10 并发已撤销 | B2 `B2_DENIED:REVOKED`；C2 `REVOKED_BY_SNAPSHOT`；C0/C1 `EXECUTED`（设计限制，不计缺陷） | B2/C2 0；C0/C1 各 1 |
| M11 并发合法 | 四组均 `ONE_EXECUTED`，reason `executed=1,dedup=7,effects=1` | 各 1（重复请求未增副作用） |
| M12 声明篡改 | 四组 × 4 臂（arguments/server/schema/executor）全部 `REJECTED`；B2 用 `B2_DENIED:ACTION_DIGEST_MISMATCH`，C 组用 `ACTION_DIGEST_MISMATCH` / `EXECUTOR_TARGET_MISMATCH` | 全 0 |
| M13 同步成本 | C2 K=1/10/100/1000 均 `MEASURED` | 0 |
| M14 头对头 | 见 §6 | 见 §6 |
| M15 B2 竞态 | `b2_race_effect_count=1`（10/10），已知边界，如实记录 | 10 |

**`false_allow_count = 0`。** 全部 `EXECUTED` 行的 reason 均为 `OK`（或 `ONE_EXECUTED`/`INITIALIZED`/`MEASURED` 对应的正常记录）；不存在"缓存已列出该 jti仍执行""快照过期仍执行""凭证过期仍执行"的行。C0/C1 在 M10 执行有效凭证与 B2 在 M15 产生一次副作用均为设计限制/已知边界，按 §7.1 第 4 条不计入缺陷。

---

## 4. HWM、重启、首次 bootstrap、伪造与回滚

| 检查 | 冻结要求 | run-001 实测 |
| --- | --- | --- |
| 进程内旧版本快照 | 拒绝且 HWM 不回退 | M07a base 10/10 `SNAPSHOT_VERSION_STALE` |
| 重启后重放旧快照 | HWM 持久化，重放拒绝 | M07b base 10/10 `SNAPSHOT_VERSION_STALE`，post 10/10 `REVOKED_BY_SNAPSHOT` |
| 持久状态不可读 | fail closed，不重新 bootstrap | M07c 10/10 `SNAPSHOT_STATE_UNAVAILABLE`（0 副作用） |
| 首次可信 bootstrap | S0 建立 `initialized`+HWM+快照+摘要 | M07d `boot_online` 10/10 `INITIALIZED`，版本=1，`initialized=TRUE` |
| 不可信通道注入陈旧快照 | 拒绝，不作为初始状态 | M07d `untrusted` 10/10 `SNAPSHOT_UNTRUSTED` |
| bootstrap 后旧版本重放 | 拒绝 | M07d `after_boot_replay` 10/10 `SNAPSHOT_VERSION_STALE` |
| 伪造签名 | 拒绝 | M08 10/10 `SNAPSHOT_SIGNATURE_INVALID` |
| 畸形/过期/未生效快照 | 拒绝 | M09 40/40 `CANDIDATE_REJECTED` |

未发现抗回滚、抗伪造、重启重放或首次注入失败；H2-b/H2-f 相关断言全部通过。

---

## 5. W_risk 与 D_prop 分层统计

复算口径（协议 §6.2，均用注入逻辑时钟，**不**与墙钟混合）：

```
W_risk(t) = (t_first_reject - t_revoke) * 1000   ms
D_prop(t) = (t_snapshot_obtained - t_revoke) * 1000  ms   （仅 C2 取得含撤销快照时）
```

### 5.1 C2 的 W_risk 分层

| 分层（`w_risk_path`） | n | median | min | max | 构成与说明 |
| --- | --- | --- | --- | --- | --- |
| `ONLINE_REFRESH_OK`（路径 A） | 30 | **38,000 ms** | 30,000 ms | 38,000 ms | M04 10 次 38s（`t_revoke=2`, `t_first_reject=40`）+ M14 pathA 10 次 30s（`t_revoke=10`, `t_first_reject=40`），另有 M10 10 次 38s |
| `OFFLINE_STALE_CONTINUE`（路径 B） | 10 | **NA** | NA | NA | M14 pathB 10/10 `w_risk_ms=NULL`：观测窗内从未拒绝，未填有限值、未填 0 |
| 无拒绝（`NA` 路径） | 280 | NA | — | — | 270 行 `NULL`（未触发拒绝）+ 10 行 `>OBSERVATION_WINDOW` |

说明：实现用 `w_risk_ms=NULL` 表示"观测窗内未拒绝"（与协议"`>观测窗上界`并单列"语义一致，均未转 0）；`>OBSERVATION_WINDOW` 用于快照已过期仍无法取得有效状态而 fail closed 的情形。C2 的 W_risk 严格按路径分层，**未**跨路径合并成一个"C2 风险窗口"，也**未**把 `R` 当作风险窗口。M04 的 38s 与 M14 的 30s 差异正说明 `R` 不等于风险窗口：实测值取决于撤销发生时刻与首次执行时刻。

### 5.2 D_prop（仅 C2）

| 场景 | n | median/min/max |
| --- | --- | --- |
| M04 撤销后在线 | 10 | 38,000 / 38,000 / 38,000 ms |
| M10 并发已撤销 | 10 | 38,000 / 38,000 / 38,000 ms |
| M14 pathA | 10 | 30,000 / 30,000 / 30,000 ms |
| 其余 C2 单元 | 290 | `NA_UNOBTAINED`（未取得含撤销的快照） |

`D_prop` 与 `W_risk` 分别统计，未相互替代。M14 pathA 中二者均为 30s，是因为取得含撤销快照的时刻与首次拒绝时刻相同；不能据此把两个概念合并。

### 5.3 C1 侧 W_risk 的实测局限

M14 pathB 的 C1（τ=60s）10/10 因 `C_EXPIRED` 拒绝，但 `t_first_reject` 记录为 `NA`，故 `w_risk_ms =>OBSERVATION_WINDOW`，无法按 §6.2 公式复算有限值。因此头对头比较中 C1 侧只能使用冻结参数 `τ=60s` 作为上界对照（协议 §7 本身即用 τ 上界判定 C2），不能宣称已实测 C1 的有限 W_risk。这是数据局限，不是"实测 C1 优于 C2"的证据。

---

## 6. A=60s 条件下的 C1/C2 头对头（M14）

| 单元 | 参数 | outcome | W_risk | 副作用 |
| --- | --- | --- | --- | --- |
| C1 `pure_offline_pathB` | τ=60s | 10/10 `REJECTED:C_EXPIRED` | `>OBSERVATION_WINDOW`（无有限实测） | 0 |
| C2 `pure_offline_pathB` | S=120s，全程无刷新 | 10/10 `EXECUTED` | `NULL`（窗内未拒绝） | 1 |
| C2 `pure_offline_pathB_expired` | S=120s 已过期 | 10/10 `REJECTED:SNAPSHOT_UNAVAILABLE` | `>OBSERVATION_WINDOW` | 0 |
| C2 `intermittent_pathA` | R=30s，刷新成功 | 10/10 `REVOKED_BY_SNAPSHOT` | 30,000 ms（10/10） | 0 |

**读法**：纯离线时 C1 的短 TTL 已能在 τ=60s 到期拒绝，而 C2 依赖 S=120s 的旧快照仍继续执行（定义内风险窗口），只有快照过期后才 fail closed。间歇可达且刷新成功时，C2 的 W_risk=30s，恰好等于 `0.5×τ = 30s`，**未达到 §7.2 要求的严格 `< 0.5τ`（改善≥2 倍）**。

---

## 7. 实际在线请求率与 B2 对照

在线成本按协议 §6.4 使用实测计数器，**未**用 `1/R` 代替。C2 请求率分母为该单元 `last_trial_end - first_trial_start`（`perf_counter` 首末跨度，含首末之间其他单元运行的真实墙钟）；整轮 `run_wall_seconds` 仅作诊断，不作任何单元分母。

| C2 单元 | attempts | success | failure | observation_wall_seconds | actual_refresh_request_rate |
| --- | --- | --- | --- | --- | --- |
| M01 / M02 / M05 / M07a / M07b（C2 单元） | 0 | 0 | 0 | 约 254 s | 0.0 |
| M04 | 10 | 10 | 0 | 254.337 | 0.039318 /s |
| M06 | 10 | 0 | 10 | 254.273 | 0.039328 /s |
| M10 | 10 | 10 | 0 | 255.259 | 0.039176 /s |
| M14 pathA | 10 | 10 | 0 | 254.628 | 0.039273 /s |
| M14 pathB | 10 | 0 | 10 | 254.545 | 0.039286 /s |
| M14 pathB_expired | 10 | 0 | 10 | 254.589 | 0.039279 /s |

`successful_refresh_interval` 在所有单元均为 NA（`NA_NO_CONTINUOUS_LOGICAL_CLOCK` 或 `NA_LESS_THAN_TWO_REFRESH_SUCCESSES`）：每个 trial 使用独立 Harness、逻辑时钟重新起点，只有同一执行实例内的相邻成功刷新才可计算，未跨 Harness 拼接出看似有效的间隔。

**与 B2 对照的诚实边界**：B2 的语义是每次执行 1 次在线查询；冻结 Runner 未为 B2 单元输出同口径的墙钟观察跨度，因此无法从 run-001 严格复算 B2 的实测查询率（次/秒）。可以复算的事实是：C2 适用 trial 共 110 个，实测 `refresh_attempt_count` 合计 **60**（其中 M04/M06/M10/M14 四个刷新臂各 10 次，其余适用 trial 为 `NO_REFRESH_NEEDED` 等 0 次），即 110 个适用 trial 中只有 60 次在线刷新尝试；失败臂（M06、M14 pathB/pathB_expired）的失败重试也已计入（各 10 次失败、rate≈0.039/s），未隐藏。因此条件 3 不因成本塌缩而触发；但本轮**没有观测到 C2 相对 B2 的在线请求数优势**；§7.2 所要求的"执行间隔 < R 时仍显著低于 B2"场景未被本矩阵构造（当前逻辑时钟被推进到 `age≥R` 后执行）。这是 NO-GO 结论的一部分，而非实验失败。

---

## 8. 快照大小、同步耗时与验签耗时随 K 的变化（M13）

每档 K 各 10 次，下表为 median（括号内 min–max）：

| K | `snapshot_payload_bytes` | `sync_duration_ms` | `snapshot_verify_ms` |
| --- | --- | --- | --- |
| 1 | 182 | 0.1562（0.0874–0.4884） | 同左 |
| 10 | 290 | 0.2031（0.0927–0.3894） | 同左 |
| 100 | 1,370 | 0.3341（0.1298–0.6498） | 同左 |
| 1000 | 12,170 | 0.4384（0.3089–1.2272） | 同左 |

从 K=100 到 K=1000，字节数 1,370→12,170（约 8.9 倍，低于 K 的 10 倍），同步耗时中位数 0.334→0.438 ms（亚线性）。累积撤销集合的设计呈近似线性增长，**§7.1 第 5 条成本不可扩展不成立**。

**字段局限**：冻结 Runner 的 M13 把 `sync_duration_ms` 与 `snapshot_verify_ms` 写成同一个计时值（`run_experiment.py` 中两行均取 `verify_ms`），因此这两个字段在本轮数据中逐 trial 完全相同，不能独立解读"整体同步耗时"与"纯验签耗时"。报告只按实测值报告字节数与同一计时量，不声称已分离测得验签成本。

---

## 9. H2-a 至 H2-g 逐项验收

| 项 | 冻结要求 | 本轮结论 |
| --- | --- | --- |
| H2-a 四组公平性 | 同请求/摘要/时钟/Sink/信任锚 | 通过：M01 四组均执行且各 1 副作用；M11 四组均恰好 1 副作用、7 次 DEDUP_HIT |
| H2-b 抗回滚/抗伪造 | 旧版本、伪造签名、重启重放均拒 | 通过：M07a/b、M08 全部按预期拒绝；0 副作用 |
| H2-c 过期与无错误放行 | 过期快照 fail closed，`false_allow=0` | 通过：M06 10/10 `SNAPSHOT_UNAVAILABLE`；全数据 `false_allow_count=0` |
| H2-d1 C2 已知撤销不放行 | M10 C2 撤销拒绝率 1.0 | 通过：10/10 `REVOKED_BY_SNAPSHOT` |
| H2-d2 四组原子消费 | 重复执行最多 1 副作用 | 通过：M10 B2/C2 0、C0/C1 ≤1；M11 四组恰 1 |
| H2-e B2 竞态如实测量 | 记录副作用，非"即时拒绝" | 通过：M15 `b2_race_effect_count=1`（10/10），按已知边界记录 |
| H2-f 首次信任 | S0 bootstrap、S1 恢复、S2 损坏 fail closed、不可信注入拒 | 通过：M07a–d 全部符合；`initialized=TRUE`、`BOOT_ONLINE` 已持久化 |
| H2-g 刷新成本如实计量 | 实测 attempts/rate，不以 `1/R` 代替 | 通过：60 次刷新尝试（110 个适用 trial）全部实测；请求率按单元首末跨度计算；无跨 Harness 间隔伪造 |

速度与正确性断言均通过；但 H2-g 要求的是"如实计量"，不是"请求数必须低"，本轮如实显示 C2 未降低请求次数。

---

## 10. 按协议 §7 的 GO / NO-GO 判定

| §7.1 NO-GO 条件 | 本轮证据 | 是否触发 |
| --- | --- | --- |
| 1. 零在线预算/路径 B：C2 上界不优于 C1 τ=A=60s，却多出同步成本 | M14 pathB：C1 τ=60s 到期拒绝（10/10），C2 凭 S=120s 旧快照仍执行（10/10），W_risk 窗内未拒绝；S=120s ≥ A=60s；C2 另有 M13 同步/验签成本 | **触发** |
| 2. 路径 A 窗口优势不足：`median(W_risk_C2, ONLINE_REFRESH_OK) ≥ 0.5τ` | τ=60s → 阈值 30,000 ms；C2 分层 median=38,000 ms；只看 M14 pathA 亦为 30,000 ms（等于阈值，未严格小于） | **触发** |
| 3. 在线成本塌缩：只有接近 B2 每次查询率才能击败 C1 | C2 未击败 C1（条件 2）；110 个适用 trial 实测 60 次刷新尝试，失败臂重试已计入；B2 同口径墙钟跨度未采集，无法严格给出 B2 次/秒 | 未触发；但无 C2 成本优势证据 |
| 4. 正确性缺陷：`false_allow>0` 或 H2-b/c/d1/f 任一失败 | `false_allow=0`；相关断言全部通过 | 不触发 |
| 5. 成本不可扩展：payload/sync 随 K 超线性 | 1,370→12,170 字节（K 100→1000，约 8.9×）；sync median 亚线性 | 不触发 |

**判定：NO-GO。** 依据：条件 1 与条件 2 已满足冻结判据；§7.2 的 GO 条件（C2 在路径 A `median(W_risk) < 0.5τ` 且随 R 单调下降可测、显著低于 B2 查询率）均不成立或不可验证。

按 §7.3 的诚实结论边界，进一步表述为部署条件依赖的权衡：

- **纯离线/零在线预算部署**：C1 的短 TTL（τ=60s）已足够，C2 在 S=120s 内继续执行且无窗口优势，同时承担同步验签成本 → **C1 足够，C2 无增量**。
- **间歇可达且刷新成功部署**：C2 在 R=30s 下取得 30–38s 的实测窗口，未达到相对 τ=60s 的 2 倍改善阈值；且本轮未覆盖 R=5/120s，无法给出"随 R 单调下降"的证据 → **当前数据不支持 C2 有价值**。
- 这不是"C2 不安全"的证明：`false_allow=0`、抗回滚/抗伪造/首次信任机制全部通过。问题是**收益不足**，不是正确性失败。

---

## 11. 数据完整性与诚实边界

### 11.1 自检结果

- `trials.csv` 671 行 = 1 表头 + 670 trials；`raw.json` 为 670 条；`summary.json` 的 `total_trials/passed_trials/failed_trials` 与 CSV 复算一致（670/670/0）。
- 67 个单元全部 N=10；无缺行、无预填预期结果；所有 `pass=TRUE`。
- 11 个 C2 刷新成本单元、`applicable_trial_count=110`，与 CSV 中 `refresh_outcome` 属于四个冻结类别的 C2 行数一致。
- `NA` 未被转换为 0：`successful_refresh_interval` 全为 NA 标记；未拒绝的 `W_risk` 为 `NULL`/`>OBSERVATION_WINDOW`；未取得快照的 `D_prop` 为 `NA_UNOBTAINED`。真实观测到的 0 次刷新尝试（如 M01/C2）才记为 rate 0.0。

### 11.2 局限与未覆盖项

1. 参数网格不全：τ=15s、R=5s、R=120s 未运行（§2）；"随 R 单调下降"无法验证。
2. B2 单元的同口径墙钟观察跨度未输出，无法严格复算 B2 实测查询率（§7）；与 C2 的对照使用协议定义与实测 attempts，标注为推断而非同口径实测。
3. M13 的 `sync_duration_ms` 与 `snapshot_verify_ms` 同源同值，不能独立解读验签耗时（§8）。
4. C1 头对头缺 `t_first_reject` 时间戳，W_risk 只能记为 `>OBSERVATION_WINDOW`，C1 侧用冻结 τ 上界对照（§5.3）。
5. `summary.json` 的 `run_id` 为冻结 Runner 固定值 `smoke-001`，实际以 `mode=full`/`n=10`/670 trials 为准（§1.3）。
6. 本轮未修改任何生产代码、测试代码或 H2.0/H2.1 冻结文档；未静默重跑覆盖失败记录；`work/` 临时库由 `.gitignore` 忽略，未混入提交。

### 11.3 不得外推的边界

C2/B2 均不提供全局即时撤销、不提供 `exactly-once`、不覆盖跨执行器全局消费；B2 存在查询—消费 TOCTOU 窗口（M15 已如实记录）；受控 Sink 不代表第三方工具服务行为；`N=10` 是机制验证而非统计显著性证明；本实验未接入真实 MCP、第三方 API 或真实 Agent，也不验证真实执行真实性。
