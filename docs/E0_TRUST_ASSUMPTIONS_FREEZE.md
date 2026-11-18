# E0 — Trust Assumptions Freeze（信任假设冻结）

> **文档性质**：冻结文档（freeze record），不是架构设计、不是实施授权。
> **基线**：E1.9-B 最终提交 `5853650`；B2.2 设计冻结 `3967100`；E1.8 / E1.9-A 已冻结。
> **本报告只描述已经实现并由提交 `5853650` 固定的系统**，不把设计意图写成已实现能力，不引入新机制、新密码学原语或新硬件依赖。
> **下游依据**：本冻结文档是 E1.9-C（Executor 集成与恢复验收）及后续安全论证的统一信任边界依据。任何改变本文第 3–6 节定义的实现，都必须先按 E0 级流程重新冻结本文。

---

## 1. Purpose and Scope

### 1.1 目的

E1.9-B 已把 E1.9-A 进程内的 `AuthorityJournal` 升级为**独立运行的 Journal Service**（独立进程、独占 DB 与签名私钥、Windows Named Pipe + OS 调用身份校验、服务端 Receipt v2 完整验证、持久化的内容敏感幂等）。随之引入了新的可信组件与新的信任关系。

本文正式回答四个问题，并把答案固定下来：

1. Journal Service 本身哪些部分属于可信计算基（TCB）？→ 第 3 节
2. Windows OS 身份如何映射到 Executor 身份？→ 第 4 节
3. Executor 公钥由谁管理、Journal 如何确定可信公钥？→ 第 5 节
4. 系统初始化、密钥配置、权限配置分别由谁负责？→ 第 6 节

并给出安全保证矩阵（第 7 节）、明确不支持的保证（第 8 节）、E1.9-C 实现约束（第 9 节）与冻结记录（第 10 节）。

### 1.2 范围内 / 范围外

| 范围 | 内容 |
|---|---|
| **范围内（冻结）** | 已实现系统的 TCB 清单、身份映射链、公钥注册表、初始化责任、保证与不保证边界 |
| **范围外（不做）** | 重新设计 Journal Service；新增密码学机制或硬件依赖；提前开展 E1.9-C；修改任何生产代码、测试代码或 E1.8 / B2.2 / E1.9-A / E1.9-B 已冻结文档 |
| **本阶段不重跑全量测试** | 本阶段不修改代码，以现有验收记录（`5853650`：Python 全量 283/283 OK，EXIT=0；Rust `cargo test` 0 failed；`git diff --check` 干净）为依据 |

### 1.3 术语

| 术语 | 含义 |
|---|---|
| **TCB** | Trusted Computing Base，可信计算基；其失陷即系统安全保证失效的组件集合 |
| **Executor** | 调用 Journal Service 追加 INTENT / RESULT 的一方；本系统中按不可信主体对待（进程/账户失陷为 T-B / T-C） |
| **Journal Service** | 独立进程 `journal_service_main.py`，持有签名私钥与权威日志，经 Named Pipe 对外提供六 API |
| **`executor_id`** | Executor 的逻辑身份标识；在请求中是**声明值（claim）**，必须经 OS 调用身份授权映射才成为已认证身份 |
| **fail-closed** | 任一校验失败即拒绝操作、不产生 Entry / Checkpoint，绝不降级为"成功" |
| **G1a / G1b** | G1a＝同一 `operation_id` 至多一个当前有效执行权持有者；G1b＝被保护资源至多一次真实 dispatch（本文明确不保证 G1b） |

---

## 2. System Trust Boundary

### 2.1 组件与信任归属

```text
不可信侧                             可信边界（Journal Service TCB）             排除 / 不设防
--------                             ------------------------------             ------------
Planner / Prover  ──┐
                    │  (不可获得可信执行权限)
Executor 进程(T-B) ─┤
Executor 账户(T-C) ─┴── Named Pipe ──▶ [服务进程 + 专用 OS 账户]
                                          ├─ 固定配置（身份映射 + 公钥注册表）── 由 ADMIN 部署时固定
                                          ├─ 签名私钥（文件 ACL 隔离）──────── 由 ADMIN 生成/保护
                                          ├─ Journal DB + 幂等 DB（ACL 隔离）
                                          └─ Windows OS 安全机制（令牌/ACL/Pipe）
                                                        ▲
                                                        │ 可被联合控制：管理员(T-F)
                                                        │ 可被攻陷：服务自身(T-E)、OS/内核
```

### 2.2 信任根的位置

本系统的信任根完全位于**本机**：Journal 服务账户、签名私钥、固定配置文件、两个 SQLite 数据库与 Windows OS 身份/ACL 机制（B2 设计 §2.1–2.3、§7.5、§10.2；E1.8 §2.2、§10.2）。

**本机范围内不存在"比管理员更可信的外部观察者"**。信任根只能移动、不能消除：要检测管理员级整库回滚，必须引入独立于本机的单调锚点（远程权威服务、外部水印/单调计数、WORM 存储、TPM/HSM），这些**均不在已实现系统内**（B2 §10.2；E1_9_A §1.2 / §7）。

### 2.3 三类攻陷场景（必须区分，不得混用）

| 场景 | 描述 | 本系统立场 |
|---|---|---|
| **A. Executor 进程或账户被攻陷（T-B / T-C）** | 攻击者以 Executor 账户身份运行任意代码、可调用 IPC、读写 Executor 自身文件 | 在 Journal 服务账户、私钥与存储隔离**有效部署**的前提下，独立服务边界旨在**降低** Executor 直接修改 Journal 数据与私钥的能力；这是本系统**主要且可验证的防御目标** |
| **B. Journal Service 本身被攻陷（T-E, B2-R1）** | 服务进程、服务账户或私钥被攻陷；攻击者获得与合法服务相同的 DB 读写 + 私钥读取/重签能力 | Journal Service 是 **TCB**。其进程/账户/私钥失陷即 **TCB 整体失陷**，本机校验无法区分攻击者与合法服务，**不能继续保证 Journal 可信记录**；本系统**不保证** |
| **C. 主机管理员或 OS 管理权限被攻陷（T-F）** | 管理员可控制所有账户、替换二进制、恢复文件与密钥、改 ACL | 能联合控制 Journal 数据库与私钥的管理员可修改、回滚并重新签署数据。**无独立外部锚点时，不得声称能保证检测这种联合回滚**；本机所有验证只检查自洽性与连续性，不检查新鲜度 |

场景 A 成立的任何表述，都不得被外推为场景 B 或 C 的保证。

---

## 3. Journal Service TCB

### 3.1 TCB 组成清单

以下组件共同构成 Journal Service 的 TCB；任一组件失陷，本系统对其声称的安全保证即失效：

| # | TCB 组件 | 实现位置 / 交付形态 | 可信理由与失陷后果 |
|---|---|---|---|
| 1 | **Journal Service 进程** | `src/online_budget/journal_service_main.py`（入口）、`journal_service.py`（核心） | 六 API 的分发与身份→回执→幂等→追加的权威编排均在此执行；进程失陷＝ TCB 失陷（T-E） |
| 2 | **Journal 服务专用 OS 账户** | 由 ADMIN 部署时创建（B2 §4.1 `JRNL_SVC_ACCT`）；配置字段 `journal_service_sid` | 必须区别于 Executor 账户；该账户拥有 DB 读写与私钥读取权，其失陷等同服务失陷 |
| 3 | **Journal 数据库及文件权限** | `journal_db_path`、`idempotency_db_path`；DACL 由 `setup_journal_service_acl.ps1` / `journal_fileacl.restrict_to_sids` 设置 | 权威日志与幂等快索引所在地；ACL 是限制 Executor 直接访问的边界，但**不抵抗管理员取回所有权** |
| 4 | **Journal 签名私钥及 ACL** | `journal_signing_key_b64`（配置）；私钥/配置目录 ACL 由 ADMIN 设置，服务启动期 `verify_private_file` 检查 | 签名链与 Checkpoint 的信任根；私钥泄露或被重签使历史完整性/认证保证失效 |
| 5 | **Named Pipe 服务端身份验证** | `journal_ipc.py`（Pipe + DACL + 帧协议）、`journal_identity.py`（OS 身份获取与鉴权） | 认证依赖 Named Pipe ACL + OS 调用身份；同时是身份映射链的入口（第 4 节） |
| 6 | **Journal 服务配置及可信身份映射** | `journal_service_config.py`（`ServiceConfig`，frozen dataclass） | `os_identity_to_executor_ids` 与 `executor_public_keys` 两张固定注册表是身份与验签的信任根，**运行期无新增/替换 API** |
| 7 | **底层 Windows OS 安全机制** | `ctypes` 调用 `ImpersonateNamedPipeClient` / `OpenThreadToken` / `GetTokenInformation(TokenUser)` / `CreateFileW` / DACL | 令牌获取与 ACL  enforcement 由 OS 提供；OS/内核失陷时本文不提供任何隔离保证 |

### 3.2 "代码强制 / 部署约定 / 未实现"三层区分

为避免把"部署约定"误写成"代码强制"，明确划分：

| 层 | 内容 | 依据 |
|---|---|---|
| **A. 已由代码强制** | ① OS 身份来自 Named Pipe 客户端安全上下文（impersonation + `OpenThreadToken` → `TokenUser`，`journal_identity.py:211-243`），请求体中的 `executor_id` 仅作 claim，必须落在固定映射中（`:302-323`）；② Receipt 公钥来自固定注册表，不接受调用者公钥（`journal_service_config.py:124-136,170-175`）；③ Receipt v2 强制 + 四方绑定 + B-F1 result 双向绑定，任一失败拒绝 append（`journal_receipt_validator.py:84-168`）；④ 内容敏感幂等 `(operation_id, phase)` + `BEGIN IMMEDIATE` + 签名 Journal 回退（`journal_idempotency.py:39-152`）；⑤ 签名链、Checkpoint 与全前缀 `verify_integrity`（`journal.py:246-337,405-416,488-608`）；⑥ 生产入口 `require_os_backed=True`（`journal_service_main.py:101,110`） | 第 4、5 节及各节引用的源码行号 |
| **B. 仅配置/部署约定，代码只做启动检查** | ① 私钥/配置/两个 DB 的 ACL 隔离：真正保护由 ADMIN 用 `setup_journal_service_acl.ps1`（`icacls`）完成；`verify_private_file` 只在启动时检查 DACL 形状；**未配置 `journal_service_sid` 时仅打印警告、不强制**（`journal_service_main.py:86-98`）；② Pipe DACL 只放行 `allowed_client_sids`，SID 是否正确取决于配置；拒绝是 OS 行为（`last_error=5` → `PIPE_ACCESS_DENIED`）；③ 启动期 `verify_integrity` 把"DB 未被就地篡改"当作部署状态的检查，**不是持续防护** | 实施报告 §9 B-F2；`journal_service_main.py:39-61`、`:86-98` |
| **C. 完全没有实现** | ① 密钥轮换 / 撤销 / 按 epoch 或 key_id 选旧公钥的双信任窗口（对 B2 §6.5 全部 grep 无命中；`README.md:145` 亦声明未实现）；② HSM/TPM、经认证的管理平面、抗回滚锚点；③ 真实多账户 ACL 拒绝的验收测试（环境依赖，未冒充通过）；④ Executor 完整集成与恢复状态机 | B2 §6.5 / §10.1；实施报告 §7、`README.md:145` |

**冻结论**：本系统的安全保证以"ADMIN 正确执行了 B 层部署约定，且 A 层代码强制生效"为前提。B 层未被正确部署时（例如 `journal_service_sid` 未配置），服务会明确警告但**仍可启动**——这不构成对隔离边界的保证。

### 3.3 完整性与抗回滚的区分（不可混用）

- **完整性（integrity）**：由 E1.9-A 签名链 + 逐条/逐 Checkpoint 签名 + 全前缀 `verify_integrity`（含辅助列与签名对象交叉校验）提供；可检测**就地篡改**与同序号检查点摘要不符。**已具备**。
- **回滚检测（rollback detection）**：仅对 **Executor 账户级回滚**具备（该账户碰不到 DB 与私钥）；对**管理员级（T-F）DB+密钥联合回滚**与 **TCB 自身（T-E）失陷**级 **不具备**——旧 DB + 旧密钥 + 旧签名三者自洽，本机验证只查自洽性不查新鲜度。**明确不保证**。
- **回滚阻止（rollback prevention）**：对 Executor 账户级具备（ACL 阻断）；管理员级与 T-E 级**不具备**。

不得把"哈希链完整性 / 签名自洽"描述为"抗回滚能力"（B2 §8.3）。

---

## 4. Executor Identity Binding

### 4.1 完整映射链

```text
Windows OS Identity  ──▶  executor_id  ──▶  Executor Public Key
  (OS 令牌 SID/account)     (声明值 claim，      (固定注册表 executor_public_keys，
   由 impersonation 取得)    须经授权映射)        供 Receipt v2 验签)
```

三段映射逐一冻结：

**第一段 — Windows OS Identity 的取得**：服务端在每次连接上通过 Named Pipe 客户端安全上下文取得调用者 OS 身份（`CallerIdentity(sid, account, via, is_os_backed)`）：

- **生产路径**：`ImpersonateNamedPipeClient(pipe_handle)` → `OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, True, ...)` → `GetTokenInformation(TokenUser)`，`via="WIN32_NAMED_PIPE_IMPERSONATION"`（`journal_identity.py:211-243,149-168`）。客户端 `CreateFileW` 显式携带 `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`（`journal_ipc.py:200-205,649-656`），否则令牌为匿名、`ImpersonateNamedPipeClient` 因 error 1368 失败。
- **生产强制**：独立进程入口 `JournalService(config, require_os_backed=True)` 且 `NamedPipeServer` 默认 `identity_mode="impersonation"`（`journal_service_main.py:101,106-111`；`journal_ipc.py:488-500`）。
- **服务端先鉴权后工作**：`provider.authenticate()` → `authorizer.authorize_read(caller)` 在读请求体之前执行（`journal_ipc.py:595-601`）。

**第二段 — OS 身份 → executor_id 授权映射**：由固定配置 `os_identity_to_executor_ids: Mapping[str, frozenset[str]]` 定义（`journal_service_config.py:50,111-122`），支持一个 OS 身份对应一个或一组允许的 `executor_id`。单点鉴权 `IdentityAuthorizer.authorize()`（`journal_identity.py:302-323`）执行：

1. 生产路径拒绝非 OS-backed 身份（`StaticIdentityProvider` 标记 `is_os_backed=False`，直接拒绝）；
2. 请求中的 `executor_id` 必须是非空字符串，且必须落在该 OS 身份的允许集合中——**声明值不等于已认证身份**；
3. 强制该 `executor_id` 在公钥注册表中有固定公钥，否则拒绝（fail-closed）；
4. 返回已认证的 `executor_id`，INTENT 阶段再核对 envelope 的 `executor_id` 与该值一致（`journal_service.py:157-161`，否则 `EXECUTOR_ID_MISMATCH`）。

映射由 ADMIN 在部署时固定；配置校验拒绝"身份映射引用了无公钥的 executor_id"（`journal_service_config.py:138-142`）。运行期**不接受客户端新增/替换映射请求**。

**第三段 — executor_id → Executor Public Key**：见第 5 节。

### 4.2 生产身份路径 vs 测试回退路径（必须区分）

| 项目 | 生产路径（安全边界） | 测试回退路径（非安全边界） |
|---|---|---|
| `identity_mode` | `"impersonation"`（默认，生产入口恒用） | `"pid_test_only"`（显式声明，仅同进程自测） |
| OS 身份来源 | `ImpersonateNamedPipeClient` → 线程令牌 → Named Pipe 客户端安全上下文 | `GetNamedPipeClientProcessId` → 进程主令牌 |
| `via` 标记 | `WIN32_NAMED_PIPE_IMPERSONATION` | `WIN32_PIPE_CLIENT_PID` |
| 代码位置 | `journal_identity.py:211-243`；`journal_ipc.py:526-529` `_provider_for` 分流 | `journal_identity.py:171-208`；`journal_ipc.py:480-485` |
| 是否 OS-backed | 是 | 是（但服务端仅在显式测试模式下选用） |
| 定位 | **生产安全边界** | **TEST-ONLY fallback**：因同进程无法 impersonation（error 1368）而存在；生产构造即为部署错误，独立进程入口永不选择（`journal_ipc.py:12-17`） |

另有 `StaticIdentityProvider`（`journal_identity.py:255-268`，`is_os_backed=False`，`via="TEST_SIMULATED"`）只用于单元测试注入，生产 `require_os_backed=True` 时直接拒绝。

**冻结声明**：不得把 PID 测试回退路径或 `StaticIdentityProvider` 描述为生产安全边界。生产系统的身份保证仅来自 impersonation 路径 + OS 身份授权映射的组合。测试 P10 断言真实管道下 `caller.via == "WIN32_NAMED_PIPE_IMPERSONATION"`（`test_e1_9_b_ipc.py:152-197`），I07 断言生产默认模式与 provider 选择（`test_e1_9_b_identity.py:101-107`）。

### 4.3 身份不匹配的 fail-closed 处理

| 场景 | 异常 / 错误码 | 位置 |
|---|---|---|
| 未映射的 OS 身份 | `CallerIdentityError`："no executor_id mapping for OS identity …" | `journal_identity.py:312-313` |
| claim 的 `executor_id` 不在允许集 | `CallerIdentityError`："not authorised for OS identity …" | `journal_identity.py:314-317` |
| claim 的 `executor_id` 无注册公钥 | `CallerIdentityError`（由 `ServiceConfigError` 转换） | `journal_identity.py:318-322` |
| INTENT envelope `executor_id` ≠ 已认证值 | `ServiceError("EXECUTOR_ID_MISMATCH", …)` | `journal_service.py:157-161` |
| Receipt `executor_id` ≠ INTENT `executor_id` | `ReceiptValidationError("EXECUTOR_ID_MISMATCH", …)` | `journal_receipt_validator.py:129-133` |
| 身份映射引用无公钥的 executor（配置期） | `ServiceConfigError` | `journal_service_config.py:138-142` |

以上任一失败均在追加前拒绝、不产生 Entry / Checkpoint，并经 IPC 层返回结构化错误（`journal_ipc.py:125-142`，异常路径绝不返回成功）。

---

## 5. Executor Public-Key Registry

### 5.1 固定映射关系

- **映射**：`executor_public_keys: Mapping[str, Ed25519PublicKey]`，由 `executor_public_keys` 配置项（JSON `dict[str, base64-pubkey]`）解析，`public_key_from_b64` 转换为 Ed25519 公钥对象（`journal_service_config.py:51,124-136`）。
- **配置/维护主体**：由 **Journal 管理员（ADMIN）** 在部署时初始化并固定指纹，语义与 B2 §6.4 公钥注册表一致。**Journal 管理员负责维护此映射**；Executor 方只持有对应私钥，不参与注册表的写入。
- **运行期不可变**：`ServiceConfig` 是 `@dataclass(frozen=True)`（`journal_service_config.py:40-41`）；注册表在进程生命周期内固定，**没有运行期新增、替换或上传公钥/身份映射的 API**——调用者无法夹带自己的公钥（`:11-15`）。

### 5.2 Journal 如何确定可信公钥

服务端追加 RESULT 时的选键与验签流程（`journal_service.py:183-211`；`journal_receipt_validator.py`）：

1. 从**签名 Journal** 按 `operation_id` 取回权威 INTENT（`_signed_intent_for`，`journal_service.py:184-191`），得到 `intent_executor_id` 与 `intent_binding_digest`——不信任客户端提供的 INTENT 内容；
2. 比对已认证 `executor_id` == `intent_executor_id`（否则 `EXECUTOR_ID_MISMATCH`）；
3. 用 `self._config.public_key_for(executor_id)` 从**固定注册表**取公钥（`:193`；未注册即 `ServiceConfigError`）；
4. `validate_result_receipt(...)` 以该公钥验签，并叠加 expected-map（executor_id / operation_id / binding_digest）做纵深防御（`journal_receipt_validator.py:151-168`）。

**冻结论**：验签公钥的唯一来源是固定注册表。**Journal 不允许调用者自行提供公钥**，也不接受公钥替换请求。

### 5.3 Receipt v2 的身份与绑定校验（冻结项）

Receipt 由 **Executor 私钥**签名（即 D10 `ExecutionReceipt` v2，E1.5 生成），服务端在追加 RESULT 前必须全部通过（`journal_receipt_validator.py:84-168`）：

| 校验 | 失败码 |
|---|---|
| `receipt_version == 2` 强制（拒 v1、拒缺失/非整数；在通用验证器之前执行） | `RECEIPT_VERSION_MISSING` / `RECEIPT_VERSION_UNSUPPORTED` |
| 精确 v2 字段集 `RECEIPT_FIELDS_V2` | `RECEIPT_FIELDS` |
| `result_digest` 按冻结规则重算：`digest({"domain":"agent-tool-result-v1","result":…})` | `RESULT_DIGEST_MISMATCH` |
| **B-F1**：`Receipt.result == envelope.result` | `RESULT_ENVELOPE_MISMATCH` |
| **B-F1**：envelope result 重算摘要 == Receipt `result_digest` | `ENVELOPE_RESULT_DIGEST_MISMATCH` |
| Receipt `executor_id` == INTENT `executor_id` | `EXECUTOR_ID_MISMATCH` |
| Receipt `operation_id` == RESULT envelope `operation_id` | `OPERATION_ID_MISMATCH` |
| Receipt `binding_digest` == envelope `binding_digest` == INTENT `binding_digest` | `BINDING_DIGEST_MISMATCH` / `INTENT_BINDING_MISMATCH` |
| 固定公钥验签 + expected-map 纵深防御 | `RECEIPT_SIGNATURE` |

任一失败 → 拒绝追加 RESULT（结构化错误 + fail-closed），不产生 Entry / Checkpoint。

### 5.4 证据边界（必须显式声明）

Receipt 由不可信 Executor 自签。服务端验签**只能证明**：该回执由登记的 Executor 密钥签发、字段自洽、与 INTENT / RESULT 绑定一致。**不能证明**工具真的执行过、`result` 反映真实执行输出、对应真实授权/真实资源消耗——持 Executor 私钥的攻击者可签出满足全部检查的伪造回执（B2 §5.4.2 / §8.1；`journal_receipt_validator.py:28-33`）。

同理，Journal 签名只证明服务在某个权威 seq 处**接收并记录了**某 envelope 内容、该条目自签发后未被就地改写；**"Journal 可信历史" ≠ "可信执行历史"**（B2 §5.4.1）。

### 5.5 未实现的能力（明确标记，不得补充为现有能力）

- **密钥轮换**：未实现。B2 §6.5 只给出目标设计（双信任窗口、按 epoch / key id 验旧条目），代码中无 `rotate` / `epoch` / `key_id` 等任何实现；README 亦声明 production-grade rotation 未实现。
- **撤销 / 吊销**：未实现。无撤销列表、无运行期撤除公钥信任的机制。
- **轮换事件是否记入日志、如何防止"借轮换掩盖回滚"**：B2 §6.5 明确记录为**未决问题**，本文保持一致，不自行决定。

---

## 6. Initialization and Operational Responsibilities

### 6.1 责任主体清单

| 操作 | 责任主体 | 性质 | 依据 / 现状 |
|---|---|---|---|
| 创建 Journal Service 账户（`JRNL_SVC_ACCT`） | **部署管理员（ADMIN）** | 管理员人工 | B2 §4.1；代码不创建账户 |
| 创建 Executor 运行账户（`EXEC_ACCT`） | **部署管理员（ADMIN）** | 管理员人工 | 实施报告 §6 命令 1 |
| 创建 Journal 数据目录（ConfigDir / StateDir） | **部署管理员（ADMIN）** | 管理员人工 | B2 §4.4；`setup_journal_service_acl.ps1:50-61` |
| 生成和保护 Journal 签名私钥 | **Journal 管理员 / 部署流程（ADMIN）** | 部署脚本 | B2 §6.1；`create_journal_service_config.py` 生成/导入密钥，私钥不落入 Executor 可读路径 |
| 创建 Executor 身份与密钥 | **Executor 管理责任方** | 外部责任 | Executor 私钥不在本仓库生成；本系统只接收公钥 |
| 配置 `executor_id → 公钥` 映射 | **Journal 管理员（ADMIN）** | 部署脚本 + 管理员 | `create_journal_service_config.py:88`；写入配置并校验指纹，运行期不可变 |
| 配置 OS 身份授权映射（`os_identity_to_executor_ids`） | **Journal 管理员（ADMIN）** | 部署脚本 + 管理员 | `create_journal_service_config.py:87`；与公钥映射同信任级别 |
| 设置 Named Pipe 与文件 ACL | **部署管理员（ADMIN）** | 部署脚本 | `journal_ipc._build_dacl` 按 `allowed_client_sids` 写 Pipe ACL；`setup_journal_service_acl.ps1` 收紧文件/目录 ACL |
| 服务启动时检查权限和配置 | **Journal Service（代码自动）** | 代码 | 见 6.2 |

**责任无空缺**：每一项均有明确主体。需强调：Executor 管理责任方只负责自身身份与密钥，注册表与授权映射的配置权专属于 Journal 管理员；Executor 方不能自行注册公钥或映射。

### 6.2 服务启动期自动检查（代码执行）

`journal_service_main.py` 启动序列：

1. 加载配置 `ServiceConfig.from_dict`（`:33-36,79`）；配置/JSON/OSError 失败 → 退出码 2（`:80-82`）；
2. 私钥/配置/DB 文件 ACL 自检 `_verify_private_file_acl → verify_private_file`（`:39-61`）：配置私钥 seed 禁 Executor 读、两个 DB（或首次启动时其父目录）禁 Executor 写；违规 → 拒绝启动、退出码 3（`:86-91`）；**未配置 `journal_service_sid` 时打印醒目警告、不强制**（`:92-98`）；
3. 私钥与验签公钥解析无效 → `ServiceStartupError`（`journal_service.py:89-103`）；
4. 全前缀 `journal.verify_integrity()`，失败 → 拒绝启动、`ServiceStartupError`（`journal_service.py:106-112`）；
5. 以 `require_os_backed=True` 启动 Named Pipe 服务（`:101,106-111`）；
6. `--print-sid` 辅助：仅输出当前进程 SID/account 供 ADMIN 建 ACL 使用（`:70-73`）。

### 6.3 代码未提供 / 未自动化的部分

- 账户创建、目录创建、ACL 实际设置、公钥/映射初始化与指纹固定：**均需 ADMIN 按部署脚本与人工命令完成**（实施报告 §6）。
- **没有完整的初始化向导或密钥轮换 / 撤销流程**；配置未填 ACL SID 时服务只警告不阻断，隔离边界是否生效取决于 ADMIN 是否完成部署。
- **权限审计**（定期核对 ACL 未被放宽）在 B2 §4.4 仅列为运维要求，**未实现自动检测**。
- **真实跨账户 ACL 拒绝**（未授权 OS 账户连接被 OS 拒绝，`last_error=5`）与真实第二账户对私钥/DB 的拒绝读取/写入：**未实测**，为管理员环境依赖；实施报告只验证了"当前账户"允许路径与真实 Win32 ACL API 的 apply→read→verify 闭环，未用模拟结果冒充通过。

---

## 7. Security Guarantee Matrix

> 表中"保证"均以 **TCB 未被攻陷（场景 B/C 不成立）且 ADMIN 正确完成 B 层部署约定**为前提。

| 攻击者能力 | 当前系统保证 | 依据 / 边界 |
|---|---|---|
| 普通不可信 Planner | 不得直接获得可信执行权限；所有 Journal 访问须经 Named Pipe + OS 身份授权映射 | 第 4 节；请求 `executor_id` 仅为 claim |
| Executor 进程被攻陷（T-B） | 在 OS 账户与 ACL 隔离有效时，限制其直接修改 Journal 数据（DB/私钥 ACL）与伪造他人身份/签名的能力；可调用 IPC 但受身份映射约束 | B2 §2.3；`journal_fileacl.py`；**前提是隔离已正确部署** |
| Executor 运行账户被攻陷（T-C） | 同上；无法读到私钥、无法回滚历史、无法伪造权威 seq/链头 | B2 §2.3；ACL 阻断 |
| Executor 私钥泄露 | 可伪造该 Executor 的签名声明（自签回执）；**不能证明实际执行**——验签不验证执行真实性 | 第 5.4 节；B2 §5.4.2 |
| Journal Service 被攻陷（T-E） | **Journal TCB 失效**；进程/账户/私钥失陷后攻击者拥有合法服务能力，本机校验无法区分 | 第 2.3 节场景 B；B2-R1 |
| 主机管理员联合控制 DB 和私钥（T-F） | **不保证能够检测联合回滚**；旧 DB+旧密钥+旧签名自洽，本机只查自洽不查新鲜度 | 第 2.3 节场景 C；B2 §7.5 / §10.2 |
| OS / 内核被攻陷 | **不提供可信隔离保证**；TCB 依赖的 OS 令牌与 ACL 机制本身不可信 | B2 §2.1；本系统不设防 |
| Journal 数据库局部篡改（就地改写） | 可检测：签名链、逐条/逐 Checkpoint 签名、全前缀 `verify_integrity`、辅助列与签名对象交叉校验；启动期 fail-closed | `journal.py:488-608`；实施报告 §4"启动完整性门禁" |
| 相同 `(operation_id, phase)` 并发 / 重放 | 内容敏感幂等 + `BEGIN IMMEDIATE` 串行化；相同键不同 payload → `IDEMPOTENCY_CONFLICT`；签名 Journal 回退避免重复 Entry | `journal_idempotency.py`；`journal_service.py:213-260`；B2-R3 |
| 外部工具副作用重复执行 | **不提供通用 G1b 保证**；A1 共享执行状态的事务串行化只给并发串行化，不能称 at-most-once dispatch | 第 8 节；E1.8 §1.1 / §5.3 |

### 7.1 五条强制注意事项（不得违反）

1. Journal 签名只能证明服务记录了某项内容，**不等于**证明工具确实执行了对应操作。
2. Receipt v2 的签名、结果一致性与 binding 校验**不能**被表述为执行真实性证明。
3. A1 共享 ExecutionStore 的事务串行化**不能**被表述为全局 at-most-once dispatch。
4. E1.9-B 的独立服务部署边界**不等于**抵御主机管理员攻击。
5. 工程测试通过（283/283）**不能**被表述为形式化安全证明。

---

## 8. Explicitly Unsupported Guarantees

以下保证本系统**明确不提供**，禁止在任何下游文档或汇报中出现为"已具备"：

| # | 不支持的保证 | 原因 / 依据 |
|---|---|---|
| 1 | G1b：至多一次真实 dispatch | dispatch 与 commit 非原子，崩溃窗口下可二次 dispatch（E1.7 T03 实测）；本系统不做 A2 执行权授权服务、不做工具端 fencing 校验；E1.8 §1.1 / §5.3 |
| 2 | 完整 G1a 执行权保证 | E1.9 实现计划只声称 A1 共享存储层并发串行化，不声称完整 G1a；本阶段未接入 A1 锁生命周期（E1_9_A §7；E1.9 §1.1） |
| 3 | 外部工具（含外部 API）副作用的 exactly-once | 需 A3 工具端幂等接口，不在范围（E1.8 §10.2；E1.9 §1.3） |
| 4 | 检测 / 阻止管理员级 DB+密钥联合回滚 | 无外部单调锚点，信任根只能移动不能消除（B2 §7.5 / §10.2） |
| 5 | Journal TCB 自身（T-E）失陷后的历史可信 | 服务进程本就有权读写 DB 与读取私钥；其失陷即 TCB 失陷（B2-R1） |
| 6 | 执行真实性 / result 真实性 / 物理资源消耗真实性 | Receipt 由 Executor 自签；Attestation 只证按策略签发费用（B2 §5.4.2；E1.0 边界） |
| 7 | 跨 Executor / 抗状态回滚的全局防重放 | 与 E1.7 边界一致：幂等仅在共享库内成立（E1.7 T03） |
| 8 | 密钥轮换 / 撤销 / 按 epoch 验旧条目 | 未实现；B2 §6.5 只给目标设计并列为未决问题（§5.5） |
| 9 | HSM / TPM / 硬件不可导出密钥 / 抗回滚锚点 | 未实现，明确排除（B2 §1.3 / §6.2；README） |
| 10 | 经认证的管理平面；真实多账户 ACL 拒绝实测 | 前者未实现；后者为管理员环境依赖，未冒充通过（实施报告 §6 / §7） |
| 11 | 独立服务边界抵御管理员或 OS 级攻击 | 账户隔离 ≠ 管理员级防回滚；软件 ACL ≠ 硬件不可导出（B2 §8.3） |
| 12 | 形式化安全证明 / 可直接部署的完整系统 | 工程测试通过不等于形式化证明（B2 §8.3 / §11.2；E1.8 §10.2） |

---

## 9. E1.9-C Implementation Constraints

E1.9-C（Executor 集成与恢复验收）必须在本节约束下实施；任何偏离都需先按 E0 级流程重新冻结本文。

### 9.1 身份与公钥（不得改变信任根）

1. 生产身份路径必须保持 `identity_mode="impersonation"` + OS-backed 强制；**不得**把 PID 测试路径或静态身份用于生产，也不得通过配置开关将其变为生产默认。
2. 请求中的 `executor_id` 始终按**声明值**处理，必须经 `IdentityAuthorizer` 的固定 OS 身份授权映射；不得允许运行期新增/替换映射，不得允许客户端自带公钥或请求公钥替换。
3. Receipt v2 强制校验（版本、字段集、四方绑定、B-F1 result 双向绑定、固定注册表验签）必须保留；**不得**退回通用 v1/v2 验证入口，不得在身份不匹配时放行。
4. 本冻结版本不含轮换/撤销；E1.9-C **不得**擅自引入 epoch/key_id/双信任窗口，若需要须先作为新信任假设冻结。

### 9.2 Journal 与回执（不得夸大证据）

5. 服务层新增逻辑（内容敏感幂等、Receipt 校验）相对冻结核心 `journal.py`（保持 `914eb42` 语义）的衔接点不得回退；E1.9-A 的签名链、Checkpoint、辅助列交叉校验与全前缀 `verify_integrity` 不得修改。
6. 恢复时必须取回**原始签发回执对象**并验签，禁止用 `make_receipt` 之类重建；原始回执不可恢复即 fail-closed（E1.8 §5.2；E1.9 §1.2 / §7）。
7. 编码与域标签以**实际冻结代码为准**：`journal.py:87-96` 定义 `e1-journal-intent-v1`（INTENT，实际冻结名）、`e1-result-envelope-v1`、`e1-journal-entry-v1`、`e1-journal-entry-sign-v1`、`e1-journal-checkpoint-v1`、`e1-journal-checkpoint-sign-v1`、`e1-journal-genesis-v1`。实施计划曾列候选名 `e1-intent-envelope-v1`，**未被采用**，不得在下游文档中当作现行域标签。
8. 不得把 Journal 记录、Receipt 验签或结果一致性检查表述为执行真实性证明；不把幂等/串行化表述为 G1a/G1b。

### 9.3 部署与运维（不得放松边界）

9. 私钥/配置/DB 的 ACL 隔离与 `journal_service_sid` / `executor_account_sids` 配置必须作为 E1.9-C 部署前置条件；未配置时服务只警告不强制，**集成验收不得在"仅警告"状态下宣称隔离边界已生效**。
10. 真实多账户 ACL 拒绝（Pipe 与文件）为管理员环境依赖；E1.9-C 若要声称该路径通过，必须由管理员建真实第二账户实测，不得用模拟身份或当前账户代替。
11. 权限审计自动化、完整初始化向导、密钥轮换、远程权威/单调锚点/HSM/TPM 均不在 E1.9-C 范围；如需引入，按新信任假设走 E0 冻结。

### 9.4 集成验收的证据口径

12. 集成验收报告必须同时声明三条诚实边界：① 管理员级 DB+密钥联合回滚无法检测；② T-E / TCB 失陷不保证；③ Journal 不证明执行真实性。缺一即不完整。
13. 工程测试（含 283/283 全量回归）只作为实现一致性的证据，不作为形式化安全证明。

---

## 10. Freeze Record

### 10.1 冻结基线

| 项目 | 值 |
|---|---|
| 阶段 | E0 Trust Assumptions Freeze |
| 冻结时 HEAD | `5853650`（`fix(e1.9-b): align deploy-script DENY ACE with startup ACL check`） |
| B2.2 设计冻结 | `3967100` |
| E1.9-B 主体 | `e689f7d`；B-F 收尾 `a17ff10`；ACL 回修 `5853650` |
| E1.8 / E1.9-A | 已冻结（A.3 冻结核心 `journal.py` 保持 `914eb42` 语义） |
| 全量测试依据 | Python 283/283 OK，EXIT=0（526.57s，含真实 Windows）；Rust `cargo test` 0 failed；`git diff --check` 干净 |
| 本项目新增文件 | `docs/E0_TRUST_ASSUMPTIONS_FREEZE.md`（本文）；未修改任何代码、测试或已冻结文档 |

### 10.2 与实际代码核对的文件及位置

| 核对主题 | 文件与位置 |
|---|---|
| 生产 OS 身份（impersonation） | `src/online_budget/journal_identity.py:211-243`（`identity_from_impersonated_pipe`）、`:149-168`（`_identity_from_token`） |
| 测试身份回退（PID / 静态） | `journal_identity.py:171-208`（`identity_from_pipe_client_pid`）、`:255-268`（`StaticIdentityProvider`） |
| 身份模式分流与安全默认值 | `journal_ipc.py:488-500`（`identity_mode`）、`:526-529`（`_provider_for`）、`:595-601`（先鉴权后工作） |
| 客户端 SQOS（error 1368 根因） | `journal_ipc.py:200-205`、`:649-656` |
| OS 身份 → executor_id 授权映射 | `journal_identity.py:302-323`（`IdentityAuthorizer.authorize`）；`journal_service_config.py:50,111-122,138-142` |
| 公钥注册表（固定、不可变） | `journal_service_config.py:40-55,124-136,170-175`；`scripts/create_journal_service_config.py:88` |
| Receipt v2 强制与四方绑定 | `journal_receipt_validator.py:84-168`；`journal_service.py:183-211` |
| B-F1 result 双向绑定 | `journal_receipt_validator.py:108-127`；错误码 `RESULT_ENVELOPE_MISMATCH` / `ENVELOPE_RESULT_DIGEST_MISMATCH` |
| 文件 ACL（主体白名单 / 预期 DENY） | `journal_fileacl.py:74-97`（位常量与 SID）、`:274-356`（`dacl_problems`）、`:360-383`（`verify_private_file`）、`:386-448`（`restrict_to_sids`） |
| 启动期 ACL 自检与警告 | `journal_service_main.py:39-61`（`_verify_private_file_acl`）、`:79-104`（启动序列） |
| 目录 ACL 部署脚本 | `scripts/setup_journal_service_acl.ps1:42-61`（SID 解析、`icacls` grant/deny；主体：服务 SID、`S-1-5-18`、`S-1-5-32-544` allow，Executor SID deny `(OI)(CI)(RX,D,W)`） |
| 签名链 / Checkpoint / 完整性 | `journal.py:246-337`（`append`）、`:405-416`（checkpoint）、`:488-608`（`_verify_entry` / `_verify_checkpoint` / `verify_integrity`）、`:87-96`（域标签） |
| 幂等（内容敏感 + BEGIN IMMEDIATE） | `journal_idempotency.py:39-152`；`journal_service.py:213-260` |
| 冻结设计依据 | `docs/E1.8_EXECUTOR_GLOBAL_REPLAY_AND_ANTI_ROLLBACK_DESIGN.md` §1.1/§2.2/§5/§8/§10；`docs/E1.9_B2_INDEPENDENT_TRUST_DOMAIN_DESIGN.md` §2/§4/§5.3/§5.4.2/§6/§7.5/§8/§10；`docs/E1_9_A_JOURNAL_FOUNDATION.md` §1.2/§3/§7；`docs/E1.9_IMPLEMENTATION_PLAN.md` §1/§2；`docs/E1.9_B_IMPLEMENTATION_REPORT.md` §2/§3/§4/§7/§9 |

> 一致性消歧（写入冻结记录以防下游误引）：
> ① INTENT 域标签以实际代码 `e1-journal-intent-v1`（`journal.py:88`）为准，实施计划中的候选名 `e1-intent-envelope-v1` 未被采用。
> ② `scripts/setup_journal_service_acl.ps1:72-73` 注释提到的 `journal_fileacl.verify_private_files()`（复数）在代码中不存在，实际为 `verify_private_file`（单数），由 `journal_service_main.py` 的 `_verify_private_file_acl` 调用。
> ③ 部署脚本 DENY 掩码为 `(OI)(CI)(RX,D,W)`，对应 `deny_mask = FILE_GENERIC_READ|WRITE|EXECUTE|DELETE`；Python 侧 DENY 强度判定用不重叠的 `FILE_READ_DATA`/`FILE_WRITE_DATA` + generic 位（`_DENY_READ_BITS` / `_DENY_WRITE_BITS`），避免 READ-only DENY 被误判为覆盖 WRITE。

### 10.3 未实现能力与不保证事项（汇总）

- **未实现**：密钥轮换/撤销/epoch 验旧条目；HSM/TPM/硬件不可导出密钥；经认证管理平面；远程权威/单调锚点；权限审计自动化；完整初始化向导；真实多账户 ACL 拒绝实测；Executor 完整集成与恢复状态机。
- **不保证**：G1b（至多一次真实 dispatch）、完整 G1a、外部工具副作用 exactly-once、管理员级联合回滚可检测/可阻止、TCB 自身失陷后的历史可信、执行真实性、跨 Executor/抗回滚全局防重放、形式化安全证明。
- **环境依赖（未冒充通过）**：真实第二 Windows 账户对 Pipe 连接与私钥/DB 的 ACL 拒绝。

### 10.4 验收清单（本任务包第七节逐条）

| # | 验收项 | 结果 |
|---|---|---|
| 1 | 四项信任假设均有明确、可执行的定义 | ✅ 第 3–6 节 |
| 2 | 描述与 E1.9-B 实际代码一致 | ✅ 第 10.2 节逐文件行号核对，含 3 处消歧 |
| 3 | 生产身份路径与测试回退路径明确区分 | ✅ 第 4.2 节对照表 |
| 4 | Executor 身份与公钥映射不存在责任主体空缺 | ✅ 第 6.1 节责任表 |
| 5 | Journal 私钥与 Executor 权限边界明确 | ✅ 第 3.1 / 3.2 / 6.1 节 |
| 6 | 管理员联合回滚限制明确 | ✅ 第 2.3 场景 C / 3.3 / 7 / 8 |
| 7 | Journal 记录与真实执行之间的证据边界明确 | ✅ 第 5.4 / 7.1 / 8(6) 节 |
| 8 | G1a/G1b 保证边界没有被夸大 | ✅ 第 7 矩阵 / 8(1)(2) / 9.4 |
| 9 | E1.9-C 后续约束清楚 | ✅ 第 9 节 13 条 |
| 10 | 没有修改任何冻结代码或文档 | ✅ 仅新增本文；`git status` 见汇报 |

### 10.5 冻结声明

本文固定的是**已实现系统的信任假设**，不是对新能力的授权。E0 阶段到此完成；E1.9-C 须在第 9 节约束下实施，并在其验收报告中逐条声明第 9.4 节的三条诚实边界。对本文任何修改都必须以新的 E0 级冻结提交记录，不得原地覆盖本冻结版本。
