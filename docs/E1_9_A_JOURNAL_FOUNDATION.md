# E1.9-A — Journal Foundation 验收报告

> 基线：E1.9 冻结设计 `5c5c641`；依据 E1.8 §5.2 / §7.1 / §7.4 / §2.2 与 E1.9 §2.3 / §2.4。
> 本阶段只建立独立权威 Journal 自身，**不接入** `TrustedToolExecutor`，不改执行流程/门禁/凭据。
> 结论先行：Journal 核心组件（追加、签名链、检查点、恢复、完整性验证、物理/密钥分离）已实现并通过 J01–J10；
> **但"独立文件 + 独立密钥"不等于已实现 B2 抗回滚**，信任边界阻碍与可行方案见第 7 节，必须如实阅读。

## 1. 信任边界与部署架构

### 1.1 本原型已建立（可在本机验证）
- **组件隔离**：`AuthorityJournal` 是全新独立模块，只操作调用方注入的 `journal_path`（独立 SQLite 文件），
  不导入、不打开、不修改 `executions` 库；不改 `executor.py` / `execution_store.py` 的执行流程。
- **独立签名密钥**：Journal 使用自己的一对 Ed25519 权威密钥（`signing_key` / `verify_key`），
  与 D10 授权、D11 预算、E1 计量、Execution Receipt 的密钥体系均不共用。
- **密码学完整性**：全局连续 `seq`、`prev_digest` 链、逐条 `entry_signature`、逐检查点
  `checkpoint_signature`、按序号历史检查点、全前缀恢复校验（J03/J05/J06/J07/J08）。
- **可检测**：日志条目或检查点被就地改写、中间记录被删除/替换、序号断裂、INTENT/RESULT 顺序异常、
  签名无效——全部 fail-closed（抛 `JournalIntegrityError`）。

### 1.2 本原型未建立（不得据此声称）
- **不能证明"Journal 自身不可被回滚"**：在本单机环境中，Journal 文件与 Executor DB 处于同一文件系统、
  同一 OS 主体、同一备份/快照域。一个能够恢复 Executor DB 旧快照的攻击者，同样能整体替换该 Journal 文件。
  单独再放一个文件、再配一把密钥，**并不能从系统层面阻止这一点**——旧文件连同当时有效的旧签名一起被换回后，
  本组件的全部验证仍会通过（因为验证只检查链与签名自洽，不检查"是否当前最新"）。
- J10 只证明"恢复 Executor 旧 DB 快照这一操作本身不会改变 Journal 文件"（物理分离），
  **不构成**"Journal 抗回滚"的证据。
- 因此本阶段交付的是**权威日志核心组件 + 完整性验证能力**，**不是**已完成的可部署 B2；
  E1.8 §2.2 的信任假设（"独立可信 Append-only Journal，追加写不可被攻击者回滚"）在此环境中**尚未落实为独立信任域**。

## 2. 新增及修改文件清单

| 文件 | 类型 | 说明 |
|---|---|---|
| `src/online_budget/journal.py` | 新增 | 权威 Journal 核心组件（约 380 行） |
| `tests/test_e1_journal.py` | 新增 | J01–J10 及负向测试（12 个用例） |
| `docs/E1_9_A_JOURNAL_FOUNDATION.md` | 新增 | 本验收报告 |

未修改：`executor.py`、`execution_store.py`、`e1_runtime.py`、`cross_layer_bridge.py`、`e1_receipts.py`、
任何 D10/D11 源文件、任何 E1.5 门禁代码、E1.8 冻结文档、Rust crate。

## 3. 精确编码与签名规范（E1.9-A 冻结）

摘要/签名原语全部复用冻结的 `canonical.py` / `e1_encoding.py`：
- `canonical_digest(domain, payload) = "sha256:" + sha256(canonical_json_bytes({"domain": domain, "payload": payload}))`
- `canonical_json_bytes` = `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`（UTF-8）
- `verify_signature(key, sig_b64, payload)` = Ed25519(标准 Base64) over `canonical_json_bytes(payload)`

新增域标签（E1.9-A 冻结，均为新增、不改动 E1.1–E1.6 已冻结域前缀）：

| 域标签 | 用途 |
|---|---|
| `e1-journal-genesis-v1` | 创世 `prev_digest` = `canonical_digest("e1-journal-genesis-v1", {})` |
| `e1-journal-intent-v1` | INTENT `payload_digest` 承诺对象 |
| `e1-result-envelope-v1` | RESULT `payload_digest`（域标签见 E1.8 §5.2，本阶段固定其编码） |
| `e1-journal-entry-v1` | `entry_digest` |
| `e1-journal-entry-sign-v1` | `entry_signature` 签名消息 |
| `e1-journal-checkpoint-v1` | `checkpoint_digest` |
| `e1-journal-checkpoint-sign-v1` | `checkpoint_signature` 签名消息 |

**JournalEntry 字段（精确集）**：
`seq`(int, 从 1 连续)、`prev_digest`(sha256)、`operation_id`、`phase`∈{INTENT,RESULT}、
`executor_id`、`envelope`(对象)、`payload_digest`(sha256)、`entry_digest`(sha256)、`entry_signature`(b64 Ed25519)。

- INTENT `envelope` = `{operation_id, binding_digest, executor_id}`（精确三字段）
- RESULT `envelope` = `{operation_id, binding_digest, result, execution_receipt}`（E1.8 §5.2 四字段，精确集）
- `payload_digest` = `canonical_digest(对应域, envelope)`
- `unsigned_entry` = `{seq, prev_digest, operation_id, phase, executor_id, payload_digest}`
  （**不含** `entry_digest`/`entry_signature`/`envelope` 全文；envelope 经其 `payload_digest` 被间接承诺，无循环依赖）
- `entry_digest = canonical_digest("e1-journal-entry-v1", unsigned_entry)`
- `entry_signature = Ed25519_sign(authority, canonical_json({"domain":"e1-journal-entry-sign-v1","entry_digest":entry_digest}))`
- `executor_id`：INTENT 时取自 envelope；RESULT 时从同 `operation_id` 的首条 INTENT 继承（E1.8 JournalEntry 含 executor_id）

**Checkpoint 字段（精确集）**：`seq`、`journal_head_digest`、`checkpoint_digest`、`checkpoint_signature`。
- `journal_head_digest(seq)` = **该 seq 处**条目的 `entry_digest`（历史快照语义，不是最新 head）
- `checkpoint_digest = canonical_digest("e1-journal-checkpoint-v1", {seq, journal_head_digest})`
- `checkpoint_signature = Ed25519_sign(authority, canonical_json({"domain":"e1-journal-checkpoint-sign-v1","checkpoint_digest":checkpoint_digest}))`

**每次 append 的落库顺序**（Journal 自身单文件 `BEGIN IMMEDIATE` 事务内）：
分配 `seq=max+1` → 校验 RESULT 前置 INTENT → 构造并签名 entry → INSERT entry → 生成并签名该 seq 的 checkpoint → INSERT checkpoint → COMMIT。
该事务**只在 Journal 文件内**，**不声称**与 Executor DB 的跨存储原子性（E1.9 §2.4）。

**恢复/读取校验（fail-closed）**：
`verify_integrity()` 逐条检查 seq 连续、prev_digest 链接（含创世）、envelope→payload_digest 重算、entry_digest 重算、
entry_signature 验签、INTENT 先于 RESULT、checkpoint 数量对齐、checkpoint_digest 重算+验签、
checkpoint 与同 seq 的 entry_digest 绑定；`head()`/`checkpoint_at(seq)`/`entries_from(seq)` 读取时同样验签。

## 4. J01–J10 测试结果

命令：`PYTHONPATH=src .venv/Scripts/python -m unittest tests.test_e1_journal -v`

| 编号 | 测试 | 结果 |
|---|---|---|
| J01 | 正常追加 INTENT，seq=1、prev=创世 | PASS |
| J02 | 正常追加 RESULT，prev=INTENT entry_digest | PASS |
| J03 | 连续多条追加，整条 prev_digest 链可验 | PASS |
| J04 | 读历史 Checkpoint（seq 1/2 与 head 各自绑定到对应 entry） | PASS |
| J05 | Journal 重启恢复，原记录与签名仍有效 | PASS |
| J06 | 修改日志条目（envelope）→ verify 拒绝 | PASS |
| J07 | 修改 Checkpoint（journal_head_digest）→ 读取与 verify 拒绝 | PASS |
| J08 | 删除中间记录 → 检测链断裂/序号不连续 | PASS |
| J09 | 8 线程并发追加 → 全局 seq 唯一连续无缺号 | PASS |
| J10 | 恢复 Executor 旧 DB 快照 → Journal 字节与历史不变 | PASS（仅证明物理分离） |

另外 2 个负向用例：无 INTENT 的 RESULT 被拒、INTENT envelope 字段集错误被拒，均 PASS。
**小计 12/12 通过。**

## 5. 重启恢复与篡改检测证据
- 重启恢复：J05 用新 `AuthorityJournal` 实例重开同一文件，`verify_integrity()` 通过、
  `head()` 与关闭前逐字段相等、`entries_from(1)` 序号 `[1,2,3,4]`。
- 篡改检测：J06 改写某条 entry 的 `envelope.executor_id`；J07 改写 checkpoint 的 `journal_head_digest`；
  J08 删除 seq=2 的 entry 与 checkpoint。三者均触发 `JournalIntegrityError`，无静默接受。

## 6. 与 Executor 本地数据库分离的验证证据
- `AuthorityJournal` 构造只接收 `journal_path` 与权威密钥，不接收、不导入 `ExecutionStore`。
- J10 用独立普通 SQLite 文件模拟 Executor DB：追加 Journal 后，改动并整体回滚该 Executor DB 文件字节，
  Journal 文件字节、`head()`、`entries_from(1)` 与 `verify_integrity()` 全部不变。
- 该证据的边界：**仅证明"回滚 Executor DB"不触及 Journal 文件**，不证明 Journal 文件自身不可被替换（见 §1.2/§7）。

## 7. 未解决的风险与限制（诚实记录）
1. **信任边界阻碍（最重要）**：单机环境下无法建立"Executor 攻击域之外"的独立信任域。
   "独立文件 + 独立密钥"提供组件隔离与就地篡改检测，但**不能**阻止同时可写这两个文件的攻击者把 Journal 整体换回旧快照。
   - 可行方案（进入后续阶段/部署时必须选定并按 E0 级冻结）：
     (a) **远程权威 Journal 服务**：Journal 运行在独立主机/独立 OS 主体，Executor 仅有 append/query 网络接口、无文件系统访问；
     (b) **独立 OS 主体 + 强制访问控制**：Executor 进程对 Journal 存储无写/替换权限（Windows ACL / 容器 / 不同用户）；
     (c) **WORM / 只追加存储**：存储层拒绝覆盖与删除；
     (d) **外部单调锚点**（TPM/HSM 或远程单调计数，E1.8 B1/B3）作为更上层检查，检测整库回滚。
   - 在上述任一方案落实前，E1.8 §2.2 的"不可回滚 Journal"信任假设**未满足**，B2 不得宣称完成。
2. **范围限制**：本阶段未接入 G2 三态恢复、未接入 `last_applied_seq`/`last_checkpoint_digest`、
   未接入 A1 `BEGIN IMMEDIATE` 锁生命周期（属 E1.9-B/C）；未实现 A2/A3/G1b。
3. **取证语义**：INTENT `payload_digest` 域 `e1-journal-intent-v1`、RESULT 编码、entry/checkpoint 域均为本阶段新冻结，
   仅在本组件内一致，尚未与 Rust/其他语言交叉验证（如进入跨语言阶段需补 Golden Vectors）。
4. **并发边界**：J09 证明单进程内多实例经 SQLite 写锁得到连续 seq；跨主机/分布式场景不在本阶段范围。
5. **系统测试基线**：本阶段仅新增独立模块与测试，未触碰任何现有生产代码。
   改动前基线 `PYTHONPATH=src .venv/Scripts/python -m unittest discover -s tests` = **194/194 OK**；
   改动后完整全量（含 J01–J10 与 2 负向用例）= **206/206 OK**（`git diff --cached --check` = 0）。

## 8. 通过标准对照
要求："Journal 作为独立组件具备完整的追加、签名、检查点、恢复和验证能力，且其持久化信任边界满足 B2 的基本要求。否则不能进入下一阶段。"
- 组件能力（追加/签名/检查点/恢复/验证）：**已具备**，J01–J09 通过。
- 持久化信任边界：在本单机原型中**仅满足组件级隔离与篡改检测，未满足 E1.8 §2.2 意义上的抗回滚**（§1.2/§7）。
- 判定：**E1.9-A 的"Journal Foundation"组件交付完成；但"满足 B2 基本要求"这一整体通过条件，
  取决于后续是否落实独立信任域（§7 方案 a–d）。在进入 E1.9-B 之前，需就此作出决策**，不得默认已通过。
