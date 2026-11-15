# ADR-0130 — 限界上下文模块划分：DDD 业务边界与六边形内侧分层（M01-DESIGN）

- 状态：Accepted (2026-11-15)
- 日期：2026-11-15
- 关联：Baseline §3（九层逻辑架构与依赖原则）、§58（推荐 Rust Workspace，workspace contract）、§78.3（Workspace Dependency Rule）、§78.6（ADR/RFC：架构语义变更必须写 ADR）、§52（Error Taxonomy：`ErrorCode` 终止 / `DegradeCode` 降级）、§53.1（单一出口 `abstain()`）、§22.5（降级方向写死，`CompletenessClass` 唯一构造器）、§59.1（`Authority` 冻结契约）；ADR-0078（M29 与归属轴）、ADR-0106 D-D（`private.run_acceptances` 唯一验收存储）、ADR-0112（M15 core/cloud 围栏）、ADR-0114（M16 代码图）、ADR-0115（M17 文本化）、ADR-0110（frontier 读法）
- 决定者：主控工程裁决（2026-11-15）。owner 已同意执行顺序「ADR → 边界闸 → 首纵切」。本 ADR 不新增产品语义，只把已复核的 19 模块划分固定成仓库契约。
- 影响面：**只加文档。** 新增本 ADR 与 `docs/architecture/modules.toml`，`Baseline_2.9.md` §58 末尾一行 Amends。不改代码 / Cargo / SQL / gate 行为 / 任务卡 ID，不 build/test/DB，不迁移任何文件。

## 背景

**M01–M29 是交付编号，不是边界定义。** 仓库现在用两套坐标描述「模块」，两者都不是限界上下文：

- 交付坐标：`docs/architecture/module_ownership.toml` 的 `[crates]` 表把 27 个 workspace member 映射到 M01..M28，M29 由 ADR-0078 后加。同一个编号同时用作任务卡前缀（`M16-13`、`M29 T06c`）、crate 归属、表 owner 前缀，三种用途混在一起。
- crate 坐标：`module_ownership.toml` 自己写明一个 crate 可承载多个模块（`humaux-adapters = "M07"` 带 `shared` 注释；`humaux-retrieval = "M11"` 同时承载 M11/M13/M14 的文件）。crate 边界是编译与发布边界，不是业务边界。
- 编号在闸里也只是兼容常量：`MODULE_ID_MAX: u8 = 28`（`xtask/src/architecture_check.rs:1100`）与表 owner 解析接受 `M01..M29`（`:12174-12183`）并存，M29 专用门从 `:4683` 起存在。这两处数字不一致本身说明 M 号是历史批次号，不能拿它当边界。（写作时状态；PR #514 / d860e6d 已统一为单一常量 29，M30 仍拒。）

结果是缺一份「业务边界」契约：统一语言在哪个上下文里成立、哪张表归谁写、同事务一致性边界在哪、跨上下文允许走哪条缝。**这正是本 ADR 要补的唯一空白。**

**两个方法的分工。** DDD 管语言、写权与一致性：一个上下文内同一套术语与不变量；一张表恰一个写主；跨上下文只能经发布语言与端口协作，不能共享可变状态。六边形管用例与 I/O 隔离：domain 是纯决策，application 实现入站用例并只为真实外部边界声明出站端口，adapter 实现端口并拥有事务，bins 是唯一组合根。依据 Baseline §3「Domain never imports HTTP / PostgreSQL / Qdrant / DashScope / ENV」与 §78.3 的禁用依赖表。

**已存在的约束只继承、不重开。** §58 的 crate 树是 workspace contract 而非示意图；唯一 read gate、六类唯一构造点、两个错误枚举、ADR-0106 D-D 的唯一验收存储都已在跑。本 ADR 的 19 个模块**不改变**它们的判据，只规定这些能力落在哪个上下文里。

## 决定

### D1 — 19 个模块，模块 = 限界上下文

以 17 个职责节点为起点：保留 15 个，运行保障拆为作业 / 知识备份 / 平台支持 3 个，协议集成保持 1 个，共 19 个。类型是职责类型，**独立于 Cargo core/cloud edition**；`platform` 与 `integration` 是技术限界上下文，明确无业务聚合，不为凑 DDD 伪造实体。

| 模块 | 类型 | 历史 M | 职责（一句话） |
|---|---|---|---|
| `knowledge_lifecycle` | core | M06/M07 | 把来源接纳为 Evidence，维护 Memory/Note/Subject 与更正/取代/归档；所有写入经过同一事实门。 |
| `work_attribution` | core | M29 | 登记项目身份、typed 关系与 Evidence/Memory 归属，集中关系有效期与冲突规则。 |
| `project_continuity` | core | M14 | 生成 brief/context/handoff/facet、记忆适用性与复用建议；消费知识，不另存知识真源。 |
| `coordination` | core | M18 | 任务计划、run/lease/fencing、候选交付与接受、进度与画布。 |
| `identity_access` | support | M02/M03 | 身份凭证、OAuth/会话、有效 scope，以及公平调度、容量与连接预算；准入不含业务执行。 |
| `commercial` | support | M04 | 计划版本/订阅、计费 inbox、额度预留结算与权益投影；产品代码不硬编码价格。 |
| `knowledge_curation` | core | M15 | 提炼/整合、候选生成、陈旧传播、经验升级；提议与接受分离。 |
| `code_intelligence` | core | M16 | 仓库/快照/overlay、symbol/edge、索引查询与代码-知识桥；运行 overlay 相互隔离。 |
| `document_acquisition` | core | M17 | 接收文件、抽取 manifest/unit/locator、质量核验、敏感扫描；知识写入交 `knowledge_lifecycle`。 |
| `data_rights` | support | M19 | 唯一删除管道、冻结 closure/确认、tombstone、分步清除、erasure ledger 与导出。 |
| `public_knowledge` | core | M20 | 选择/匿名化/贡献确认、公共 claim 与 provenance、撤销；消费被授权密封数据。 |
| `knowledge_association` | core | M28 | 基于 Subject 与 typed 关系的有界图遍历、派生社区/快照与代码桥消费。 |
| `retrieval_read_model` | support | M08/M09/M10/M11/M12/M13 | 统一 final read gate、stream/outbox、投影/缓存、候选读取与 completeness/envelope。 |
| `provider_execution` | support | M05 | 按目的执行推理/embedding/rerank、出境/秘密/许可、admission、调用成本记录。 |
| `contract_kernel` | platform | M01 | 小型标识符/错误/配置/时间与跨模块契约；module ownership 与导出形状。 |
| `protocol_integration` | integration | M25/M26/M27 | MCP/REST/legacy 适配、schema/生成 client、console 与插件；同一用例多入口。 |
| `job_execution` | support | M21 | 后台作业 claim/执行/重试与调度状态的唯一家。 |
| `operations_platform` | platform | M22/M24 | 观测/通知、测试夹具与既有工程检查；技术标签，无统一业务聚合。 |
| `knowledge_backup` | support | M23 | 备份/恢复请求、restore 尝试与闭包；单向读取 erasure fence，不获得业务写权。 |

每个模块的聚合、唯一表写主、发布语言与消费端口见 `docs/architecture/modules.toml`（D8）。模块数、历史 M、表数、依赖边的机器可读形态只在该文件里，本 ADR 不复述表清单。

### D2 — 模块内六边形分层

| 层 | 放什么 | 禁止 / 保留 |
|---|---|---|
| `domain::<context>` | 实体、聚合、值对象、纯策略 | 无 HTTP/DB/SDK/ENV（§3、§78.3）；纯函数直接调用，不每个 CRUD 包一个 trait |
| `application::<context>` | 业务命令/结果、用例（= 入站端口的实现） | 不泄漏 SQLx `Transaction`/`Row`、供应商 JSON；不用万能 `Repository`/`UnitOfWork`/服务定位器 |
| 出站端口 | 只在**真实** adapter 边界声明（PG、Qdrant、对象存储、provider、HTTP），由 application 调用 | 不为想象中的实现预建 trait；domain 不依赖 application 或 adapter |
| `adapters::<context>::*` | SQL 事务、typed pool 角色、Qdrant、临时对象存储、provider 翻译 | 同事务的事实/receipt/额度/审计/stream 不得拆成每聚合单独 commit |
| `protocol` / gateway 入口 | 解析、身份转换、wire 错误映射，调用 application 端口 | handler 不直接用 adapter 的命令类型 |
| `bins` | 唯一配置/资源构造、端口接线、进程 loop | 不放业务规则 |

调用方向固定为：入站 adapter → application（入站端口实现、用例）→ domain 纯决策；application 声明真实出站端口并取得适配器注入。依赖倒置不等于让 domain 依赖 application 或 adapter。一个完整动作（如 remember）由 application 的**一个**入站端口驱动；现有窄接口可以在 adapter 内部携带事务句柄，但不向 application 公开连接或事务对象。

### D3 — 物理落位：保留分层 crate，上下文为各 crate 一级 module

保留 §58 的现有分层 crate（domain / application / adapters / protocol / retrieval / projection / bins…），在各 crate 内把上下文作为一级 module：`domain::knowledge_lifecycle`、`application::knowledge_lifecycle`、`adapters::knowledge_lifecycle::pg`。理由：

1. §58 的树是 workspace contract，改树要先改 §58；本 ADR 不承担那次改动。
2. 现有安全与版别围栏（core/cloud、egress/cell、typed pool）按分层生效；先拆业务 crate 会让两套围栏同时改。
3. 局部纵切可审查、可回退；同事务原子性不因目录移动被拆开。

本 ADR **不新增 crate、不改 Cargo member**。模块与 crate 的对应见 `modules.toml` 的 `may_depend_on` 与 `docs/architecture/module_ownership.toml` 的 crate 行；一个 crate 可承载多个上下文，反之不成立（上下文不跨 crate 做写主）。

### D4 — 表唯一写主

238 张现有表（`docs/architecture/backup_catalog.toml` 与 `docs/architecture/db_objects.md` 的表全集）每张恰一个写主，写进 `modules.toml` 的 `owned_tables`；19 个模块中 17 个有表，`contract_kernel` 与 `protocol_integration` 无业务表。规则：

- 一张表只出现在一个模块的 `owned_tables`（叶分区随父表，不增第二写主）。
- guest 只以列级职责或同事务 PG 窄门出现，不获得 INSERT/UPDATE/DELETE 写权。
- 已接受但未部署的存储只有 `private.run_acceptances`（`coordination`，ADR-0106 D-D），标 `ACCEPTED_DESIGN_NOT_ASSERTED_DEPLOYED`，DDL 落地前不进 `owned_tables`。
- `owned_tables` 由 `backup_catalog.toml` / `db_objects.md` 派生，禁手写第二份表清单；对账由后续边界闸以集合相等完成，不靠人工同步。

### D5 — 跨模块只经发布语言与端口

跨上下文协作只有两条合法缝：发布语言（命令/查询/事件）与端口。`modules.toml` 的 `may_depend_on` 是**目标应用依赖图**（consumer → 发布契约提供方），62 条边、无环；它不宣称当前源码已经无环。

- 稳定 ID 作为输入不产生对事实 owner 的反向 application 调用；PG 读取事实表不等于导入 `knowledge_lifecycle` 的 application。
- `retrieval_read_model` 的 `final_read_gate` 是内部叶子能力：只接收稳定授权值/ID，依赖 kernel 类型，不回调 `knowledge_lifecycle`；其余检索用例仍可消费 provider 端口，不能把 gate 复制到各模块。
- **同事务协作属于 adapter 内部**：remember 的 M07 事实门、M29 归属门、M18 验证、M04 额度与 M09 票据门在一个 PG 事务里协作，标记为 `pg_door_collaborations.kind = in_txn_pg_door`。它不是 application 跨模块调用、不是 callback、不各自 commit；把它写成 application 端口调用就等于拆事务。
- 反向装配（如 `data_rights` 声明擦除目标端口、由 `document_acquisition`/`public_knowledge` 的实现注入）由组合根完成，不是反向 import。

### D6 — M 号保留为历史别名，任务卡永不重编号

M01..M29 在 `modules.toml` 的 `legacy_m` 里逐一保留；既有执行卡的 ID、依赖与归属不变。**不得用「19 个模块」替换旧 M 号**，也不得按新模块数重排卡号。统一 M 号合法集合（`MODULE_ID_MAX` 与 `M01..M29` 并存问题）是迁移第 0 步，已由 PR #514（d860e6d）完成：单一 `MODULE_ID_MAX = 29`，三处校验同引，M30 仍红。

### D7 — 保留的 Baseline 硬约束（本 ADR 不改宽任何一条）

1. **同事务原子性在 PG adapter**：事实、receipt、额度、审计、stream 的一道完整动作在一个 PostgreSQL 事务内完成（§58 的单库边界）。ADR-0106 D-D 只定唯一验收存储，事务归属仍是 PG adapter；模块划分不构成拆事务的理由。
2. **唯一 read gate**：`crates/adapters/src/read_gate.rs:1-33` 的六条件、all-backing-evidence 闭包与同一 REPEATABLE READ snapshot。每个只读业务的返回都必须经过它；gate 不复制到各模块，也不按模块各判一次可见性。
3. **六个唯一构造点**（断言写精确计数，不写 `<=`；pin 上有两处不是全局 `== 1`，照现行闸原样保留）：`Authority::new`（§59.1，`xtask/src/architecture_check.rs:932`）、`evidence::payload_sha256`（`:3617`，**`== 2`**：唯一哈希构造 + 不做哈希的受控 read-back `EvidencePayloadSha256::from_stored_digest`，第三处或模块外任一处仍红）、`retrieval::build_request`（`:3318`）、`abstain()`（§53.1，Baseline `:11198`）、`ledger::close`（§22.5，`:7495`）、`classify()` 按 `ClassifiedMemoryId` 与 `CompletenessClass` 两个关注点**各自** 1（`:5582`，不把两者合计）。
4. **两个错误枚举**：`ErrorCode`（终止）与 `DegradeCode`（降级），互斥，禁开第三个（§52、§52.2）。
5. **单一验收存储**：`private.run_acceptances`（ADR-0106 D-D），不是 `coord.gate_decisions`，不是第二张 acceptances 表。

### D7a — 依赖无环的范围：只针对应用端口

`may_depend_on` 只表达 application 层跨模块端口依赖，这张图必须无环。一道 PG 事务内的同事务协作（例如 remember 中 `knowledge_lifecycle` 的事实门与 `coordination` 的验证门在同一事务里互相调用）不是应用端口依赖，属于 PG adapter 内部的具名窄门；它可以双向，单独列在 `modules.toml` 的 `in_txn_doors` 里，不计入无环判定，也不得借它在 application 层建立反向依赖。

### D8 — 机器可读目录 `docs/architecture/modules.toml`

`modules.toml` 是本 ADR 的清单形态：字段 `id`、`kind`、`legacy_m`、`owned_tables`、`may_depend_on`，由 19 模块目录派生，供后续边界闸（`HEX-CONTEXT` / `HEX-WRITER` / `HEX-COVERAGE`）读取。文件头写明职责、读者与不变量（表唯一写主、依赖无环、历史 M 全覆盖）。在闸实现并拿到注错记录之前，它只是清单，不是闸；不得据此宣称边界已被强制。

## 未取的替代方案

### (b) 每个上下文一个 crate — rejected（本阶段）

理由三条，**不包含「crate 不能隔离事务」**（那是错的，crate 确实给编译期隔离）：

1. 当前没有任何上下文有独立发布或独立许可证的已确认消费者；单仓里拆 crate 不产生新的业务保证。
2. 批量拆包会把跨上下文的原子动作（remember 的 receipt/额度/审计/stream）逼进一个过大的 common crate，反而伤到 D7 第 1 条。
3. 27 个 workspace member（§58）已带安全/版别围栏，先拆业务 crate 会让两套围栏同时改，回归面不可控。

可测重评信号（任一成立才重评）：① 出现 ≥1 个必须独立分发或许可证边界的已确认消费者，且所有受影响原子动作都已有窄端口；② 同一上下文在连续 2 个发布周期里出现 ≥3 个经复核的跨边界依赖违规（`HEX-CONTEXT` 判红并在卡内复核）。

### (c) 新业务上下文 crate 与分层 crate 并行混合 — rejected（本阶段新增拆分）

1. 双组织方式让「这个文件归谁」没有唯一答案，owner 查找成本翻倍。
2. 当前的真实接缝是「用例写在 adapter 里」，不是「目录不够细」；没有测量支持先拆包。
3. 混合会造出两套 import 规则，`HEX-CONTEXT` 无法用单一拓扑判定。

重评信号：同一纵切连续 2 个发布周期仍出现 ≥3 个经复核的「绕过内部围栏」实例时，**只提取该模块**为 crate；§58 已有的技术 crate（`infra-*`、`retrieval-provider` 等）不算新拆分。

### 其他已否决写法

- 每 CRUD 一个 trait、万能 `Repository`/`UnitOfWork`、DI 服务定位器：D2 已禁；端口按真实业务对话定义，不按表。
- 用 19 个模块替换 M 号、重编号任务卡：D6 禁止；历史追溯与现有 gate 都依赖 M 号。
- 为凑 DDD 给 `contract_kernel`/`protocol_integration`/`operations_platform` 造业务聚合：D1 明确它们是技术上下文，无业务聚合。
- 把静态扫描当作事务原子性证明：编译与扫描证明不了 COMMIT 行为，原子性仍由真实 PG 负控证伪（§79），故不新增静态原子门。

## 迁移顺序

| 步 | 动作 | 可证伪验收（沿现有 gate） |
|---|---|---|
| 0 | **已完成（PR #514）**：统一 M 号合法集合（`M01..M29`）与 `MODULE_ID_MAX` 的过渡；先做存量集合比对，确认无遗漏再动文件 | M29 合法正例通过；M00 / M30 / 缺一归属反例各判红后恢复绿；旧 gate 继续绿；不放宽成任意字符串，不删 M29 专用门 |
| 1 | 实现四类最小边界闸并取得「注错→红→恢复→绿」记录 | `HEX-LAYER`：application 导入 adapter DTO 或 sqlx → 红；`HEX-CONTEXT`：`knowledge_lifecycle → retrieval_read_model` 与反向边同时存在 → `CycleError` → 红；`HEX-WRITER`：第二处 `private.context_bindings` INSERT → 红；`HEX-COVERAGE`：删一个 owner 或加一个无归属文件 → 红。四条各自恢复后绿。**没有这份记录，闸不算存在（§80.1）** |
| 2 | 首纵切 `knowledge_lifecycle` / remember：业务命令与入站用例进 application，PG 端口封装完整事务，gateway 只映射应用命令，bins 装配 adapter | 同输入下 receipt/stream/额度/幂等与错误码前后一致；重复不同 bytes、COMMIT 未知、lease 过期原 PG 反例仍红/绿；gateway 不再直接引用 adapter 命令类型 |
| 3 | 按 `may_depend_on` 的拓扑序推进其余纵切，每步绑该步新 SHA | 其余顺序即 `modules.toml` 的拓扑序：`contract_kernel` → `identity_access` → `operations_platform` → `commercial` → `provider_execution` → `retrieval_read_model`（唯一 read gate 叶子化，六条件与 all-backing-evidence 原判据不变）→ `work_attribution` → `data_rights` → `coordination` → `document_acquisition` → `public_knowledge` → `knowledge_backup` → `knowledge_curation` → `code_intelligence` → `job_execution` → `knowledge_association` → `project_continuity` → `protocol_integration`（`knowledge_lifecycle` 已作为第 2 步先行）；每步的既有 gate 继续绿，旧证据随新 SHA 作废 |

约束：第 0、1 步通过前不得移动任何文件；文件移动后 M 号仍是历史别名、卡 ID 不变；本 ADR 不注册新任务队列、不关闭任何产品卡、不把设计写成已实施。

## Open

- OPEN-1：context half精确列/窄门同事务协作由M07/M14契约owner确认；关闭前project_continuity仅read/authorize、零可写列，不把意图当写权限。
- OPEN-2：直接revoked_at位置及可信回读/verifier map依赖由M18/M26/TrustedConnector契约owner依ADR-0106:91–102确认；存储已定不重问。
- OPEN-3：共享PG/导出文件内部符号按纵切定位后由相应owner定端口；243一级条目不是逐符号迁移清单。

## 后果

- 边界变成可测契约：`modules.toml` 给后续 `architecture-check` 提供唯一的机器可读输入；表写主、依赖方向、历史 M 别名一次说清，不再只存在于设计稿与人的记忆里。
- 不动代码：不新增 crate、不换运行时/ORM/异步栈、不拆事务；29 个 M 号与既有卡的 ID 保持原样。
- 代价 1：`modules.toml` 是派生清单，会与 `backup_catalog.toml` / `db_objects.md` 漂移。对策不是再写一份判据，而是让 `HEX-WRITER`/`HEX-COVERAGE` 以集合相等对账（新增表无 owner、owner 重复、历史 M 缺失均判红）。
- 代价 2：19 个模块里 2 个没有业务表、3 个没有业务聚合（技术上下文）。这是有意的：不为对称伪造实体，它们的边界由导入规则与既有 gate 管。
- 代价 3：端口名（`authorize`、`reserve_quota`…）是设计意图，不是现有 Rust API；照名字虚构 trait 会在第一个纵切暴露。D2 的「真实 adapter 边界」是判据。
- 未覆盖：当前源码仍有 import cycle（`crates/adapters/src/read_gate.rs` 的 `ponytail:` 注释记录两处）。`HEX-CONTEXT` 约束的是**目标图无环**，不宣称现状无环；现状由后续纵切逐步消化。
- 证据级：本 ADR 止于文档结构（`modules.toml` 自检：19 模块、238 表唯一写主、62 边无环）与原文行号核对；产品 build/test/DB 为 NOT_RUN，设计正确性由独立复核承担（R1 已处理；R2 待回）。

## Provenance

设计来源（**只记出处，不作依据**）：`.orchestrator/reports/architecture-ddd-20261115/architecture/MODULES_DDD_HEX.md` 与同目录 `module_catalog.json`（2026-11-15，源码 pin `09f505b3`），独立复核 `review/MD1_REVIEW.md`。本 ADR 的全部可执行主张均引用仓库内已提交文件与 § 号。
