# ADR-0137 — OAuth 租户与工作区选择

- 状态：Proposed
- 日期：2026-11-21
- 源码基线：`ecff6d0f18075d939b98265d21f06b9986d65f38`
- 前置：M02-10b 已交付的单租户 consent 路径及本 ADR 获批。M02-10c 的动态注册按自身卡验收。

## 权威与产品决策

[Baseline 2.9 §33（Tenant / Workspace Chooser，:8294–8345）](../architecture/Baseline_2.9.md#L8294) 要求登录后的候选同时考虑身份、成员关系、策略、组、租户状态与有效权益，允许选择租户或项目级连接的工作区，由授权服务器将选择绑定到 Grant。[Baseline 2.9 §73.6（Web Console Session，:14812–14828）](../architecture/Baseline_2.9.md#L14812) 及现行会话与 CSRF 实现（`crates/application/src/session.rs`、`bins/gateway/src/auth_pages.rs`、`bins/gateway/src/oauth_http.rs`）规定服务端会话及同源、CSRF、撤销、过期和 epoch 校验。以上行号均对应源码基线 `ecff6d0f`。

U1–U3 的产品依据为『主人裁定 2026-11-21』。以下为获裁定的契约，具体表名和迁移由实施卡确定。

| 输入 | 语义 | 表归属及唯一写入方 | 决策版本来源 |
|---|---|---|---|
| MCP Connection Policy（U1） | 仅租户管理员可设置。按工作区与客户端匹配。无策略或策略停用时沿用 M02-10b 的现行准入，无额外策略限制。匹配冲突时 deny 优先。 | `identity_access` 拥有策略持久化，唯一写入方为同租户的租户管理员接口（U3）。 | [Baseline 2.9 §33:8296–8310](../architecture/Baseline_2.9.md#L8296) 定义判定输入；『主人裁定 2026-11-21』确定规则，生效值取当前策略行版本（U3）。 |
| Allowed Groups（U2） | 组是租户内组，由 `identity_access` 提供组与成员资格事实。未配置允许组时不按组限制。已配置时，用户必须在至少一个允许组内，否则拒绝；空组没有成员（无人满足）。 | `identity_access` 拥有允许组配置、租户组及成员关系，唯一写入方为同租户的租户管理员接口（U3）。 | [Baseline 2.9 §33:8296–8310](../architecture/Baseline_2.9.md#L8296) 定义判定输入；『主人裁定 2026-11-21』确定规则，生效值取当前配置、组及相关成员资格行版本（U3）。 |
| 会话、成员关系、候选、选择、授权码与 Grant | `identity_access` 从已验证会话及其活跃成员关系派生候选。工作区还须有同租户的活跃工作区成员关系及当前授权范围。 | [模块目录:220–246](../architecture/modules.toml#L220) 登记会话、租户、成员关系、工作区、授权码和 Grant 的唯一写主 `identity_access`。[ADR-0035:24–37](0035-workspace-membership-and-scope.md#L24) 规定工作区成员关系的唯一运行时写门。 | Baseline §73.6（`crates/application/src/session.rs`）、ADR-0035 D-A/D-B/D-D/D-F、Baseline 2.9 §33:8294–8345。 |
| 有效权益 | 由 `commercial` 按当前 MCP BMO 准入谓词解释每租户权益快照，用同一观察时间选取生效值（含 successor）并判断有效期。 | [模块目录:291–308](../architecture/modules.toml#L291) 登记 `commercial` 为订阅、权益来源与快照的唯一写主。 | [ADR-0072:19–30](0072-quota-period-renewal.md#L19) D-A、Baseline §76，以及当前 `crates/adapters/src/request_guard_repo.rs:111–176`、`crates/application/src/read_quota.rs:115–156`、`bins/gateway/src/bootstrap.rs:2648–2657`。 |

无策略、策略停用或未配置允许组必须由成功读取的权威状态确认。无法作出判定或读取失败一律拒绝。以上规则只作用于已获准的精确目标，出码或 refresh 失败时禁止回退到其他工作区或更宽的租户范围。

## 拟议只读契约与依赖方向

**策略与组。** `identity_access` 在内部消费单一只读判定。目标集合在服务端从当前用户已验证身份和活跃成员关系派生。端口只需已验证的客户端标识，resource 和 scopes 继续由 OAuth 流程校验。`ConsentTarget` 是 `(TenantId, Option<WorkspaceId>)`。`None` 表示明确获准的租户级连接，工作区目标用 `Some`。

```text
allowed_mcp_targets(
    user: UserId,
    client: &ValidatedClientId,
    candidates: &[ConsentTarget],
) -> Result<AllowedSubset<ConsentTarget>, ErrorCode>
```

允许集仅能取自输入，省略表示明确拒绝。行版本不可确认、读取失败或结果不完整时整体失败。只向调用方返回判定。出码和 refresh 均用单元素集合重验，读取并锁定此时生效的行版本。页面签名和旧版本只可用于核对原选择。

**商业权益。** 每个租户只评估一次现行 BMO 准入，再用于其全部仍获准的目标。商业模块接收由已验证会话派生的、去重且受限的租户集。数据读取须保留租户隔离及调用者对输入租户的授权约束，使用现有 typed gateway PG 权限与窄门。批量接口禁止接受浏览器提交的租户集，不新增跨租户表读权限。

```text
mcp_entitlement_for_tenants(
    authorized_tenants: &[TenantId],
) -> Result<Map<TenantId, McpEntitlement>, ErrorCode>
// McpEntitlement 有 Enabled 和 EntitlementRequired 两种判定
```

成功时逐个覆盖输入租户，使用同一读取快照和商业观察时间。快照缺失或现有谓词判定无有效权益时，该租户为 `EntitlementRequired`。依赖不可用、超时或批次缺项时整批终止；依赖故障映射 `DependencyUnavailable`，数据损坏或返回集合违反契约映射 `Internal`。出码仍以选中租户套用现行准入和事务保护（`migrations/0308_oauth_consent_revoke.sql:26–46`、`bins/gateway/src/bootstrap.rs:2740–2785` 和 `crates/adapters/src/oauth_repo.rs:417–455`）。候选及出码均只读权益，无订阅写入、预留、用量或计费写入。

**依赖。** [ADR-0130 D2/D4/D5/D7a/D8:53–112](0130-bounded-context-modules-ddd-hexagonal.md#L53) 要求应用端口依赖无环、表唯一写主，PG 同事务协作单独登记。

| 调用或协作方向 | `may_depend_on` 增量 |
|---|---|
| `protocol_integration → identity_access`，浏览器适配调用身份用例 | 0，现有边见 [模块目录:838–849](../architecture/modules.toml#L838)。 |
| `protocol_integration → commercial`，现有 gateway 组合根接线至商业批量查询，身份用例仅接收受限判定 | 0，现有边见 [模块目录:838–849](../architecture/modules.toml#L838)。编排不将资格规则留在 HTTP handler。 |
| `identity_access` 的出码 PG adapter → `commercial` 的只读权益与锁门 | 0。实现卡新增 `[[in_txn_door]]`，模块为 `["identity_access", "commercial"]`，用例为 OAuth consent；记录仅消费权益事实及商业判定，同一 PG 事务提交。 |
| `identity_access` 的候选、出码和 refresh → 本上下文策略与允许组判定 | 0。两项均为同上下文读取。 |

本 ADR 提议的新增应用边为 **零**。`commercial → identity_access` 已登记（[模块目录:309–312](../architecture/modules.toml#L309)），新增反向应用边会形成二环。组合根注入的商业判定与 PG 窄门保留商业所有权，不引入通用仓库、跨模块 SQL 写权或共享层业务行为。

## 生成候选、出码与 refresh

1. **GET** 按 Baseline §73.6（`crates/application/src/session.rs`）认证会话，先完成现有 OAuth client、redirect、PKCE S256、resource 与 scopes 校验。只从该用户的活跃租户、租户成员关系与同租户工作区授权范围取候选，取策略、组及商业准入交集。沿用现有受限集合上限（`crates/domain/src/identity.rs:67–88` 的 `BoundedSet::MAX_LEN = 256` 与 [ADR-0035 D-D:52–56](0035-workspace-membership-and-scope.md#L52) 的 `LIMIT 257` 机械判界），超界时以 `ErrorCode::InvalidInput` 明确拒绝，禁静默截断。现行 `oauth_consent_tenants` 的 `LIMIT 2` 只够证明单租户阶段的基数（`migrations/0308_oauth_consent_revoke.sql:2–14`），完整 chooser 须走受限候选读取。
2. **页面** 展示允许的目标及经验证的请求。签名绑定本页目标（包含 tenant/workspace）、会话、有效期及原请求（client、redirect、PKCE、resource、scope、state）。用户显式提交本页签入的那一个目标。服务端仅从校验成功的签名材料取得选择。延续同源和会话绑定的 CSRF 验证。
3. **POST 重验** 在出码前复核同一活会话（含撤销、expiry、epoch）、请求有效性、已签入目标且用户确认、活跃 user/tenant/tenant membership，以及工作区归属、活跃 membership 和当前允许范围。再从现行来源复核策略、组和选中租户的权益。其他候选变化既不能替换选中目标，也不能扩大其授权。
4. **出码事务** 保留 `persist_consent_code` 的单次提交边界（`crates/application/src/oauth_exchange.rs:352–378`）。在写码的同一 PG 事务内先共享锁定稳定的租户内保护行，再读取并共享锁定策略、组及相关成员资格的当前行版本，锁保持至提交。管理员写门须先对此保护行加冲突锁，使无配置、空组、首次配置、插入 deny 或删除配置与读取同样可排序。现有会话、成员与权益检查也必须与相应撤权写入可排序。依赖故障、撤权、事务冲突或失效均回滚，提交成功后才返回 code。
5. **绑定** 以原样的已选 `tenant_id` 和可选 `workspace_id` 写入授权码，兑换从该码传给 Grant（`crates/application/src/oauth_exchange.rs:418–449`，`migrations/0268_oauth_persistence.sql:216–268,274–323`）。浏览器外的客户端参数无权替换它们。继续验证 workspace 绑定只收窄（ADR-0035 D-D/D-F），并保留现行 refresh、Grant 生命周期与资源绑定闸。
6. **Refresh 事务** 从持久化 Grant 取用户、租户、工作区和客户端来重验策略与组。在轮换的同一 PG 事务内锁定相关行及保护行，沿用出码的行版本与共享锁协议。明确拒绝或读取失败时回滚本次轮换，无新 token，也无范围回退。保留现有 refresh 重用导致 family／Grant 撤销的提交分支（`crates/application/src/oauth_exchange.rs:509–565`）。策略或组的撤权一经提交，即阻止新的出码和 refresh。仅由此类变更触发的撤权对已签发的 access token 以其 TTL 到期为界，原有 Grant 撤销、epoch 等检查仍适用。

**错误。** 沿用 [ADR-0130 D7:98–104](0130-bounded-context-modules-ddd-hexagonal.md#L98) 和 `domain::error::ErrorCode`（`crates/domain/src/error.rs:56–95`，Baseline §52.1）。目标不可见、不在本页、被策略或组拒绝、撤权或没有可选目标时，以 `Forbidden` 结束。有效目标缺权益时为 `EntitlementRequired`。候选集超过受限上限（`crates/domain/src/identity.rs:73–86` 的 `BoundedSet::MAX_LEN = 256`、[ADR-0035 D-D:54–56](0035-workspace-membership-and-scope.md#L54)）时映射 `InvalidInput`，禁静默截断。无效登录、CSRF、客户端请求与用户主动拒绝走原有 M02/OAuth 映射；依赖失败走 `DependencyUnavailable`（现 handler 为 503），内部损坏走 `Internal`，并发冲突保留原映射（`bins/gateway/src/oauth_http.rs:563–568,685–728,846–852`）。浏览器不获知其他主体、租户、组或未展示目标的存在。权限失败全部终止，无 `DegradeCode` 成功回退，也无第三种业务错误枚举。

## 实现卡与验收

本 ADR 获批后按下表实施。每卡上限 15 个文件（含真 PG 测试、迁移 manifest 与目录登记），超出上限先拆卡。

| 卡 / 文件预算 | 任务边界与顺序 | 验收与独立注错 |
|---|---|---|
| 身份策略与组存储 / ≤15 | `identity_access` 落持久化、行版本与唯一的租户管理员写门，登记表归属及冲突锁协议。 | 真 PG 验证同租户管理员可写、普通成员和跨租户管理员均拒绝且无写入、写入推进版本。分别注错绕过管理员校验、绕过租户校验及跳过版本更新，各自红后恢复绿。 |
| 身份策略与组读取 / ≤12 | 存储卡通过后，`identity_access` 提供窄判定及共享锁读取。 | 真 PG 验证工作区与客户端共同匹配、无策略、停用、deny 优先、未配置组、空组、任一允许组命中及读取失败。分别注错丢掉匹配维度、让 allow 覆盖 deny、把空组视为允许所有用户或把读失败视为无配置，各自红后恢复绿。 |
| 商业权益批量查询 / ≤10 | `commercial` 提供只读批量路径，复用现行 BMO 谓词及快照时点，保留出码用的权益锁门。 | 真 PG 同一批具备有效、缺失、过期及 successor 到期切换样本，失败批次整体拒绝，权益、计费和预留表无写入。注错以默认方案放过无权益、忽略 successor、把不可用作为部分成功，各自红后恢复绿。 |
| 身份候选和原子出码 / ≤15 | 身份读取和商业契约可调用后，集成 PG 窄门、精确工作区绑定、撤权排序，并登记同事务协作。 | 真 PG 比对多个可用租户、同租户 workspace、他人或跨租户目标和非活跃身份/成员。授权码、兑换、Grant 对账同一选择。逐项注错移除会话、tenant membership、workspace membership、策略、组或商业重验、绕过共享锁，以及失败回退到 tenant，各自红后恢复绿。并发夹具在候选与出码之间提交策略或组撤权，验证无新码，并覆盖从无配置插入 deny 的排序。 |
| 身份原子 refresh / ≤12 | 身份读取契约可调用后，在现有轮换事务内对 Grant 的精确绑定接入策略与组重验。 | 真 PG 验证政策和组撤权提交后无新 token，失败轮换回滚，同时保留重用撤销和既有 access token 的 TTL 行为。分别注错使用旧行版本、绕过共享锁、失败仍提交轮换或回退到租户，各自红后恢复绿。 |
| 浏览器 consent / ≤12 | 原子出码和 refresh 验收后，把签入选择与出码接到现有 OAuth 路由。 | HTTP 加真 PG 验证显式选择、空候选、签入目标篡改、另一会话复用、同源/CSRF、策略或商业依赖不可用及无回退。分别注错允许未签入目标、取消会话绑定和在依赖失败时默认选租户，各自红后恢复绿。 |

保留现行 OAuth 与会话门禁（Baseline §33 / §73.6，`crates/application/src/oauth.rs`、`crates/application/src/session.rs`、`bins/gateway/src/oauth_http.rs`）：G-M02-5（跨会话或跨站 CSRF）、6（PKCE plain／非 loopback HTTP）、7（code 重放／错误 resource 或 verifier）、8（refresh 重放撤销整 family）、9（Grant 最长时限／epoch）、14（metadata golden，包括适用 URL）原判据。按当前入口跑受影响的全部 OAuth 模式。每卡交付最终 SHA、真 PG 正反例和逐项注错红→恢复绿的 CI 证据，再由独立复核验收。保持现有 HEX 基线。本文只提交 Proposed 设计，chooser 产品实现及对应运行验证仍待执行。

## Provenance

设计来源（**只记出处，不作依据**）：外部规划稿 `module_design_M02.md`（`:123–128`，SHA-256 `e947c6751a4df7e39e857c4ae351c92b64faee0e1d43d4e0bfed7e96bc27d943`；§8 `:174–183`）与 M02-10-CHOOSER 草案 `DRAFT.md`（`:5–18`，SHA-256 `4c888f8d0db5acb1325717074c45fe62c1e751d0ff85684676a3e11600f06dd5`）。本 ADR 的全部可执行主张均锚定仓库内已提交文件、§ 号与『主人裁定 2026-11-21』。
