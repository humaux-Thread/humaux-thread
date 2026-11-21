# ADR-0137 — OAuth 租户与工作区选择

- 状态：Proposed
- 日期：2026-11-21
- 源码基线：`ecff6d0f18075d939b98265d21f06b9986d65f38`
- 前置：M02-10b 已交付的单租户 consent 路径及本 ADR 获批。M02-10c 的动态注册按自身卡验收。

## 权威与待裁定事项

[Baseline 2.9:8294–8345](../architecture/Baseline_2.9.md#L8294) 要求登录后的候选同时考虑身份、成员关系、策略、组、租户状态与有效权益，允许选择租户或项目级连接的工作区，由授权服务器将选择绑定到 Grant。M02 D6（`module_design_M02.md:123–128`，SHA-256 `e947c6751a4df7e39e857c4ae351c92b64faee0e1d43d4e0bfed7e96bc27d943`）规定服务端会话及同源、CSRF、撤销、过期和 epoch 校验。M02-10-CHOOSER `DRAFT.md:5–18`（SHA-256 `4c888f8d0db5acb1325717074c45fe62c1e751d0ff85684676a3e11600f06dd5`）规定选择边界和验收。以上行号均对应所列版本。

| 输入 | 一手来源可确认的语义 | 现行表归属及唯一写入方 | 现行决策版本来源 |
|---|---|---|---|
| MCP Connection Policy | 参与 MCP 连接目标资格判定。规则主体、条件及默认行为 **UNKNOWN（U1）**。 | **UNKNOWN（U3）**。 | Baseline 2.9:8296–8310 定义其为判定输入。规则版本源 **UNKNOWN（U3）**。 |
| Allowed Groups | 组约束参与同一次资格判定。组的来源、成员资格及匹配规则 **UNKNOWN（U2）**。 | **UNKNOWN（U3）**。 | Baseline 2.9:8296–8310 定义其为判定输入。组决策版本源 **UNKNOWN（U3）**。 |
| 会话、成员关系、候选、选择、授权码与 Grant | `identity_access` 从已验证会话及其活跃成员关系派生候选。工作区还须有同租户的活跃工作区成员关系及当前授权范围。 | [模块目录:220–246](../architecture/modules.toml#L220) 登记会话、租户、成员关系、工作区、授权码和 Grant 的唯一写主 `identity_access`。[ADR-0035:24–37](0035-workspace-membership-and-scope.md#L24) 规定工作区成员关系的唯一运行时写门。 | M02 D6、ADR-0035 D-A/D-B/D-D/D-F、Baseline 2.9:8294–8345。 |
| 有效权益 | 由 `commercial` 按当前 MCP BMO 准入谓词解释每租户权益快照，用同一观察时间选取生效值（含 successor）并判断有效期。 | [模块目录:291–308](../architecture/modules.toml#L291) 登记 `commercial` 为订阅、权益来源与快照的唯一写主。 | [ADR-0072:19–30](0072-quota-period-renewal.md#L19) D-A、Baseline §76，以及当前 `request_guard_repo.rs:111–176`、`read_quota.rs:115–156`、`bootstrap.rs:2648–2657`。 |

负责人需裁定的三项如下。对照 Baseline、M02 D6、现行 ADR、模块目录、迁移与源码，尚未定位另外的已批准策略权威。

1. **U1，策略语义。** 谁可设置策略，哪些租户、工作区、客户端、resource 或 scopes 参与匹配？无策略、冲突及停用时怎样决策？策略变化对已签发 Grant 和 refresh 有何生效时点？
2. **U2，组语义。** 组和成员资格的权威来自哪里，租户与工作区如何关联，空组、缺失组或多个组关系如何判断？组变更对已签发 Grant 和 refresh 有何生效时点？
3. **U3，持久化与版本。** 两项事实分别属于哪个上下文、存储或发布源、由哪个唯一业务写入方及窄门维护？哪个现行决策版本或一致读取机制可作为出码重验依据，更新和撤销如何与出码排序？

U1–U3 阻塞 chooser 启用及相应实现卡。继续使用 M02-10b 现行入口行为，直到正式权威及可执行窄门到位。把未知规则当成允许、把 tenant membership 当作组证据、从工作区拒绝回退到租户，均会扩大授权。

## 拟议只读契约与依赖方向

**策略与组。** `identity_access` 消费单一只读判定，提议签名如下。目标集合在服务端从当前用户已验证身份和活跃成员关系派生。 `ValidatedConnection` 是已验证请求的最窄只读视图，仅含客户端标识、resource、scopes；`ConsentTarget` 是 `(TenantId, Option<WorkspaceId>)`。 `None` 表示明确获准的租户级连接，工作区目标用 `Some`。

```text
allowed_mcp_targets(
    user: UserId,
    connection: &ValidatedConnection,
    candidates: &[ConsentTarget],
) -> Result<AllowedSubset<ConsentTarget>, ErrorCode>
```

允许集仅能取自输入，省略表示明确拒绝。权威版本不可确认、读取失败或结果不完整时整体失败。只返回判定，无需读取组清单、规则全文或内部存储结构。出码时以选中目标的单元素集合调用等价判定，读取此时生效的权威版本；签入页面的候选和旧版本均不能代替重验。待 U3 批准后，以实际存储边界确定端口实现和并发检查。

**商业权益。** 每个租户只评估一次现行 BMO 准入，再用于其全部仍获准的目标。商业模块接收由已验证会话派生的、去重且受限的租户集。数据读取须保留租户隔离及调用者对输入租户的授权约束，使用现有 typed gateway PG 权限与窄门。批量接口禁止接受浏览器提交的租户集，不新增跨租户表读权限。

```text
mcp_entitlement_for_tenants(
    authorized_tenants: &[TenantId],
) -> Result<Map<TenantId, McpEntitlement>, ErrorCode>
// McpEntitlement 有 Enabled 和 EntitlementRequired 两种判定
```

成功时逐个覆盖输入租户，使用同一读取快照和商业观察时间。快照缺失或现有谓词判定无有效权益时，该租户为 `EntitlementRequired`。依赖不可用、超时或批次缺项时整批终止；依赖故障映射 `DependencyUnavailable`，数据损坏或返回集合违反契约映射 `Internal`。出码仍以选中租户套用现行准入和事务保护（`0308_oauth_consent_revoke.sql:26–46`、`bootstrap.rs:2740–2785` 和 `oauth_repo.rs:417–455`）。候选及出码均只读权益，无订阅写入、预留、用量或计费写入。

**依赖。** [ADR-0130 D2/D4/D5/D7a/D8:53–112](0130-bounded-context-modules-ddd-hexagonal.md#L53) 要求应用端口依赖无环、表唯一写主，PG 同事务协作单独登记。

| 调用或协作方向 | `may_depend_on` 增量 |
|---|---|
| `protocol_integration → identity_access`，浏览器适配调用身份用例 | 0，现有边见 [模块目录:838–849](../architecture/modules.toml#L838)。 |
| `protocol_integration → commercial`，现有 gateway 组合根接线至商业批量查询，身份用例仅接收受限判定 | 0，现有边见 [模块目录:838–849](../architecture/modules.toml#L838)。编排不将资格规则留在 HTTP handler。 |
| `identity_access` 的出码 PG adapter → `commercial` 的只读权益与锁门 | 0。实现卡新增 `[[in_txn_door]]`，模块为 `["identity_access", "commercial"]`，用例为 OAuth consent；记录仅消费权益事实及商业判定，同一 PG 事务提交。 |
| `identity_access →` U3 确认的策略或组提供方 | 当前 0。若由同一上下文提供则无需边。若采用跨上下文应用端口，先逐条登记 `identity_access → <提供方>` 并证明无环。若采用同 PG 事务窄门，登记具体 `in_txn_door`。 |

本 ADR 提议的已知新增应用边为 **零**。`commercial → identity_access` 已登记（[模块目录:309–312](../architecture/modules.toml#L309)），新增反向应用边会形成二环。组合根注入的商业判定与 PG 窄门保留商业所有权，不引入通用仓库、跨模块 SQL 写权或共享层业务行为。

## 生成候选与出码

1. **GET** 按 M02 D6 认证会话，先完成现有 OAuth client、redirect、PKCE S256、resource 与 scopes 校验。只从该用户的活跃租户、租户成员关系与同租户工作区授权范围取候选，取策略、组及商业准入交集。沿用现有集合约束。超界时明确拒绝，禁静默截断。现行 `oauth_consent_tenants` 的 `LIMIT 2` 只够证明单租户阶段的基数（`0308_oauth_consent_revoke.sql:2–14`），完整 chooser 须走受限候选读取。
2. **页面** 展示允许的目标及经验证的请求。签名绑定本页目标（包含 tenant/workspace）、会话、有效期及原请求（client、redirect、PKCE、resource、scope、state）。用户显式提交本页签入的那一个目标。服务端仅从校验成功的签名材料取得选择。延续同源和会话绑定的 CSRF 验证。
3. **POST 重验** 在出码前复核同一活会话（含撤销、expiry、epoch）、请求有效性、已签入目标且用户确认、活跃 user/tenant/tenant membership，以及工作区归属、活跃 membership 和当前允许范围。再从现行来源复核策略、组和选中租户的权益。其他候选变化既不能替换选中目标，也不能扩大其授权。
4. **事务** 保留 `persist_consent_code` 的单次提交边界（`oauth_exchange.rs:352–378`）。校验与写码共享 PG 事务。终检对会话和成员关系、策略/组、权益建立与对应撤权写入可排序的检查（在 PG 内以存量锁门或相应 owner 的版本/锁门保护至提交，缺失行或新增 deny 同样须纳入排序）。若 U3 的权威无法提供这种保证，chooser 保持停用。依赖故障、撤权、事务冲突或失效均回滚，不返回授权码；向回调返回 code 只发生在提交成功后。
5. **绑定** 以原样的已选 `tenant_id` 和可选 `workspace_id` 写入授权码，兑换从该码传给 Grant（`oauth_exchange.rs:418–449`，`0268_oauth_persistence.sql:216–268,274–323`）。浏览器外的客户端参数无权替换它们。继续验证 workspace 绑定只收窄（ADR-0035 D-D/D-F），并保留现行 refresh、Grant 生命周期与资源绑定闸。

**错误。** 沿用 [ADR-0130 D7:98–104](0130-bounded-context-modules-ddd-hexagonal.md#L98) 和 `domain::error::ErrorCode`。目标不可见、不在本页、被策略或组拒绝、撤权或没有可选目标时，以 `Forbidden` 结束。有效目标缺权益时为 `EntitlementRequired`。无效登录、CSRF、客户端请求与用户主动拒绝走原有 M02/OAuth 映射；依赖失败走 `DependencyUnavailable`（现 handler 为 503），内部损坏走 `Internal`，并发冲突保留原映射（`oauth_http.rs:563–568,685–728,846–852`）。浏览器不获知其他主体、租户、组或未展示目标的存在。权限失败全部终止，无 `DegradeCode` 成功回退，也无第三种业务错误枚举。

## 实现卡与验收

每卡上限 15 个文件（含测试、迁移 manifest 与目录登记）。任何涉及 U1–U3 的卡待负责人裁定后才可开始。预算含受影响的真实 PG 测试，超出上限先重新拆卡。

| 卡 / 文件预算 | 任务边界与顺序 | 验收与独立注错 |
|---|---|---|
| 策略与组提供方 / ≤15 | U1–U3 后，由获批 owner 提供只读判定、权威版本及撤权排序窄门。获批为不同 owner 时按 owner 各开一张 ≤15 文件卡。 | 真 PG 验证允许与明确拒绝、跨租户隔离、规则版本及唯一写主。分别注错跳过策略、跳过组判断或丢失决策来源，须红，恢复后绿。 |
| 商业权益批量查询 / ≤10 | `commercial` 提供只读批量路径，复用现行 BMO 谓词及快照时点，保留出码用的权益锁门。 | 真 PG 同一批具备有效、缺失、过期及 successor 到期切换样本，失败批次整体拒绝，权益、计费和预留表无写入。注错以默认方案放过无权益、忽略 successor、把不可用作为部分成功，各自红后恢复绿。 |
| 身份候选和原子出码 / ≤15 | 前两张契约已可调用后集成 `identity_access` 端口与 PG 窄门、精确工作区绑定、撤权排序，并登记协作方向。 | 真 PG 比对多个可用租户、同租户 workspace、他人或跨租户目标和非活跃身份/成员。授权码、兑换、Grant 对账同一选择。逐项注错移除会话、tenant membership、workspace membership、策略、组或商业重验，以及将失败回退到 tenant；各自红，恢复后绿。并发夹具在展示和出码之间先提交撤权，验证拒绝且无新码，再验证出码事务与撤权的明确顺序。 |
| 浏览器 consent / ≤12 | 前述卡通过后，把签入选择与出码接到现有 OAuth 路由。 | HTTP 加真 PG 验证显式选择、空候选、签入目标篡改、另一会话复用、同源/CSRF、策略或商业依赖不可用及无回退。分别注错允许未签入目标、取消会话绑定和在依赖失败时默认选租户，各自红，恢复后绿。 |

保留 M02 §8（同一固定版本 :174–183）的 G-M02-5（跨会话或跨站 CSRF）、6（PKCE plain／非 loopback HTTP）、7（code 重放／错误 resource 或 verifier）、8（refresh 重放撤销整 family）、9（Grant 最长时限／epoch）、14（metadata golden，包括适用 URL）原判据。按当前入口跑受影响的全部 OAuth 模式。每卡交付最终 SHA、真 PG 正反例和逐项注错红→恢复绿的 CI 证据，再由独立复核验收。保持现有 HEX 基线。本文只提交 Proposed 设计与编号登记，chooser 产品实现及对应运行验证仍待执行。
