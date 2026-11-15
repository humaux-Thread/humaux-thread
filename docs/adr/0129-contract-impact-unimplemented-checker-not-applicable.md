# ADR-0129 — contract-impact：映射到但尚未实现的 mandatory checker 判 `not_applicable` 并点名交付卡

- 状态：Accepted (2026-11-15)
- 日期：2026-11-15
- 关联：Baseline §80.3（contract-impact 闭包）、§57.1 第 2/3 条（三态 `pass` / `fail` / `not_applicable`）、§80.1（闸的准入条件）、§46「Main branch 不允许红」
- 前例：ADR-0004（§80.3 承重块 7 → 9；被测对象未交付时打印 `NOT_APPLICABLE … missing object`）、ADR-0005（跳过 ≠ 通过）、ADR-0006（`not_applicable` 的条件不得与闸要抓的违规状态重合）
- 决定者：主控工程裁决（2026-11-15），依据 owner 的工程授权（memory `ea1553f1`，2026-10-19「需要问我的问题，你基本上已经问了」＋「只有红线事项才问 owner」）；owner 对「未实现 checker 判红还是 `not_applicable`」**没有逐字裁决**（历史检索结论见 H1 §A④，UNKNOWN）
- 影响面：**只补 ADR 与 spec 文字。不改任何判红条件，不改代码，不改 `xtask` 行为。**

## 背景

`docs/architecture/Baseline_2.9.md:16397`（§80.3 步骤 4）自 §80.3 第一次带入本仓（`d8e8ff94`，2026-08-25）起只有一种写法：

```text
4. checker 自己未执行 / skipped / no_data -> 红（Phase 0 明确允许的 no_data 例外需由 checker 自己声明）；
```

这段文字覆盖的是「checker 存在、这次没被跑到」，没有任何「checker 本体还没实现」的例外；同章
`:16430-16446` 的 G80-42 注错 A–D 也全部只覆盖「已实现 checker 缺席」。只读步骤 4 的人因此必然把
未实现的 checker 判红（2026-11-15 的 independent-707 P2 F2 正是这样读的）。

实现从 T0.15 起一直是两层，不是二选一：

| 层 | 状态 | 判据 | 原文 |
|---|---|---|---|
| 已实现 | `Implemented(&'static str)` | 这次 CI 清单里没跑 → **红** | `xtask/src/contract_impact.rs:323-326`、`:330`；§80.3 步骤 4（`:16397`） |
| 未实现 | `NotImplemented(&'static str)` | **结构性 `not_applicable`**，载荷是交付卡 | `xtask/src/contract_impact.rs:342-362`、`:388-390`；§57.1 第 2 条（`:12015`） |

T0.15 的落地提交 `f6025662`（2026-08-26，p0-wave2）正文写「All gates three-state; metrics-registry
default-mode exit 0 with NA listing missing objects」，`:323-326` 的注释逐字给出理由：「未实现 -> 结构性
`not_applicable`，不算这次 PR 的责任（§80.3 步骤 4 的『checker 自己未执行』不适用于本来就不存在的
checker）」。`default_checker_kind`（`:342-362`）把 G80-18 → M22、G80-46 → M14、`mcp-contract-lock` → M26
映射成「未实现 + 交付卡」，其余落到 `UNASSIGNED_OWNER`（`:334`）；`:388-390` 的 NA 文案固定包含
`missing object: checker <id> not implemented yet … owning card: <card>`。测试 `:1040`、
`:1067-1083` 钉住两件事：NA 行不许被从闭包报告里丢掉，文案必须点名交付卡。

同一语义在 ADR 与模块设计里各有一处落点：ADR-0004 §6（`docs/adr/0004-baseline-2.9-grounding-merge.md:103-116`）
把「被测对象未交付 → 打印 `NOT_APPLICABLE … missing object`」定为合法做法并明确反对「伪装通过」；
M24-5（PR #48 / `3c9e7c40`，merge `a2388bc2`，green run 38693872152）只把 owning card 写进 NA 文案，
保留 NA 语义。§57.1 第 3 条（`:12016`）说明「main 不允许红」只有在这套三态下才成立。

**偏离在 spec 文本这一侧，不在代码：** §80.3 步骤 4 从未把「未实现」例外写进正文，也没有任何 ADR 记录
这条裁决。本 ADR 补的是文字，不补行为。

## 决定

contract-impact 的 mandatory checker 判据是**两层**的，两条同时成立：

1. **已实现的 mandatory checker 未执行 / skipped / no_data → 红。** §80.3 步骤 4 的现行文字（`:16397`）
   原样保留，本节不改写它、不加宽它；`no_data` 的例外仍必须由 checker 自己声明。
2. **映射到、但尚未实现的 checker → `not_applicable`，且必须打印缺失的 checker id 与交付卡。**
   依据是 §57.1 第 2 条：`not_applicable` 的唯一合法理由是「被测对象在当前 Phase 尚未交付」，且必须
   打印缺失对象名；在这里被测对象就是 checker 本体，checker id 即缺失对象名，交付卡即 §57.1 要求的
   责任落点。缺其中任何一项就退化成「扫不到当通过」（§57.1 第 2 条、ADR-0005）。

两条不冲突：ADR-0006 禁止「NA 条件与闸要抓的违规状态重合」。步骤 4 要抓的是「存在却未执行」，
本 ADR 的 NA 主语是「本体不存在」；两者互斥，不构成自我豁免。

**Baseline 的对应改动只有一句：** §80.3 步骤 4 之后追加一句例外并引本 ADR（`Baseline_2.9.md:16398`）。
判红条件（步骤 3、步骤 4 本身）一字未动。

## 未取的替代方案

- **把未实现的 checker 判红。** 会让 Phase 0 的 main 在每个触及承重块的 PR 上必红，正是 §57.1 第 3 条
  点名的失效模式（「第一个 PR 就没有合法的绿法，结果一定是有人把这几项注释掉」）。要选它，改的是代码，
  且必须先改 §57.1，不是本 ADR。
- **静默跳过未实现的 checker。** ADR-0005 已否决：没有被测对象时，跳过与通过长得一模一样。
- **把未实现的 checker 从 impact-map 行里删掉。** T0.15 的原始理由之一就是不许漏报——map 行本身必须留着，
  否则 block 变更会从闭包里静默消失。

## 后果

- 只读 §80.3 的人不再必然判红：步骤 4 之后的一句例外把他们指向本 ADR，两层的完整判据不再只存在于代码注释里。
- 闸的强度不变：已实现 checker 缺席仍红；NA 文案必须同时含 checker id 与交付卡；`UNASSIGNED_OWNER` 的
  checker 也不得静默（文案会打印 `none registered (add it to default_checker_kind)`）。
- 未实现清单随交付缩短，不是永久豁免：某个 checker 一旦实现，必须同时改 `default_checker_kind`
  （`Implemented(...)`）并进 CI 清单，否则 `not_applicable` 会掩盖一个「已实现却没跑」的真违规——这正是
  步骤 4 仍然管的那一层。
- 本 ADR 不新增闸、不改 gate 注册表、不产生代码 diff；证据级止于文档与原文行号核对。
