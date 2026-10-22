# tests/fault/ — 注错测试（§53.4）

## 归属闸

**§53.4**「每个 reason 必须有一条注错测试」+ **§53.3 规则2**：
`|DegradeCode 变体| == |DEGRADE_TOTAL 标签基数| == |注错测试数|`，三个数字不
等即红。这个目录就是等式右边「注错测试数」的计数对象。

## 命名规则

```text
tests/fault/<variant_snake_case>.rs
```

文件名 = `lower(fold(变体名))`，与 `DegradeCode` 变体一一对应。当前 12 个
变体 ⇒ 12 个文件。两条注入方式不能从变体名直接读出，登记于 §53.4：

```text
projection_invisible_loss.rs   绕过 retention::tombstone 直接从 Qdrant 删 10 个 point
rerank_provider_timeout.rs     rerank provider 注入读超时
```

其余文件照变体语义注入。**从未被触发过的 reason 不许合并**——加了变体没加
测试，§53.3 规则2 的等式立刻不等，CI 红。

## 每条测试必须断言什么

对注入的故障，断言：

1. `degrade_total{code="<变体名>"}` 恰好 `+1`
2. 响应体 `completeness.degradations[]` 含该变体的**线格式**值（三种映射
   见 §53.2）

用 `humaux_testkit::assert_fault_observed`（见 `crates/testkit/src/lib.rs`）
统一这两条断言，避免每个文件各写一套判定逻辑。

## 真实路径或登记休眠（M01 D4 / G-M01-4，ADR-0077）

"从未被触发过的 reason 不许合并"（§53.4）只有在测试走的是生产代码时才成立。`architecture-check` 的 G-M01-4 把
变体分成两类，两个方向都会红：

```text
有生产 emit 点     非测试代码里有 abstain(<路径>::X, ..) 或 .also(<路径>::X)（限定路径、别名、glob、turbofish 都算）
                   → 本目录里的测试必须驱动发出它的生产函数，文件里不得出现 `abstain` 或 `.also`
                   （当前三个：projection_lag / projection_invisible_loss / lane_substituted，
                    经 retrieval::envelope 的 build_projection_block / dense_lane_substitution）
无生产 emit 点     → 必须是 dormant.toml 的一行（variant + owner 卡 + reason），测试保留合成注入
                   （直接调用 abstain()）；该变体一旦有了 emit 点，这一行必须删掉，账本只减不增
```

新增变体：先看它有没有生产 emit 点；没有就在 `dormant.toml` 加一行并写明哪张卡会加 emit 点。

两条兜底（同一道闸）：生产代码里第一个参数不是变体路径的 `abstain(..)` / `.also(..)`（形参、局部变量、表达式）
无法归属，直接红并指出 file:line；本目录里每个 `*.rs` 必须在 `tests/fault_main.rs` 有相邻的
`#[path = "fault/<stem>.rs"] mod <stem>;`，否则 cargo 根本不编译它。

