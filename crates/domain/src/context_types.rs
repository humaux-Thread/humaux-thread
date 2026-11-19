//! `domain::context_types` — closed selector identifiers shared by continuity and retrieval.
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: []
//! Invariants: [closed selector set]
//! Spec: Baseline §25.4

/// §25.4 逐字点名的五个确定性 selector。**闭集**——加一个 selector 必须改这里，
/// 编译器会逼所有 `match` 跟着改。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SelectorId {
    /// 任务显式指定的上下文。
    TaskExplicitContextV1,
    /// 项目当前生效的约束。
    ProjectActiveConstraintsV1,
    /// 用户已确认的纠正。
    UserConfirmedCorrectionsV1,
    /// 必须带上的 current-state facet。
    RequiredCurrentStateFacetsV1,
    /// 显式建立的 MANDATORY binding。
    ExplicitMandatoryBindingsV1,
}
