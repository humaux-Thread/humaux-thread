//! `retrieval::handoff` — §25.3 continuity handoff 的**字节域**（G80-31）。
//! Depends-on: crates=[humaux-domain, serde, serde_json, sha2]; services=[]; env=[]; modules=[domain::context::budget_views, retrieval::compiler]
//! Called-by: [adapters::context_repo, adapters::continuity_read, application::continuity, application::recall_read, gateway::context, tests]
//! Invariants: []
//! Spec: §25.3; §57.1
//!
//! §57.1 Phase 8 出场判据前半：「同一 `context_snapshot_seq` 两次装配 handoff 逐字节相同」。
//! 本模块的策略是**类型即比较域**——凡是会让两次装配字节不同的东西，[`Handoff`] 在结构上
//! 就装不下（一个都不许靠"注意不要"）：
//!
//! - 无 supplemental 字段（Qdrant top-k / rerank 非确定）；
//! - 无时间戳（`state_age_seconds` 之类的挂钟量在类型上进不来）；
//! - 无 f32/f64（`fusion_score` 没 derive Serialize，`completeness_ratio` 是 Qdrant 活读）；
//! - 无 HashMap（迭代序随机）；所有 Vec 由 lane 构造器按 `(selector, memory_id)` 预排序；
//! - 内容体不入域（jsonb::text 的渲染跨 PG 版本会漂）——v1 是 **ids + counts 的 manifest**。
//!
//! 序列化唯一入口是 [`Handoff::canonical_bytes`]；快照身份的语义（seq 必要非充分、
//! token 充分）见 [`FrozenSnapshot`] 的字段说明。

use humaux_domain::context::budget_views::MandatoryOverflow;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::compiler::{ContextItem, FrozenLaneRow, FrozenReservation, compile};

/// 字节域里的一条 lane 项：id + 来源 selector + authority 线值。**没有分数、没有内容。**
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HandoffItem {
    /// memory id（uuid 文本）。
    pub memory_id: String,
    /// 哪个 selector 选进来的。
    pub selector: String,
    /// authority 线值（PascalCase 变体名逐字）。
    pub authority: String,
}

/// DOD-093 的 `needs_verification[]` 线格式。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NeedsVerificationWire {
    /// memory id。
    pub memory_id: String,
    /// 哪个 selector 想选它。
    pub selector: String,
    /// 被撤销资格时的 grounding 状态（snake_case）。
    pub state: String,
}

/// 计数块。全 u64/bool——冻结 SQL 的整数，无浮点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HandoffCounts {
    /// mandatory 应有（各可用 selector 独立授权候选集合的并集基数）。
    pub mandatory_expected: u64,
    /// mandatory 实际进入。
    pub mandatory_returned: u64,
    /// 差额。
    pub mandatory_missing: u64,
    /// pinned 应有（独立 COUNT，外部 oracle）。
    pub pinned_expected: u64,
    /// pinned 实际进入。
    pub pinned_returned: u64,
    /// pinned 被排除（低 authority、铸造门分流，或已由 mandatory 吸收），具名清单在顶层块。
    pub pinned_excluded: u64,
    /// §25.5 溢出。true 时 mandatory/pinned 为空、`overflow_manifest` 携带全量 id。
    pub overflow: bool,
}

/// §25.3 handoff——**类型即字节域**（见模块 doc）。
///
/// 字段序即 serde 输出序（struct 按声明序序列化）；改字段顺序就是改字节域，
/// 与改字段一样要过 review。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Handoff {
    /// `pg_snapshot_xmin`——fingerprint 轴（§1.2.1/§16.1），必要非充分。
    pub context_snapshot_seq: i64,
    /// `SHA256(pg_current_snapshot()::text)`——快照身份，「同快照 ⇒ 同字节」的充分条件。
    pub snapshot_token_sha256: String,
    /// §25.4 步骤 2 的产物（已过铸造门 + compile）。
    pub mandatory: Vec<HandoffItem>,
    /// §25.4 步骤 5 的产物。
    pub pinned: Vec<HandoffItem>,
    /// DOD-093：被铸造门分流的行，具名。
    pub needs_verification: Vec<NeedsVerificationWire>,
    /// 快照内不可裁的行（NotJudged——「没判」不许伪装成「判过且通过」）。
    pub not_judged: Vec<String>,
    /// partial-lane：不可用的 selector 与探测出的缺失对象。
    pub unavailable_selectors: Vec<(String, String)>,
    /// §25.5 溢出时的全量 manifest（非溢出为空）。
    pub overflow_manifest: Vec<String>,
    /// 计数。
    pub counts: HandoffCounts,
}

/// Read-only handoff input projected from one authorised PG snapshot by project continuity.
#[derive(Debug)]
pub struct FrozenSnapshot {
    /// Snapshot xmin, the fingerprint axis. Concurrent transactions may share it.
    pub context_snapshot_seq: i64,
    /// Digest of the complete snapshot. This distinguishes snapshots that share xmin.
    pub snapshot_token_sha256: String,
    pub mandatory: Vec<FrozenLaneRow>,
    pub pinned: Vec<FrozenLaneRow>,
    pub mandatory_expected: u64,
    pub pinned_expected: u64,
    pub pinned_excluded: u64,
    pub needs_verification: Vec<NeedsVerificationWire>,
    pub unavailable_selectors: Vec<(String, String)>,
    pub reservation: FrozenReservation,
}

/// Pure projection of a closed snapshot. Implementations keep lane admission,
/// overlap removal, budget reservation, and selector registration with the owner.
pub trait FrozenHandoffRead<B> {
    fn prepare(self, budget: B) -> FrozenSnapshot;
}

/// §25.4 步骤 4–7 → handoff。**单一 compile 真源**：mandatory/pinned 的最终集合来自
/// [`compile`]（G25-1 的被测对象），不是从 lane 直接抄——抄会绕开 G25-1 看守的那一层。
///
/// 溢出（§25.5）不产出条目：`counts.overflow = true`、`overflow_manifest` 全量具名、
/// mandatory/pinned 为空——`MandatoryOverflow` 里没有 Context 可返回，这里也没有。
#[must_use]
pub fn assemble_with_context<B>(
    frozen: impl FrozenHandoffRead<B>,
    budget: B,
) -> (Handoff, crate::compiler::ContextOutcome) {
    let FrozenSnapshot {
        mandatory,
        pinned,
        context_snapshot_seq,
        snapshot_token_sha256,
        mandatory_expected,
        pinned_expected,
        pinned_excluded,
        needs_verification,
        unavailable_selectors,
        reservation,
    } = frozen.prepare(budget);
    let not_judged = not_judged_ids(&mandatory, &pinned);
    let outcome = match reservation {
        Err(overflow) => crate::compiler::ContextOutcome::Overflow(overflow),
        Ok(supplemental_budget) => crate::compiler::ContextOutcome::Compiled(compile(
            mandatory,
            pinned,
            supplemental_budget,
            Vec::new(),
        )),
    };
    let handoff = match &outcome {
        crate::compiler::ContextOutcome::Overflow(overflow) => Handoff {
            context_snapshot_seq,
            snapshot_token_sha256,
            mandatory: Vec::new(),
            pinned: Vec::new(),
            needs_verification,
            not_judged,
            unavailable_selectors,
            overflow_manifest: overflow_manifest(overflow),
            counts: HandoffCounts {
                mandatory_expected,
                mandatory_returned: 0,
                mandatory_missing: mandatory_expected,
                pinned_expected,
                pinned_returned: 0,
                pinned_excluded,
                overflow: true,
            },
        },
        crate::compiler::ContextOutcome::Compiled(compiled) => {
            let mut mandatory = Vec::new();
            let mut pinned = Vec::new();
            for item in compiled.items() {
                match item {
                    ContextItem::Mandatory(row) => {
                        mandatory.push(HandoffItem {
                            memory_id: row.memory_id.0.to_string(),
                            selector: row.registered_name.to_string(),
                            authority: format!("{:?}", row.authority),
                        });
                    }
                    ContextItem::Pinned(row) => {
                        pinned.push(HandoffItem {
                            memory_id: row.memory_id.0.to_string(),
                            selector: row.registered_name.to_string(),
                            authority: format!("{:?}", row.authority),
                        });
                    }
                    ContextItem::Supplemental(_) => {
                        unreachable!("handoff 的字节域不含 supplemental")
                    }
                }
            }
            let mandatory_returned = mandatory.len() as u64;
            let pinned_returned = pinned.len() as u64;
            Handoff {
                context_snapshot_seq,
                snapshot_token_sha256,
                mandatory,
                pinned,
                needs_verification,
                not_judged,
                unavailable_selectors,
                overflow_manifest: Vec::new(),
                counts: HandoffCounts {
                    mandatory_expected,
                    mandatory_returned,
                    mandatory_missing: mandatory_expected.saturating_sub(mandatory_returned),
                    pinned_expected,
                    pinned_returned,
                    pinned_excluded,
                    overflow: false,
                },
            }
        }
    };
    (handoff, outcome)
}
#[must_use]
pub fn assemble<B>(frozen: impl FrozenHandoffRead<B>, budget: B) -> Handoff {
    assemble_with_context(frozen, budget).0
}

fn not_judged_ids(mandatory: &[FrozenLaneRow], pinned: &[FrozenLaneRow]) -> Vec<String> {
    let mut ids = mandatory
        .iter()
        .chain(pinned)
        .filter(|row| row.grounding.state().is_none())
        .map(|row| row.memory_id.0.to_string())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn overflow_manifest(o: &MandatoryOverflow) -> Vec<String> {
    let mut v: Vec<String> = o.manifest().iter().map(|m| m.0.to_string()).collect();
    v.sort_unstable();
    v
}

impl Handoff {
    /// **唯一**序列化入口（G80-31 的比较域）。serde_json 对 struct 按声明序输出，
    /// 本类型无 map、无浮点、Vec 全部预排序——字节由值唯一决定。
    ///
    /// # Panics
    /// serde_json 对本类型不可能失败（无 map key 非串、无 NaN）；失败即内存损坏级别。
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Handoff 的字节域按构造可序列化")
    }

    /// 字节指纹。
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}
