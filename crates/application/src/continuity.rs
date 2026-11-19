//! `application::continuity` — §25.3 continuity 产品的装配入口（G80-31 的被测调用路径）。
//! Depends-on: crates=[async-trait, hex, humaux-domain, humaux-retrieval, serde, serde_json, sha2, uuid]; services=[]; env=[]; modules=[domain::context, domain::continuity, domain::error, domain::ids, retrieval::compiler, retrieval::envelope, retrieval::handoff]
//! Called-by: [adapters::context_repo, adapters::continuity_read, adapters::continuity_repo, gateway::bootstrap, gateway::continuity, gateway::mcp_application, tests]
//! Invariants: [facet_completeness is the one FACET_COMPLETE predicate: only ContinuityStatus::Current covers a
//!   required facet, and an empty required profile fails closed (§22.0, ADR-0110 D-D)]
//! Spec: §25.3; §25.3.1; §22.2; §22.0; ADR-0110
//!
//! 端口反转的原因是依赖方向：`adapters` 依赖本 crate（不能反过来 import
//! `adapters::context_repo`），所以取数以 [`ContextReadPort`] 注入——`adapters` 侧实现它、
//! 委托 `context_repo::fetch_frozen`。先例：[`crate::consolidate::PrivateReasoningPort`]。
//!
//! 装配本体是纯函数（[`humaux_retrieval::handoff::assemble`]）：本函数只做「取冻结读数 →
//! 装配」两步，**收不到时钟、收不到连接**——G80-31「同一快照两次装配逐字节相同」的
//! application 侧保证就是这个签名形状。

use humaux_domain::context::{ContextBudget, FrozenReads, MandatoryRow, SelectorId, spec};
use humaux_domain::continuity::{
    ContinuityFacetKind, ContinuityPublishResult, ContinuityPublishState, ProjectId,
};
use humaux_domain::error::{ConflictReason, ErrorCode};
use humaux_domain::ids::{Scope, WorkspaceId};
use humaux_retrieval::compiler::FrozenLaneRow;
use humaux_retrieval::envelope::FrozenGrounding;
use humaux_retrieval::handoff::{FrozenHandoffRead, FrozenSnapshot, Handoff, assemble};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Projects the owner's admitted lanes without reopening the captured snapshot.
pub struct ClosedFrozenReads(pub FrozenReads);

impl FrozenHandoffRead<ContextBudget> for ClosedFrozenReads {
    fn prepare(self, budget: ContextBudget) -> FrozenSnapshot {
        let FrozenReads {
            mandatory,
            pinned,
            context_snapshot_seq,
            snapshot_token_sha256,
        } = self.0;
        let pinned = pinned.excluding_mandatory(&mandatory);
        let reservation = budget.reserve(&mandatory, &pinned).map(Into::into);
        FrozenSnapshot {
            context_snapshot_seq,
            snapshot_token_sha256,
            mandatory_expected: mandatory.expected(),
            pinned_expected: pinned.expected(),
            pinned_excluded: pinned.excluded().len() as u64,
            needs_verification: mandatory
                .needs_verification()
                .iter()
                .map(|nv| (*nv, selector_wire(nv.selector)))
                .collect(),
            unavailable_selectors: mandatory
                .unavailable()
                .iter()
                .map(|(id, missing)| (selector_wire(*id).to_string(), missing.clone()))
                .collect(),
            mandatory: mandatory
                .into_parts()
                .1
                .into_iter()
                .map(freeze_row)
                .collect(),
            pinned: pinned.into_rows().into_iter().map(freeze_row).collect(),
            reservation,
        }
    }
}

/// Read the registered name from the one selector registry. The slot identifier
/// for the task selector deliberately survives the retired v1 wire registration.
const fn selector_wire(id: SelectorId) -> &'static str {
    spec(id).registered_name
}

fn freeze_row(row: MandatoryRow) -> FrozenLaneRow {
    FrozenLaneRow {
        memory_id: row.memory_id(),
        selector: row.selector(),
        registered_name: selector_wire(row.selector()),
        authority: row.authority(),
        source_authority: row.source_authority(),
        est_tokens: row.est_tokens(),
        grounding: FrozenGrounding::from_snapshot(row.grounding_state()),
    }
}

/// §25.4 冻结读数的取数端口。实现方：`adapters`（`context_repo::fetch_frozen`，
/// 单 REPEATABLE READ 事务）。
#[async_trait::async_trait]
pub trait ContextReadPort: Send + Sync {
    /// 单快照取齐 §25.4 步骤 2/5 的全部读数与快照身份。
    async fn fetch_frozen(&self, scope: &Scope) -> Result<FrozenReads, ErrorCode>;
}

/// §25.3：装配一份 continuity handoff。
///
/// `budget` 由调用方从上层配置传入（§78.1：domain/application 不内置默认值——
/// 默认值就是第二真源）。
///
/// # Errors
/// 取数失败原样上抛；装配本体不失败（溢出是 [`Handoff`] 里的一个如实状态，不是错误）。
pub async fn assemble_handoff(
    port: &dyn ContextReadPort,
    scope: &Scope,
    budget: ContextBudget,
) -> Result<Handoff, ErrorCode> {
    let frozen = port.fetch_frozen(scope).await?;
    Ok(assemble(ClosedFrozenReads(frozen), budget))
}

/// W2 adapter port. The implementation owns the single read-only RR transaction and returns
/// only a closed snapshot; application assembly cannot perform another read.
#[async_trait::async_trait]
pub trait ContinuityReadPort: Send + Sync {
    type Authorization: Sync;

    async fn read_snapshot(
        &self,
        authorization: &Self::Authorization,
        project_id: ProjectId,
        requested_workspace: Option<WorkspaceId>,
        budget: ContextBudget,
    ) -> Result<ClosedContinuitySnapshot, ErrorCode>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityStatus {
    Current,
    Missing,
    Unavailable,
    Stale,
    Conflicted,
}

impl ContinuityStatus {
    const fn tag(self) -> u8 {
        match self {
            Self::Current => 1,
            Self::Missing => 2,
            Self::Unavailable => 3,
            Self::Stale => 4,
            Self::Conflicted => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiagnosticCode {
    NoCurrentVersion,
    AuthoritativeSourceUnavailable,
    VisibilityRevalidationFailed,
    SourceRevalidationFailed,
    StoredStale,
    UnresolvedSemanticConflict,
}

impl DiagnosticCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoCurrentVersion => "NO_CURRENT_VERSION",
            Self::AuthoritativeSourceUnavailable => "AUTHORITATIVE_SOURCE_UNAVAILABLE",
            Self::VisibilityRevalidationFailed => "VISIBILITY_REVALIDATION_FAILED",
            Self::SourceRevalidationFailed => "SOURCE_REVALIDATION_FAILED",
            Self::StoredStale => "STORED_STALE",
            Self::UnresolvedSemanticConflict => "UNRESOLVED_SEMANTIC_CONFLICT",
        }
    }
}

/// A CURRENT payload whose body/hash/source closure was verified inside the adapter's RR.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedCurrentFacet {
    facet_version_id: Uuid,
    facet_version: u64,
    body: Value,
    body_sha256: [u8; 32],
    memory_source_ids: Vec<Uuid>,
    evidence_source_ids: Vec<Uuid>,
}

impl VerifiedCurrentFacet {
    /// Constructs a current facet only after binding the exact PostgreSQL `jsonb::text` bytes
    /// to the stored database digest. Parsing happens after that check, so no caller can pair an
    /// arbitrary [`Value`] with an unrelated hash or redefine the database canonical bytes.
    pub fn from_authoritative_jsonb_text(
        facet_version_id: Uuid,
        facet_version: i64,
        body_text: String,
        body_sha256: [u8; 32],
        memory_source_ids: Vec<Uuid>,
        evidence_source_ids: Vec<Uuid>,
    ) -> Result<Self, ErrorCode> {
        let facet_version = u64::try_from(facet_version)
            .ok()
            .filter(|version| *version > 0)
            .ok_or(ErrorCode::CannotEstablishCompleteness)?;
        if facet_version_id.is_nil()
            || memory_source_ids.iter().any(Uuid::is_nil)
            || evidence_source_ids.iter().any(Uuid::is_nil)
        {
            return Err(ErrorCode::CannotEstablishCompleteness);
        }
        let computed_body_sha256: [u8; 32] = Sha256::digest(body_text.as_bytes()).into();
        if computed_body_sha256 != body_sha256 {
            return Err(ErrorCode::CannotEstablishCompleteness);
        }
        let body =
            serde_json::from_str(&body_text).map_err(|_| ErrorCode::CannotEstablishCompleteness)?;
        if memory_source_ids
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
            || evidence_source_ids
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(ErrorCode::CannotEstablishCompleteness);
        }
        Ok(Self {
            facet_version_id,
            facet_version,
            body,
            body_sha256,
            memory_source_ids,
            evidence_source_ids,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SourceFacetState {
    Missing,
    Current(VerifiedCurrentFacet),
    Stale(DiagnosticCode),
    Conflicted,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SourceFacetInput {
    pub kind: ContinuityFacetKind,
    pub state: SourceFacetState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClosedContinuitySnapshot {
    pub project_id: ProjectId,
    pub facets: [SourceFacetInput; 15],
    pub handoff: Handoff,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CurrentFacetWire {
    facet_version_id: String,
    facet_version: u64,
    body: Value,
    body_sha256: String,
    memory_source_ids: Vec<String>,
    evidence_source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CurrentSourceFacetWire {
    kind: &'static str,
    mode: &'static str,
    status: ContinuityStatus,
    current: CurrentFacetWire,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NonCurrentSourceFacetWire {
    kind: &'static str,
    mode: &'static str,
    status: ContinuityStatus,
    diagnostic_code: DiagnosticCode,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DerivedFacetWire {
    kind: &'static str,
    mode: &'static str,
    status: ContinuityStatus,
    payload_ref: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ContinuityFacetWire {
    Current(CurrentSourceFacetWire),
    NonCurrent(NonCurrentSourceFacetWire),
    Derived(DerivedFacetWire),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletenessClass {
    FacetComplete,
    CannotEstablish,
}

impl CompletenessClass {
    const fn tag(&self) -> u8 {
        match self {
            Self::FacetComplete => 1,
            Self::CannotEstablish => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContinuityCoverage {
    required: u8,
    current: u8,
    missing: u8,
    unavailable: u8,
    stale: u8,
    conflicted: u8,
    ratio: f64,
    completeness_class: CompletenessClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContinuitySnapshotWire {
    context_snapshot_seq: i64,
    snapshot_token_sha256: String,
    result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContinuityResult {
    contract_version: &'static str,
    project_id: String,
    snapshot: ContinuitySnapshotWire,
    facets: Vec<ContinuityFacetWire>,
    handoff: Handoff,
    coverage: ContinuityCoverage,
}

/// Runs the application use case and builds the exact W0 wire result after the adapter has
/// committed its one closed RR snapshot.
pub async fn read_project_continuity<Authorization: Sync>(
    port: &dyn ContinuityReadPort<Authorization = Authorization>,
    authorization: &Authorization,
    project_id: ProjectId,
    requested_workspace: Option<WorkspaceId>,
    budget: ContextBudget,
) -> Result<ContinuityResult, ErrorCode> {
    let closed = port
        .read_snapshot(authorization, project_id, requested_workspace, budget)
        .await?;
    assemble_continuity_result(closed)
}

pub const W2_FORCED_UNAVAILABLE: [ContinuityFacetKind; 6] = [
    ContinuityFacetKind::ActiveTasks,
    ContinuityFacetKind::RecentChanges,
    ContinuityFacetKind::Code,
    ContinuityFacetKind::Tests,
    ContinuityFacetKind::Config,
    ContinuityFacetKind::Migrations,
];

fn unavailable_in_w2(kind: ContinuityFacetKind) -> bool {
    W2_FORCED_UNAVAILABLE.contains(&kind)
}

/// U5 fallback required-facet profile (ADR-0110 :150-151): the §25.3.1 SOURCE_BACKED set minus
/// [`W2_FORCED_UNAVAILABLE`], in [`ContinuityFacetKind::ALL`] order.
// ponytail: U5 fallback profile (ADR-0110 :150-151); M14 declares the real required-facet profile and switches the brief coverage line to it
pub fn fallback_required_facets() -> Vec<ContinuityFacetKind> {
    ContinuityFacetKind::ALL
        .into_iter()
        .filter(|kind| !unavailable_in_w2(*kind))
        .collect()
}

/// [`facet_completeness`] verdict (§22.2, ADR-0110 D-D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetCompleteness {
    /// `FacetComplete` iff the required profile is non-empty and every required facet is covered,
    /// else `CannotEstablish` (§22.0: no unproven completeness claim).
    pub class: CompletenessClass,
    /// Required facets whose slot is `Current`.
    pub covered: u8,
    /// Distinct facets in the required profile.
    pub required: u8,
    /// Required facets that are not covered, in [`ContinuityFacetKind::ALL`] order.
    pub missing: Vec<ContinuityFacetKind>,
}

/// §22.2 FACET_COMPLETE over a snapshot's slot states (ADR-0110 D-D). Pure: the caller supplies the
/// required profile; no clock, no I/O.
///
/// Only [`ContinuityStatus::Current`] covers a facet: `Missing`, `Unavailable`, `Stale`,
/// `Conflicted` and a required facet absent from `slots` never do, and a kind listed twice is
/// covered only if every entry is `Current`. An empty profile is `CannotEstablish` (§22.0).
pub fn facet_completeness(
    slots: &[(ContinuityFacetKind, ContinuityStatus)],
    required: &[ContinuityFacetKind],
) -> FacetCompleteness {
    let covered_kind = |kind: ContinuityFacetKind| {
        let mut states = slots
            .iter()
            .filter(|(slot, _)| *slot == kind)
            .map(|(_, status)| *status);
        states.next() == Some(ContinuityStatus::Current)
            && states.all(|status| status == ContinuityStatus::Current)
    };
    let wanted: Vec<ContinuityFacetKind> = ContinuityFacetKind::ALL
        .into_iter()
        .filter(|kind| required.contains(kind))
        .collect();
    let missing: Vec<ContinuityFacetKind> = wanted
        .iter()
        .copied()
        .filter(|kind| !covered_kind(*kind))
        .collect();
    let class = if wanted.is_empty() || !missing.is_empty() {
        CompletenessClass::CannotEstablish
    } else {
        CompletenessClass::FacetComplete
    };
    // `wanted` is a subset of the 15-kind closed set, so the conversions cannot saturate.
    FacetCompleteness {
        class,
        covered: u8::try_from(wanted.len().saturating_sub(missing.len())).unwrap_or(u8::MAX),
        required: u8::try_from(wanted.len()).unwrap_or(u8::MAX),
        missing,
    }
}

fn source_wire(input: SourceFacetInput) -> ContinuityFacetWire {
    let kind = input.kind.as_str();
    if unavailable_in_w2(input.kind) {
        return ContinuityFacetWire::NonCurrent(NonCurrentSourceFacetWire {
            kind,
            mode: "SOURCE_BACKED",
            status: ContinuityStatus::Unavailable,
            diagnostic_code: DiagnosticCode::AuthoritativeSourceUnavailable,
        });
    }
    match input.state {
        SourceFacetState::Missing => ContinuityFacetWire::NonCurrent(NonCurrentSourceFacetWire {
            kind,
            mode: "SOURCE_BACKED",
            status: ContinuityStatus::Missing,
            diagnostic_code: DiagnosticCode::NoCurrentVersion,
        }),
        SourceFacetState::Stale(diagnostic_code) => {
            ContinuityFacetWire::NonCurrent(NonCurrentSourceFacetWire {
                kind,
                mode: "SOURCE_BACKED",
                status: ContinuityStatus::Stale,
                diagnostic_code,
            })
        }
        SourceFacetState::Conflicted => {
            ContinuityFacetWire::NonCurrent(NonCurrentSourceFacetWire {
                kind,
                mode: "SOURCE_BACKED",
                status: ContinuityStatus::Conflicted,
                diagnostic_code: DiagnosticCode::UnresolvedSemanticConflict,
            })
        }
        SourceFacetState::Current(current) => {
            ContinuityFacetWire::Current(CurrentSourceFacetWire {
                kind,
                mode: "SOURCE_BACKED",
                status: ContinuityStatus::Current,
                current: CurrentFacetWire {
                    facet_version_id: current.facet_version_id.to_string(),
                    facet_version: current.facet_version,
                    body: current.body,
                    body_sha256: hex::encode(current.body_sha256),
                    memory_source_ids: current
                        .memory_source_ids
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect(),
                    evidence_source_ids: current
                        .evidence_source_ids
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect(),
                },
            })
        }
    }
}

fn status_of(facet: &ContinuityFacetWire) -> ContinuityStatus {
    match facet {
        ContinuityFacetWire::Current(value) => value.status,
        ContinuityFacetWire::NonCurrent(value) => value.status,
        ContinuityFacetWire::Derived(value) => value.status,
    }
}

fn assemble_continuity_result(
    closed: ClosedContinuitySnapshot,
) -> Result<ContinuityResult, ErrorCode> {
    if closed.project_id.0.is_nil()
        || closed
            .facets
            .iter()
            .zip(ContinuityFacetKind::ALL)
            .any(|(input, expected)| input.kind != expected)
        || closed.handoff.context_snapshot_seq < 0
    {
        return Err(ErrorCode::CannotEstablishCompleteness);
    }
    let source: Vec<ContinuityFacetWire> = closed.facets.into_iter().map(source_wire).collect();
    // §22.2: slot kinds were checked equal to `ALL` above; statuses are the wire statuses
    // (W2 forced-unavailable included), so the verdict is exactly "all 15 source facets Current".
    let slots: Vec<(ContinuityFacetKind, ContinuityStatus)> = ContinuityFacetKind::ALL
        .into_iter()
        .zip(source.iter().map(status_of))
        .collect();
    let facet_complete = facet_completeness(&slots, &ContinuityFacetKind::ALL).class
        == CompletenessClass::FacetComplete;
    let mut source = source.into_iter();
    let mut facets = Vec::with_capacity(17);
    facets.extend(source.by_ref().take(13));
    facets.push(ContinuityFacetWire::Derived(DerivedFacetWire {
        kind: "HANDOFF",
        mode: "SYSTEM_DERIVED",
        status: ContinuityStatus::Current,
        payload_ref: "#/handoff",
    }));
    facets.extend(source);

    let mut counts = [0u8; 5];
    for facet in &facets {
        let index = usize::from(status_of(facet).tag() - 1);
        counts[index] = counts[index].checked_add(1).ok_or(ErrorCode::Internal)?;
    }
    // COVERAGE is itself a successfully derived CURRENT facet.
    counts[0] = counts[0].checked_add(1).ok_or(ErrorCode::Internal)?;
    let accounted = counts
        .iter()
        .try_fold(0u8, |sum, value| sum.checked_add(*value))
        .ok_or(ErrorCode::Internal)?;
    if accounted != 17 {
        return Err(ErrorCode::CannotEstablishCompleteness);
    }
    let completeness_class = if facet_complete && !closed.handoff.counts.overflow {
        CompletenessClass::FacetComplete
    } else {
        CompletenessClass::CannotEstablish
    };
    let coverage = ContinuityCoverage {
        required: 17,
        current: counts[0],
        missing: counts[1],
        unavailable: counts[2],
        stale: counts[3],
        conflicted: counts[4],
        ratio: f64::from(counts[0]) / 17.0,
        completeness_class,
    };
    facets.push(ContinuityFacetWire::Derived(DerivedFacetWire {
        kind: "COVERAGE",
        mode: "SYSTEM_DERIVED",
        status: ContinuityStatus::Current,
        payload_ref: "#/coverage",
    }));

    let snapshot_token = parse_hex_digest(&closed.handoff.snapshot_token_sha256)?;
    let result_sha256 = continuity_result_sha256(
        closed.project_id,
        closed.handoff.context_snapshot_seq,
        snapshot_token,
        &facets,
        closed.handoff.sha256(),
        &coverage,
    )?;
    Ok(ContinuityResult {
        contract_version: "1",
        project_id: closed.project_id.0.to_string(),
        snapshot: ContinuitySnapshotWire {
            context_snapshot_seq: closed.handoff.context_snapshot_seq,
            snapshot_token_sha256: closed.handoff.snapshot_token_sha256.clone(),
            result_sha256: hex::encode(result_sha256),
        },
        facets,
        handoff: closed.handoff,
        coverage,
    })
}

fn parse_hex_digest(value: &str) -> Result<[u8; 32], ErrorCode> {
    let bytes = hex::decode(value).map_err(|_| ErrorCode::Internal)?;
    bytes.try_into().map_err(|_| ErrorCode::Internal)
}

fn push_diagnostic(
    bytes: &mut Vec<u8>,
    diagnostic: Option<DiagnosticCode>,
) -> Result<(), ErrorCode> {
    let Some(diagnostic) = diagnostic else {
        bytes.push(0);
        return Ok(());
    };
    let diagnostic = diagnostic.as_str().as_bytes();
    let length = u16::try_from(diagnostic.len()).map_err(|_| ErrorCode::Internal)?;
    bytes.push(1);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(diagnostic);
    Ok(())
}

fn push_ids(bytes: &mut Vec<u8>, ids: &[String]) -> Result<(), ErrorCode> {
    let count = u32::try_from(ids.len()).map_err(|_| ErrorCode::Internal)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for id in ids {
        let id = Uuid::parse_str(id).map_err(|_| ErrorCode::Internal)?;
        bytes.extend_from_slice(id.as_bytes());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn continuity_result_sha256(
    project_id: ProjectId,
    context_snapshot_seq: i64,
    snapshot_token_sha256: [u8; 32],
    facets: &[ContinuityFacetWire],
    handoff_sha256: [u8; 32],
    coverage: &ContinuityCoverage,
) -> Result<[u8; 32], ErrorCode> {
    let seq = u64::try_from(context_snapshot_seq).map_err(|_| ErrorCode::Internal)?;
    if facets.len() != 17 {
        return Err(ErrorCode::Internal);
    }
    let mut bytes = b"humaux.continuity.result.v1\0".to_vec();
    bytes.extend_from_slice(project_id.0.as_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(&snapshot_token_sha256);
    for (index, facet) in facets.iter().enumerate() {
        bytes.push(u8::try_from(index + 1).map_err(|_| ErrorCode::Internal)?);
        match facet {
            ContinuityFacetWire::Current(value) => {
                bytes.extend_from_slice(&[1, ContinuityStatus::Current.tag()]);
                push_diagnostic(&mut bytes, None)?;
                let version_id = Uuid::parse_str(&value.current.facet_version_id)
                    .map_err(|_| ErrorCode::Internal)?;
                bytes.extend_from_slice(version_id.as_bytes());
                bytes.extend_from_slice(&value.current.facet_version.to_be_bytes());
                bytes.extend_from_slice(&parse_hex_digest(&value.current.body_sha256)?);
                push_ids(&mut bytes, &value.current.memory_source_ids)?;
                push_ids(&mut bytes, &value.current.evidence_source_ids)?;
            }
            ContinuityFacetWire::NonCurrent(value) => {
                bytes.extend_from_slice(&[1, value.status.tag()]);
                push_diagnostic(&mut bytes, Some(value.diagnostic_code))?;
            }
            ContinuityFacetWire::Derived(value) => {
                bytes.extend_from_slice(&[2, value.status.tag()]);
                push_diagnostic(&mut bytes, None)?;
                bytes.push(match value.payload_ref {
                    "#/handoff" => 1,
                    "#/coverage" => 2,
                    _ => return Err(ErrorCode::Internal),
                });
            }
        }
    }
    bytes.extend_from_slice(&handoff_sha256);
    bytes.extend_from_slice(&[
        coverage.required,
        coverage.current,
        coverage.missing,
        coverage.unavailable,
        coverage.stale,
        coverage.conflicted,
        coverage.completeness_class.tag(),
    ]);
    Ok(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod w2_tests {
    use super::*;
    use humaux_retrieval::handoff::{HandoffCounts, HandoffItem};

    fn id(value: &str) -> Uuid {
        Uuid::parse_str(value).expect("fixed UUID")
    }

    fn handoff() -> Handoff {
        Handoff {
            context_snapshot_seq: 42,
            snapshot_token_sha256:
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            mandatory: vec![HandoffItem {
                memory_id: "018f0000-0000-7000-8000-000000000010".into(),
                selector: "project_active_constraints_v1".into(),
                authority: "ProjectConstraint".into(),
            }],
            pinned: Vec::new(),
            needs_verification: Vec::new(),
            not_judged: Vec::new(),
            unavailable_selectors: Vec::new(),
            overflow_manifest: Vec::new(),
            counts: HandoffCounts {
                mandatory_expected: 1,
                mandatory_returned: 1,
                mandatory_missing: 0,
                pinned_expected: 0,
                pinned_returned: 0,
                pinned_excluded: 0,
                overflow: false,
            },
        }
    }

    fn closed_snapshot() -> ClosedContinuitySnapshot {
        let body = r#"{"a": 1, "b": [2, 3]}"#.to_owned();
        let body_sha256 = Sha256::digest(body.as_bytes()).into();
        let current = VerifiedCurrentFacet::from_authoritative_jsonb_text(
            id("018f0000-0000-7000-8000-000000000020"),
            1,
            body,
            body_sha256,
            vec![id("018f0000-0000-7000-8000-000000000030")],
            vec![id("018f0000-0000-7000-8000-000000000040")],
        )
        .expect("closed current facet");
        let mut current = Some(current);
        ClosedContinuitySnapshot {
            project_id: ProjectId(id("018f0000-0000-7000-8000-000000000001")),
            facets: std::array::from_fn(|index| SourceFacetInput {
                kind: ContinuityFacetKind::ALL[index],
                state: if index == 0 {
                    SourceFacetState::Current(current.take().expect("one current facet"))
                } else {
                    SourceFacetState::Missing
                },
            }),
            handoff: handoff(),
        }
    }

    #[test]
    fn authoritative_body_and_order_are_unforgeable() {
        let body = r#"{"value": 1}"#.to_owned();
        let hash: [u8; 32] = Sha256::digest(body.as_bytes()).into();
        assert!(
            VerifiedCurrentFacet::from_authoritative_jsonb_text(
                id("018f0000-0000-7000-8000-000000000020"),
                1,
                body.clone(),
                [0; 32],
                Vec::new(),
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            VerifiedCurrentFacet::from_authoritative_jsonb_text(
                id("018f0000-0000-7000-8000-000000000020"),
                1,
                body,
                hash,
                vec![
                    id("018f0000-0000-7000-8000-000000000032"),
                    id("018f0000-0000-7000-8000-000000000031"),
                ],
                Vec::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn fixed_result_has_exact_order_partition_and_zero_leak() {
        let result = assemble_continuity_result(closed_snapshot()).expect("closed result");
        let kinds = result
            .facets
            .iter()
            .map(|facet| match facet {
                ContinuityFacetWire::Current(value) => value.kind,
                ContinuityFacetWire::NonCurrent(value) => value.kind,
                ContinuityFacetWire::Derived(value) => value.kind,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                "GOAL",
                "CURRENT_STATE",
                "DECISIONS",
                "REJECTIONS",
                "CONSTRAINTS",
                "KNOWN_ISSUES",
                "NEXT_ACTIONS",
                "ACTIVE_TASKS",
                "RECENT_CHANGES",
                "CODE",
                "TESTS",
                "CONFIG",
                "MIGRATIONS",
                "HANDOFF",
                "PROCEDURES",
                "OUTCOMES",
                "COVERAGE",
            ]
        );
        assert_eq!(result.coverage.current, 3);
        assert_eq!(result.coverage.missing, 8);
        assert_eq!(result.coverage.unavailable, 6);
        assert_eq!(result.coverage.stale, 0);
        assert_eq!(result.coverage.conflicted, 0);
        assert_eq!(
            result.coverage.completeness_class,
            CompletenessClass::CannotEstablish
        );
        let wire = serde_json::to_value(&result).expect("serializable result");
        for facet in wire["facets"].as_array().expect("facet array") {
            if facet["status"] != "CURRENT" {
                assert!(facet.get("current").is_none());
                assert!(facet.get("body").is_none());
                assert!(facet.get("body_sha256").is_none());
                assert!(facet.get("memory_source_ids").is_none());
                assert!(facet.get("evidence_source_ids").is_none());
            }
        }
    }

    fn recompute(result: &ContinuityResult) -> String {
        hex::encode(
            continuity_result_sha256(
                ProjectId(id(&result.project_id)),
                result.snapshot.context_snapshot_seq,
                parse_hex_digest(&result.snapshot.snapshot_token_sha256).expect("snapshot digest"),
                &result.facets,
                result.handoff.sha256(),
                &result.coverage,
            )
            .expect("hash view"),
        )
    }

    #[test]
    fn result_hash_v1_golden_and_self_omission() {
        let mut result = assemble_continuity_result(closed_snapshot()).expect("closed result");
        assert_eq!(
            result.snapshot.result_sha256,
            "61b906b7b32b6c5bbfae20e73706ab2be506230e5a24f9e6955e0085e47e879c"
        );
        let original = result.snapshot.result_sha256.clone();
        result.snapshot.result_sha256 =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
        assert_eq!(recompute(&result), original);
    }

    #[test]
    fn every_hash_view_semantic_mutation_changes_digest() {
        type Mutation = (&'static str, fn(&mut ContinuityResult));
        let mutations: [Mutation; 20] = [
            ("project", |result| {
                result.project_id = "018f0000-0000-7000-8000-000000000002".into();
            }),
            ("sequence", |result| {
                result.snapshot.context_snapshot_seq += 1
            }),
            ("snapshot token", |result| {
                result.snapshot.snapshot_token_sha256 = "22".repeat(32);
            }),
            ("facet ordinal", |result| result.facets.swap(0, 1)),
            ("mode", |result| {
                result.facets[1] = ContinuityFacetWire::Derived(DerivedFacetWire {
                    kind: "CURRENT_STATE",
                    mode: "SYSTEM_DERIVED",
                    status: ContinuityStatus::Current,
                    payload_ref: "#/handoff",
                });
            }),
            ("status", |result| {
                let ContinuityFacetWire::NonCurrent(facet) = &mut result.facets[1] else {
                    panic!("fixed non-current facet")
                };
                facet.status = ContinuityStatus::Stale;
            }),
            ("diagnostic", |result| {
                let ContinuityFacetWire::NonCurrent(facet) = &mut result.facets[1] else {
                    panic!("fixed non-current facet")
                };
                facet.diagnostic_code = DiagnosticCode::StoredStale;
            }),
            ("version id", |result| {
                let ContinuityFacetWire::Current(facet) = &mut result.facets[0] else {
                    panic!("fixed current facet")
                };
                facet.current.facet_version_id = "018f0000-0000-7000-8000-000000000021".into();
            }),
            ("version", |result| {
                let ContinuityFacetWire::Current(facet) = &mut result.facets[0] else {
                    panic!("fixed current facet")
                };
                facet.current.facet_version += 1;
            }),
            ("body hash", |result| {
                let ContinuityFacetWire::Current(facet) = &mut result.facets[0] else {
                    panic!("fixed current facet")
                };
                facet.current.body_sha256 = "33".repeat(32);
            }),
            ("memory source ids", |result| {
                let ContinuityFacetWire::Current(facet) = &mut result.facets[0] else {
                    panic!("fixed current facet")
                };
                facet.current.memory_source_ids =
                    vec!["018f0000-0000-7000-8000-000000000031".into()];
            }),
            ("evidence source ids", |result| {
                let ContinuityFacetWire::Current(facet) = &mut result.facets[0] else {
                    panic!("fixed current facet")
                };
                facet.current.evidence_source_ids =
                    vec!["018f0000-0000-7000-8000-000000000041".into()];
            }),
            ("handoff", |result| {
                result.handoff.mandatory[0].memory_id =
                    "018f0000-0000-7000-8000-000000000011".into();
            }),
            ("coverage required", |result| result.coverage.required -= 1),
            ("coverage current", |result| result.coverage.current += 1),
            ("coverage missing", |result| result.coverage.missing -= 1),
            ("coverage unavailable", |result| {
                result.coverage.unavailable -= 1;
            }),
            ("coverage stale", |result| result.coverage.stale += 1),
            ("coverage conflicted", |result| {
                result.coverage.conflicted += 1
            }),
            ("coverage class", |result| {
                result.coverage.completeness_class = CompletenessClass::FacetComplete;
            }),
        ];
        let baseline = assemble_continuity_result(closed_snapshot()).expect("closed result");
        let baseline_hash = recompute(&baseline);
        for (label, mutate) in mutations {
            let mut candidate = baseline.clone();
            mutate(&mut candidate);
            assert_ne!(recompute(&candidate), baseline_hash, "mutation: {label}");
        }
    }

    type Slots = Vec<(ContinuityFacetKind, ContinuityStatus)>;

    fn required_count() -> u8 {
        u8::try_from(ContinuityFacetKind::ALL.len()).expect("closed set fits u8")
    }

    /// Every kind `Current`, except `kind`, which carries `status` or is left out when `None`.
    fn slots_except(kind: ContinuityFacetKind, status: Option<ContinuityStatus>) -> Slots {
        ContinuityFacetKind::ALL
            .into_iter()
            .filter_map(|slot| {
                if slot == kind {
                    status.map(|status| (slot, status))
                } else {
                    Some((slot, ContinuityStatus::Current))
                }
            })
            .collect()
    }

    fn assert_only_missing(kind: ContinuityFacetKind, status: Option<ContinuityStatus>) {
        let n = required_count();
        assert_eq!(
            facet_completeness(&slots_except(kind, status), &ContinuityFacetKind::ALL),
            FacetCompleteness {
                class: CompletenessClass::CannotEstablish,
                covered: n - 1,
                required: n,
                missing: vec![kind],
            },
            "{kind:?} as {status:?}"
        );
    }

    #[test]
    fn facet_completeness_all_current_is_facet_complete() {
        let n = required_count();
        let slots = ContinuityFacetKind::ALL
            .into_iter()
            .map(|kind| (kind, ContinuityStatus::Current))
            .collect::<Slots>();
        assert_eq!(
            facet_completeness(&slots, &ContinuityFacetKind::ALL),
            FacetCompleteness {
                class: CompletenessClass::FacetComplete,
                covered: n,
                required: n,
                missing: Vec::new(),
            }
        );
    }

    #[test]
    fn facet_completeness_stale_is_not_covered() {
        assert_only_missing(
            ContinuityFacetKind::Decisions,
            Some(ContinuityStatus::Stale),
        );
    }

    #[test]
    fn facet_completeness_conflicted_is_not_covered() {
        assert_only_missing(
            ContinuityFacetKind::Constraints,
            Some(ContinuityStatus::Conflicted),
        );
    }

    #[test]
    fn facet_completeness_unavailable_is_not_covered() {
        assert_only_missing(
            ContinuityFacetKind::Code,
            Some(ContinuityStatus::Unavailable),
        );
    }

    #[test]
    fn facet_completeness_missing_is_not_covered() {
        assert_only_missing(ContinuityFacetKind::Goal, Some(ContinuityStatus::Missing));
    }

    #[test]
    fn facet_completeness_absent_slot_is_not_covered() {
        assert_only_missing(ContinuityFacetKind::Outcomes, None);
    }

    #[test]
    fn facet_completeness_mixed_names_missing_in_closed_set_order() {
        let n = required_count();
        // Built in reverse closed-set order so the order of `missing` cannot come from the input.
        let slots = ContinuityFacetKind::ALL
            .into_iter()
            .rev()
            .filter_map(|kind| match kind {
                ContinuityFacetKind::Outcomes => Some((kind, ContinuityStatus::Stale)),
                ContinuityFacetKind::Code => Some((kind, ContinuityStatus::Unavailable)),
                ContinuityFacetKind::Decisions => Some((kind, ContinuityStatus::Conflicted)),
                ContinuityFacetKind::Goal => None,
                _ => Some((kind, ContinuityStatus::Current)),
            })
            .collect::<Slots>();
        assert_eq!(
            facet_completeness(&slots, &ContinuityFacetKind::ALL),
            FacetCompleteness {
                class: CompletenessClass::CannotEstablish,
                covered: n - 4,
                required: n,
                missing: vec![
                    ContinuityFacetKind::Goal,
                    ContinuityFacetKind::Decisions,
                    ContinuityFacetKind::Code,
                    ContinuityFacetKind::Outcomes,
                ],
            }
        );
    }

    #[test]
    fn facet_completeness_empty_profile_fails_closed() {
        let slots = slots_except(ContinuityFacetKind::Goal, Some(ContinuityStatus::Current));
        assert_eq!(
            facet_completeness(&slots, &[]),
            FacetCompleteness {
                class: CompletenessClass::CannotEstablish,
                covered: 0,
                required: 0,
                missing: Vec::new(),
            }
        );
    }

    #[test]
    fn facet_completeness_profile_governs_and_duplicates_fail_closed() {
        // Only the required profile counts: a non-required facet being Unavailable is irrelevant,
        // and a repeated required kind is one facet.
        let profile = [
            ContinuityFacetKind::Goal,
            ContinuityFacetKind::Decisions,
            ContinuityFacetKind::Goal,
        ];
        let slots = slots_except(
            ContinuityFacetKind::Code,
            Some(ContinuityStatus::Unavailable),
        );
        assert_eq!(
            facet_completeness(&slots, &profile),
            FacetCompleteness {
                class: CompletenessClass::FacetComplete,
                covered: 2,
                required: 2,
                missing: Vec::new(),
            }
        );
        // The same kind reported both Current and Stale is ambiguous, so not covered.
        let mut ambiguous = slots;
        ambiguous.push((ContinuityFacetKind::Goal, ContinuityStatus::Stale));
        let verdict = facet_completeness(&ambiguous, &profile);
        assert_eq!(verdict.class, CompletenessClass::CannotEstablish);
        assert_eq!(verdict.missing, vec![ContinuityFacetKind::Goal]);
    }

    #[test]
    fn fallback_required_facets_is_all_minus_w2_forced_unavailable() {
        let profile = fallback_required_facets();
        assert_eq!(
            profile.len(),
            ContinuityFacetKind::ALL.len() - W2_FORCED_UNAVAILABLE.len()
        );
        for kind in ContinuityFacetKind::ALL {
            assert_eq!(
                profile.contains(&kind),
                !W2_FORCED_UNAVAILABLE.contains(&kind),
                "{kind:?}"
            );
        }
        // Closed-set order, so `facet_completeness` names missing facets the same way.
        let positions = profile
            .iter()
            .map(|kind| ContinuityFacetKind::ALL.iter().position(|k| k == kind))
            .collect::<Vec<_>>();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityMemorySource {
    pub memory_id: Uuid,
    pub content_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuityEvidenceSource {
    pub evidence_id: Uuid,
    pub payload_sha256: [u8; 32],
}

/// One `continuity.publish` input. The expected slot version is deliberately absent: it is the
/// door's own in-transaction read, never a caller value (ADR-0094 D-C).
#[derive(Debug, Clone)]
pub struct PublishContinuityFacet<'a> {
    /// §50 / ADR-0094 D-D: positive total attempts, parsed once by process bootstrap.
    pub list_merge_attempts: usize,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub facet_kind: ContinuityFacetKind,
    pub published_state: ContinuityPublishState,
    pub body: &'a Value,
    pub memories: &'a [ContinuityMemorySource],
    pub evidence: &'a [ContinuityEvidenceSource],
    /// `source_id`s dropped after the union; empty for every scalar facet.
    pub removals: &'a [String],
}

/// The outcome of one facet publication. `Conflict` is success-shaped (nothing was written): the
/// caller gets the typed §52 D-B sub-reason and the slot version to merge against, so it can retry
/// without a second error registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishFacetOutcome {
    /// The immutable version, its links and the slot compare-and-swap committed.
    Published(ContinuityPublishResult),
    /// The slot did not hold the version the door read; `current_slot_version` is what it holds now.
    Conflict {
        reason: ConflictReason,
        current_slot_version: i64,
    },
}

/// Whole publication operation, including slot read, CAS, source links and commit (§25.3.1).
#[async_trait::async_trait]
pub trait FacetPublicationPort: Send + Sync {
    type Authorization: Sync;

    /// Publish in a single adapter-owned transaction (ADR-0094 D-C).
    async fn publish_facet(
        &self,
        authorization: &Self::Authorization,
        command: &PublishContinuityFacet<'_>,
    ) -> Result<PublishFacetOutcome, ErrorCode>;
}

/// Publish a facet through the transaction-owning adapter (§25.3.1).
pub async fn publish_facet<Authorization: Sync>(
    port: &dyn FacetPublicationPort<Authorization = Authorization>,
    authorization: &Authorization,
    command: &PublishContinuityFacet<'_>,
) -> Result<PublishFacetOutcome, ErrorCode> {
    port.publish_facet(authorization, command).await
}

#[cfg(test)]
mod frozen_tests {
    use super::*;
    use humaux_domain::authority::MemoryId;
    use humaux_domain::context::{
        Admitted, FrozenReads, MandatoryLane, MandatoryRow, PinnedLane, SelectorId,
        SelectorOutcome, spec,
    };
    use humaux_domain::grounding::{GroundingInputs, RowGrounding, derive_grounding_state};
    use humaux_retrieval::compiler::ContextOutcome;
    use humaux_retrieval::handoff::assemble_with_context;

    fn assemble(frozen: FrozenReads, budget: ContextBudget) -> Handoff {
        super::assemble(ClosedFrozenReads(frozen), budget)
    }

    fn current() -> RowGrounding {
        RowGrounding::Judged(derive_grounding_state(GroundingInputs::Edges(&[])))
    }

    fn row_with(id: MemoryId, tokens: u32) -> MandatoryRow {
        row_with_grounding(id, tokens, current())
    }

    fn row_with_grounding(id: MemoryId, tokens: u32, grounding: RowGrounding) -> MandatoryRow {
        let s = spec(SelectorId::ProjectActiveConstraintsV1);
        match MandatoryRow::from_selector(s, id, s.min_authority, tokens, grounding)
            .expect("参数合法")
        {
            Admitted::Row(r) => r,
            Admitted::NeedsVerification(nv) => panic!("row 不该被分流: {nv:?}"),
        }
    }

    fn lane_of(ids: &[MemoryId]) -> MandatoryLane {
        lane_with_rows(ids.iter().map(|id| row_with(*id, 10)).collect())
    }

    fn lane_with_rows(rows: Vec<MandatoryRow>) -> MandatoryLane {
        MandatoryLane::from_selectors([
            SelectorOutcome::Ran {
                id: SelectorId::TaskExplicitContextV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::ProjectActiveConstraintsV1,
                candidate_ids: rows.iter().map(|row| row.memory_id()).collect(),
                rows,
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::UserConfirmedCorrectionsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::RequiredCurrentStateFacetsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::ExplicitMandatoryBindingsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
        ])
        .expect("selector outcomes")
    }

    fn frozen_of(ids: &[MemoryId]) -> FrozenReads {
        FrozenReads {
            mandatory: lane_of(ids),
            pinned: PinnedLane::new(0, vec![], vec![]),
            context_snapshot_seq: 12345,
            snapshot_token_sha256: "deadbeef".repeat(8),
        }
    }

    /// **G80-31 前半的纯函数形态**：同值 FrozenReads ⇒ 逐字节相同。
    /// 行的**喂入顺序不同**也必须同字节——顺序是 lane 构造器排出来的，不是调用方碰巧的。
    /// 注错：把 from_selectors 里的 sort 删掉 ⇒ 本条红。
    #[test]
    fn equal_frozen_reads_assemble_to_identical_bytes_regardless_of_feed_order() {
        let a = MemoryId::new();
        let b = MemoryId::new();
        let budget = || ContextBudget::new(1000, 500).expect("budget");

        let h1 = assemble(frozen_of(&[a, b]), budget());
        let h2 = assemble(frozen_of(&[b, a]), budget()); // 反序喂入
        assert_eq!(
            h1.canonical_bytes(),
            h2.canonical_bytes(),
            "同值冻结读数必须逐字节相同——顺序由构造器保证，不靠调用方"
        );
        assert_eq!(h1.sha256(), h2.sha256());
    }

    /// 不同快照身份 ⇒ 字节必不同（身份真的在字节域里，不是装饰字段）。
    #[test]
    fn a_different_snapshot_token_changes_the_bytes() {
        let a = MemoryId::new();
        let budget = || ContextBudget::new(1000, 500).expect("budget");
        let h1 = assemble(frozen_of(&[a]), budget());
        let mut f2 = frozen_of(&[a]);
        f2.snapshot_token_sha256 = "feedface".repeat(8);
        let h2 = assemble(f2, budget());
        assert_ne!(h1.canonical_bytes(), h2.canonical_bytes());
    }

    /// §25.5 溢出：不产出条目、manifest 全量具名、counts.overflow=true。
    /// 「截一半发出去」在这条路径上没有值可发。
    #[test]
    fn overflow_produces_a_manifest_not_a_truncated_handoff() {
        let ids = [MemoryId::new(), MemoryId::new()];
        let mut f = frozen_of(&ids);
        f.pinned = PinnedLane::new(0, vec![], vec![]);
        // 每行 10 token，上限 5：必溢出。
        let h = assemble(f, ContextBudget::new(100, 5).expect("budget"));
        assert!(h.counts.overflow);
        assert!(h.mandatory.is_empty(), "溢出路径一条都不交付");
        assert_eq!(h.overflow_manifest.len(), 2, "manifest 必须全量");
        assert_eq!(h.counts.mandatory_returned, 0);
    }

    /// Overflow returns no body-bearing rows, but keeps the snapshot's existing NotJudged
    /// diagnostic instead of silently relabeling it as judged.
    #[test]
    fn overflow_keeps_not_judged_diagnostics() {
        let id = MemoryId::new();
        let frozen = FrozenReads {
            mandatory: lane_with_rows(vec![row_with_grounding(id, 10, RowGrounding::NotJudged)]),
            pinned: PinnedLane::new(0, vec![], vec![]),
            context_snapshot_seq: 12345,
            snapshot_token_sha256: "deadbeef".repeat(8),
        };

        let handoff = assemble(frozen, ContextBudget::new(100, 5).expect("budget"));

        assert!(handoff.counts.overflow);
        assert!(handoff.mandatory.is_empty());
        assert!(handoff.pinned.is_empty());
        assert_eq!(handoff.not_judged, vec![id.0.to_string()]);
    }

    /// Feeding overlapping owner lanes to compilation must retain only the Mandatory row.
    #[test]
    fn compile_keeps_a_raw_cross_lane_memory_id_once() {
        let memory_id = MemoryId::new();
        let mut frozen = frozen_of(&[memory_id]);
        frozen.pinned = PinnedLane::new(1, vec![row_with(memory_id, 10)], vec![]);
        let prepared =
            ClosedFrozenReads(frozen).prepare(ContextBudget::new(20, 10).expect("budget"));
        let compiled = humaux_retrieval::compiler::compile(
            prepared.mandatory,
            prepared.pinned,
            prepared.reservation.expect("raw overlap must not overflow"),
            vec![],
        );
        let mut ids = compiled
            .mandatory_ids()
            .into_iter()
            .chain(compiled.pinned_ids())
            .collect::<Vec<_>>();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();

        assert_eq!(before, 1);
        assert_eq!(ids, vec![memory_id]);
    }

    /// Cross-lane overlap is mandatory-precedence before reservation: one physical item,
    /// no duplicate Pinned count, and no false mandatory overflow from charging it twice.
    #[test]
    fn mandatory_precedence_deduplicates_pinned_before_budget_reservation() {
        let id = MemoryId::new();
        let frozen = FrozenReads {
            mandatory: lane_of(&[id]),
            pinned: PinnedLane::new(1, vec![row_with(id, 10)], vec![]),
            context_snapshot_seq: 12345,
            snapshot_token_sha256: "deadbeef".repeat(8),
        };
        let (handoff, outcome) = assemble_with_context(
            ClosedFrozenReads(frozen),
            ContextBudget::new(15, 10).expect("one mandatory item fits"),
        );

        assert!(matches!(outcome, ContextOutcome::Compiled(_)));
        assert_eq!(handoff.mandatory.len(), 1);
        assert!(handoff.pinned.is_empty());
        assert_eq!(handoff.counts.pinned_expected, 1);
        assert_eq!(handoff.counts.pinned_returned, 0);
        assert_eq!(handoff.counts.pinned_excluded, 1);
    }

    /// needs_verification 与 unavailable 都在字节域里——它们变，字节就变。
    /// 「fail-loud」如果不进字节域，两次装配一个有告警一个没有也会"逐字节相同"，
    /// 那是把 DOD-093 的披露从判据里洗掉。
    #[test]
    fn needs_verification_and_unavailable_are_part_of_the_byte_domain() {
        let a = MemoryId::new();
        let budget = || ContextBudget::new(1000, 500).expect("budget");
        let h1 = assemble(frozen_of(&[a]), budget());

        let mut lane_outcomes = frozen_of(&[a]);
        // 同一行数据，但带上一条 unavailable。
        lane_outcomes.mandatory = MandatoryLane::from_selectors([
            SelectorOutcome::Unavailable {
                id: SelectorId::TaskExplicitContextV1,
                // dep-map: allow table-undeclared — selector metadata names the missing column; SQL runs in adapters
                missing_object: "private.memory_records.task_id".into(),
            },
            SelectorOutcome::Ran {
                id: SelectorId::ProjectActiveConstraintsV1,
                candidate_ids: vec![a],
                rows: vec![row_with(a, 10)],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::UserConfirmedCorrectionsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::RequiredCurrentStateFacetsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
            SelectorOutcome::Ran {
                id: SelectorId::ExplicitMandatoryBindingsV1,
                candidate_ids: vec![],
                rows: vec![],
                needs_verification: vec![],
            },
        ])
        .expect("selector outcomes");
        let h2 = assemble(lane_outcomes, budget());
        assert_ne!(
            h1.canonical_bytes(),
            h2.canonical_bytes(),
            "unavailable 必须改变字节——否则 partial 与 full 不可区分"
        );
        assert_eq!(h2.unavailable_selectors.len(), 1);
    }
    /// The retired registration `task_explicit_context_v1` (ADR-0046) must never reappear on
    /// any handoff surface, and every emitted selector name must be a *registered* one.
    ///
    /// Fault injection: put the literal back in `selector_wire` (or point it at
    /// `RETIRED_SELECTORS`) and this goes red on both halves.
    #[test]
    fn retired_selector_v1_never_reaches_the_wire() {
        let registered: Vec<&'static str> = humaux_domain::context::REGISTRY
            .iter()
            .map(|s| s.registered_name)
            .collect();
        for id in [
            SelectorId::TaskExplicitContextV1,
            SelectorId::ProjectActiveConstraintsV1,
            SelectorId::UserConfirmedCorrectionsV1,
            SelectorId::RequiredCurrentStateFacetsV1,
            SelectorId::ExplicitMandatoryBindingsV1,
        ] {
            let wire = selector_wire(id);
            assert_ne!(
                wire, "task_explicit_context_v1",
                "{id:?} still emits the retired v1 registration on the wire (ADR-0046)"
            );
            assert!(
                registered.contains(&wire),
                "{id:?} emits {wire}, which is not a §25.4 registered name"
            );
        }
        assert_eq!(
            selector_wire(SelectorId::TaskExplicitContextV1),
            "task_explicit_context_v2"
        );
    }
}
