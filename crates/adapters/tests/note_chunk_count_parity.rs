//! `adapters::tests::note_chunk_count_parity` — ADR-0068 gate `rust_sql_chunk_count_parity`: migration 0237's
//!   `projection.note_chunk_count` and 0238's `projection.note_legacy_capacity_holds` agree with the Rust NoteChunksV1
//!   count and legacy predicate on every title and body in the matrix; and 0238's projection policy and registry
//!   defaults match what the Rust side reads.
//! Depends-on: crates=[humaux-domain, humaux-projection, humaux-testkit, postgres]; services=[PostgreSQL(any)
//!   r=[projection.card_profile_policies, projection.private_memory_points] x=[projection.note_chunk_count,
//!   projection.note_legacy_capacity_holds]]; env=[HUMAUX_TEST_PG_DSN]; modules=[domain::authority,
//!   domain::dataclass, domain::memory, domain::ticket_family, humaux-testkit, projection::card,
//!   projection::note_chunks]
//! Called-by: [cargo-test]
//! Invariants: [read-only (IMMUTABLE function calls and catalog / policy reads, no row written); no DSN or no live
//!   Postgres is a visible SKIP and HUMAUX_REQUIRE_DB=1 turns it into a failure; every mismatch is collected and
//!   reported with its case in one assertion]
//! Spec: Baseline §6.2.2; §78.2; §79.2; ADR-0068
//!
//! Each case is compared three ways: SQL, the Rust closed form (`legacy_capacity_holds` / `chunk_count`), and the
//! plan `build_projection_plan` actually yields for an identity note under the NoteChunksV1 policy (its branch and
//! its slot count) — so the SQL is tied to the plan the worker will use, not only to a second copy of the formula. A
//! slot is legacy iff the predicate holds; the matrix must contain one-slot NoteChunksV1 cases, so a classifier that
//! reads "count == 1" as legacy is red here.

use std::time::SystemTime;

use humaux_domain::authority::MemoryId;
use humaux_domain::dataclass::DataClass;
use humaux_domain::memory::MemoryType;
use humaux_domain::ticket_family::TicketFamily;
use humaux_projection::card::{CardBudget, CardInput, EgressDisposition};
use humaux_projection::note_chunks::{
    LEGACY_CARD_PROFILE_HASH, LEGACY_NOTE_SEPARATORS, NoteChunkPolicy, PlanInput, ProjectionPlan,
    build_projection_plan, chunk_count, legacy_capacity_holds,
};
use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::{Client, NoTls};

/// `(case, title, body)`: ASCII, CJK, 4-byte emoji, combining marks and CRLF, at the legacy boundary (title term
/// included: budget − 3 − title ± 1) and the window boundaries 0 / 479 / 480 / 481 / 896 / 897, plus 64 KiB.
fn cases() -> Vec<(String, String, String)> {
    let budget = CardBudget::default().max_chars;
    let mut cases = Vec::new();
    let units = [
        ("ascii", "a"),
        ("cjk", "長"),
        ("emoji", "😀"),
        ("combining", "e\u{301}"),
        ("crlf", "\r\n"),
    ];
    for (name, unit) in units {
        let per = unit.chars().count();
        for title_len in [0, 1, 20, 119, 597, 598, 700] {
            let title = "題".repeat(title_len);
            let at = budget.saturating_sub(LEGACY_NOTE_SEPARATORS + title_len);
            let mut lengths = vec![0, 1, 479, 480, 481, 896, 897, at, at + 1];
            lengths.extend(at.checked_sub(1));
            for scalars in lengths {
                // A multi-scalar unit cannot hit every length exactly; pad the remainder with ASCII so it does.
                let body = format!(
                    "{}{}",
                    unit.repeat(scalars / per),
                    "x".repeat(scalars % per)
                );
                cases.push((
                    format!("{name} title={title_len} body={scalars}"),
                    title.clone(),
                    body,
                ));
            }
        }
    }
    cases.push(("ascii 64 KiB".into(), "t".into(), "a".repeat(65_536)));
    cases.push((
        "mixed 64 KiB".into(),
        "標題😀".into(),
        "長😀e\u{301}\r\n".repeat(10_000),
    ));
    cases
}

/// `(legacy branch?, slots)` of the real plan for an identity note under the NoteChunksV1 policy.
fn plan_slots(title: &str, body: &str) -> (bool, usize) {
    let input = PlanInput {
        card: CardInput {
            memory_id: MemoryId::new(),
            memory_type: MemoryType::Note,
            data_class: DataClass::Private,
            egress_disposition: EgressDisposition::Allowed,
            workspace_id: None,
            topic: None,
            effective_from: SystemTime::UNIX_EPOCH,
            title: title.to_owned(),
            key_claim: Some(body.to_owned()),
            entities: Vec::new(),
            evidence_excerpt: None,
        },
        is_identity_note: true,
        policy: NoteChunkPolicy::NoteChunksV1,
    };
    match build_projection_plan(input) {
        ProjectionPlan::LegacyCardV1(_) => (true, 1),
        ProjectionPlan::NoteChunksV1(chunks) => (false, chunks.len()),
    }
}

/// A live client on `HUMAUX_TEST_PG_DSN`, or a visible skip (a failure under `HUMAUX_REQUIRE_DB=1`).
fn connect(test: &str) -> Option<Client> {
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(
            test,
            "missing object: HUMAUX_TEST_PG_DSN",
            ExternalDep::Postgres,
        );
        return None;
    };
    // dep: PostgreSQL(any) — pure 0237/0238 functions and catalog / policy reads
    match Client::connect(&dsn, NoTls) {
        Ok(client) => Some(client),
        Err(e) => {
            skip_or_fail(
                test,
                &format!("missing object: live Postgres ({e})"),
                ExternalDep::Postgres,
            );
            None
        }
    }
}

/// ADR-0068 gate `rust_sql_chunk_count_parity`. Faults: `<` for `<=` or `+ 2` for `+ 3` in 0237's or 0238's body ⇒
/// red at `title=N body=600-3-N`; `octet_length` for `char_length` ⇒ red on every multi-byte case; a window or stride
/// drift on either side ⇒ red at 481 / 897; drop `char_length(p_body) = 0` from 0238 ⇒ red at `title=598 body=0`;
/// a predicate rewritten as `note_chunk_count(...) = 1` ⇒ red on every one-slot NoteChunksV1 case.
#[test]
fn rust_sql_chunk_count_parity() {
    let Some(mut client) = connect("rust_sql_chunk_count_parity") else {
        return;
    };
    let cases = cases();
    let mut problems = Vec::new();
    let mut one_chunk_notes = 0;
    for (case, title, body) in &cases {
        let row = client
            .query_one(
                "SELECT projection.note_chunk_count($1, $2), projection.note_legacy_capacity_holds($1, $2)",
                &[&title.as_str(), &body.as_str()],
            )
            .expect("the 0237 count and the 0238 legacy predicate");
        let (sql_count, sql_legacy): (i32, bool) = (row.get(0), row.get(1));
        let rust_legacy = legacy_capacity_holds(title, body);
        let rust_count = if rust_legacy {
            1
        } else {
            chunk_count(body.chars().count())
        };
        let (plan_legacy, plan_count) = plan_slots(title, body);
        if usize::try_from(sql_count).ok() != Some(rust_count)
            || plan_count != rust_count
            || sql_legacy != rust_legacy
            || plan_legacy != rust_legacy
        {
            problems.push(format!(
                "{case}: count sql={sql_count} rust={rust_count} plan={plan_count}; \
                 legacy sql={sql_legacy} rust={rust_legacy} plan={plan_legacy}"
            ));
        }
        one_chunk_notes += usize::from(!sql_legacy && sql_count == 1);
    }
    assert!(
        problems.is_empty(),
        "{} of {} cases disagree: {problems:?}",
        problems.len(),
        cases.len()
    );
    assert!(cases.len() > 300, "the matrix shrank to {}", cases.len());
    assert!(
        one_chunk_notes > 0,
        "the matrix has no one-slot NoteChunksV1 case, so count == 1 would pass for legacy"
    );
}

/// ADR-0068 D-I / D-C (0238): the serving projection's policy row exists and is NULL (legacy only), and the Rust
/// policy reads it as `LegacyOnly`; the ledger definer's owner can read it with no RLS in the way; no role but the
/// owner can write it; and the registry's default profile is the Rust legacy marker (§78.2). Faults: seed a hash
/// or no row ⇒ red on the seed; ENABLE ROW LEVEL SECURITY or a different owner ⇒ red on the definer read; GRANT
/// INSERT to any role ⇒ red on the writers; a default other than `LegacyCardV1` ⇒ red on the contract.
#[test]
fn serving_projection_policy_is_seeded_legacy_and_read_only() {
    let Some(mut client) = connect("serving_projection_policy_is_seeded_legacy_and_read_only")
    else {
        return;
    };
    let family = TicketFamily::PrivateMemory;
    let seeded = client
        .query_opt(
            "SELECT note_chunk_profile_hash FROM projection.card_profile_policies \
              WHERE domain = $1 AND projection_kind = $2 AND projection_version = $3",
            &[
                &family.domain(),
                &family.projection_kind(),
                &family.projection_version(),
            ],
        )
        .expect("read the 0238 policy")
        .map(|row| row.get::<_, Option<String>>(0));
    assert_eq!(seeded, Some(None), "the serving projection's row, NULL");
    assert_eq!(
        NoteChunkPolicy::from_profile_hash(seeded.flatten().as_deref()),
        Ok(NoteChunkPolicy::LegacyOnly)
    );
    let definer_reads: bool = client
        .query_one(
            "SELECT bool_and(p.prosecdef AND has_table_privilege(p.proowner, c.oid, 'SELECT') \
                             AND NOT c.relrowsecurity) AND count(*) = 1 \
               FROM pg_proc p, pg_class c \
              WHERE p.proname = 'stream_point_ledger' AND p.pronamespace = 'projection'::regnamespace \
                AND c.oid = to_regclass('projection.card_profile_policies')",
            &[],
        )
        .expect("the ledger definer and the policy table")
        .get(0);
    assert!(
        definer_reads,
        "the ledger definer cannot read every policy row"
    );
    let writers: Vec<String> = client
        .query(
            "SELECT r.rolname::text FROM pg_roles r, pg_class c \
              WHERE c.oid = to_regclass('projection.card_profile_policies') \
                AND r.rolname LIKE 'role\\_%' AND r.rolname <> 'role_migration_owner' \
                AND has_table_privilege(r.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE') \
              ORDER BY 1",
            &[],
        )
        .expect("list the policy writers")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(
        writers.is_empty(),
        "roles that can write the policy: {writers:?}"
    );
    let default: String = client
        .query_one(
            "SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d \
               JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum \
              WHERE d.adrelid = to_regclass('projection.private_memory_points') \
                AND a.attname = 'card_profile_hash'",
            &[],
        )
        .expect("the registry's card_profile_hash default")
        .get(0);
    assert_eq!(default, format!("'{LEGACY_CARD_PROFILE_HASH}'::text"));
}
