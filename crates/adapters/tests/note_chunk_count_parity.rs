//! `adapters::tests::note_chunk_count_parity` — ADR-0068 gate `rust_sql_chunk_count_parity`: migration 0237's
//!   `projection.note_chunk_count` and the Rust NoteChunksV1 count agree on every title and body in the matrix.
//! Depends-on: crates=[humaux-domain, humaux-projection, humaux-testkit, postgres]; services=[PostgreSQL(any)
//!   x=[projection.note_chunk_count]]; env=[HUMAUX_TEST_PG_DSN]; modules=[domain::authority, domain::dataclass,
//!   domain::memory, humaux-testkit, projection::card, projection::note_chunks]
//! Called-by: [cargo-test]
//! Invariants: [read-only (one IMMUTABLE function call per case, no table touched); no DSN or no live Postgres is a
//!   visible SKIP and HUMAUX_REQUIRE_DB=1 turns it into a failure; every mismatch is collected and reported with its
//!   case in one assertion]
//! Spec: Baseline §79.2; ADR-0068
//!
//! Each case is compared three ways: SQL, the Rust closed form (`legacy_capacity_holds` / `chunk_count`), and the
//! slot count `build_projection_plan` actually yields for an identity note (1 legacy card, or one entry per chunk) —
//! so the SQL count is tied to the plan the worker will use, not only to a second copy of the formula.

use std::time::SystemTime;

use humaux_domain::authority::MemoryId;
use humaux_domain::dataclass::DataClass;
use humaux_domain::memory::MemoryType;
use humaux_projection::card::{CardBudget, CardInput, EgressDisposition};
use humaux_projection::note_chunks::{
    LEGACY_NOTE_SEPARATORS, PlanInput, ProjectionPlan, build_projection_plan, chunk_count,
    legacy_capacity_holds,
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

fn plan_slots(title: &str, body: &str) -> usize {
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
    };
    match build_projection_plan(input) {
        ProjectionPlan::LegacyCardV1(_) => 1,
        ProjectionPlan::NoteChunksV1(chunks) => chunks.len(),
    }
}

/// ADR-0068 gate `rust_sql_chunk_count_parity`. Fault: `<` for `<=` or `+ 2` for `+ 3` in 0237's body ⇒ red at
/// `title=N body=600-3-N`; `octet_length` for `char_length` ⇒ red on every multi-byte case; a window or stride drift
/// on either side ⇒ red at 481 / 897.
#[test]
fn rust_sql_chunk_count_parity() {
    const TEST: &str = "rust_sql_chunk_count_parity";
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(
            TEST,
            "missing object: HUMAUX_TEST_PG_DSN",
            ExternalDep::Postgres,
        );
        return;
    };
    // dep: PostgreSQL(any) — calls the pure projection.note_chunk_count
    let mut client = match Client::connect(&dsn, NoTls) {
        Ok(client) => client,
        Err(e) => {
            skip_or_fail(
                TEST,
                &format!("missing object: live Postgres ({e})"),
                ExternalDep::Postgres,
            );
            return;
        }
    };
    let cases = cases();
    let mut problems = Vec::new();
    for (case, title, body) in &cases {
        let sql: i32 = client
            .query_one(
                "SELECT projection.note_chunk_count($1, $2)",
                &[&title.as_str(), &body.as_str()],
            )
            .expect("the 0237 chunk-count function")
            .get(0);
        let rust = if legacy_capacity_holds(title, body) {
            1
        } else {
            chunk_count(body.chars().count())
        };
        let plan = plan_slots(title, body);
        if usize::try_from(sql).ok() != Some(rust) || plan != rust {
            problems.push(format!("{case}: sql={sql} rust={rust} plan={plan}"));
        }
    }
    assert!(
        problems.is_empty(),
        "{} of {} cases disagree: {problems:?}",
        problems.len(),
        cases.len()
    );
    assert!(cases.len() > 300, "the matrix shrank to {}", cases.len());
}
