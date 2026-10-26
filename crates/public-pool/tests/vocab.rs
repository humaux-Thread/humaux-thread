//! `public-pool::tests::vocab` — Real-PostgreSQL vocabulary loader and closed-set contracts (G-M20-16, §78.2).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, tokio];
//!   services=[PostgreSQL(any) r=[public.concepts, public.concept_labels, public.concept_relations], PostgreSQL(role_public_worker)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, domain::error, humaux-testkit, public-pool::vocab, public-pool::vocab::model]
//! Called-by: [cargo-test]
//! Invariants: [the production write door runs twice; exact full seed and CHECK sets; absent DB fails in CI]
//! Spec: Baseline §12.3; §78.2; §79.2; ADR-0089 D-E; ADR-0090 D-B

use humaux_adapters::postgres::PublicWorkerDbPool;
use humaux_domain::error::ErrorCode;
use humaux_public_pool::vocab::{
    self,
    model::{Facet, LabelKind, RelationKind, Status, Vocabulary},
};
use postgres::{Client, NoTls};
use std::collections::BTreeSet;

const SOURCE: &str = include_str!("../../../contracts/public/vocab_v1.toml");
const LOCK: &str = include_str!("../../../contracts/public/vocab_ids.lock");

fn check_set(admin: &mut Client, constraint: &str, expected: BTreeSet<&str>, count: usize) {
    assert_eq!(expected.len(), count, "Rust closed set count: {constraint}");
    let rows = admin.query("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace='public'::regnamespace AND conname=$1", &[&constraint]).expect("catalog CHECK");
    assert_eq!(rows.len(), 1, "exactly one CHECK: {constraint}");
    let definition: String = rows[0].get(0);
    let actual: BTreeSet<_> = definition
        .split('\'')
        .enumerate()
        .filter_map(|(i, s)| (i % 2 == 1).then_some(s))
        .collect();
    assert_eq!(actual, expected, "Rust ↔ DB exact set: {constraint}");
}
fn contracts(admin: &mut Client) {
    check_set(
        admin,
        "concepts_facet_check",
        Facet::ALL.iter().map(|v| v.as_str()).collect(),
        6,
    );
    check_set(
        admin,
        "concepts_status_check",
        Status::ALL.iter().map(|v| v.as_str()).collect(),
        2,
    );
    check_set(
        admin,
        "concept_labels_kind_check",
        LabelKind::ALL.iter().map(|v| v.as_str()).collect(),
        2,
    );
    check_set(
        admin,
        "concept_relations_kind_check",
        RelationKind::ALL.iter().map(|v| v.as_str()).collect(),
        4,
    );
}
fn exact_seed(admin: &mut Client) {
    let vocab = Vocabulary::parse(SOURCE, LOCK).expect("seed contract");
    let rows = admin.query("SELECT concept_id,facet,status,replaced_by,definition FROM public.concepts ORDER BY concept_id", &[]).expect("concepts");
    assert_eq!(rows.len(), 8);
    let actual: BTreeSet<(String, String, String, Option<String>, String)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    let expected = vocab
        .concepts
        .iter()
        .map(|c| {
            (
                c.id.clone(),
                c.facet.as_str().into(),
                c.status.as_str().into(),
                c.replaced_by.clone(),
                c.definition.clone(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
    let rows = admin
        .query(
            "SELECT concept_id,lang,kind,label FROM public.concept_labels",
            &[],
        )
        .expect("labels");
    assert_eq!(rows.len(), 8);
    let actual: BTreeSet<(String, String, String, String)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    let expected = [
        ("knowledge-fix", "en", "PREF", "FIX"),
        ("knowledge-decision", "en", "PREF", "DECISION"),
        ("knowledge-research", "en", "PREF", "RESEARCH"),
        ("knowledge-usage", "en", "PREF", "USAGE"),
        ("knowledge-checklist", "en", "PREF", "CHECKLIST"),
        ("knowledge-failure-case", "en", "PREF", "FAILURE_CASE"),
        ("en", "en", "PREF", "English"),
        ("zh", "en", "PREF", "Chinese"),
    ]
    .into_iter()
    .map(|(a, b, c, d)| (a.into(), b.into(), c.into(), d.into()))
    .collect();
    assert_eq!(actual, expected);
    let count: i64 = admin
        .query_one("SELECT count(*) FROM public.concept_relations", &[])
        .expect("relation count")
        .get(0);
    assert_eq!(count, 0);
}

#[tokio::test]
async fn loader_idempotent_exact_seed_and_closed_checks() {
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        humaux_testkit::skip_or_fail(
            "vocab loader",
            "HUMAUX_TEST_PG_DSN",
            humaux_testkit::ExternalDep::Postgres,
        );
        return;
    };
    // dep: PostgreSQL(any) — §78.2 real catalog and exact seed rows.
    let mut admin = Client::connect(&dsn, NoTls).expect("CI PostgreSQL");
    contracts(&mut admin);
    let worker_dsn = format!(
        "{dsn}{}options=-c%20role%3Drole_public_worker",
        if dsn.contains('?') { '&' } else { '?' }
    );
    // dep: PostgreSQL(role_public_worker) — §12.3 production writer identity.
    let worker = PublicWorkerDbPool::connect(&worker_dsn)
        .await
        .expect("typed worker pool");
    vocab::apply(&worker, SOURCE, LOCK)
        .await
        .expect("first apply");
    vocab::apply(&worker, SOURCE, LOCK)
        .await
        .expect("idempotent second apply");
    exact_seed(&mut admin);
    // §12.3: rewriting both current files cannot rename a persisted id.
    let renamed = SOURCE.replace("knowledge-fix", "knowledge-renamed");
    let renamed_lock = LOCK.replace("knowledge-fix", "knowledge-renamed");
    assert_eq!(
        vocab::apply(&worker, &renamed, &renamed_lock).await,
        Err(ErrorCode::InvalidInput)
    );
    exact_seed(&mut admin);
}
