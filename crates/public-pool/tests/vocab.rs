//! `public-pool::tests::vocab` — Real-PostgreSQL vocabulary loader and closed-set contracts (G-M20-16, §78.2).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, tokio];
//!   services=[PostgreSQL(any) r=[public.concepts, public.concept_labels, public.concept_relations] w=[public.concepts, public.concept_labels, public.concept_relations], PostgreSQL(role_public_worker)];
//!   env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::postgres, domain::error, humaux-testkit, public-pool::vocab, public-pool::vocab::model]
//! Called-by: [cargo-test]
//! Invariants: [the production write door runs twice; exact full seed with pinned definitions and CHECK sets; PREF/definition edits update in place; ALT removal is rejected naming the concept; each integrity constraint is exercised with SQLSTATE and constraint name; absent DB fails in CI]
//! Spec: Baseline §12.3; §78.2; §79.2; ADR-0089 D-E; ADR-0090 D-B

use humaux_adapters::postgres::PublicWorkerDbPool;
use humaux_domain::error::ErrorCode;
use humaux_public_pool::vocab::{
    self, ApplyError,
    model::{Facet, LabelKind, RelationKind, Status, Vocabulary},
};
use postgres::{Client, NoTls, error::SqlState};
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
const FIX_DEFINITION: &str = "Reproduction, expected versus actual, root cause, change, regression check, rollback and failure conditions.";

// §78.2: literals, not derived from the toml, so a drifting seed definition turns this red.
fn seed_concepts() -> BTreeSet<(String, String, String, Option<String>, String)> {
    [
        ("knowledge-fix", "knowledge_type", FIX_DEFINITION),
        ("knowledge-decision", "knowledge_type", "Goal, at least two candidates, constraints, trade-offs, rejected alternatives and redecision triggers."),
        ("knowledge-research", "knowledge_type", "Per-claim source, version and locator, fact or inference, applicability and limits."),
        ("knowledge-usage", "knowledge_type", "Environment, input, steps, expected output, verification state, errors and inapplicable cases."),
        ("knowledge-checklist", "knowledge_type", "Preconditions, steps, checkpoints, completion criteria, exception branches and rollback."),
        ("knowledge-failure-case", "knowledge_type", "Hypothesis, attempt, environment, observation, excluded causes and unknowns."),
        ("en", "content_language", "English-language content."),
        ("zh", "content_language", "Chinese-language content."),
    ]
    .into_iter()
    .map(|(id, facet, definition)| (id.into(), facet.into(), "ACTIVE".into(), None, definition.into()))
    .collect()
}
fn exact_seed(admin: &mut Client) {
    Vocabulary::parse(SOURCE, LOCK).expect("seed contract");
    let rows = admin.query("SELECT concept_id,facet,status,replaced_by,definition FROM public.concepts ORDER BY concept_id", &[]).expect("concepts");
    assert_eq!(rows.len(), 8);
    let actual: BTreeSet<(String, String, String, Option<String>, String)> = rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    assert_eq!(actual, seed_concepts());
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
    let expected: BTreeSet<(String, String, String, String)> = [
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

#[test]
fn loader_idempotent_exact_seed_and_closed_checks() {
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
    let rt = tokio::runtime::Runtime::new().expect("test runtime");
    // dep: PostgreSQL(role_public_worker) — §12.3 production writer identity.
    let worker = rt
        .block_on(PublicWorkerDbPool::connect(&worker_dsn))
        .expect("typed worker pool");
    rt.block_on(vocab::apply(&worker, SOURCE, LOCK))
        .expect("first apply");
    rt.block_on(vocab::apply(&worker, SOURCE, LOCK))
        .expect("idempotent second apply");
    exact_seed(&mut admin);
    // §12.3: rewriting both current files cannot rename a persisted id.
    let renamed = SOURCE.replace("knowledge-fix", "knowledge-renamed");
    let renamed_lock = LOCK.replace("knowledge-fix", "knowledge-renamed");
    assert_eq!(
        rt.block_on(vocab::apply(&worker, &renamed, &renamed_lock)),
        Err(rejected(
            "knowledge-fix: persisted concept id removed or renamed; ids are append-only"
        ))
    );
    exact_seed(&mut admin);
    edits_update_in_place(&rt, &worker, &mut admin);
    alt_label_removal_needs_migration(&rt, &worker, &mut admin);
    constraints_reject_direct_writes(&dsn);
}

fn rejected(reason: &str) -> ApplyError {
    ApplyError {
        code: ErrorCode::InvalidInput,
        reason: reason.into(),
    }
}
const PREF_FIX: &str = "label = \"FIX\"";

// §12.3: only concept ids are append-only; a PREF edit is an UPDATE on (concept_id, lang, 'PREF').
fn edits_update_in_place(
    rt: &tokio::runtime::Runtime,
    worker: &PublicWorkerDbPool,
    admin: &mut Client,
) {
    assert_eq!(SOURCE.matches(PREF_FIX).count(), 1);
    assert_eq!(SOURCE.matches(FIX_DEFINITION).count(), 1);
    let edited = SOURCE
        .replace(PREF_FIX, "label = \"FIX-EDITED\"")
        .replace(FIX_DEFINITION, "Edited fix definition.");
    rt.block_on(vocab::apply(worker, &edited, LOCK))
        .expect("edited PREF label and definition apply");
    let row = admin
        .query_one("SELECT label FROM public.concept_labels WHERE concept_id='knowledge-fix' AND lang='en' AND kind='PREF'", &[])
        .expect("one PREF row");
    assert_eq!(row.get::<_, String>(0), "FIX-EDITED");
    let row = admin
        .query_one(
            "SELECT definition FROM public.concepts WHERE concept_id='knowledge-fix'",
            &[],
        )
        .expect("definition row");
    assert_eq!(row.get::<_, String>(0), "Edited fix definition.");
    let count: i64 = admin
        .query_one("SELECT count(*) FROM public.concept_labels", &[])
        .expect("label count")
        .get(0);
    assert_eq!(count, 8);
    rt.block_on(vocab::apply(worker, SOURCE, LOCK))
        .expect("restore seed");
    exact_seed(admin);
}

fn alt_label_removal_needs_migration(
    rt: &tokio::runtime::Runtime,
    worker: &PublicWorkerDbPool,
    admin: &mut Client,
) {
    let with_alt = SOURCE.replace(
        PREF_FIX,
        &format!(
            "{PREF_FIX}\n[[concepts.labels]]\nlang = \"en\"\nkind = \"ALT\"\nlabel = \"repair\""
        ),
    );
    rt.block_on(vocab::apply(worker, &with_alt, LOCK))
        .expect("ALT label added");
    assert_eq!(
        rt.block_on(vocab::apply(worker, SOURCE, LOCK)),
        Err(rejected(
            "knowledge-fix: ALT label 'repair' (en) removal needs a migration"
        ))
    );
    let count: i64 = admin
        .query_one("SELECT count(*) FROM public.concept_labels", &[])
        .expect("label count")
        .get(0);
    assert_eq!(count, 9, "rejected apply leaves the ALT row in place");
    // The worker has no DELETE; the admin connection restores the seed for the other assertions.
    admin
        .execute(
            "DELETE FROM public.concept_labels WHERE label='repair'",
            &[],
        )
        .expect("cleanup");
    exact_seed(admin);
}

fn violates(worker: &mut Client, sql: &str, state: &SqlState, constraint: &str) {
    let error = worker.execute(sql, &[]).expect_err(sql);
    let db = error.as_db_error().expect("database error");
    assert_eq!(db.code(), state, "{sql}");
    assert_eq!(db.constraint(), Some(constraint), "{sql}");
}

// §12.3: the worker role has direct INSERT, so these constraints are the real gate.
fn constraints_reject_direct_writes(dsn: &str) {
    // dep: PostgreSQL(any) — §12.3 direct-write constraint probes.
    let mut worker = Client::connect(dsn, NoTls).expect("CI PostgreSQL");
    // dep: PostgreSQL(role_public_worker) — §12.3 the production writer identity.
    worker
        .batch_execute("SET ROLE role_public_worker")
        .expect("worker role");
    let concept =
        "INSERT INTO public.concepts (concept_id,facet,status,replaced_by,definition) VALUES";
    let label = "INSERT INTO public.concept_labels (concept_id,facet,lang,kind,label) VALUES";
    let check = &SqlState::CHECK_VIOLATION;
    let unique = &SqlState::UNIQUE_VIOLATION;
    violates(
        &mut worker,
        &format!("{concept} ('Bad Slug','task','ACTIVE',NULL,'d')"),
        check,
        "concepts_slug_check",
    );
    for values in [
        "('zz-dep','task','DEPRECATED',NULL,'d')",
        "('zz-self','task','DEPRECATED','zz-self','d')",
        "('zz-act','task','ACTIVE','knowledge-fix','d')",
    ] {
        violates(
            &mut worker,
            &format!("{concept} {values}"),
            check,
            "concepts_replacement_check",
        );
    }
    violates(
        &mut worker,
        &format!("{label} ('knowledge-fix','knowledge_type','en','PREF','FIX TWO')"),
        unique,
        "concept_labels_one_pref",
    );
    violates(
        &mut worker,
        &format!("{label} ('knowledge-decision','knowledge_type','en','ALT','fix')"),
        unique,
        "concept_labels_facet_unique",
    );
    violates(
        &mut worker,
        "INSERT INTO public.concept_relations (from_id,to_id,kind) VALUES ('knowledge-fix','knowledge-fix','RELATED')",
        check,
        "concept_relations_no_self_check",
    );
}
