//! `adapters::tests::plan_catalog` — the plan catalogue of migration 0262 against a real PostgreSQL throwaway database:
//!   the committed values file seeds exactly its five draft versions through the owner door, a pinned version never
//!   changes, nobody but role_maintenance can write, and the template key set is closed (G-M04-1).
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, tokio];
//!   services=[PostgreSQL(owner) w=[control.plan_versions, control.plans] x=[control.publish_plan_version],
//!   PostgreSQL(role_maintenance)]; env=[];
//!   modules=[adapters::plan_repo, adapters::postgres, adapters::tests::support::throwaway_db, domain::error,
//!   domain::plan, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [every test owns its throwaway database humaux_thread_m04_plans_<pid>_<n>, created and migrated by the
//!   fixture and dropped by its Drop even on panic; the catalogue is seeded the way production seeds it, as
//!   role_maintenance through plan_repo::seed, and read back as the database owner, so the assertions judge the stored
//!   rows and not the repository's own reading of them; no DSN or unreachable DB is a visible §79.2 skip]
//! Spec: Baseline §71.1; §78.1; §78.2; §79.2
//!
//! The values file under test is the committed placeholder (`deploy/plans/plan_catalogue.json`): the assertions pin its
//! shape, not any commercial number.

use humaux_adapters::plan_repo::{self, SeedReport};
use humaux_adapters::postgres::MaintenanceDbPool;
use humaux_domain::error::ErrorCode;
use humaux_domain::plan::{
    ChargePolicy, EntitlementKey, EntitlementTemplate, QuotaPeriod, TemplateValue,
};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use serde_json::{Value, json};

#[path = "support/throwaway_db.rs"]
#[allow(dead_code)]
mod throwaway_db;
use throwaway_db::ThrowawayDb;

/// The committed placeholder catalogue.
const CATALOGUE: &str = include_str!("../../../deploy/plans/plan_catalogue.json");

/// The nine principals the catalogue must not be writable by: the eight login roles and PUBLIC.
const NON_WRITERS: [&str; 9] = [
    "role_gateway",
    "role_private_worker",
    "role_consolidation_worker",
    "role_public_worker",
    "role_retrieval_worker",
    "role_batch_issuer",
    "role_maintenance",
    "role_admin",
    "public",
];

/// A row of `versions()`: plan key, version, price, billing interval, is-a-draft.
type VersionRow = (String, i32, i64, String, bool);

fn row(key: &str, version: i32, price: i64, interval: &str, draft: bool) -> VersionRow {
    (key.to_owned(), version, price, interval.to_owned(), draft)
}

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

fn catalogue() -> Value {
    serde_json::from_str(CATALOGUE).expect("the committed catalogue is JSON")
}

/// Fields drop in order: the pool and the owner connection close before `_db` drops the database.
struct Handle {
    rt: tokio::runtime::Runtime,
    maintenance: MaintenanceDbPool,
    admin: Client,
    _db: ThrowawayDb,
}

struct PlanFixture;

impl DbIntegrationFixture for PlanFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        let db = throwaway_db::create("m04_plans")?;
        let dsn = db.dsn();
        // dep: PostgreSQL(owner) — the fixture's owner connection to this test's throwaway database
        let admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(role_maintenance) — the door's only caller role
        let maintenance = rt
            .block_on(MaintenanceDbPool::connect(&dsn_as_role(
                &dsn,
                "role_maintenance",
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
            maintenance,
            admin,
            _db: db,
        })
    }
}

impl Handle {
    /// Parses `text` and seeds it as role_maintenance.
    fn seed_text(&self, text: &str) -> Result<SeedReport, ErrorCode> {
        let specs = plan_repo::parse_catalogue(text).expect("the catalogue text parses");
        self.rt.block_on(plan_repo::seed(&self.maintenance, &specs))
    }

    /// Every stored version, in plan-key then version order.
    fn versions(&mut self) -> Vec<VersionRow> {
        self.admin
            .query(
                "SELECT p.plan_key, v.version, v.price_cents, v.billing_interval, v.valid_from IS NULL \
                 FROM control.plan_versions v JOIN control.plans p ON p.plan_id = v.plan_id \
                 ORDER BY p.plan_key COLLATE \"C\", v.version",
                &[],
            )
            .expect("read versions")
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
            .collect()
    }

    /// One text column of the version priced `price` (the placeholder prices are distinct).
    fn text_of(&mut self, column: &str, price: i64) -> String {
        self.admin
            .query_one(
                &format!("SELECT {column}::text FROM control.plan_versions WHERE price_cents = $1"),
                &[&price],
            )
            .expect("read one column")
            .get(0)
    }
}

/// A sample value of the shape `key` demands.
fn sample(key: EntitlementKey) -> TemplateValue {
    [
        TemplateValue::PeriodQuota {
            limit: 1,
            period: QuotaPeriod::CalendarMonth,
            charge_policy: ChargePolicy::SuccessOnly,
        },
        TemplateValue::Allowance { limit: 1 },
        TemplateValue::Flag,
    ]
    .into_iter()
    .find(|value| key.accepts(value))
    .expect("every key accepts one of the three shapes")
}

/// Inserts a version of the plan `closed_set` straight as the owner, bypassing the door and its Rust validation.
fn insert_version(
    admin: &mut Client,
    version: i32,
    template: &Value,
    references: &Value,
) -> Result<u64, postgres::Error> {
    admin.execute(
        "INSERT INTO control.plan_versions \
           (plan_id, version, price_cents, billing_interval, entitlement_template, lease_block, provider_product_ref) \
         SELECT plan_id, $1::integer, 0, 'month', $2::jsonb, 1, $3::jsonb \
           FROM control.plans WHERE plan_key = 'closed_set'",
        &[&version, template, references],
    )
}

/// SQLSTATE of check_violation, the class a pinned version's refusals carry.
const CHECK_VIOLATION: &str = "23514";

/// The SQLSTATE of a refused statement.
fn sqlstate(error: &postgres::Error) -> Option<&str> {
    error.code().map(SqlState::code)
}

/// The server's message of a refused statement (`postgres::Error` displays only "db error").
fn message(error: &postgres::Error) -> &str {
    error.as_db_error().map_or("", |db| db.message())
}

/// The constraint a refused statement violated.
fn violated(error: &postgres::Error) -> Option<&str> {
    error.as_db_error().and_then(|db| db.constraint())
}

/// The stored rows are the file's rows: template, provider mapping, lease block and currency, version by version.
fn assert_rows_are_the_files(h: &mut Handle) {
    let specs = plan_repo::parse_catalogue(CATALOGUE).expect("parses");
    for spec in &specs {
        let key = spec.plan_key().as_str();
        let stored = h
            .admin
            .query_one(
                "SELECT v.entitlement_template, v.provider_product_ref, v.lease_block, v.currency \
                 FROM control.plan_versions v JOIN control.plans p ON p.plan_id = v.plan_id \
                 WHERE p.plan_key = $1 AND v.version = $2",
                &[&key, &spec.version()],
            )
            .expect("stored version");
        assert_eq!(
            stored.get::<_, Value>(0),
            plan_repo::entitlement_template_json(spec.entitlement_template()),
            "{key}: template"
        );
        assert_eq!(
            stored.get::<_, Value>(1),
            plan_repo::provider_product_ref_json(spec.provider_product_ref()),
            "{key}: provider mapping"
        );
        assert_eq!(
            stored.get::<_, i32>(2),
            spec.lease_block(),
            "{key}: lease block"
        );
        assert_eq!(stored.get::<_, String>(3), "USD", "{key}: currency");
    }
}

/// No login role and not PUBLIC holds a write verb on either table, and only role_maintenance can execute the door.
fn assert_only_the_door_writes(h: &mut Handle) {
    let principals: Vec<&str> = NON_WRITERS.to_vec();
    let tables: Vec<&str> = ["control.plans", "control.plan_versions"].to_vec();
    let verbs: Vec<&str> = ["INSERT", "UPDATE", "DELETE", "TRUNCATE"].to_vec();
    let writers: i64 = h
        .admin
        .query_one(
            "SELECT count(*) FROM unnest($1::text[]) r CROSS JOIN unnest($2::text[]) t \
             CROSS JOIN unnest($3::text[]) v WHERE has_table_privilege(r, t, v)",
            &[&principals, &tables, &verbs],
        )
        .expect("write privileges")
        .get(0);
    assert_eq!(
        writers, 0,
        "no principal holds a write verb on a catalogue table"
    );
    let executors: Vec<String> = h
        .admin
        .query(
            "SELECT r FROM unnest($1::text[]) r WHERE has_function_privilege(r, \
             'control.publish_plan_version(text,integer,bigint,text,text,jsonb,integer,jsonb,boolean)'::regprocedure, \
             'EXECUTE')",
            &[&principals],
        )
        .expect("door executors")
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(executors, ["role_maintenance"]);
}

/// The committed catalogue seeds exactly its five draft versions, once, through the owner door as role_maintenance, and
/// the stored rows are the file's rows. The door is the only writer. Fault: a seed that skips a version or stores a
/// different template, or a grant that opens a table ⇒ red.
#[test]
fn the_committed_catalogue_seeds_exactly_its_versions_once_and_only_the_door_writes() {
    run_db_fixture::<PlanFixture, _>(
        "the_committed_catalogue_seeds_exactly_its_versions_once_and_only_the_door_writes",
        |mut h| {
            let seeded = SeedReport {
                created: 5,
                existing: 0,
            };
            assert_eq!(h.seed_text(CATALOGUE), Ok(seeded));
            let expected = [
                row("basic", 1, 100, "month", true),
                row("basic_yearly", 1, 1000, "year", true),
                row("free", 1, 0, "month", true),
                row("max", 1, 300, "month", true),
                row("pro", 1, 200, "month", true),
            ];
            assert_eq!(h.versions(), expected);
            let plans: i64 = h
                .admin
                .query_one("SELECT count(*) FROM control.plans", &[])
                .expect("count plans")
                .get(0);
            assert_eq!(plans, 5, "one plan per plan key");
            assert_rows_are_the_files(&mut h);

            let repeat = SeedReport {
                created: 0,
                existing: 5,
            };
            assert_eq!(
                h.seed_text(CATALOGUE),
                Ok(repeat),
                "a repeat call verifies and writes no new version"
            );
            assert_eq!(h.versions(), expected);
            assert_only_the_door_writes(&mut h);
        },
    );
}

/// A seed that disagrees with a stored version is Conflict and leaves nothing behind, a version it would have created
/// included.
fn assert_a_disagreeing_seed_leaves_nothing_behind(h: &mut Handle, baseline: &[VersionRow]) {
    let mut changed = catalogue();
    changed["plan_versions"][4]["price_cents"] = json!(1001);
    let mut next = catalogue()["plan_versions"][0].clone();
    next["version"] = json!(2);
    changed["plan_versions"]
        .as_array_mut()
        .expect("array")
        .insert(0, next);
    assert_eq!(h.seed_text(&changed.to_string()), Err(ErrorCode::Conflict));
    assert_eq!(
        h.versions(),
        baseline,
        "a refused call leaves nothing behind"
    );
}

/// The owner cannot rewrite or remove a pinned version either, and cannot retire a draft.
fn assert_the_owner_cannot_rewrite_remove_or_retire_a_draft(
    h: &mut Handle,
    baseline: &[VersionRow],
) {
    for set in [
        "price_cents = price_cents + 1",
        "lease_block = lease_block + 1",
        "billing_interval = 'year'",
        "entitlement_template = '{}'::jsonb",
        "version = version + 1",
    ] {
        let error = h
            .admin
            .execute(
                &format!("UPDATE control.plan_versions SET {set} WHERE price_cents = 100"),
                &[],
            )
            .expect_err(set);
        assert_eq!(sqlstate(&error), Some(CHECK_VIOLATION), "{set}: {error:?}");
        assert!(
            message(&error).contains("never changes"),
            "{set}: {error:?}"
        );
    }
    let removal = h
        .admin
        .execute(
            "DELETE FROM control.plan_versions WHERE price_cents = 100",
            &[],
        )
        .expect_err("a version is never removed");
    assert_eq!(sqlstate(&removal), Some(CHECK_VIOLATION));
    assert!(message(&removal).contains("never removed"), "{removal:?}");
    assert_eq!(h.versions(), baseline);

    let draft = h
        .admin
        .execute(
            "UPDATE control.plan_versions SET retired_at = now() WHERE price_cents = 200",
            &[],
        )
        .expect_err("a draft cannot be retired");
    assert_eq!(
        violated(&draft),
        Some("plan_versions_lifecycle"),
        "{draft:?}"
    );
}

/// Publishing is a repeat call with the flag set and happens once, the provider mapping moves in the same call, a
/// published version is never a draft again, and retiring happens once.
fn assert_publish_and_retire_move_once(h: &mut Handle, baseline: &[VersionRow]) {
    let mut published = catalogue();
    published["plan_versions"][2]["published"] = json!(true);
    published["plan_versions"][2]["provider_product_ref"]["test"] = json!("test_product_pro_v1");
    let repeat = SeedReport {
        created: 0,
        existing: 5,
    };
    assert_eq!(h.seed_text(&published.to_string()), Ok(repeat));
    let mut after_publish = baseline.to_vec();
    after_publish[4] = row("pro", 1, 200, "month", false);
    assert_eq!(h.versions(), after_publish);
    let mapping: Value =
        serde_json::from_str(&h.text_of("provider_product_ref", 200)).expect("json");
    assert_eq!(
        mapping,
        json!({ "fake": "fake_product_pro_v1", "test": "test_product_pro_v1" })
    );
    let published_at = h.text_of("valid_from", 200);
    assert_eq!(h.seed_text(&published.to_string()), Ok(repeat));
    assert_eq!(
        h.text_of("valid_from", 200),
        published_at,
        "publishing happens once"
    );

    assert_eq!(h.seed_text(CATALOGUE), Err(ErrorCode::Conflict));
    assert_eq!(
        h.versions(),
        after_publish,
        "a published version is never a draft again"
    );

    h.admin
        .execute(
            "UPDATE control.plan_versions SET retired_at = now() WHERE price_cents = 200",
            &[],
        )
        .expect("a published version can be retired");
    let retired_at = h.text_of("retired_at", 200);
    let again = h
        .admin
        .execute(
            "UPDATE control.plan_versions SET retired_at = now() + interval '1 hour' WHERE price_cents = 200",
            &[],
        )
        .expect_err("retired_at is set once");
    assert_eq!(sqlstate(&again), Some(CHECK_VIOLATION));
    assert!(message(&again).contains("set once"), "{again:?}");
    assert_eq!(h.text_of("retired_at", 200), retired_at);
}

/// A pinned version never changes: only the one-way publish, the one-way retire and the provider mapping move. Fault:
/// drop the content comparison, the pin trigger or the lifecycle CHECK ⇒ red.
#[test]
fn a_pinned_version_never_changes_and_only_publish_retire_and_mapping_move() {
    run_db_fixture::<PlanFixture, _>(
        "a_pinned_version_never_changes_and_only_publish_retire_and_mapping_move",
        |mut h| {
            h.seed_text(CATALOGUE).expect("baseline seed");
            let baseline = h.versions();
            assert_eq!(baseline.len(), 5);
            assert_a_disagreeing_seed_leaves_nothing_behind(&mut h, &baseline);
            assert_the_owner_cannot_rewrite_remove_or_retire_a_draft(&mut h, &baseline);
            assert_publish_and_retire_move_once(&mut h, &baseline);
        },
    );
}

/// SQLSTATE of unique_violation, which the door raises for a term that differs from the stored version.
const UNIQUE_VIOLATION: &str = "23505";

/// What `plan_versions_pin` says when a commercial term of a version changes (migration 0262).
const PINNED_MESSAGE: &str = "a pinned plan version never changes: publish a new version number";

/// What `plan_versions_pin` says when a version is removed.
const REMOVED_MESSAGE: &str = "a plan version is never removed: retire it";

/// What the door says when a repeat call carries a different term.
const CONFLICT_MESSAGE: &str = "plan version content conflict";

/// The commercial terms of a stored version: price, currency, interval, template, lease block.
type Terms = (i64, String, String, Value, i32);

/// The stored commercial terms of the version of `plan_key` (every plan has one version in these tests).
fn stored_terms(h: &mut Handle, plan_key: &str) -> Terms {
    let stored = h
        .admin
        .query_one(
            "SELECT v.price_cents, v.currency, v.billing_interval, v.entitlement_template, v.lease_block \
             FROM control.plan_versions v JOIN control.plans p ON p.plan_id = v.plan_id WHERE p.plan_key = $1",
            &[&plan_key],
        )
        .expect("stored terms");
    (
        stored.get(0),
        stored.get(1),
        stored.get(2),
        stored.get(3),
        stored.get(4),
    )
}

/// The owner cannot rewrite or remove a PUBLISHED version either: every commercial term is refused by the pin trigger
/// itself (its SQLSTATE and its exact message; for the currency this also proves the trigger fires before the CHECK that
/// would refuse `EUR` on its own), and the stored terms and the row survive each attempt.
fn assert_the_owner_cannot_rewrite_or_remove_a_published_version(h: &mut Handle, terms: &Terms) {
    for set in [
        "price_cents = price_cents + 1",
        "currency = 'EUR'",
        "billing_interval = 'year'",
        "entitlement_template = '{}'::jsonb",
        "lease_block = lease_block + 1",
    ] {
        let error = h
            .admin
            .execute(
                &format!("UPDATE control.plan_versions SET {set} WHERE price_cents = 200"),
                &[],
            )
            .expect_err(set);
        assert_eq!(sqlstate(&error), Some(CHECK_VIOLATION), "{set}: {error:?}");
        assert_eq!(message(&error), PINNED_MESSAGE, "{set}: {error:?}");
        assert_eq!(
            violated(&error),
            None,
            "{set}: refused by the trigger, not by a CHECK"
        );
        assert_eq!(
            &stored_terms(h, "pro"),
            terms,
            "{set}: the stored terms are unchanged"
        );
    }
    let removal = h
        .admin
        .execute(
            "DELETE FROM control.plan_versions WHERE price_cents = 200",
            &[],
        )
        .expect_err("a published version is never removed");
    assert_eq!(sqlstate(&removal), Some(CHECK_VIOLATION), "{removal:?}");
    assert_eq!(message(&removal), REMOVED_MESSAGE, "{removal:?}");
    assert_eq!(
        h.versions().len(),
        5,
        "the published row survives its removal"
    );
    assert_eq!(&stored_terms(h, "pro"), terms);
}

/// One call of the door for the published `pro` version with the given terms; the rest is what the file states.
fn door_call(
    h: &mut Handle,
    price: i64,
    interval: &str,
    template: &Value,
    lease_block: i32,
) -> Result<usize, postgres::Error> {
    let references = json!({ "fake": "fake_product_pro_v1" });
    h.admin
        .query(
            "SELECT out_created FROM control.publish_plan_version($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &"pro",
                &1_i32,
                &price,
                &"USD",
                &interval,
                template,
                &lease_block,
                &references,
                &true,
            ],
        )
        .map(|rows| rows.len())
}

/// A repeat call for a published version that carries a changed term is refused at the door with 23505, through the
/// repository as `Conflict`, and the stored terms are exactly what they were; the same call with the stored terms is
/// accepted, so the refusals are about the changed term alone.
fn assert_the_door_refuses_a_changed_term_of_a_published_version(h: &mut Handle, terms: &Terms) {
    let (price, _, _, template, lease_block) = terms;
    assert_eq!(*price, 200, "the published price is the file's");
    assert_eq!(
        door_call(h, 200, "month", template, *lease_block).expect("the stored terms are accepted"),
        1
    );
    let empty = json!({});
    let attempts: [(&str, Result<usize, postgres::Error>); 4] = [
        ("price", door_call(h, 201, "month", template, *lease_block)),
        (
            "interval",
            door_call(h, 200, "year", template, *lease_block),
        ),
        ("template", door_call(h, 200, "month", &empty, *lease_block)),
        (
            "lease block",
            door_call(h, 200, "month", template, lease_block + 1),
        ),
    ];
    for (term, attempt) in attempts {
        let error = attempt.expect_err(term);
        assert_eq!(
            sqlstate(&error),
            Some(UNIQUE_VIOLATION),
            "{term}: {error:?}"
        );
        assert_eq!(message(&error), CONFLICT_MESSAGE, "{term}: {error:?}");
    }
    let mut dearer = catalogue();
    dearer["plan_versions"][2]["published"] = json!(true);
    dearer["plan_versions"][2]["price_cents"] = json!(201);
    assert_eq!(h.seed_text(&dearer.to_string()), Err(ErrorCode::Conflict));
    assert_eq!(
        stored_terms(h, "pro").0,
        200,
        "the stored price is unchanged"
    );
    assert_eq!(&stored_terms(h, "pro"), terms);
}

/// A PUBLISHED version is pinned exactly like a draft: the owner cannot change a commercial term or remove it, and a
/// repeat seed that carries a changed term is refused. Fault: a trigger that pins only drafts (or none), or a door that
/// stops comparing a term ⇒ red.
#[test]
fn a_published_version_is_pinned_against_the_owner_and_the_door() {
    run_db_fixture::<PlanFixture, _>(
        "a_published_version_is_pinned_against_the_owner_and_the_door",
        |mut h| {
            let mut published = catalogue();
            published["plan_versions"][2]["published"] = json!(true);
            let seeded = SeedReport {
                created: 5,
                existing: 0,
            };
            assert_eq!(h.seed_text(&published.to_string()), Ok(seeded));
            let draft: Vec<bool> = h.versions().iter().map(|r| r.4).collect();
            assert_eq!(
                draft,
                [true, true, true, true, false],
                "only pro (last in plan-key order) is published"
            );
            let terms = stored_terms(&mut h, "pro");
            let file_template = catalogue()["plan_versions"][2]["entitlement_template"].clone();
            assert_eq!(
                terms,
                (
                    200,
                    "USD".to_owned(),
                    "month".to_owned(),
                    file_template,
                    256
                )
            );
            assert_the_owner_cannot_rewrite_or_remove_a_published_version(&mut h, &terms);
            assert_the_door_refuses_a_changed_term_of_a_published_version(&mut h, &terms);
        },
    );
}

/// The entitlement-template key set is closed: the database accepts a template carrying each `EntitlementKey` and
/// refuses one carrying a key outside the set, a template that is not an object, and a provider mapping keyed by anything
/// but a billing mode; a plan key must have the catalogue's shape. Fault: a Rust key the CHECK lacks (or the reverse) ⇒
/// the per-key insert, or the outside-key refusal, is red.
#[test]
fn the_template_key_set_is_closed() {
    run_db_fixture::<PlanFixture, _>("the_template_key_set_is_closed", |mut h| {
        h.admin
            .execute(
                "INSERT INTO control.plans (plan_key) VALUES ('closed_set')",
                &[],
            )
            .expect("plan row");
        for (index, key) in EntitlementKey::ALL.into_iter().enumerate() {
            let template =
                EntitlementTemplate::new([(key, sample(key))]).expect("a sample fits its key");
            let version = i32::try_from(index).expect("small") + 1;
            insert_version(
                &mut h.admin,
                version,
                &plan_repo::entitlement_template_json(&template),
                &json!({}),
            )
            .unwrap_or_else(|e| {
                panic!("the database must accept template key {}: {e}", key.wire())
            });
        }
        let everything =
            EntitlementTemplate::new(EntitlementKey::ALL.map(|key| (key, sample(key))))
                .expect("one value per key");
        insert_version(
            &mut h.admin,
            50,
            &plan_repo::entitlement_template_json(&everything),
            &json!({ "fake": "a", "test": "b", "live": "c" }),
        )
        .expect("a template with every key and a mapping with every mode");

        let refused = [
            json!({ "feature.other": true }),
            json!({ "feature.byok": true, "feature.other": true }),
            json!([]),
            json!("feature.byok"),
            json!(1),
        ];
        for (index, template) in refused.iter().enumerate() {
            let version = 100 + i32::try_from(index).expect("small");
            let error = insert_version(&mut h.admin, version, template, &json!({}))
                .expect_err("a template outside the closed set must be refused");
            assert_eq!(
                violated(&error),
                Some("plan_versions_template_keys_v1_check"),
                "{template}: {error:?}"
            );
        }
        let mapping = insert_version(&mut h.admin, 200, &json!({}), &json!({ "staging": "x" }))
            .expect_err("a provider mode outside the set must be refused");
        assert_eq!(
            violated(&mapping),
            Some("plan_versions_provider_modes_v1_check"),
            "{mapping:?}"
        );

        let key_shape = h
            .admin
            .execute(
                "INSERT INTO control.plans (plan_key) VALUES ('Bad Key')",
                &[],
            )
            .expect_err("a plan key has the catalogue's shape");
        assert_eq!(
            violated(&key_shape),
            Some("plans_plan_key_shape"),
            "{key_shape:?}"
        );

        let stored: i64 = h
            .admin
            .query_one("SELECT count(*) FROM control.plan_versions", &[])
            .expect("count versions")
            .get(0);
        assert_eq!(
            stored, 7,
            "six single-key versions and the all-keys one; every refusal stored nothing"
        );
    });
}
