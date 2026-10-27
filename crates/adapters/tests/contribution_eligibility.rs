//! `adapters::tests::contribution_eligibility` — G-M20-5 (ADR-0090 D-A, migration 0286): the public-pool eligibility predicate
//!   judges the whole M07 closure, one verdict per failing check in a fixed order; applicability is never a licence; the
//!   verdict set equals the Rust set and the notice categories equal the unit types.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, sqlx, tokio, uuid];
//!   services=[PostgreSQL(any) r=[] w=[control.contribution_notices, control.private_reasoning_domains, control.tenants,
//!   control.users, private.evidence_affects, private.evidence_objects, private.evidence_subjects, private.memory_affects,
//!   private.memory_applicability, private.memory_evidence, private.memory_records, private.memory_subjects,
//!   private.subject_roles, private.subjects] x=[private.contribution_eligibility, private.contribution_unit_type],
//!   PostgreSQL(role_gateway), PostgreSQL(role_public_worker)]; env=[HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::contribution_eligibility, domain::authority, domain::dataclass, domain::error, domain::ids,
//!   domain::note, humaux-testkit, testkit::disposable, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every test owns throwaway tenants, users and the notice versions it publishes, removed on drop; closure links are
//!   SUPPORTING or CONTRADICTING only, because a PRIMARY link fires the derived-consolidate enqueue and the affect copy hook,
//!   cluster-global effects this binary must not cause; the notice table is global and public-pool's notice binary needs it
//!   empty, so this binary runs in nextest's serial-public-notice group beside it, and plain `cargo test` or targeted.yml must
//!   pass `-- --test-threads=1` (the no-notice test needs an empty notice table); the unit types are read from the DB's
//!   `units_type_check` (0275), which public-pool's completeness test pins to `UnitType`, so this crate holds no copy; a
//!   missing database is a visible §79.2 skip, a FAIL under HUMAUX_REQUIRE_DB]
//! Spec: Baseline §7.5.1; §52; §78.2; §79.2; ADR-0088 D-A; ADR-0090 D-A; ADR-0096 D-F

use std::collections::BTreeSet;

use humaux_adapters::contribution_eligibility::{self, EligibilityVerdict};
use humaux_domain::{
    authority::MemoryId, dataclass::DataClass, error::ErrorCode, ids::TenantId, note::NoteKind,
};
use humaux_testkit::{
    DbFixtureSkipReason, DbIntegrationFixture, disposable::require_disposable,
    fixture_purge::purge_tenant_fixture_sql, run_db_fixture,
};
use postgres::{Client, NoTls};
use sqlx::{Connection, PgConnection, Postgres, Transaction};
use uuid::Uuid;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

/// A fixture tenant and its reasoning domain (the Evidence FK).
#[derive(Clone, Copy)]
struct Tenant {
    id: Uuid,
    domain: Uuid,
}

struct Handle {
    rt: tokio::runtime::Runtime,
    gateway_dsn: String,
    public_dsn: String,
    admin: Client,
    tenants: Vec<Uuid>,
    users: Vec<Uuid>,
    notices: Vec<i32>,
}

impl Drop for Handle {
    fn drop(&mut self) {
        for tenant in self.tenants.clone() {
            let purged = purge_tenant_fixture_sql(&tenant.to_string())
                .and_then(|sql| self.admin.batch_execute(&sql).map_err(|e| e.to_string()));
            if let Err(e) = purged {
                eprintln!("eligibility cleanup ({tenant}): {e}");
            }
        }
        let users = self.users.clone();
        if let Err(e) = self.admin.execute(
            "DELETE FROM control.users WHERE user_id = ANY($1)",
            &[&users],
        ) {
            eprintln!("eligibility cleanup (users): {e}");
        }
        let notices = self.notices.clone();
        if let Err(e) = self.admin.execute(
            "DELETE FROM control.contribution_notices WHERE notice_version = ANY($1)",
            &[&notices],
        ) {
            eprintln!("eligibility cleanup (notices): {e}");
        }
    }
}

struct EligibilityFixture;

impl DbIntegrationFixture for EligibilityFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the setup/inspection connection
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        require_disposable(&mut admin).unwrap_or_else(|refusal| panic!("{refusal}"));
        let migrated: bool = admin
            .query_one(
                "SELECT to_regprocedure('private.contribution_eligibility(uuid,uuid)') IS NOT NULL",
                &[],
            )
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "the eligibility predicate is missing: apply migration 0286 first".to_string(),
            ));
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the request-path role the predicate is granted to
        let gateway_dsn = dsn_as_role(&dsn, "role_gateway");
        // dep: PostgreSQL(role_public_worker) — a public role, which must be refused
        let public_dsn = dsn_as_role(&dsn, "role_public_worker");
        Ok(Handle {
            rt,
            gateway_dsn,
            public_dsn,
            admin,
            tenants: Vec::new(),
            users: Vec::new(),
            notices: Vec::new(),
        })
    }
}

/// `(evidence, role)` closure links, all SUPPORTING.
fn supporting(evidence: &[Uuid]) -> Vec<(Uuid, &'static str)> {
    evidence.iter().map(|e| (*e, "SUPPORTING")).collect()
}

/// The single-quoted literals of a CHECK definition, as a set.
fn literals(definition: &str) -> BTreeSet<String> {
    definition
        .split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

impl Handle {
    /// A throwaway tenant with a reasoning domain; purged on drop (the name carries the fixture prefix the purge demands).
    fn new_tenant(&mut self) -> Tenant {
        let id: Uuid = self
            .admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('e2e-fixture m20-5 eligibility') RETURNING tenant_id",
                &[],
            )
            .expect("insert tenant")
            .get(0);
        self.tenants.push(id);
        let domain: Uuid = self
            .admin
            .query_one(
                "INSERT INTO control.private_reasoning_domains (tenant_id, name) VALUES ($1, 'm20-5') \
                 RETURNING reasoning_domain_id",
                &[&id],
            )
            .expect("insert reasoning domain")
            .get(0);
        Tenant { id, domain }
    }

    fn new_user(&mut self) -> Uuid {
        let user = Uuid::new_v4();
        self.admin
            .execute("INSERT INTO control.users (user_id) VALUES ($1)", &[&user])
            .expect("insert user");
        self.users.push(user);
        user
    }

    /// Publishes the next notice version, effective immediately: the greatest `published_at` so far.
    fn try_publish_notice(&mut self, categories: &[&str]) -> Result<i32, postgres::Error> {
        let version: i32 = self
            .admin
            .query_one(
                "INSERT INTO control.contribution_notices \
                   (notice_version, text_sha256, scope_categories, licence_text, licence_code, published_at) \
                 SELECT coalesce(max(notice_version), 0) + 1, sha256(convert_to(gen_random_uuid()::text, 'UTF8')), \
                        $1::text[], 'CC-BY-4.0', 'MIT', clock_timestamp() \
                   FROM control.contribution_notices RETURNING notice_version",
                &[&categories],
            )?
            .get(0);
        self.notices.push(version);
        Ok(version)
    }

    fn publish_notice(&mut self, categories: &[&str]) -> i32 {
        self.try_publish_notice(categories).expect("publish notice")
    }

    /// The phase-1 unit types as the DB spells them: the literals of `units_type_check` (0275).
    fn unit_types(&mut self) -> Vec<String> {
        let definition: String = self
            .admin
            .query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                  WHERE conname = 'units_type_check' AND connamespace = 'public'::regnamespace",
                &[],
            )
            .expect("units_type_check")
            .get(0);
        literals(&definition).into_iter().collect()
    }

    fn notice_rows(&mut self) -> i64 {
        self.admin
            .query_one("SELECT count(*) FROM control.contribution_notices", &[])
            .expect("count notices")
            .get(0)
    }

    /// One Evidence row of `class`, TENANT_SHARED or (with `owner`) USER_PRIVATE to that user.
    fn evidence(&mut self, t: Tenant, class: &str, owner: Option<Uuid>) -> Uuid {
        let visibility = if owner.is_some() {
            "USER_PRIVATE"
        } else {
            "TENANT_SHARED"
        };
        self.admin
            .query_one(
                "INSERT INTO private.evidence_objects \
                   (tenant_id, evidence_kind, payload_sha256, data_class, origin_class, visibility_class, \
                    visibility_user_id, reasoning_domain_id) \
                 VALUES ($1, 'EVENT', sha256(convert_to(gen_random_uuid()::text, 'UTF8')), $2, 'DirectUserInput', \
                         $3, $4, $5) RETURNING evidence_id",
                &[&t.id, &class, &visibility, &owner, &t.domain],
            )
            .expect("insert evidence")
            .get(0)
    }

    /// An active, unarchived memory of `kind` (`None` = not a note) backed by `links`.
    fn memory(&mut self, t: Tenant, kind: Option<NoteKind>, links: &[(Uuid, &str)]) -> Uuid {
        self.memory_in_state(t, kind, "active", false, links)
    }

    /// A memory in an explicit lifecycle state. The memory and its links are one statement, so the deferred orphan trigger
    /// (0004) sees the closure at COMMIT.
    /// Each body (`key_claim`) is unique: the 0269 exact-dedupe index keys active first-version notes on its digest.
    fn memory_in_state(
        &mut self,
        t: Tenant,
        kind: Option<NoteKind>,
        status: &str,
        archived: bool,
        links: &[(Uuid, &str)],
    ) -> Uuid {
        let memory = Uuid::new_v4();
        let memory_type = kind.map_or("FACT", |k| k.memory_type().wire());
        let note_kind = kind.map(NoteKind::wire);
        let evidence: Vec<Uuid> = links.iter().map(|(e, _)| *e).collect();
        let roles: Vec<&str> = links.iter().map(|(_, r)| *r).collect();
        self.admin
            .query_one(
                "WITH m AS ( \
                   INSERT INTO private.memory_records \
                     (memory_id, tenant_id, memory_type, content, visibility_class, authority_class, confidence, \
                      status, asserted_at, archived_at, note_kind, note_id) \
                   VALUES ($1::uuid, $2, $3, jsonb_build_object('title', 'fixture', 'key_claim', gen_random_uuid()::text), 'TENANT_SHARED', 'PrivateKnowledge', \
                           0.9, $4, now(), CASE WHEN $5 THEN now() END, $6::text, \
                           CASE WHEN $6::text IS NULL THEN NULL ELSE $1::uuid END) \
                   RETURNING memory_id), \
                 l AS ( \
                   INSERT INTO private.memory_evidence (memory_id, evidence_id, role, ordinal) \
                   SELECT m.memory_id, t.e, t.r, (t.n - 1)::int \
                     FROM m, unnest($7::uuid[], $8::text[]) WITH ORDINALITY AS t(e, r, n)) \
                 SELECT memory_id FROM m",
                &[
                    &memory,
                    &t.id,
                    &memory_type,
                    &status,
                    &archived,
                    &note_kind,
                    &evidence,
                    &roles,
                ],
            )
            .expect("insert memory")
            .get(0)
    }

    /// A memory with an empty closure. The deferred orphan trigger would refuse it at COMMIT, so replica mode skips that
    /// trigger for this one insert.
    fn memory_without_evidence(&mut self, t: Tenant, kind: Option<NoteKind>) -> Uuid {
        self.admin
            .batch_execute("SET session_replication_role = replica")
            .expect("replica mode");
        let memory = self.memory_in_state(t, kind, "active", false, &[]);
        self.admin
            .batch_execute("SET session_replication_role = DEFAULT")
            .expect("origin mode");
        memory
    }

    /// An affect on the memory itself.
    fn memory_affect(&mut self, t: Tenant, memory: Uuid, evidence: Uuid) {
        self.admin
            .execute(
                "INSERT INTO private.memory_affects \
                   (tenant_id, memory_id, affect_kind, intensity_bp, confidence_bp, evidence_id, observed_at) \
                 VALUES ($1, $2, 'EMOTION', 5000, 5000, $3, now())",
                &[&t.id, &memory, &evidence],
            )
            .expect("insert memory affect");
    }

    /// An affect on a closure Evidence row only; the memory row stays clean.
    fn evidence_affect(&mut self, t: Tenant, evidence: Uuid) {
        self.admin
            .execute(
                "INSERT INTO private.evidence_affects \
                   (tenant_id, evidence_id, affect_kind, intensity_bp, confidence_bp, observed_at) \
                 VALUES ($1, $2, 'EMOTION', 5000, 5000, now())",
                &[&t.id, &evidence],
            )
            .expect("insert evidence affect");
    }

    /// A subject of `kind`, holding the CUSTOMER role when `customer`.
    fn subject(&mut self, t: Tenant, kind: &str, customer: bool) -> Uuid {
        let subject: Uuid = self
            .admin
            .query_one(
                "INSERT INTO private.subjects (tenant_id, kind, display_name) VALUES ($1, $2, 'fixture') \
                 RETURNING subject_id",
                &[&t.id, &kind],
            )
            .expect("insert subject")
            .get(0);
        if customer {
            self.admin
                .execute(
                    "INSERT INTO private.subject_roles (tenant_id, subject_id, role) VALUES ($1, $2, 'CUSTOMER')",
                    &[&t.id, &subject],
                )
                .expect("insert subject role");
        }
        subject
    }

    fn link_memory(&mut self, t: Tenant, memory: Uuid, subject: Uuid) {
        self.admin
            .execute(
                "INSERT INTO private.memory_subjects \
                   (tenant_id, memory_id, subject_id, relation, source_kind, confidence_bp) \
                 VALUES ($1, $2, $3, 'ABOUT', 'DECLARED', 10000)",
                &[&t.id, &memory, &subject],
            )
            .expect("link memory to subject");
    }

    fn link_evidence(&mut self, t: Tenant, evidence: Uuid, subject: Uuid) {
        self.admin
            .execute(
                "INSERT INTO private.evidence_subjects (tenant_id, evidence_id, subject_id, source_kind) \
                 VALUES ($1, $2, $3, 'DECLARED')",
                &[&t.id, &evidence, &subject],
            )
            .expect("link evidence to subject");
    }

    /// An APPROVED UNIVERSAL applicability row: the widest private scope there is.
    fn universal_applicability(&mut self, t: Tenant, memory: Uuid, decision_evidence: Uuid) {
        self.admin
            .execute(
                "INSERT INTO private.memory_applicability \
                   (tenant_id, memory_id, scope, qualifiers, status, assignment_method, decision_evidence_id) \
                 VALUES ($1, $2, 'UNIVERSAL', \
                         jsonb_build_object('implementation_languages', jsonb_build_array(), \
                                            'exclusions', jsonb_build_array()), \
                         'APPROVED', 'AGENT_ON_OWNER_CHAT', $3)",
                &[&t.id, &memory, &decision_evidence],
            )
            .expect("insert applicability");
    }

    /// The predicate asked as `dsn`'s role from a session of `session_tenant` and `user`, with `arg_tenant` as its argument.
    fn call(
        &self,
        dsn: &str,
        session_tenant: Uuid,
        user: Uuid,
        arg_tenant: Uuid,
        memory: Uuid,
    ) -> Result<EligibilityVerdict, ErrorCode> {
        self.rt.block_on(async {
            let mut conn = connect(dsn).await;
            let mut tx = begin(&mut conn, session_tenant, user).await;
            let verdict = contribution_eligibility::contribution_eligibility(
                &mut tx,
                TenantId(arg_tenant),
                MemoryId(memory),
            )
            .await;
            settle(tx).await;
            verdict
        })
    }

    /// The verdict `role_gateway` gets for `memory` of `tenant` in a session of that tenant and `user`.
    fn verdict(&self, tenant: Uuid, user: Uuid, memory: Uuid) -> EligibilityVerdict {
        self.call(&self.gateway_dsn, tenant, user, tenant, memory)
            .expect("the predicate")
    }
}

async fn connect(dsn: &str) -> PgConnection {
    // dep: PostgreSQL(any) — one connection per predicate call, as the role the DSN names
    PgConnection::connect(dsn).await.expect("connect")
}

async fn begin(conn: &mut PgConnection, tenant: Uuid, user: Uuid) -> Transaction<'_, Postgres> {
    // dep: PostgreSQL(any) — one transaction per predicate call
    let mut tx = conn.begin().await.expect("begin");
    // dep: PostgreSQL(any) — the session context the 0286 predicate pins its tenant argument to
    sqlx::query(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
    )
    .bind(tenant.to_string())
    .bind(user.to_string())
    .execute(&mut *tx)
    .await
    .expect("install session");
    tx
}

/// The predicate writes nothing, so every call ends in a rollback.
async fn settle(tx: Transaction<'_, Postgres>) {
    tx.rollback().await.expect("rollback");
}

/// G-M20-5 (a): a Fix note whose closure is INTERNAL and PUBLIC, linked only to an ORGANISATION and a PRODUCT without the
/// CUSTOMER role, under a notice that lists FIX, is ELIGIBLE.
#[test]
fn g_m20_5_a_clean_closure_is_eligible() {
    run_db_fixture::<EligibilityFixture, _>("g_m20_5_a_clean_closure_is_eligible", |mut h| {
        let t = h.new_tenant();
        let user = h.new_user();
        h.publish_notice(&["FIX"]);
        let internal = h.evidence(t, "INTERNAL", None);
        let public = h.evidence(t, "PUBLIC", None);
        let memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[internal, public]));
        let vendor = h.subject(t, "ORGANISATION", false);
        let product = h.subject(t, "PRODUCT", false);
        h.link_memory(t, memory, vendor);
        h.link_evidence(t, internal, product);
        assert_eq!(h.verdict(t.id, user, memory), EligibilityVerdict::Eligible);
    });
}

/// G-M20-5 (b): the memory row is clean but ONE closure Evidence, linked as CONTRADICTING, is SENSITIVE: DATA_CLASS. The
/// boundary is the lattice's: PUBLIC and INTERNAL pass, PRIVATE, SENSITIVE and SECRET_MATERIAL fail (§7.5.1).
#[test]
fn g_m20_5_b_one_over_internal_closure_evidence_is_data_class() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_b_one_over_internal_closure_evidence_is_data_class",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            h.publish_notice(&["FIX"]);
            let internal = h.evidence(t, "INTERNAL", None);
            let sensitive = h.evidence(t, "SENSITIVE", None);
            let memory = h.memory(
                t,
                Some(NoteKind::Fix),
                &[(internal, "SUPPORTING"), (sensitive, "CONTRADICTING")],
            );
            assert_eq!(h.verdict(t.id, user, memory), EligibilityVerdict::DataClass);
            for class in DataClass::ALL {
                let evidence = h.evidence(t, class.as_str(), None);
                let memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[evidence]));
                let expected = if class <= DataClass::Internal {
                    EligibilityVerdict::Eligible
                } else {
                    EligibilityVerdict::DataClass
                };
                assert_eq!(h.verdict(t.id, user, memory), expected, "{class}");
            }
        },
    );
}

/// G-M20-5 (c): a clean memory row whose closure Evidence carries an affect is AFFECT, and so is a memory carrying one itself;
/// a memory beside them with neither stays ELIGIBLE.
#[test]
fn g_m20_5_c_affect_on_the_memory_or_its_closure_is_affect() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_c_affect_on_the_memory_or_its_closure_is_affect",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            h.publish_notice(&["FIX"]);
            let clean_evidence = h.evidence(t, "INTERNAL", None);
            let clean = h.memory(t, Some(NoteKind::Fix), &supporting(&[clean_evidence]));
            let affected_evidence = h.evidence(t, "INTERNAL", None);
            let by_evidence = h.memory(t, Some(NoteKind::Fix), &supporting(&[affected_evidence]));
            h.evidence_affect(t, affected_evidence);
            let own_evidence = h.evidence(t, "INTERNAL", None);
            let by_memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[own_evidence]));
            h.memory_affect(t, by_memory, own_evidence);
            assert_eq!(h.verdict(t.id, user, clean), EligibilityVerdict::Eligible);
            assert_eq!(
                h.verdict(t.id, user, by_evidence),
                EligibilityVerdict::Affect
            );
            assert_eq!(h.verdict(t.id, user, by_memory), EligibilityVerdict::Affect);
        },
    );
}

/// G-M20-5 (d): a link to a PERSON, from the closure Evidence or from the memory, is PERSON_OR_CUSTOMER_LINK.
#[test]
fn g_m20_5_d_person_link_is_refused() {
    run_db_fixture::<EligibilityFixture, _>("g_m20_5_d_person_link_is_refused", |mut h| {
        let t = h.new_tenant();
        let user = h.new_user();
        h.publish_notice(&["FIX"]);
        let person = h.subject(t, "PERSON", false);
        let evidence = h.evidence(t, "INTERNAL", None);
        let by_evidence = h.memory(t, Some(NoteKind::Fix), &supporting(&[evidence]));
        h.link_evidence(t, evidence, person);
        let other = h.evidence(t, "INTERNAL", None);
        let by_memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[other]));
        h.link_memory(t, by_memory, person);
        for memory in [by_evidence, by_memory] {
            assert_eq!(
                h.verdict(t.id, user, memory),
                EligibilityVerdict::PersonOrCustomerLink
            );
        }
    });
}

/// G-M20-5 (e): an ORGANISATION holding the CUSTOMER role is a customer link, from the memory or from the closure Evidence;
/// the same kind of subject without the role is not.
#[test]
fn g_m20_5_e_customer_role_is_refused() {
    run_db_fixture::<EligibilityFixture, _>("g_m20_5_e_customer_role_is_refused", |mut h| {
        let t = h.new_tenant();
        let user = h.new_user();
        h.publish_notice(&["FIX"]);
        let customer = h.subject(t, "ORGANISATION", true);
        let vendor = h.subject(t, "ORGANISATION", false);
        let first = h.evidence(t, "INTERNAL", None);
        let by_memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[first]));
        h.link_memory(t, by_memory, customer);
        let second = h.evidence(t, "INTERNAL", None);
        let by_evidence = h.memory(t, Some(NoteKind::Fix), &supporting(&[second]));
        h.link_evidence(t, second, customer);
        let third = h.evidence(t, "INTERNAL", None);
        let vendor_only = h.memory(t, Some(NoteKind::Fix), &supporting(&[third]));
        h.link_memory(t, vendor_only, vendor);
        for memory in [by_memory, by_evidence] {
            assert_eq!(
                h.verdict(t.id, user, memory),
                EligibilityVerdict::PersonOrCustomerLink
            );
        }
        assert_eq!(
            h.verdict(t.id, user, vendor_only),
            EligibilityVerdict::Eligible
        );
    });
}

/// G-M20-5 (f): a Lesson note and a memory that is no note have no phase-1 unit type; with a notice listing every category,
/// exactly Fix, Decision and Research are ELIGIBLE and every other of the twelve note kinds is KIND_NOT_MAPPED.
#[test]
fn g_m20_5_f_only_three_note_kinds_have_a_unit_type() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_f_only_three_note_kinds_have_a_unit_type",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            let unit_types = h.unit_types();
            h.publish_notice(&unit_types.iter().map(String::as_str).collect::<Vec<_>>());
            let evidence = h.evidence(t, "INTERNAL", None);
            let links = supporting(&[evidence]);
            let lesson = h.memory(t, Some(NoteKind::Lesson), &links);
            let not_a_note = h.memory(t, None, &links);
            for memory in [lesson, not_a_note] {
                assert_eq!(
                    h.verdict(t.id, user, memory),
                    EligibilityVerdict::KindNotMapped
                );
            }
            for kind in NoteKind::ALL {
                let memory = h.memory(t, Some(kind), &links);
                let expected = match kind {
                    NoteKind::Fix | NoteKind::Decision | NoteKind::Research => {
                        EligibilityVerdict::Eligible
                    }
                    _ => EligibilityVerdict::KindNotMapped,
                };
                assert_eq!(h.verdict(t.id, user, memory), expected, "{}", kind.wire());
            }
        },
    );
}

/// G-M20-5 (g): a Fix note while the current notice lists only DECISION is CATEGORY_NOT_IN_NOTICE (a Decision note is
/// ELIGIBLE); the next notice version, which lists FIX, moves both.
#[test]
fn g_m20_5_g_category_must_be_in_the_current_notice() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_g_category_must_be_in_the_current_notice",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            let evidence = h.evidence(t, "INTERNAL", None);
            let links = supporting(&[evidence]);
            let fix = h.memory(t, Some(NoteKind::Fix), &links);
            let decision = h.memory(t, Some(NoteKind::Decision), &links);
            h.publish_notice(&["DECISION"]);
            assert_eq!(
                h.verdict(t.id, user, fix),
                EligibilityVerdict::CategoryNotInNotice
            );
            assert_eq!(
                h.verdict(t.id, user, decision),
                EligibilityVerdict::Eligible
            );
            h.publish_notice(&["FIX"]);
            assert_eq!(h.verdict(t.id, user, fix), EligibilityVerdict::Eligible);
            assert_eq!(
                h.verdict(t.id, user, decision),
                EligibilityVerdict::CategoryNotInNotice
            );
        },
    );
}

/// G-M20-5 (h): a memory of another tenant is NOT_FOUND under the session tenant, the verdict of an absent id; naming the
/// other tenant as the argument is a refusal, whatever the memory.
#[test]
fn g_m20_5_h_foreign_tenant_memory_is_not_found() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_h_foreign_tenant_memory_is_not_found",
        |mut h| {
            let mine = h.new_tenant();
            let theirs = h.new_tenant();
            let user = h.new_user();
            h.publish_notice(&["FIX"]);
            let evidence = h.evidence(theirs, "INTERNAL", None);
            let foreign = h.memory(theirs, Some(NoteKind::Fix), &supporting(&[evidence]));
            assert_eq!(
                h.verdict(theirs.id, user, foreign),
                EligibilityVerdict::Eligible,
                "the memory is eligible in its own tenant"
            );
            assert_eq!(
                h.verdict(mine.id, user, foreign),
                EligibilityVerdict::NotFound
            );
            assert_eq!(
                h.verdict(mine.id, user, Uuid::new_v4()),
                EligibilityVerdict::NotFound,
                "an absent id reads the same"
            );
            assert_eq!(
                h.call(&h.gateway_dsn, mine.id, user, theirs.id, foreign),
                Err(ErrorCode::Forbidden)
            );
        },
    );
}

/// G-M20-5 (i): applicability is never a licence. A memory that fails (c) and carries an APPROVED UNIVERSAL applicability row
/// is still AFFECT; a clean memory with the same row is ELIGIBLE on its own merits.
#[test]
fn g_m20_5_i_universal_applicability_is_no_licence() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_i_universal_applicability_is_no_licence",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            h.publish_notice(&["FIX"]);
            let affected_evidence = h.evidence(t, "INTERNAL", None);
            let affected = h.memory(t, Some(NoteKind::Fix), &supporting(&[affected_evidence]));
            h.evidence_affect(t, affected_evidence);
            h.universal_applicability(t, affected, affected_evidence);
            let clean_evidence = h.evidence(t, "INTERNAL", None);
            let clean = h.memory(t, Some(NoteKind::Fix), &supporting(&[clean_evidence]));
            h.universal_applicability(t, clean, clean_evidence);
            assert_eq!(h.verdict(t.id, user, affected), EligibilityVerdict::Affect);
            assert_eq!(h.verdict(t.id, user, clean), EligibilityVerdict::Eligible);
        },
    );
}

/// G-M20-5 (j): a public role may not execute the predicate, by catalog and by call; the two roles of the existing contribution
/// path may.
#[test]
fn g_m20_5_j_public_roles_cannot_execute_the_predicate() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_j_public_roles_cannot_execute_the_predicate",
        |mut h| {
            let t = h.new_tenant();
            let user = h.new_user();
            h.publish_notice(&["FIX"]);
            let evidence = h.evidence(t, "INTERNAL", None);
            let memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[evidence]));
            assert_eq!(
                h.call(&h.public_dsn, t.id, user, t.id, memory),
                Err(ErrorCode::Forbidden),
                "role_public_worker is refused"
            );
            for (role, expected) in [
                ("role_gateway", true),
                ("role_private_worker", true),
                ("role_public_worker", false),
                ("role_retrieval_worker", false),
                ("role_consolidation_worker", false),
            ] {
                let held: bool = h
                    .admin
                    .query_one(
                        "SELECT has_function_privilege($1, 'private.contribution_eligibility(uuid,uuid)', 'EXECUTE')",
                        &[&role],
                    )
                    .expect("privilege probe")
                    .get(0);
                assert_eq!(held, expected, "{role}");
            }
            let public_disclosure_executes: bool = h
                .admin
                .query_one(
                    "SELECT coalesce(bool_or(has_function_privilege(r.rolname, \
                        'private.contribution_eligibility(uuid,uuid)', 'EXECUTE')), false) \
                       FROM pg_roles r WHERE r.rolname = 'role_public_disclosure'",
                    &[],
                )
                .expect("privilege probe")
                .get(0);
            assert!(!public_disclosure_executes, "role_public_disclosure");
        },
    );
}

/// G-M20-5 (k): closure Evidence the session cannot see is unknown, never skipped. A memory backed by an Evidence row private
/// to its author is ELIGIBLE in the author's session and DATA_CLASS in another member's, so a hidden source cannot vanish
/// from the closure.
#[test]
fn g_m20_5_k_hidden_closure_evidence_fails_closed() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_k_hidden_closure_evidence_fails_closed",
        |mut h| {
            let t = h.new_tenant();
            let author = h.new_user();
            let other = h.new_user();
            h.publish_notice(&["FIX"]);
            let evidence = h.evidence(t, "INTERNAL", Some(author));
            let memory = h.memory(t, Some(NoteKind::Fix), &supporting(&[evidence]));
            assert_eq!(
                h.verdict(t.id, author, memory),
                EligibilityVerdict::Eligible
            );
            assert_eq!(
                h.verdict(t.id, other, memory),
                EligibilityVerdict::DataClass
            );
        },
    );
}

/// G-M20-5 (l): a revoked, an expired and an archived memory is NOT_ACTIVE; a memory without Evidence is
/// NO_EVIDENCE; with no notice published at all, a Fix note is NO_NOTICE.
#[test]
fn g_m20_5_l_lifecycle_evidence_and_notice_preconditions() {
    run_db_fixture::<EligibilityFixture, _>(
        "g_m20_5_l_lifecycle_evidence_and_notice_preconditions",
        |mut h| {
            assert_eq!(
                h.notice_rows(),
                0,
                "the no-notice leg needs an empty notice table: run this binary in the serial-public-notice group"
            );
            let t = h.new_tenant();
            let user = h.new_user();
            let evidence = h.evidence(t, "INTERNAL", None);
            let links = supporting(&[evidence]);
            let live = h.memory(t, Some(NoteKind::Fix), &links);
            assert_eq!(h.verdict(t.id, user, live), EligibilityVerdict::NoNotice);

            h.publish_notice(&["FIX"]);
            assert_eq!(h.verdict(t.id, user, live), EligibilityVerdict::Eligible);
            for (status, archived) in [("revoked", false), ("expired", false), ("active", true)] {
                let memory = h.memory_in_state(t, Some(NoteKind::Fix), status, archived, &links);
                assert_eq!(
                    h.verdict(t.id, user, memory),
                    EligibilityVerdict::NotActive,
                    "{status} archived={archived}"
                );
            }
            let orphan = h.memory_without_evidence(t, Some(NoteKind::Fix));
            assert_eq!(
                h.verdict(t.id, user, orphan),
                EligibilityVerdict::NoEvidence
            );
        },
    );
}

/// G-M20-5 (m): the verdict is the first failure in the fixed order. One memory per rung, each failing every later check too.
#[test]
fn g_m20_5_m_the_first_failure_wins() {
    run_db_fixture::<EligibilityFixture, _>("g_m20_5_m_the_first_failure_wins", |mut h| {
        let t = h.new_tenant();
        let user = h.new_user();
        let person = h.subject(t, "PERSON", false);
        let sensitive = h.evidence(t, "SENSITIVE", None);
        h.link_evidence(t, sensitive, person);
        h.evidence_affect(t, sensitive);
        let sensitive_links = supporting(&[sensitive]);
        let internal = h.evidence(t, "INTERNAL", None);
        h.link_evidence(t, internal, person);
        h.evidence_affect(t, internal);
        let internal_links = supporting(&[internal]);
        let plain = h.evidence(t, "INTERNAL", None);
        h.link_evidence(t, plain, person);
        let plain_links = supporting(&[plain]);

        let archived =
            h.memory_in_state(t, Some(NoteKind::Lesson), "active", true, &sensitive_links);
        let lesson = h.memory(t, Some(NoteKind::Lesson), &sensitive_links);
        let out_of_scope = h.memory(t, Some(NoteKind::Fix), &sensitive_links);
        let over_class = h.memory(t, Some(NoteKind::Fix), &sensitive_links);
        let affected = h.memory(t, Some(NoteKind::Fix), &internal_links);
        let linked = h.memory(t, Some(NoteKind::Fix), &plain_links);

        h.publish_notice(&["DECISION"]);
        assert_eq!(
            h.verdict(t.id, user, archived),
            EligibilityVerdict::NotActive
        );
        assert_eq!(
            h.verdict(t.id, user, lesson),
            EligibilityVerdict::KindNotMapped
        );
        assert_eq!(
            h.verdict(t.id, user, out_of_scope),
            EligibilityVerdict::CategoryNotInNotice
        );
        h.publish_notice(&["FIX"]);
        assert_eq!(
            h.verdict(t.id, user, over_class),
            EligibilityVerdict::DataClass
        );
        assert_eq!(h.verdict(t.id, user, affected), EligibilityVerdict::Affect);
        assert_eq!(
            h.verdict(t.id, user, linked),
            EligibilityVerdict::PersonOrCustomerLink
        );
    });
}

/// §78.2: the verdicts the function returns equal [`EligibilityVerdict::ALL`], both ways, and the function is the owner-owned
/// SECURITY DEFINER the migration declares.
#[test]
fn verdict_literals_equal_the_rust_set_and_the_function_is_pinned() {
    run_db_fixture::<EligibilityFixture, _>(
        "verdict_literals_equal_the_rust_set_and_the_function_is_pinned",
        |mut h| {
            let source: String = h
                .admin
                .query_one(
                    "SELECT prosrc FROM pg_proc WHERE oid = 'private.contribution_eligibility(uuid,uuid)'::regprocedure",
                    &[],
                )
                .expect("function source")
                .get(0);
            let db: BTreeSet<String> = source
                .split("RETURN '")
                .skip(1)
                .filter_map(|rest| rest.split('\'').next())
                .map(str::to_owned)
                .collect();
            let rust: BTreeSet<String> = EligibilityVerdict::ALL
                .iter()
                .map(|v| v.wire().to_owned())
                .collect();
            assert_eq!(rust.len(), 10);
            assert_eq!(db, rust);

            let row = h
                .admin
                .query_one(
                    "SELECT p.prosecdef, pg_get_userbyid(p.proowner)::text, p.provolatile::text, \
                            coalesce(p.proconfig, ARRAY[]::text[]) \
                       FROM pg_proc p WHERE p.oid = 'private.contribution_eligibility(uuid,uuid)'::regprocedure",
                    &[],
                )
                .expect("function attributes");
            assert!(row.get::<_, bool>(0), "SECURITY DEFINER");
            assert_eq!(row.get::<_, String>(1), "role_migration_owner");
            assert_eq!(row.get::<_, String>(2), "s");
            assert_eq!(
                row.get::<_, Vec<String>>(3),
                vec!["search_path=pg_catalog, pg_temp".to_owned()]
            );
        },
    );
}

/// ADR-0090 D-A, ADR-0096 D-F: the body of the predicate names no applicability, project-attribution or public object.
#[test]
fn the_predicate_body_reads_no_applicability_or_public_object() {
    run_db_fixture::<EligibilityFixture, _>(
        "the_predicate_body_reads_no_applicability_or_public_object",
        |mut h| {
            let definition: String = h
                .admin
                .query_one(
                    "SELECT pg_get_functiondef('private.contribution_eligibility(uuid,uuid)'::regprocedure)",
                    &[],
                )
                .expect("function definition")
                .get(0);
            assert!(definition.contains("memory_evidence"), "sentinel positive");
            for forbidden in [
                "memory_applicability",
                "memory_projects",
                "memory_in_project",
                "public.",
            ] {
                assert!(
                    !definition.contains(forbidden),
                    "the predicate must not name {forbidden}"
                );
            }
        },
    );
}

/// §78.2: the note-kind map returns only phase-1 unit types, for Fix, Decision and Research and for nothing else, and NULL
/// (a memory that is no note) maps to nothing.
#[test]
fn unit_type_map_returns_only_unit_types() {
    run_db_fixture::<EligibilityFixture, _>("unit_type_map_returns_only_unit_types", |mut h| {
        let unit_types = h.unit_types();
        let mut mapped = Vec::new();
        for kind in NoteKind::ALL {
            let unit: Option<String> = h
                .admin
                .query_one("SELECT private.contribution_unit_type($1)", &[&kind.wire()])
                .expect("unit type")
                .get(0);
            if let Some(unit) = unit {
                assert!(
                    unit_types.contains(&unit),
                    "{} maps to {unit}, which is no unit type",
                    kind.wire()
                );
                mapped.push((kind.wire(), unit));
            }
        }
        assert_eq!(
            mapped,
            vec![
                ("decision", "DECISION".to_owned()),
                ("fix", "FIX".to_owned()),
                ("research", "RESEARCH".to_owned()),
            ]
        );
        let none: Option<String> = h
            .admin
            .query_one("SELECT private.contribution_unit_type(NULL)", &[])
            .expect("unit type of NULL")
            .get(0);
        assert_eq!(none, None);
    });
}

/// §78.2: the notice scope-category CHECK equals the unit-type set, both ways, and a notice with any other category (the old
/// placeholder included) is refused by that CHECK.
#[test]
fn scope_categories_check_equals_the_unit_types() {
    run_db_fixture::<EligibilityFixture, _>(
        "scope_categories_check_equals_the_unit_types",
        |mut h| {
            let check = "contribution_notices_scope_categories_unit_types_check";
            let def: String = h
                .admin
                .query_one(
                    "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
                      WHERE conname = $1 AND conrelid = 'control.contribution_notices'::regclass",
                    &[&check],
                )
                .expect(check)
                .get(0);
            let unit_types: BTreeSet<String> = h.unit_types().into_iter().collect();
            assert_eq!(unit_types.len(), 6);
            assert_eq!(literals(&def), unit_types, "{def}");

            for categories in [&["PRIVATE_MEMORY"][..], &["FIX", "PLAYBOOK"][..]] {
                let error = h
                    .try_publish_notice(categories)
                    .expect_err("a category outside the unit types");
                let db = error.as_db_error().expect("a database error");
                assert_eq!(db.code().code(), "23514", "{categories:?}: {error}");
                assert_eq!(db.constraint(), Some(check));
            }
            assert_eq!(h.notice_rows(), 0, "a refused notice leaves no row");
        },
    );
}
