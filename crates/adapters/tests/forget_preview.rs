//! `adapters::tests::forget_preview` — G-M19-1 (preview honesty) and the M19-2 request-v2 contract: frozen closure,
//!   manifest hash, visibility-filtered impact preview, 0272 shape and grants, on a disposable database.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, sqlx, tokio]; services=[PostgreSQL(any) w=[control.deletion_requests, control.deletion_targets, control.private_reasoning_domains, control.tenants, control.users, private.evidence_edges, private.evidence_objects, private.evidence_subjects, private.memory_evidence, private.memory_records, private.subjects], PostgreSQL(owner), PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::forget_repo, application::forget, domain::identity, domain::ids, humaux-testkit, testkit::disposable, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every fixture calls require_disposable before it writes a row; the closure is frozen from the owner view and
//!   previewed through role_gateway under each user's own RLS; every count, title set and hash is asserted exactly]
//! Spec: ADR-0092 D-A, D-B; module design M19 D1, D2, D3; G-M19-1; §78.2; §79.2

use std::collections::BTreeSet;

use humaux_adapters::forget_repo::{self, FrozenDeletion};
use humaux_application::forget::{
    DeletionScopeKind, DeletionTarget, DeletionTargetKind, ImpactPreview, manifest_hash,
};
use humaux_domain::identity::{AuthorizationScope, BoundedSet, PrincipalId};
use humaux_domain::ids::{TenantId, UserId, WorkspaceId};
use humaux_testkit::disposable::require_disposable;
use humaux_testkit::fixture_purge::purge_tenant_fixture_sql;
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;

fn dsn_as_role(admin_dsn: &str, role: &str) -> String {
    let sep = if admin_dsn.contains('?') { '&' } else { '?' };
    format!("{admin_dsn}{sep}options=-c%20role%3D{role}")
}

struct Handle {
    rt: tokio::runtime::Runtime,
    admin_pool: sqlx::Pool<sqlx::Postgres>,
    gateway_pool: sqlx::Pool<sqlx::Postgres>,
    admin: Client,
    tenant_id: Uuid,
    reasoning_domain: Uuid,
    /// The user the requests are recorded for, and the two readers of the closure.
    requester: Uuid,
    reader: Uuid,
    other_reader: Uuid,
}

impl Drop for Handle {
    fn drop(&mut self) {
        let purged = purge_tenant_fixture_sql(&self.tenant_id.to_string())
            .and_then(|sql| self.admin.batch_execute(&sql).map_err(|e| e.to_string()));
        if let Err(e) = purged {
            eprintln!("forget_preview cleanup ({}): {e}", self.tenant_id);
        }
    }
}

struct Fixture;

fn new_user(admin: &mut Client) -> Uuid {
    admin
        .query_one(
            "INSERT INTO control.users (state) VALUES ('ACTIVE') RETURNING user_id",
            &[],
        )
        .expect("seed user")
        .get(0)
}

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        let setup = |e: String| DbFixtureSkipReason::IsolationSetupFailed(e);
        // dep: PostgreSQL(owner) — admin connection for seeding, inspection and cleanup
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        require_disposable(&mut admin).unwrap_or_else(|refusal| panic!("{refusal}"));
        let reached: bool = admin
            .query_one(
                "SELECT to_regclass('control.deletion_targets') IS NOT NULL",
                &[],
            )
            .map_err(|e| setup(e.to_string()))?
            .get(0);
        if !reached {
            return Err(setup(
                "control.deletion_targets does not exist (migration 0272)".into(),
            ));
        }
        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ('e2e-fixture forget_preview') RETURNING tenant_id",
                &[],
            )
            .map_err(|e| setup(e.to_string()))?
            .get(0);
        let reasoning_domain: Uuid = admin
            .query_one(
                "INSERT INTO control.private_reasoning_domains (tenant_id, name) \
                 VALUES ($1, 'forget_preview') RETURNING reasoning_domain_id",
                &[&tenant_id],
            )
            .map_err(|e| setup(e.to_string()))?
            .get(0);
        let (requester, reader, other_reader) = (
            new_user(&mut admin),
            new_user(&mut admin),
            new_user(&mut admin),
        );
        let rt = tokio::runtime::Runtime::new().map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(owner) — the closure walk sees every row of the tenant
        let admin_pool = rt
            .block_on(sqlx::Pool::<sqlx::Postgres>::connect(&dsn))
            .map_err(|e| setup(e.to_string()))?;
        // dep: PostgreSQL(role_gateway) — the preview runs under the request-path role's RLS
        let gateway_pool = rt
            .block_on(sqlx::Pool::<sqlx::Postgres>::connect(&dsn_as_role(
                &dsn,
                "role_gateway",
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
            admin_pool,
            gateway_pool,
            admin,
            tenant_id,
            reasoning_domain,
            requester,
            reader,
            other_reader,
        })
    }
}

/// An Evidence row visible to the whole tenant (`owner` None) or private to `owner`.
fn seed_evidence(h: &mut Handle, label: &str, owner: Option<Uuid>) -> Uuid {
    let class = if owner.is_some() {
        "USER_PRIVATE"
    } else {
        "TENANT_SHARED"
    };
    h.admin
        .query_one(
            "INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, data_class, \
               origin_class, visibility_class, visibility_user_id, reasoning_domain_id) \
             VALUES ($1, 'EVENT', sha256(convert_to($2::text, 'UTF8')), 'INTERNAL', 'DirectUserInput', \
               $3::text, $4::uuid, $5) RETURNING evidence_id",
            &[&h.tenant_id, &label, &class, &owner, &h.reasoning_domain],
        )
        .expect("seed evidence")
        .get(0)
}

/// A Memory titled `title` whose inputs are `inputs` (first PRIMARY, the rest SUPPORTING), in one statement so the deferred
/// orphan check (§8.6) passes.
fn seed_memory(h: &mut Handle, title: &str, owner: Option<Uuid>, inputs: &[Uuid]) -> Uuid {
    let class = if owner.is_some() {
        "USER_PRIVATE"
    } else {
        "TENANT_SHARED"
    };
    h.admin
        .query_one(
            "WITH m AS ( \
               INSERT INTO private.memory_records (tenant_id, memory_type, content, visibility_class, \
                 visibility_user_id, authority_class, confidence, status, asserted_at) \
               VALUES ($1, 'NOTE', jsonb_build_object('title', $2::text), $3::text, $4::uuid, \
                 'PrivateKnowledge', 0.9, 'active', now()) RETURNING memory_id), \
             l AS ( \
               INSERT INTO private.memory_evidence (memory_id, evidence_id, role, ordinal) \
               SELECT m.memory_id, t.e, CASE WHEN t.n = 1 THEN 'PRIMARY' ELSE 'SUPPORTING' END, (t.n - 1)::int \
                 FROM m, unnest($5::uuid[]) WITH ORDINALITY AS t(e, n)) \
             SELECT memory_id FROM m",
            &[&h.tenant_id, &title, &class, &owner, &inputs],
        )
        .expect("seed memory")
        .get(0)
}

fn derive(h: &mut Handle, child: Uuid, parent: Uuid) {
    h.admin
        .execute(
            "INSERT INTO private.evidence_edges (child_evidence_id, parent_evidence_id, relation) \
             VALUES ($1, $2, 'DERIVED_FROM')",
            &[&child, &parent],
        )
        .expect("seed DERIVED_FROM edge");
}

fn link_two_subjects(h: &mut Handle, evidence: Uuid) {
    for name in ["Ada", "Grace"] {
        let subject: Uuid = h
            .admin
            .query_one(
                "INSERT INTO private.subjects (tenant_id, kind, display_name) \
                 VALUES ($1, 'PERSON', $2) RETURNING subject_id",
                &[&h.tenant_id, &name],
            )
            .expect("seed subject")
            .get(0);
        h.admin
            .execute(
                "INSERT INTO private.evidence_subjects (tenant_id, evidence_id, subject_id, source_kind) \
                 VALUES ($1, $2, $3, 'DECLARED')",
                &[&h.tenant_id, &evidence, &subject],
            )
            .expect("seed evidence_subjects");
    }
}

/// The seeded closure: Evidence root → {child (shared), hidden (private to `other_reader`)}, plus an unrelated Evidence.
struct Seeded {
    root: Uuid,
    child: Uuid,
    hidden: Uuid,
    memories: [Uuid; 4],
}

fn seed_closure(h: &mut Handle) -> Seeded {
    let other = h.other_reader;
    let root = seed_evidence(h, "root", None);
    let child = seed_evidence(h, "child", None);
    let hidden = seed_evidence(h, "hidden", Some(other));
    let unrelated = seed_evidence(h, "unrelated", None);
    derive(h, child, root);
    derive(h, hidden, root);
    link_two_subjects(h, child);
    link_two_subjects(h, hidden);
    let alpha = seed_memory(h, "alpha", None, &[root]);
    let beta = seed_memory(h, "beta", None, &[child]);
    let secret = seed_memory(h, "secret", Some(other), &[hidden]);
    // Tenant-shared, but one backing Evidence is private: unreadable to everyone but `other_reader` (§8.6).
    let mixed = seed_memory(h, "mixed", None, &[root, hidden]);
    seed_memory(h, "unrelated", None, &[unrelated]);
    Seeded {
        root,
        child,
        hidden,
        memories: [alpha, beta, secret, mixed],
    }
}

fn expected_targets(s: &Seeded) -> Vec<DeletionTarget> {
    let evidence = [s.root, s.child, s.hidden].map(|id| DeletionTarget {
        kind: DeletionTargetKind::Evidence,
        id,
    });
    let memories = s.memories.map(|id| DeletionTarget {
        kind: DeletionTargetKind::Memory,
        id,
    });
    evidence.into_iter().chain(memories).collect()
}

fn freeze(h: &Handle, roots: &[Uuid]) -> FrozenDeletion {
    h.rt.block_on(async {
        // dep: PostgreSQL(owner) — the closure walk sees every row of the tenant
        let mut txn = h.admin_pool.begin().await.expect("begin");
        let frozen =
            forget_repo::freeze_evidence_closure_in_txn(&mut txn, h.tenant_id, h.requester, roots)
                .await
                .expect("freeze");
        txn.commit().await.expect("commit");
        frozen
    })
}

fn preview(h: &Handle, user: Uuid, request_id: Uuid) -> ImpactPreview {
    let authorization = AuthorizationScope::new(
        TenantId(h.tenant_id),
        PrincipalId::new(),
        Some(UserId(user)),
        BoundedSet::new([WorkspaceId::new()]).expect("one workspace"),
    );
    h.rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — the preview runs under the request-path role's RLS
        let mut txn = h.gateway_pool.begin().await.expect("begin");
        let preview = forget_repo::preview_in_txn(&mut txn, &authorization, request_id)
            .await
            .expect("preview");
        txn.rollback().await.expect("rollback");
        preview
    })
}

fn sorted(set: &[&str]) -> Vec<String> {
    set.iter().map(|s| (*s).to_owned()).collect()
}

/// G-M19-1: the displayed counts, titles and multi-person list come from what the caller may read, exactly.
#[test]
fn preview_counts_only_what_the_caller_can_read() {
    run_db_fixture::<Fixture, _>("preview_counts_only_what_the_caller_can_read", |mut h| {
        let seeded = seed_closure(&mut h);
        let frozen = freeze(&h, &[seeded.root]);
        let want: BTreeSet<DeletionTarget> = expected_targets(&seeded).into_iter().collect();
        assert_eq!(
            frozen.targets.iter().copied().collect::<BTreeSet<_>>(),
            want
        );
        assert_eq!(
            frozen.targets.len(),
            7,
            "3 Evidence + 4 Memories; the unrelated pair is not in the closure"
        );
        assert_eq!(
            frozen.manifest_hash,
            manifest_hash(&expected_targets(&seeded))
        );

        let reader = preview(&h, h.reader, frozen.request_id);
        assert_eq!(reader.scope_kind, DeletionScopeKind::EvidenceClosure);
        assert_eq!(
            reader.memory_count, 2,
            "secret and mixed are unreadable to this reader"
        );
        assert_eq!(
            reader.evidence_count, 2,
            "the hidden Evidence is not counted"
        );
        assert_eq!(reader.memory_titles, sorted(&["alpha", "beta"]));
        assert_eq!(reader.multi_person_evidence, vec![seeded.child]);
        assert!(!reader.restore_supported && !reader.source_retained);
        assert_eq!(
            reader.manifest_hash, frozen.manifest_hash,
            "the hash covers the whole closure"
        );

        let owner_of_hidden = preview(&h, h.other_reader, frozen.request_id);
        assert_eq!(owner_of_hidden.memory_count, 4);
        assert_eq!(owner_of_hidden.evidence_count, 3);
        assert_eq!(
            owner_of_hidden.memory_titles,
            sorted(&["alpha", "beta", "mixed", "secret"])
        );
        let both: BTreeSet<Uuid> = [seeded.child, seeded.hidden].into_iter().collect();
        assert_eq!(
            owner_of_hidden
                .multi_person_evidence
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            both
        );
        assert_eq!(owner_of_hidden.manifest_hash, reader.manifest_hash);
    });
}

/// An unreadable target added to the closure changes the hash and nothing the reader sees.
#[test]
fn an_unreadable_target_changes_the_hash_and_no_displayed_value() {
    run_db_fixture::<Fixture, _>(
        "an_unreadable_target_changes_the_hash_and_no_displayed_value",
        |mut h| {
            let seeded = seed_closure(&mut h);
            let first = freeze(&h, &[seeded.root]);
            let again = freeze(&h, &[seeded.root]);
            assert_eq!(
                again.request_id, first.request_id,
                "the same open closure is one request"
            );
            assert_eq!(
                again.manifest_hash, first.manifest_hash,
                "the same closure, the same hash"
            );
            let before = preview(&h, h.reader, first.request_id);

            let other = h.other_reader;
            let extra = seed_evidence(&mut h, "extra", Some(other));
            derive(&mut h, extra, seeded.root);
            seed_memory(&mut h, "extra memory", Some(other), &[extra]);
            let grown = freeze(&h, &[seeded.root]);
            assert_eq!(grown.targets.len(), 9);
            assert_ne!(grown.request_id, first.request_id);
            assert_ne!(
                grown.manifest_hash, first.manifest_hash,
                "two targets more, another hash"
            );

            let after = preview(&h, h.reader, grown.request_id);
            assert_eq!(after.memory_count, before.memory_count);
            assert_eq!(after.evidence_count, before.evidence_count);
            assert_eq!(after.memory_titles, before.memory_titles);
            assert_eq!(after.multi_person_evidence, before.multi_person_evidence);
            assert_eq!(after.manifest_hash, grown.manifest_hash);
        },
    );
}

/// MEMORY scope: the Memory alone, source Evidence retained.
#[test]
fn memory_scope_freezes_the_memory_alone_with_source_retained() {
    run_db_fixture::<Fixture, _>(
        "memory_scope_freezes_the_memory_alone_with_source_retained",
        |mut h| {
            let evidence = seed_evidence(&mut h, "source", None);
            let memory = seed_memory(&mut h, "solo", None, &[evidence]);
            let frozen = h.rt.block_on(async {
                // dep: PostgreSQL(owner) — a MEMORY freeze needs no RLS view beyond the tenant
                let mut txn = h.admin_pool.begin().await.expect("begin");
                let frozen =
                    forget_repo::freeze_memory_in_txn(&mut txn, h.tenant_id, h.requester, memory)
                        .await
                        .expect("freeze");
                txn.commit().await.expect("commit");
                frozen
            });
            assert_eq!(
                frozen.targets,
                vec![DeletionTarget {
                    kind: DeletionTargetKind::Memory,
                    id: memory
                }]
            );
            let shown = preview(&h, h.reader, frozen.request_id);
            assert_eq!(shown.scope_kind, DeletionScopeKind::Memory);
            assert_eq!(shown.memory_count, 1);
            assert_eq!(
                shown.evidence_count, 0,
                "the source Evidence is not a target"
            );
            assert_eq!(shown.memory_titles, sorted(&["solo"]));
            assert!(shown.source_retained);
            assert!(!shown.restore_supported);
        },
    );
}

fn quoted_literals(constraint_def: &str) -> BTreeSet<String> {
    constraint_def
        .split('\'')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn check_literals(h: &mut Handle, table: &str, name_filter: &str) -> BTreeSet<String> {
    let def: String = h
        .admin
        .query_one(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint \
              WHERE conrelid = $1::text::regclass AND contype = 'c' AND conname LIKE $2",
            &[&table, &name_filter],
        )
        .expect("one CHECK constraint")
        .get(0);
    quoted_literals(&def)
}

/// §78.2: the two DB CHECK sets equal the Rust enums, and the table is the v2 shape.
#[test]
fn db_checks_match_the_rust_enums_and_the_table_is_v2_shaped() {
    run_db_fixture::<Fixture, _>(
        "db_checks_match_the_rust_enums_and_the_table_is_v2_shaped",
        |mut h| {
            let scopes: BTreeSet<String> = DeletionScopeKind::ALL
                .iter()
                .map(|k| k.as_db_str().to_owned())
                .collect();
            assert_eq!(
                check_literals(
                    &mut h,
                    "control.deletion_requests",
                    "deletion_requests_scope_kind_check"
                ),
                scopes
            );
            let kinds: BTreeSet<String> = DeletionTargetKind::ALL
                .iter()
                .map(|k| k.as_db_str().to_owned())
                .collect();
            assert_eq!(
                check_literals(&mut h, "control.deletion_targets", "%kind%"),
                kinds
            );

            let rows = h
                .admin
                .query(
                    "SELECT column_name::text FROM information_schema.columns \
                  WHERE table_schema = 'control' AND table_name = 'deletion_requests'",
                    &[],
                )
                .expect("columns");
            let columns: BTreeSet<String> = rows.iter().map(|r| r.get(0)).collect();
            let want: BTreeSet<String> = [
                "deletion_request_id",
                "tenant_id",
                "scope_kind",
                "scope_id",
                "state",
                "requested_at",
                "updated_at",
                "completed_at",
                "requested_by",
                "manifest_hash",
                "confirm_token_id",
                "logical_deleted_at",
            ]
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
            assert_eq!(columns, want);
        },
    );
}

/// D3: no runtime role writes either table directly; the door is the only path.
#[test]
fn runtime_roles_cannot_write_the_request_tables_directly() {
    run_db_fixture::<Fixture, _>(
        "runtime_roles_cannot_write_the_request_tables_directly",
        |h| {
            let statements = [
                "DELETE FROM control.deletion_targets",
                "DELETE FROM control.deletion_requests",
                "INSERT INTO control.deletion_targets (request_id, tenant_id, kind, id) \
             VALUES (gen_random_uuid(), gen_random_uuid(), 'MEMORY', gen_random_uuid())",
                "UPDATE control.deletion_requests SET state = 'FAILED'",
            ];
            for statement in statements {
                // dep: PostgreSQL(role_gateway) — a direct write the request-path role must be refused
                let refusal =
                    h.rt.block_on(sqlx::query(statement).execute(&h.gateway_pool))
                        .expect_err("role_gateway holds no write privilege on the request tables");
                let code = refusal
                    .as_database_error()
                    .and_then(|e| e.code().map(|c| c.into_owned()));
                assert_eq!(code.as_deref(), Some("42501"), "{statement}: {refusal}");
            }
        },
    );
}
