//! `adapters::tests::forget_preview` — G-M19-1 (preview honesty) and the M19-2 request-v2 contract: the freeze door's own
//!   closure and hash, its refusals, concurrent freezes, the visibility-filtered impact preview, 0272 shape and grants, on a
//!   disposable database.
//! Depends-on: crates=[humaux-adapters, humaux-application, humaux-domain, humaux-testkit, postgres, sqlx, tokio]; services=[PostgreSQL(any) w=[control.deletion_requests, control.deletion_targets, control.private_reasoning_domains, control.tenants, control.users, private.evidence_edges, private.evidence_objects, private.evidence_subjects, private.memory_evidence, private.memory_records, private.subjects] x=[control.deletion_request_freeze], PostgreSQL(owner), PostgreSQL(role_gateway)]; env=[HUMAUX_TEST_PG_DSN]; modules=[adapters::forget_repo, application::forget, domain::identity, domain::ids, humaux-testkit, testkit::disposable, testkit::fixture_purge]
//! Called-by: [cargo-test]
//! Invariants: [every fixture calls require_disposable before it writes a row; every freeze runs through role_gateway, the
//!   door's one granted role, under the requester's own session; the preview runs through role_gateway under each user's
//!   own RLS; every count, title set, target set and hash is asserted exactly]
//! Spec: ADR-0092 D-A, D-B; module design M19 D1, D2, D3; G-M19-1; §78.2; §79.2

use std::collections::BTreeSet;
use std::sync::Barrier;
use std::time::Duration;

use humaux_adapters::forget_repo::{self, ForgetRepoError, FrozenDeletion};
use humaux_application::forget::{
    DeletionScopeKind, DeletionState, DeletionTarget, DeletionTargetKind, ImpactPreview,
    evidence_closure_targets, manifest_hash,
};
use humaux_domain::error::ErrorCode;
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
        let users = vec![self.requester, self.reader, self.other_reader];
        if let Err(e) = self.admin.execute(
            "DELETE FROM control.users WHERE user_id = ANY($1)",
            &[&users],
        ) {
            eprintln!("forget_preview cleanup (users): {e}");
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
        // dep: PostgreSQL(role_gateway) — freeze and preview run under the request-path role
        let gateway_pool = rt
            .block_on(sqlx::Pool::<sqlx::Postgres>::connect(&dsn_as_role(
                &dsn,
                "role_gateway",
            )))
            .map_err(|e| setup(e.to_string()))?;
        Ok(Handle {
            rt,
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

/// Where an Evidence row or a Memory is visible.
#[derive(Clone, Copy)]
enum Vis {
    Tenant,
    User(Uuid),
    Workspace(Uuid),
}

impl Vis {
    fn columns(self) -> (&'static str, Option<Uuid>, Option<Uuid>) {
        match self {
            Vis::Tenant => ("TENANT_SHARED", None, None),
            Vis::User(user) => ("USER_PRIVATE", Some(user), None),
            Vis::Workspace(ws) => ("WORKSPACE_SHARED", None, Some(ws)),
        }
    }
}

fn seed_evidence_class(h: &mut Handle, label: &str, vis: Vis, data_class: &str) -> Uuid {
    let (class, user, workspace) = vis.columns();
    h.admin
        .query_one(
            "INSERT INTO private.evidence_objects (tenant_id, evidence_kind, payload_sha256, data_class, \
               origin_class, visibility_class, visibility_user_id, visibility_workspace_id, reasoning_domain_id) \
             VALUES ($1, 'EVENT', sha256(convert_to($2::text, 'UTF8')), $3, 'DirectUserInput', \
               $4::text, $5::uuid, $6::uuid, $7) RETURNING evidence_id",
            &[
                &h.tenant_id,
                &label,
                &data_class,
                &class,
                &user,
                &workspace,
                &h.reasoning_domain,
            ],
        )
        .expect("seed evidence")
        .get(0)
}

fn seed_evidence(h: &mut Handle, label: &str, vis: Vis) -> Uuid {
    seed_evidence_class(h, label, vis, "INTERNAL")
}

/// A Memory titled `title` whose inputs are `inputs` (first PRIMARY, the rest SUPPORTING), in one statement so the deferred
/// orphan check (§8.6) passes.
fn seed_memory(h: &mut Handle, title: &str, vis: Vis, inputs: &[Uuid]) -> Uuid {
    let (class, user, workspace) = vis.columns();
    h.admin
        .query_one(
            "WITH m AS ( \
               INSERT INTO private.memory_records (tenant_id, memory_type, content, visibility_class, \
                 visibility_user_id, visibility_workspace_id, authority_class, confidence, status, asserted_at) \
               VALUES ($1, 'NOTE', jsonb_build_object('title', $2::text), $3::text, $4::uuid, $5::uuid, \
                 'PrivateKnowledge', 0.9, 'active', now()) RETURNING memory_id), \
             l AS ( \
               INSERT INTO private.memory_evidence (memory_id, evidence_id, role, ordinal) \
               SELECT m.memory_id, t.e, CASE WHEN t.n = 1 THEN 'PRIMARY' ELSE 'SUPPORTING' END, (t.n - 1)::int \
                 FROM m, unnest($6::uuid[]) WITH ORDINALITY AS t(e, n)) \
             SELECT memory_id FROM m",
            &[&h.tenant_id, &title, &class, &user, &workspace, &inputs],
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

/// A workspace of the fixture tenant that `user` is an ACTIVE member of.
fn seed_workspace_with_member(h: &mut Handle, user: Uuid) -> Uuid {
    h.admin
        .execute(
            "INSERT INTO control.memberships (tenant_id, user_id, role, state) \
             VALUES ($1, $2, 'member', 'ACTIVE') ON CONFLICT DO NOTHING",
            &[&h.tenant_id, &user],
        )
        .expect("seed membership");
    let workspace: Uuid = h
        .admin
        .query_one(
            "INSERT INTO control.workspaces (tenant_id, name) VALUES ($1, 'forget_preview ws') RETURNING workspace_id",
            &[&h.tenant_id],
        )
        .expect("seed workspace")
        .get(0);
    h.admin
        .execute(
            "INSERT INTO control.workspace_memberships (tenant_id, workspace_id, user_id, role, state) \
             VALUES ($1, $2, $3, 'MEMBER', 'ACTIVE')",
            &[&h.tenant_id, &workspace, &user],
        )
        .expect("seed workspace membership");
    workspace
}

/// The seeded closure of `root`. Targets: `root` and the four Memories that read it (one of them only as a SUPPORTING
/// input, two of them unreadable to `reader`). Not targets: `child` and `hidden` (derived from `root`, ADR-0079 D-J) and the
/// Memories that read only those.
struct Seeded {
    root: Uuid,
    child: Uuid,
    hidden: Uuid,
    /// alpha, secret, mixed, supporting-only.
    memories: [Uuid; 4],
    /// Reads only `child`: derived evidence is no root, so it is not a target.
    beta: Uuid,
}

fn seed_closure(h: &mut Handle) -> Seeded {
    let other = h.other_reader;
    let root = seed_evidence(h, "root", Vis::Tenant);
    let child = seed_evidence(h, "child", Vis::Tenant);
    let hidden = seed_evidence(h, "hidden", Vis::User(other));
    let side = seed_evidence(h, "side", Vis::Tenant);
    let unrelated = seed_evidence(h, "unrelated", Vis::Tenant);
    derive(h, child, root);
    derive(h, hidden, root);
    link_two_subjects(h, root);
    let alpha = seed_memory(h, "alpha", Vis::Tenant, &[root]);
    // Private to `other_reader`: a Memory the freezer cannot read still depends on the root and must be frozen.
    let secret = seed_memory(h, "secret", Vis::User(other), &[root]);
    // Tenant-shared, but one backing Evidence is private: unreadable to everyone but `other_reader` (§8.6).
    let mixed = seed_memory(h, "mixed", Vis::Tenant, &[root, hidden]);
    // The only link to the root is a SUPPORTING (non-primary) input; the PRIMARY input is `side`.
    let supporting = seed_memory(h, "supporting", Vis::Tenant, &[side, root]);
    let beta = seed_memory(h, "beta", Vis::Tenant, &[child]);
    seed_memory(h, "unrelated", Vis::Tenant, &[unrelated]);
    Seeded {
        root,
        child,
        hidden,
        memories: [alpha, secret, mixed, supporting],
        beta,
    }
}

fn expected_targets(s: &Seeded) -> Vec<DeletionTarget> {
    let evidence = DeletionTarget {
        kind: DeletionTargetKind::Evidence,
        id: s.root,
    };
    let memories = s.memories.map(|id| DeletionTarget {
        kind: DeletionTargetKind::Memory,
        id,
    });
    std::iter::once(evidence).chain(memories).collect()
}

fn auth(h: &Handle, user: Uuid, workspaces: &[Uuid]) -> AuthorizationScope {
    auth_in(h.tenant_id, user, workspaces)
}

fn auth_in(tenant: Uuid, user: Uuid, workspaces: &[Uuid]) -> AuthorizationScope {
    let scope: Vec<WorkspaceId> = if workspaces.is_empty() {
        vec![WorkspaceId::new()]
    } else {
        workspaces.iter().map(|w| WorkspaceId(*w)).collect()
    };
    AuthorizationScope::new(
        TenantId(tenant),
        PrincipalId::new(),
        Some(UserId(user)),
        BoundedSet::new(scope).expect("bounded workspaces"),
    )
}

/// Freezes `roots` as `user` through `role_gateway`, the way the request path does.
fn freeze_as(h: &Handle, user: Uuid, roots: &[Uuid]) -> Result<FrozenDeletion, ForgetRepoError> {
    freeze_with(&h.rt, &h.gateway_pool, &auth(h, user, &[]), roots)
}

fn freeze_with(
    rt: &tokio::runtime::Runtime,
    pool: &sqlx::Pool<sqlx::Postgres>,
    authorization: &AuthorizationScope,
    roots: &[Uuid],
) -> Result<FrozenDeletion, ForgetRepoError> {
    rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — the door's one granted caller
        let mut txn = pool.begin().await.map_err(ForgetRepoError::Db)?;
        let frozen =
            forget_repo::freeze_evidence_closure_in_txn(&mut txn, authorization, roots).await?;
        txn.commit().await.map_err(ForgetRepoError::Db)?;
        Ok(frozen)
    })
}

fn preview_with(h: &Handle, authorization: &AuthorizationScope, request_id: Uuid) -> ImpactPreview {
    h.rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — the preview runs under the request-path role's RLS
        let mut txn = h.gateway_pool.begin().await.expect("begin");
        let preview = forget_repo::preview_in_txn(&mut txn, authorization, request_id)
            .await
            .expect("preview");
        txn.rollback().await.expect("rollback");
        preview
    })
}

fn preview(h: &Handle, user: Uuid, request_id: Uuid) -> ImpactPreview {
    preview_with(h, &auth(h, user, &[]), request_id)
}

fn sorted(set: &[&str]) -> Vec<String> {
    set.iter().map(|s| (*s).to_owned()).collect()
}

fn refusal(result: Result<FrozenDeletion, ForgetRepoError>) -> (ErrorCode, &'static str) {
    match result.expect_err("the door must refuse") {
        ForgetRepoError::Refused { code, reason } => (code, reason),
        other => panic!("expected a door refusal, got {other}"),
    }
}

fn request_count(h: &mut Handle) -> i64 {
    h.admin
        .query_one(
            "SELECT count(*) FROM control.deletion_requests WHERE tenant_id = $1",
            &[&h.tenant_id],
        )
        .expect("count requests")
        .get(0)
}

/// ADR-0092 D-A: the closure is exactly the roots plus every Memory with ANY input among them, whole, frozen by the door
/// through `role_gateway` — including Memories the freezing user cannot read — and its hash is the door's own.
#[test]
fn closure_is_the_roots_plus_every_memory_with_any_input_among_them() {
    run_db_fixture::<Fixture, _>(
        "closure_is_the_roots_plus_every_memory_with_any_input_among_them",
        |mut h| {
            let seeded = seed_closure(&mut h);
            let requester = h.requester;
            let frozen = freeze_as(&h, requester, &[seeded.root]).expect("freeze");
            let want: BTreeSet<DeletionTarget> = expected_targets(&seeded).into_iter().collect();
            assert_eq!(
                frozen.targets.iter().copied().collect::<BTreeSet<_>>(),
                want,
                "root + alpha + secret + mixed + supporting; not child, hidden or beta"
            );
            assert_eq!(frozen.targets.len(), 5);
            for absent in [seeded.child, seeded.hidden, seeded.beta] {
                assert!(
                    frozen.targets.iter().all(|t| t.id != absent),
                    "{absent} is derived from the root, not a root and not a reader of it"
                );
            }
            assert_eq!(
                frozen.manifest_hash,
                manifest_hash(&expected_targets(&seeded))
            );

            let links: Vec<(Uuid, Uuid)> = h
                .admin
                .query(
                    "SELECT me.memory_id, me.evidence_id FROM private.memory_evidence me \
                       JOIN private.memory_records m ON m.memory_id = me.memory_id WHERE m.tenant_id = $1",
                    &[&h.tenant_id],
                )
                .expect("links")
                .iter()
                .map(|r| (r.get(0), r.get(1)))
                .collect();
            assert_eq!(
                evidence_closure_targets(&[seeded.root], &links)
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                want,
                "the SQL door and the pure rule agree"
            );

            let stored_by: Uuid = h
                .admin
                .query_one(
                    "SELECT requested_by FROM control.deletion_requests WHERE deletion_request_id = $1",
                    &[&frozen.request_id],
                )
                .expect("request row")
                .get(0);
            assert_eq!(stored_by, requester, "requested_by comes from the session");
        },
    );
}

/// The door refuses what the caller cannot read or does not own, and no caller-supplied target or hash exists to forge.
#[test]
fn a_forged_root_or_hash_cannot_be_frozen() {
    run_db_fixture::<Fixture, _>("a_forged_root_or_hash_cannot_be_frozen", |mut h| {
        let seeded = seed_closure(&mut h);
        let (requester, other) = (h.requester, h.other_reader);
        let private_root = seed_evidence(&mut h, "private root", Vis::User(other));
        let before = request_count(&mut h);

        for (label, roots) in [
            ("a made-up id", vec![Uuid::new_v4()]),
            ("another user's private Evidence", vec![private_root]),
            (
                "a real root next to a forged one",
                vec![seeded.root, Uuid::new_v4()],
            ),
            (
                "a Memory id given as an Evidence root",
                vec![seeded.memories[0]],
            ),
        ] {
            assert_eq!(
                refusal(freeze_as(&h, requester, &roots)),
                (ErrorCode::NotFound, "root_unreadable"),
                "{label}"
            );
        }
        // Another tenant's session cannot reach this tenant's root either.
        let foreign_tenant = Uuid::new_v4();
        let foreign = freeze_with(
            &h.rt,
            &h.gateway_pool,
            &auth_in(foreign_tenant, requester, &[]),
            &[seeded.root],
        );
        let (code, _) = refusal(foreign);
        assert!(
            code == ErrorCode::NotFound || code == ErrorCode::Forbidden,
            "a foreign tenant is refused, got {code:?}"
        );
        assert_eq!(request_count(&mut h), before, "a refusal stores nothing");

        // The old seven-argument door, with caller-chosen kinds, ids and hash, no longer exists.
        let forged = h.rt.block_on(
            sqlx::query(
                "SELECT control.deletion_request_freeze($1, 'EVIDENCE_CLOSURE', $2, $3, sha256('forged'::bytea), \
                   ARRAY['MEMORY']::text[], ARRAY[$4]::uuid[])",
            )
            .bind(h.tenant_id)
            .bind(seeded.root)
            .bind(requester)
            .bind(Uuid::new_v4())
            .execute(&h.gateway_pool),
        );
        let code = forged
            .expect_err("no caller-supplied targets or hash")
            .as_database_error()
            .and_then(|e| e.code().map(|c| c.into_owned()));
        assert_eq!(code.as_deref(), Some("42883"), "undefined function");

        let frozen = freeze_as(&h, requester, &[seeded.root]).expect("the honest freeze");
        assert_eq!(frozen.targets.len(), 5);
        assert_eq!(
            frozen.manifest_hash,
            manifest_hash(&expected_targets(&seeded)),
            "the stored hash covers the door's own closure"
        );
        let stored: Vec<u8> = h
            .admin
            .query_one(
                "SELECT manifest_hash FROM control.deletion_requests WHERE deletion_request_id = $1",
                &[&frozen.request_id],
            )
            .expect("row")
            .get(0);
        assert_eq!(stored.as_slice(), frozen.manifest_hash.as_slice());
    });
}

/// Two real connections freeze the same scope at once: exactly one request and one target set.
#[test]
fn concurrent_freezes_of_one_scope_make_one_request() {
    run_db_fixture::<Fixture, _>(
        "concurrent_freezes_of_one_scope_make_one_request",
        |mut h| {
            let seeded = seed_closure(&mut h);
            let requester = h.requester;
            let barrier = Barrier::new(2);
            let results: Vec<Uuid> = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..2)
                    .map(|_| {
                        let (rt, pool, barrier) = (&h.rt, &h.gateway_pool, &barrier);
                        let authorization = auth_in(h.tenant_id, requester, &[]);
                        let root = seeded.root;
                        scope.spawn(move || {
                            rt.block_on(async {
                                // dep: PostgreSQL(role_gateway) — one of two racing freezers
                                let mut txn = pool.begin().await.expect("begin");
                                barrier.wait();
                                let frozen = forget_repo::freeze_evidence_closure_in_txn(
                                    &mut txn,
                                    &authorization,
                                    &[root],
                                )
                                .await
                                .expect("freeze");
                                // Hold the transaction open so the second freezer meets an uncommitted request.
                                std::thread::sleep(Duration::from_millis(300));
                                txn.commit().await.expect("commit");
                                frozen.request_id
                            })
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|w| w.join().expect("freezer thread"))
                    .collect()
            });
            assert_eq!(results.len(), 2);
            assert_eq!(results[0], results[1], "both freezers got the same request");
            assert_eq!(request_count(&mut h), 1, "exactly one request");
            let targets: i64 = h
                .admin
                .query_one(
                    "SELECT count(*) FROM control.deletion_targets WHERE tenant_id = $1",
                    &[&h.tenant_id],
                )
                .expect("count targets")
                .get(0);
            assert_eq!(targets, 5, "exactly one target set");
        },
    );
}

/// G-M19-1: the displayed counts, titles and multi-person list come from what the caller may read, exactly.
#[test]
fn preview_counts_only_what_the_caller_can_read() {
    run_db_fixture::<Fixture, _>("preview_counts_only_what_the_caller_can_read", |mut h| {
        let seeded = seed_closure(&mut h);
        let requester = h.requester;
        let frozen = freeze_as(&h, requester, &[seeded.root]).expect("freeze");

        let reader = preview(&h, h.reader, frozen.request_id);
        assert_eq!(reader.scope_kind, DeletionScopeKind::EvidenceClosure);
        assert_eq!(
            reader.memory_count, 2,
            "secret and mixed are unreadable to this reader"
        );
        assert_eq!(reader.evidence_count, 1, "the root");
        assert_eq!(reader.memory_titles, sorted(&["alpha", "supporting"]));
        assert_eq!(reader.multi_person_evidence, vec![seeded.root]);
        assert!(!reader.restore_supported && !reader.source_retained);
        assert_eq!(
            reader.manifest_hash, frozen.manifest_hash,
            "the hash covers the whole closure"
        );

        let owner_of_hidden = preview(&h, h.other_reader, frozen.request_id);
        assert_eq!(owner_of_hidden.memory_count, 4);
        assert_eq!(owner_of_hidden.evidence_count, 1);
        assert_eq!(
            owner_of_hidden.memory_titles,
            sorted(&["alpha", "mixed", "secret", "supporting"])
        );
        assert_eq!(owner_of_hidden.manifest_hash, reader.manifest_hash);
    });
}

/// A secret-backed Memory is a target but its title and count are never shown.
#[test]
fn secret_backed_memories_are_never_shown_in_the_preview() {
    run_db_fixture::<Fixture, _>(
        "secret_backed_memories_are_never_shown_in_the_preview",
        |mut h| {
            let requester = h.requester;
            let root = seed_evidence(&mut h, "root", Vis::Tenant);
            let vault = seed_evidence_class(&mut h, "vault", Vis::Tenant, "SECRET_MATERIAL");
            seed_memory(&mut h, "plain", Vis::Tenant, &[root]);
            seed_memory(&mut h, "classified", Vis::Tenant, &[root, vault]);
            let frozen = freeze_as(&h, requester, &[root]).expect("freeze");
            assert_eq!(frozen.targets.len(), 3, "root + both Memories are frozen");

            let shown = preview(&h, h.reader, frozen.request_id);
            assert_eq!(
                shown.memory_count, 1,
                "the secret-backed Memory is not counted"
            );
            assert_eq!(shown.memory_titles, sorted(&["plain"]));
            assert_eq!(shown.evidence_count, 1);
        },
    );
}

/// The preview judges Evidence against the caller's own workspace scope, not RLS alone: a member of two workspaces who is
/// scoped to W1 never counts W2 Evidence.
#[test]
fn other_workspace_evidence_never_counts_for_a_scoped_caller() {
    run_db_fixture::<Fixture, _>(
        "other_workspace_evidence_never_counts_for_a_scoped_caller",
        |mut h| {
            let reader = h.reader;
            let w1 = seed_workspace_with_member(&mut h, reader);
            let w2 = seed_workspace_with_member(&mut h, reader);
            let in_w1 = seed_evidence(&mut h, "in w1", Vis::Workspace(w1));
            let in_w2 = seed_evidence(&mut h, "in w2", Vis::Workspace(w2));
            let shared = seed_evidence(&mut h, "tenant shared", Vis::Tenant);
            seed_memory(&mut h, "m1", Vis::Workspace(w1), &[in_w1]);
            seed_memory(&mut h, "m2", Vis::Workspace(w2), &[in_w2]);
            let frozen =
                freeze_as(&h, reader, &[in_w1, in_w2, shared]).expect("freeze as a member of both");
            assert_eq!(frozen.targets.len(), 5, "3 Evidence + 2 Memories");

            let scoped = preview_with(&h, &auth(&h, reader, &[w1]), frozen.request_id);
            assert_eq!(
                scoped.evidence_count, 2,
                "W1 Evidence and the tenant-shared one"
            );
            assert_eq!(scoped.memory_count, 1);
            assert_eq!(scoped.memory_titles, sorted(&["m1"]));

            let both = preview_with(&h, &auth(&h, reader, &[w1, w2]), frozen.request_id);
            assert_eq!(both.evidence_count, 3);
            assert_eq!(both.memory_count, 2);
            assert_eq!(both.memory_titles, sorted(&["m1", "m2"]));
        },
    );
}

/// An unreadable target added to the closure changes the hash and nothing the reader sees.
#[test]
fn an_unreadable_target_changes_the_hash_and_no_displayed_value() {
    run_db_fixture::<Fixture, _>(
        "an_unreadable_target_changes_the_hash_and_no_displayed_value",
        |mut h| {
            let seeded = seed_closure(&mut h);
            let requester = h.requester;
            let first = freeze_as(&h, requester, &[seeded.root]).expect("freeze");
            let again = freeze_as(&h, requester, &[seeded.root]).expect("freeze again");
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
            seed_memory(&mut h, "extra memory", Vis::User(other), &[seeded.root]);
            let grown = freeze_as(&h, requester, &[seeded.root]).expect("freeze grown");
            assert_eq!(grown.targets.len(), 6);
            assert_ne!(grown.request_id, first.request_id);
            assert_ne!(
                grown.manifest_hash, first.manifest_hash,
                "one target more, another hash"
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

/// MEMORY scope: the Memory alone, source Evidence retained; an unreadable Memory root is refused.
#[test]
fn memory_scope_freezes_the_memory_alone_with_source_retained() {
    run_db_fixture::<Fixture, _>(
        "memory_scope_freezes_the_memory_alone_with_source_retained",
        |mut h| {
            let requester = h.requester;
            let other = h.other_reader;
            let evidence = seed_evidence(&mut h, "source", Vis::Tenant);
            let memory = seed_memory(&mut h, "solo", Vis::Tenant, &[evidence]);
            let private = seed_memory(&mut h, "private", Vis::User(other), &[evidence]);
            let authorization = auth(&h, requester, &[]);
            let frozen = h.rt.block_on(async {
                // dep: PostgreSQL(role_gateway) — the door's one granted caller
                let mut txn = h.gateway_pool.begin().await.expect("begin");
                let frozen = forget_repo::freeze_memory_in_txn(&mut txn, &authorization, memory)
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

            let refused = h.rt.block_on(async {
                let mut txn = h.gateway_pool.begin().await.expect("begin");
                forget_repo::freeze_memory_in_txn(&mut txn, &authorization, private).await
            });
            assert_eq!(
                refusal(refused),
                (ErrorCode::NotFound, "root_unreadable"),
                "another user's private Memory"
            );
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

/// §78.2: the DB CHECK sets equal the Rust enums (exact set both ways), and the table is the v2 shape.
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
            let states: BTreeSet<String> = DeletionState::ALL
                .iter()
                .map(|s| s.as_db_str().to_owned())
                .collect();
            assert_eq!(states.len(), 7);
            assert_eq!(
                check_literals(
                    &mut h,
                    "control.deletion_requests",
                    "deletion_requests_state_check"
                ),
                states
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

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()))
}

/// The freeze door, called as its one granted role with a raw session: a foreign tenant argument, a session without a
/// user, a scope without a closure fn, an empty or oversized root list are each refused with their own SQLSTATE.
#[test]
fn the_freeze_door_runs_as_role_gateway_and_checks_its_arguments() {
    run_db_fixture::<Fixture, _>(
        "the_freeze_door_runs_as_role_gateway_and_checks_its_arguments",
        |mut h| {
            let evidence = seed_evidence(&mut h, "door root", Vis::Tenant);
            let call = |tenant: Uuid,
                        user: Option<Uuid>,
                        scope: &str,
                        roots: Vec<Uuid>|
             -> Result<Uuid, sqlx::Error> {
                h.rt.block_on(async {
                    // dep: PostgreSQL(role_gateway) — the door's one granted caller
                    let mut txn = h.gateway_pool.begin().await?;
                    sqlx::query("SELECT set_config('humaux.tenant_id', $1, true)")
                        .bind(h.tenant_id.to_string())
                        .execute(&mut *txn)
                        .await?;
                    sqlx::query("SELECT set_config('humaux.user_id', $1, true)")
                        .bind(user.map(|u| u.to_string()).unwrap_or_default())
                        .execute(&mut *txn)
                        .await?;
                    let request_id = sqlx::query_scalar::<_, Uuid>(
                        "SELECT control.deletion_request_freeze($1, $2, $3::uuid[])",
                    )
                    .bind(tenant)
                    .bind(scope)
                    .bind(roots)
                    .fetch_one(&mut *txn)
                    .await?;
                    txn.rollback().await?;
                    Ok(request_id)
                })
            };
            let requester = Some(h.requester);
            call(h.tenant_id, requester, "EVIDENCE_CLOSURE", vec![evidence])
                .expect("the session tenant and user are accepted");
            let foreign = call(
                Uuid::new_v4(),
                requester,
                "EVIDENCE_CLOSURE",
                vec![evidence],
            )
            .expect_err("foreign tenant");
            assert_eq!(sqlstate(&foreign).as_deref(), Some("42501"), "{foreign}");
            let anonymous = call(h.tenant_id, None, "EVIDENCE_CLOSURE", vec![evidence])
                .expect_err("no session user");
            assert_eq!(
                sqlstate(&anonymous).as_deref(),
                Some("42501"),
                "{anonymous}"
            );
            let nil = call(
                h.tenant_id,
                Some(Uuid::nil()),
                "EVIDENCE_CLOSURE",
                vec![evidence],
            )
            .expect_err("headless nil user");
            assert_eq!(sqlstate(&nil).as_deref(), Some("42501"), "{nil}");
            let subject = call(h.tenant_id, requester, "SUBJECT", vec![evidence])
                .expect_err("no closure fn for SUBJECT yet");
            assert_eq!(sqlstate(&subject).as_deref(), Some("22023"), "{subject}");
            let empty =
                call(h.tenant_id, requester, "EVIDENCE_CLOSURE", vec![]).expect_err("empty roots");
            assert_eq!(sqlstate(&empty).as_deref(), Some("22023"), "{empty}");
            let two_memories = call(
                h.tenant_id,
                requester,
                "MEMORY",
                vec![evidence, Uuid::new_v4()],
            )
            .expect_err("MEMORY takes exactly one root");
            assert_eq!(
                sqlstate(&two_memories).as_deref(),
                Some("22023"),
                "{two_memories}"
            );
        },
    );
}
