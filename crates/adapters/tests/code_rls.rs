//! `adapters::tests::code_rls` — G-M16-7 isolation of the code-graph tables: FORCE RLS, tenant-and-workspace scoped reads through a
//!   real role_gateway login, read-only grants, and the composite FKs that keep a file or active row inside its own tenant.
//!   The symbol and edge tables (0291) ride the same reads and catalog pins; their one-snapshot FKs are G-M16-3 (code_schema).
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres, uuid]; services=[PostgreSQL(owner)
//!   w=[control.memberships, control.repositories, control.tenants, control.users, control.workspace_memberships,
//!   control.workspaces, private.code_active_snapshots, private.code_edges, private.code_files, private.code_snapshots,
//!   private.code_symbols],
//!   PostgreSQL(role_gateway)]; env=[HUMAUX_GATEWAY_PG_DSN, HUMAUX_TEST_PG_DSN]; modules=[domain::code, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [the owner connection only seeds and removes this scenario's tenants, repositories and code rows; every
//!   observation is a real unprivileged role_gateway login under the request GUCs; a missing database is a visible SKIP, or
//!   a failure under HUMAUX_REQUIRE_DB (§79.2); the scenario removes its rows leaf-first on drop, also after a red run]
//! Spec: Baseline §62; §6.1.1; §78.2; §79.2; ADR-0114 D-B
//!
//! Scenario: tenant A holds two workspaces (WA1, WA2) and three users (A1 in WA1, A2 in WA2, A3 in none); tenant B holds WB1 and
//! user B1. One repository per workspace, plus one repository without a workspace, each with a READY snapshot, two files, one
//! symbol per file, one edge between the two symbols and an active row. Visibility is the tenant predicate AND an ACTIVE workspace membership in the repository's workspace (0284), so
//! each request context must see exactly its own repository's rows and nothing else.

use humaux_domain::code::{
    EdgeKind, EvidenceLevel, RepositoryProvider, SnapshotKind, SnapshotState, SymbolKind,
};
use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::error::SqlState;
use postgres::{Client, NoTls, Transaction};
use uuid::Uuid;

const NAME: &str = "code_rls";

const TABLES: [&str; 5] = [
    "private.code_snapshots",
    "private.code_files",
    "private.code_active_snapshots",
    "private.code_symbols",
    "private.code_edges",
];

const NON_OWNER_ROLES: [&str; 8] = [
    "role_gateway",
    "role_private_worker",
    "role_consolidation_worker",
    "role_public_worker",
    "role_retrieval_worker",
    "role_batch_issuer",
    "role_maintenance",
    "role_admin",
];

fn admin() -> Option<Client> {
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(NAME, "missing object: Postgres DSN", ExternalDep::Postgres);
        return None;
    };
    // dep: PostgreSQL(owner) — the test admin DSN seeds and removes the scenario rows
    let Ok(client) = Client::connect(&dsn, NoTls) else {
        skip_or_fail(NAME, "missing object: live Postgres", ExternalDep::Postgres);
        return None;
    };
    Some(client)
}

/// The actual unprivileged gateway login: a `SET ROLE` on the admin DSN would not prove the grants.
fn gateway() -> Option<Client> {
    let Ok(dsn) = std::env::var("HUMAUX_GATEWAY_PG_DSN") else {
        skip_or_fail(NAME, "missing object: gateway DSN", ExternalDep::Postgres);
        return None;
    };
    // dep: PostgreSQL(role_gateway) — every observation runs as the request-path role
    let Ok(mut client) = Client::connect(&dsn, NoTls) else {
        skip_or_fail(
            NAME,
            "missing object: live gateway login",
            ExternalDep::Postgres,
        );
        return None;
    };
    let real: bool = client
        .query_one(
            "SELECT current_user = 'role_gateway' AND session_user = 'role_gateway' \
             AND NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user)",
            &[],
        )
        .expect("inspect the gateway login")
        .get(0);
    assert!(
        real,
        "the gateway DSN must be an unprivileged role_gateway login"
    );
    Some(client)
}

/// One repository with its READY snapshot, two files, a symbol per file, an edge between the symbols and (in the scenario)
/// one active row.
struct Repo {
    repository: Uuid,
    workspace: Option<Uuid>,
    snapshot: Uuid,
    files: [Uuid; 2],
    symbols: [Uuid; 2],
    edge: Uuid,
}

impl Repo {
    fn new(workspace: Option<Uuid>) -> Self {
        Self {
            repository: Uuid::new_v4(),
            workspace,
            snapshot: Uuid::new_v4(),
            files: [Uuid::new_v4(), Uuid::new_v4()],
            symbols: [Uuid::new_v4(), Uuid::new_v4()],
            edge: Uuid::new_v4(),
        }
    }
}

/// What one request context reads from the five code tables, ids sorted.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    snapshots: Vec<Uuid>,
    files: Vec<Uuid>,
    active: Vec<Uuid>,
    symbols: Vec<Uuid>,
    edges: Vec<Uuid>,
}

fn expected(repos: &[&Repo]) -> Seen {
    let mut seen = Seen {
        snapshots: Vec::new(),
        files: Vec::new(),
        active: Vec::new(),
        symbols: Vec::new(),
        edges: Vec::new(),
    };
    for repo in repos {
        seen.snapshots.push(repo.snapshot);
        seen.files.extend(repo.files);
        seen.active.push(repo.repository);
        seen.symbols.extend(repo.symbols);
        seen.edges.push(repo.edge);
    }
    seen.snapshots.sort_unstable();
    seen.files.sort_unstable();
    seen.active.sort_unstable();
    seen.symbols.sort_unstable();
    seen.edges.sort_unstable();
    seen
}

fn ids(txn: &mut Transaction<'_>, sql: &str) -> Vec<Uuid> {
    txn.query(sql, &[])
        .expect("scoped code read")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// A gateway request transaction: the same two GUCs the request path sets, then five bare reads (never a join, which
/// would let one table's policy hide another's leak).
fn seen_by(gateway: &mut Client, tenant: Uuid, user: Uuid) -> Seen {
    let mut txn = gateway.transaction().expect("gateway request transaction");
    txn.query_one(
        "SELECT set_config('humaux.tenant_id', $1, true), set_config('humaux.user_id', $2, true)",
        &[&tenant.to_string(), &user.to_string()],
    )
    .expect("request context");
    let seen = Seen {
        snapshots: ids(
            &mut txn,
            "SELECT snapshot_id FROM private.code_snapshots ORDER BY snapshot_id",
        ),
        files: ids(
            &mut txn,
            "SELECT file_id FROM private.code_files ORDER BY file_id",
        ),
        active: ids(
            &mut txn,
            "SELECT repository_id FROM private.code_active_snapshots ORDER BY repository_id",
        ),
        symbols: ids(
            &mut txn,
            "SELECT symbol_id FROM private.code_symbols ORDER BY symbol_id",
        ),
        edges: ids(
            &mut txn,
            "SELECT edge_id FROM private.code_edges ORDER BY edge_id",
        ),
    };
    txn.rollback().expect("end gateway request");
    seen
}

/// Everything the scenario owns. Dropped leaf-first so a red run leaves no tenant behind.
struct Scenario {
    admin: Client,
    tenant_a: Uuid,
    tenant_b: Uuid,
    workspaces: [Uuid; 3],
    user_a1: Uuid,
    user_a2: Uuid,
    user_a3: Uuid,
    user_b1: Uuid,
    repo_a1: Repo,
    repo_a2: Repo,
    repo_a0: Repo,
    repo_b1: Repo,
}

impl Scenario {
    fn new(admin: Client) -> Self {
        let workspaces = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        Self {
            admin,
            tenant_a: Uuid::new_v4(),
            tenant_b: Uuid::new_v4(),
            workspaces,
            user_a1: Uuid::new_v4(),
            user_a2: Uuid::new_v4(),
            user_a3: Uuid::new_v4(),
            user_b1: Uuid::new_v4(),
            repo_a1: Repo::new(Some(workspaces[0])),
            repo_a2: Repo::new(Some(workspaces[1])),
            repo_a0: Repo::new(None),
            repo_b1: Repo::new(Some(workspaces[2])),
        }
    }

    fn seed(&mut self) {
        let [wa1, wa2, wb1] = self.workspaces;
        for tenant in [self.tenant_a, self.tenant_b] {
            self.admin
                .execute(
                    "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,$2,'ACTIVE')",
                    &[&tenant, &format!("code-rls-{tenant}")],
                )
                .expect("seed tenant");
        }
        for (tenant, workspace) in [
            (self.tenant_a, wa1),
            (self.tenant_a, wa2),
            (self.tenant_b, wb1),
        ] {
            self.admin
                .execute(
                    "INSERT INTO control.workspaces(workspace_id,tenant_id,name) VALUES($1,$2,'code rls fixture')",
                    &[&workspace, &tenant],
                )
                .expect("seed workspace");
        }
        for (tenant, user, workspace) in [
            (self.tenant_a, self.user_a1, Some(wa1)),
            (self.tenant_a, self.user_a2, Some(wa2)),
            (self.tenant_a, self.user_a3, None),
            (self.tenant_b, self.user_b1, Some(wb1)),
        ] {
            seed_user(&mut self.admin, tenant, user, workspace);
        }
        for (tenant, repo) in [
            (self.tenant_a, &self.repo_a1),
            (self.tenant_a, &self.repo_a2),
            (self.tenant_a, &self.repo_a0),
            (self.tenant_b, &self.repo_b1),
        ] {
            seed_repo(&mut self.admin, tenant, repo);
        }
    }
}

fn seed_user(admin: &mut Client, tenant: Uuid, user: Uuid, workspace: Option<Uuid>) {
    admin
        .execute(
            "INSERT INTO control.users(user_id,state) VALUES($1,'ACTIVE')",
            &[&user],
        )
        .expect("seed user");
    admin
        .execute(
            "INSERT INTO control.memberships(tenant_id,user_id,role,state) VALUES($1,$2,'member','ACTIVE')",
            &[&tenant, &user],
        )
        .expect("seed tenant membership");
    if let Some(workspace) = workspace {
        admin
            .execute(
                "INSERT INTO control.workspace_memberships(tenant_id,workspace_id,user_id,role,state) \
                 VALUES($1,$2,$3,'MEMBER','ACTIVE')",
                &[&tenant, &workspace, &user],
            )
            .expect("seed workspace membership");
    }
}

fn seed_repo(admin: &mut Client, tenant: Uuid, repo: &Repo) {
    admin
        .execute(
            "INSERT INTO control.repositories(repository_id,tenant_id,workspace_id,name,provider,external_id) \
             VALUES($1,$2,$3,'code rls fixture',$4,$5)",
            &[
                &repo.repository,
                &tenant,
                &repo.workspace,
                &RepositoryProvider::Client.as_db_str(),
                &repo.repository.to_string(),
            ],
        )
        .expect("seed repository");
    admin
        .execute(
            "INSERT INTO private.code_snapshots(tenant_id,snapshot_id,repository_id,kind,target_key,tree_sitter_version,\
             grammar_set,extractor_version,identity_sha256,manifest_sha256,state) \
             VALUES($1,$2,$3,$4,'fixture-target','fixture','fixture','fixture',$5,$5,$6)",
            &[
                &tenant,
                &repo.snapshot,
                &repo.repository,
                &SnapshotKind::Commit.as_db_str(),
                &vec![1_u8; 32],
                &SnapshotState::Ready.as_db_str(),
            ],
        )
        .expect("seed snapshot");
    for (n, file) in repo.files.iter().enumerate() {
        admin
            .execute(
                "INSERT INTO private.code_files(tenant_id,snapshot_id,file_id,path,sha256,size_bytes) \
                 VALUES($1,$2,$3,$4,$5,$6)",
                &[
                    &tenant,
                    &repo.snapshot,
                    file,
                    &format!("src/f{n}.rs"),
                    &vec![2_u8; 32],
                    &1_i64,
                ],
            )
            .expect("seed file");
    }
    for (n, (symbol, file)) in repo.symbols.iter().zip(&repo.files).enumerate() {
        admin
            .execute(
                "INSERT INTO private.code_symbols(tenant_id,snapshot_id,symbol_id,file_id,kind,name,qualified_name,\
                 start_line,end_line,start_byte,end_byte,content_sha256) \
                 VALUES($1,$2,$3,$4,$5,$6,$6,1,2,0,10,$7)",
                &[
                    &tenant,
                    &repo.snapshot,
                    symbol,
                    file,
                    &SymbolKind::Function.as_db_str(),
                    &format!("f{n}"),
                    &vec![4_u8; 32],
                ],
            )
            .expect("seed symbol");
    }
    admin
        .execute(
            "INSERT INTO private.code_edges(tenant_id,snapshot_id,edge_id,from_symbol_id,to_symbol_id,kind,evidence_level) \
             VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &tenant,
                &repo.snapshot,
                &repo.edge,
                &repo.symbols[0],
                &repo.symbols[1],
                &EdgeKind::Calls.as_db_str(),
                &EvidenceLevel::SyntaxCandidate.as_db_str(),
            ],
        )
        .expect("seed edge");
    admin
        .execute(
            "INSERT INTO private.code_active_snapshots(tenant_id,repository_id,snapshot_id,generation) \
             VALUES($1,$2,$3,1)",
            &[&tenant, &repo.repository, &repo.snapshot],
        )
        .expect("seed active row");
}

impl Drop for Scenario {
    fn drop(&mut self) {
        let tenants = vec![self.tenant_a, self.tenant_b];
        let users = vec![self.user_a1, self.user_a2, self.user_a3, self.user_b1];
        for statement in [
            "DELETE FROM private.code_active_snapshots WHERE tenant_id = ANY($1)",
            "DELETE FROM private.code_edges WHERE tenant_id = ANY($1)",
            "DELETE FROM private.code_symbols WHERE tenant_id = ANY($1)",
            "DELETE FROM private.code_files WHERE tenant_id = ANY($1)",
            "DELETE FROM private.code_snapshots WHERE tenant_id = ANY($1)",
            "DELETE FROM control.repositories WHERE tenant_id = ANY($1)",
            "DELETE FROM control.workspace_memberships WHERE tenant_id = ANY($1)",
            "DELETE FROM control.memberships WHERE tenant_id = ANY($1)",
            "DELETE FROM control.workspaces WHERE tenant_id = ANY($1)",
        ] {
            if let Err(error) = self.admin.execute(statement, &[&tenants]) {
                eprintln!("code_rls cleanup failed ({statement}): {error}");
            }
        }
        if let Err(error) = self.admin.execute(
            "DELETE FROM control.users WHERE user_id = ANY($1)",
            &[&users],
        ) {
            eprintln!("code_rls user cleanup failed: {error}");
        }
        if let Err(error) = self.admin.execute(
            "DELETE FROM control.tenants WHERE tenant_id = ANY($1)",
            &[&tenants],
        ) {
            eprintln!("code_rls tenant cleanup failed: {error}");
        }
    }
}

/// G-M16-7: each request context reads exactly its own repository's snapshots, files, active rows, symbols and edges. Fault: a
/// code_files or code_symbols policy with the tenant predicate only ⇒ A2 also reads A1's rows and A3 reads its whole tenant's ⇒ red.
#[test]
fn g_m16_7_reads_follow_tenant_and_workspace_membership() {
    let Some(admin) = admin() else { return };
    let Some(mut gateway) = gateway() else { return };
    let mut scenario = Scenario::new(admin);
    scenario.seed();

    // Non-vacuity: the owner sees all four snapshots the policies then hide.
    let tenants = vec![scenario.tenant_a, scenario.tenant_b];
    let seeded: i64 = scenario
        .admin
        .query_one(
            "SELECT count(*) FROM private.code_snapshots WHERE tenant_id = ANY($1)",
            &[&tenants],
        )
        .expect("owner count")
        .get(0);
    assert_eq!(seeded, 4, "the scenario seeds one snapshot per repository");
    for (table, want) in [("code_symbols", 8_i64), ("code_edges", 4)] {
        let rows: i64 = scenario
            .admin
            .query_one(
                &format!("SELECT count(*) FROM private.{table} WHERE tenant_id = ANY($1)"),
                &[&tenants],
            )
            .expect("owner count")
            .get(0);
        assert_eq!(
            rows, want,
            "the scenario seeds {table} rows the policies then hide"
        );
    }

    let cases = [
        (
            "A1 reads its workspace's repository",
            scenario.tenant_a,
            scenario.user_a1,
            expected(&[&scenario.repo_a1]),
        ),
        (
            "A2, another workspace of the same tenant, reads only its own",
            scenario.tenant_a,
            scenario.user_a2,
            expected(&[&scenario.repo_a2]),
        ),
        (
            "A3 holds no workspace membership and reads nothing",
            scenario.tenant_a,
            scenario.user_a3,
            expected(&[]),
        ),
        (
            "B1 reads tenant B's repository",
            scenario.tenant_b,
            scenario.user_b1,
            expected(&[&scenario.repo_b1]),
        ),
        (
            "B1 under tenant A's context reads nothing",
            scenario.tenant_a,
            scenario.user_b1,
            expected(&[]),
        ),
        (
            "A1 under tenant B's context reads nothing",
            scenario.tenant_b,
            scenario.user_a1,
            expected(&[]),
        ),
    ];
    for (who, tenant, user, want) in cases {
        assert_eq!(seen_by(&mut gateway, tenant, user), want, "{who}");
    }
}

/// G-M16-7: FORCE RLS, the owner, exactly one tenant-keyed ALL policy, and a gateway that can read and nothing else, on all
/// five code-graph tables.
#[test]
fn g_m16_7_catalog_pins_force_rls_owner_policy_and_read_only_grants() {
    let Some(mut admin) = admin() else { return };
    let Some(mut gateway) = gateway() else { return };
    for table in TABLES {
        let Some(row) = admin
            .query_opt(
                "SELECT c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner), \
                 (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid), \
                 (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid AND p.polcmd = '*' \
                    AND strpos(pg_get_expr(p.polqual, p.polrelid), 'humaux.tenant_id') > 0 \
                    AND strpos(pg_get_expr(p.polwithcheck, p.polrelid), 'humaux.tenant_id') > 0) \
                 FROM pg_class c WHERE c.oid = to_regclass($1)",
                &[&table],
            )
            .expect("catalog probe")
        else {
            skip_or_fail(
                NAME,
                &format!(
                    "missing object: {table} — run `cargo xtask migrate` (migrations/0284_code_snapshots.sql, 0291_code_symbols_edges.sql)"
                ),
                ExternalDep::Postgres,
            );
            return;
        };
        assert!(row.get::<_, bool>(0), "{table}: RLS enabled");
        assert!(row.get::<_, bool>(1), "{table}: FORCE RLS");
        assert_eq!(row.get::<_, String>(2), "role_migration_owner", "{table}");
        assert_eq!(row.get::<_, i64>(3), 1, "{table}: exactly one policy");
        assert_eq!(
            row.get::<_, i64>(4),
            1,
            "{table}: that policy is an ALL policy keyed on the tenant GUC"
        );
    }
    for role in NON_OWNER_ROLES {
        for table in TABLES {
            let row = admin
                .query_one(
                    "SELECT has_any_column_privilege($1::name, $2::text, 'SELECT'), \
                     has_table_privilege($1::name, $2::text, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') \
                     OR has_any_column_privilege($1::name, $2::text, 'INSERT,UPDATE,REFERENCES')",
                    &[&role, &table],
                )
                .expect("privilege probe");
            assert_eq!(
                (row.get::<_, bool>(0), row.get::<_, bool>(1)),
                (role == "role_gateway", false),
                "{role} on {table}: (read, write)"
            );
        }
    }
    // The real login proves it: no write verb reaches even an empty statement.
    for table in TABLES {
        for sql in [
            format!("INSERT INTO {table} SELECT * FROM {table} WHERE false"),
            format!("DELETE FROM {table}"),
        ] {
            let error = gateway
                .execute(&sql, &[])
                .expect_err("the gateway holds no write privilege");
            assert_eq!(
                error.code(),
                Some(&SqlState::INSUFFICIENT_PRIVILEGE),
                "{sql}: {error}"
            );
        }
    }
}

/// The constraint a rejected statement named; the rejection must be a foreign-key violation (SQLSTATE 23503).
fn rejected_fk(result: Result<u64, postgres::Error>, what: &str) -> String {
    let error = result.expect_err(what);
    let db = error.as_db_error().expect("a database error");
    assert_eq!(db.code(), &SqlState::FOREIGN_KEY_VIOLATION, "{what}: {db}");
    db.constraint()
        .expect("a foreign-key violation names its constraint")
        .to_owned()
}

/// G-M16-7: a file row cannot name another tenant's snapshot, and an active row cannot name another repository's
/// snapshot. Fault: `code_files` keyed on `snapshot_id` alone ⇒ the tenant-B row is accepted ⇒ red.
#[test]
fn g_m16_7_composite_fks_keep_rows_inside_their_tenant_and_repository() {
    let Some(admin) = admin() else { return };
    let mut scenario = Scenario::new(admin);
    scenario.seed();

    let insert_file = "INSERT INTO private.code_files(tenant_id,snapshot_id,file_id,path,sha256,size_bytes) \
                       VALUES($1,$2,$3,'src/extra.rs',$4,1)";
    // Positive control: the same statement with the snapshot's own tenant is accepted.
    scenario
        .admin
        .execute(
            insert_file,
            &[
                &scenario.tenant_a,
                &scenario.repo_a1.snapshot,
                &Uuid::new_v4(),
                &vec![3_u8; 32],
            ],
        )
        .expect("a file of the snapshot's own tenant is accepted");
    let cross_tenant = scenario.admin.execute(
        insert_file,
        &[
            &scenario.tenant_b,
            &scenario.repo_a1.snapshot,
            &Uuid::new_v4(),
            &vec![3_u8; 32],
        ],
    );
    assert_eq!(
        rejected_fk(cross_tenant, "tenant B's file naming tenant A's snapshot"),
        "code_files_snapshot_fkey"
    );

    let cross_repository = scenario.admin.execute(
        "UPDATE private.code_active_snapshots SET snapshot_id = $3 WHERE tenant_id = $1 AND repository_id = $2",
        &[
            &scenario.tenant_a,
            &scenario.repo_a2.repository,
            &scenario.repo_a1.snapshot,
        ],
    );
    assert_eq!(
        rejected_fk(
            cross_repository,
            "repository A2's active row naming repository A1's snapshot"
        ),
        "code_active_snapshots_snapshot_fkey"
    );
}
