//! `adapters::tests::code_schema` — G-M16-3 one-snapshot edges: the composite FKs and CHECKs of private.code_symbols and
//!   private.code_edges, judged by the SQLSTATE and constraint the owner connection gets back for each bad row.
//! Depends-on: crates=[humaux-domain, humaux-testkit, postgres, uuid]; services=[PostgreSQL(owner)
//!   w=[control.repositories, control.tenants, private.code_edges, private.code_files, private.code_snapshots,
//!   private.code_symbols]]; env=[HUMAUX_TEST_PG_DSN]; modules=[domain::code, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [an edge and a symbol never leave their own snapshot (a symbol's file, both ends of an edge); an edge names
//!   exactly one of a target symbol and an unresolved name; one fact is one row; the closed sets reject a label outside
//!   them; every rejection asserts SQLSTATE and constraint name, and each case has an accepted twin so a red is never a
//!   broken fixture; the scenario removes its rows leaf-first on drop, also after a red run; a missing database is a
//!   visible SKIP, or a failure under HUMAUX_REQUIRE_DB (§79.2)]
//! Spec: Baseline §27; §78.2; §79.2; ADR-0114 D-B, D-E
//!
//! Scenario: one tenant and repository hold two READY snapshots A and B, a file in each, and a symbol sA (in A) and sB (in B).
//! The owner connection bypasses RLS on purpose: this file judges constraints, G-M16-7 (code_rls) judges visibility.

use humaux_domain::code::{
    EdgeKind, EvidenceLevel, RepositoryProvider, SnapshotKind, SnapshotState, SymbolKind,
};
use humaux_testkit::{ExternalDep, skip_or_fail};
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use uuid::Uuid;

const NAME: &str = "code_schema";

/// One snapshot of the scenario: its file and the symbol defined in that file.
#[derive(Clone, Copy)]
struct Snap {
    snapshot: Uuid,
    file: Uuid,
    symbol: Uuid,
}

impl Snap {
    fn new() -> Self {
        Self {
            snapshot: Uuid::new_v4(),
            file: Uuid::new_v4(),
            symbol: Uuid::new_v4(),
        }
    }
}

/// The columns of one edge row the cases vary. Kind and level are raw labels so a case can pass one outside the closed set.
struct Edge {
    from: Uuid,
    to: Option<Uuid>,
    unresolved: Option<&'static str>,
    kind: &'static str,
    level: &'static str,
}

impl Edge {
    /// A resolved CALLS edge at the only level v1 extraction emits.
    fn calls(from: Uuid, to: Uuid) -> Self {
        Self {
            from,
            to: Some(to),
            unresolved: None,
            kind: EdgeKind::Calls.as_db_str(),
            level: EvidenceLevel::SyntaxCandidate.as_db_str(),
        }
    }

    /// A REFERENCES edge whose target stayed a name (ADR-0114 D-E).
    fn unresolved(from: Uuid, name: &'static str) -> Self {
        Self {
            from,
            to: None,
            unresolved: Some(name),
            kind: EdgeKind::References.as_db_str(),
            level: EvidenceLevel::SyntaxCandidate.as_db_str(),
        }
    }
}

fn admin() -> Option<Client> {
    let Ok(dsn) = std::env::var("HUMAUX_TEST_PG_DSN") else {
        skip_or_fail(NAME, "missing object: Postgres DSN", ExternalDep::Postgres);
        return None;
    };
    // dep: PostgreSQL(owner) — the test admin DSN seeds, probes and removes the scenario rows
    let Ok(client) = Client::connect(&dsn, NoTls) else {
        skip_or_fail(NAME, "missing object: live Postgres", ExternalDep::Postgres);
        return None;
    };
    Some(client)
}

/// Everything the scenario owns. Dropped leaf-first so a red run leaves no tenant behind.
struct Scenario {
    admin: Client,
    tenant: Uuid,
    repository: Uuid,
    a: Snap,
    b: Snap,
}

impl Scenario {
    fn new(admin: Client) -> Self {
        Self {
            admin,
            tenant: Uuid::new_v4(),
            repository: Uuid::new_v4(),
            a: Snap::new(),
            b: Snap::new(),
        }
    }

    fn seed(&mut self) {
        self.admin
            .execute(
                "INSERT INTO control.tenants(tenant_id,name,state) VALUES($1,$2,'ACTIVE')",
                &[&self.tenant, &format!("code-schema-{}", self.tenant)],
            )
            .expect("seed tenant");
        self.admin
            .execute(
                "INSERT INTO control.repositories(repository_id,tenant_id,workspace_id,name,provider,external_id) \
                 VALUES($1,$2,NULL,'code schema fixture',$3,$4)",
                &[
                    &self.repository,
                    &self.tenant,
                    &RepositoryProvider::Client.as_db_str(),
                    &self.repository.to_string(),
                ],
            )
            .expect("seed repository");
        // Two live snapshots of one repository need two identities (code_snapshots_identity_live_key).
        for (snap, identity) in [(self.a, 1_u8), (self.b, 2_u8)] {
            self.admin
                .execute(
                    "INSERT INTO private.code_snapshots(tenant_id,snapshot_id,repository_id,kind,target_key,tree_sitter_version,\
                     grammar_set,extractor_version,identity_sha256,manifest_sha256,state) \
                     VALUES($1,$2,$3,$4,'fixture-target','fixture','fixture','fixture',$5,$5,$6)",
                    &[
                        &self.tenant,
                        &snap.snapshot,
                        &self.repository,
                        &SnapshotKind::Commit.as_db_str(),
                        &vec![identity; 32],
                        &SnapshotState::Ready.as_db_str(),
                    ],
                )
                .expect("seed snapshot");
            self.admin
                .execute(
                    "INSERT INTO private.code_files(tenant_id,snapshot_id,file_id,path,sha256,size_bytes) \
                     VALUES($1,$2,$3,'src/lib.rs',$4,1)",
                    &[&self.tenant, &snap.snapshot, &snap.file, &vec![3_u8; 32]],
                )
                .expect("seed file");
            self.insert_symbol(snap.snapshot, snap.symbol, snap.file)
                .expect("a symbol naming its own snapshot's file is accepted");
        }
    }

    fn insert_symbol(
        &mut self,
        snapshot: Uuid,
        symbol: Uuid,
        file: Uuid,
    ) -> Result<u64, postgres::Error> {
        self.admin.execute(
            "INSERT INTO private.code_symbols(tenant_id,snapshot_id,symbol_id,file_id,kind,name,qualified_name,\
             start_line,end_line,start_byte,end_byte,content_sha256) \
             VALUES($1,$2,$3,$4,$5,'f','crate::f',1,2,0,10,$6)",
            &[
                &self.tenant,
                &snapshot,
                &symbol,
                &file,
                &SymbolKind::Function.as_db_str(),
                &vec![4_u8; 32],
            ],
        )
    }

    fn insert_edge(&mut self, snapshot: Uuid, edge: &Edge) -> Result<u64, postgres::Error> {
        self.admin.execute(
            "INSERT INTO private.code_edges(tenant_id,snapshot_id,from_symbol_id,to_symbol_id,to_unresolved_name,kind,\
             evidence_level) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[
                &self.tenant,
                &snapshot,
                &edge.from,
                &edge.to,
                &edge.unresolved,
                &edge.kind,
                &edge.level,
            ],
        )
    }
}

impl Drop for Scenario {
    fn drop(&mut self) {
        for statement in [
            "DELETE FROM private.code_edges WHERE tenant_id = $1",
            "DELETE FROM private.code_symbols WHERE tenant_id = $1",
            "DELETE FROM private.code_files WHERE tenant_id = $1",
            "DELETE FROM private.code_snapshots WHERE tenant_id = $1",
            "DELETE FROM control.repositories WHERE tenant_id = $1",
            "DELETE FROM control.tenants WHERE tenant_id = $1",
        ] {
            if let Err(error) = self.admin.execute(statement, &[&self.tenant]) {
                eprintln!("code_schema cleanup failed ({statement}): {error}");
            }
        }
    }
}

/// A seeded scenario, or `None` after a visible SKIP (a failure under HUMAUX_REQUIRE_DB, §79.2).
fn seeded() -> Option<Scenario> {
    let mut client = admin()?;
    for table in ["private.code_symbols", "private.code_edges"] {
        let present: bool = client
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
            .expect("table probe")
            .get(0);
        if !present {
            skip_or_fail(
                NAME,
                &format!(
                    "missing object: {table} — run `cargo xtask migrate` (migrations/0291_code_symbols_edges.sql)"
                ),
                ExternalDep::Postgres,
            );
            return None;
        }
    }
    let mut scenario = Scenario::new(client);
    scenario.seed();
    Some(scenario)
}

/// The SQLSTATE and constraint a rejected statement reports; an accepted statement fails the case.
fn rejection(result: Result<u64, postgres::Error>, what: &str) -> (SqlState, String) {
    let error = result.expect_err(what);
    let db = error.as_db_error().expect("a database error");
    (
        db.code().clone(),
        db.constraint().unwrap_or_default().to_owned(),
    )
}

fn fk(constraint: &str) -> (SqlState, String) {
    (SqlState::FOREIGN_KEY_VIOLATION, constraint.to_owned())
}

fn check(constraint: &str) -> (SqlState, String) {
    (SqlState::CHECK_VIOLATION, constraint.to_owned())
}

fn unique(constraint: &str) -> (SqlState, String) {
    (SqlState::UNIQUE_VIOLATION, constraint.to_owned())
}

/// G-M16-3: an edge cannot join two snapshots, and a symbol cannot name another snapshot's file. Fault: the to-end FK keyed on
/// `symbol_id` alone ⇒ snapshot A's edge to sB is accepted ⇒ red.
#[test]
fn g_m16_3_an_edge_cannot_join_two_snapshots() {
    let Some(mut scenario) = seeded() else { return };
    let (a, b) = (scenario.a, scenario.b);

    scenario
        .insert_edge(a.snapshot, &Edge::calls(a.symbol, a.symbol))
        .expect("an edge inside snapshot A is accepted");
    let to_end = scenario.insert_edge(a.snapshot, &Edge::calls(a.symbol, b.symbol));
    assert_eq!(
        rejection(to_end, "snapshot A's edge to snapshot B's symbol"),
        fk("code_edges_to_symbol_fkey")
    );
    let from_end = scenario.insert_edge(a.snapshot, &Edge::calls(b.symbol, a.symbol));
    assert_eq!(
        rejection(from_end, "snapshot A's edge from snapshot B's symbol"),
        fk("code_edges_from_symbol_fkey")
    );
    let foreign_file = scenario.insert_symbol(a.snapshot, Uuid::new_v4(), b.file);
    assert_eq!(
        rejection(foreign_file, "snapshot A's symbol in snapshot B's file"),
        fk("code_symbols_file_fkey")
    );
}

/// G-M16-3: an edge names exactly one of a target symbol and an unresolved name (ADR-0114 D-E), and an unresolved name is not
/// empty. Fault: the `num_nonnulls` CHECK dropped ⇒ both and neither are accepted ⇒ red.
#[test]
fn g_m16_3_an_edge_has_exactly_one_target() {
    let Some(mut scenario) = seeded() else { return };
    let a = scenario.a;

    scenario
        .insert_edge(a.snapshot, &Edge::unresolved(a.symbol, "callee"))
        .expect("an unresolved edge (NULL to_symbol_id skips the FK) is accepted");
    let both = Edge {
        unresolved: Some("callee"),
        ..Edge::calls(a.symbol, a.symbol)
    };
    assert_eq!(
        rejection(scenario.insert_edge(a.snapshot, &both), "both targets"),
        check("code_edges_target_check")
    );
    let neither = Edge {
        to: None,
        ..Edge::calls(a.symbol, a.symbol)
    };
    assert_eq!(
        rejection(scenario.insert_edge(a.snapshot, &neither), "no target"),
        check("code_edges_target_check")
    );
    let empty = Edge::unresolved(a.symbol, "");
    assert_eq!(
        rejection(scenario.insert_edge(a.snapshot, &empty), "an empty name"),
        check("code_edges_to_unresolved_name_check")
    );
}

/// G-M16-3: kind and evidence level are closed sets, and one fact is one row (an edge repeated with the same level collapses,
/// a different level is a different fact).
#[test]
fn g_m16_3_closed_sets_and_one_row_per_fact() {
    let Some(mut scenario) = seeded() else { return };
    let a = scenario.a;

    let kind = Edge {
        kind: "CALLED",
        ..Edge::calls(a.symbol, a.symbol)
    };
    assert_eq!(
        rejection(scenario.insert_edge(a.snapshot, &kind), "kind CALLED"),
        check("code_edges_kind_check")
    );
    let level = Edge {
        level: "precise",
        ..Edge::calls(a.symbol, a.symbol)
    };
    assert_eq!(
        rejection(scenario.insert_edge(a.snapshot, &level), "level precise"),
        check("code_edges_evidence_level_check")
    );

    scenario
        .insert_edge(a.snapshot, &Edge::unresolved(a.symbol, "callee"))
        .expect("the first unresolved edge is accepted");
    let repeat = scenario.insert_edge(a.snapshot, &Edge::unresolved(a.symbol, "callee"));
    assert_eq!(
        rejection(repeat, "the same unresolved fact twice"),
        unique("code_edges_fact_key")
    );
    let other_level = Edge {
        level: EvidenceLevel::SemanticResolved.as_db_str(),
        ..Edge::unresolved(a.symbol, "callee")
    };
    scenario
        .insert_edge(a.snapshot, &other_level)
        .expect("the same name at another evidence level is another fact");
}
