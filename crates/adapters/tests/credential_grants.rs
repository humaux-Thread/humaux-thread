//! `adapters::tests::credential_grants` — G-M02-1 (SEC-1, M02 D11, migration 0260): the eight `control` tables that hold a credential verifier are readable by role_gateway and role_maintenance and by no other role, proven by connecting as each role.
//! Depends-on: crates=[humaux-testkit, postgres]; services=[PostgreSQL(any) r=[control.api_keys, control.email_challenges,
//!   control.email_change_requests, control.oauth_authorization_codes, control.oauth_client_registrations,
//!   control.oauth_grants, control.oauth_refresh_tokens, control.password_credentials,
//!   control.password_reset_challenges, control.recovery_codes, control.sessions, control.team_invitations]];
//!   env=[HUMAUX_TEST_PG_DSN];
//!   modules=[humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [reads the shared test database only: every probe runs in a transaction that is rolled back, so no
//!   row, grant or role changes; a SELECT that succeeds as a worker, batch issuer, admin or health reader is the
//!   failure, and the grant set read back from the table ACL (PUBLIC included, column-level included) must equal
//!   exactly SELECT for the two readers; the four OAuth tables of 0268 (M02-8) hold no grant for any role and are reached
//!   only through nine doors executable by role_gateway alone; no DSN or unreachable database is a visible §79.2 skip]
//! Spec: Baseline §6.2.1; §6.2.2; §79.2

use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::error::SqlState;
use postgres::{Client, NoTls};

/// The tables migration 0260 closes; `maintenance::rls_check` carries the same eight as §6.2.2 cells.
const VERIFIER_TABLES: [&str; 8] = [
    "control.api_keys",
    "control.sessions",
    "control.email_challenges",
    "control.password_reset_challenges",
    "control.email_change_requests",
    "control.password_credentials",
    "control.recovery_codes",
    "control.team_invitations",
];

/// The only roles that may SELECT them (M02 D11).
const READERS: [&str; 2] = ["role_gateway", "role_maintenance"];

/// Every other role of §6.2.0 except the owner.
const NON_READERS: [&str; 7] = [
    "role_private_worker",
    "role_consolidation_worker",
    "role_public_worker",
    "role_retrieval_worker",
    "role_batch_issuer",
    "role_admin",
    "role_health_reader",
];

/// Table-level ACL entries of one table other than the owner's: `(grantee, privilege)`, PUBLIC spelled `PUBLIC`.
const ACL_SQL: &str = "SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END, \
                              a.privilege_type \
                         FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a \
                        WHERE c.oid = to_regclass($1) AND a.grantee <> c.relowner \
                        ORDER BY 1, 2";

/// Column-level ACLs of one table (any grantee): none may exist.
const COLUMN_ACL_SQL: &str = "SELECT count(*) FROM pg_attribute \
                               WHERE attrelid = to_regclass($1) AND coalesce(cardinality(attacl), 0) > 0";

struct Handle {
    client: Client,
}

struct GrantsFixture;

impl DbIntegrationFixture for GrantsFixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — the shared test database, read-only: every probe is rolled back
        let client = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        Ok(Handle { client })
    }
}

/// `SELECT 1 FROM <table> LIMIT 1` as `role`, in a transaction that is always rolled back; `Err` carries the SQLSTATE.
/// An RLS table answers zero rows without a tenant GUC, which is `Ok`: only the privilege check can refuse.
fn select_as(client: &mut Client, role: &str, table: &str) -> Result<(), Option<SqlState>> {
    let mut txn = client.transaction().expect("open the probe transaction");
    // dep: PostgreSQL(any) — the probe runs as the role under test
    txn.batch_execute(&format!("SET LOCAL ROLE {role}"))
        .expect("switch to the role under test");
    let outcome = txn.query(&format!("SELECT 1 FROM {table} LIMIT 1"), &[]);
    txn.rollback().expect("roll back the probe transaction");
    outcome.map(|_| ()).map_err(|e| e.code().cloned())
}

/// G-M02-1, behaviour: the two readers still read every secret table, and every other role is refused with 42501.
#[test]
fn g_m02_1_only_gateway_and_maintenance_select_a_secret_table() {
    run_db_fixture::<GrantsFixture, _>(
        "g_m02_1_only_gateway_and_maintenance_select_a_secret_table",
        |mut h| {
            for table in VERIFIER_TABLES {
                for role in READERS {
                    assert_eq!(
                        select_as(&mut h.client, role, table),
                        Ok(()),
                        "{role} must keep SELECT on {table}"
                    );
                }
                for role in NON_READERS {
                    assert_eq!(
                        select_as(&mut h.client, role, table),
                        Err(Some(SqlState::INSUFFICIENT_PRIVILEGE)),
                        "{role} must be refused SELECT on {table}"
                    );
                }
            }
        },
    );
}

/// G-M02-1, catalog: the grant set of each secret table, read back from its ACL, is exactly SELECT for the two readers.
/// This also sees what a probe cannot: PUBLIC, a write verb, and a column-level grant.
#[test]
fn g_m02_1_a_secret_table_acl_is_exactly_gateway_and_maintenance_select() {
    run_db_fixture::<GrantsFixture, _>(
        "g_m02_1_a_secret_table_acl_is_exactly_gateway_and_maintenance_select",
        |mut h| {
            let expected: Vec<(String, String)> = READERS
                .iter()
                .map(|role| ((*role).to_owned(), "SELECT".to_owned()))
                .collect();
            for table in VERIFIER_TABLES {
                let grants: Vec<(String, String)> = h
                    .client
                    .query(ACL_SQL, &[&table])
                    .expect("read the table ACL")
                    .iter()
                    .map(|row| (row.get(0), row.get(1)))
                    .collect();
                assert_eq!(grants, expected, "{table}: grant set");
                let columns: i64 = h
                    .client
                    .query_one(COLUMN_ACL_SQL, &[&table])
                    .expect("read the column ACLs")
                    .get(0);
                assert_eq!(columns, 0, "{table}: column-level grants");
            }
        },
    );
}

/// The OAuth tables of migration 0268 and one column of each, for the UPDATE probe. No role may touch any of them.
const OAUTH_TABLES: [(&str, &str); 4] = [
    ("control.oauth_client_registrations", "kind"),
    ("control.oauth_authorization_codes", "used_at"),
    ("control.oauth_grants", "status"),
    ("control.oauth_refresh_tokens", "status"),
];

/// The nine doors of migration 0268, by `pg_proc.proname`: the whole access path to the four tables.
const OAUTH_DOORS: [&str; 9] = [
    "oauth_client_lookup",
    "oauth_client_register",
    "oauth_code_consume",
    "oauth_code_issue",
    "oauth_grant_issue",
    "oauth_grant_lookup",
    "oauth_grant_revoke",
    "oauth_refresh_family_revoke",
    "oauth_refresh_rotate",
];

/// `statement` as `role`, in a transaction that is always rolled back; `Err` carries the SQLSTATE. Every statement used
/// here selects or changes no row, so only the privilege check can refuse.
fn run_as(client: &mut Client, role: &str, statement: &str) -> Result<(), Option<SqlState>> {
    let mut txn = client.transaction().expect("open the probe transaction");
    // dep: PostgreSQL(any) — the probe runs as the role under test
    txn.batch_execute(&format!("SET LOCAL ROLE {role}"))
        .expect("switch to the role under test");
    let outcome = txn.batch_execute(statement);
    txn.rollback().expect("roll back the probe transaction");
    outcome.map_err(|e| e.code().cloned())
}

/// G-M02-1 for 0268, behaviour: every one of the nine non-owner roles, role_gateway included, is refused SELECT, UPDATE
/// and DELETE on each OAuth table with 42501.
#[test]
fn g_m02_1_no_role_touches_an_oauth_table_directly() {
    run_db_fixture::<GrantsFixture, _>(
        "g_m02_1_no_role_touches_an_oauth_table_directly",
        |mut h| {
            let roles: Vec<&str> = READERS.iter().chain(NON_READERS.iter()).copied().collect();
            assert_eq!(roles.len(), 9, "every non-owner role of §6.2.0");
            assert_eq!(OAUTH_TABLES.len(), 4, "the four OAuth tables");
            for (table, column) in OAUTH_TABLES {
                let statements = [
                    format!("SELECT 1 FROM {table} LIMIT 1"),
                    format!("UPDATE {table} SET {column} = {column} WHERE false"),
                    format!("DELETE FROM {table} WHERE false"),
                ];
                for role in &roles {
                    for statement in &statements {
                        assert_eq!(
                            run_as(&mut h.client, role, statement),
                            Err(Some(SqlState::INSUFFICIENT_PRIVILEGE)),
                            "{role} must be refused `{statement}`"
                        );
                    }
                }
            }
        },
    );
}

/// G-M02-1 for 0268, catalog: the grant set of each OAuth table, read back from its ACL, is exactly empty — PUBLIC, every
/// verb and every column-level grant included.
#[test]
fn g_m02_1_an_oauth_table_acl_is_exactly_empty() {
    run_db_fixture::<GrantsFixture, _>("g_m02_1_an_oauth_table_acl_is_exactly_empty", |mut h| {
        for (table, _) in OAUTH_TABLES {
            let grants: Vec<(String, String)> = h
                .client
                .query(ACL_SQL, &[&table])
                .expect("read the table ACL")
                .iter()
                .map(|row| (row.get(0), row.get(1)))
                .collect();
            assert_eq!(grants, Vec::<(String, String)>::new(), "{table}: grant set");
            let columns: i64 = h
                .client
                .query_one(COLUMN_ACL_SQL, &[&table])
                .expect("read the column ACLs")
                .get(0);
            assert_eq!(columns, 0, "{table}: column-level grants");
        }
    });
}

/// G-M02-1 for 0268, doors: the `control.oauth_*` functions are exactly the nine named, each owner SECURITY DEFINER with
/// `search_path=pg_catalog` alone, and EXECUTE is held by role_gateway alone (PUBLIC included).
#[test]
fn g_m02_1_the_oauth_doors_are_executable_by_gateway_alone() {
    run_db_fixture::<GrantsFixture, _>(
        "g_m02_1_the_oauth_doors_are_executable_by_gateway_alone",
        |mut h| {
            let rows = h
                .client
                .query(
                    "SELECT p.proname::text, p.prosecdef, pg_get_userbyid(p.proowner)::text, \
                            coalesce(p.proconfig, ARRAY[]::text[]), \
                            ARRAY(SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END \
                                    FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a \
                                   WHERE a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner ORDER BY 1) \
                       FROM pg_proc p \
                      WHERE p.pronamespace = 'control'::regnamespace AND p.proname LIKE 'oauth\\_%' ORDER BY 1",
                    &[],
                )
                .expect("read the door catalog");
            let names: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
            let expected: Vec<String> = OAUTH_DOORS.iter().map(|d| (*d).to_owned()).collect();
            assert_eq!(names, expected, "the door set");
            for row in &rows {
                let name: String = row.get(0);
                let secdef: bool = row.get(1);
                let owner: String = row.get(2);
                let config: Vec<String> = row.get(3);
                let executors: Vec<String> = row.get(4);
                assert!(secdef, "{name}: SECURITY DEFINER");
                assert_eq!(owner, "role_migration_owner", "{name}: owner");
                assert_eq!(
                    config,
                    vec!["search_path=pg_catalog".to_owned()],
                    "{name}: config"
                );
                assert_eq!(
                    executors,
                    vec!["role_gateway".to_owned()],
                    "{name}: EXECUTE set"
                );
            }
        },
    );
}
