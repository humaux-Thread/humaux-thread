//! `adapters::tests::evidence_sources` — M06-1a (ADR-0098): `remember_sourced_in_txn` against a real Postgres, plus the
//!   §78.2 reconciliation of `IngestSourceKind` / `IngestEventKind` with their CHECK lists.
//! Depends-on: crates=[humaux-adapters, humaux-domain, humaux-testkit, postgres, serde_json, sqlx, tokio];
//!   services=[PostgreSQL(any) w=[control.memberships, control.private_reasoning_domains,
//!   control.tenants, control.users, ops.jobs, ops.outbox, private.events, private.evidence_objects,
//!   private.evidence_sources, projection.stream_checkpoints, projection.stream_log], PostgreSQL(role_gateway)];
//!   env=[CARGO_MANIFEST_DIR, HUMAUX_TEST_PG_DSN];
//!   modules=[adapters::remember, adapters::tests::support::token_keys, domain::dataclass, domain::error,
//!   domain::evidence, domain::source, domain::subject, humaux-testkit]
//! Called-by: [cargo-test]
//! Invariants: [rows are scoped to a throwaway tenant and user this file owns; every sourced write runs on a real
//!   role_gateway login through remember_in_txn's own RLS context; no DSN or unreachable DB is a visible SKIP, a
//!   declared DB that is missing is a FAIL (§79.2)]
//! Spec: Baseline §7.5; §8.7; §60; §78.2; §79.2; ADR-0098
//!
//! G-M06-3 `two_ok_messages_two_evidence`: equal text under different object keys is two Evidence (no body-hash dedupe).
//! G-M06-4 `email_cannot_be_workspace_shared`: a third-party source is forced to USER_PRIVATE + SENSITIVE + ExternalContent.
//! G-M06-7 `sourced_write_is_one_atomic_unit`: a refused source row rolls back the Evidence, event, ticket and outbox row.

#[path = "support/token_keys.rs"]
mod token_keys;

use humaux_adapters::remember::{self, RememberCommand, RememberError};
use humaux_domain::dataclass::DataClass;
use humaux_domain::error::ErrorCode;
use humaux_domain::evidence::{EvidenceOriginClass, payload_sha256};
use humaux_domain::source::{IngestEventKind, IngestSourceKind, SourceIdentity};
use humaux_testkit::{DbFixtureSkipReason, DbIntegrationFixture, run_db_fixture};
use postgres::{Client, NoTls};
use sqlx::types::Uuid;
use sqlx::types::time::OffsetDateTime;

const MIGRATION_0264: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0264_evidence_sources.sql"
));
const MIGRATION_0004: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0004_private_evidence_memory.sql"
));

/// The comma-separated list that follows `needle` up to its closing parenthesis, trimmed of spaces and quotes.
fn check_list(sql: &str, needle: &str) -> Vec<String> {
    let start = sql
        .find(needle)
        .unwrap_or_else(|| panic!("migration must contain {needle:?}"))
        + needle.len();
    let close = sql[start..]
        .find(')')
        .unwrap_or_else(|| panic!("unterminated list after {needle:?}"))
        + start;
    sql[start..close]
        .split(',')
        .map(|s| s.trim().trim_matches('\'').to_string())
        .collect()
}

/// §78.2: the `source_kind` CHECK list is exactly `IngestSourceKind::ALL`'s codes, in order.
#[test]
fn source_kind_codes_match_the_0264_check() {
    let db = check_list(MIGRATION_0264, "CHECK (source_kind IN (");
    let rust: Vec<String> = IngestSourceKind::ALL
        .iter()
        .map(|kind| kind.db_code().to_string())
        .collect();
    assert_eq!(db, rust);
    assert_eq!(rust.len(), 6);
}

/// §78.2: every `IngestEventKind` literal is a member of the `private.events.event_kind` CHECK list.
#[test]
fn ingest_event_kinds_are_members_of_the_events_check() {
    let db = check_list(MIGRATION_0004, "event_kind IN (");
    assert_eq!(db.len(), 9);
    let rust: Vec<&str> = IngestEventKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(
        rust,
        vec!["USER_MESSAGE", "ASSISTANT_MESSAGE", "SYSTEM_IMPORT"]
    );
    for literal in rust {
        assert!(
            db.iter().any(|v| v == literal),
            "{literal} is not in the event_kind CHECK"
        );
    }
}

struct Handle {
    rt: tokio::runtime::Runtime,
    admin: Client,
    gateway: sqlx::Pool<sqlx::Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    reasoning_domain_id: Uuid,
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Err(error) = self.admin.batch_execute(&format!(
            "DELETE FROM ops.jobs WHERE tenant_id = '{0}'; \
             DELETE FROM ops.outbox WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_log WHERE tenant_id = '{0}'; \
             DELETE FROM projection.stream_checkpoints WHERE tenant_id = '{0}'; \
             DELETE FROM private.evidence_sources WHERE tenant_id = '{0}'; \
             DELETE FROM private.events USING private.evidence_objects eo \
               WHERE events.event_id = eo.evidence_id AND eo.tenant_id = '{0}'; \
             DELETE FROM private.evidence_objects WHERE tenant_id = '{0}'; \
             DELETE FROM control.private_reasoning_domains WHERE tenant_id = '{0}'; \
             DELETE FROM control.memberships WHERE tenant_id = '{0}';",
            self.tenant_id,
        )) {
            eprintln!(
                "evidence_sources cleanup failed for tenant {}: {error}",
                self.tenant_id
            );
        }
        let _ = self.admin.batch_execute(&format!(
            "DELETE FROM control.tenants WHERE tenant_id = '{0}'; \
             DELETE FROM control.users WHERE user_id = '{1}';",
            self.tenant_id, self.user_id,
        ));
    }
}

struct Fixture;

impl DbIntegrationFixture for Fixture {
    type Handle = Handle;

    fn isolate() -> Result<Self::Handle, DbFixtureSkipReason> {
        token_keys::install();
        let dsn =
            std::env::var("HUMAUX_TEST_PG_DSN").map_err(|_| DbFixtureSkipReason::NoDatabaseUrl)?;
        // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
        let mut admin = Client::connect(&dsn, NoTls)
            .map_err(|e| DbFixtureSkipReason::ConnectFailed(e.to_string()))?;
        let setup = |e: postgres::Error| DbFixtureSkipReason::IsolationSetupFailed(e.to_string());

        let migrated: bool = admin
            .query_one(
                "SELECT to_regclass('private.evidence_sources') IS NOT NULL",
                &[],
            )
            .map_err(setup)?
            .get(0);
        if !migrated {
            return Err(DbFixtureSkipReason::IsolationSetupFailed(
                "private.evidence_sources missing — run `cargo xtask migrate` against HUMAUX_TEST_PG_DSN first (0264)"
                    .to_string(),
            ));
        }
        let tenant_id: Uuid = admin
            .query_one(
                "INSERT INTO control.tenants (name) VALUES ($1) RETURNING tenant_id",
                &[&"evidence_sources.rs throwaway tenant"],
            )
            .map_err(setup)?
            .get(0);
        let user_id: Uuid = admin
            .query_one(
                "INSERT INTO control.users (state) VALUES ('ACTIVE') RETURNING user_id",
                &[],
            )
            .map_err(setup)?
            .get(0);
        admin
            .execute(
                "INSERT INTO control.memberships (tenant_id, user_id, role, state) \
                 VALUES ($1, $2, 'member', 'ACTIVE')",
                &[&tenant_id, &user_id],
            )
            .map_err(setup)?;
        let reasoning_domain_id: Uuid = admin
            .query_one(
                "INSERT INTO control.private_reasoning_domains (tenant_id, name) \
                 VALUES ($1, 'throwaway') RETURNING reasoning_domain_id",
                &[&tenant_id],
            )
            .map_err(setup)?
            .get(0);

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        let sep = if dsn.contains('?') { '&' } else { '?' };
        let gateway_dsn = format!("{dsn}{sep}options=-c%20role%3Drole_gateway");
        let gateway = rt
            // dep: PostgreSQL(any) — open a role-scoped PG connection/pool for this test
            // ADR-0065 D-A: `Pool::connect`, so the pool builder keeps its one site in postgres.rs.
            .block_on(sqlx::Pool::<sqlx::Postgres>::connect(&gateway_dsn))
            .map_err(|e| DbFixtureSkipReason::IsolationSetupFailed(e.to_string()))?;
        Ok(Handle {
            rt,
            admin,
            gateway,
            tenant_id,
            user_id,
            reasoning_domain_id,
        })
    }
}

/// A `remember` input that asks for the weakest classification a caller can: INTERNAL data, a direct-user origin and a
/// plain note event, so every stored value that differs from it was decided by the source classification.
fn command(handle: &Handle, content: &str, visibility_class: &str) -> RememberCommand {
    RememberCommand {
        tenant_id: handle.tenant_id,
        authorization_user_id: Some(handle.user_id),
        scope_kind: "workspace".to_string(),
        scope_id: Uuid::new_v4(),
        domain: "private_memory".to_string(),
        projection_kind: "PRIVATE_MEMORY".to_string(),
        projection_version: "v1".to_string(),
        consistency_token_expires_at: OffsetDateTime::now_utc()
            + std::time::Duration::from_secs(3600),
        batch_id: None,
        payload_sha256: payload_sha256(content.as_bytes()),
        data_class: "INTERNAL".to_string(),
        origin_class: EvidenceOriginClass::DirectUserInput,
        origin_principal_id: None,
        origin_connector_id: None,
        visibility_class: visibility_class.to_string(),
        visibility_user_id: (visibility_class == "USER_PRIVATE").then_some(handle.user_id),
        visibility_workspace_id: None,
        reasoning_domain_id: handle.reasoning_domain_id,
        occurred_at: None,
        event_kind: "MANUAL_NOTE".to_string(),
        event_payload: serde_json::json!({ "content": content }),
        subjects: humaux_domain::subject::SubjectDeclaration::default(),
        affects: Vec::new(),
        mood_half_life: None,
    }
}

/// One sourced write on its own `role_gateway` transaction, committed only when it succeeds.
fn put(
    handle: &Handle,
    kind: IngestSourceKind,
    object_key: &str,
    content: &str,
    visibility_class: &str,
) -> Result<Uuid, RememberError> {
    let source = SourceIdentity::new(kind, object_key, Some("v1"), Some("thread-1"))
        .expect("a valid source identity");
    let cmd = command(handle, content, visibility_class);
    handle.rt.block_on(async {
        // dep: PostgreSQL(role_gateway) — transaction entry for the sourced write
        let mut txn = handle.gateway.begin().await?;
        let pending = remember::remember_sourced_in_txn(&mut txn, cmd, &source).await?;
        txn.commit().await?;
        Ok(pending.into_accepted().evidence_id)
    })
}

fn count(handle: &mut Handle, table: &str) -> i64 {
    let tenant_id = handle.tenant_id;
    handle
        .admin
        .query_one(
            &format!("SELECT count(*) FROM {table} WHERE tenant_id = $1"),
            &[&tenant_id],
        )
        .expect("count query")
        .get(0)
}

/// G-M06-3 (§8.7, ADR-0098 D1): two messages with equal text and different ids are two Evidence and two source rows;
/// identity is never the body hash.
#[test]
fn two_ok_messages_two_evidence() {
    run_db_fixture::<Fixture, _>("two_ok_messages_two_evidence", |mut handle| {
        let first = put(
            &handle,
            IngestSourceKind::ChatMessage,
            "msg-1",
            "OK",
            "USER_PRIVATE",
        );
        let second = put(
            &handle,
            IngestSourceKind::ChatMessage,
            "msg-2",
            "OK",
            "USER_PRIVATE",
        );
        assert!(first.is_ok(), "first message: {first:?}");
        assert!(second.is_ok(), "second message with equal text: {second:?}");
        assert_ne!(first.expect("ok"), second.expect("ok"));

        assert_eq!(count(&mut handle, "private.evidence_objects"), 2);
        assert_eq!(count(&mut handle, "private.evidence_sources"), 2);
        let tenant_id = handle.tenant_id;
        let row = handle
            .admin
            .query_one(
                "SELECT count(DISTINCT payload_sha256), count(DISTINCT object_key_d16) \
                 FROM private.evidence_sources WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .expect("distinct counts");
        assert_eq!(
            (row.get::<_, i64>(0), row.get::<_, i64>(1)),
            (1, 2),
            "one body, two identities"
        );
    });
}

/// G-M06-4 (§7.5, §8.7, ADR-0098 D2): an email cannot be shared wider than its owner, and what is stored is
/// USER_PRIVATE + SENSITIVE + ExternalContent whatever the caller asked for.
#[test]
fn email_cannot_be_workspace_shared() {
    run_db_fixture::<Fixture, _>("email_cannot_be_workspace_shared", |mut handle| {
        for wider in ["WORKSPACE_SHARED", "TENANT_SHARED"] {
            let refused = put(
                &handle,
                IngestSourceKind::EmailMessage,
                "mail-1",
                "hello",
                wider,
            );
            assert!(
                matches!(refused, Err(RememberError::Source(ErrorCode::InvalidInput))),
                "{wider}: {refused:?}"
            );
        }
        assert_eq!(count(&mut handle, "private.evidence_objects"), 0);
        assert_eq!(count(&mut handle, "private.evidence_sources"), 0);

        let evidence_id = put(
            &handle,
            IngestSourceKind::EmailMessage,
            "mail-1",
            "hello",
            "USER_PRIVATE",
        )
        .expect("a user-private email is accepted");
        let stored = handle
            .admin
            .query_one(
                "SELECT eo.data_class, eo.origin_class, eo.visibility_class, e.event_kind, s.source_kind \
                 FROM private.evidence_objects eo \
                 JOIN private.events e ON e.event_id = eo.evidence_id \
                 JOIN private.evidence_sources s ON s.evidence_id = eo.evidence_id AND s.tenant_id = eo.tenant_id \
                 WHERE eo.evidence_id = $1",
                &[&evidence_id],
            )
            .expect("the stored classification");
        assert_eq!(stored.get::<_, String>(0), DataClass::Sensitive.as_str());
        assert_eq!(stored.get::<_, String>(1), "ExternalContent");
        assert_eq!(stored.get::<_, String>(2), "USER_PRIVATE");
        assert_eq!(stored.get::<_, String>(3), "SYSTEM_IMPORT");
        assert_eq!(
            stored.get::<_, i16>(4),
            IngestSourceKind::EmailMessage.db_code()
        );
    });
}

/// G-M06-7 (§60, §60.1): the source row rides in the Evidence's transaction. One accepted sourced write leaves exactly
/// one Evidence, event, source row, stream_log row and outbox row; a repeat of the same identity is refused by the UNIQUE
/// and leaves all five counts where they were, so no half-written Evidence is ever left behind.
#[test]
fn sourced_write_is_one_atomic_unit() {
    run_db_fixture::<Fixture, _>("sourced_write_is_one_atomic_unit", |mut handle| {
        put(
            &handle,
            IngestSourceKind::CalendarItem,
            "cal-1",
            "standup",
            "USER_PRIVATE",
        )
        .expect("first write");
        let counts = |handle: &mut Handle| {
            [
                count(handle, "private.evidence_objects"),
                count(handle, "private.evidence_sources"),
                count(handle, "projection.stream_log"),
                count(handle, "ops.outbox"),
            ]
        };
        assert_eq!(counts(&mut handle), [1, 1, 1, 1]);

        let repeat = put(
            &handle,
            IngestSourceKind::CalendarItem,
            "cal-1",
            "standup moved",
            "USER_PRIVATE",
        );
        let violated = match &repeat {
            Err(RememberError::Db(sqlx::Error::Database(db))) => (
                db.code().map(|c| c.to_string()),
                db.constraint().map(str::to_owned),
            ),
            other => panic!("a repeated identity must be a database error: {other:?}"),
        };
        assert_eq!(
            violated,
            (
                Some("23505".to_string()),
                Some("evidence_sources_identity_key".to_string())
            ),
            "the refusal must be the identity UNIQUE, not another constraint"
        );
        assert_eq!(counts(&mut handle), [1, 1, 1, 1]);
    });
}
