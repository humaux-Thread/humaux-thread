//! `adapters::billing_repo` — contract C4, the webhook inbox door of Baseline §71.3: `inbox_insert` stores one verified
//!   provider event once, keyed by (provider, event_id), as `role_gateway` with INSERT on the table and nothing else
//!   (module design M04 D7, G-M04-13).
//! Depends-on: crates=[humaux-domain, serde_json, sqlx]; services=[PostgreSQL(role_gateway) w=[control.billing_inbox]];
//!   env=[]; modules=[adapters::postgres, domain::billing, domain::error]
//! Called-by: [tests]
//! Invariants: [the insert is `ON CONFLICT DO NOTHING` with no conflict target and no RETURNING, so the primary key
//!   (provider, event_id) decides a duplicate and the gateway never needs SELECT on the inbox; a redelivery is the
//!   result `Duplicate`, never an error and never a second row; the first delivery's payload is kept; this module
//!   writes no other billing table: the subscription projection is the processor's, through owner doors (M04-11)]
//! Spec: Baseline §71.3; §6.2.2; §76
//!
//! A conflict target (`ON CONFLICT (provider, event_id)`) would make PostgreSQL ask for SELECT on those columns, and
//! `RETURNING` asks for SELECT on the returned ones; the rows-affected count says the same thing with INSERT alone
//! (G-M04-13: no runtime role reads raw billing tables, §76). Signature verification happens before this call, in the
//! webhook route (M04-10); this door stores whatever it is handed.

use humaux_domain::billing::BillingProviderId;
use humaux_domain::error::ErrorCode;
use serde_json::Value;

use crate::postgres::RuntimeDbPool;

/// What one [`inbox_insert`] did. A result, not an error: a redelivered event is the normal case (§71.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxInsert {
    /// The event was new and is stored.
    Stored,
    /// The (provider, event_id) pair was already stored; nothing changed.
    Duplicate,
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("22023" | "22P02" | "23502" | "23514") => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

/// Stores one provider event in `control.billing_inbox` unless its (provider, event_id) is already there.
///
/// `payload` is the event body as received (JSON); `api_version` and `object_id` are the provider's own, when it sends
/// them. The row starts `RECEIVED`; the processor settles it later.
pub async fn inbox_insert(
    pool: &RuntimeDbPool,
    provider: BillingProviderId,
    event_id: &str,
    event_type: &str,
    api_version: Option<&str>,
    object_id: Option<&str>,
    payload: &Value,
) -> Result<InboxInsert, ErrorCode> {
    // dep: PostgreSQL(role_gateway) — the inbox INSERT, the only privilege the gateway holds on the table (G-M04-13)
    let stored = sqlx::query(
        "INSERT INTO control.billing_inbox (provider, event_id, event_type, api_version, object_id, payload) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
    )
    .bind(provider.wire())
    .bind(event_id)
    .bind(event_type)
    .bind(api_version)
    .bind(object_id)
    .bind(payload)
    .execute(pool.pool())
    .await
    .map_err(db_error)?;
    Ok(if stored.rows_affected() == 1 {
        InboxInsert::Stored
    } else {
        InboxInsert::Duplicate
    })
}
