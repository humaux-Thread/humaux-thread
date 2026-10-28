//! `billing-worker::normalize` — provider envelope boundary (§71.2).
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[]; modules=[domain::billing, domain::error, domain::plan]
//! Called-by: [tests]
//! Invariants: [no checkout-response money; no status inferred from event type; missing amounts fail closed]
//! Spec: Baseline §71.2; §71.3; §52; §78.2

use humaux_domain::{
    billing::{ObservedStatus, PaymentKind},
    error::ErrorCode,
    plan::Currency,
};
use serde_json::Value;

/// §71.3: non-payment events carry no invented payment facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// §71.3: append-only payment direction.
    Payment(PaymentKind),
    /// §71.3: requires an authoritative subscription re-fetch.
    SubscriptionChanged,
    /// §71.3: retained by the inbox, without billing effects.
    Ignored,
}

/// §71.3: integer cents and millisecond period bounds from payload/fetch only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Money {
    /// §71.3: never defaults to zero.
    pub amount_cents: i64,
    /// §78.2: the existing USD-only vocabulary.
    pub currency: Currency,
    /// §71.3: absent tax stays unknown.
    pub tax_amount: Option<i64>,
    /// §71.3: transaction period start in epoch milliseconds.
    pub period_start: i64,
    /// §71.3: transaction period end in epoch milliseconds.
    pub period_end: i64,
    /// §71.3: event-specific refund, never aggregate refunded_amount.
    pub refund_amount: Option<i64>,
}

/// §71.3: normalization does not confer signature verification or deduplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedEvent {
    /// §71.3: inbox deduplication key.
    pub id: String,
    /// §71.3: retained even for ignored events.
    pub event_type: String,
    /// §71.3: envelope epoch milliseconds, not a replay check.
    pub created_at: i64,
    /// §71.3: effect category independent of subscription status.
    pub kind: EventKind,
    /// §71.3: present exactly for payment events.
    pub money: Option<Money>,
}

/// §71.3: caller supplies the fetched subscription status, never the event type.
pub fn status(fetched_status: &str) -> Result<ObservedStatus, ErrorCode> {
    ObservedStatus::parse_wire(fetched_status).ok_or(ErrorCode::InvalidInput)
}

/// §71.3: `fetched_transaction` must be the authoritative transaction for this event;
/// a checkout creation response is not an admissible input (M04 D13a).
pub fn normalize(
    raw_body: &[u8],
    fetched_transaction: Option<&Value>,
) -> Result<NormalizedEvent, ErrorCode> {
    let envelope: Value = serde_json::from_slice(raw_body).map_err(|_| ErrorCode::InvalidInput)?;
    let event_type = text(&envelope, "eventType")?;
    let kind = match event_type {
        "checkout.completed" | "subscription.paid" => EventKind::Payment(PaymentKind::Charge),
        "refund.created" => EventKind::Payment(PaymentKind::Refund),
        "dispute.created" => EventKind::Payment(PaymentKind::Chargeback),
        other if other.starts_with("subscription.") => EventKind::SubscriptionChanged,
        _ => EventKind::Ignored,
    };
    let object = &envelope["object"];
    let money = if let EventKind::Payment(payment) = kind {
        let source = match event_type {
            "checkout.completed" => &object["order"],
            "subscription.paid" => &object["last_transaction"],
            _ => &object["transaction"],
        };
        let field = |key: &str| source.get(key).or_else(|| fetched_transaction?.get(key));
        let amount_source = if payment == PaymentKind::Chargeback {
            object
        } else {
            source
        };
        let amount = amount_source
            .get("amount")
            .or_else(|| fetched_transaction?.get("amount"));
        let currency = if payment == PaymentKind::Chargeback {
            object
                .get("currency")
                .or_else(|| fetched_transaction?.get("currency"))
        } else {
            field("currency")
        };
        let tax_amount = field("tax_amount")
            .filter(|value| !value.is_null())
            .map(|value| cents(Some(value)))
            .transpose()?;
        let period_start = cents(field("period_start"))?;
        let period_end = cents(field("period_end"))?;
        if period_end <= period_start {
            return Err(ErrorCode::InvalidInput);
        }
        Some(Money {
            amount_cents: cents(amount)?,
            currency: Currency::parse_wire(
                currency
                    .and_then(Value::as_str)
                    .ok_or(ErrorCode::InvalidInput)?,
            )
            .ok_or(ErrorCode::InvalidInput)?,
            tax_amount,
            period_start,
            period_end,
            refund_amount: if payment == PaymentKind::Refund {
                Some(cents(object.get("refund_amount"))?)
            } else {
                None
            },
        })
    } else {
        None
    };
    Ok(NormalizedEvent {
        id: text(&envelope, "id")?.to_owned(),
        event_type: event_type.to_owned(),
        created_at: cents(envelope.get("created_at"))?,
        kind,
        money,
    })
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, ErrorCode> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(ErrorCode::InvalidInput)
}

fn cents(value: Option<&Value>) -> Result<i64, ErrorCode> {
    value
        .and_then(Value::as_i64)
        .filter(|amount| *amount >= 0)
        .ok_or(ErrorCode::InvalidInput)
}
