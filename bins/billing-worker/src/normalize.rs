//! `billing-worker::normalize` — provider envelope boundary (§71.2).
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[]; modules=[domain::billing, domain::error, domain::plan]
//! Called-by: [billing-worker::creem, tests]
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
    /// §71.3: M04-11 stores the explicitly named amount for each direction.
    pub amount: PaymentAmount,
    /// §78.2: the existing USD-only vocabulary.
    pub currency: Currency,
    /// §71.3: absent tax stays unknown.
    pub tax_amount: Option<i64>,
    /// §71.3: transaction period start in epoch milliseconds.
    pub period_start: i64,
    /// §71.3: transaction period end in epoch milliseconds.
    pub period_end: i64,
}

/// §71.3: M04-11 writes charged_amount, refund_amount or disputed_amount respectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentAmount {
    /// §71.3: CHARGE stores charged_amount.
    Charge {
        /// §71.3: charged cents, never defaulted.
        charged_amount: i64,
    },
    /// §71.3: REFUND stores refund_amount, never original_transaction_amount.
    Refund {
        /// §71.3: event-specific reversal, not aggregate refunded_amount.
        refund_amount: i64,
        /// §71.3: original charge retained separately.
        original_transaction_amount: i64,
    },
    /// §71.3: CHARGEBACK stores disputed_amount from the dispute object.
    Chargeback {
        /// §71.3: disputed cents, independent of the original transaction amount.
        disputed_amount: i64,
    },
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
    /// §71.3: payment transaction identity for the ledger UNIQUE key; absent on non-payments.
    pub provider_txn_ref: Option<String>,
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
        let (source, reference) = transaction_source(&envelope)?;
        if let Some(fetched) = fetched_transaction {
            if text(fetched, "id")? != reference {
                return Err(ErrorCode::InvalidInput);
            }
        }
        let field = |key: &str| source.get(key).or_else(|| fetched_transaction?.get(key));
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
            amount: match payment {
                PaymentKind::Charge => PaymentAmount::Charge {
                    charged_amount: cents(field("amount"))?,
                },
                PaymentKind::Refund => PaymentAmount::Refund {
                    refund_amount: cents(object.get("refund_amount"))?,
                    original_transaction_amount: cents(field("amount"))?,
                },
                PaymentKind::Chargeback => PaymentAmount::Chargeback {
                    disputed_amount: cents(object.get("amount"))?,
                },
            },
            currency: Currency::parse_wire(
                currency
                    .and_then(Value::as_str)
                    .ok_or(ErrorCode::InvalidInput)?,
            )
            .ok_or(ErrorCode::InvalidInput)?,
            tax_amount,
            period_start,
            period_end,
        })
    } else {
        None
    };
    Ok(NormalizedEvent {
        id: text(&envelope, "id")?.to_owned(),
        event_type: event_type.to_owned(),
        created_at: cents(envelope.get("created_at"))?,
        kind,
        provider_txn_ref: if money.is_some() {
            Some(transaction_source(&envelope)?.1.to_owned())
        } else {
            None
        },
        money,
    })
}

/// §71.3: checkout order ids must never substitute for transaction ids.
pub(crate) fn transaction_source(envelope: &Value) -> Result<(&Value, &str), ErrorCode> {
    let object = &envelope["object"];
    let (source, key) = match text(envelope, "eventType")? {
        "checkout.completed" => (&object["order"], "transaction"),
        "subscription.paid" => (&object["last_transaction"], "id"),
        "refund.created" | "dispute.created" => (&object["transaction"], "id"),
        _ => return Err(ErrorCode::InvalidInput),
    };
    Ok((source, text(source, key)?))
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
