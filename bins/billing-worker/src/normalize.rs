//! `billing-worker::normalize` — provider envelope boundary (§71.2).
//! Depends-on: crates=[humaux-application, humaux-domain, serde_json, uuid]; services=[]; env=[]; modules=[application::billing, application::billing_process, domain::billing, domain::error, domain::ids, domain::plan]
//! Called-by: [billing-worker::creem, billing-worker::process, tests]
//! Invariants: [no checkout-response money; no status inferred from event type; missing amounts fail closed]
//! Spec: Baseline §71.2; §71.3; §52; §78.2

use humaux_domain::{
    billing::{ObservedStatus, PaymentKind},
    error::ErrorCode,
    ids::TenantId,
    plan::Currency,
};
use serde_json::Value;
use uuid::Uuid;

use humaux_application::{
    billing::{ProviderSubscription, VerifiedBillingEvent},
    billing_process::BillingEventPayload,
};

/// §71.3: normalized provider-neutral values returned to existing provider callers.
pub use humaux_application::billing_process::{EventKind, Money, NormalizedEvent, PaymentAmount};

/// §71.3: caller supplies the fetched subscription status, never the event type.
pub fn status(fetched_status: &str) -> Result<ObservedStatus, ErrorCode> {
    ObservedStatus::parse_wire(fetched_status).ok_or(ErrorCode::InvalidInput)
}

/// §71.3: fallback fields must be authoritative for this transaction; checkout periods may come
/// from the subscription fetched under its lock (lead ruling 2026-10-29);
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
        if let Some(fetched) = fetched_transaction
            && text(fetched, "id")? != reference
        {
            return Err(ErrorCode::InvalidInput);
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
        let period = if event_type == "checkout.completed" {
            fetched_transaction.unwrap_or(source)
        } else {
            source
        };
        let period_start = cents(period.get("period_start").or_else(|| field("period_start")))?;
        let period_end = cents(period.get("period_end").or_else(|| field("period_end")))?;
        if period_end <= period_start {
            return Err(ErrorCode::InvalidInput);
        }
        Some(Money {
            amount: match payment {
                PaymentKind::Charge => PaymentAmount::Charge {
                    charged_amount: cents(field("amount_paid"))?,
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
        provider_txn_ref: match kind {
            EventKind::Payment(PaymentKind::Charge) => {
                Some(transaction_source(&envelope)?.1.to_owned())
            }
            EventKind::Payment(_) => Some(text(object, "id")?.to_owned()),
            _ => None,
        },
        original_txn_ref: match kind {
            EventKind::Payment(PaymentKind::Refund | PaymentKind::Chargeback) => {
                Some(transaction_source(&envelope)?.1.to_owned())
            }
            _ => None,
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

/// Stored authenticated envelope, decoded only when reached in the processing sequence.
pub(crate) struct StoredEnvelope(pub(crate) Value);

impl BillingEventPayload for StoredEnvelope {
    fn tenant(&self, event: &VerifiedBillingEvent) -> Result<TenantId, ErrorCode> {
        let payload = &self.0;
        // §71.3: inbox columns must agree with the authenticated envelope.
        if event.event_id.is_empty()
            || event.event_type.is_empty()
            || payload["id"].as_str() != Some(event.event_id.as_str())
            || payload["eventType"].as_str() != Some(event.event_type.as_str())
            || payload["object"]["id"].as_str() != event.object_id.as_deref()
            || payload["created_at"].as_i64().is_none_or(|n| n < 0)
        {
            return Err(ErrorCode::InvalidInput);
        }
        let object = &payload["object"];
        let reversal = matches!(
            event.event_type.as_str(),
            "refund.created" | "dispute.created"
        );
        event_tenant(object, reversal)
    }

    fn subscription_ref(&self, event: &VerifiedBillingEvent) -> Result<&str, ErrorCode> {
        let object = &self.0["object"];
        let reversal = matches!(
            event.event_type.as_str(),
            "refund.created" | "dispute.created"
        );
        let subscription = if reversal {
            object
                .get("subscription")
                .unwrap_or(&object["transaction"]["subscription"])
        } else if event.event_type == "checkout.completed" {
            &object["subscription"]
        } else {
            object
        };
        subscription
            .as_str()
            .or_else(|| subscription["id"].as_str())
            .filter(|id| !id.is_empty())
            .ok_or(ErrorCode::InvalidInput)
    }

    fn normalize(
        &self,
        event: &VerifiedBillingEvent,
        fetched: &ProviderSubscription,
    ) -> Result<NormalizedEvent, ErrorCode> {
        let payload = &self.0;
        // §71.3: checkout orders omit periods; only the locked authoritative subscription supplies them.
        let fallback = if event.event_type == "checkout.completed" {
            Some(serde_json::json!({"id":transaction_source(payload)?.1,
            "period_start":fetched.current_period_start.unix_timestamp_nanos() / 1_000_000,
            "period_end":fetched.current_period_end.unix_timestamp_nanos() / 1_000_000}))
        } else {
            None
        };
        normalize(
            &serde_json::to_vec(payload).map_err(|_| ErrorCode::InvalidInput)?,
            fallback.as_ref(),
        )
    }
}

fn event_tenant(object: &Value, reversal: bool) -> Result<TenantId, ErrorCode> {
    // §71.3: Creem v1 refund/dispute metadata belongs to subscription/checkout (docs 2026-10-29).
    let subscription = &object["subscription"]["metadata"]["tenant_id"];
    let checkout = &object["checkout"]["metadata"]["tenant_id"];
    if reversal && !subscription.is_null() && !checkout.is_null() && subscription != checkout {
        return Err(ErrorCode::TenantBoundary);
    }
    let value = if reversal {
        if subscription.is_null() {
            checkout
        } else {
            subscription
        }
    } else {
        &object["metadata"]["tenant_id"]
    };
    value
        .as_str()
        .and_then(|id| Uuid::parse_str(id).ok())
        .filter(|id| !id.is_nil())
        .map(TenantId)
        .ok_or(ErrorCode::NotFound)
}
