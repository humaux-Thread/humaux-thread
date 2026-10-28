//! `billing-worker::tests::normalization` — money and event contracts (§71.3).
//! Depends-on: crates=[humaux-domain, serde_json]; services=[]; env=[]; modules=[billing-worker::normalize, domain::billing, domain::error, domain::plan]
//! Called-by: [cargo-test]
//! Invariants: [exact event/status sets; missing money rejected; no external calls]
//! Spec: Baseline §71.2; §71.3; §79.5
use humaux_billing_worker::normalize::{EventKind, Money, PaymentAmount, normalize, status};
use humaux_domain::{
    billing::{ObservedStatus, PaymentKind},
    error::ErrorCode,
    plan::Currency,
};
use serde_json::{Value, json};

fn transaction() -> Value {
    json!({"id":"txn_fixture","transaction":"txn_fixture","amount":500,"currency":"USD","tax_amount":50,"period_start":1000,"period_end":2000})
}
fn event(kind: &str, object: Value) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"id":"evt_fixture","eventType":kind,"created_at":3000,"object":object}),
    )
    .unwrap()
}
#[test]
fn missing_amount_is_refused() {
    let mut txn = transaction();
    txn.as_object_mut().unwrap().remove("amount");
    assert_eq!(
        normalize(
            &event("subscription.paid", json!({"last_transaction":txn})),
            None
        ),
        Err(ErrorCode::InvalidInput)
    );
}
#[test]
fn exact_events_and_payload_money() {
    for (kind, object, payment) in [
        (
            "checkout.completed",
            json!({"order":transaction()}),
            PaymentKind::Charge,
        ),
        (
            "subscription.paid",
            json!({"last_transaction":transaction()}),
            PaymentKind::Charge,
        ),
        (
            "refund.created",
            json!({"transaction":transaction(),"refund_amount":125}),
            PaymentKind::Refund,
        ),
        (
            "dispute.created",
            json!({"transaction":transaction(),"amount":600,"currency":"USD"}),
            PaymentKind::Chargeback,
        ),
    ] {
        let actual = normalize(&event(kind, object), None).unwrap();
        assert_eq!(actual.provider_txn_ref.as_deref(), Some("txn_fixture"));
        assert_eq!(actual.id, "evt_fixture");
        assert_eq!(actual.event_type, kind);
        assert_eq!(actual.created_at, 3000);
        assert_eq!(actual.kind, EventKind::Payment(payment));
        assert_eq!(
            actual.money,
            Some(Money {
                amount: match payment {
                    PaymentKind::Charge => PaymentAmount::Charge {
                        charged_amount: 500
                    },
                    PaymentKind::Refund => PaymentAmount::Refund {
                        refund_amount: 125,
                        original_transaction_amount: 500
                    },
                    PaymentKind::Chargeback => PaymentAmount::Chargeback {
                        disputed_amount: 600
                    },
                },
                currency: Currency::Usd,
                tax_amount: Some(50),
                period_start: 1000,
                period_end: 2000
            })
        );
    }
    for kind in [
        "subscription.active",
        "subscription.expired",
        "subscription.update",
    ] {
        let actual = normalize(&event(kind, json!({"status":"active"})), None).unwrap();
        assert_eq!(
            (actual.kind, actual.money),
            (EventKind::SubscriptionChanged, None)
        );
    }
    for kind in [
        "credits.granted",
        "credits.consumed",
        "credits.auto_recharged",
        "customer_credits.exhausted",
        "unknown",
    ] {
        assert_eq!(
            normalize(&event(kind, json!({})), None).unwrap().kind,
            EventKind::Ignored
        );
    }
}
#[test]
fn fetched_status_and_money_fail_closed() {
    let names = [
        "incomplete",
        "trialing",
        "active",
        "past_due",
        "unpaid",
        "paused",
        "scheduled_cancel",
        "canceled",
        "expired",
    ];
    assert_eq!(
        names.map(|name| status(name).unwrap()),
        [
            ObservedStatus::Incomplete,
            ObservedStatus::Trialing,
            ObservedStatus::Active,
            ObservedStatus::PastDue,
            ObservedStatus::Unpaid,
            ObservedStatus::Paused,
            ObservedStatus::ScheduledCancel,
            ObservedStatus::Canceled,
            ObservedStatus::Expired,
        ]
    );
    for name in ["unknown", "ACTIVE", ""] {
        assert_eq!(status(name), Err(ErrorCode::InvalidInput));
    }
    assert_eq!(
        normalize(
            &event(
                "subscription.paid",
                json!({"last_transaction":{"id":"txn_fixture"}})
            ),
            Some(&transaction())
        )
        .unwrap()
        .money
        .unwrap()
        .amount,
        PaymentAmount::Charge {
            charged_amount: 500
        }
    );
    for (key, bad) in [
        ("amount", json!(-1)),
        ("amount", json!("500")),
        ("currency", json!("EUR")),
        ("period_end", json!(1000)),
        ("tax_amount", json!(-1)),
    ] {
        let mut txn = transaction();
        txn[key] = bad;
        assert_eq!(
            normalize(
                &event("subscription.paid", json!({"last_transaction":txn})),
                None
            ),
            Err(ErrorCode::InvalidInput)
        );
    }
    for key in ["amount", "currency", "period_start", "period_end"] {
        let mut txn = transaction();
        txn.as_object_mut().unwrap().remove(key);
        assert_eq!(
            normalize(
                &event("subscription.paid", json!({"last_transaction":txn})),
                None
            ),
            Err(ErrorCode::InvalidInput)
        );
    }
    assert_eq!(
        normalize(
            &event("refund.created", json!({"transaction":transaction()})),
            None
        ),
        Err(ErrorCode::InvalidInput)
    );
    for body in [b"{}".as_slice(), b"invalid"] {
        assert_eq!(normalize(body, None), Err(ErrorCode::InvalidInput));
    }
}

#[test]
fn transaction_identity_and_dispute_amount_are_required() {
    let raw = event(
        "subscription.paid",
        json!({"last_transaction":transaction()}),
    );
    let mut wrong = transaction();
    wrong["id"] = json!("different");
    assert_eq!(normalize(&raw, Some(&wrong)), Err(ErrorCode::InvalidInput));
    for kind in [
        "checkout.completed",
        "subscription.paid",
        "refund.created",
        "dispute.created",
    ] {
        assert_eq!(
            normalize(&event(kind, json!({})), Some(&transaction())),
            Err(ErrorCode::InvalidInput)
        );
    }
    let raw = event(
        "dispute.created",
        json!({"transaction":transaction(),"currency":"USD"}),
    );
    for fetched in [None, Some(transaction())] {
        assert_eq!(
            normalize(&raw, fetched.as_ref()),
            Err(ErrorCode::InvalidInput)
        );
    }
}
