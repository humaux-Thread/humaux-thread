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
    json!({"id":"txn_fixture","order":"ord_fixture","subscription":"sub_fixture","amount":500,"amount_paid":550,"currency":"USD","tax_amount":50,"period_start":1000,"period_end":2000})
}
fn order() -> Value {
    let mut order = transaction();
    order["id"] = json!("ord_fixture");
    order["transaction"] = json!("txn_fixture");
    order
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
    txn.as_object_mut().unwrap().remove("amount_paid");
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
    for (kind, object, payment, reference, original) in [
        (
            "checkout.completed",
            json!({"id":"ch_fixture","order":order(),"subscription":{"id":"sub_fixture"}}),
            PaymentKind::Charge,
            "txn_fixture",
            None,
        ),
        (
            "subscription.paid",
            json!({"id":"sub_fixture","last_transaction":transaction()}),
            PaymentKind::Charge,
            "txn_fixture",
            None,
        ),
        (
            "refund.created",
            json!({"id":"ref_fixture","transaction":transaction(),"refund_amount":125}),
            PaymentKind::Refund,
            "ref_fixture",
            Some("txn_fixture"),
        ),
        (
            "dispute.created",
            json!({"id":"disp_fixture","transaction":transaction(),"amount":600,"currency":"USD"}),
            PaymentKind::Chargeback,
            "disp_fixture",
            Some("txn_fixture"),
        ),
    ] {
        let actual = normalize(&event(kind, object), None).unwrap();
        assert_eq!(
            actual.provider_txn_ref.as_deref(),
            Some(reference),
            "{kind}"
        );
        assert_eq!(actual.original_txn_ref.as_deref(), original, "{kind}");
        assert_eq!(actual.id, "evt_fixture");
        assert_eq!(actual.event_type, kind);
        assert_eq!(actual.created_at, 3000);
        assert_eq!(actual.kind, EventKind::Payment(payment));
        assert_eq!(
            actual.money,
            Some(Money {
                amount: match payment {
                    PaymentKind::Charge => PaymentAmount::Charge {
                        charged_amount: 550
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
}
#[test]
fn non_payment_events_have_no_ledger_refs() {
    for kind in [
        "subscription.active",
        "subscription.expired",
        "subscription.update",
    ] {
        let actual = normalize(&event(kind, json!({"status":"active"})), None).unwrap();
        assert_eq!(
            (
                actual.kind,
                actual.money,
                actual.provider_txn_ref,
                actual.original_txn_ref
            ),
            (EventKind::SubscriptionChanged, None, None, None)
        );
    }
    for kind in [
        "credits.granted",
        "credits.consumed",
        "credits.auto_recharged",
        "customer_credits.exhausted",
        "unknown",
    ] {
        let actual = normalize(&event(kind, json!({})), None).unwrap();
        assert_eq!(
            (
                actual.kind,
                actual.money,
                actual.provider_txn_ref,
                actual.original_txn_ref
            ),
            (EventKind::Ignored, None, None, None)
        );
    }
}
#[test]
fn two_partial_refunds_have_distinct_ledger_refs() {
    let actual = [("evt_first", "ref_first", 125), ("evt_second", "ref_second", 100)]
        .map(|(event_id, refund_id, amount)| {
            let raw = serde_json::to_vec(&json!({"id":event_id,"eventType":"refund.created","created_at":3000,"object":{"id":refund_id,"transaction":transaction(),"refund_amount":amount}})).unwrap();
            let normalized = normalize(&raw, None).unwrap();
            (normalized.provider_txn_ref, normalized.original_txn_ref, normalized.money.unwrap().amount)
        });
    assert_eq!(
        actual,
        [
            (
                Some("ref_first".to_owned()),
                Some("txn_fixture".to_owned()),
                PaymentAmount::Refund {
                    refund_amount: 125,
                    original_transaction_amount: 500
                }
            ),
            (
                Some("ref_second".to_owned()),
                Some("txn_fixture".to_owned()),
                PaymentAmount::Refund {
                    refund_amount: 100,
                    original_transaction_amount: 500
                }
            ),
        ]
    );
}
#[test]
fn documented_reversal_ids_are_required() {
    for kind in ["refund.created", "dispute.created"] {
        for id in [None, Some(json!("")), Some(json!(17))] {
            let mut object = json!({"transaction":transaction(),"refund_amount":125,"amount":600,"currency":"USD"});
            if let Some(id) = id {
                object["id"] = id;
            }
            assert_eq!(
                normalize(&event(kind, object), None),
                Err(ErrorCode::InvalidInput)
            );
        }
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
            charged_amount: 550
        }
    );
    for (key, bad) in [
        ("amount_paid", json!(-1)),
        ("amount_paid", json!("500")),
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
    for key in ["amount_paid", "currency", "period_start", "period_end"] {
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
