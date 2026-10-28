//! `domain::billing` — the billing vocabularies of Baseline §71.2 and §71.3 and the pure projection from a provider's
//!   authoritative subscription status to the local subscription state (module design M04 D7, owner answer Q4).
//! Depends-on: crates=[time]; services=[]; env=[]; modules=[domain::plan]
//! Called-by: [adapters::billing_repo, application::billing, gateway::billing_webhook, gateway::bootstrap, tests]
//! Invariants: [every closed vocabulary below has one wire spelling per variant, mirrored by a CHECK of migration 0288
//!   and reconciled by contract test (§78.2); project_state is stateless: its result is a function of the observed
//!   status and the recorded facts only, never of the previous local state or of the order webhooks arrived in; no
//!   grace length, price or plan name is spelled here (§78.1): the grace period is a parameter]
//! Spec: Baseline §71.2; §71.3; §76; §78.1; §78.2
//!
//! The provider is the authority on a subscription, the webhook is only a hint that it changed (§71.3: webhooks are
//! unordered and duplicated). The processor therefore re-fetches the authoritative subscription, normalizes its status
//! into [`ObservedStatus`] (the adapter's job, M04-9) and calls [`project_state`]. Pure: no clock is read here, `now` is
//! a fact the caller passes.

use time::{Duration, OffsetDateTime};

use crate::plan::wire_enum;

wire_enum! {
    /// The local subscription state of Baseline §71.2. The wire spelling is the CHECK literal of
    /// `control.subscriptions.state` and `control.subscription_events`.
    SubscriptionState {
        /// Created, the first payment is not confirmed.
        Incomplete => "INCOMPLETE",
        /// In a trial.
        Trialing => "TRIALING",
        /// Paid up.
        Active => "ACTIVE",
        /// The renewal charge failed and the paid period has not ended yet.
        PastDue => "PAST_DUE",
        /// The renewal charge failed and the paid period has ended: the grace window before the downgrade (Q4).
        Grace => "GRACE",
        /// Paused; no payment is collected.
        Paused => "PAUSED",
        /// Paid until the period end, where it ends: a scheduled cancellation. A state, not a flag beside another state.
        CancelAtPeriodEnd => "CANCEL_AT_PERIOD_END",
        /// Ended.
        Canceled => "CANCELED",
    }
}

wire_enum! {
    /// The provider-neutral status of the authoritative subscription the adapter fetched: the input of
    /// [`project_state`] and nothing else. It has no database column; the wire spelling only names it in logs and
    /// reconciliation findings. Mapping a provider's own status strings onto it is the adapter's job (M04-9).
    ObservedStatus {
        /// Created, the first payment is not confirmed.
        Incomplete => "incomplete",
        /// In a trial.
        Trialing => "trialing",
        /// Paid up.
        Active => "active",
        /// The latest charge failed and is being retried.
        PastDue => "past_due",
        /// Retries are exhausted and the subscription is unpaid.
        Unpaid => "unpaid",
        /// Paused.
        Paused => "paused",
        /// Active, with a cancellation scheduled for the period end.
        ScheduledCancel => "scheduled_cancel",
        /// Canceled.
        Canceled => "canceled",
        /// Ran out.
        Expired => "expired",
    }
}

wire_enum! {
    /// The direction of a provider transaction in `control.billing_payments.kind`.
    PaymentKind {
        /// Money taken from the customer.
        Charge => "CHARGE",
        /// Money returned to the customer by the merchant.
        Refund => "REFUND",
        /// Money pulled back by the customer's bank.
        Chargeback => "CHARGEBACK",
    }
}

wire_enum! {
    /// The processing status of a webhook event in `control.billing_inbox.status`.
    InboxStatus {
        /// Stored by the webhook route, not yet processed.
        Received => "RECEIVED",
        /// Applied by the processor.
        Processed => "PROCESSED",
        /// The processor gave up on it.
        Failed => "FAILED",
    }
}

wire_enum! {
    /// The billing provider, a closed set of one (M04 D7: Creem only; the fake and test modes are still Creem-shaped).
    /// The wire spelling is the CHECK literal of every `provider` column of migration 0288.
    BillingProviderId {
        /// Creem.
        Creem => "creem",
    }
}

/// The recorded facts [`project_state`] reads besides the observed status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingFacts {
    /// The instant the projection is judged at; passed in, never read from a clock here.
    pub now: OffsetDateTime,
    /// The end of the paid period the subscription is in.
    pub current_period_end: OffsetDateTime,
    /// How long a failed renewal keeps the paid entitlement after the period end (owner answer Q4 names 7 days; the
    /// configured value lives in M04-12's plan configuration, never in this crate, §78.1).
    pub grace: Duration,
    /// A REFUND or CHARGEBACK is recorded for the current period.
    pub reversed: bool,
}

/// The local state a subscription is in, given what the provider says it is and what is recorded.
///
/// Stateless on purpose: no previous local state is an input, so the result depends only on the authoritative fetch and
/// the recorded facts and a reordered or duplicated webhook cannot change it (§71.3). Precedence, first match wins:
///
/// 1. a reversed payment is `Canceled` at once (owner answer Q4: refund or chargeback is an immediate downgrade);
/// 2. `Canceled` and `Expired` are `Canceled`;
/// 3. `PastDue` and `Unpaid` are `PastDue` until the period ends, `Grace` for [`BillingFacts::grace`] after it, then
///    `Canceled` (Q4: grace, then Free);
/// 4. every other status maps to its own state.
pub fn project_state(observed: ObservedStatus, facts: &BillingFacts) -> SubscriptionState {
    if facts.reversed {
        return SubscriptionState::Canceled;
    }
    match observed {
        ObservedStatus::Canceled | ObservedStatus::Expired => SubscriptionState::Canceled,
        ObservedStatus::PastDue | ObservedStatus::Unpaid => dunning_state(facts),
        ObservedStatus::Paused => SubscriptionState::Paused,
        ObservedStatus::ScheduledCancel => SubscriptionState::CancelAtPeriodEnd,
        ObservedStatus::Trialing => SubscriptionState::Trialing,
        ObservedStatus::Incomplete => SubscriptionState::Incomplete,
        ObservedStatus::Active => SubscriptionState::Active,
    }
}

/// Rule 3 of [`project_state`]: where a failed renewal stands on the clock.
fn dunning_state(facts: &BillingFacts) -> SubscriptionState {
    if facts.now < facts.current_period_end {
        return SubscriptionState::PastDue;
    }
    // ponytail: grace runs from the period end (a renewal failure); a mid-period charge failure has no own clock — add payment_failed_at when M04-11 sees one.
    // An end that cannot be represented counts as elapsed: the entitlement fails closed.
    let in_grace = facts
        .current_period_end
        .checked_add(facts.grace)
        .is_some_and(|grace_end| facts.now < grace_end);
    if in_grace {
        SubscriptionState::Grace
    } else {
        SubscriptionState::Canceled
    }
}

/// Whether a subscription in `state` still carries the paid plan's entitlements (owner answer Q4: after the grace the
/// tenant is on Free). Exhaustive without a wildcard, so a new state forces a decision here.
// ponytail: Paused keeps no paid scope (no payment, no paid scope) — a lead interpretation of Q4, owner-revisable here.
pub const fn keeps_paid_entitlement(state: SubscriptionState) -> bool {
    match state {
        SubscriptionState::Active
        | SubscriptionState::Trialing
        | SubscriptionState::PastDue
        | SubscriptionState::Grace
        | SubscriptionState::CancelAtPeriodEnd => true,
        SubscriptionState::Incomplete | SubscriptionState::Paused | SubscriptionState::Canceled => {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ObservedStatus as O, SubscriptionState as S, *};

    const PERIOD_END: i64 = 1_000_000;
    /// A test value standing in for the configured grace (the owner's 7 days, in seconds).
    const GRACE: i64 = 604_800;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds)
    }

    fn facts(now: i64, reversed: bool) -> BillingFacts {
        BillingFacts {
            now: at(now),
            current_period_end: at(PERIOD_END),
            grace: Duration::seconds(GRACE),
            reversed,
        }
    }

    fn wires<T: Copy>(all: &[T], wire: impl Fn(T) -> &'static str) -> Vec<&'static str> {
        all.iter().map(|variant| wire(*variant)).collect()
    }

    /// The vocabularies spell exactly the literals migration 0288's CHECKs spell, in the §71.2 order, and a spelling
    /// parses back to its own variant only. Fault: change one wire literal ⇒ the exact list differs ⇒ red.
    #[test]
    fn the_closed_vocabularies_have_exactly_these_wire_spellings() {
        assert_eq!(
            wires(&S::ALL, S::wire),
            [
                "INCOMPLETE",
                "TRIALING",
                "ACTIVE",
                "PAST_DUE",
                "GRACE",
                "PAUSED",
                "CANCEL_AT_PERIOD_END",
                "CANCELED"
            ]
        );
        assert_eq!(
            wires(&PaymentKind::ALL, PaymentKind::wire),
            ["CHARGE", "REFUND", "CHARGEBACK"]
        );
        assert_eq!(
            wires(&InboxStatus::ALL, InboxStatus::wire),
            ["RECEIVED", "PROCESSED", "FAILED"]
        );
        assert_eq!(
            wires(&BillingProviderId::ALL, BillingProviderId::wire),
            ["creem"]
        );
        assert_eq!(ObservedStatus::ALL.len(), 9);
        for state in S::ALL {
            assert_eq!(S::parse_wire(state.wire()), Some(state));
        }
        assert_eq!(S::parse_wire("grace"), None);
        assert_eq!(S::parse_wire("SUSPENDED"), None);
        assert_eq!(BillingProviderId::parse_wire("stripe"), None);
    }

    /// Away from the dunning clock every observed status maps to its own state; the table lists each status once.
    #[test]
    fn each_observed_status_maps_by_the_precedence_table() {
        let table = [
            (O::Incomplete, S::Incomplete),
            (O::Trialing, S::Trialing),
            (O::Active, S::Active),
            (O::PastDue, S::PastDue),
            (O::Unpaid, S::PastDue),
            (O::Paused, S::Paused),
            (O::ScheduledCancel, S::CancelAtPeriodEnd),
            (O::Canceled, S::Canceled),
            (O::Expired, S::Canceled),
        ];
        assert_eq!(table.map(|(observed, _)| observed), ObservedStatus::ALL);
        for (observed, want) in table {
            assert_eq!(
                project_state(observed, &facts(PERIOD_END - 100, false)),
                want,
                "{observed:?}"
            );
        }
    }

    /// Q4: a recorded REFUND or CHARGEBACK is an immediate downgrade, whatever the provider still reports and whatever
    /// the clock says. Fault: a projection that ignores `reversed` ⇒ Active stays Active ⇒ red.
    #[test]
    fn a_reversed_payment_cancels_every_observed_status_at_once() {
        for observed in ObservedStatus::ALL {
            for now in [PERIOD_END - 100, PERIOD_END, PERIOD_END + GRACE + 100] {
                assert_eq!(
                    project_state(observed, &facts(now, true)),
                    S::Canceled,
                    "{observed:?} at {now}"
                );
            }
        }
    }

    /// Q4: a failed renewal is PastDue until the period ends, in Grace for the grace length after it, then Canceled; the
    /// four instants around the two boundaries decide each side.
    #[test]
    fn the_dunning_clock_has_exact_boundaries() {
        for observed in [O::PastDue, O::Unpaid] {
            for (now, want) in [
                (PERIOD_END - 1, S::PastDue),
                (PERIOD_END, S::Grace),
                (PERIOD_END + GRACE - 1, S::Grace),
                (PERIOD_END + GRACE, S::Canceled),
            ] {
                assert_eq!(
                    project_state(observed, &facts(now, false)),
                    want,
                    "{observed:?} at {now}"
                );
            }
        }
    }

    /// Only the two dunning statuses read the clock, and a grace whose end cannot be represented counts as elapsed.
    #[test]
    fn only_dunning_reads_the_clock_and_an_unrepresentable_grace_fails_closed() {
        let late = facts(PERIOD_END + GRACE + 100, false);
        assert_eq!(project_state(O::Active, &late), S::Active);
        assert_eq!(project_state(O::Paused, &late), S::Paused);
        assert_eq!(
            project_state(O::ScheduledCancel, &late),
            S::CancelAtPeriodEnd
        );

        let endless = BillingFacts {
            grace: Duration::MAX,
            ..facts(PERIOD_END + 1, false)
        };
        assert_eq!(project_state(O::PastDue, &endless), S::Canceled);
    }

    /// Q4 "then Free": the five paying or paid-through states keep the paid entitlement, the three others do not.
    /// PAUSED → false is a lead interpretation, pinned here so a change is a visible diff.
    #[test]
    fn keeps_paid_entitlement_is_decided_for_all_eight_states() {
        let want = [
            (S::Incomplete, false),
            (S::Trialing, true),
            (S::Active, true),
            (S::PastDue, true),
            (S::Grace, true),
            (S::Paused, false),
            (S::CancelAtPeriodEnd, true),
            (S::Canceled, false),
        ];
        assert_eq!(want.map(|(state, _)| state), S::ALL);
        for (state, keeps) in want {
            assert_eq!(keeps_paid_entitlement(state), keeps, "{state:?}");
        }
    }
}
