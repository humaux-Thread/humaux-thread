//! `domain::plan` — the plan catalogue shapes of §71.1: the closed vocabularies and the validated plan-version spec that a
//!   values file seeds into `control.plan_versions` (module design M04 D2).
//! Depends-on: crates=[]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::plan_repo, tests]
//! Invariants: [every closed vocabulary below has one wire spelling per variant, mirrored by a CHECK of migration 0262 and
//!   reconciled by contract test (§78.2); no plan name, price, limit or block size is spelled here (§78.1): a value
//!   arrives from the values file and is only validated for shape; a spec that fails validation is never built]
//! Spec: Baseline §71.1; §78.1; §78.2
//!
//! A plan is a set of entitlements, not a name the code branches on (§71.1): the template maps a closed set of
//! [`EntitlementKey`]s to values, and `control.plan_versions` pins one template per version so an old subscription keeps
//! its terms. This module is pure: parsing a values file is `adapters::plan_repo`'s job, and the writer is the owner door
//! `control.publish_plan_version`.

use std::collections::BTreeMap;
use std::fmt;

/// A closed wire vocabulary (§78.2): the enum, `ALL`, `wire` and `parse_wire` come from one list, so they cannot drift
/// from each other. The DB side is a CHECK in migration 0262, compared against `ALL` by contract test.
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $($(#[$vmeta:meta])* $variant:ident => $wire:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: [$name; { [$(stringify!($variant)),+].len() }] = [$($name::$variant,)+];

            /// The wire spelling: the CHECK literal in the database and the key or value in the values file.
            pub const fn wire(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                }
            }

            /// The variant spelled `wire`; any other text is `None`, never a default (fail closed).
            pub fn parse_wire(wire: &str) -> Option<Self> {
                Self::ALL.into_iter().find(|variant| variant.wire() == wire)
            }
        }
    };
}

wire_enum! {
    /// The currency a plan price is stated in. USD only: the owner priced in USD (2026-10-15).
    // ponytail: one currency, because the owner decided USD; widen the CHECK in a new migration when a second is decided
    // (the payment provider also prices in EUR, R4).
    Currency {
        /// US dollars.
        Usd => "USD",
    }
}

wire_enum! {
    /// How often a plan's price is charged. An annual plan is its own plan key at its own price; its quota windows stay
    /// monthly (M04 D10).
    BillingInterval {
        /// Charged every month.
        Month => "month",
        /// Charged every year.
        Year => "year",
    }
}

wire_enum! {
    /// The billing-provider mode a product reference belongs to (M04 D8). `Live` is spelled here so a production values
    /// file can carry it; no committed values file does.
    ProviderMode {
        /// The in-repo provider double.
        Fake => "fake",
        /// The provider's test mode.
        Test => "test",
        /// The provider's live mode: owner-only.
        Live => "live",
    }
}

wire_enum! {
    /// How a per-period quota window is cut, as `control.issue_quota_window` validates it.
    QuotaPeriod {
        /// A calendar month.
        CalendarMonth => "calendar_month",
        /// The subscription's own period.
        SubscriptionPeriod => "subscription_period",
    }
}

wire_enum! {
    /// Which calls a quota window charges, as `control.issue_quota_window` validates it.
    ChargePolicy {
        /// Only successful operations.
        SuccessOnly => "success_only",
        /// Every completed business call.
        CompletedBusinessCalls => "completed_business_calls",
    }
}

wire_enum! {
    /// The closed set of keys an entitlement template may carry (§76: the projector turns them into the snapshot's
    /// `effective` object). A key a plan lacks is absent, which means no entitlement.
    EntitlementKey {
        /// The renewed per-period operation quota (M04 D4).
        PerPeriod => "mcp.billable_operations.per_period",
        /// The credit window: packs, the one-time starter, the upgrade delta (M04 D4).
        Credit => "mcp.billable_operations.credit",
        /// The emergency window, spendable only by relay-critical operations (M04 D4).
        Emergency => "mcp.billable_operations.emergency",
        /// The retained-bytes allowance (owner Q2: the mechanism now, the numbers after R11).
        StorageRetainedBytes => "storage.retained_bytes",
        /// The cloud-intelligence capability.
        CloudIntelligence => "feature.cloud_intelligence",
        /// The bring-your-own-key capability.
        Byok => "feature.byok",
    }
}

/// A plan catalogue value that fails validation, naming the offending field. It is a build-time and seed-time report, not
/// a §52 request classification (the precedent is `contracts::feature_registry::FeatureRegistryError`), so it is not a
/// third error enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSpecError(pub String);

impl fmt::Display for PlanSpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlanSpecError {}

/// One template entry's value, in the shape its key demands ([`EntitlementKey::accepts`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateValue {
    /// The shape of [`EntitlementKey::PerPeriod`]: the renewed window `control.issue_quota_window` reads.
    PeriodQuota {
        /// Operations the window admits.
        limit: u64,
        /// How the window is cut.
        period: QuotaPeriod,
        /// Which calls it charges.
        charge_policy: ChargePolicy,
    },
    /// The shape of the non-renewing allowances: [`EntitlementKey::Credit`], [`EntitlementKey::Emergency`] and
    /// [`EntitlementKey::StorageRetainedBytes`].
    Allowance {
        /// Units the allowance admits.
        limit: u64,
    },
    /// The shape of the capabilities: on. A capability a plan lacks is absent from the template.
    Flag,
}

impl TemplateValue {
    /// The number this value carries, if it carries one.
    fn limit(&self) -> Option<u64> {
        match self {
            Self::PeriodQuota { limit, .. } | Self::Allowance { limit } => Some(*limit),
            Self::Flag => None,
        }
    }
}

impl EntitlementKey {
    /// Whether `value` has the shape this key demands.
    pub fn accepts(self, value: &TemplateValue) -> bool {
        matches!(
            (self, value),
            (Self::PerPeriod, TemplateValue::PeriodQuota { .. })
                | (
                    Self::Credit | Self::Emergency | Self::StorageRetainedBytes,
                    TemplateValue::Allowance { .. }
                )
                | (Self::CloudIntelligence | Self::Byok, TemplateValue::Flag)
        )
    }
}

/// A plan version's entitlement template: closed keys, each with the value shape it demands, none twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementTemplate(BTreeMap<EntitlementKey, TemplateValue>);

impl EntitlementTemplate {
    /// Builds a template, refusing a value whose shape the key does not accept, a number above `i64::MAX` (the quota
    /// windows count in `bigint`), and a key given twice.
    pub fn new(
        entries: impl IntoIterator<Item = (EntitlementKey, TemplateValue)>,
    ) -> Result<Self, PlanSpecError> {
        let mut map = BTreeMap::new();
        for (key, value) in entries {
            if !key.accepts(&value) {
                return Err(PlanSpecError(format!(
                    "template key {}: the value does not have the shape this key demands",
                    key.wire()
                )));
            }
            if value.limit().is_some_and(|n| i64::try_from(n).is_err()) {
                return Err(PlanSpecError(format!(
                    "template key {}: the limit exceeds the bigint range of the quota windows",
                    key.wire()
                )));
            }
            if map.insert(key, value).is_some() {
                return Err(PlanSpecError(format!(
                    "template key {} is given twice",
                    key.wire()
                )));
            }
        }
        Ok(Self(map))
    }

    /// The entries, ordered by key.
    pub fn entries(&self) -> impl Iterator<Item = (EntitlementKey, &TemplateValue)> {
        self.0.iter().map(|(key, value)| (*key, value))
    }
}

/// A plan identifier as the catalogue spells it: lowercase ASCII letters, digits and `_`, starting with a letter, at most
/// [`PlanKey::MAX_LEN`] bytes (the `control.plans` CHECK). It names a sellable plan and nothing branches on it (§71.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlanKey(String);

impl PlanKey {
    /// The longest plan key, in bytes.
    pub const MAX_LEN: usize = 32;

    /// Validates `text` as a plan key.
    pub fn parse(text: &str) -> Result<Self, PlanSpecError> {
        let mut chars = text.chars();
        let starts_with_letter = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if starts_with_letter && rest_ok && text.len() <= Self::MAX_LEN {
            Ok(Self(text.to_owned()))
        } else {
            Err(PlanSpecError(format!(
                "plan key {text:?}: want a lowercase letter, then lowercase letters, digits or _, at most {} bytes",
                Self::MAX_LEN
            )))
        }
    }

    /// The key as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The fields of one plan version before validation, as a values file states them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanVersionParts {
    /// The plan this is a version of.
    pub plan_key: String,
    /// The version number within the plan, from 1.
    pub version: i32,
    /// The price in the smallest currency unit; 0 is a free plan.
    pub price_cents: i64,
    /// The currency of the price.
    pub currency: Currency,
    /// How often the price is charged.
    pub billing_interval: BillingInterval,
    /// What the version entitles.
    pub entitlement_template: EntitlementTemplate,
    /// Operation slots a gateway claims per block (M04 D5), from 1.
    pub lease_block: i32,
    /// The billing provider's product reference per mode.
    pub provider_product_ref: BTreeMap<ProviderMode, String>,
    /// Whether the version is offered; `false` is a draft.
    pub published: bool,
}

/// One validated plan version: the only value `adapters::plan_repo` seeds from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanVersionSpec {
    plan_key: PlanKey,
    parts: PlanVersionParts,
}

/// The longest provider product reference, in bytes.
const MAX_PRODUCT_REF_LEN: usize = 128;

impl PlanVersionSpec {
    /// Validates `parts`: a plan key of the allowed shape, a version and a lease block of at least 1, a price of at least
    /// 0, and provider references that are non-empty printable ASCII without whitespace.
    pub fn new(parts: PlanVersionParts) -> Result<Self, PlanSpecError> {
        let plan_key = PlanKey::parse(&parts.plan_key)?;
        let at = |field: &str, problem: &str| {
            PlanSpecError(format!(
                "plan {} version {}: {field} {problem}",
                plan_key.as_str(),
                parts.version
            ))
        };
        if parts.version < 1 {
            return Err(at("version", "must be at least 1"));
        }
        if parts.price_cents < 0 {
            return Err(at("price_cents", "must not be negative"));
        }
        if parts.lease_block < 1 {
            return Err(at("lease_block", "must be at least 1"));
        }
        for (mode, reference) in &parts.provider_product_ref {
            let printable = reference.bytes().all(|b| b.is_ascii_graphic());
            if reference.is_empty() || reference.len() > MAX_PRODUCT_REF_LEN || !printable {
                return Err(at(
                    "provider_product_ref",
                    &format!(
                        "{} reference must be 1 to {MAX_PRODUCT_REF_LEN} printable ASCII bytes",
                        mode.wire()
                    ),
                ));
            }
        }
        Ok(Self { plan_key, parts })
    }

    /// The plan this is a version of.
    pub fn plan_key(&self) -> &PlanKey {
        &self.plan_key
    }

    /// The version number within the plan.
    pub fn version(&self) -> i32 {
        self.parts.version
    }

    /// The price in the smallest currency unit.
    pub fn price_cents(&self) -> i64 {
        self.parts.price_cents
    }

    /// The currency of the price.
    pub fn currency(&self) -> Currency {
        self.parts.currency
    }

    /// How often the price is charged.
    pub fn billing_interval(&self) -> BillingInterval {
        self.parts.billing_interval
    }

    /// What the version entitles.
    pub fn entitlement_template(&self) -> &EntitlementTemplate {
        &self.parts.entitlement_template
    }

    /// Operation slots a gateway claims per block.
    pub fn lease_block(&self) -> i32 {
        self.parts.lease_block
    }

    /// The billing provider's product reference per mode.
    pub fn provider_product_ref(&self) -> &BTreeMap<ProviderMode, String> {
        &self.parts.provider_product_ref
    }

    /// Whether the version is offered; `false` is a draft.
    pub fn published(&self) -> bool {
        self.parts.published
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(limit: u64) -> TemplateValue {
        TemplateValue::PeriodQuota {
            limit,
            period: QuotaPeriod::SubscriptionPeriod,
            charge_policy: ChargePolicy::SuccessOnly,
        }
    }

    fn parts() -> PlanVersionParts {
        PlanVersionParts {
            plan_key: "tier_a".to_owned(),
            version: 1,
            price_cents: 0,
            currency: Currency::Usd,
            billing_interval: BillingInterval::Month,
            entitlement_template: EntitlementTemplate::new([(EntitlementKey::PerPeriod, quota(7))])
                .unwrap(),
            lease_block: 4,
            provider_product_ref: BTreeMap::new(),
            published: false,
        }
    }

    fn wires<T: Copy>(all: &[T], wire: impl Fn(T) -> &'static str) -> Vec<&'static str> {
        all.iter().map(|variant| wire(*variant)).collect()
    }

    /// Every vocabulary spells exactly the literals the migration's CHECKs spell, and a spelling parses back to its own
    /// variant. Fault: change one wire literal ⇒ the exact list differs ⇒ red.
    #[test]
    fn the_closed_vocabularies_have_exactly_these_wire_spellings() {
        assert_eq!(wires(&Currency::ALL, Currency::wire), ["USD"]);
        assert_eq!(
            wires(&BillingInterval::ALL, BillingInterval::wire),
            ["month", "year"]
        );
        assert_eq!(
            wires(&ProviderMode::ALL, ProviderMode::wire),
            ["fake", "test", "live"]
        );
        assert_eq!(
            wires(&QuotaPeriod::ALL, QuotaPeriod::wire),
            ["calendar_month", "subscription_period"]
        );
        assert_eq!(
            wires(&ChargePolicy::ALL, ChargePolicy::wire),
            ["success_only", "completed_business_calls"]
        );
        assert_eq!(
            wires(&EntitlementKey::ALL, EntitlementKey::wire),
            [
                "mcp.billable_operations.per_period",
                "mcp.billable_operations.credit",
                "mcp.billable_operations.emergency",
                "storage.retained_bytes",
                "feature.cloud_intelligence",
                "feature.byok",
            ]
        );
        for key in EntitlementKey::ALL {
            assert_eq!(EntitlementKey::parse_wire(key.wire()), Some(key));
        }
        assert_eq!(EntitlementKey::parse_wire("feature.other"), None);
        assert_eq!(BillingInterval::parse_wire("Month"), None);
        assert_eq!(Currency::parse_wire("usd"), None);
    }

    /// Each key accepts exactly one value shape.
    #[test]
    fn each_key_accepts_exactly_its_own_value_shape() {
        let shapes = [
            quota(1),
            TemplateValue::Allowance { limit: 1 },
            TemplateValue::Flag,
        ];
        let accepted: Vec<(EntitlementKey, usize)> = EntitlementKey::ALL
            .into_iter()
            .map(|key| {
                let hits: Vec<usize> = (0..shapes.len())
                    .filter(|i| key.accepts(&shapes[*i]))
                    .collect();
                assert_eq!(
                    hits.len(),
                    1,
                    "{} must accept exactly one shape",
                    key.wire()
                );
                (key, hits[0])
            })
            .collect();
        assert_eq!(
            accepted,
            [
                (EntitlementKey::PerPeriod, 0),
                (EntitlementKey::Credit, 1),
                (EntitlementKey::Emergency, 1),
                (EntitlementKey::StorageRetainedBytes, 1),
                (EntitlementKey::CloudIntelligence, 2),
                (EntitlementKey::Byok, 2),
            ]
        );
    }

    /// A template refuses a mismatched shape, a duplicate key and a number past `i64::MAX`, and accepts one that fits.
    #[test]
    fn a_template_refuses_a_wrong_shape_a_duplicate_and_an_oversized_limit() {
        let wrong = EntitlementTemplate::new([(EntitlementKey::Byok, quota(1))]).unwrap_err();
        assert!(wrong.0.contains("feature.byok"), "{wrong}");
        let twice = EntitlementTemplate::new([
            (
                EntitlementKey::Credit,
                TemplateValue::Allowance { limit: 1 },
            ),
            (
                EntitlementKey::Credit,
                TemplateValue::Allowance { limit: 2 },
            ),
        ])
        .unwrap_err();
        assert!(twice.0.contains("given twice"), "{twice}");
        let huge = EntitlementTemplate::new([(
            EntitlementKey::Emergency,
            TemplateValue::Allowance { limit: u64::MAX },
        )])
        .unwrap_err();
        assert!(huge.0.contains("bigint"), "{huge}");
        let edge = i64::MAX.unsigned_abs();
        let fits = EntitlementTemplate::new([(
            EntitlementKey::Emergency,
            TemplateValue::Allowance { limit: edge },
        )])
        .unwrap();
        assert_eq!(fits.entries().count(), 1);
    }

    /// The plan key shape is the `control.plans` CHECK: `^[a-z][a-z0-9_]{0,31}$`.
    #[test]
    fn a_plan_key_is_lowercase_letter_then_lowercase_digits_or_underscore_up_to_32_bytes() {
        let longest = format!("a{}", "b".repeat(PlanKey::MAX_LEN - 1));
        let too_long = format!("a{}", "b".repeat(PlanKey::MAX_LEN));
        for ok in ["a", "tier_a", "tier_2", "a_", longest.as_str()] {
            assert_eq!(PlanKey::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "",
            "Tier",
            "2tier",
            "_tier",
            "tier-a",
            "tier a",
            "tièr",
            too_long.as_str(),
        ] {
            assert!(PlanKey::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// Validation refuses each out-of-range field by name and accepts the free plan (price 0).
    #[test]
    fn a_spec_refuses_each_out_of_range_field_by_name() {
        assert_eq!(PlanVersionSpec::new(parts()).unwrap().price_cents(), 0);
        let cases = [
            (
                "version",
                PlanVersionParts {
                    version: 0,
                    ..parts()
                },
            ),
            (
                "price_cents",
                PlanVersionParts {
                    price_cents: -1,
                    ..parts()
                },
            ),
            (
                "lease_block",
                PlanVersionParts {
                    lease_block: 0,
                    ..parts()
                },
            ),
        ];
        for (field, bad) in cases {
            let error = PlanVersionSpec::new(bad).unwrap_err();
            assert!(error.0.contains(field), "{field}: {error}");
        }
        for reference in ["", "has space", "tab\there", "naïve"] {
            let bad = PlanVersionParts {
                provider_product_ref: BTreeMap::from([(ProviderMode::Fake, reference.to_owned())]),
                ..parts()
            };
            let error = PlanVersionSpec::new(bad).unwrap_err();
            assert!(
                error.0.contains("provider_product_ref"),
                "{reference:?}: {error}"
            );
        }
        let long = PlanVersionParts {
            provider_product_ref: BTreeMap::from([(
                ProviderMode::Test,
                "x".repeat(MAX_PRODUCT_REF_LEN + 1),
            )]),
            ..parts()
        };
        assert!(PlanVersionSpec::new(long).is_err());
        let bad_key = PlanVersionParts {
            plan_key: "Bad".to_owned(),
            ..parts()
        };
        assert!(PlanVersionSpec::new(bad_key).is_err());
    }
}
