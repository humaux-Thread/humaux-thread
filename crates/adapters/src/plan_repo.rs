//! `adapters::plan_repo` — reads a plan values file into validated plan-version specs and seeds them into the plan
//!   catalogue through the one owner door `control.publish_plan_version` (module design M04 D2, card M04-1).
//! Depends-on: crates=[humaux-domain, serde, serde_json, sqlx]; services=[PostgreSQL(role_maintenance)
//!   x=[control.publish_plan_version]]; env=[]; modules=[adapters::postgres, domain::error, domain::plan]
//! Called-by: [tests]
//! Invariants: [the door is the only writer of the catalogue and only role_maintenance can call it; the whole file is
//!   seeded in one transaction, so a refused version leaves none behind; a version that is already stored is verified
//!   against the file, never rewritten: any difference in price, currency, interval, template or lease block is
//!   Conflict; the file is read with unknown fields refused and every enum, number and key checked by domain::plan
//!   before any SQL runs; no price, limit, plan name or block size is spelled here (§78.1)]
//! Spec: Baseline §71.1; §78.1; §78.2
//!
//! The values file is JSON (`deploy/plans/plan_catalogue.json` is the committed placeholder; the production file is the
//! owner's and lives outside the repository). Which process reads the file and calls [`seed`] is a later card's wiring;
//! this module only turns text into specs and specs into door calls.

use std::collections::{BTreeMap, BTreeSet};

use humaux_domain::error::ErrorCode;
use humaux_domain::plan::{
    BillingInterval, ChargePolicy, Currency, EntitlementKey, EntitlementTemplate, PlanSpecError,
    PlanVersionParts, PlanVersionSpec, ProviderMode, QuotaPeriod, TemplateValue,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::Row;

use crate::postgres::MaintenanceDbPool;

/// The values file as written. Unknown fields are refused so a misspelled key cannot silently drop a limit.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalogue {
    /// Free text for the reader of the file; never interpreted.
    #[serde(rename = "note", default)]
    _note: Option<String>,
    plan_versions: Vec<RawVersion>,
}

/// One plan version as the file spells it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVersion {
    plan_key: String,
    version: i32,
    price_cents: i64,
    currency: String,
    billing_interval: String,
    lease_block: i32,
    published: bool,
    entitlement_template: BTreeMap<String, Value>,
    #[serde(default)]
    provider_product_ref: BTreeMap<String, String>,
}

/// The value of [`EntitlementKey::PerPeriod`] as the file spells it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeriodQuota {
    limit: u64,
    period: String,
    charge_policy: String,
}

/// The value of an allowance key as the file spells it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowance {
    limit: u64,
}

/// What one [`seed`] call did, in plan versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeedReport {
    /// Versions the door inserted.
    pub created: usize,
    /// Versions that were already stored and matched the file (a repeat call may still have published a draft or
    /// replaced the provider mapping).
    pub existing: usize,
}

fn db_error(error: sqlx::Error) -> ErrorCode {
    match error {
        sqlx::Error::RowNotFound => ErrorCode::NotFound,
        sqlx::Error::Database(ref db) => match db.code().as_deref() {
            Some("42501") => ErrorCode::Forbidden,
            Some("23505" | "40001" | "40P01" | "55P03") => ErrorCode::Conflict,
            Some("22023" | "22P02" | "22003" | "23514") => ErrorCode::InvalidInput,
            _ => ErrorCode::Internal,
        },
        _ => ErrorCode::DependencyUnavailable,
    }
}

fn template_value(key: EntitlementKey, raw: &Value) -> Result<TemplateValue, PlanSpecError> {
    let bad =
        |error: serde_json::Error| PlanSpecError(format!("template key {}: {error}", key.wire()));
    match key {
        EntitlementKey::PerPeriod => {
            let quota: RawPeriodQuota = serde_json::from_value(raw.clone()).map_err(bad)?;
            let period = QuotaPeriod::parse_wire(&quota.period).ok_or_else(|| {
                PlanSpecError(format!(
                    "template key {}: unknown period {:?}",
                    key.wire(),
                    quota.period
                ))
            })?;
            let charge_policy =
                ChargePolicy::parse_wire(&quota.charge_policy).ok_or_else(|| {
                    PlanSpecError(format!(
                        "template key {}: unknown charge_policy {:?}",
                        key.wire(),
                        quota.charge_policy
                    ))
                })?;
            Ok(TemplateValue::PeriodQuota {
                limit: quota.limit,
                period,
                charge_policy,
            })
        }
        EntitlementKey::Credit
        | EntitlementKey::Emergency
        | EntitlementKey::StorageRetainedBytes => {
            let allowance: RawAllowance = serde_json::from_value(raw.clone()).map_err(bad)?;
            Ok(TemplateValue::Allowance {
                limit: allowance.limit,
            })
        }
        EntitlementKey::CloudIntelligence | EntitlementKey::Byok => {
            if raw == &Value::Bool(true) {
                Ok(TemplateValue::Flag)
            } else {
                Err(PlanSpecError(format!(
                    "template key {}: want true (a capability a plan lacks is absent, never false)",
                    key.wire()
                )))
            }
        }
    }
}

fn spec_from_raw(row: RawVersion) -> Result<PlanVersionSpec, PlanSpecError> {
    let at = |problem: String| {
        PlanSpecError(format!(
            "plan {} version {}: {problem}",
            row.plan_key, row.version
        ))
    };
    let currency = Currency::parse_wire(&row.currency)
        .ok_or_else(|| at(format!("unknown currency {:?}", row.currency)))?;
    let billing_interval = BillingInterval::parse_wire(&row.billing_interval).ok_or_else(|| {
        at(format!(
            "unknown billing_interval {:?}",
            row.billing_interval
        ))
    })?;
    let mut entries = Vec::with_capacity(row.entitlement_template.len());
    for (name, raw) in &row.entitlement_template {
        let key = EntitlementKey::parse_wire(name)
            .ok_or_else(|| at(format!("unknown template key {name:?}")))?;
        entries.push((key, template_value(key, raw)?));
    }
    let entitlement_template = EntitlementTemplate::new(entries)?;
    let mut provider_product_ref = BTreeMap::new();
    for (mode, reference) in &row.provider_product_ref {
        let mode = ProviderMode::parse_wire(mode)
            .ok_or_else(|| at(format!("unknown provider mode {mode:?}")))?;
        provider_product_ref.insert(mode, reference.clone());
    }
    PlanVersionSpec::new(PlanVersionParts {
        plan_key: row.plan_key.clone(),
        version: row.version,
        price_cents: row.price_cents,
        currency,
        billing_interval,
        entitlement_template,
        lease_block: row.lease_block,
        provider_product_ref,
        published: row.published,
    })
}

/// Parses and validates a values file. Refuses unknown fields, an empty file, an unknown enum or template key, a value
/// of the wrong shape for its key, an out-of-range number and a (plan, version) listed twice; nothing is built from a
/// file that fails any of them.
pub fn parse_catalogue(text: &str) -> Result<Vec<PlanVersionSpec>, PlanSpecError> {
    let raw: RawCatalogue = serde_json::from_str(text)
        .map_err(|error| PlanSpecError(format!("plan catalogue: {error}")))?;
    if raw.plan_versions.is_empty() {
        return Err(PlanSpecError(
            "plan catalogue lists no plan version".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut specs = Vec::with_capacity(raw.plan_versions.len());
    for row in raw.plan_versions {
        let spec = spec_from_raw(row)?;
        if !seen.insert((spec.plan_key().clone(), spec.version())) {
            return Err(PlanSpecError(format!(
                "plan {} version {} is listed twice",
                spec.plan_key().as_str(),
                spec.version()
            )));
        }
        specs.push(spec);
    }
    Ok(specs)
}

/// The jsonb a template is stored as: keys and values spelled exactly as the values file spells them.
pub fn entitlement_template_json(template: &EntitlementTemplate) -> Value {
    let mut map = Map::new();
    for (key, value) in template.entries() {
        let rendered = match value {
            TemplateValue::PeriodQuota {
                limit,
                period,
                charge_policy,
            } => json!({
                "limit": limit,
                "period": period.wire(),
                "charge_policy": charge_policy.wire(),
            }),
            TemplateValue::Allowance { limit } => json!({ "limit": limit }),
            TemplateValue::Flag => Value::Bool(true),
        };
        map.insert(key.wire().to_owned(), rendered);
    }
    Value::Object(map)
}

/// The jsonb a provider mapping is stored as: mode -> product reference.
pub fn provider_product_ref_json(references: &BTreeMap<ProviderMode, String>) -> Value {
    Value::Object(
        references
            .iter()
            .map(|(mode, reference)| (mode.wire().to_owned(), Value::String(reference.clone())))
            .collect::<Map<String, Value>>(),
    )
}

/// Seeds `specs` through the owner door in one transaction: a version the catalogue lacks is inserted, a stored one is
/// verified against the spec (Conflict on any difference in price, currency, interval, template or lease block), and a
/// repeat call may publish a draft or replace the provider mapping. A refused version rolls the whole call back.
///
/// ponytail: one transaction holds every per-version advisory lock until commit, which is fine for tens of versions;
/// batch per plan if the catalogue ever grows past that.
pub async fn seed(
    pool: &MaintenanceDbPool,
    specs: &[PlanVersionSpec],
) -> Result<SeedReport, ErrorCode> {
    // dep: PostgreSQL(role_maintenance) — one transaction for the whole catalogue, so a refused version leaves none
    let mut txn = pool.pool().begin().await.map_err(db_error)?;
    let mut report = SeedReport {
        created: 0,
        existing: 0,
    };
    for spec in specs {
        let row = sqlx::query(
            "SELECT out_created FROM control.publish_plan_version($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(spec.plan_key().as_str())
        .bind(spec.version())
        .bind(spec.price_cents())
        .bind(spec.currency().wire())
        .bind(spec.billing_interval().wire())
        .bind(entitlement_template_json(spec.entitlement_template()))
        .bind(spec.lease_block())
        .bind(provider_product_ref_json(spec.provider_product_ref()))
        .bind(spec.published())
        .fetch_one(&mut *txn)
        .await
        .map_err(db_error)?;
        let created: bool = row.try_get("out_created").map_err(db_error)?;
        if created {
            report.created += 1;
        } else {
            report.existing += 1;
        }
    }
    txn.commit().await.map_err(db_error)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed placeholder catalogue (`deploy/plans/plan_catalogue.json`).
    const CATALOGUE: &str = include_str!("../../../deploy/plans/plan_catalogue.json");

    fn catalogue_value() -> Value {
        serde_json::from_str(CATALOGUE).expect("the committed catalogue is JSON")
    }

    fn parse_value(value: &Value) -> Result<Vec<PlanVersionSpec>, PlanSpecError> {
        parse_catalogue(&value.to_string())
    }

    fn refused(value: &Value) -> String {
        parse_value(value)
            .expect_err("the catalogue must be refused")
            .0
    }

    /// The committed catalogue is exactly these five draft versions at these placeholder prices, with only fake-mode
    /// product references and none of the storage allowance (owner Q2: numbers after R11).
    #[test]
    fn the_committed_catalogue_parses_to_exactly_these_versions() {
        let specs = parse_catalogue(CATALOGUE).unwrap();
        let rows: Vec<(&str, i32, i64, &str, bool)> = specs
            .iter()
            .map(|s| {
                (
                    s.plan_key().as_str(),
                    s.version(),
                    s.price_cents(),
                    s.billing_interval().wire(),
                    s.published(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("free", 1, 0, "month", false),
                ("basic", 1, 100, "month", false),
                ("pro", 1, 200, "month", false),
                ("max", 1, 300, "month", false),
                ("basic_yearly", 1, 1000, "year", false),
            ]
        );
        let modes: BTreeSet<ProviderMode> = specs
            .iter()
            .flat_map(|s| s.provider_product_ref().keys().copied())
            .collect();
        assert_eq!(modes, BTreeSet::from([ProviderMode::Fake]));
        let keys: BTreeSet<EntitlementKey> = specs
            .iter()
            .flat_map(|s| s.entitlement_template().entries().map(|(key, _)| key))
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                EntitlementKey::PerPeriod,
                EntitlementKey::Credit,
                EntitlementKey::Emergency,
                EntitlementKey::CloudIntelligence,
                EntitlementKey::Byok,
            ])
        );
    }

    /// Typed -> jsonb is the inverse of the file's own spelling, version by version.
    #[test]
    fn the_stored_template_json_is_the_files_own_spelling() {
        let value = catalogue_value();
        let specs = parse_value(&value).unwrap();
        assert_eq!(specs.len(), 5);
        for (index, spec) in specs.iter().enumerate() {
            let row = &value["plan_versions"][index];
            assert_eq!(
                entitlement_template_json(spec.entitlement_template()),
                row["entitlement_template"],
                "{}",
                spec.plan_key().as_str()
            );
            assert_eq!(
                provider_product_ref_json(spec.provider_product_ref()),
                row["provider_product_ref"],
                "{}",
                spec.plan_key().as_str()
            );
        }
    }

    /// Each way a file can be wrong is refused by name; nothing is built from it.
    #[test]
    fn a_malformed_file_is_refused_and_says_where() {
        let mut unknown_top = catalogue_value();
        unknown_top["extra"] = json!(1);
        assert!(
            refused(&unknown_top).contains("unknown field"),
            "{}",
            refused(&unknown_top)
        );

        let mut empty = catalogue_value();
        empty["plan_versions"] = json!([]);
        assert!(refused(&empty).contains("no plan version"));

        let mut unknown_key = catalogue_value();
        unknown_key["plan_versions"][0]["entitlement_template"]["feature.other"] = json!(true);
        assert!(refused(&unknown_key).contains("unknown template key"));

        let mut capability_off = catalogue_value();
        capability_off["plan_versions"][2]["entitlement_template"]["feature.byok"] = json!(false);
        assert!(refused(&capability_off).contains("want true"));

        let mut wrong_currency = catalogue_value();
        wrong_currency["plan_versions"][1]["currency"] = json!("EUR");
        assert!(refused(&wrong_currency).contains("unknown currency"));

        let mut wrong_period = catalogue_value();
        wrong_period["plan_versions"][1]["entitlement_template"]["mcp.billable_operations.per_period"]
            ["period"] = json!("fortnight");
        assert!(refused(&wrong_period).contains("unknown period"));

        let mut extra_in_quota = catalogue_value();
        extra_in_quota["plan_versions"][1]["entitlement_template"]["mcp.billable_operations.per_period"]
            ["burst"] = json!(5);
        assert!(refused(&extra_in_quota).contains("unknown field"));

        let mut negative = catalogue_value();
        negative["plan_versions"][1]["price_cents"] = json!(-1);
        assert!(refused(&negative).contains("price_cents"));

        let mut twice = catalogue_value();
        let first = twice["plan_versions"][0].clone();
        twice["plan_versions"].as_array_mut().unwrap().push(first);
        assert!(refused(&twice).contains("listed twice"));

        let mut bad_mode = catalogue_value();
        bad_mode["plan_versions"][1]["provider_product_ref"]["staging"] = json!("x");
        assert!(refused(&bad_mode).contains("unknown provider mode"));

        assert!(
            parse_catalogue("not json")
                .unwrap_err()
                .0
                .starts_with("plan catalogue:")
        );
    }

    /// The parser accepts a live-mode reference (the owner's production file carries them); keeping them out of
    /// committed files is a deploy-values gate, not this parser's job.
    #[test]
    fn a_live_mode_reference_parses() {
        let mut value = catalogue_value();
        value["plan_versions"][1]["provider_product_ref"]["live"] = json!("ref");
        let specs = parse_value(&value).unwrap();
        let modes: Vec<ProviderMode> = specs[1].provider_product_ref().keys().copied().collect();
        assert_eq!(modes, [ProviderMode::Fake, ProviderMode::Live]);
    }
}
