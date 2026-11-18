//! `maintenance::roles` — `roles rotate` and `deploy-check` (ADR-0059 D-E, D-F): where role passwords come from, how
//!   generated ones are printed, and which roles and variables each check covers.
//! Depends-on: crates=[humaux-application, humaux-adapters, rand, serde_json]; services=[PostgreSQL(owner),
//!   PostgreSQL(any)]; env=[CARGO_MANIFEST_DIR, HUMAUX_MAINTENANCE_PG_DSN, HUMAUX_MIGRATOR_PG_DSN, HUMAUX_ROLE_PASSWORD_ADMIN,
//!   HUMAUX_ROLE_PASSWORD_BATCH_ISSUER, HUMAUX_ROLE_PASSWORD_CONSOLIDATION_WORKER, HUMAUX_ROLE_PASSWORD_GATEWAY,
//!   HUMAUX_ROLE_PASSWORD_MAINTENANCE, HUMAUX_ROLE_PASSWORD_PRIVATE_WORKER, HUMAUX_ROLE_PASSWORD_PUBLIC_WORKER,
//!   HUMAUX_ROLE_PASSWORD_RETRIEVAL_WORKER]; modules=[application::role_rotation, adapters::postgres, adapters::role_hygiene, maintenance::main]
//! Called-by: [maintenance::main]
//! Invariants: [a generated password is printed exactly once, as `HUMAUX_ROLE_PASSWORD_<SUFFIX>=<value>` on stdout
//!   before the receipt, never in the receipt or on stderr; an env value is validated and refused by variable name
//!   only, and refused when it is built on the 0011 placeholder prefix; the placeholders of migration 0011 are parsed
//!   at run time and never copied into this crate; the migrator principal is never a rotation target]
//! Spec: Baseline §6.2.0; §57.1; §77; ADR-0059

use humaux_adapters::postgres::{
    MigratorDbPool, ROLE_ADMIN, ROLE_BATCH_ISSUER, ROLE_CONSOLIDATION_WORKER, ROLE_GATEWAY,
    ROLE_MAINTENANCE, ROLE_MIGRATION_OWNER, ROLE_PRIVATE_WORKER, ROLE_PUBLIC_WORKER,
    ROLE_RETRIEVAL_WORKER,
};
use humaux_adapters::role_hygiene;
use humaux_application::role_rotation::{
    self, CheckResult, CheckStatus, Placeholders, RoleCredential, RolePassword, RotateRoles,
    Source, derive_candidates, env_name, parse_roles_sql,
};
#[cfg(test)]
use humaux_application::role_rotation::{
    MIN_PASSWORD_LEN, maintenance_not_applicable, password_for,
};
use serde_json::{Value, json};

use crate::{Admin, Args, Failure, Output, Result, env};

/// The LOGIN roles migration 0011 creates; `--create-missing` provisions exactly these (ADR-0059 D-A).
const LOGIN_ROLES_0011: [&str; 7] = [
    ROLE_GATEWAY,
    ROLE_PRIVATE_WORKER,
    ROLE_CONSOLIDATION_WORKER,
    ROLE_PUBLIC_WORKER,
    ROLE_RETRIEVAL_WORKER,
    ROLE_BATCH_ISSUER,
    ROLE_MAINTENANCE,
];

/// The eight password roles (§6.2.0 minus the NOLOGIN owner): the default rotation set and the
/// non-owner set of the `schema_migrations_write` check.
fn password_roles() -> Vec<String> {
    LOGIN_ROLES_0011
        .iter()
        .chain([ROLE_ADMIN].iter())
        .map(|r| (*r).to_owned())
        .collect()
}

/// ADR-0059 D-F: the placeholder set of the `--roles-sql <0011>` file, parsed at run time.
fn placeholders_from(args: &Args) -> Result<Placeholders> {
    let path = args.required("--roles-sql")?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Failure::Usage(format!("--roles-sql {path}: {e}")))?;
    let pairs = parse_roles_sql(&text)
        .map_err(|why| Failure::Infra(format!("roles-sql parse drift: {why}")))?;
    derive_candidates(&pairs).ok_or_else(|| {
        Failure::Infra("roles-sql parse drift: a placeholder is not <P>_<role>".to_owned())
    })
}

/// The print-once lines for generated values (ADR-0059 D-E), in rotation order.
fn generated_lines(rotated: &[(String, RolePassword, Source)]) -> Vec<String> {
    rotated
        .iter()
        .filter(|(_, _, source)| *source == Source::Generated)
        .map(|(role, password, _)| format!("{}={}", env_name(role), password.expose()))
        .collect()
}

/// The rotation receipt: roles and sources, never a value.
// ponytail: the receipt is the only durable record (control.audit_events needs a tenant, roles are
// cluster-level, ADR-0059 L3); add a tenant-less ops audit stream if rotations must be queryable.
fn rotate_receipt(rotated: &[(String, RolePassword, Source)], admin: &Admin) -> Value {
    json!({
        "command": "roles rotate",
        "roles": rotated
            .iter()
            .map(|(role, _, source)| json!({ "role": role, "source": source.as_str() }))
            .collect::<Vec<_>>(),
        "owner_nologin": true,
        "actor": admin.actor,
        "reason": admin.reason,
        "ticket": admin.ticket,
        "trace_id": admin.trace_id,
    })
}

/// `roles rotate --roles-sql <0011> [--role R]... [--create-missing]` (ADR-0059 D-E): one
/// transaction through `HUMAUX_MIGRATOR_PG_DSN`; generated values printed once after COMMIT.
pub(crate) async fn rotate(args: &Args) -> Result<Output> {
    let admin = Admin::from(args)?;
    let create_missing = args.0.iter().any(|a| a == "--create-missing");
    let named: Vec<String> = args
        .0
        .windows(2)
        .filter(|w| w[0] == "--role")
        .map(|w| w[1].clone())
        .collect();
    let targets =
        role_rotation::rotation_targets(named, create_missing, &LOGIN_ROLES_0011, ROLE_ADMIN)
            .map_err(Failure::Usage)?;
    let placeholders = placeholders_from(args)?;
    let rotated =
        role_rotation::prepare_passwords(targets, &placeholders, |name| std::env::var(name).ok())
            .map_err(Failure::Usage)?;
    let dsn = env("HUMAUX_MIGRATOR_PG_DSN")?;
    // dep: PostgreSQL(owner) — the migrate principal, the only one that may ALTER ROLE
    let pool = MigratorDbPool::connect(&dsn)
        .await
        .map_err(|e| Failure::Infra(format!("connect HUMAUX_MIGRATOR_PG_DSN: {e}")))?;
    let pairs: Vec<RoleCredential<'_>> = rotated
        .iter()
        .map(|(role, password, _)| RoleCredential {
            role,
            password: password.expose(),
        })
        .collect();
    role_rotation::rotate(
        &pool,
        &RotateRoles {
            targets: &pairs,
            owner: ROLE_MIGRATION_OWNER,
            create_missing,
        },
    )
    .await?;
    let mut output = Output::ok(rotate_receipt(&rotated, &admin));
    output.once = generated_lines(&rotated);
    Ok(output)
}

fn check_json(check: &CheckResult) -> Value {
    json!({ "name": check.name, "status": check.status.as_str(), "detail": check.detail })
}

const MAINTENANCE_DSN: &str = "HUMAUX_MAINTENANCE_PG_DSN";
const MIGRATOR_DSN: &str = "HUMAUX_MIGRATOR_PG_DSN";
/// Receipt `maintenance_dsn_source` of a DSN derived from the migrate one-shot's two variables.
const DERIVED_SOURCE: &str = "derived:HUMAUX_MIGRATOR_PG_DSN+HUMAUX_ROLE_PASSWORD_MAINTENANCE";

/// The catalog connection of deploy-check and its receipt source: an explicit
/// `HUMAUX_MAINTENANCE_PG_DSN` wins; else the migrator URL logging in as `role_maintenance` with
/// `HUMAUX_ROLE_PASSWORD_MAINTENANCE` (ADR-0066 review fix 3: the release bundle gives the migrate
/// one-shot only those). `Err` = the §57.1 missing objects, names only.
fn maintenance_dsn(
    lookup: impl Fn(&str) -> Option<String>,
) -> std::result::Result<(String, &'static str), String> {
    let get = |name: &str| lookup(name).filter(|v| !v.trim().is_empty());
    if let Some(dsn) = get(MAINTENANCE_DSN) {
        return Ok((dsn, "env"));
    }
    let password_var = env_name(ROLE_MAINTENANCE);
    match (get(MIGRATOR_DSN), get(&password_var)) {
        (Some(migrator), Some(password)) => {
            role_hygiene::role_dsn(&migrator, ROLE_MAINTENANCE, &password)
                .map(|dsn| (dsn, DERIVED_SOURCE))
                .ok_or_else(|| {
                    format!("{MAINTENANCE_DSN} (and {MIGRATOR_DSN} is not a PostgreSQL URL)")
                })
        }
        (migrator, password) => {
            let missing: Vec<&str> = [
                migrator.is_none().then_some(MIGRATOR_DSN),
                password.is_none().then_some(password_var.as_str()),
            ]
            .into_iter()
            .flatten()
            .collect();
            Err(format!("{MAINTENANCE_DSN} or {}", missing.join("+")))
        }
    }
}

/// `deploy-check --roles-sql <0011>` (ADR-0059 D-F): five named checks, read-only, names only.
pub(crate) async fn deploy_check(args: &Args) -> Result<Output> {
    let placeholders = placeholders_from(args)?;
    let superuser = std::env::var("HUMAUX_MIGRATOR_PG_DSN")
        .ok()
        .and_then(|dsn| role_hygiene::dsn_user(&dsn));
    let mut probed: Vec<String> = password_roles();
    probed.push(ROLE_MIGRATION_OWNER.to_owned());
    probed.extend(superuser.clone());

    let maintenance = maintenance_dsn(|name| std::env::var(name).ok());
    let source = maintenance.as_ref().ok().map(|(_, source)| *source);
    let checks = role_rotation::deploy_check(
        &role_hygiene::deploy_checks(),
        role_rotation::DeployCheck {
            maintenance: maintenance
                .as_ref()
                .map(|(dsn, _)| dsn.as_str())
                .map_err(String::as_str),
            probed: &probed,
            password_roles: &password_roles(),
            owner: ROLE_MIGRATION_OWNER,
            superuser: superuser.as_deref(),
            placeholders: &placeholders,
        },
        || std::env::vars().collect(),
    )
    .await
    .map_err(|e| match e {
        role_rotation::DeployCheckError::InvalidDsn => {
            Failure::Usage(format!("{MAINTENANCE_DSN}: not a PostgreSQL URL"))
        }
        role_rotation::DeployCheckError::Connect(e) => {
            Failure::Infra(format!("connect {MAINTENANCE_DSN}: {e}"))
        }
        role_rotation::DeployCheckError::Probe(e) => e.into(),
    })?;
    let refused = checks.iter().any(|c| c.status != CheckStatus::Pass);
    let mut output = Output::ok(json!({
        "command": "deploy-check",
        "maintenance_dsn_source": source,
        "checks": checks.iter().map(check_json).collect::<Vec<_>>(),
    }));
    output.refused = refused;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_token(len: usize) -> String {
        (0..len)
            .map(|_| {
                let b: u8 = rand::random::<u8>() % 36;
                char::from_digit(u32::from(b), 36).expect("base-36 digit")
            })
            .collect()
    }

    fn synthetic_0011(roles: &[&str], prefix: &str) -> String {
        roles
            .iter()
            .map(|r| {
                format!(
                    "  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{r}') THEN\n    \
                     CREATE ROLE {r} LOGIN PASSWORD '{prefix}_{r}'\n      NOSUPERUSER;\n  END IF;\n"
                )
            })
            .collect()
    }

    const EIGHT: [&str; 8] = [
        "role_a", "role_b", "role_c", "role_d", "role_e", "role_f", "role_g", "role_h",
    ];

    /// T11 (ADR-0059 D-F): exactly eight distinct roles parse; seven or a duplicate is drift.
    #[test]
    fn roles_sql_parse_requires_exactly_eight_distinct_roles() {
        let prefix = random_token(20);
        let pairs = parse_roles_sql(&synthetic_0011(&EIGHT, &prefix)).expect("eight roles");
        assert_eq!(pairs.len(), 8);
        assert_eq!(pairs[0].0, "role_a");
        assert_eq!(pairs[0].1.expose(), format!("{prefix}_role_a"));
        assert!(parse_roles_sql(&synthetic_0011(&EIGHT[..7], &prefix)).is_err());
        let mut dup = EIGHT;
        dup[7] = "role_a";
        assert!(parse_roles_sql(&synthetic_0011(&dup, &prefix)).is_err());
    }

    /// The real migration parses into eight pairs that follow the `P_<role>` convention.
    #[test]
    fn the_real_0011_parses_and_follows_the_convention() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../migrations/0011_roles_and_grants.sql"),
        )
        .expect("0011 body");
        let pairs = parse_roles_sql(&text).expect("eight roles");
        assert!(pairs.iter().all(|(r, _)| r.starts_with("role_")));
        assert!(derive_candidates(&pairs).is_some());
    }

    /// Operator values are validated and refused by variable name; absent ones are generated.
    #[test]
    fn env_values_are_validated_by_name_and_absent_ones_generated() {
        let none = synthetic_placeholders();
        let good = random_token(40);
        let (password, source) = password_for("role_gateway", &none, |n| {
            (n == "HUMAUX_ROLE_PASSWORD_GATEWAY").then(|| good.clone())
        })
        .expect("valid env value");
        assert_eq!((password.expose(), source), (good.as_str(), Source::Env));
        for bad in [random_token(31), format!("{}@", random_token(40))] {
            let err =
                password_for("role_admin", &none, |_| Some(bad.clone())).expect_err("refused");
            assert!(err.starts_with("HUMAUX_ROLE_PASSWORD_ADMIN:"), "{err}");
            assert!(!err.contains(&bad));
        }
        let (a, source) = password_for("role_admin", &none, |_| None).expect("generated");
        let (b, _) = password_for("role_admin", &none, |_| None).expect("generated");
        assert_eq!(source, Source::Generated);
        assert_eq!(a.expose().len(), 64);
        assert_ne!(a, b);
    }

    fn synthetic_placeholders() -> Placeholders {
        let pairs = parse_roles_sql(&synthetic_0011(&EIGHT, &random_token(20))).expect("eight");
        derive_candidates(&pairs).expect("convention")
    }

    /// ADR-0059 D-E (review P1): an env value equal to a published placeholder, or built on its prefix
    /// `P`, is refused naming the variable, so a rotation can never succeed while `P_<role>` stays live.
    #[test]
    fn env_value_built_on_a_placeholder_is_refused() {
        let prefix = random_token(28);
        let pairs = parse_roles_sql(&synthetic_0011(&EIGHT, &prefix)).expect("eight");
        let placeholders = derive_candidates(&pairs).expect("convention");
        let published = format!("{prefix}_role_a");
        for value in [
            published.clone(),
            format!("{prefix}_role_gateway"),
            format!("{prefix}{}", random_token(12)),
            format!("{}{prefix}", random_token(12)),
        ] {
            assert!(
                value.chars().count() >= MIN_PASSWORD_LEN,
                "test value passes the length rule"
            );
            let err = password_for("role_a", &placeholders, |_| Some(value.clone()))
                .expect_err("placeholder-derived value refused");
            assert!(err.starts_with("HUMAUX_ROLE_PASSWORD_A:"), "{err}");
            assert!(!err.contains(&prefix), "a refusal never prints the value");
        }
    }

    /// T12 (ADR-0059 D-E): each generated value appears exactly once in stdout (its print-once line)
    /// and never in the receipt; an env-sourced value appears nowhere.
    #[test]
    fn rotate_output_prints_each_generated_secret_once() {
        let rotated = vec![
            (
                "role_gateway".to_owned(),
                RolePassword::new(random_token(64)),
                Source::Generated,
            ),
            (
                "role_admin".to_owned(),
                RolePassword::new(random_token(40)),
                Source::Env,
            ),
        ];
        let admin = Admin {
            actor: "t".to_owned(),
            reason: "t".to_owned(),
            ticket: "t".to_owned(),
            trace_id: "t".to_owned(),
            step_up: "t".to_owned(),
        };
        let mut output = Output::ok(rotate_receipt(&rotated, &admin));
        output.once = generated_lines(&rotated);
        let stdout = output.render();
        let receipt = output.receipt.to_string();
        let generated = rotated[0].1.expose();
        assert_eq!(stdout.matches(generated).count(), 1, "printed once");
        assert_eq!(
            stdout
                .lines()
                .filter(|l| *l == format!("HUMAUX_ROLE_PASSWORD_GATEWAY={generated}"))
                .count(),
            1
        );
        assert_eq!(receipt.matches(generated).count(), 0);
        assert_eq!(stdout.matches(rotated[1].1.expose()).count(), 0);
        assert!(receipt.contains("\"source\":\"generated\""), "{receipt}");
    }

    fn lookup_of(pairs: Vec<(&str, String)>) -> impl Fn(&str) -> Option<String> + use<> {
        let pairs: Vec<(String, String)> =
            pairs.into_iter().map(|(n, v)| (n.to_owned(), v)).collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        }
    }

    /// Review fix 3 (ADR-0066): the migrate one-shot has no `HUMAUX_MAINTENANCE_PG_DSN`; the DSN is
    /// derived from the migrator URL with `role_maintenance` and its password variable.
    #[test]
    fn maintenance_dsn_is_derived_from_the_migrator_url_and_the_role_password() {
        let (migrator_pw, maintenance_pw) = (random_token(32), random_token(32));
        let lookup = lookup_of(vec![
            (
                "HUMAUX_MIGRATOR_PG_DSN",
                format!(
                    "postgres://role_migrator:{migrator_pw}@db-host:6543/humaux?sslmode=require"
                ),
            ),
            (env_name(ROLE_MAINTENANCE).as_str(), maintenance_pw.clone()),
        ]);
        let (dsn, source) = maintenance_dsn(lookup).expect("derived");
        assert_eq!(source, DERIVED_SOURCE);
        assert!(
            dsn == format!(
                "postgres://role_maintenance:{maintenance_pw}@db-host:6543/humaux?sslmode=require"
            ),
            "derived DSN keeps host/port/db/query, user role_maintenance, the env password"
        );
        let options = role_hygiene::probe_options(&dsn).expect("a PostgreSQL URL");
        assert_eq!(options.get_username(), ROLE_MAINTENANCE);
        assert_eq!((options.get_host(), options.get_port()), ("db-host", 6543));
        assert_eq!(options.get_database(), Some("humaux"));
    }

    #[test]
    fn an_explicit_maintenance_dsn_wins_over_derivation() {
        let explicit = format!(
            "postgres://role_maintenance:{}@ops-host/humaux",
            random_token(32)
        );
        let lookup = lookup_of(vec![
            ("HUMAUX_MAINTENANCE_PG_DSN", explicit.clone()),
            (
                "HUMAUX_MIGRATOR_PG_DSN",
                format!(
                    "postgres://role_migrator:{}@db-host/humaux",
                    random_token(32)
                ),
            ),
            (env_name(ROLE_MAINTENANCE).as_str(), random_token(32)),
        ]);
        let (dsn, source) = maintenance_dsn(lookup).expect("explicit");
        assert_eq!(source, "env");
        assert!(
            dsn == explicit,
            "the explicit HUMAUX_MAINTENANCE_PG_DSN is used as given"
        );
    }

    #[test]
    fn without_either_route_the_four_checks_name_both_missing_objects() {
        for pairs in [vec![], vec![("HUMAUX_MAINTENANCE_PG_DSN", "  ".to_owned())]] {
            let missing = maintenance_dsn(lookup_of(pairs)).expect_err("no route");
            let checks = maintenance_not_applicable(&missing);
            assert_eq!(checks.len(), 4);
            for check in &checks {
                assert_eq!(check.status, CheckStatus::NotApplicable);
                for object in [
                    "HUMAUX_MAINTENANCE_PG_DSN",
                    "HUMAUX_MIGRATOR_PG_DSN",
                    env_name(ROLE_MAINTENANCE).as_str(),
                ] {
                    assert!(
                        check.detail.contains(object),
                        "{}: {} lacks {object}",
                        check.name,
                        check.detail
                    );
                }
            }
        }
        let only_migrator = lookup_of(vec![(
            "HUMAUX_MIGRATOR_PG_DSN",
            "postgres://role_migrator@db-host/humaux".to_owned(),
        )]);
        let missing = maintenance_dsn(only_migrator).expect_err("no password");
        assert_eq!(
            missing,
            "HUMAUX_MAINTENANCE_PG_DSN or HUMAUX_ROLE_PASSWORD_MAINTENANCE"
        );
    }
}
