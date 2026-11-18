//! `application::role_rotation` — whole-operation role credential rotation (ADR-0130 D2/D5).
//! Depends-on: crates=[async-trait, rand]; services=[]; env=[HUMAUX_MIGRATOR_PG_DSN]; modules=[]
//! Called-by: [adapters::role_hygiene, maintenance::roles, tests]
//! Invariants: [all role changes commit together; credentials are never formatted]
//! Spec: §6.2.0; §77; ADR-0059 D-E; ADR-0130 D7

/// Borrowed rotation credential; deliberately has no Debug or serialization implementation.
pub struct RoleCredential<'a> {
    /// Role already validated by the operator entry.
    pub role: &'a str,
    /// Plaintext only for the adapter's SCRAM verifier construction.
    pub password: &'a str,
}

/// One atomic rotation, including optional creation of missing roles (ADR-0059 D-E).
pub struct RotateRoles<'a> {
    /// Credentials in operator-specified order.
    pub targets: &'a [RoleCredential<'a>],
    /// NOLOGIN migration owner, never a password target.
    pub owner: &'a str,
    /// Whether missing roles may be provisioned.
    pub create_missing: bool,
}

/// Complete PG rotation boundary; validation and every mutation share one transaction.
/// The one-shot operator awaits the adapter locally; no spawned task or Send future is required.
#[async_trait::async_trait(?Send)]
pub trait RoleRotationPort: Send + Sync {
    /// Preserves the adapter's operator refusal and infrastructure failure mapping.
    type Error: Send;
    /// Rotate every target atomically; expose no transaction to the caller.
    async fn rotate_roles(&self, request: &RotateRoles<'_>) -> Result<(), Self::Error>;
}

/// Rotate role credentials; the caller prints generated values only after success.
///
/// # Errors
/// Returns the original rotation refusal or infrastructure failure unchanged.
pub async fn rotate<P: RoleRotationPort>(
    port: &P,
    request: &RotateRoles<'_>,
) -> Result<(), P::Error> {
    port.rotate_roles(request).await
}

use std::collections::BTreeSet;

/// A role password held in memory only. `Debug` prints `<redacted>` so a stray `{:?}` cannot leak it.
#[derive(Clone, PartialEq, Eq)]
pub struct RolePassword(String);

impl RolePassword {
    /// Wraps a value read from the environment, the generator, or the parsed migration 0011.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The plaintext, for the one place that must use it (a login probe, the print-once line).
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RolePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RolePassword(<redacted>)")
    }
}

/// Tri-state result of one deploy-check (§57.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// The invariant holds.
    Pass,
    /// The invariant is broken; the detail names the roles or variables.
    Fail,
    /// The check could not run; the detail names the missing object.
    NotApplicable,
}

impl CheckStatus {
    /// The wire spelling in the deploy-check receipt.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// One named deploy-check result. `detail` holds role or variable names only, never a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    /// Stable check name (`placeholder_login`, `probe_valid`, ...).
    pub name: &'static str,
    /// Tri-state outcome.
    pub status: CheckStatus,
    /// Names only.
    pub detail: String,
}

impl CheckResult {
    /// §57.1: a check that cannot run names the missing object.
    pub fn not_applicable(name: &'static str, missing_object: &str) -> Self {
        Self {
            name,
            status: CheckStatus::NotApplicable,
            detail: format!("missing object: {missing_object}"),
        }
    }

    /// Report a failed check when any offending names were found.
    pub fn from_problems(name: &'static str, problems: Vec<String>, ok: String) -> Self {
        if problems.is_empty() {
            Self {
                name,
                status: CheckStatus::Pass,
                detail: ok,
            }
        } else {
            Self {
                name,
                status: CheckStatus::Fail,
                detail: problems.join("; "),
            }
        }
    }
}

/// The repository placeholder set (ADR-0059 D-F): the passwords migration 0011 publishes, all of the
/// form `P_<role>` for one common prefix `P`.
pub struct Placeholders {
    values: Vec<RolePassword>,
    prefix: String,
}

/// ADR-0059 D-F: checks every `(role, value)` pair has the form `P_<role>` for one common `P` and keeps
/// that `P`. `None` = convention drift (the caller reports `roles-sql parse drift`).
pub fn derive_candidates(pairs: &[(String, RolePassword)]) -> Option<Placeholders> {
    let (first_role, first) = pairs.first()?;
    let prefix = first.expose().strip_suffix(&format!("_{first_role}"))?;
    if prefix.is_empty()
        || pairs
            .iter()
            .any(|(role, v)| v.expose() != format!("{prefix}_{role}"))
    {
        return None;
    }
    Some(Placeholders {
        values: pairs.iter().map(|(_, v)| v.clone()).collect(),
        prefix: prefix.to_owned(),
    })
}

impl Placeholders {
    /// Candidates tried against `role`: the published values, plus `P_<role>` (the same convention
    /// for a role 0011 does not create, e.g. role_admin) and `P` itself (the dev superuser value).
    pub fn for_role(&self, role: &str) -> Vec<RolePassword> {
        let mut seen = BTreeSet::new();
        self.values
            .iter()
            .cloned()
            .chain([
                RolePassword::new(format!("{}_{role}", self.prefix)),
                RolePassword::new(self.prefix.clone()),
            ])
            .filter(|c| seen.insert(c.expose().to_owned()))
            .collect()
    }

    /// ADR-0059 D-E: `true` when `value` contains the prefix `P`, which every published value and
    /// every candidate of [`Self::for_role`] does, so equality with any candidate is covered too.
    pub fn taints(&self, value: &str) -> bool {
        value.contains(&self.prefix)
    }

    /// Whether this value exactly matches a published placeholder or its prefix.
    pub fn contains(&self, value: &str) -> bool {
        value == self.prefix || self.values.iter().any(|v| v.expose() == value)
    }
}

/// Minimum length of an operator-supplied role password (ADR-0059 D-E).
pub const MIN_PASSWORD_LEN: usize = 32;

/// `HUMAUX_ROLE_PASSWORD_<SUFFIX>`, SUFFIX = the role name without `role_`, upper-cased.
pub fn env_name(role: &str) -> String {
    format!(
        "HUMAUX_ROLE_PASSWORD_{}",
        role.strip_prefix("role_")
            .unwrap_or(role)
            .to_ascii_uppercase()
    )
}

/// Where one rotated password came from (receipt field `source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Value supplied by the operator.
    Env,
    /// Value generated for this rotation.
    Generated,
}

impl Source {
    /// Stable receipt spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Generated => "generated",
        }
    }
}

/// The new password of `role`: `HUMAUX_ROLE_PASSWORD_<SUFFIX>` when set (at least
/// [`MIN_PASSWORD_LEN`] URL-unreserved characters, so a DSN needs no encoding, and not built on the
/// repository placeholder prefix), else 32 random bytes hex-encoded. A refusal names the variable,
/// never the value.
pub fn password_for(
    role: &str,
    placeholders: &Placeholders,
    lookup: impl Fn(&str) -> Option<String>,
) -> std::result::Result<(RolePassword, Source), String> {
    let name = env_name(role);
    match lookup(&name) {
        Some(value) => {
            let unreserved = value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'));
            if value.chars().count() < MIN_PASSWORD_LEN || !unreserved {
                return Err(format!(
                    "{name}: must be at least {MIN_PASSWORD_LEN} characters from [A-Za-z0-9._~-]"
                ));
            }
            // ADR-0059 D-E: a rotation must never report success while a published value stays live.
            if placeholders.taints(&value) {
                return Err(format!(
                    "{name}: is built on the repository placeholder prefix of migration 0011; \
                     unset it to generate a value"
                ));
            }
            Ok((RolePassword::new(value), Source::Env))
        }
        None => {
            let bytes: [u8; 32] = rand::random();
            let hex = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Ok((RolePassword::new(hex), Source::Generated))
        }
    }
}

/// ADR-0059 D-F: the eight `(role, placeholder)` pairs of migration 0011, parsed at run time so the
/// repository holds no second copy. Exactly eight distinct roles, or `Err` (parse drift).
pub fn parse_roles_sql(text: &str) -> std::result::Result<Vec<(String, RolePassword)>, String> {
    const CREATE: &str = "CREATE ROLE ";
    const PASSWORD: &str = " LOGIN PASSWORD '";
    let mut pairs: Vec<(String, RolePassword)> = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix(CREATE) else {
            continue;
        };
        let Some((role, tail)) = rest.split_once(PASSWORD) else {
            continue;
        };
        let value = tail
            .split_once('\'')
            .map(|(v, _)| v)
            .ok_or_else(|| format!("role {role}: unterminated password literal"))?;
        if pairs.iter().any(|(r, _)| r == role) {
            return Err(format!("role {role} appears twice"));
        }
        pairs.push((role.to_owned(), RolePassword::new(value.to_owned())));
    }
    if pairs.len() != 8 {
        return Err(format!(
            "{} placeholder roles, expected 8 (ADR-0059 D-F)",
            pairs.len()
        ));
    }
    Ok(pairs)
}

/// The four catalog/probe checks when no maintenance connection can be formed (§57.1).
pub fn maintenance_not_applicable(missing: &str) -> Vec<CheckResult> {
    [
        "placeholder_login",
        "probe_valid",
        "owner_nologin",
        "schema_migrations_write",
    ]
    .into_iter()
    .map(|name| CheckResult::not_applicable(name, missing))
    .collect()
}

/// A probe check that ran without the superuser target is at best `not_applicable` (§57.1).
fn without_superuser(check: CheckResult, superuser: Option<&str>) -> CheckResult {
    match (check.status, superuser) {
        (CheckStatus::Pass, None) => {
            CheckResult::not_applicable(check.name, "HUMAUX_MIGRATOR_PG_DSN")
        }
        _ => check,
    }
}

/// Resolve the requested role subset, preserving the operator order and create-missing restrictions.
///
/// # Errors
/// Returns the original usage error when a named role is outside the allowed set.
pub fn rotation_targets(
    named: Vec<String>,
    create_missing: bool,
    login_roles: &[&str],
    admin_role: &str,
) -> Result<Vec<String>, String> {
    let mut allowed: Vec<String> = login_roles.iter().map(|r| (*r).to_owned()).collect();
    if !create_missing {
        allowed.push(admin_role.to_owned());
    }
    if let Some(other) = named.iter().find(|r| !allowed.contains(r)) {
        return Err(format!(
            "--role {other}: not one of {allowed:?} (role_admin is created by migration 0110, \
             rotate it after migrate)"
        ));
    }
    Ok(if named.is_empty() { allowed } else { named })
}

/// Prepare credentials in the requested order without opening the database.
///
/// # Errors
/// Returns the original usage error for a rejected environment credential.
pub fn prepare_passwords(
    targets: Vec<String>,
    placeholders: &Placeholders,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<(String, RolePassword, Source)>, String> {
    targets
        .into_iter()
        .map(|role| {
            let (password, source) = password_for(&role, placeholders, &lookup)?;
            Ok((role, password, source))
        })
        .collect()
}

/// Deploy-check's operator error categories.
pub enum DeployCheckError<C, P> {
    /// The chosen DSN could not supply probe options.
    InvalidDsn,
    /// The maintenance connection failed.
    Connect(C),
    /// A catalog or login probe failed.
    Probe(P),
}

/// Catalog and environment probes for the deployment invariants.
#[async_trait::async_trait(?Send)]
pub trait DeployCheckPort {
    type ConnectError;
    type ProbeError;

    /// Read the four checks requiring a maintenance connection.
    async fn catalog_checks(
        &self,
        dsn: &str,
        probed: &[String],
        password_roles: &[String],
        owner: &str,
        placeholders: &Placeholders,
    ) -> Result<[CheckResult; 4], DeployCheckError<Self::ConnectError, Self::ProbeError>>;

    /// Inspect environment DSNs without opening connections.
    fn env_check(&self, env: &[(String, String)], placeholders: &Placeholders) -> CheckResult;
}

/// Inputs to the deployment check, in the original probe order.
pub struct DeployCheck<'a> {
    pub maintenance: Result<&'a str, &'a str>,
    pub probed: &'a [String],
    pub password_roles: &'a [String],
    pub owner: &'a str,
    pub superuser: Option<&'a str>,
    pub placeholders: &'a Placeholders,
}

/// Check the catalog and, after those probes, inspect the operator environment.
///
/// # Errors
/// Returns the original probe or connection error.
pub async fn deploy_check<P: DeployCheckPort>(
    port: &P,
    request: DeployCheck<'_>,
    environment: impl FnOnce() -> Vec<(String, String)>,
) -> Result<Vec<CheckResult>, DeployCheckError<P::ConnectError, P::ProbeError>> {
    let mut checks = match request.maintenance {
        Err(missing) => maintenance_not_applicable(missing),
        Ok(dsn) => {
            let [login, valid, owner, writes] = port
                .catalog_checks(
                    dsn,
                    request.probed,
                    request.password_roles,
                    request.owner,
                    request.placeholders,
                )
                .await?;
            vec![
                without_superuser(login, request.superuser),
                without_superuser(valid, request.superuser),
                owner,
                writes,
            ]
        }
    };
    checks.push(port.env_check(&environment(), request.placeholders));
    Ok(checks)
}
