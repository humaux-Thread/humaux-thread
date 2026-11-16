//! `application::role_rotation` — whole-operation role credential rotation (ADR-0130 D2/D5).
//! Depends-on: crates=[async-trait]; services=[]; env=[]; modules=[]
//! Called-by: [adapters::role_hygiene, maintenance::roles]
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
