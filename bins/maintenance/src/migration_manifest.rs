//! `maintenance::migration_manifest` — the §46.1 migration manifest: its closed class set, its required fields and
//!   the one parser every reader uses (`maintenance::migrate` applies the checks, `xtask::migration_rehearsal`
//!   validates the set statically).
//! Depends-on: crates=[toml]; services=[]; env=[]; modules=[]
//! Called-by: [maintenance::migrate, tests, xtask::migration_rehearsal]
//! Invariants: [a manifest missing a required field, with an illegal class, or with a check that carries a `;`
//!   statement separator outside comments/literals is an error naming its file (§57.1 rule 2, ADR-0051 D-L)]
//! Spec: Baseline §46.1; ADR-0050 D-D; ADR-0051 D-L; ADR-0066 D-Q
//!
//! Moved verbatim from `xtask::migration_rehearsal` (ADR-0066 D-Q): `humaux-maintenance migrate` runs on a node that
//! has no xtask, and it must parse the manifests with the same code the static rehearsal gate validates them with.

use std::collections::HashMap;
use std::fmt;

/// §46.1: the three migration classes a manifest must declare, closed enum.
///
/// - `Reversible`: `up -> down -> up`; the two `up` runs must leave an identical schema digest.
/// - `ExpandContract`: expand/migrate/switch/contract; `contract` only after the observation window.
/// - `ForwardOnly`: no faked `down`; requires a pre-migration restore point + forward-fix rehearsal.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MigrationClass {
    Reversible,
    ExpandContract,
    ForwardOnly,
}

impl MigrationClass {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "REVERSIBLE" => Some(Self::Reversible),
            "EXPAND_CONTRACT" => Some(Self::ExpandContract),
            "FORWARD_ONLY" => Some(Self::ForwardOnly),
            _ => None,
        }
    }
}

/// §46.1: required manifest fields for one `migrations/*.sql` file.
///
/// `schema_digest_before/after` are computed at rehearsal-execution time, not authored
/// statically, so they are not part of this struct.
///
/// `precheck`/`postcheck` are executed by `humaux-maintenance migrate` (ADR-0050 D-D) and syntax/shape
/// checked by `xtask::migration_rehearsal::check_sql` (D-E).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub migration_id: String,
    pub class: MigrationClass,
    pub precheck: String,
    pub postcheck: String,
    // Validated-present only: read by the rehearsal *execution* runner (DOD-089, not built).
    #[allow(dead_code)]
    pub rollback_or_forward_fix: String,
    #[allow(dead_code)]
    pub backup_restore_requirement: String,
}

/// One static-check failure. Always names the offending file (§57.1 rule 2: a
/// `not_applicable`/`fail` that cannot point at the object is "扫不到当通过").
#[derive(Debug)]
pub struct CheckError {
    pub file: String,
    pub reason: String,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.reason)
    }
}

/// §46.1: the manifest's frozen required-field set (besides `class`, checked separately
/// against the closed enum).
const REQUIRED_STRING_FIELDS: &[&str] = &[
    "migration_id",
    "precheck",
    "postcheck",
    "rollback_or_forward_fix",
    "backup_restore_requirement",
];

/// Parse and validate one manifest's required fields (§46.1).
///
/// `file` is used only for error attribution, not read from disk here.
pub fn parse_manifest(file: &str, contents: &str) -> Result<Manifest, CheckError> {
    let err = |reason: String| CheckError {
        file: file.to_string(),
        reason,
    };

    let value: toml::Value =
        toml::from_str(contents).map_err(|e| err(format!("invalid TOML: {e}")))?;
    let table = value
        .as_table()
        .ok_or_else(|| err("manifest root must be a TOML table".to_string()))?;

    let mut fields = HashMap::with_capacity(REQUIRED_STRING_FIELDS.len());
    for key in REQUIRED_STRING_FIELDS {
        let v = table
            .get(*key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(format!("missing required field `{key}`")))?;
        fields.insert(*key, v.to_string());
    }

    for key in ["precheck", "postcheck"] {
        if let Some(at) = statement_separator(&fields[key]) {
            return Err(err(format!(
                "`{key}` has a `;` statement separator at byte {at}: a check is exactly one \
                 SQL statement (ADR-0051 D-L)"
            )));
        }
    }

    let class_raw = table
        .get("class")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err("missing required field `class`".to_string()))?;
    let class = MigrationClass::parse(class_raw).ok_or_else(|| {
        err(format!(
            "class `{class_raw}` not in {{REVERSIBLE, EXPAND_CONTRACT, FORWARD_ONLY}}"
        ))
    })?;

    Ok(Manifest {
        migration_id: fields.remove("migration_id").expect("checked above"),
        class,
        precheck: fields.remove("precheck").expect("checked above"),
        postcheck: fields.remove("postcheck").expect("checked above"),
        rollback_or_forward_fix: fields
            .remove("rollback_or_forward_fix")
            .expect("checked above"),
        backup_restore_requirement: fields
            .remove("backup_restore_requirement")
            .expect("checked above"),
    })
}

/// Byte offset of the first `;` in `sql` that is outside `--` / nested `/* */` comments,
/// `'…'` literals (`''` escape), `"…"` identifiers and `$tag$…$tag$` bodies — i.e. a real
/// statement separator. Checks are single statements by contract; a second statement would
/// otherwise ride along with `EXPLAIN` over the simple-query protocol.
pub fn statement_separator(sql: &str) -> Option<usize> {
    let b = sql.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b';' => return Some(i),
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0usize;
                while i < b.len() {
                    if b[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if b[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            q @ (b'\'' | b'"') => {
                i += 1;
                while i < b.len() {
                    if b[i] == q {
                        if b.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
            }
            b'$' => {
                let end = b[i + 1..]
                    .iter()
                    .position(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                    .map(|n| i + 1 + n)
                    .filter(|e| b[*e] == b'$');
                if let Some(end) = end {
                    let tag = &b[i..=end];
                    let body = end + 1;
                    i = b[body..]
                        .windows(tag.len())
                        .position(|w| w == tag)
                        .map_or(b.len(), |n| body + n + tag.len());
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}
