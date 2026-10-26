//! `maintenance::migration_manifest` — the §46.1 migration manifest: its closed class set, its required fields and
//!   the one parser every reader uses (`maintenance::migrate` applies the checks, `xtask::migration_rehearsal`
//!   validates the set statically).
//! Depends-on: crates=[toml]; services=[]; env=[]; modules=[]
//! Called-by: [maintenance::migrate, tests, xtask::migration_rehearsal]
//! Invariants: [a manifest missing a required field, with an illegal class, with a check that carries a `;`
//!   statement separator outside comments/literals, or with a malformed `accepted_prior_checksums` entry is an error
//!   naming its file (§57.1 rule 2, ADR-0051 D-L, ADR-0082); a recorded checksum is accepted for a changed file only
//!   through [`compare_recorded`], the one drift rule]
//! Spec: Baseline §46.1; ADR-0050 D-D; ADR-0051 D-L; ADR-0066 D-Q; ADR-0082
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

/// ADR-0082: one reviewed amendment of an applied migration body. The manifest lists the checksum the file had
/// before the amendment; `migrate` then accepts a database that recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedChecksum {
    /// The FNV-1a checksum of the pre-amendment file: 16 lowercase hex digits, as `ops.schema_migrations` records it.
    pub checksum: String,
    /// Why the body changed; never empty.
    pub reason: String,
}

/// ADR-0082: how a file's current checksum stands against the checksum its database recorded.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordedChecksum<'a> {
    /// The recorded checksum is the file's own.
    Same,
    /// The file changed after this database applied it, and the recorded checksum is on the file's reviewed list.
    Amended {
        /// The listed reason for the change.
        reason: &'a str,
    },
    /// The recorded checksum is neither the file's nor on its list: §46 drift, the run stops.
    Drift,
}

/// ADR-0082: the one rule for "recorded vs file". Every reader of `ops.schema_migrations.checksum` that compares it
/// with a file calls this; it only reads, so no caller has a path that rewrites a recorded row (ADR-0060 SEC-2).
///
/// A forged row still fails: the list lives in the file under review in git, and a recorded value outside it is drift.
// ponytail: no automated schema-equivalence proof until a migration-rehearsal digest exists, so review is the only
// guard that a listed amendment changed no schema effect; upgrade = compare `schema_digest_before/after` (§46.1).
pub fn compare_recorded<'a>(
    current: &str,
    recorded: &str,
    accepted: &'a [AcceptedChecksum],
) -> RecordedChecksum<'a> {
    if recorded == current {
        return RecordedChecksum::Same;
    }
    match accepted.iter().find(|a| a.checksum == recorded) {
        Some(a) => RecordedChecksum::Amended { reason: &a.reason },
        None => RecordedChecksum::Drift,
    }
}

/// ADR-0082: the manifest key listing pre-amendment checksums.
const ACCEPTED_KEY: &str = "accepted_prior_checksums";

/// ADR-0082: the manifest's `accepted_prior_checksums = [{ checksum = "<fnv1a hex>", reason = "<why>" }, …]`; absent
/// ⇒ empty. Anything else is an error naming `file`: not an array of tables, a key outside `checksum`/`reason`, a
/// checksum that is not 16 lowercase hex digits, or a blank reason.
pub fn accepted_prior_checksums(
    file: &str,
    contents: &str,
) -> Result<Vec<AcceptedChecksum>, CheckError> {
    let err = |reason: String| CheckError {
        file: file.to_string(),
        reason,
    };
    let value: toml::Value =
        toml::from_str(contents).map_err(|e| err(format!("invalid TOML: {e}")))?;
    let Some(raw) = value.get(ACCEPTED_KEY) else {
        return Ok(Vec::new());
    };
    let shape = format!("`{ACCEPTED_KEY}` must be an array of {{ checksum, reason }} tables");
    let entries = raw.as_array().ok_or_else(|| err(shape.clone()))?;
    let mut out = Vec::with_capacity(entries.len());
    for (n, entry) in entries.iter().enumerate() {
        let at = format!("`{ACCEPTED_KEY}` entry #{}", n + 1);
        let table = entry.as_table().ok_or_else(|| err(shape.clone()))?;
        if let Some(key) = table
            .keys()
            .find(|k| !matches!(k.as_str(), "checksum" | "reason"))
        {
            return Err(err(format!(
                "{at} has key `{key}` outside the closed set {{checksum, reason}}"
            )));
        }
        let checksum = table
            .get("checksum")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| err(format!("{at} needs a string `checksum`")))?;
        if checksum.len() != 16
            || !checksum
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(err(format!(
                "{at}: checksum `{checksum}` is not 16 lowercase hex digits (FNV-1a, as the migration ledger records it)"
            )));
        }
        let reason = table
            .get("reason")
            .and_then(toml::Value::as_str)
            .filter(|r| !r.trim().is_empty())
            .ok_or_else(|| err(format!("{at} needs a non-empty string `reason`")))?;
        out.push(AcceptedChecksum {
            checksum: checksum.to_owned(),
            reason: reason.to_owned(),
        });
    }
    Ok(out)
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

    // ADR-0082: every reader that parses a manifest refuses a malformed amendment list, `migrate` and the static gate alike.
    accepted_prior_checksums(file, contents)?;

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
// ponytail: the nested `/* */` depth scan and the quoted-body scan put two blocks past clippy.toml's ceiling of
// 5 (§78.4 / G-M01-8); M01-6 refactors nothing, so the scanner keeps its allow. Upgrade: one helper per SQL
// lexical region when this tokenizer is next touched.
#[allow(clippy::excessive_nesting)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "d09c6b3d81a0c99c";

    /// ADR-0082: a recorded checksum passes only as the file's own or as a listed one. Fault: answer `Amended` for
    /// every unlisted value ⇒ the two `Drift` assertions are red.
    #[test]
    fn a_recorded_checksum_is_accepted_only_when_it_is_the_files_or_listed() {
        let list = [AcceptedChecksum {
            checksum: OLD.to_owned(),
            reason: "why".to_owned(),
        }];
        let now = "0123456789abcdef";
        assert_eq!(
            compare_recorded(now, now, &[]),
            RecordedChecksum::Same,
            "the file's own checksum"
        );
        assert_eq!(
            compare_recorded(now, OLD, &list),
            RecordedChecksum::Amended { reason: "why" }
        );
        assert_eq!(
            compare_recorded(now, "ffffffffffffffff", &list),
            RecordedChecksum::Drift,
            "a forged row outside the list"
        );
        assert_eq!(
            compare_recorded(now, OLD, &[]),
            RecordedChecksum::Drift,
            "no list, no acceptance"
        );
    }

    fn manifest_with(extra: &str) -> String {
        format!(
            "migration_id = \"0001_x\"\nclass = \"FORWARD_ONLY\"\nprecheck = \"select true\"\n\
             postcheck = \"select true\"\nrollback_or_forward_fix = \"n/a\"\n\
             backup_restore_requirement = \"n/a\"\n{extra}\n"
        )
    }

    /// ADR-0082: the list is optional, and a well-formed one parses through `parse_manifest` and the extractor alike.
    #[test]
    fn a_well_formed_amendment_list_parses_and_is_optional() {
        let none = manifest_with("");
        parse_manifest("0001_x.manifest.toml", &none).expect("no list is fine");
        assert!(
            accepted_prior_checksums("0001_x.manifest.toml", &none)
                .expect("absent key")
                .is_empty()
        );
        let one = manifest_with(&format!(
            "accepted_prior_checksums = [\n  {{ checksum = \"{OLD}\", reason = \"#137 aggregate ORDER BY constant\" }},\n]"
        ));
        parse_manifest("0001_x.manifest.toml", &one).expect("a well-formed list is fine");
        assert_eq!(
            accepted_prior_checksums("0001_x.manifest.toml", &one).expect("one entry"),
            [AcceptedChecksum {
                checksum: OLD.to_owned(),
                reason: "#137 aggregate ORDER BY constant".to_owned()
            }]
        );
    }

    /// ADR-0082: the parser refuses everything but `{ checksum, reason }` tables with a well-formed checksum and a
    /// non-blank reason, naming the file. Fault: drop the checksum shape test ⇒ the two checksum cases are red.
    #[test]
    fn a_malformed_amendment_list_is_refused_naming_the_file() {
        let cases = [
            (format!("accepted_prior_checksums = \"{OLD}\""), "array of"),
            (
                format!("accepted_prior_checksums = [\"{OLD}\"]"),
                "array of",
            ),
            (
                format!("accepted_prior_checksums = [{{ checksum = \"{OLD}\" }}]"),
                "non-empty",
            ),
            (
                format!("accepted_prior_checksums = [{{ checksum = \"{OLD}\", reason = \"  \" }}]"),
                "non-empty",
            ),
            (
                "accepted_prior_checksums = [{ checksum = \"D09C6B3D81A0C99C\", reason = \"r\" }]"
                    .to_owned(),
                "16 lowercase hex",
            ),
            (
                "accepted_prior_checksums = [{ checksum = \"d09c6b3d\", reason = \"r\" }]"
                    .to_owned(),
                "16 lowercase hex",
            ),
            (
                format!(
                    "accepted_prior_checksums = [{{ checksum = \"{OLD}\", reason = \"r\", note = \"x\" }}]"
                ),
                "closed set",
            ),
        ];
        for (extra, expect) in cases {
            let e =
                parse_manifest("0001_x.manifest.toml", &manifest_with(&extra)).expect_err(&extra);
            assert!(
                e.file == "0001_x.manifest.toml" && e.reason.contains(expect),
                "{extra}: {e}"
            );
        }
    }
}
