//! `xtask::architecture_check` — CI gate family for §53.3 / §55.1 / §48.0① / §59.1 / §78.3 architecture boundary lints.
//! Depends-on: crates=[humaux-domain, serde_json, toml]; services=[PostgreSQL(any) r=[ops.commit_seq_seq, ops.model_call_ledger, ops.provider_health_current, ops.reasoning_account_health_observations, ops.reasoning_provider_health_observations, private.continuity_facet_evidence_links, private.continuity_facet_memory_links, private.continuity_facet_slots, private.continuity_facet_versions, private.continuity_projects, private.memory_projects, private.memory_projects_live, private.publish_continuity_facet, private.read_continuity_project_storage_v1, private.register_continuity_project] w=[private.context_bindings, private.evidence_objects, private.evidence_projects, private.evidence_task_runs, private.memory_evidence, private.memory_projects, private.memory_records, private.processing_runs, private.task_binding_grants, projection.stream_log] x=[control.resolve_user_reasoning_admission, ops.reasoning_health_observation_reject_mutation, ops.reasoning_model_call_validate, private.publish_continuity_facet, private.read_continuity_project_storage_v1], subprocess(cargo)]; env=[CARGO_MANIFEST_DIR, GITHUB_ACTIONS, HUMAUX_NO_PYTHON_COMPOSE_JSON, HUMAUX_REQUIRE_DOCKER]; modules=[domain::affect, domain::confirm, domain::plan, domain::subject, xtask::serial_lane]
//! Called-by: [xtask::direction_table, xtask::known_red, xtask::main]
//! Invariants: [each sub-check reports pass/fail/not_applicable independently; not_applicable names the missing object (§57.1); exit 1 iff any sub-check fails]
//! Spec: Baseline §53.3; §55.1; §59.1; §78.3; §78; §52.4
//!
//! xtask `architecture-check` — the CI gate family for §53.3 (Outcome fallback rule +
//! positive sentinels), §55.1 / §48.0① / §59.1 (unique construction points), §78.3
//! (Workspace Dependency Rule), the §78 Architecture Boundary Lints, §52.4 G52-1, and the open-core
//! edition gates G-M01-1 / G-M01-2 (ADR-0073 D-B, ADR-0074), the crate boundary table G-M01-3 (M01 D5) and the real-path
//! fault gate G-M01-4 (M01 D4, ADR-0077).
//!
//! Every sub-check below is independent and prints its own three-state verdict
//! (`pass` / `fail` / `not_applicable`); `not_applicable` always names the missing object
//! (§57.1 第2条). The process exit code is 1 iff at least one sub-check `fail`ed —
//! `not_applicable` never fails the build, it is a legitimate state for an object whose
//! delivering Phase has not landed yet (§80.1.1).
//!
//! §80.1.1 registers the injected-fault records for the rules that don't yet have a home
//! in their own spec section: G80-1 (§53.3 规则3), G80-2 (§55.1), G80-4 (§16.2 — registered
//! below; `not_applicable` only while the `serving_version` definition is absent),
//! G80-20 (§67.4, out of this task's scope). G80-22 lives at §48.0①. G80-11's source_hash leg
//! lives at §1.3/§48.0 (T5.1) — same single-crate-convergence family as G80-22, G80-11's other
//! two legs (§1.12 tool schema, §7.5 classifier) are out of this task's scope. G59-3 lives at
//! §59.1. Each rule below cites its own §.
//!
//! G52-1 / G59-3 / G80-2 / G80-4 / G80-11 / G80-22 scan the **whole workspace root**
//! (`crates/` + `bins/` + `evals/` + `xtask/` + `migrations/`), not just `crates/`: §80.1.1 /
//! §48.0① / §59.1 / §52.4 all name `bins/*` / `evals/*` as required injection/scan territory.
//! [`walk_workspace_rs`] is the shared scan domain for those five — it excludes this file
//! itself ([`SELF_FILE`]) and strips every file's own `#[cfg(test)]` module
//! ([`strip_cfg_test_module`]), both documented
//! at their definitions below.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Absolute path to the workspace root, derived from `xtask`'s own manifest dir rather than
/// the process CWD — tests need this to be stable regardless of where `cargo test` is
/// invoked from; `run()` uses it too so both paths exercise identical logic.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// One sub-check's outcome. `Fail`/`NotApplicable` carry human-readable detail lines;
/// `NotApplicable`'s single `String` is always the missing object name (§57.1 第2条).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(Vec<String>),
    NotApplicable(String),
}

// ============================================================================
// shared fs helpers
// ============================================================================

/// Recursively collects every file under `dir` whose extension is in `exts`, skipping
/// `target`/`.git`/`node_modules`. Read errors on a subtree (permissions, races) are
/// swallowed the same way `config_check.rs::walk` does — a directory this can't read
/// contributes no files, it does not abort the whole scan.
fn walk_files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_files_rec(dir, exts, &mut out);
    out
}

fn walk_files_rec(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "node_modules") {
                continue;
            }
            walk_files_rec(&path, exts, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && exts.contains(&ext)
        {
            out.push(path);
        }
    }
}

/// This checker's own path, relative to workspace root. Excluded from the workspace-wide
/// construction/type-uniqueness scans below (§59.1 G59-3, §55.1 G80-2, §48.0① G80-22, §52.4
/// G52-1) once their scan domain widens past `crates/` to the whole workspace (§80.1.1 /
/// §48.0①/§52.4 all name `bins/*` / `evals/*` / xtask as required scan territory): this file's
/// own source necessarily contains the literal needle text those scans hunt for — both as the
/// needle arguments passed to [`count_construction_calls`] / [`find_construction_braces`]
/// themselves, and as this file's own `mod tests` fixture strings — so scanning it can only
/// ever produce false hits about itself, never a real violation in production code elsewhere.
/// This is not a loosened judgment: it excludes the auditor from auditing its own necessarily
/// self-quoting source, the same way a linter's own test fixtures are excluded from its own
/// lint run.
const SELF_FILE: &str = "xtask/src/architecture_check.rs";

/// Blanks out the first top-level `#[cfg(test)] mod ... { .. }` block in `source`, replacing
/// its non-newline bytes with spaces (char-by-char, so a multi-byte UTF-8 character is
/// replaced by exactly one space rather than corrupting the string) so every other line's
/// number is unaffected. Applied by [`walk_workspace_rs`] below: this codebase's xtask helper
/// crate legitimately writes fixture *strings* for its own unit tests that reuse real spec
/// vocabulary — e.g. `metrics_registry.rs`'s own `mod tests` defines a `pub fn build_request()`
/// fixture for its unrelated §80.2 metrics-registry tests, which textually collides with G80-2's
/// `RetrievalRequest`/`build_request` object-existence probe once the scan domain widens to
/// include xtask/. Without this, one checker's test fixtures would flip a *different* checker's
/// verdict. This does not hide a real violation: every four-check target in this codebase (see
/// `authority.rs`'s own `mod tests`, which only ever calls `Authority::new`) already routes its
/// own tests through the public constructor, never the raw struct literal — the rule these
/// checks enforce holds *inside* test code too, so stripping test-only text cannot turn a real
/// violation invisible, it only removes unrelated fixture noise.
///
/// ponytail: single top-level `mod tests` per file, matching this codebase's own rustfmt-output
/// convention (`metrics_registry.rs`'s own `#[cfg(test)]`-skip logic documents the identical
/// assumption for its spec-fixture line scan) — a file with two would only have its first
/// block stripped. Upgrade to a loop if that convention ever changes.
fn strip_cfg_test_module(source: &str) -> String {
    // Skip past `#[cfg(test)]` occurrences that are themselves inside a `//` comment (e.g. a
    // doc comment quoting the attribute as example text, not applying it) — same false-match
    // shape every other scan in this module guards against with `line_is_comment_at`.
    let mut search = 0usize;
    let attr_rel = loop {
        let Some(rel) = source[search..].find("#[cfg(test)]") else {
            return source.to_string();
        };
        let idx = search + rel;
        if !line_is_comment_at(source, idx) {
            break idx;
        }
        search = idx + "#[cfg(test)]".len();
    };
    let Some(mod_rel) = source[attr_rel..].find("mod ") else {
        return source.to_string();
    };
    let mod_kw = attr_rel + mod_rel;
    let Some(brace_rel) = source[mod_kw..].find('{') else {
        return source.to_string();
    };
    let open = mod_kw + brace_rel;
    let Some(close) = matching_brace_end(source, open) else {
        return source.to_string();
    };
    source
        .char_indices()
        .map(|(i, c)| {
            if i >= open && i < close && c != '\n' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Every `.rs` file in the whole workspace (skipping target/.git/node_modules like
/// [`walk_files`]) with its `#[cfg(test)]` module stripped ([`strip_cfg_test_module`]) and
/// [`SELF_FILE`] excluded outright (its production code, not just its tests, quotes these
/// checks' own needle strings — see [`SELF_FILE`]'s doc) — the shared scan domain for the four
/// workspace-wide construction/type-uniqueness checks.
fn walk_workspace_rs(root: &Path) -> Vec<(PathBuf, String)> {
    read_files(&walk_files(root, &["rs"]))
        .into_iter()
        .filter(|(p, _)| display(root, p) != SELF_FILE)
        .map(|(p, s)| {
            let stripped = strip_cfg_test_module(&s);
            (p, stripped)
        })
        .collect()
}

fn read_files(paths: &[PathBuf]) -> Vec<(PathBuf, String)> {
    paths
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok().map(|s| (p.clone(), s)))
        .collect()
}

fn display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// Whether the line containing byte offset `idx` in `source` is a `//` comment line
/// (trimmed prefix starts with `//`). Cheap guard against grepping doc-comment prose that
/// merely *mentions* a pattern instead of containing real code (§53.3 / §59.1 G59-3 scans
/// below both need this — a spec-quoting comment must never count as a hit).
fn line_is_comment_at(source: &str, idx: usize) -> bool {
    let line_start = source[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
    source[line_start..]
        .lines()
        .next()
        .unwrap_or("")
        .trim_start()
        .starts_with("//")
}

/// Byte offset one past the `}` that closes the `{` at `open_brace_idx` (which must itself
/// be `{`), found by naive depth counting over raw bytes.
///
/// ponytail: this is not a Rust parser — it does not know about strings, chars, or comments,
/// so a literal `{`/`}` inside a string constant would desync the count. None of this
/// module's targets (fn bodies, `degrade_code! {}`, `impl` blocks) contain brace characters
/// inside string literals today; upgrade to `syn` if that ever changes.
fn matching_brace_end(source: &str, open_brace_idx: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut i = open_brace_idx;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ============================================================================
// §53.3 规则1 + 规则3: Outcome<_> fallback scan, shared by real code and sentinels
// ============================================================================

/// Scans `source` for `fn`s whose signature contains the literal text `Outcome<` and, within
/// each such fn's body (nested closures included — §53.3 规则1 says "函数体内", not "顶层
/// 语句"), flags `unwrap_or_default()` / `unwrap_or(` / `Ok(Vec::new())` / `Ok(None)` unless
/// the same line also calls `abstain(` (i.e. is itself the abstain call chain).
///
/// ponytail: literal-text matching on `Outcome<`, not type resolution — a fn returning the
/// `Response<T>` alias (`Result<Outcome<T>, ErrorCode>`) is invisible to this scan because
/// its signature text says `Response<T>`, not `Outcome<`. §53.3 registers this as a grep-
/// style check ("forbidden import grep with positive sentinels", §78.3); upgrade to alias-
/// aware matching if `Response<T>`-returning functions start actually using bare fallbacks.
pub fn scan_outcome_fallback_violations(display_path: &str, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find("fn ") {
        let fn_kw = search_from + rel;
        let after = &source[fn_kw..];
        let brace_opt = after.find('{');
        let semi_opt = after.find(';');
        // A `;` reached before the next `{` means this is a body-less declaration (a trait
        // method signature, `fn a(&self) -> Outcome<i32>;`) — its own "signature" text must
        // not be treated as ending at some later, unrelated fn's opening brace, and that
        // later fn's real body must not be misattributed to this bodyless one.
        let is_bodyless = match (semi_opt, brace_opt) {
            (Some(s), Some(b)) => s < b,
            (Some(_), None) => true,
            _ => false,
        };
        if is_bodyless {
            search_from = fn_kw + semi_opt.expect("is_bodyless implies semi_opt is Some") + 1;
            continue;
        }
        let Some(brace_rel) = brace_opt else {
            break;
        };
        let open_brace = fn_kw + brace_rel;
        let signature = &source[fn_kw..open_brace];
        // A stray '}' before the next '{' means we scanned across some other block (e.g.
        // "fn" appearing inside a comment/string) rather than a real signature — skip it.
        if !signature.contains('}')
            && signature.contains("Outcome<")
            && !line_is_comment_at(source, fn_kw)
            && let Some(close) = matching_brace_end(source, open_brace)
        {
            let body = &source[open_brace..close];
            let body_start_line = source[..open_brace].matches('\n').count() + 1;
            for (i, line) in body.lines().enumerate() {
                // §53.3 规则1 targets real fallback calls, not prose that merely mentions
                // them (e.g. a comment citing this very rule inside the fn body it documents).
                if line.trim_start().starts_with("//") {
                    continue;
                }
                let has_fallback = line.contains("unwrap_or_default()")
                    || line.contains("unwrap_or(")
                    || line.contains("Ok(Vec::new())")
                    || line.contains("Ok(None)");
                if has_fallback && !line.contains("abstain(") {
                    violations.push(format!("{display_path}:{}", body_start_line + i));
                }
            }
            search_from = close;
            continue;
        }
        search_from = open_brace + 1;
    }
    violations
}

/// §53.3 规则1: no `crates/**/*.rs` function returning `Outcome<_>` may fall back to a
/// swallowed-error value outside `abstain()`'s call chain.
pub fn rule1_forbidden_fallback(root: &Path) -> Verdict {
    let crates_dir = root.join("crates");
    let files = read_files(&walk_files(&crates_dir, &["rs"]));
    let mut violations = Vec::new();
    for (path, source) in &files {
        violations.extend(scan_outcome_fallback_violations(
            &display(root, path),
            source,
        ));
    }
    if violations.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(violations)
    }
}

/// §53.3 规则3: exactly 3 `.sample` files must live under `crates/testkit/sentinels/`, and
/// [`scan_outcome_fallback_violations`] must hit each of them **exactly** once — not "3 hits
/// somewhere in the directory total". Aggregating only the total would let one sentinel file
/// go missing while another one over-hits and still read as 3; the spec's "3 个【本该命中】的
/// 样本文件…恰好命中 3 次" names the file dimension, not just the sum, so this checks both.
pub fn rule3_positive_sentinels(root: &Path) -> Verdict {
    let sentinels_dir = root.join("crates/testkit/sentinels");
    let files = read_files(&walk_files(&sentinels_dir, &["sample"]));
    if files.len() != 3 {
        return Verdict::Fail(vec![format!(
            "expected exactly 3 `.sample` files under crates/testkit/sentinels/, found {}: {:?}",
            files.len(),
            files
                .iter()
                .map(|(p, _)| display(root, p))
                .collect::<Vec<_>>()
        )]);
    }
    let mut bad = Vec::new();
    for (path, source) in &files {
        let disp = display(root, path);
        let hits = scan_outcome_fallback_violations(&disp, source);
        if hits.len() != 1 {
            bad.push(format!(
                "{disp}: expected exactly 1 hit, found {}: {:?}",
                hits.len(),
                hits
            ));
        }
    }
    if bad.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(bad)
    }
}

// ============================================================================
// §53.3 规则2: |DegradeCode variants| == |testkit/tests/fault/*.rs| by name
// ============================================================================

/// PascalCase → snake_case (`RerankModelMismatch` → `rerank_model_mismatch`), the §53.4
/// file-naming rule (`lower(fold(变体名))`, distinct from `degrade::fold`'s SCREAMING_SNAKE
/// output — same insertion rule, different case target).
pub fn pascal_to_snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Extracts the variant identifier list from a `degrade_code! { ... }` macro invocation
/// (as defined in `crates/telemetry/src/degrade.rs`) — doc-comment lines (`///`) are
/// skipped, each remaining non-empty trimmed line (minus its trailing comma) is one variant.
pub fn parse_degrade_variant_names(source: &str) -> Vec<String> {
    let Some(kw_rel) = source.find("degrade_code! {") else {
        return Vec::new();
    };
    let open_brace = kw_rel + "degrade_code! {".len() - 1;
    let Some(close) = matching_brace_end(source, open_brace) else {
        return Vec::new();
    };
    let block = &source[open_brace + 1..close - 1];
    let mut out = Vec::new();
    for line in block.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("///") {
            continue;
        }
        let t = t.trim_end_matches(',');
        if t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && t.chars().all(|c| c.is_ascii_alphanumeric())
        {
            out.push(t.to_string());
        }
    }
    out
}

/// §53.3 规则2 pure comparator — covers 2 of the rule's 3 named counts (`|DegradeCode variants|`
/// vs. `|testkit/tests/fault/*.rs|`). The third count (live `degrade_total{code}` label
/// cardinality) is a runtime Prometheus fact this source-only xtask check cannot observe; its
/// static proxy — `fold` must be injective over the live variant set, so the label cardinality
/// can never silently fall below the variant count via an `as_str()`-for-`fold()` swap — lives
/// as `fold_is_injective_over_all_variants` in `crates/telemetry/src/degrade.rs`, not here. Do
/// not read this sub-check's name as promising all three counts.
/// `variant_names` vs. the set of `.rs` file stems present under `testkit/tests/fault/`.
/// Reports both directions of mismatch (missing variant files *and* orphaned fault files)
/// rather than only a bare count, so a name-level typo (equal counts, wrong names) is still
/// caught, not just a count drift.
pub fn rule2_check(variant_names: &[String], fault_stems: &BTreeSet<String>) -> Verdict {
    let expected: BTreeSet<String> = variant_names.iter().map(|v| pascal_to_snake(v)).collect();
    let missing: Vec<&String> = expected.difference(fault_stems).collect();
    let extra: Vec<&String> = fault_stems.difference(&expected).collect();
    if missing.is_empty() && extra.is_empty() && variant_names.len() == fault_stems.len() {
        return Verdict::Pass;
    }
    let mut details = vec![format!(
        "|DegradeCode variants|={} != |testkit/tests/fault/*.rs|={}",
        variant_names.len(),
        fault_stems.len()
    )];
    if !missing.is_empty() {
        details.push(format!(
            "missing object: fault test file(s) for variant(s) {}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !extra.is_empty() {
        details.push(format!(
            "unexpected fault file(s) with no matching DegradeCode variant: {}",
            extra
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Verdict::Fail(details)
}

fn rule2_degrade_fault_parity(root: &Path) -> Verdict {
    let degrade_path = root.join("crates/telemetry/src/degrade.rs");
    let Ok(degrade_src) = fs::read_to_string(&degrade_path) else {
        return Verdict::Fail(vec![format!("cannot read {}", degrade_path.display())]);
    };
    let variants = parse_degrade_variant_names(&degrade_src);
    let fault_dir = root.join("crates/testkit/tests/fault");
    let stems: BTreeSet<String> = walk_files(&fault_dir, &["rs"])
        .iter()
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(String::from))
        .collect();
    rule2_check(&variants, &stems)
}

// ============================================================================
// §52.4 G52-1: only ErrorCode may serialize at an `error_code` position
// ============================================================================

/// Scans `source` for `error_code\s*:\s*<Type>` occurrences (struct field decls, struct
/// literals, and fn params alike — text-level, not scope-aware) and returns every PascalCase
/// type name found there. Lowercase captures (`error_code: code`, a value not a type) are
/// filtered out by construction: Rust type/enum names are PascalCase by convention, so this
/// alone tells a type occupying the position apart from a variable merely named `code`.
///
/// ponytail: this targets the flat `error_code: ErrorCode` field convention this codebase
/// actually uses today, not a nested `error: { code: ... }` JSON shape — no serde-tagged
/// response envelope exists yet to grep for. Revisit when §23's envelope type lands.
pub fn find_error_code_field_types(source: &str) -> Vec<String> {
    let needle = "error_code";
    let mut out = Vec::new();
    let mut start = 0usize;
    while let Some(rel) = source[start..].find(needle) {
        let idx = start + rel;
        if line_is_comment_at(source, idx) {
            start = idx + needle.len();
            continue;
        }
        let after = &source[idx + needle.len()..];
        if let Some(rest) = after.trim_start().strip_prefix(':') {
            let rest = rest.trim_start();
            let ty: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if ty.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                out.push(ty);
            }
        }
        start = idx + needle.len();
    }
    out
}

/// G52-1 pure comparator: the set of types found at an `error_code` position must be exactly
/// `{"ErrorCode"}` — anything else is a second enum sharing the slot (the violation the spec
/// injection names); an empty set means the positive control itself didn't fire, which is
/// indistinguishable from "matcher is broken" (§59.1 G59-3 同款「写成 <= 1 时又是一个恒真
/// 闸」), so that must fail too, not silently pass.
pub fn g52_1_check(types_found: &BTreeSet<String>) -> Verdict {
    let mut expected = BTreeSet::new();
    expected.insert("ErrorCode".to_string());
    if types_found == &expected {
        Verdict::Pass
    } else if types_found.is_empty() {
        Verdict::Fail(vec![
            "positive control missing: no `error_code: ErrorCode` occurrence found anywhere \
             in the workspace — matcher is broken, not the codebase"
                .to_string(),
        ])
    } else {
        let extra: Vec<&String> = types_found.difference(&expected).collect();
        Verdict::Fail(vec![format!(
            "type(s) other than ErrorCode found at an `error_code` position: {:?}",
            extra
        )])
    }
}

fn g52_1_error_code_uniqueness(root: &Path) -> Verdict {
    // §52.4 G52-1 names "扫全 workspace" explicitly, not just crates/.
    let files = walk_workspace_rs(root);
    let mut types_found = BTreeSet::new();
    for (_, source) in &files {
        types_found.extend(find_error_code_field_types(source));
    }
    g52_1_check(&types_found)
}

// ============================================================================
// §59.1 G59-3: exactly one `Authority { .. }` struct literal, inside authority.rs::new()
// ============================================================================

/// Word-bounded "`word` immediately (after whitespace) followed by `{`" scan over
/// `[search_start, search_end)` of `source`, skipping declaration-shaped and comment-line
/// occurrences. `is_declaration` receives the trimmed text immediately preceding the match.
/// Shared by the `Authority {` and (within `impl Authority` scope only) `Self {` scans below —
/// same shape, different word and declaration predicate.
fn find_construction_braces(
    source: &str,
    word: &str,
    search_start: usize,
    search_end: usize,
    is_declaration: impl Fn(&str) -> bool,
) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut start = search_start;
    while start < search_end {
        let Some(rel) = source[start..search_end].find(word) else {
            break;
        };
        let idx = start + rel;
        let before_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
        let after_idx = idx + word.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok
            && after_ok
            && !is_declaration(source[..idx].trim_end())
            && source[after_idx..].trim_start().starts_with('{')
            && !line_is_comment_at(source, idx)
        {
            out.push(idx);
        }
        start = idx + word.len();
    }
    out
}

/// Every `impl Authority { .. }` block's `(open_brace, close_brace)` byte range in `source`
/// (word-bounded, so `impl AuthorityPolicy` is not mistaken for it — same convention as
/// [`authority_new_body_range`] below). Trait impls (`impl PartialOrd for Authority`) are not
/// matched: the token immediately after `impl` there is the trait name, not `Authority`.
fn impl_authority_block_ranges(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let needle = "impl Authority";
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(needle) {
        let idx = search + rel;
        let after_idx = idx + needle.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if after_ok && let Some(brace_rel) = source[after_idx..].find('{') {
            let open = after_idx + brace_rel;
            if let Some(close) = matching_brace_end(source, open) {
                out.push((open, close));
            }
        }
        search = idx + needle.len();
    }
    out
}

/// Finds every `Authority {` struct-literal site in `source`, plus every `Self {` site that
/// falls inside an `impl Authority { .. }` block (`Self` only resolves to `Authority` there —
/// §59.1 G59-3's real construction point, `authority.rs::Authority::new`, is free to spell its
/// return as `Ok(Self { .. })`, the idiomatic form `clippy::use_self` prefers, and a matcher
/// that only recognizes the bare `Authority { .. }` spelling silently reads that as "0 hits",
/// which prints as the unrelated, misleading "not yet landed" reason instead of a real bug
/// report). `AuthorityClass {` / `AuthorityStatus {` / `AuthorityPolicy {` don't match (word
/// bounds); comment lines are skipped both ways.
pub fn find_authority_struct_literals(source: &str) -> Vec<usize> {
    let mut hits = find_construction_braces(source, "Authority", 0, source.len(), |prefix| {
        // `struct Authority {` / `impl Authority {` are declarations, not construction sites;
        // `-> Authority {` is a fn signature whose own body brace happens to follow the
        // return-type name, same false-positive shape as `count_construction_calls` guards.
        prefix.ends_with("struct") || prefix.ends_with("impl") || prefix.ends_with("->")
    });
    for (open, close) in impl_authority_block_ranges(source) {
        hits.extend(find_construction_braces(
            source,
            "Self",
            open,
            close,
            |prefix| {
                // `-> Self {` is `Authority::new`'s own fn signature ending in its body brace, not
                // a `Self { .. }` struct literal — the brace belongs to the fn body that follows.
                prefix.ends_with("->")
            },
        ));
    }
    hits.sort_unstable();
    hits
}

/// Byte range of `Authority::new`'s fn body within `source`, if `source` contains both an
/// `impl Authority { .. }` block (word-bounded, so `impl AuthorityPolicy` is not mistaken
/// for it) and a `fn new(` inside it.
fn authority_new_body_range(source: &str) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let needle = "impl Authority";
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(needle) {
        let idx = search + rel;
        let after_idx = idx + needle.len();
        let after_ok = after_idx >= bytes.len() || !is_ident_byte(bytes[after_idx]);
        if after_ok {
            let impl_brace_rel = source[after_idx..].find('{')?;
            let impl_open = after_idx + impl_brace_rel;
            let impl_close = matching_brace_end(source, impl_open)?;
            let impl_body = &source[impl_open..impl_close];
            if let Some(fn_rel) = impl_body.find("fn new(") {
                let fn_kw = impl_open + fn_rel;
                if let Some(brace_rel) = source[fn_kw..impl_close].find('{') {
                    let fn_open = fn_kw + brace_rel;
                    if let Some(fn_close) = matching_brace_end(source, fn_open) {
                        return Some((fn_open, fn_close));
                    }
                }
            }
            return None;
        }
        search = idx + needle.len();
    }
    None
}

/// G59-3 pure comparator: exactly one `Authority {`/`Self {}` construction site in the whole
/// workspace, and it must sit inside `authority.rs`'s `Authority::new` body — the § assertion
/// is written `== 1`, never `<= 1` (a matcher that hits 0 due to a typo would pass `<= 1`
/// silently, the exact "恒真闸" shape §59.1 calls out).
pub fn g59_3_check(
    hits: &[(String, usize)],
    authority_rs_new_range: Option<(usize, usize)>,
) -> Verdict {
    match hits.len() {
        // 0 hits is ambiguous by construction: it means either "Authority::new isn't landed
        // yet" or "it landed, but the matcher failed to recognize the shape it was written
        // in" — the message must not assert either cause as fact (§53.3/§59.1 同款「恒真闸」
        // 反例：把「matcher 坏了」误报成「预期状态」本身就是一次假报告).
        0 => Verdict::Fail(vec![
            "missing object: no `Authority {{ .. }}`/`Self {{ .. }}` (inside `impl Authority`) \
             construction site found anywhere in the scanned workspace — either \
             Authority::new is not yet landed, or it landed in a shape this matcher does not \
             recognize; both must be treated as red, never assumed"
                .to_string(),
        ]),
        1 => {
            let (file, offset) = &hits[0];
            let in_new = file.ends_with("authority.rs")
                && authority_rs_new_range.is_some_and(|(s, e)| (s..e).contains(offset));
            if in_new {
                Verdict::Pass
            } else {
                Verdict::Fail(vec![format!(
                    "the sole `Authority {{ .. }}` literal is at {file}, not inside \
                     authority.rs::Authority::new()"
                )])
            }
        }
        n => Verdict::Fail(vec![format!(
            "expected exactly 1 `Authority {{ .. }}` construction site, found {n}"
        )]),
    }
}

fn g59_3_authority_construction_point(root: &Path) -> Verdict {
    // Whole workspace, not just crates/domain: §59.1 G59-3 注错a names `evals/` as the
    // injection point for the second construction site, which lives outside crates/ entirely.
    let files = walk_workspace_rs(root);
    let mut hits = Vec::new();
    let mut new_range = None;
    for (path, source) in &files {
        let disp = display(root, path);
        for offset in find_authority_struct_literals(source) {
            hits.push((disp.clone(), offset));
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("authority.rs") {
            new_range = authority_new_body_range(source);
        }
    }
    g59_3_check(&hits, new_range)
}

// ============================================================================
// §78.3 Workspace Dependency Rule
// ============================================================================

/// crates that `humaux-domain` may never depend on: §78.3's verbatim seven-item list (axum,
/// sqlx, qdrant client, reqwest, dashscope, stripe, openbao client) plus the separate
/// Architecture Boundary Lints line "Domain crate cannot depend on adapters/protocol/runtime"
/// (`humaux-adapters` / `humaux-protocol` / `humaux-runtime` — the last does not exist as a
/// workspace member yet, forbidding it now is still correct: domain trivially depends on
/// nothing named that), plus a substring catch-all for "任何 SDK", since provider SDKs
/// multiply faster than this list can be hand-maintained. `tokio-postgres` / `aws-sdk-s3` are
/// not in §78.3's literal text but are strictly redundant with `sqlx` / the `sdk` catch-all —
/// kept as extra, non-conflicting protection, not removed.
///
/// ponytail: the substring check is `name.to_lowercase().contains("sdk")` — cheap and
/// catches `aws-sdk-s3` / future `*-sdk` crates without enumerating them, at the cost of a
/// false positive on some hypothetical crate that merely has "sdk" in its name without being
/// one. No such crate exists in this dependency tree today.
const DOMAIN_FORBIDDEN_DEPS: &[&str] = &[
    "sqlx",
    "axum",
    "reqwest",
    "qdrant-client",
    "tokio-postgres",
    "aws-sdk-s3",
    "stripe",
    "openbao",
    "dashscope",
    "humaux-adapters",
    "humaux-protocol",
    "humaux-runtime",
];

/// Pure §78.3 comparator over a parsed `cargo metadata --no-deps` document — takes the JSON
/// text directly so tests can inject a fixture without shelling out to `cargo`.
///
/// `humaux-application` is deliberately not checked here: no spec line or ADR grounds a
/// forbidden-dependency rule for it (§78's only frozen line names `domain`, not
/// `application`) — inventing one and shipping it as if §78.3 required it would be exactly the
/// kind of ungrounded judgment this checker exists to catch elsewhere. Add it back only once a
/// spec section or `docs/adr/` entry actually says so.
pub fn dependency_rule_from_metadata_json(metadata_json: &str) -> Verdict {
    let parsed: serde_json::Value = match serde_json::from_str(metadata_json) {
        Ok(v) => v,
        Err(e) => return Verdict::Fail(vec![format!("cargo metadata output not valid JSON: {e}")]),
    };
    let Some(packages) = parsed.get("packages").and_then(|p| p.as_array()) else {
        return Verdict::Fail(vec![
            "cargo metadata output has no `packages` array".to_string(),
        ]);
    };

    let mut violations = Vec::new();
    check_package_deps(
        packages,
        "humaux-domain",
        DOMAIN_FORBIDDEN_DEPS,
        |name| name.to_lowercase().contains("sdk"),
        &mut violations,
    );

    if violations.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(violations)
    }
}

fn check_package_deps(
    packages: &[serde_json::Value],
    package_name: &str,
    forbidden_exact: &[&str],
    forbidden_pred: impl Fn(&str) -> bool,
    violations: &mut Vec<String>,
) {
    let Some(pkg) = packages
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(package_name))
    else {
        // Package not present in this metadata document — the matcher's target went missing
        // (renamed, dropped from the workspace, or a wrong `--no-deps` fixture was handed in).
        // §59.1 G59-3 同款「恒真闸」: silently returning here would make this half of the gate
        // permanently, invisibly green — that is a red, not an inapplicable check, because
        // `humaux-domain` is a frozen workspace member name (§58), not an optional object.
        violations.push(format!(
            "package `{package_name}` not found in cargo metadata output — matcher target \
             missing, not a clean dependency graph"
        ));
        return;
    };
    let deps = pkg
        .get("dependencies")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    for dep in &deps {
        let Some(dep_name) = dep.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        if forbidden_exact.contains(&dep_name) || forbidden_pred(dep_name) {
            violations.push(format!(
                "{package_name} depends on forbidden crate {dep_name}"
            ));
        }
    }
}

/// `cargo metadata --no-deps` of the workspace at `root`, as text — the one spawn behind §78.3 and the
/// two edition gates below. `Err` is the `Fail` detail line.
fn workspace_metadata_json(root: &Path) -> Result<String, String> {
    // dep: subprocess(cargo) — cargo metadata, workspace dependency graph read
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output();
    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(o) => Err(format!(
            "cargo metadata exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        )),
        Err(e) => Err(format!("failed to run cargo metadata: {e}")),
    }
}

fn dependency_rule_check(root: &Path) -> Verdict {
    match workspace_metadata_json(root) {
        Ok(json) => dependency_rule_from_metadata_json(&json),
        Err(e) => Verdict::Fail(vec![e]),
    }
}

// ============================================================================
// M01 D1 / ADR-0074 — edition metadata: G-M01-1 (workspace members), G-M01-2 (core never depends on cloud)
// ============================================================================

/// Crate -> home-module rows G-M01-1 compares the workspace against (M01 D1, ADR-0074 D-B).
const MODULE_OWNERSHIP_FILE: &str = "docs/architecture/module_ownership.toml";

/// Edition value of the open-source crates (ADR-0073 D-A).
const EDITION_CORE: &str = "core";

/// Edition value of the cloud-only crates (ADR-0073 D-A).
const EDITION_CLOUD: &str = "cloud";

/// The closed vocabulary of `[package.metadata.humaux] edition` (ADR-0073 D-A, ADR-0074 D-A).
const EDITIONS: [&str; 2] = [EDITION_CORE, EDITION_CLOUD];

/// Highest module id the ownership rows may name (M01 design note: M01..M28).
const MODULE_ID_MAX: u8 = 28;

/// `Mnn` with `nn` in `01..=MODULE_ID_MAX`.
fn is_module_id(s: &str) -> bool {
    s.len() == 3
        && s.starts_with('M')
        && s[1..].bytes().all(|b| b.is_ascii_digit())
        && matches!(s[1..].parse::<u8>(), Ok(1..=MODULE_ID_MAX))
}

/// The `packages` array of a `cargo metadata --no-deps` document.
fn metadata_packages(metadata_json: &str) -> Result<Vec<serde_json::Value>, String> {
    let mut parsed: serde_json::Value = serde_json::from_str(metadata_json)
        .map_err(|e| format!("cargo metadata output not valid JSON: {e}"))?;
    match parsed.get_mut("packages").map(serde_json::Value::take) {
        Some(serde_json::Value::Array(packages)) => Ok(packages),
        _ => Err("cargo metadata output has no `packages` array".to_string()),
    }
}

/// `name` of one metadata package.
fn package_name(pkg: &serde_json::Value) -> Option<&str> {
    pkg.get("name")?.as_str()
}

/// `[package.metadata.humaux] edition` of one metadata package, when it is a string.
fn declared_edition(pkg: &serde_json::Value) -> Option<&str> {
    pkg.pointer("/metadata/humaux/edition")?.as_str()
}

/// G-M01-1 pure comparator (M01 D1; spec §58 "workspace tree is a contract"): every workspace member declares
/// an edition in [`EDITIONS`], and the `[crates]` keys of `ownership_toml` equal the member set, each value a
/// module id. No `NotApplicable` leg: both objects are delivered together with this gate, so a missing or
/// unparsable one is a regression, not an undelivered object (§57.1 第2条). Injected-fault record: ADR-0074.
pub fn workspace_members_from(metadata_json: &str, ownership_toml: &str) -> Verdict {
    let packages = match metadata_packages(metadata_json) {
        Ok(p) => p,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    let mut problems = Vec::new();
    let mut members = BTreeSet::new();
    for pkg in &packages {
        let Some(name) = package_name(pkg) else {
            problems.push("cargo metadata lists a package without a `name`".to_string());
            continue;
        };
        members.insert(name);
        match declared_edition(pkg) {
            Some(e) if EDITIONS.contains(&e) => {}
            Some(e) => problems.push(format!(
                "package `{name}` declares unknown edition `{e}` in [package.metadata.humaux] (expected one of {EDITIONS:?})"
            )),
            None => problems.push(format!(
                "package `{name}` has no [package.metadata.humaux] edition (expected one of {EDITIONS:?})"
            )),
        }
    }
    if members.is_empty() {
        problems
            .push("cargo metadata lists no workspace package (a vacuous member check)".to_string());
    }
    let rows = match toml::from_str::<toml::Value>(ownership_toml) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("{MODULE_OWNERSHIP_FILE} is not valid TOML: {e}"));
            return Verdict::Fail(problems);
        }
    };
    let Some(rows) = rows.get("crates").and_then(|c| c.as_table()) else {
        problems.push(format!("{MODULE_OWNERSHIP_FILE} has no [crates] table"));
        return Verdict::Fail(problems);
    };
    for (name, module) in rows {
        if !module.as_str().is_some_and(is_module_id) {
            problems.push(format!(
                "{MODULE_OWNERSHIP_FILE}: row `{name}` has module {module} (expected M01..M{MODULE_ID_MAX})"
            ));
        }
        if !members.contains(name.as_str()) {
            problems.push(format!(
                "{MODULE_OWNERSHIP_FILE}: row `{name}` names no workspace member"
            ));
        }
    }
    for name in members.iter().filter(|m| !rows.contains_key(**m)) {
        problems.push(format!(
            "workspace member `{name}` has no row in {MODULE_OWNERSHIP_FILE}"
        ));
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// G-M01-2 pure comparator (ADR-0073 D-B; M01 design §4): no `edition = "core"` package may depend on an
/// `edition = "cloud"` package through a normal, dev or build dependency — optional, renamed or
/// target-specific or not; cloud may depend on core. Direct edges of every core package suffice by induction
/// over the member graph: a transitive core -> cloud path starts with a core -> X edge, X cloud or X core with
/// its own offending edge. `cargo metadata --no-deps` lists every declared edge (the `name` field is the
/// package name even when the dependency is renamed). Fail-closed on shape: a core package without a
/// `dependencies` array or with a nameless dependency, and a core path dependency that is not a workspace
/// member (the induction needs a member-closed graph), are violations, never skips. `NotApplicable` while no
/// package is cloud (the expected state in the open-source repository after the split, ADR-0073 D-D).
/// Injected-fault record: ADR-0074.
// ponytail: crate-granular — cloud-to-be files inside core crates are invisible here (the shrink-only file
// ledger of card M01-5 tracks them); packages with a missing or unknown edition are skipped and rely on G-M01-1
// being green in the same run; member-closure of the graph rests on the non-member path-dependency violation
// below (upgrade: file-level ledger for the first, one full `cargo metadata` for the rest).
pub fn core_cloud_edges_from(metadata_json: &str) -> Verdict {
    let packages = match metadata_packages(metadata_json) {
        Ok(p) => p,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    let cloud: BTreeSet<&str> = packages
        .iter()
        .filter(|p| declared_edition(p) == Some(EDITION_CLOUD))
        .filter_map(package_name)
        .collect();
    if cloud.is_empty() {
        return Verdict::NotApplicable(format!("package with edition = \"{EDITION_CLOUD}\""));
    }
    let members: BTreeSet<&str> = packages.iter().filter_map(package_name).collect();
    let mut violations = Vec::new();
    for pkg in &packages {
        let Some(name) = package_name(pkg) else {
            violations.push("cargo metadata lists a package without a `name`".to_string());
            continue;
        };
        if declared_edition(pkg) == Some(EDITION_CORE) {
            violations.extend(core_package_edge_violations(name, pkg, &cloud, &members));
        }
    }
    if violations.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(violations)
    }
}

/// G-M01-2 violation lines of one core package: edges to `cloud` packages, path dependencies outside
/// `members`, and a malformed dependency list.
fn core_package_edge_violations(
    name: &str,
    pkg: &serde_json::Value,
    cloud: &BTreeSet<&str>,
    members: &BTreeSet<&str>,
) -> Vec<String> {
    let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) else {
        return vec![format!(
            "core package `{name}` has no `dependencies` array in cargo metadata (a missing list cannot prove the absence of a cloud edge)"
        )];
    };
    let mut out = Vec::new();
    for dep in deps {
        let Some(dep_name) = dep.get("name").and_then(|n| n.as_str()) else {
            out.push(format!(
                "core package `{name}` lists a dependency without a `name`"
            ));
            continue;
        };
        if dep.get("path").is_some_and(|p| !p.is_null()) && !members.contains(dep_name) {
            out.push(format!(
                "core package `{name}` has a path dependency on `{dep_name}`, which is not a workspace member (G-M01-2 needs a member-closed graph)"
            ));
        }
        if cloud.contains(dep_name) {
            let kind = dep.get("kind").and_then(|k| k.as_str()).unwrap_or("normal");
            let mut qualifiers = String::new();
            if dep.get("optional").and_then(|o| o.as_bool()) == Some(true) {
                qualifiers.push_str(", optional");
            }
            if let Some(alias) = dep.get("rename").and_then(|r| r.as_str()) {
                qualifiers.push_str(&format!(", renamed `{alias}`"));
            }
            if let Some(target) = dep.get("target").and_then(|t| t.as_str()) {
                qualifiers.push_str(&format!(", target `{target}`"));
            }
            out.push(format!(
                "core package `{name}` depends on cloud package `{dep_name}` ({kind} dependency{qualifiers}; ADR-0073 D-B: cloud may depend on core, never the reverse)"
            ));
        }
    }
    out
}

/// G-M01-1 over the real workspace.
fn m01_1_workspace_members(root: &Path) -> Verdict {
    let metadata = match workspace_metadata_json(root) {
        Ok(m) => m,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    match fs::read_to_string(root.join(MODULE_OWNERSHIP_FILE)) {
        Ok(rows) => workspace_members_from(&metadata, &rows),
        Err(e) => Verdict::Fail(vec![format!("{MODULE_OWNERSHIP_FILE} unreadable: {e}")]),
    }
}

/// G-M01-2 over the real workspace.
fn m01_2_core_cloud_edges(root: &Path) -> Verdict {
    match workspace_metadata_json(root) {
        Ok(json) => core_cloud_edges_from(&json),
        Err(e) => Verdict::Fail(vec![e]),
    }
}

// ============================================================================
// M01 D5 — G-M01-3: crate boundary table (§78 Boundary Lints, generalising the §78.3 domain rule)
// ============================================================================

/// Ledger file of known violations; the `[[crate_boundary]]` section is read here and evaluated by `known-red`.
const KNOWN_RED_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/known_red.toml");

/// One row of the crate-boundary table: the dependency `dep` may be declared only by the `allowed_in` packages.
struct BoundaryRule {
    dep: &'static str,
    allowed_in: &'static [&'static str],
    /// A `[dev-dependencies]` entry is "testing" (§78 sqlx line) and is not counted.
    dev_exempt: bool,
    /// Also match `<dep>-*` (sqlx-core, sqlx-postgres, ...): a direct dependency on a sub-crate is the same access.
    family: bool,
    why: &'static str,
}

impl BoundaryRule {
    /// Whether the dependency named `name` falls under this row.
    fn matches(&self, name: &str) -> bool {
        name == self.dep
            || (self.family
                && name
                    .strip_prefix(self.dep)
                    .is_some_and(|rest| rest.starts_with('-')))
    }
}

/// M01 D5 table. Matching is by package name (`dependencies[].name`), so a renamed dependency counts under its
/// real name; target-specific and build dependencies count like normal ones, optional ones too. Ledger ids carry
/// the dependency kind, so a ledgered dev edge never covers a normal edge of the same pair.
// ponytail: crate-granular like G-M01-2 — a forbidden `use` inside an allowed crate is the file-level ledger of
// M01-5; `qdrant-client` is not in Cargo.lock (Qdrant is reached over REST through humaux-infra-cell), the row is
// the guard for the day a client crate is added.
const BOUNDARY_TABLE: &[BoundaryRule] = &[
    BoundaryRule {
        dep: "reqwest",
        allowed_in: &["humaux-infra-network"],
        dev_exempt: false,
        family: false,
        why: "§78 / ADR-0003: Layer 0 is the only raw HTTP transport",
    },
    BoundaryRule {
        dep: "sqlx",
        allowed_in: &["humaux-adapters", "humaux-public-pool"],
        dev_exempt: true,
        family: true,
        why: "§78: Postgres access lives in the postgres adapter (dev-dependencies are testing)",
    },
    BoundaryRule {
        dep: "qdrant-client",
        allowed_in: &["humaux-adapters", "humaux-projection"],
        dev_exempt: false,
        family: false,
        why: "§78: the Qdrant client lives in the projection adapter",
    },
];

/// L0 kernel rows (M01 design §4): each package, and the workspace members it may depend on, in any dependency
/// kind. Every other workspace member is a violation.
const L0_WORKSPACE_DEPS: &[(&str, &[&str])] = &[
    ("humaux-domain", &[]),
    ("humaux-contracts", &[]),
    ("humaux-fail-closed-macro", &[]),
    (
        "humaux-telemetry",
        &[
            "humaux-domain",
            "humaux-contracts",
            "humaux-fail-closed-macro",
        ],
    ),
];

/// One G-M01-3 violation: `id` is the ledger key (`<package> -> <dependency> (<kind>)`, kind `normal`, `dev` or
/// `build`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryViolation {
    /// `[[crate_boundary]]` row id that ledgers this violation.
    pub id: String,
    /// Human-readable cause, naming the rule.
    pub detail: String,
}

/// Every violation of [`BOUNDARY_TABLE`] and [`L0_WORKSPACE_DEPS`] in a `cargo metadata --no-deps` document.
/// `Err` is a shape problem (no packages, a missing L0 package, a package without `dependencies`, a nameless
/// dependency): fail-closed and never ledgerable, because a missing list cannot prove the absence of an edge.
fn boundary_violations_in(metadata_json: &str) -> Result<Vec<BoundaryViolation>, String> {
    let packages = metadata_packages(metadata_json)?;
    let members: BTreeSet<&str> = packages.iter().filter_map(package_name).collect();
    if members.is_empty() {
        return Err("cargo metadata lists no workspace package (a vacuous boundary check)".into());
    }
    if let Some((missing, _)) = L0_WORKSPACE_DEPS.iter().find(|(n, _)| !members.contains(n)) {
        return Err(format!(
            "L0 package `{missing}` not found in cargo metadata output: matcher target missing"
        ));
    }
    let mut out = Vec::new();
    for pkg in &packages {
        let name = package_name(pkg).ok_or("cargo metadata lists a package without a `name`")?;
        let deps = pkg
            .get("dependencies")
            .and_then(|d| d.as_array())
            .ok_or_else(|| {
                format!("package `{name}` has no `dependencies` array in cargo metadata")
            })?;
        for dep in deps {
            let dep_name = dep
                .get("name")
                .and_then(|n| n.as_str())
                .ok_or_else(|| format!("package `{name}` lists a dependency without a `name`"))?;
            let kind = dep.get("kind").and_then(|k| k.as_str()).unwrap_or("normal");
            let id = format!("{name} -> {dep_name} ({kind})");
            for rule in BOUNDARY_TABLE.iter().filter(|r| r.matches(dep_name)) {
                if !rule.allowed_in.contains(&name) && !(rule.dev_exempt && kind == "dev") {
                    out.push(BoundaryViolation {
                        id: id.clone(),
                        detail: format!(
                            "`{name}` declares `{dep_name}` ({kind} dependency) but only {:?} may ({})",
                            rule.allowed_in, rule.why
                        ),
                    });
                }
            }
            if let Some((_, allowed)) = L0_WORKSPACE_DEPS.iter().find(|(n, _)| *n == name)
                && members.contains(dep_name)
                && !allowed.contains(&dep_name)
            {
                out.push(BoundaryViolation {
                    id,
                    detail: format!(
                        "L0 package `{name}` depends on workspace package `{dep_name}` ({kind} dependency) but may depend only on {allowed:?} (M01 design §4)"
                    ),
                });
            }
        }
    }
    Ok(out)
}

/// G-M01-3 pure comparator: a violation whose id is in `ledgered` is known-red, not green-silent (it comes back
/// as a note line for the log and `known-red` forces the row out once the violation is gone); any other
/// violation is `Fail`. Injected-fault record: ADR-0074 (G-M01-3 section).
pub fn crate_boundary_from(
    metadata_json: &str,
    ledgered: &BTreeSet<String>,
) -> (Verdict, Vec<String>) {
    let violations = match boundary_violations_in(metadata_json) {
        Ok(v) => v,
        Err(e) => return (Verdict::Fail(vec![e]), Vec::new()),
    };
    let (known, unknown): (Vec<_>, Vec<_>) = violations
        .into_iter()
        .partition(|v| ledgered.contains(&v.id));
    let notes = known
        .iter()
        .map(|v| {
            format!(
                "known-red: ledgered [crate_boundary] {}: {}",
                v.id, v.detail
            )
        })
        .collect();
    let verdict = if unknown.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(
            unknown
                .iter()
                .map(|v| {
                    format!(
                        "{}; not in xtask/known_red.toml [[crate_boundary]]",
                        v.detail
                    )
                })
                .collect(),
        )
    };
    (verdict, notes)
}

/// Ids of the `[[crate_boundary]]` rows in the ledger text; no section means none.
fn ledgered_boundary_ids(ledger_toml: &str) -> Result<BTreeSet<String>, String> {
    let parsed: toml::Table = ledger_toml
        .parse()
        .map_err(|e| format!("xtask/known_red.toml is not valid TOML: {e}"))?;
    let Some(rows) = parsed.get("crate_boundary") else {
        return Ok(BTreeSet::new());
    };
    rows.as_array()
        .ok_or("xtask/known_red.toml: crate_boundary must be written [[crate_boundary]]")?
        .iter()
        .map(|r| {
            r.get("id")
                .and_then(|i| i.as_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    "xtask/known_red.toml: a [[crate_boundary]] row has no string `id`".to_string()
                })
        })
        .collect()
}

/// G-M01-3 over the real workspace.
fn m01_3_crate_boundary(root: &Path) -> Verdict {
    let metadata = match workspace_metadata_json(root) {
        Ok(m) => m,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    let ledgered = match fs::read_to_string(KNOWN_RED_FILE)
        .map_err(|e| format!("xtask/known_red.toml unreadable: {e}"))
        .and_then(|raw| ledgered_boundary_ids(&raw))
    {
        Ok(ids) => ids,
        Err(e) => return Verdict::Fail(vec![e]),
    };
    let (verdict, notes) = crate_boundary_from(&metadata, &ledgered);
    for note in notes {
        println!("{note}");
    }
    verdict
}

/// Every G-M01-3 violation of the real workspace as `(id, detail)`, for the `crate_boundary` section of
/// `known-red`; `Err` when the metadata cannot be read or is malformed.
pub fn crate_boundary_violations() -> Result<Vec<(String, String)>, String> {
    let metadata = workspace_metadata_json(&workspace_root())?;
    Ok(boundary_violations_in(&metadata)?
        .into_iter()
        .map(|v| (v.id, v.detail))
        .collect())
}

// ============================================================================
// M01 D4 — G-M01-4: a DegradeCode variant is proven on its real path, or declared dormant (§53.4)
// ============================================================================

/// The dormant ledger: DegradeCode variants with no production emit site yet, one `[[dormant]]` row each.
const DORMANT_FILE: &str = "crates/testkit/tests/fault/dormant.toml";

/// The Cargo entry point that pulls `tests/fault/*.rs` into one test binary (§53.4).
const FAULT_MAIN_FILE: &str = "crates/testkit/tests/fault_main.rs";

/// Keys a `[[dormant]]` row may carry; any other key is a typo that would silently weaken the rule.
const DORMANT_ROW_KEYS: [&str; 3] = ["variant", "owner", "reason"];

/// `source` with `/* */` and `//` comments blanked (line numbers kept), so prose that mentions a name never counts as code.
/// String literals stay as written: [`fault_main_wires`] reads the `#[path = ".."]` string.
fn code_without_comments(source: &str) -> String {
    let no_block = strip_block_comments(source);
    no_block
        .lines()
        .map(code_before_line_comment)
        .collect::<Vec<_>>()
        .join("\n")
}

/// `source` with each `(start, end)` byte span (sorted, disjoint) turned into spaces, newlines kept so line numbers
/// survive.
fn blank_spans(source: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(source.len());
    let mut next = spans.iter().peekable();
    for (i, c) in source.char_indices() {
        while next.peek().is_some_and(|s| i >= s.1) {
            next.next();
        }
        let blanked = next.peek().is_some_and(|s| i >= s.0);
        out.push(if blanked && c != '\n' { ' ' } else { c });
    }
    out
}

/// `source` with every comment and every string, raw-string and char literal blanked, newlines kept: prose and quoted
/// text that mention an exit (`"abstain(DegradeCode::X, ..)"` in a metric help text) never read as code, and braces
/// or parentheses inside a literal never unbalance the matching below.
// ponytail: a lexer-lite shared with `strip_block_comments` (no macro-body awareness, C-string literals unread);
// upgrade to `proc_macro2` tokenizing if a file ever mis-masks.
fn mask_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let starts_token = |at: usize| at == 0 || !is_ident_byte(bytes[at - 1]);
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let end = match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                source[i..].find('\n').map_or(bytes.len(), |n| i + n)
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => block_comment_end(bytes, i),
            b'"' => string_end(bytes, i + 1),
            b'r' if starts_token(i) || (bytes[i - 1] == b'b' && starts_token(i - 1)) => {
                raw_string_end(bytes, i).unwrap_or(i + 1)
            }
            b'\'' => char_literal_end(source, i),
            _ => i + 1,
        };
        if end > i + 1 {
            spans.push((i, end));
        }
        i = end.max(i + 1);
    }
    blank_spans(source, &spans)
}

/// Blanks every `#[cfg(test)]` / `#[cfg(all(test, ..))]` item of `source`, newlines kept. An item ends at its `;` or at
/// the `}` matching its first `{`. [`strip_cfg_test_module`] blanks one module per file; `degrade.rs` and `envelope.rs`
/// each gate a `fn` before their gated `mod`s, so a test module that is not the first gated item must not read as
/// production code here.
// ponytail: brace matching ignores braces inside strings and chars (as `matching_brace_end` does; the emit-site scan
// feeds it [`mask_comments_and_literals`] output, which has none) and a `;` inside a gated item's signature
// (`-> [u8; 4]`) ends it early; upgrade to a token walk if a gated item ever needs either.
fn blank_cfg_test_items(source: &str) -> String {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut at = 0usize;
    while let Some(rel) = source[at..].find("#[cfg(") {
        let idx = at + rel;
        let attr = &source[idx..];
        if !(attr.starts_with("#[cfg(test)]") || attr.starts_with("#[cfg(all(test,")) {
            at = idx + "#[cfg(".len();
            continue;
        }
        let end = match (attr.find(';'), attr.find('{')) {
            (Some(s), Some(b)) if s < b => idx + s + 1,
            (Some(s), None) => idx + s + 1,
            (_, Some(b)) => matching_brace_end(source, idx + b).unwrap_or(source.len()),
            (None, None) => source.len(),
        };
        spans.push((idx, end));
        at = end;
    }
    blank_spans(source, &spans)
}

/// Whether `path` (workspace-relative) is production source for the emit-site scan: `src/` of a crate or a bin,
/// not the testkit (test infrastructure).
fn is_degrade_scan_source(path: &str) -> bool {
    (path.starts_with("crates/") || path.starts_with("bins/"))
        && path.contains("/src/")
        && !path.starts_with("crates/testkit/")
}

/// The `(workspace-relative path, source)` pairs of every production source file under `crates/` and `bins/`, sorted.
fn degrade_scan_files(root: &Path) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = ["crates", "bins"]
        .iter()
        .flat_map(|d| read_files(&walk_files(&root.join(d), &["rs"])))
        .map(|(p, s)| (display(root, &p), s))
        .filter(|(p, _)| is_degrade_scan_source(p))
        .collect();
    files.sort();
    files
}

/// The file that defines the degrade exit (§53.1). Its `abstain(code, ..)` forwards a parameter by design, so it is the
/// one file the scan does not hold to "the first argument names a variant".
const DEGRADE_HOME: &str = "crates/telemetry/src/degrade.rs";

/// The callees through which a `DegradeCode` leaves a function fail-open (§53.1): `abstain(code, ..)` is the single
/// exit and `Outcome::also(code)` forwards to it. The emit-site scan and the fault-test bypass check both read this
/// one list, so a new exit shape is added in one place and both see it.
const DEGRADE_EXIT_CALLEES: [&str; 2] = ["abstain", "also"];

/// One mention of a [`DEGRADE_EXIT_CALLEES`] callee in masked code.
struct ExitMention<'a> {
    /// Which callee was named.
    callee: &'static str,
    /// Byte offset of the callee identifier.
    at: usize,
    /// The text between the call's parentheses; `None` when the callee is only named (an import, a function value).
    args: Option<&'a str>,
}

/// Every mention of a [`DEGRADE_EXIT_CALLEES`] callee in `code` (already masked by [`mask_comments_and_literals`]),
/// in source order. `abstain` counts wherever it is a whole identifier; `also` only as a method or an associated
/// function (`.also` / `::also`), because a bare `also` is some local name.
fn exit_mentions(code: &str) -> Vec<ExitMention<'_>> {
    let bytes = code.as_bytes();
    let mut found = Vec::new();
    for callee in DEGRADE_EXIT_CALLEES {
        let mut from = 0usize;
        while let Some(rel) = code[from..].find(callee) {
            let at = from + rel;
            from = at + callee.len();
            let whole = (at == 0 || !is_ident_byte(bytes[at - 1]))
                && bytes.get(from).is_none_or(|b| !is_ident_byte(*b));
            let before = code[..at].trim_end();
            let reached_by_path = before.ends_with('.') || before.ends_with("::");
            if whole && (callee != "also" || reached_by_path) {
                found.push(ExitMention {
                    callee,
                    at,
                    args: call_args(code, from),
                });
            }
        }
    }
    found.sort_by_key(|m| m.at);
    found
}

/// Index just past the delimiter closing the one that opens at `open_at` (`bytes[open_at] == open`); `None` when it
/// is never closed.
fn balanced_end(bytes: &[u8], open_at: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(open_at) {
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(i + 1);
            }
        }
    }
    None
}

/// The text between the parentheses of the call whose callee identifier ends at `after` in `code`, looking past a
/// turbofish (`abstain::<T>(..)`); `None` when no call follows.
fn call_args(code: &str, after: usize) -> Option<&str> {
    let bytes = code.as_bytes();
    let skip_ws = |mut at: usize| {
        while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        at
    };
    let mut at = skip_ws(after);
    if code[at..].starts_with("::") {
        at = skip_ws(at + 2);
        if bytes.get(at) != Some(&b'<') {
            return None;
        }
        at = skip_ws(balanced_end(bytes, at, b'<', b'>')?);
    }
    if bytes.get(at) != Some(&b'(') {
        return None;
    }
    let end = balanced_end(bytes, at, b'(', b')')?;
    Some(&code[at + 1..end - 1])
}

/// The first argument of a call, given the text between its parentheses: up to the first comma outside any bracket.
fn first_argument(args: &str) -> &str {
    let mut depth = 0i32;
    for (i, b) in args.bytes().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => return &args[..i],
            _ => {}
        }
    }
    args
}

/// The variant that `arg` names by the last segment of a plain path: `DegradeCode::V`, a qualified
/// `humaux_telemetry::degrade::DegradeCode::V`, an aliased `C::V` (`use DegradeCode as C`) or a glob-imported bare
/// `V`. A parameter or local (`code`, lower-case, never a variant name), a call, a field access or a cast names none.
fn named_variant<'v>(arg: &str, variants: &'v [String]) -> Option<&'v str> {
    let path = arg.trim();
    if path.is_empty()
        || !path
            .bytes()
            .all(|b| is_ident_byte(b) || b == b':' || b.is_ascii_whitespace())
    {
        return None;
    }
    let last = path.rsplit("::").next()?.trim();
    variants.iter().map(String::as_str).find(|v| *v == last)
}

/// Production emit sites of the `variants`, plus the exit calls the scan could not classify, over `files`
/// (`(workspace-relative path, source)`).
///
/// The map is `variant -> "path:line"` of the first non-test, non-comment, non-string call of a
/// [`DEGRADE_EXIT_CALLEES`] callee whose first argument is a path ending in that variant: `DegradeCode::V`, a
/// qualified `a::b::DegradeCode::V`, an aliased `C::V` (`use DegradeCode as C`) or a glob-imported bare `V`, with or
/// without a turbofish on the callee. A `DegradeCode::V` that is matched on, counted, listed in a slice or handed to
/// another function is a reader of the variant, not an emitter.
///
/// The list holds one `path:line` problem per exit call whose first argument names no variant (a parameter, a local,
/// an expression): the scan cannot tell what it emits, so it fails closed instead of letting that variant read as
/// dormant (§53.4; M01-3 review W1). [`DEGRADE_HOME`] is exempt, its `abstain(code, ..)` forwards the parameter by
/// design (§53.1).
// ponytail: an exit callee renamed by `use .. as`, passed as a function value or reached through a macro is not seen,
// and neither is a hand-built `Outcome { degradations: .. }`; the single construction point of `abstain` (§53.1,
// CLAUDE.md) keeps those shapes out of the tree. Upgrade to resolving the callee if one ever appears.
pub fn degrade_emit_sites(
    files: &[(String, String)],
    variants: &[String],
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut sites = BTreeMap::new();
    let mut unclassified = Vec::new();
    for (path, source) in files {
        let code = blank_cfg_test_items(&mask_comments_and_literals(source));
        for m in exit_mentions(&code) {
            let Some(args) = m.args else { continue };
            let line = code[..m.at].matches('\n').count() + 1;
            let first = first_argument(args);
            if let Some(v) = named_variant(first, variants) {
                sites
                    .entry(v.to_string())
                    .or_insert_with(|| format!("{path}:{line}"));
            } else if path.as_str() != DEGRADE_HOME {
                let shown = first.split_whitespace().collect::<Vec<_>>().join(" ");
                unclassified.push(format!(
                    "{path}:{line}: `{}(` is a degrade exit whose first argument `{shown}` names no DegradeCode variant, so G-M01-4 cannot tell which variant it emits (§53.4); pass `DegradeCode::<Variant>` at the call",
                    m.callee
                ));
            }
        }
    }
    (sites, unclassified)
}

/// The first mention of a degrade exit in a fault test's `source`, as `(line, callee)`: an import, a call or a function
/// value of `abstain`, or an `.also` / `::also` call, in code (comments and string literals do not count). A live
/// variant's fault test must reach the exit through the production function, never name it. The same
/// [`DEGRADE_EXIT_CALLEES`] list drives the emit-site scan, so an exit shape the scan recognises cannot bypass this
/// check (M01-3 review B1).
pub fn degrade_exit_named(source: &str) -> Option<(usize, &'static str)> {
    let code = mask_comments_and_literals(source);
    exit_mentions(&code).first().map(|m| {
        let line = code[..m.at].matches('\n').count() + 1;
        (line, m.callee)
    })
}

/// One `[[dormant]]` row of [`DORMANT_FILE`].
#[derive(Debug)]
struct DormantRow {
    variant: String,
    owner: String,
    reason: String,
}

/// `M<nn>` or `M<nn>-<card>`: the module card that adds the emit site.
// ponytail: same shape check as `known_red::owner_ok` (private there); one shared helper once either file moves.
fn card_owner_ok(owner: &str) -> bool {
    let Some(rest) = owner.strip_prefix('M') else {
        return false;
    };
    let (module, card) = match rest.split_once('-') {
        Some((m, c)) => (m, Some(c)),
        None => (rest, None),
    };
    module.len() == 2
        && module.bytes().all(|b| b.is_ascii_digit())
        && card.is_none_or(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Parses [`DORMANT_FILE`]: the readable rows plus every structural problem (a typo is red, never ignored).
fn parse_dormant(raw: &str) -> (Vec<DormantRow>, Vec<String>) {
    let table = match raw.parse::<toml::Table>() {
        Ok(t) => t,
        Err(e) => {
            return (
                Vec::new(),
                vec![format!("{DORMANT_FILE} is not valid TOML: {e}")],
            );
        }
    };
    let mut problems: Vec<String> = table
        .keys()
        .filter(|k| k.as_str() != "dormant")
        .map(|k| {
            format!("{DORMANT_FILE}: unknown top-level key `{k}` (only [[dormant]] rows are read)")
        })
        .collect();
    let Some(value) = table.get("dormant") else {
        return (Vec::new(), problems);
    };
    let Some(entries) = value.as_array() else {
        problems.push(format!(
            "{DORMANT_FILE}: `dormant` must be an array of tables, written [[dormant]]"
        ));
        return (Vec::new(), problems);
    };
    let mut rows = Vec::new();
    for (n, entry) in entries.iter().enumerate() {
        let tag = format!("{DORMANT_FILE} row #{}", n + 1);
        let Some(t) = entry.as_table() else {
            problems.push(format!("{tag}: not a table"));
            continue;
        };
        for k in t.keys().filter(|k| !DORMANT_ROW_KEYS.contains(&k.as_str())) {
            problems.push(format!(
                "{tag}: unknown key `{k}` (known: {})",
                DORMANT_ROW_KEYS.join(", ")
            ));
        }
        let field = |k: &str| {
            t.get(k)
                .and_then(toml::Value::as_str)
                .map(str::trim)
                .unwrap_or_default()
                .to_string()
        };
        let row = DormantRow {
            variant: field("variant"),
            owner: field("owner"),
            reason: field("reason"),
        };
        if row.variant.is_empty() {
            problems.push(format!("{tag}: missing `variant`"));
            continue;
        }
        if !card_owner_ok(&row.owner) {
            problems.push(format!(
                "{tag} ({}): owner `{}` is not a module card (expected M<nn> or M<nn>-<card>, e.g. M11)",
                row.variant, row.owner
            ));
        }
        if row.reason.is_empty() {
            problems.push(format!("{tag} ({}): missing `reason`", row.variant));
        }
        rows.push(row);
    }
    (rows, problems)
}

/// Whether `fault_main` (the source of [`FAULT_MAIN_FILE`]) pulls `fault/<stem>.rs` into the test binary. Cargo never
/// discovers a file under `tests/fault/` by itself, so a fault test without its `#[path = ..] mod ..;` pair is never
/// compiled, let alone run: the §53.4 injection record would exist on disk and prove nothing. The pair must sit in
/// code (a commented-out line does not count) and be adjacent, so a `#[cfg(..)]` gate between them is red as well.
fn fault_main_wires(fault_main: &str, stem: &str) -> bool {
    let code = code_without_comments(fault_main);
    let flat = code.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.contains(&format!("#[path = \"fault/{stem}.rs\"] mod {stem};"))
}

/// G-M01-4 pure comparator (M01 D4, §53.4; tri-state per §57.1). Per variant of `variants`:
/// - it has a fault file (`fault_sources`, by variant name) ⇒ [`FAULT_MAIN_FILE`] must wire it (`fault_main`);
/// - it has a production emit site (`emit_sites`) ⇒ its fault test must not name a degrade exit
///   ([`degrade_exit_named`]: `abstain` or `.also`), and [`DORMANT_FILE`] must not list it (a stale row is red: the
///   ledger only shrinks);
/// - it has none ⇒ it must be listed in `dormant_toml` with an owner card and a reason.
///
/// `unclassified` are the exit calls [`degrade_emit_sites`] could not attribute to a variant; each is red. A row naming
/// no variant, a duplicate row, an unknown key and a bad owner are red as well. The notes are the ledger lines for the
/// log, so growth shows (the `rows: N` habit of `known-red`). No `not_applicable` leg: the ledger and the fault tests
/// are delivered by the same card, so absence is a regression (§57.1 rule 2).
/// Injected-fault record: ADR-0077 (red records).
pub fn real_path_from(
    variants: &[String],
    emit_sites: &BTreeMap<String, String>,
    unclassified: &[String],
    fault_sources: &BTreeMap<String, String>,
    fault_main: &str,
    dormant_toml: &str,
) -> (Verdict, Vec<String>) {
    let (rows, mut problems) = parse_dormant(dormant_toml);
    problems.extend(unclassified.iter().cloned());
    let mut listed: BTreeSet<&str> = BTreeSet::new();
    for row in &rows {
        if !variants.contains(&row.variant) {
            problems.push(format!(
                "{DORMANT_FILE}: row `{}` names no DegradeCode variant",
                row.variant
            ));
        } else if !listed.insert(row.variant.as_str()) {
            problems.push(format!("{DORMANT_FILE}: `{}` is listed twice", row.variant));
        }
    }
    for v in variants {
        let is_listed = listed.contains(v.as_str());
        let stem = pascal_to_snake(v);
        let test_file = format!("crates/testkit/tests/fault/{stem}.rs");
        if fault_sources.contains_key(v) && !fault_main_wires(fault_main, &stem) {
            problems.push(format!(
                "{v}: {test_file} exists but {FAULT_MAIN_FILE} has no `#[path = \"fault/{stem}.rs\"] mod {stem};` pair, so cargo never compiles or runs it (§53.4)"
            ));
        }
        if let Some(site) = emit_sites.get(v) {
            if is_listed {
                problems.push(format!(
                    "{v}: {DORMANT_FILE} still lists it, but it now has a production emit site ({site}); delete the row (the dormant ledger only shrinks)"
                ));
            }
            if let Some((line, callee)) = fault_sources.get(v).and_then(|s| degrade_exit_named(s)) {
                problems.push(format!(
                    "{v}: production emit site {site}, but {test_file}:{line} names the degrade exit `{callee}`; drive the production function that emits it (§53.4: a reason never triggered on its real path must not merge)"
                ));
            }
        } else if !is_listed {
            problems.push(format!(
                "{v}: no production emit site (a call of `abstain(` or `.also(` whose first argument names {v}, in non-test code of crates/*/src or bins/*/src) and no [[dormant]] row in {DORMANT_FILE}; add the row naming the card that will emit it"
            ));
        }
    }
    let mut notes = vec![format!(
        "G-M01-4: {} variant(s) driven through their production emit site; dormant rows: {}",
        emit_sites.len(),
        rows.len()
    )];
    notes.extend(rows.iter().map(|r| {
        format!(
            "G-M01-4: dormant {} (owner {}): {}",
            r.variant, r.owner, r.reason
        )
    }));
    let verdict = if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    };
    (verdict, notes)
}

/// G-M01-4 over the real workspace.
fn m01_4_real_path_or_dormant(root: &Path) -> Verdict {
    let degrade_path = root.join(DEGRADE_HOME);
    let Ok(degrade_src) = fs::read_to_string(&degrade_path) else {
        return Verdict::Fail(vec![format!("cannot read {}", degrade_path.display())]);
    };
    let variants = parse_degrade_variant_names(&degrade_src);
    if variants.is_empty() {
        return Verdict::Fail(vec![format!(
            "no `degrade_code! {{` block in {DEGRADE_HOME}; the variant list cannot be read"
        )]);
    }
    let dormant = match fs::read_to_string(root.join(DORMANT_FILE)) {
        Ok(raw) => raw,
        Err(e) => return Verdict::Fail(vec![format!("{DORMANT_FILE} unreadable: {e}")]),
    };
    let fault_main = match fs::read_to_string(root.join(FAULT_MAIN_FILE)) {
        Ok(raw) => raw,
        Err(e) => return Verdict::Fail(vec![format!("{FAULT_MAIN_FILE} unreadable: {e}")]),
    };
    let fault_sources: BTreeMap<String, String> = variants
        .iter()
        .filter_map(|v| {
            let path = root.join(format!(
                "crates/testkit/tests/fault/{}.rs",
                pascal_to_snake(v)
            ));
            fs::read_to_string(path).ok().map(|s| (v.clone(), s))
        })
        .collect();
    let (sites, unclassified) = degrade_emit_sites(&degrade_scan_files(root), &variants);
    let (verdict, notes) = real_path_from(
        &variants,
        &sites,
        &unclassified,
        &fault_sources,
        &fault_main,
        &dormant,
    );
    for note in notes {
        println!("{note}");
    }
    verdict
}

// ============================================================================
// §78 Boundary Lints: No env::var outside config/bootstrap
// ============================================================================

/// §78 boundary lint pure scanner: any real call to `std::env::var` is a violation, under
/// either spelling the codebase actually uses —
///
/// - fully qualified: `std::env::var("X")`,
/// - short form after `use std::env;`: `env::var("X")` (a substring of the qualified spelling,
///   so one `env::var` needle search catches both — the character before `env` in the
///   qualified form is `:`, never an identifier char, so the word-boundary check does not
///   need to special-case it),
/// - re-exported short form after `use std::env::var;`: bare `var("X")` calls in that file.
///
/// Comment lines are skipped for both. Callers filter which `(path, source)` pairs get passed
/// in — that's where the `contracts` config-read-point and `bins/*`/`xtask/` bootstrap
/// exemptions live (§78: "No env::var outside config/bootstrap").
/// 测试控制量的名字前缀。读这些**不是**本闸要管的事。
///
/// 本闸的判据是「不许有第二个**生产配置**读取点」（§78.1/§50.1，唯一读取点在
/// `humaux-contracts`）。`/tests/` 目录的豁免早就写明了这层意思——「读
/// `HUMAUX_TEST_PG_DSN` 属于三态 DB fixture 模式，不是生产配置」——但那条豁免是按
/// **目录**给的，于是同一类读取只要挪出 `/tests/` 就会被误报。
///
/// 实际撞上了：`crates/testkit/src/lib.rs::skip_or_fail` 是「跳过还是失败」的唯一判定点
/// （ADR-0005），它读 `HUMAUX_REQUIRE_DB` —— 与 `/tests/` 里那些读取同一类别，却因为住在
/// `src/` 被判违规。把豁免从「哪个目录」改成「哪一类变量」，判据一点没松：任何名字不带
/// 这些前缀的读取，无论在哪个文件，照旧算第二个生产配置读取点。
const TEST_CONTROL_ENV_PREFIXES: [&str; 2] = ["HUMAUX_TEST_", "HUMAUX_REQUIRE_"];

/// 命中处所在行读的是不是测试控制量。
///
/// 只看命中行本身：这些读取在本仓一律写成 `env::var("NAME")` 的单行形式（变量名与调用同行）。
/// 名字由参数传入、跨行拼接的写法**不会**被豁免——那正确，因为那种写法下静态扫描无从判断
/// 读的到底是什么，宁可误报也不放过。
fn line_reads_test_control_var(source: &str, idx: usize) -> bool {
    let line_start = source[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line = source[line_start..].lines().next().unwrap_or("");
    TEST_CONTROL_ENV_PREFIXES
        .iter()
        .any(|prefix| line.contains(prefix))
}

pub fn scan_env_var_violations(display_path: &str, source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut hit_lines: BTreeSet<usize> = BTreeSet::new();
    let mut record = |idx: usize| {
        if !line_is_comment_at(source, idx) && !line_reads_test_control_var(source, idx) {
            hit_lines.insert(source[..idx].matches('\n').count() + 1);
        }
    };

    let qualified_or_short = "env::var";
    let mut start = 0usize;
    while let Some(rel) = source[start..].find(qualified_or_short) {
        let idx = start + rel;
        // `use std::env::var;` is an import declaration, not a call — only the bare `var(`
        // call it enables (scanned separately below) is the real access site.
        let line_start = source[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_is_use = source[line_start..]
            .lines()
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with("use ");
        if (idx == 0 || !is_ident_byte(bytes[idx - 1])) && !line_is_use {
            record(idx);
        }
        start = idx + qualified_or_short.len();
    }

    // ponytail: `use std::env::var` gates a bare-`var(`-call scan of the *whole file*, not a
    // scope-resolved one — a file that imports `std::env::var` this way and also happens to
    // define/call an unrelated fn literally named `var` would over-flag it too. No such name
    // collision exists in this codebase today; tighten to real scope resolution if one shows
    // up.
    if source.contains("use std::env::var") {
        let mut start = 0usize;
        while let Some(rel) = source[start..].find("var(") {
            let idx = start + rel;
            let before_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
            let already_env_qualified =
                idx >= "env::".len() && &source[idx - "env::".len()..idx] == "env::";
            if before_ok && !already_env_qualified {
                record(idx);
            }
            start = idx + "var(".len();
        }
    }

    hit_lines
        .into_iter()
        .map(|line| format!("{display_path}:{line}"))
        .collect()
}

/// Byte offset of the file's trailing `#[cfg(test)]`-mod region, if the next
/// non-empty line after the attribute begins a `mod` — see the caller's ponytail note.
fn cfg_test_mod_offset(source: &str) -> Option<usize> {
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find("#[cfg(test)]") {
        let at = search_from + rel;
        let after = &source[at..];
        let mut lines = after.lines();
        lines.next(); // the attribute line itself
        for line in lines {
            let trimmed = line.trim_start();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("mod ") || trimmed.starts_with("pub mod ") {
                return Some(at);
            }
            break;
        }
        search_from = at + "#[cfg(test)]".len();
    }
    None
}

fn env_var_scan(root: &Path) -> Verdict {
    // Whole workspace, not just crates/: bins/* and xtask are real exemptible bootstrap
    // territory (see below), but a violation planted in evals/ (outside both) must still be
    // observable — it was invisible to the old crates/-only domain.
    let files = read_files(&walk_files(root, &["rs"]));
    let mut violations = Vec::new();
    for (path, source) in &files {
        // exemptions: humaux-contracts owns the one legitimate config-read point (§50.1);
        // bins/* is real process bootstrap; xtask is the CI-gate tooling itself (this file's
        // own module doc: "the CI gate family") — both categories the spec line names
        // ("config/bootstrap"), and both now genuinely reachable now that the scan domain is
        // the whole workspace instead of only crates/.
        let disp = display(root, path);
        if disp.contains("crates/contracts/")
            || disp.starts_with("bins/")
            || disp.starts_with("xtask/")
            || disp.contains("/tests/")
        {
            // `/tests/` integration dirs: reading HUMAUX_TEST_PG_DSN there is the
            // sanctioned three-state DB-fixture pattern, not production config
            // (§79.2 / repo CLAUDE.md 测试规范). Production reads stay covered.
            continue;
        }
        // Same sanction for a file's trailing `#[cfg(test)] mod` region: this repo's
        // convention keeps unit tests at file end; env reads after that attr are test
        // fixture, not runtime config.
        // ponytail: prefix-scope heuristic (everything after the first `#[cfg(test)]`
        // line followed by `mod` is exempt); upgrade to real span parsing if a
        // production `#[cfg(test)]`-adjacent violation ever needs catching.
        let scan_source = match cfg_test_mod_offset(source) {
            Some(off) => &source[..off],
            None => source.as_str(),
        };
        violations.extend(scan_env_var_violations(&disp, scan_source));
    }
    if violations.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(violations)
    }
}

// ============================================================================
// §55.1 G80-2 / §48.0① G80-22: unique construction points
// ============================================================================

/// Counts non-definition occurrences of `needle` (e.g. `"Foo {"` for a struct literal, or
/// `"Foo("` for a tuple-struct/fn-style call) in `source`. Excludes shapes that share the same
/// trailing token but are not construction: the type's own declaration or an `impl`/`trait`
/// block header for it (`struct`/`enum`/`impl`/`trait`/`for` immediately precedes the type
/// name — the `for` case covers blanket/trait impls, `impl<T> From<T> for Foo {`), and a
/// function signature whose return type is immediately followed by its own body-opening brace
/// (`-> Foo {`, prefix trimmed ends with `->` — that `{` opens the fn body, it is not a
/// struct-literal brace). Checking the immediate prefix rather than "does the whole line start
/// with `struct`/`fn`" matters: a construction call can share a line with an unrelated `fn`
/// keyword (e.g. `fn shortcut() { let _ = Foo { .. }; }`), and a whole-line check would
/// wrongly exempt it. Without the `impl` case, `impl Foo { .. }` landing anywhere in a scanned
/// file makes this permanently over-count by one — a false red the day the type's first method
/// is added.
fn count_construction_calls(source: &str, needle: &str) -> usize {
    let mut count = 0usize;
    let mut start = 0usize;
    while let Some(rel) = source[start..].find(needle) {
        let idx = start + rel;
        let prefix = source[..idx].trim_end();
        let is_declaration = prefix.ends_with("struct")
            || prefix.ends_with("enum")
            || prefix.ends_with("impl")
            || prefix.ends_with("trait")
            || prefix.ends_with("for")
            || prefix.ends_with("->");
        if !is_declaration && !line_is_comment_at(source, idx) {
            count += 1;
        }
        start = idx + needle.len();
    }
    count
}

/// Counts real **call sites** of `name(` in `source`: a `name(` occurrence that is neither a
/// definition (`fn name(`, in any file — a `tests/` helper is a definition too) nor part of a
/// longer identifier (`other_name(`, `name_in_txn(`), nor inside a `//` comment.
///
/// Card 21: written because G80-4 counted the bare substring `serving_version(` and only
/// escaped a false red through `walk_workspace_rs`'s `#[cfg(test)]` stripping — an accident
/// one helper declaration in a `tests/` file away from breaking. A judgement that survives only
/// because of an unrelated filter is not a judgement (ADR-0006's 「NA 不得与违规重合」, applied
/// to false positives instead of false negatives).
fn count_call_sites(source: &str, name: &str) -> usize {
    let needle = format!("{name}(");
    let bytes = source.as_bytes();
    let mut count = 0usize;
    let mut start = 0usize;
    while let Some(rel) = source[start..].find(&needle) {
        let idx = start + rel;
        start = idx + needle.len();
        // Left word boundary: `other_serving_version(` is a different function.
        if idx > 0 && (bytes[idx - 1].is_ascii_alphanumeric() || bytes[idx - 1] == b'_') {
            continue;
        }
        if line_is_comment_at(source, idx) {
            continue;
        }
        // A definition of ANY name is never a call site — `fn name(`, `pub fn name(`,
        // `pub async fn name(`, `pub(crate) fn name(` all end in the token `fn`.
        let prefix = source[..idx].trim_end();
        if prefix.ends_with("fn") {
            continue;
        }
        count += 1;
    }
    count
}

/// §78.1 / §15.1 (card 21): the ticket-family triple `(domain, projection_kind,
/// projection_version)` may be spelled in exactly ONE place — `crates/domain/src/
/// ticket_family.rs` — and every producer and consumer of `projection.stream_log` derives it
/// from there.
///
/// Why this is a gate and not a code review note: the three columns are how an issuer and a
/// resolver find each other. Before card 21 the gateway's `remember.put`, the consolidation
/// worker's rollup re-signal and the retrieval worker each carried their own copy (three
/// literals in `consolidate_repo`, three `HUMAUX_RETRIEVAL_WORKER_*` env values, and a
/// `DOMAIN=…; PKIND=…; PVER=…` line in the rehearsal script). Mis-set one and nothing fails —
/// the worker polls a stream nobody writes, forever, silently. There is no runtime signal for
/// that, so the signal has to be here.
///
/// **Scope: production source only** (`…/src/…`, with `#[cfg(test)]` modules stripped by
/// `walk_workspace_rs`). A test that writes the literal and asserts production derives the
/// same value is a positive control, not drift — `qdrant.rs::retrieval_family_matches_ticket_family`
/// and `retrieval-worker`'s `ticket_triple_is_derived_from_the_projection_family` are exactly
/// that shape, and `distill_hop_e2e` pins its own fixture constants against the derived triple.
///
/// **Why only two needles.** `"private_memory"` and `"PRIVATE_MEMORY"` are distinctive enough
/// to match nothing else; `"v1"` is not (a dozen unrelated versions spell it) and a scan that
/// matched it would be noise. The version cannot drift alone anyway: `TicketFamily::
/// collection_name` derives `{domain}_{version}` and `retrieval_family_matches_ticket_family`
/// pins that against §17's own Qdrant collection name, so moving the version without moving
/// §17 is red there.
fn g78_1_ticket_family_literals(root: &Path) -> Verdict {
    /// The one module allowed to spell them. Exact suffix, never `contains` (G80-22.5's
    /// 改名绕过 lesson).
    const HOME: &str = "crates/domain/src/ticket_family.rs";
    const NEEDLES: [&str; 2] = ["\"private_memory\"", "\"PRIVATE_MEMORY\""];

    let files = walk_workspace_rs(root);
    // §57.1: `not_applicable` only when the object under test is undelivered, and it must be
    // named. The object here is the closed set itself.
    if !files
        .iter()
        .any(|(p, src)| display(root, p).ends_with(HOME) && src.contains("pub enum TicketFamily"))
    {
        return Verdict::NotApplicable(format!(
            "missing object: `domain::ticket_family::TicketFamily` ({HOME}) 尚未交付"
        ));
    }

    let mut offenders = Vec::new();
    for (path, source) in &files {
        let disp = display(root, path);
        if disp.ends_with(HOME) || !disp.contains("/src/") {
            continue;
        }
        for needle in NEEDLES {
            let hits = source
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .filter(|l| l.contains(needle))
                .count();
            if hits > 0 {
                offenders.push(format!("{disp}: {needle} ×{hits}"));
            }
        }
    }
    if offenders.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "§78.1/§15.1: the ticket-family triple may only be spelled in {HOME}; production \
             source still carries the literal: {offenders:?}. Derive it from \
             `TicketFamily::PrivateMemory` (or, in a retrieval context, \
             `RetrievalFamily::ticket_family()`) instead."
        )])
    }
}

fn g80_2_build_request_unique(root: &Path) -> Verdict {
    // Whole workspace, not just crates/: §55.1 G80-2's own 注错 names `evals/` as the second
    // construction site, which lives outside crates/ entirely.
    let files = walk_workspace_rs(root);
    let object_exists = files
        .iter()
        .any(|(_, s)| s.contains("struct RetrievalRequest") || s.contains("fn build_request("));
    if !object_exists {
        return Verdict::NotApplicable(
            "retrieval::build_request / RetrievalRequest (§55.1, Phase 1 尚未交付)".to_string(),
        );
    }
    let mut count = 0usize;
    let mut sites = Vec::new();
    for (path, source) in &files {
        let n = count_construction_calls(source, "RetrievalRequest {");
        if n > 0 {
            sites.push(format!("{}: {n}", display(root, path)));
        }
        count += n;
    }
    if count == 1 {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "expected exactly 1 `RetrievalRequest {{ .. }}` construction site, found {count}: {sites:?}"
        )])
    }
}

// ============================================================================
// §55.6 G55-6 ① (G80-27): retrieval depth is never caller input
// ============================================================================

/// §55.6 G55-6 ①: the names no caller-assignable `RetrievalRequest` field or `build_request` parameter may carry. The
/// first five are the Baseline's set; the next five are ADR-0083 D-D's registry entries (T-RET-6c-1, T-RET-6c-2); the
/// last four are ADR-0084 D-E's, all but `rerank_depth`, which `depth` already catches word for word (T-RET-7d-2).
const G55_6_FORBIDDEN_NAMES: [&str; 14] = [
    "limit",
    "top_k",
    "cand_k",
    "depth",
    "max_candidates",
    "cand_multiplier",
    "leg_depth",
    "rrf_k",
    "sparse_leg_enabled",
    "sparse_timeout_ms",
    "rerank_enabled",
    "rerank_max_len",
    "rerank_timeout_ms",
    "rerank_threads",
];

/// Whether `name` carries `forbidden` as a run of whole `_`-separated words: `top_k_override` carries `top_k` (the
/// Baseline's own injection ①), `stop_k` does not.
fn g55_6_name_carries(name: &str, forbidden: &str) -> bool {
    let words: Vec<&str> = name.split('_').collect();
    let wanted: Vec<&str> = forbidden.split('_').collect();
    words.windows(wanted.len()).any(|w| w == wanted.as_slice())
}

/// `text` split at the commas that sit outside any `<>`, `()` or `[]` pair.
fn g55_6_split_top_level(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start, mut prev) = (0i32, 0usize, ' ');
    for (i, c) in text.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        prev = c;
    }
    parts.push(&text[start..]);
    parts
}

/// One field or parameter declaration with its comment and attribute lines dropped.
fn g55_6_decl(part: &str) -> String {
    part.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//") && !line.starts_with("#["))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The names a caller can assign directly: the plain-`pub` fields of `pub struct RetrievalRequest` and every
/// parameter of `pub fn build_request` found in `source` (§55.1). A private or `pub(crate)` field is not caller input.
///
/// ponytail: text scan like its siblings (no `syn`); a field or parameter declared through a macro is invisible to
/// it. [`g55_6_1_caller_depth_names`] fails closed on a spelling this scan cannot read. Upgrade to `syn` if the
/// request type ever grows macro-generated fields.
fn g55_6_caller_assignable_names(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(at) = source.find("pub struct RetrievalRequest {") {
        let open = at + "pub struct RetrievalRequest ".len();
        if let Some(close) = matching_brace_end(source, open) {
            for part in g55_6_split_top_level(&source[open + 1..close - 1]) {
                let decl = g55_6_decl(part);
                if let Some(field) = decl.strip_prefix("pub ")
                    && let Some((name, _)) = field.split_once(':')
                {
                    names.insert(name.trim().to_string());
                }
            }
        }
    }
    if let Some(at) = source.find("pub fn build_request(") {
        let open = at + "pub fn build_request".len();
        let mut depth = 0i32;
        let mut close = None;
        for (i, b) in source.bytes().enumerate().skip(open) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(close) = close {
            for param in g55_6_split_top_level(&source[open + 1..close]) {
                let decl = g55_6_decl(param);
                let name = decl.split(':').next().unwrap_or("").trim();
                let name = name.strip_prefix("mut ").unwrap_or(name).trim();
                if !name.is_empty() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

/// Every caller-assignable name in `source` that carries a [`G55_6_FORBIDDEN_NAMES`] word run, with the word it hit.
fn g55_6_offenders(source: &str) -> Vec<String> {
    g55_6_caller_assignable_names(source)
        .into_iter()
        .filter_map(|name| {
            G55_6_FORBIDDEN_NAMES
                .iter()
                .copied()
                .find(|forbidden| g55_6_name_carries(&name, forbidden))
                .map(|forbidden| format!("`{name}` carries `{forbidden}`"))
        })
        .collect()
}

/// §55.6 G55-6 ① over the workspace: `RetrievalRequest` fields ∪ `build_request` parameters, restricted to what a
/// caller can assign, ∩ [`G55_6_FORBIDDEN_NAMES`] must be empty. Depth comes from the registered profile only.
///
/// Fail closed: a file that spells the type or the constructor in a form [`g55_6_caller_assignable_names`] cannot read
/// (`pub(crate) struct RetrievalRequest`, `pub async fn build_request(`) would make the gate silently blind to its own
/// object, so that is red, not `not_applicable` and not a pass.
fn g55_6_1_caller_depth_names(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    let loose_type = |s: &str| s.contains("struct RetrievalRequest");
    let loose_fn = |s: &str| s.contains("fn build_request(");
    if !files.iter().any(|(_, s)| loose_type(s) || loose_fn(s)) {
        return Verdict::NotApplicable(
            "missing object: retrieval::build_request / RetrievalRequest (§55.1)".to_string(),
        );
    }
    let unreadable: Vec<String> = files
        .iter()
        .filter(|(_, s)| {
            (loose_type(s) && !s.contains("pub struct RetrievalRequest {"))
                || (loose_fn(s) && !s.contains("pub fn build_request("))
        })
        .map(|(path, _)| display(root, path))
        .collect();
    if !unreadable.is_empty() {
        return Verdict::Fail(vec![format!(
            "§55.6 G55-6 ①: {unreadable:?} spell `struct RetrievalRequest` or `fn build_request(` in a form the gate \
             cannot read (it reads `pub struct RetrievalRequest {{` and `pub fn build_request(`): it would be blind \
             to its own object. Use that spelling or extend the matcher."
        )]);
    }
    let offenders: Vec<String> = files
        .iter()
        .flat_map(|(path, source)| {
            g55_6_offenders(source)
                .into_iter()
                .map(move |hit| format!("{}: {hit}", display(root, path)))
        })
        .collect();
    if offenders.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "§55.6 G55-6 ①: a caller can assign retrieval depth: {offenders:?}. Depth values come from the registered \
             profile only (§50 registry), never from RetrievalRequest or build_request."
        )])
    }
}

/// §16.2 G80-4: "检索侧禁止把 `projection_version` 当常量读，只能经
/// `serving_version(stream_family)` 取" — the enforcement mechanism is a workspace-wide
/// consumer call-site count. `serving_version`'s own definition (`adapters::serving_repo`) and
/// its direct definition-testing file (`adapters/tests/serving_repo.rs`, which calls it purely
/// to pin the function's own read behavior, not as a retrieval consumer) are excluded from the
/// count — same shape as `count_construction_calls` excluding a type's own declaration.
///
/// The pool-owned wrapper and its caller-owned transaction form share one SQL authority
/// in `serving_repo`. Count both forms together: moving a retrieval read into its final RR
/// transaction changes the API spelling, not the exactly-one consumer constraint. A missing
/// consumer is a failure; only a missing definition can be `not_applicable` (ADR-0006).
fn g80_4_serving_version_sole_entry_point(root: &Path) -> Verdict {
    /// 定义点及其直属测试。**按精确路径排除，不用 `disp.contains("serving_repo")`**：
    /// 子串匹配会连带排除任何未来路径含该子串的文件（`serving_repo_client.rs`、
    /// `tests/serving_repo_wiring.rs`……），真调用点藏进那种文件里就永远数不到——
    /// 与 G80-22.5 踩过的「改名绕过」同型。
    const DEFINITION_FILES: [&str; 2] = [
        "crates/adapters/src/serving_repo.rs",
        "crates/adapters/tests/serving_repo.rs",
    ];

    let files = walk_workspace_rs(root);

    // §57.1 第2条：not_applicable 的唯一合法理由是**被测对象尚未交付**，且必须打印缺失
    // 对象名。这里的被测对象是 `serving_version` 这个函数本身，按**内容**探针判（同
    // `g80_2` 的 `fn build_request(` 手法），不按调用点数量。
    //
    // 先前判 NA 的条件是「检索侧一个调用点都没有」——而那恰恰就是 §16.2 被违反的状态本身，
    // 于是这道闸在违规最严重的时候最安静，NA 与违规不可区分（ADR-0006）。§57.1 允许 NA 是
    // 因为「没有被测对象就没什么可判的」，不是因为「判了会红」。
    if !files
        .iter()
        .any(|(_, src)| src.contains("pub async fn serving_version("))
    {
        return Verdict::NotApplicable(
            "missing object: §16.2 读路由入口 `pub async fn serving_version(` 尚未交付".to_string(),
        );
    }

    let mut count = 0usize;
    let mut sites = Vec::new();
    for (path, source) in &files {
        let disp = display(root, path);
        if disp.ends_with(SELF_FILE) || DEFINITION_FILES.iter().any(|d| disp.ends_with(d)) {
            continue;
        }
        // The two closed spellings enter the same authoritative SQL; together they must
        // still have exactly one consumer. Card 21: this used to be a raw `matches()` substring
        // count, which counted any text ending in `serving_version(` — a `fn serving_version(`
        // definition included. It only avoided a false red because `walk_workspace_rs` strips
        // `#[cfg(test)]` modules, i.e. because of something G80-4 does not control: a helper
        // declared in a `tests/` file (which is NOT a `#[cfg(test)]` module) would have turned
        // this gate red without a single retrieval call moving. Real call-site matching now:
        // word boundary on the left, and a `fn` definition of any name never counts.
        let n = count_call_sites(source, "serving_version")
            + count_call_sites(source, "serving_version_in_txn");
        if n > 0 {
            sites.push(format!("{disp}: {n}"));
            count += n;
        }
    }

    match count {
        1 => Verdict::Pass,
        0 => Verdict::Fail(vec![format!(
            "§16.2「检索侧只能经 serving_version(stream_family) 取」——消费侧调用点为 0，\
             也就是读路径根本没有经过读路由。这**不是** not_applicable：被测对象
             `serving_version` 就在 {}，缺的是调用它。",
            DEFINITION_FILES[0]
        )]),
        n => Verdict::Fail(vec![format!(
            "expected exactly 1 consumer-side `serving_version`/`serving_version_in_txn` call site outside the \
             definition files, found {n}: {sites:?}"
        )]),
    }
}

/// §48.0① G80-22 — **widened 口径, card 21** (ADR-0016 registered this change as the root-cause
/// fix for its own "指纹不能只从 run 行重算" debt).
///
/// What G80-22 protects is that ONE place decides the §8.1 *encoding*: no second crate may
/// re-derive "the payload digest" for itself. The old rule enforced that by counting exactly
/// one `EvidencePayloadSha256(` construction site workspace-wide, which also — accidentally —
/// forbade *reading back* a digest that is already persisted. That accident had a cost: the
/// §16.1 distill fingerprint could only obtain an anchor by hashing something, so it hashed a
/// re-rendered canonical jsonb of `events.payload` instead of the Evidence's stored
/// `payload_sha256`, and `private.processing_runs.source_hash` stopped being recomputable from
/// the persisted row (the §16.1.1 property the fingerprint exists for).
///
/// The rule now: **every** construction site lives in the one domain module, and there are
/// exactly two — one hasher ([`payload_sha256`]) and one read-back
/// (`EvidencePayloadSha256::from_stored_digest`, which performs no hashing and so cannot
/// introduce a second encoding). A third site, or any site outside that module, is still red.
fn g80_22_payload_sha256_unique(root: &Path) -> Verdict {
    /// The single module allowed to construct the type. Exact path, not a `contains` —
    /// substring matching is the 改名绕过 shape G80-22.5 already paid for.
    const HOME: &str = "crates/domain/src/evidence.rs";
    /// One hasher + one read-back. Both are in `HOME`; neither may be duplicated.
    const EXPECTED_SITES: usize = 2;

    // Whole workspace, not just crates/: §48.0① names `bins/*` / `evals/*` / migration tooling
    // as required scan territory for a stray construction site.
    let files = walk_workspace_rs(root);
    let object_exists = files.iter().any(|(_, s)| {
        s.contains("struct EvidencePayloadSha256") || s.contains("fn payload_sha256(")
    });
    if !object_exists {
        return Verdict::NotApplicable(
            "evidence::payload_sha256 / EvidencePayloadSha256 (§48.0① G80-22, Phase 6 尚未交付)"
                .to_string(),
        );
    }
    let mut home_count = 0usize;
    let mut foreign = Vec::new();
    for (path, source) in &files {
        let n = count_construction_calls(source, "EvidencePayloadSha256(");
        if n == 0 {
            continue;
        }
        let disp = display(root, path);
        if disp.ends_with(HOME) {
            home_count += n;
        } else {
            foreign.push(format!("{disp}: {n}"));
        }
    }
    let mut failures = Vec::new();
    if !foreign.is_empty() {
        failures.push(format!(
            "§48.0① G80-22: `EvidencePayloadSha256( .. )` may only be constructed in {HOME}; \
             found construction sites elsewhere: {foreign:?}"
        ));
    }
    if home_count != EXPECTED_SITES {
        failures.push(format!(
            "§48.0① G80-22: {HOME} must hold exactly {EXPECTED_SITES} construction sites (one \
             hasher `payload_sha256`, one read-back `from_stored_digest`), found {home_count}"
        ));
    }
    // The read-back must stay a read-back: if it ever hashes, the second site becomes a second
    // *encoding* and the whole widening is void. Cheap structural probe, same shape as
    // `g80_2`'s content probe.
    if let Some((_, home_src)) = files.iter().find(|(p, _)| display(root, p).ends_with(HOME)) {
        if !home_src.contains("pub fn from_stored_digest(") {
            failures.push(format!(
                "§48.0① G80-22: {HOME} declares no `pub fn from_stored_digest(` — the read-back \
                 leg of the widened 口径 is missing"
            ));
        }
        let readback = home_src
            .split("pub fn from_stored_digest(")
            .nth(1)
            .and_then(|rest| rest.split("\n    }").next())
            .unwrap_or("");
        // Needles that mean "this function hashes": the hasher path (`Sha256::…`) and the crate
        // that provides it. NOT the bare string `Sha256` — the type's own name contains it, so
        // that needle would be red on every correct implementation (a gate that cannot be green
        // is not a gate).
        if readback.contains("Sha256::") || readback.contains("sha2::") {
            failures.push(format!(
                "§48.0① G80-22: `from_stored_digest` in {HOME} hashes — a read-back must adopt \
                 the persisted bytes, never re-derive them (that is a second encoding)"
            ));
        }
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// ADR-0059: the functions that build role DDL carrying a verifier, and the one parser that reads
/// migration 0011's placeholder literals, each have exactly one production call site.
const ADR0059_SOLE_CALLS: [&str; 3] = [
    "alter_role_password_sql",
    "create_role_sql",
    "parse_roles_sql",
];

/// ADR-0059 D-E/D-F pure comparator: each name in [`ADR0059_SOLE_CALLS`] is called `== 1` times
/// across `files` (`#[cfg(test)]` modules already stripped by the walker); 0 is red as well.
fn sole_call_site_problems(root: &Path, files: &[(PathBuf, String)]) -> Vec<String> {
    names_with_one_call_site(root, files, &ADR0059_SOLE_CALLS)
}

/// Each of `names` is called `== 1` times across `files`; 0 is red as well.
fn names_with_one_call_site(
    root: &Path,
    files: &[(PathBuf, String)],
    names: &[&str],
) -> Vec<String> {
    names
        .iter()
        .filter_map(|name| {
            let sites: Vec<String> = files
                .iter()
                .filter_map(|(path, source)| {
                    let n = count_call_sites(source, name);
                    (n > 0).then(|| format!("{}: {n}", display(root, path)))
                })
                .collect();
            let total: usize = files.iter().map(|(_, s)| count_call_sites(s, name)).sum();
            (total != 1).then(|| {
                format!("expected exactly 1 `{name}(` call site, found {total}: {sites:?}")
            })
        })
        .collect()
}

/// ADR-0059 D-G: the token key set is installed by exactly one production call (gateway
/// bootstrap), and the 11-field token parser is reached only through MAC verification.
const ADR0059_TOKEN_SOLE_CALLS: [&str; 2] = ["install_token_keys", "parse_token_fields"];

/// [`ADR0059_TOKEN_SOLE_CALLS`] over production sources: integration-test trees (a `tests`
/// path component) install their own per-process keys and are not production call sites.
fn token_sole_call_problems(root: &Path, files: &[(PathBuf, String)]) -> Vec<String> {
    let production: Vec<(PathBuf, String)> = files
        .iter()
        .filter(|(path, _)| {
            !path
                .strip_prefix(root)
                .unwrap_or(path)
                .components()
                .any(|c| c.as_os_str() == "tests")
        })
        .cloned()
        .collect();
    names_with_one_call_site(root, &production, &ADR0059_TOKEN_SOLE_CALLS)
}

fn adr0059_token_sole_call_sites(root: &Path) -> Verdict {
    let problems = token_sole_call_problems(root, &walk_workspace_rs(root));
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

fn adr0059_role_hygiene_sole_call_sites(root: &Path) -> Verdict {
    let problems = sole_call_site_problems(root, &walk_workspace_rs(root));
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// ADR-0060 D-B / D-A (T31): the private worker's provider instances have one production source.
/// Over `bins/*/src` (tests stripped): `RouteProviders::new(` is called exactly once, in the
/// private worker's `main.rs`; exactly one `ReasoningProviderDescriptor {` literal exists, in
/// `route_providers.rs` (a second one is a process-level descriptor again). Over
/// `crates/adapters/src`: exactly one `reasoning_profile_capabilities(` call, the admission
/// wrapper's.
fn route_provider_sole_site_problems(root: &Path, files: &[(PathBuf, String)]) -> Vec<String> {
    let in_dir = |prefix: &str| -> Vec<(String, &String)> {
        files
            .iter()
            .map(|(p, s)| (display(root, p), s))
            .filter(|(d, _)| d.starts_with(prefix) && d.contains("/src/") && !d.contains("/tests/"))
            .collect()
    };
    let bins = in_dir("bins/");
    let adapters = in_dir("crates/adapters/");
    let mut problems = Vec::new();
    let mut expect =
        |sources: &[(String, &String)], count: &dyn Fn(&str) -> usize, what: &str, home: &str| {
            let sites: Vec<(String, usize)> = sources
                .iter()
                .map(|(d, s)| (d.clone(), count(s)))
                .filter(|(_, n)| *n > 0)
                .collect();
            let total: usize = sites.iter().map(|(_, n)| n).sum();
            if total != 1 || !sites.iter().all(|(d, _)| d.ends_with(home)) {
                problems.push(format!(
                    "ADR-0060 D-B: expected exactly 1 {what} in {home}, found {total}: {sites:?}"
                ));
            }
        };
    expect(
        &bins,
        &|s| count_call_sites(s, "RouteProviders::new"),
        "`RouteProviders::new(` call",
        "bins/private-worker/src/main.rs",
    );
    expect(
        &bins,
        &|s| count_construction_calls(s, "ReasoningProviderDescriptor {"),
        "`ReasoningProviderDescriptor {` literal",
        "bins/private-worker/src/route_providers.rs",
    );
    expect(
        &adapters,
        &|s| count_call_sites(s, "reasoning_profile_capabilities"),
        "`reasoning_profile_capabilities(` call",
        "crates/adapters/src/reasoning_route_admission.rs",
    );
    problems
}

fn adr0060_route_provider_sole_sites(root: &Path) -> Verdict {
    let problems = route_provider_sole_site_problems(root, &walk_workspace_rs(root));
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// The file whose `&'static str` label signature carries the ADR-0061 D-A bound; the scan
/// domain is dead without it.
const METRICS_ENCODER_FILE: &str = "crates/telemetry/src/metrics.rs";

/// The ways a runtime `String` becomes `&'static str`: the three std `leak` paths and the method
/// form `.leak(` (ADR-0061 review-fix 3, F11).
const LEAK_TOKENS: [&str; 4] = ["Box::leak", "String::leak", "Vec::leak", ".leak("];

/// `file:line: token` of every non-comment leak in one source.
fn box_leak_hits(display_path: &str, source: &str) -> Vec<String> {
    source
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .flat_map(|(i, l)| {
            LEAK_TOKENS
                .iter()
                .filter(move |t| l.contains(**t))
                .map(move |t| format!("{display_path}:{}: {t}", i + 1))
        })
        .collect()
}

/// The crates whose code renders or records a §41.2 label (ADR-0061 D-A, D-C) plus every binary.
fn in_leak_scan_domain(display_path: &str) -> bool {
    [
        "crates/telemetry/src/",
        "crates/retrieval/src/",
        "crates/retrieval-provider/src/",
    ]
    .iter()
    .any(|p| display_path.starts_with(p))
        || (display_path.starts_with("bins/") && display_path.contains("/src/"))
}

/// ADR-0061 D-A: metric label values are `&'static str` from closed enums, so a tenant id,
/// user id or free text can reach a label only by leaking it. No production leak may exist in
/// the label-recording crates (telemetry, retrieval, retrieval-provider) or any `bins/*/src`
/// (test modules stripped).
fn adr0061_no_box_leak_labels(root: &Path) -> Verdict {
    let files: Vec<(String, String)> = walk_workspace_rs(root)
        .into_iter()
        .map(|(p, s)| (display(root, &p), s))
        .filter(|(d, _)| in_leak_scan_domain(d))
        .collect();
    adr0061_box_leak_verdict(&files)
}

fn adr0061_box_leak_verdict(files: &[(String, String)]) -> Verdict {
    if !files.iter().any(|(d, _)| d == METRICS_ENCODER_FILE) {
        return Verdict::Fail(vec![format!(
            "positive sentinel dead: {METRICS_ENCODER_FILE} is not in the scan domain"
        )]);
    }
    let hits: Vec<String> = files
        .iter()
        .flat_map(|(d, s)| box_leak_hits(d, s))
        .collect();
    if hits.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(hits)
    }
}

/// §1.3/§48.0 G80-11 (source_hash leg): `humaux_projection::fingerprint::source_hash` is the
/// sole construction point of `SourceHash` (§16.1/§16.1.1, T5.1) — same single-crate
/// convergence family as `EvidencePayloadSha256` (G80-22, above) and the §1.12 canonical tool
/// schema. A second `SourceHash(` construction site anywhere in the workspace (a second crate
/// re-deriving the processing-input-fingerprint encoding instead of calling `source_hash`)
/// would let two different encodings both claim the name "the fingerprint", exactly the drift
/// §1.3's "缺任意一项...回放/模型对比/精准重建...全部无法回答" warns about.
fn g80_11_source_hash_unique(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    let object_exists = files
        .iter()
        .any(|(_, s)| s.contains("struct SourceHash") || s.contains("fn source_hash("));
    if !object_exists {
        return Verdict::NotApplicable(
            "projection::fingerprint::source_hash / SourceHash (§1.3/§48.0 G80-11, T5.1 尚未交付)"
                .to_string(),
        );
    }
    let mut count = 0usize;
    let mut sites = Vec::new();
    for (path, source) in &files {
        let n = count_construction_calls(source, "SourceHash(");
        if n > 0 {
            sites.push(format!("{}: {n}", display(root, path)));
        }
        count += n;
    }
    if count == 1 {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "expected exactly 1 `SourceHash( .. )` construction site, found {count}: {sites:?}"
        )])
    }
}

// ============================================================================
// Sole-INSERT doors (M07 D9 / G-M07-1, M09 D1 / G-M09-1). A door statement is ONE statement in ONE file in
// non-test code, so a change to the model behind it edits that module and no writer can skip what the door enforces.
// M07: the Evidence and Memory INSERTs (the digest-as-hex binding, the PRIMARY `memory_evidence` link, the §6.1.3
// subject hook). M09: the `stream_log` INSERT and the `commit_seq` allocation (the §60 statement order, the outbox row
// that closes A1 for the Evidence it announces).
// ============================================================================

/// `(statement text, the one file that may hold it)`.
type DoorStatement = (&'static str, &'static str);

/// Door statements of M07 D9 (module design M07 §6, gate G-M07-1).
const M07_INSERT_DOORS: [DoorStatement; 2] = [
    (
        "INSERT INTO private.evidence_objects",
        "crates/adapters/src/evidence_repo.rs",
    ),
    (
        "INSERT INTO private.memory_records",
        "crates/adapters/src/memory_repo.rs",
    ),
];

/// Door statements of M09 D1 (module design M09 §6, gate G-M09-1). The `nextval` needle stops before the closing
/// parenthesis, so `nextval('ops.commit_seq_seq'::regclass)` and `nextval( 'ops.commit_seq_seq' )` count too.
const M09_TICKET_DOORS: [DoorStatement; 2] = [
    (
        "INSERT INTO projection.stream_log",
        "crates/adapters/src/stream_repo.rs",
    ),
    (
        "nextval('ops.commit_seq_seq'",
        "crates/adapters/src/stream_repo.rs",
    ),
];

/// `(door statement, file, most copies it may hold)`: a file outside the door's home that is counted against a bound
/// instead of failing at its first copy. More than the bound is red like any stray copy, so the bound is a ceiling the
/// file cannot grow past without an edit here.
type BoundedSite = (&'static str, &'static str, usize);

/// `xtask`'s onboarding e2e is the one non-test file that spells M09 door statements outside the door: it seeds one
/// ISSUED `stream_log` row, with a `nextval`, as the DB owner to stage a fault scenario (no `role_gateway`
/// transaction, no outbox row — that is the scenario). Exact path and exact bounds, never a directory.
///
/// ponytail: the bound is per statement, not per call site, so a copy swapped for another in that file goes unseen,
/// upgrade to naming the fixture's function if the e2e harness ever grows more raw `stream_log` writes.
const M09_TICKET_DOOR_BOUNDED: [BoundedSite; 2] = [
    (
        "INSERT INTO projection.stream_log",
        "xtask/src/e2e_onboard.rs",
        1,
    ),
    (
        "nextval('ops.commit_seq_seq'",
        "xtask/src/e2e_onboard.rs",
        1,
    ),
];

/// Whether `disp` (repo-relative, `/`-separated) sits in a test tree, judged by path **structure** like the sibling
/// [`count_outside_allowed`]: only `crates/<pkg>/tests`, `bins/<pkg>/tests` and `xtask/tests`. A bare `tests` path
/// component is not enough — `crates/adapters/src/tests/writer.rs` and `crates/tests/src/lib.rs` are production code.
fn door_is_test_tree(disp: &str) -> bool {
    let segments: Vec<&str> = disp.split('/').collect();
    matches!(
        segments.as_slice(),
        ["crates" | "bins", _, "tests", ..] | ["xtask", "tests", ..]
    )
}

/// Every workspace `.rs` file as production code: this file excluded (it quotes the needles), test trees excluded
/// ([`door_is_test_tree`]; integration tests seed rows with raw INSERTs), and each file cut at its trailing
/// `#[cfg(test)] mod` ([`cfg_test_mod_offset`], the same prefix heuristic [`count_outside_allowed`] uses).
///
/// Not [`walk_workspace_rs`]: that blanks the test module by naive brace counting, which a `{` inside a string
/// literal desyncs, and `xtask/src/e2e_seed.rs`'s test module is such a file — its fixture INSERTs would be counted.
fn door_production_sources(root: &Path) -> Vec<(String, String)> {
    read_files(&walk_files(root, &["rs"]))
        .into_iter()
        .filter_map(|(path, source)| {
            let disp = display(root, &path);
            if disp == SELF_FILE || door_is_test_tree(&disp) {
                return None;
            }
            // ponytail: prefix cut at the first `#[cfg(test)] mod`, so production items declared after it are not
            // scanned (rustfmt keeps test modules last and `count_outside_allowed` has the same ceiling), upgrade to
            // span-parsing the test module if a production item ever follows one.
            let production = match cfg_test_mod_offset(&source) {
                Some(off) => source[..off].to_string(),
                None => source,
            };
            Some((disp, production))
        })
        .collect()
}

/// The text a SQL string literal spells, for matching: comment lines dropped, `\`-newline continuations joined the way
/// rustc joins them (the next line's leading whitespace is skipped), whitespace runs collapsed to one space, lowercased,
/// spaces around parentheses removed — so `insert  into private.memory_records` and a `\`-split `INSERT INTO \` +
/// `private.memory_records` both match, and so does `nextval( 'x' )` against the needle `nextval('x'`.
fn door_normalised(source: &str) -> String {
    let mut text = String::with_capacity(source.len());
    let mut continued = false;
    for line in source.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let line = if continued { line.trim_start() } else { line };
        match line.strip_suffix('\\') {
            Some(head) => {
                text.push_str(head);
                continued = true;
            }
            None => {
                text.push_str(line);
                text.push(' ');
                continued = false;
            }
        }
    }
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
        .replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(") ", ")")
}

/// `needle` occurrences in each file's [`door_normalised`] text (files with none are omitted).
///
/// ponytail: matches the spelled-out statement text, so a statement assembled with `format!` or from separate string
/// pieces evades it, upgrade to statement parsing if that ever shows up.
fn door_statement_sites(files: &[(String, String)], needle: &str) -> Vec<(String, usize)> {
    let needle = door_normalised(needle);
    files
        .iter()
        .filter_map(|(disp, source)| {
            let n = door_normalised(source).matches(needle.as_str()).count();
            (n > 0).then(|| (disp.clone(), n))
        })
        .collect()
}

/// Sole-door check: each statement in `doors` appears `== 1` times in non-test code, in its home file; 0 is red (a
/// typo'd needle or a deleted door must not read as "no duplicates"), so is a single copy anywhere else, and so is a
/// statement that exists while its home file does not. `bounded` files may hold up to their bound of a statement
/// without being counted; one more copy than the bound is counted in full. `not_applicable` only when the statement
/// appears nowhere and the home file does not exist yet, and it names that file (§57.1 第2条) — a failing door is never
/// masked by another door's `not_applicable`. `gate` prefixes every red line; `door_kind` names the doors in the
/// `not_applicable` line.
fn sole_door_statements(
    root: &Path,
    gate: &str,
    door_kind: &str,
    doors: &[DoorStatement],
    bounded: &[BoundedSite],
) -> Verdict {
    let files = door_production_sources(root);
    let mut problems = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for (needle, home) in doors {
        let sites: Vec<(String, usize)> = door_statement_sites(&files, needle)
            .into_iter()
            .filter(|(disp, n)| {
                !bounded.iter().any(|(b_needle, b_file, limit)| {
                    b_needle == needle && b_file == disp && n <= limit
                })
            })
            .collect();
        let total: usize = sites.iter().map(|(_, n)| n).sum();
        let home_exists = files.iter().any(|(disp, _)| disp == home);
        if !home_exists && total == 0 {
            if !missing.contains(home) {
                missing.push(*home);
            }
            continue;
        }
        let sole = home_exists && total == 1 && sites.iter().all(|(disp, _)| disp == home);
        if !sole {
            let gone = if home_exists {
                ""
            } else {
                " (the home file does not exist)"
            };
            problems.push(format!(
                "{gate}: expected exactly 1 `{needle}` in non-test code, in {home}{gone}; found {total}: {sites:?}"
            ));
        }
    }
    if !problems.is_empty() {
        Verdict::Fail(problems)
    } else if !missing.is_empty() {
        Verdict::NotApplicable(format!(
            "missing object: {door_kind} file(s) not delivered yet: {}",
            missing.join(", ")
        ))
    } else {
        Verdict::Pass
    }
}

/// M07 D9 / G-M07-1: the Evidence and Memory INSERT doors ([`M07_INSERT_DOORS`]).
fn m07_1_insert_doors(root: &Path) -> Verdict {
    sole_door_statements(
        root,
        "M07 D9 / G-M07-1",
        "M07 D9 write door",
        &M07_INSERT_DOORS,
        &[],
    )
}

/// M09 D1 / G-M09-1: the `stream_log` INSERT and the `commit_seq` allocation ([`M09_TICKET_DOORS`]), both in
/// `stream_repo.rs`; the 注错 is a second `INSERT INTO projection.stream_log` in another module (`found 2`).
fn m09_1_ticket_doors(root: &Path) -> Verdict {
    sole_door_statements(
        root,
        "M09 D1 / G-M09-1",
        "M09 D1 ticket door",
        &M09_TICKET_DOORS,
        &M09_TICKET_DOOR_BOUNDED,
    )
}

// ============================================================================
// M04 D2 / G-M04-1: plans are data. A plan name, a price and a lease block size are rows of the plan catalogue (seeded
// from the values file), never Rust: no production source branches on a plan key or states a price (§71.1, §78.1).
// ============================================================================

/// The committed plan values file; its `plan_key`s are the names the scan looks for (the names are data, so the gate
/// reads them from the data instead of repeating them).
const M04_CATALOGUE_FILE: &str = "deploy/plans/plan_catalogue.json";

/// Identifiers whose assignment, comparison or field initialisation with an integer literal spells a price, a lease
/// block or a quota number in Rust: the plan version's `price_cents` and `lease_block`, the quota window's
/// `hard_limit` and the lease's `granted_slots` (module design M04 §3, D4, D5). Only identifiers the quota and plan
/// catalogue own: the scan is not a general number detector (a bare `limit == 0` shape check is everywhere).
const M04_BUSINESS_NUMBER_IDENTS: [&str; 4] =
    ["price_cents", "lease_block", "hard_limit", "granted_slots"];

/// Struct-variant literals of the entitlement template whose `limit` field is a quota number the catalogue owns
/// (`domain::plan::TemplateValue`): a `limit` given an integer inside their braces is a limit spelled in Rust.
const M04_QUOTA_LITERALS: [&str; 2] = ["PeriodQuota {", "Allowance {"];

/// The newest migration on `main` when G-M04-1 widened from production Rust to `migrations/*.sql` (0262,
/// `plan_catalogue`). A migration numbered at or below this floor predates the rule and is not rescanned: its literals
/// were reviewed under §71.1 before the gate existed. Only a file numbered strictly above the floor is scanned.
const M04_MIGRATION_SCAN_FLOOR: u32 = 262;

/// Catalogue migrations whose own CHECK lists spell the closed sets on purpose. A file is skipped whole, by its exact
/// repo-relative path only — never a prefix or a pattern. `0262_plan_catalogue.sql` sits at
/// [`M04_MIGRATION_SCAN_FLOOR`] and is therefore not scanned, so it needs no entry; a catalogue migration above the
/// floor adds one path here and nothing else.
const M04_MIGRATION_CATALOGUE_ALLOW: [&str; 0] = [];

/// The plan-version identifiers that may be spelled as a quoted SQL key (`('price_cents', 980)`): the price and the
/// lease block. `hard_limit` is already found by [`m04_quoted_limit_integer`]; `granted_slots` is not a catalogue
/// column.
const M04_SQL_QUOTED_IDENTS: [&str; 2] = ["price_cents", "lease_block"];

/// The `plan_key` of every row of the values file, or why the file cannot be read as one.
fn m04_catalogue_plan_keys(text: &str) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("{M04_CATALOGUE_FILE}: {error}"))?;
    let rows = value
        .get("plan_versions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{M04_CATALOGUE_FILE}: no `plan_versions` array"))?;
    Ok(rows
        .iter()
        .filter_map(|row| row.get("plan_key").and_then(serde_json::Value::as_str))
        .map(str::to_owned)
        .collect())
}

/// What follows an assignment-like operator (`:`, `=`, `==`, `!=`) at the start of `rest`; `None` for anything else,
/// `::` (a path) and `<`/`>` comparisons included.
fn m04_after_assignment(rest: &str) -> Option<&str> {
    let rest = rest.trim_start();
    if rest.starts_with("::") {
        return None;
    }
    ["==", "!=", ":", "="]
        .iter()
        .find_map(|operator| rest.strip_prefix(*operator))
}

/// Whether `line` gives the identifier `ident` an integer literal (`price_cents: 980`, `let lease_block = 16;`,
/// `price_cents == 0`).
fn m04_assigns_integer(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(relative) = line[from..].find(ident) {
        let start = from + relative;
        let end = start + ident.len();
        from = end;
        let whole_word = (start == 0 || !is_ident_byte(bytes[start - 1]))
            && (end == bytes.len() || !is_ident_byte(bytes[end]));
        if !whole_word {
            continue;
        }
        let integer_follows = m04_after_assignment(&line[end..])
            .and_then(|value| value.trim_start().bytes().next())
            .is_some_and(|byte| byte.is_ascii_digit());
        if integer_follows {
            return true;
        }
    }
    false
}

/// Whether `rest` (the text after a quoted key) is a `:` or `,` followed by an integer literal: the JSON member
/// `"limit": 5`, the SQL pair `'limit', 50` and the tuple `("key", 500)`.
fn m04_integer_after_separator(rest: &str) -> bool {
    let rest = rest.trim_start();
    rest.strip_prefix(':')
        .or_else(|| rest.strip_prefix(','))
        .and_then(|value| value.trim_start().bytes().next())
        .is_some_and(|byte| byte.is_ascii_digit())
}

/// Whether `line` spells a quoted key that names a limit (`"limit"`, `'hard_limit'`, `"emergency_limit"`) and gives it
/// an integer: `json!({"limit": 5})`, `jsonb_build_object('limit', 50)`. A quoted `"limit"` that is looked up
/// (`.get("limit")`) or given a variable is not a number.
fn m04_quoted_limit_integer(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(relative) = line[from..].find("limit") {
        let at = from + relative;
        from = at + "limit".len();
        let mut start = at;
        while start > 0 && is_ident_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = from;
        while end < bytes.len() && is_ident_byte(bytes[end]) {
            end += 1;
        }
        let quoted = start > 0
            && end < bytes.len()
            && matches!(bytes[start - 1], b'"' | b'\'')
            && bytes[end] == bytes[start - 1];
        if quoted && m04_integer_after_separator(&line[end + 1..]) {
            return true;
        }
    }
    false
}

/// Whether `line` spells the quoted entitlement key `key` and gives it an integer: `("mcp.billable_operations.x", 500)`.
fn m04_quoted_key_integer(line: &str, key: &str) -> bool {
    ['"', '\''].into_iter().any(|quote| {
        let needle = format!("{quote}{key}{quote}");
        line.match_indices(&needle)
            .any(|(at, _)| m04_integer_after_separator(&line[at + needle.len()..]))
    })
}

/// The four-digit number a migration file name starts with, or `None` when it carries none. The gate dates the file
/// against [`M04_MIGRATION_SCAN_FLOOR`]; an unnumbered `.sql` under `migrations/` is red, never silently old.
fn m04_migration_number(path: &Path) -> Option<u32> {
    let name = path.file_name()?.to_str()?;
    let (digits, _) = name.split_at_checked(4)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// One migration's SQL with its comments blanked and its line numbers kept: `--` to end of line, `/* .. */` (nested)
/// between statements, and a `--` inside a single- or double-quoted token left alone. A plan name or a price in prose
/// is not a statement the database runs (§71.1).
fn m04_sql_code(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    let mut out = String::with_capacity(source.len());
    let mut quote: Option<char> = None;
    let mut i = 0;
    while i < chars.len() {
        let current = chars[i];
        if let Some(q) = quote {
            out.push(current);
            if current == q {
                if at(i + 1) == q {
                    out.push(q);
                    i += 2;
                    continue;
                }
                quote = None;
            }
            i += 1;
            continue;
        }
        if current == '\'' || current == '"' {
            quote = Some(current);
            out.push(current);
            i += 1;
            continue;
        }
        if current == '-' && at(i + 1) == '-' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if current == '/' && at(i + 1) == '*' {
            let mut depth = 0_usize;
            while i < chars.len() {
                if chars[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        out.push(current);
        i += 1;
    }
    out
}

/// The plan-name, price and limit literals in one migration's text ([`m04_plan_literal_hits`]) plus a quoted price or
/// lease-block key that is given an integer (`('price_cents', 980)`), the SQL spelling of the #216 patterns
/// (§71.1, §78.1). Comments are blanked first ([`m04_sql_code`]), so a header comment can name a plan without turning
/// the gate red.
fn m04_sql_plan_literal_hits(source: &str, plan_keys: &BTreeSet<String>) -> Vec<String> {
    let code = m04_sql_code(source);
    let mut hits = m04_plan_literal_hits(&code, plan_keys);
    for (index, line) in code.lines().enumerate() {
        for ident in M04_SQL_QUOTED_IDENTS {
            if m04_quoted_key_integer(line, ident) {
                hits.push(format!(
                    "line {}: the quoted price / limit key {ident} given an integer literal",
                    index + 1
                ));
            }
        }
    }
    hits
}

/// The template struct-variant literals in `source` ([`M04_QUOTA_LITERALS`]) that give their `limit` an integer, as
/// `line N: ..` hits. Comment lines are blanked with their line numbers kept, so a doc comment never reads as code.
fn m04_quota_literal_hits(source: &str) -> Vec<String> {
    let code = source
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut hits = Vec::new();
    for needle in M04_QUOTA_LITERALS {
        for (at, _) in code.match_indices(needle) {
            let open = at + needle.len() - 1;
            let Some(end) = matching_brace_end(&code, open) else {
                continue;
            };
            if m04_assigns_integer(&code[open..end], "limit") {
                let line = code[..at].matches('\n').count() + 1;
                hits.push(format!(
                    "line {line}: a `{needle} .. }}` literal gives `limit` an integer"
                ));
            }
        }
    }
    hits
}

/// The plan-name literals, price and quota numbers in one production file's text: a comment line is skipped, a plan key
/// counts only as a whole literal (`"key"` or `'key'`, the second being a SQL string inside Rust), and a number counts
/// where the catalogue owns it: an identifier of [`M04_BUSINESS_NUMBER_IDENTS`], a quoted limit key, a quoted
/// entitlement key (`domain::plan::EntitlementKey`, the window keys included) or a [`M04_QUOTA_LITERALS`] body.
fn m04_plan_literal_hits(source: &str, plan_keys: &BTreeSet<String>) -> Vec<String> {
    let entitlement_keys =
        humaux_domain::plan::EntitlementKey::ALL.map(humaux_domain::plan::EntitlementKey::wire);
    let mut hits = Vec::new();
    for (index, line) in source.lines().enumerate() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        for key in plan_keys {
            for quote in ['"', '\''] {
                if line.contains(&format!("{quote}{key}{quote}")) {
                    hits.push(format!(
                        "line {}: plan key {quote}{key}{quote} spelled as a literal",
                        index + 1
                    ));
                }
            }
        }
        for ident in M04_BUSINESS_NUMBER_IDENTS {
            if m04_assigns_integer(line, ident) {
                hits.push(format!(
                    "line {}: `{ident}` given an integer literal",
                    index + 1
                ));
            }
        }
        if m04_quoted_limit_integer(line) {
            hits.push(format!(
                "line {}: a quoted limit key given an integer literal",
                index + 1
            ));
        }
        for key in entitlement_keys {
            if m04_quoted_key_integer(line, key) {
                hits.push(format!(
                    "line {}: the entitlement key {key:?} given an integer literal",
                    index + 1
                ));
            }
        }
    }
    hits.extend(m04_quota_literal_hits(source));
    hits
}

/// M04 D2 / G-M04-1: production source under `crates/` and `bins/` (test trees and trailing `#[cfg(test)]` modules
/// excluded, [`door_production_sources`]) and in every migration above [`M04_MIGRATION_SCAN_FLOOR`] (older migrations
/// predate the rule) holds no plan-key literal of the values file and gives no price, lease block or quota limit an
/// integer literal ([`m04_plan_literal_hits`] lists the positions; [`m04_sql_plan_literal_hits`] reads `.sql`).
/// `not_applicable` only while the values file does not exist, naming it (§57.1 第2条); a file that lists no plan key,
/// or a scan that reads no source, is red: it would be blind.
fn m04_1_plans_are_data(root: &Path) -> Verdict {
    let Ok(text) = fs::read_to_string(root.join(M04_CATALOGUE_FILE)) else {
        return Verdict::NotApplicable(format!(
            "missing object: {M04_CATALOGUE_FILE} (the M04-1 plan values file) is not delivered yet"
        ));
    };
    let plan_keys = match m04_catalogue_plan_keys(&text) {
        Ok(keys) if !keys.is_empty() => keys,
        Ok(_) => {
            return Verdict::Fail(vec![format!(
                "M04 D2 / G-M04-1: {M04_CATALOGUE_FILE} lists no plan_key, so the scan would be blind"
            )]);
        }
        Err(problem) => return Verdict::Fail(vec![format!("M04 D2 / G-M04-1: {problem}")]),
    };
    let mut scanned = 0usize;
    let mut problems = Vec::new();
    for (disp, source) in door_production_sources(root) {
        if !(disp.starts_with("crates/") || disp.starts_with("bins/")) {
            continue;
        }
        scanned += 1;
        for hit in m04_plan_literal_hits(&source, &plan_keys) {
            problems.push(format!("{disp}: {hit}"));
        }
    }
    for (path, source) in read_files(&walk_files(&root.join("migrations"), &["sql"])) {
        let disp = display(root, &path);
        let Some(number) = m04_migration_number(&path) else {
            problems.push(format!(
                "{disp}: migration file name has no four-digit number, so the scan cannot date it"
            ));
            continue;
        };
        if number <= M04_MIGRATION_SCAN_FLOOR
            || M04_MIGRATION_CATALOGUE_ALLOW.contains(&disp.as_str())
        {
            continue;
        }
        for hit in m04_sql_plan_literal_hits(&source, &plan_keys) {
            problems.push(format!("{disp}: {hit}"));
        }
    }
    if scanned == 0 {
        return Verdict::Fail(vec![
            "M04 D2 / G-M04-1: no production source under crates/ or bins/ was scanned, so the scan is blind".to_owned(),
        ]);
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "M04 D2 / G-M04-1: plan names, prices and lease blocks are data, not Rust (§71.1, §78.1); production source \
             (and migrations above {M04_MIGRATION_SCAN_FLOOR}) spells {} of them: {problems:?}",
            problems.len()
        )])
    }
}

/// Door statement of M29 T04c (design v0.2 §15, gate G-T04c-3): the §30.2 Evidence → task-run carrier INSERT is one
/// statement in non-test code, in `remember::insert_evidence_task_run_in_txn`. This arm pins only that statement;
/// `pub(crate)` pins the function's callers to the adapters crate, and the §6.2.2 grants (rls_check: INSERT for
/// `role_gateway` only) are the DB backstop.
const T04C_CARRIER_DOOR: [DoorStatement; 1] = [(
    "INSERT INTO private.evidence_task_runs",
    "crates/adapters/src/remember.rs",
)];

/// M29 T04c / G-T04c-3: exactly one `INSERT INTO private.evidence_task_runs` in non-test code, in `remember.rs`
/// ([`T04C_CARRIER_DOOR`]); the 注错 is a second copy in another module (`found 2`).
fn t04c_3_carrier_door(root: &Path) -> Verdict {
    sole_door_statements(
        root,
        "M29 T04c / G-T04c-3",
        "M29 T04c task-run carrier door",
        &T04C_CARRIER_DOOR,
        &[],
    )
}

/// Door statement of M29 T06c (ADR-0078 D-D rung A1, gate G-T06c-3): the declared-project carrier INSERT is one
/// statement in non-test code, in `remember::insert_evidence_project_in_txn`. This arm pins only that statement;
/// `pub(crate)` pins the function's callers to the adapters crate, its `DeclaredProject` argument (constructed only by
/// `remember::resolve_declared_project_in_txn`) pins the resolution before it, and the §6.2.2 grants (rls_check:
/// INSERT for `role_gateway` only) are the DB backstop.
const T06C_DECLARED_DOOR: [DoorStatement; 1] = [(
    "INSERT INTO private.evidence_projects",
    "crates/adapters/src/remember.rs",
)];

/// M29 T06c / G-T06c-3: exactly one `INSERT INTO private.evidence_projects` in non-test code, in `remember.rs`
/// ([`T06C_DECLARED_DOOR`]); the 注错 is a second copy in another module (`found 2`).
fn t06c_door(root: &Path) -> Verdict {
    sole_door_statements(
        root,
        "M29 T06c / G-T06c-3",
        "M29 T06c declared-project carrier door",
        &T06C_DECLARED_DOOR,
        &[],
    )
}

/// Rule site of M29 T06b (ADR-0078 D-D A3', gate G-M29-5(b)): in non-test Rust the `correction@1` wire literal lives
/// only in `RuleId`'s closed set, and `RuleId::Correction1` is named nowhere else, so no Rust path writes an A3' row
/// (migration 0255's trigger is the one writer; rls_check's §6.1.4 A3' single-site gate pins the database side). The
/// needle keeps its quotes: rls_check's probes spell `correction@1` inside larger SQL strings, never as the literal.
const T06B_RULE_HOME: &str = "crates/domain/src/attribution.rs";
const T06B_RULE_LITERAL: [DoorStatement; 1] = [("\"correction@1\"", T06B_RULE_HOME)];

/// M29 T06b / G-M29-5(b): exactly one `"correction@1"` in non-test code, in `attribution.rs`
/// ([`T06B_RULE_LITERAL`]), and no `RuleId::Correction1` outside it; the 注错 is a second literal in another module
/// (`found 2`).
fn t06b_correction_rule_site(root: &Path) -> Verdict {
    let gate = "M29 T06b / G-M29-5(b)";
    let verdict = sole_door_statements(
        root,
        gate,
        "M29 T06b correction rule",
        &T06B_RULE_LITERAL,
        &[],
    );
    let strays: Vec<(String, usize)> =
        door_statement_sites(&door_production_sources(root), "RuleId::Correction1")
            .into_iter()
            .filter(|(disp, _)| disp != T06B_RULE_HOME)
            .collect();
    if strays.is_empty() {
        return verdict;
    }
    let mut lines = match verdict {
        Verdict::Fail(lines) => lines,
        _ => Vec::new(),
    };
    lines.push(format!(
        "{gate}: `RuleId::Correction1` in non-test code outside {T06B_RULE_HOME}: {strays:?}"
    ));
    Verdict::Fail(lines)
}

/// Home of the M29 T07 attribution reader (ADR-0078 D-D, design v0.2 §15.8).
const T07_READER_HOME: &str = "crates/adapters/src/attribution_repo.rs";
/// The attribution table; `private.memory_projects_live` is its live view (migration 0255 ②).
const T07_TABLE: &str = "private.memory_projects";
/// rls_check names the table and the view as catalog strings (its grant and policy matrix), never as a read: up to
/// this many table / view tokens there are not counted; one more and that kind is counted in full.
const T07_CATALOG_SITE: (&str, usize, usize) = ("bins/maintenance/src/rls_check.rs", 2, 2);

/// Rust source with `//` and (nested) `/* */` comments replaced by a space and string, raw-string and char literals
/// copied verbatim (the SQL lives in them), so neither a `/*` or `//` inside a literal nor a glob in a doc comment hides
/// the code after it, and a commented-out statement is no statement.
///
/// ponytail: lexes comments and literals only, so SQL assembled with `format!` / `concat!` or loaded with
/// `include_str!` from a `.sql` file is not scanned, and a SQL `--` comment inside a literal still counts; upgrade to
/// statement parsing if that ever shows up.
fn t07_strip_comments(source: &str) -> String {
    let s: Vec<char> = source.chars().collect();
    let at = |i: usize| s.get(i).copied().unwrap_or('\0');
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < s.len() {
        let start = i;
        if s[i] == '/' && at(i + 1) == '/' {
            while i < s.len() && s[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if s[i] == '/' && at(i + 1) == '*' {
            let mut depth = 0_usize;
            while i < s.len() {
                if s[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if s[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        let ident_before = i > 0 && (s[i - 1].is_alphanumeric() || s[i - 1] == '_');
        let raw_hashes_from = match s[i] {
            'r' if !ident_before => Some(i + 1),
            'b' if !ident_before && at(i + 1) == 'r' => Some(i + 2),
            _ => None,
        };
        if let Some(mut j) = raw_hashes_from {
            let mut hashes = 0;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
            if at(j) == '"' {
                j += 1;
                while j < s.len() && !(s[j] == '"' && (1..=hashes).all(|k| at(j + k) == '#')) {
                    j += 1;
                }
                i = (j + 1 + hashes).min(s.len());
                out.extend(&s[start..i]);
                continue;
            }
        }
        if s[i] == '"' {
            i += 1;
            while i < s.len() && s[i] != '"' {
                i += if s[i] == '\\' { 2 } else { 1 };
            }
            i = (i + 1).min(s.len());
            out.extend(&s[start..i]);
            continue;
        }
        if s[i] == '\'' {
            // `'x'` and `'\…'` are char literals (so `'"'` opens no string); any other `'` starts a lifetime.
            let close = if at(i + 1) == '\\' {
                (i + 3..s.len().min(i + 12)).find(|&k| s[k] == '\'')
            } else {
                (at(i + 2) == '\'').then_some(i + 2)
            };
            i = close.map_or(i + 1, |k| k + 1);
            out.extend(&s[start..i]);
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// [`door_normalised`] text of [`t07_strip_comments`] with SQL identifier quoting undone (a `"` becomes a space, so
/// `FROM"private"` stays two words), so `FROM "private"."memory_projects"` and `FROM private . memory_projects` read
/// as the table.
fn t07_normalised(source: &str) -> String {
    door_normalised(&t07_strip_comments(source))
        .replace("\\\"", " ")
        .replace('"', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" .", ".")
        .replace(". ", ".")
}

/// (table, view) tokens in one [`t07_normalised`] text: a table token is [`T07_TABLE`] followed by no identifier
/// character and not directly after `insert into ` (the A1 / A3 writers); a view token is `private.memory_projects_live`.
/// A comma join or `FROM ONLY` names the token like any other read.
fn t07_tokens(text: &str) -> (usize, usize) {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let (mut table, mut view) = (0, 0);
    for (at, _) in text.match_indices(T07_TABLE) {
        if text[..at].chars().next_back().is_some_and(ident) {
            continue;
        }
        let after = &text[at + T07_TABLE.len()..];
        if let Some(tail) = after.strip_prefix("_live") {
            if !tail.starts_with(ident) {
                view += 1;
            }
        } else if !after.starts_with(ident) && !text[..at].ends_with("insert into ") {
            table += 1;
        }
    }
    (table, view)
}

/// M29 T07 / ADR-0078 Consequences (design v0.2 §15.7, §15.8): in non-test Rust, (1) no mention of
/// `private.memory_projects` other than the `_live` view and the `INSERT INTO private.memory_projects` writers, because
/// "exists and is not revoked" lives only in the view (migration 0255 ②); (2) exactly one mention of
/// `private.memory_projects_live`, in [`T07_READER_HOME`] (`== 1`; 0 is red). Tokens per [`t07_tokens`], the
/// [`T07_CATALOG_SITE`] bound aside. `not_applicable` only when the view is
/// read nowhere and the home file does not exist, naming that file (§57.1 第2条); a direct table read is red
/// regardless.
fn m29_attribution_reader(root: &Path) -> Verdict {
    let gate = "M29 T07 / ADR-0078 D-D reader";
    let files = door_production_sources(root);
    let mut direct: Vec<(String, usize)> = Vec::new();
    let mut readers: Vec<(String, usize)> = Vec::new();
    for (disp, source) in &files {
        let (mut table, mut view) = t07_tokens(&t07_normalised(source));
        if disp == T07_CATALOG_SITE.0 {
            if table <= T07_CATALOG_SITE.1 {
                table = 0;
            }
            if view <= T07_CATALOG_SITE.2 {
                view = 0;
            }
        }
        if table > 0 {
            direct.push((disp.clone(), table));
        }
        if view > 0 {
            readers.push((disp.clone(), view));
        }
    }
    let mut problems = Vec::new();
    if !direct.is_empty() {
        problems.push(format!(
            "{gate}: non-test code reads private.memory_projects directly instead of private.memory_projects_live: {direct:?}"
        ));
    }
    let total: usize = readers.iter().map(|(_, n)| n).sum();
    let home_exists = files.iter().any(|(disp, _)| disp == T07_READER_HOME);
    if !home_exists && total == 0 {
        return if problems.is_empty() {
            Verdict::NotApplicable(format!(
                "missing object: M29 T07 attribution reader file not delivered yet: {T07_READER_HOME}"
            ))
        } else {
            Verdict::Fail(problems)
        };
    }
    if !(total == 1 && readers.iter().all(|(disp, _)| disp == T07_READER_HOME)) {
        problems.push(format!(
            "{gate}: expected exactly 1 read of private.memory_projects_live in non-test code, in {T07_READER_HOME}; found {total}: {readers:?}"
        ));
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// ADR-0078 D-D (Q1 ruling) / G-M29-5(a) and D-E / G-N09-1 (card M29 T06a): the Memory INSERT door invokes M07's
// attribution port exactly once, through a required parameter, and the M29 write path of `memory_projects` names no
// model source.
// ============================================================================

/// The Memory INSERT door's file (M07) and the M29 attribution implementation's file.
const M29_DOOR_HOME: &str = "crates/adapters/src/memory_repo.rs";
const M29_LADDER_HOME: &str = "crates/adapters/src/attribution_repo.rs";

/// G-M29-5(a) sites, each `== 1` in non-test code: the port method call, in the door's file; and the port's one
/// implementation, M29's (a second one would be a production no-op or a rival ladder).
const M29_5A_SITES: [DoorStatement; 2] = [
    (".link_memory_projects(", M29_DOOR_HOME),
    ("MemoryAttribution for", M29_LADDER_HOME),
];

/// ADR-0078 D-D / G-M29-5(a): [`M29_5A_SITES`] each `== 1` in its home file, and inside `fn insert_memory_in_txn` the
/// port is a parameter whose type is not `Option<…>`, invoked after the PRIMARY `memory_evidence` INSERT and the
/// subject hook. Case- and whitespace-tolerant ([`door_normalised`]); `not_applicable` names a missing home file.
fn m29_5a_attribution_site(root: &Path) -> Verdict {
    const GATE: &str = "ADR-0078 / G-M29-5(a)";
    let sites = sole_door_statements(root, GATE, "M29 attribution port", &M29_5A_SITES, &[]);
    if sites != Verdict::Pass {
        return sites;
    }
    let text = door_normalised(&fs::read_to_string(root.join(M29_DOOR_HOME)).unwrap_or_default());
    let Some(start) = text.find("fn insert_memory_in_txn(") else {
        return Verdict::Fail(vec![format!(
            "{GATE}: no `fn insert_memory_in_txn(` in {M29_DOOR_HOME}"
        )]);
    };
    let door = &text[start..];
    let door = &door[..door[1..].find(" fn ").map_or(door.len(), |i| i + 1)];
    let params = &door[..door.find(")->").unwrap_or(door.len())];
    let mut problems = Vec::new();
    match params.find("memoryattribution") {
        None => problems.push(format!(
            "{GATE}: `insert_memory_in_txn` takes no `MemoryAttribution` parameter"
        )),
        Some(at) => {
            let ty = &params[params[..at].rfind([',', '(']).map_or(0, |i| i + 1)..at];
            if ty.contains("option<") {
                problems.push(format!(
                    "{GATE}: the port parameter is optional: `{}MemoryAttribution`",
                    ty.trim()
                ));
            }
        }
    }
    match door.find(".link_memory_projects(") {
        None => problems.push(format!(
            "{GATE}: the port is not invoked inside `insert_memory_in_txn`"
        )),
        Some(call) => {
            let before = [
                door.find("insert into private.memory_evidence"),
                door.find("link_memory_in_txn("),
            ];
            if before.iter().any(|at| at.is_none_or(|at| at > call)) {
                problems.push(format!(
                    "{GATE}: the port runs before the PRIMARY memory_evidence link or the subject hook"
                ));
            }
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// G-N09-1 scan targets: the M29 write path of `memory_projects` and the closed sets it binds.
const N09_1_FILES: [&str; 2] = [M29_LADDER_HOME, "crates/domain/src/attribution.rs"];

/// Provider, inference, embedding and HTTP crate / module names (lowercased, as [`door_normalised`] leaves them).
///
/// ponytail: substring match over the files' non-comment code, so an alias that hides every listed name evades it;
/// the files are two small modules, so add a name here when a new provider-side module appears.
const N09_1_MODEL_NAMES: [&str; 11] = [
    "provider",
    "inference",
    "embedding",
    "reasoner",
    "byok",
    "egress",
    "qdrant",
    "reqwest",
    "infra_cell",
    "model_call",
    "distill",
];

/// ADR-0078 D-E / G-N09-1 (import half): no [`N09_1_MODEL_NAMES`] entry in the non-test, non-comment code of
/// [`N09_1_FILES`] (N09 R2: model output never writes a formal attribution). The closed-set half is
/// `domain::attribution`'s frozen-set test. `not_applicable` names a missing file.
fn n09_1_no_model_source(root: &Path) -> Verdict {
    const GATE: &str = "ADR-0078 / G-N09-1";
    let mut problems = Vec::new();
    let mut missing = Vec::new();
    for file in N09_1_FILES {
        let Ok(source) = fs::read_to_string(root.join(file)) else {
            missing.push(file);
            continue;
        };
        let production = cfg_test_mod_offset(&source).map_or(source.as_str(), |off| &source[..off]);
        let text = door_normalised(production);
        for name in N09_1_MODEL_NAMES {
            if text.contains(name) {
                problems.push(format!("{GATE}: {file} names `{name}` in code"));
            }
        }
    }
    if !problems.is_empty() {
        Verdict::Fail(problems)
    } else if !missing.is_empty() {
        Verdict::NotApplicable(format!(
            "missing object: G-N09-1 scan file(s) not delivered yet: {}",
            missing.join(", ")
        ))
    } else {
        Verdict::Pass
    }
}

// ============================================================================
// M08 D1 / G-M08-2 "one home": the final read gate has one home. `can_read(` is the visibility judge (§6.1.1); the
// all-backing-evidence closure around it (§8.6) lives in `crates/adapters/src/read_gate.rs`, so a read op that calls
// `can_read(` anywhere else is judging visibility itself and can drift from the closure (a Memory with an unreadable
// backing Evidence row slipping through). The gate's row-level door, `read_gate::visibility_readable`, is the same
// judge one row at a time, so it is ratcheted the same way: the number of `can_read` tokens and the number of
// `visibility_readable` tokens per file are each pinned with `==`, and a new caller of the door is a declared row with
// a reason, never a pass by proxy.
// ============================================================================

/// The read gate's own file: the one home of `can_read` and of the definition of `visibility_readable`.
const M08_GATE_HOME: &str = "crates/adapters/src/read_gate.rs";

/// `(file, count, why)`: the declared sites G-M08-2 pins for `can_read`, each with the exact number of bare `can_read`
/// tokens its non-test code holds ([`identifier_tokens`]: the import counts, so a file that imports and calls once is
/// `2`). Compared per file with `==`, so a file added or dropped, one more use in a declared file, and one fewer are
/// all red. Adapters and bins non-test code only (`domain` defines `can_read`, `projection` mirrors it for Qdrant
/// filters under G-M08-7). The gate is the only declared site; every other reader judges through
/// [`M08_VISIBILITY_READABLE_SITES`] or `read_gate::readable_memory_ids` (§8.6).
const M08_CAN_READ_SITES: [(&str, usize, &str); 1] = [(
    M08_GATE_HOME,
    2,
    "the gate: the import and the one call inside `visibility_readable`, the judgement `readable_memory_ids` applies to a Memory and every backing Evidence row and the row-level callers apply to a row they already fetched (§6.1.1, §8.6)",
)];

/// `(file, count, why)`: the declared callers of `read_gate::visibility_readable` outside the gate, each with the exact
/// number of bare `visibility_readable` tokens its non-test code holds (the import counts). Compared per file with `==`
/// exactly like [`M08_CAN_READ_SITES`], so a fifth caller, one more use in a declared caller, and one fewer are all red.
/// The gate file is exempt: it defines the door and applies it inside `readable_memory_ids`.
///
/// ponytail: every row hands the door a row its own SQL already fetched, which `readable_memory_ids` cannot take
/// because it reads its own rows; `contribution_entry_repo.rs` also hand-rolls the §8.6 closure (the Memory row, then
/// each backing Evidence row), upgrade by routing its Memory case through `readable_memory_ids` and dropping the row.
const M08_VISIBILITY_READABLE_SITES: [(&str, usize, &str); 4] = [
    (
        "crates/adapters/src/read_materialize.rs",
        2,
        "`load_overlay`: re-judges just-written Evidence rows of the RYW overlay; no Memory is involved, so `readable_memory_ids` has nothing to judge (§15.5)",
    ),
    (
        "crates/adapters/src/contribution_entry_repo.rs",
        2,
        "`visible`: judges a contribution source's Memory row and then each backing Evidence row itself, a hand-rolled copy of the §8.6 closure `readable_memory_ids` owns",
    ),
    (
        "crates/adapters/src/operation_receipt.rs",
        2,
        "`replay`: re-judges the one prior Evidence row its stream-binding SQL fetched, before reissuing a consistency token",
    ),
    (
        "crates/adapters/src/continuity_read.rs",
        2,
        "`validate_evidence`: re-judges the Evidence rows behind a continuity fact, next to its hash, SECRET_MATERIAL and lifecycle checks",
    ),
];

/// The identifier G-M08-2 counts first. Not `can_read(`: an alias (`use ...::can_read as cr; cr(..)`), a function pointer
/// (`let g = identity::can_read; g(..)`), an argument (`helper(can_read, v)`, `judge!(can_read, v)`) and `can_read (`
/// all use the function without that exact spelling.
const CAN_READ: &str = "can_read";

/// The identifier of the gate's row-level door, counted the same way as [`CAN_READ`].
const VISIBILITY_READABLE: &str = "visibility_readable";

/// Whether `disp` (repo-relative, `/`-separated) is production code G-M08-2 scans: `crates/adapters/src/**` and
/// `bins/<bin>/src/**`. Test trees are already excluded by [`door_production_sources`].
fn can_read_scan_scope(disp: &str) -> bool {
    let segments: Vec<&str> = disp.split('/').collect();
    matches!(
        segments.as_slice(),
        ["crates", "adapters", "src", ..] | ["bins", _, "src", ..]
    )
}

/// How many times `source`'s code names the identifier `name`: block comments blanked ([`strip_block_comments`]) and
/// every line cut at its `//` comment ([`code_before_line_comment`], so `///` and `//!` lines are empty), then `name`
/// with a non-identifier byte (or the line edge) on both sides. A call, an import (with or without `as`), a function
/// pointer, an argument and `name (` all count; `cannot_read`, `my_can_read` and `can_read_all` are other identifiers
/// for `can_read`.
///
/// ponytail: textual, so `name` inside a string literal counts (a false red, never a false green) and a wrapper that
/// calls it under another name is judged by its own file, upgrade to a syn-level call-graph check if either ever
/// shows up.
fn identifier_tokens(source: &str, name: &str) -> usize {
    strip_block_comments(source)
        .lines()
        .map(|line| {
            let code = code_before_line_comment(line);
            let bytes = code.as_bytes();
            code.match_indices(name)
                .filter(|(at, _)| {
                    (*at == 0 || !is_ident_byte(bytes[*at - 1]))
                        && !bytes
                            .get(*at + name.len())
                            .is_some_and(|b| is_ident_byte(*b))
                })
                .count()
        })
        .sum()
}

/// One identifier G-M08-2 ratchets: its declared `sites`, the wording of its red lines, and whether the gate file is
/// exempt from the pin.
struct M08Pin {
    token: &'static str,
    headline: &'static str,
    sites_const: &'static str,
    route: &'static str,
    sites: &'static [(&'static str, usize, &'static str)],
    gate_exempt: bool,
}

/// Red lines of one [`M08Pin`] over the scanned `sources`: an undeclared file holding the token, a declared file with
/// more tokens than its row, and a declared file with fewer (or gone).
fn m08_2_pin_problems(sources: &[(String, String)], pin: &M08Pin) -> Vec<String> {
    let found: BTreeMap<&str, usize> = sources
        .iter()
        .filter(|(disp, _)| !(pin.gate_exempt && disp == M08_GATE_HOME))
        .map(|(disp, source)| (disp.as_str(), identifier_tokens(source, pin.token)))
        .filter(|(_, tokens)| *tokens > 0)
        .collect();
    let (token, headline, sites_const, route) =
        (pin.token, pin.headline, pin.sites_const, pin.route);
    let mut problems = Vec::new();
    for (file, tokens) in &found {
        if !pin.sites.iter().any(|(site, _, _)| site == file) {
            problems.push(format!(
                "G-M08-2: {headline}: {file} holds {tokens} `{token}` token(s) and is not a declared site \
                 ({route}, or declare the file in {sites_const} with its count and reason)"
            ));
        }
    }
    for (file, expected, _) in pin.sites {
        let actual = found.get(file).copied().unwrap_or(0);
        if actual > *expected {
            problems.push(format!(
                "G-M08-2: {headline}: {file} holds {actual} `{token}` tokens, expected {expected} \
                 (an extra use in a declared site; {route}, or raise the count in {sites_const} with its reason)"
            ));
        } else if actual < *expected {
            problems.push(format!(
                "G-M08-2: {file} holds {actual} `{token}` tokens, expected {expected} \
                 (a declared use is gone, or the file does not exist; lower the count in {sites_const}, or drop the file once it is empty)"
            ));
        }
    }
    problems
}

/// M08 D1 / G-M08-2: for every file in [`can_read_scan_scope`] the number of `can_read` tokens equals its
/// [`M08_CAN_READ_SITES`] count and the number of `visibility_readable` tokens equals its
/// [`M08_VISIBILITY_READABLE_SITES`] count (the gate file exempt from the second), and a file with tokens that is not
/// declared is red. Red lines name the file and, for a declared one, both the found and the expected count:
/// "G-M08-2: can_read( call outside the read gate" / "G-M08-2: visibility_readable use outside its declared sites" for
/// an undeclared file or an extra use, and "... expected N" for a use that is gone or a file that does not exist.
/// `not_applicable` only when `crates/adapters/src` itself does not exist, and it names that directory (§57.1 第2条).
fn m08_2_can_read_one_home(root: &Path) -> Verdict {
    if !root.join("crates/adapters/src").is_dir() {
        return Verdict::NotApplicable(
            "missing object: crates/adapters/src (the read gate's crate) not delivered yet"
                .to_string(),
        );
    }
    let sources: Vec<(String, String)> = door_production_sources(root)
        .into_iter()
        .filter(|(disp, _)| can_read_scan_scope(disp))
        .collect();
    let pins = [
        M08Pin {
            token: CAN_READ,
            headline: "can_read( call outside the read gate",
            sites_const: "M08_CAN_READ_SITES",
            route: "route the read through read_gate::readable_memory_ids or read_gate::visibility_readable",
            sites: &M08_CAN_READ_SITES,
            gate_exempt: false,
        },
        M08Pin {
            token: VISIBILITY_READABLE,
            headline: "visibility_readable use outside its declared sites",
            sites_const: "M08_VISIBILITY_READABLE_SITES",
            route: "route the read through read_gate::readable_memory_ids",
            sites: &M08_VISIBILITY_READABLE_SITES,
            gate_exempt: true,
        },
    ];
    let problems: Vec<String> = pins
        .iter()
        .flat_map(|pin| m08_2_pin_problems(&sources, pin))
        .collect();
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// §23.1② / §22.5: `LedgerCounts` field set is exactly 6 — same shape as §37.2's "12 列"
// check. Guards the frozen invariant that the `visible` numerator can never be folded back
// into the ledger struct (adding a 7th `visible: u64` field would let G23-2's two injections
// stop being observable, §23.1②'s own text names this exact regression).
// ============================================================================

const LEDGER_COUNTS_FIELDS: &[&str] = &[
    "expected",
    "done",
    "deleted",
    "skipped",
    "open_gaps",
    "pending",
];

fn g23_1_ledger_counts_exactly_six_fields(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    let hit = files
        .iter()
        .find(|(_, s)| s.contains("struct LedgerCounts {"));
    let Some((path, source)) = hit else {
        return Verdict::NotApplicable(
            "retrieval::completeness::LedgerCounts (§22.5, ledger::close 尚未交付)".to_string(),
        );
    };

    let Some(start) = source.find("struct LedgerCounts {") else {
        return Verdict::NotApplicable("LedgerCounts struct body".to_string());
    };
    let Some(rel_end) = source[start..].find('}') else {
        return Verdict::Fail(vec![format!(
            "{}: `struct LedgerCounts {{` has no matching `}}` on the same scan window",
            display(root, path)
        )]);
    };
    let body = &source[start..start + rel_end];

    // One field name per non-empty line inside the braces, `name: type,` shape — the struct's
    // own definition is exactly this shape (see completeness.rs), so a plain per-line field
    // name extraction is sufficient without a full Rust parser.
    let mut fields: Vec<&str> = Vec::new();
    for line in body.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            fields.push(name.trim());
        }
    }

    if fields.len() != 6 {
        return Verdict::Fail(vec![format!(
            "{}: LedgerCounts has {} field(s) {:?}, expected exactly 6 {:?} — a 7th field \
             (e.g. `visible: u64`) would move the numerator back inside the ledger struct, \
             defeating G23-2's fault injections (§23.1②)",
            display(root, path),
            fields.len(),
            fields,
            LEDGER_COUNTS_FIELDS
        )]);
    }

    let expected: std::collections::BTreeSet<&str> = LEDGER_COUNTS_FIELDS.iter().copied().collect();
    let actual: std::collections::BTreeSet<&str> = fields.iter().copied().collect();
    if expected != actual {
        return Verdict::Fail(vec![format!(
            "{}: LedgerCounts field set is {:?}, expected exactly {:?}",
            display(root, path),
            fields,
            LEDGER_COUNTS_FIELDS
        )]);
    }

    Verdict::Pass
}

/// §11.8 / §22.5 / CLAUDE.md "唯一构造点模式": two independent concerns each name their sole
/// constructor `classify()` — `ClassifiedMemoryId` (`domain::consolidate`, §11.8) and
/// `CompletenessClass` (`retrieval::completeness`, §22.5). `FreshnessClass`'s equivalent
/// (§21.5) is named `classify_age` in `retrieval::signals`, not `classify` — it does not share
/// this needle and is out of this check's scope.
///
/// A single workspace-wide `fn classify(` count conflates the two concerns and can never pass
/// once both land (T6.4 pushed the count from 1 to 2 — the fixer-review finding that named
/// this exact collision) — so each concern's own file is checked independently: exactly 1
/// `fn classify(` in that file, never `<= 1` (a missing constructor is its own
/// `NotApplicable`, not a silent pass). The workspace-wide total is still cross-checked
/// against the number of landed known sites, so a stray third `fn classify(` anywhere else is
/// still red — it now fails at the site list instead of at a single global count.
const CLASSIFY_SOLE_CONSTRUCTION_SITES: &[(&str, &str)] = &[
    (
        "crates/domain/src/consolidate.rs",
        "ClassifiedMemoryId (§11.8)",
    ),
    (
        "crates/retrieval/src/completeness.rs",
        "CompletenessClass (§22.5)",
    ),
];

fn g11_8_classify_sole_construction_point(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    let total: usize = files
        .iter()
        .map(|(_, s)| s.matches("fn classify(").count())
        .sum();

    let mut applicable = 0usize;
    let mut failures = Vec::new();
    for (rel_path, label) in CLASSIFY_SOLE_CONSTRUCTION_SITES {
        let full = root.join(rel_path);
        let Some((_, source)) = files.iter().find(|(p, _)| *p == full) else {
            continue;
        };
        applicable += 1;
        let n = source.matches("fn classify(").count();
        if n != 1 {
            failures.push(format!(
                "{rel_path} ({label}): expected exactly 1 `fn classify(`, found {n}"
            ));
        }
    }

    if applicable == 0 {
        return Verdict::NotApplicable(
            "domain::consolidate::classify (§11.8) / retrieval::completeness::classify \
             (§22.5) — neither has landed yet"
                .to_string(),
        );
    }

    if total != applicable {
        failures.push(format!(
            "workspace-wide `fn classify(` count is {total}, expected {applicable} (one per \
             landed sole-construction site {CLASSIFY_SOLE_CONSTRUCTION_SITES:?}) — a stray \
             definition exists outside the known sites"
        ));
    }

    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

// ============================================================================
// §83.4 G80-3: Outbound Network Choke Point — real RHS
// ============================================================================

/// §83.4's `external-egress-registry` fenced block, column 1, verbatim order — the exact
/// variant-name set `OutboundPurpose` (`crates/domain/src/egress.rs`, §7.3/§83.4) must equal.
const EXTERNAL_EGRESS_REGISTRY: &[&str] = &[
    "USER_REASONING",
    "RETRIEVAL_EMBEDDING",
    "RETRIEVAL_RERANK",
    "PUBLIC_REASONING",
    "BILLING",
    "TRANSACTIONAL_EMAIL",
    "GIT_PROVIDER",
    "OAUTH_METADATA",
    "PUBLIC_SOURCE_FETCH",
    "DEADMAN_HEALTHCHECK",
];

const INFRA_NETWORK_HTTP_RS: &str = "crates/infra-network/src/http.rs";

/// ADR-0003 / §83.4's `intra-cell-resource-registry` fenced block, column 1 — the exact
/// variant-name set `IntraCellResource` (`crates/infra-cell/src/resource.rs`) must equal.
/// Sibling of [`EXTERNAL_EGRESS_REGISTRY`]; the two are checked for disjointness by
/// [`intra_cell_registry_disjoint_from_external`] — a resource must never be nameable through
/// both registries at once.
const INTRA_CELL_RESOURCE_REGISTRY: &[&str] = &[
    "QDRANT_REST",
    "RETRIEVAL_EMBEDDING_RPC",
    "PRIVATE_INFERENCE_RPC",
];

const INFRA_CELL_RESOURCE_RS: &str = "crates/infra-cell/src/resource.rs";

/// ADR-0003 Layer 1A's own sentinel file (external-egress HTTP transport, now built on top of
/// Layer 0 instead of constructing its own raw client — [`g80_3_layer1_crates_sentinel`]).
const INFRA_EGRESS_HTTP_RS_LAYER1A: &str = "crates/infra-egress/src/http.rs";

/// §83.4 判据1, 注错 a: `reqwest`/`hyper`'s client type reached through a `use`-imported bare
/// alias (`use reqwest::Client; Client::new()`) is exactly as much a raw-client construction
/// as the fully-qualified spelling — the fully-qualified needle set below cannot see it at
/// all, which is the exact loophole the 注错 a fixture in this module's tests demonstrates.
/// Matched with a word-boundary guard ([`is_bare_needle_word_start`]) so an unrelated type that
/// merely ends in `Client` (`MyClient::new(`) is not a false hit.
const BARE_HTTP_CLIENT_NEEDLES: [&str; 4] = [
    "Client::new(",
    "Client::builder(",
    "Client::default(",
    "ClientBuilder::new(",
];

/// §83.4 判据1, decisive proof this closes: `humaux_infra_network::reqwest`'s re-export lets a
/// second crate reach `reqwest::Client` without ever listing `reqwest` in its own manifest —
/// [`g80_3_manifest_dependency_check`] alone cannot see that (the second crate depends on
/// `humaux-infra-network`, not `reqwest`, so its manifest set stays clean), and
/// [`is_bare_needle_word_start`]'s own word-boundary guard *rejects* an attacker-chosen alias
/// that happens to end in `Client` (`use ... reqwest::Client as HttpClient; HttpClient::new()`
/// — the byte before `Client::new(` inside `HttpClient::new(` is `p`, an identifier char) by
/// design, since that guard exists to reject an *unrelated* type merely named `MyClient`. This
/// needle instead matches the import line itself — `reqwest::Client as`/`reqwest::ClientBuilder
/// as`, any qualification prefix, any chosen alias name — so the alias's own name can never
/// evade it the way the call-site needle above can be evaded.
const REQWEST_CLIENT_ALIAS_IMPORT_NEEDLES: [&str; 2] =
    ["reqwest::Client as ", "reqwest::ClientBuilder as "];

/// §83.4 raw HTTP transport construction needles: `reqwest::Client::new`/`::builder` and
/// `hyper::Client::new`/`::builder` (fully-qualified spellings, kept alongside the bare-alias
/// set above so both spellings are named explicitly in one place rather than relying on the
/// bare set's substring overlap to carry the qualified case), comment-line-filtered like every
/// other scan in this module. The needle already includes the call-opening `(`, so — unlike
/// [`count_construction_calls`]'s struct-literal targets — there is no legal
/// `struct`/`impl`/`->`-prefixed spelling of `reqwest::Client::new(` that isn't a real call,
/// so no declaration-shape guard is needed for the qualified forms.
fn find_raw_http_client_calls(source: &str) -> Vec<usize> {
    let qualified_needles = [
        "reqwest::Client::new(",
        "reqwest::Client::builder(",
        "hyper::Client::new(",
        "hyper::Client::builder(",
    ];
    let mut hits = Vec::new();
    for needle in qualified_needles {
        let mut start = 0usize;
        while let Some(rel) = source[start..].find(needle) {
            let idx = start + rel;
            if !line_is_comment_at(source, idx) {
                hits.push(idx);
            }
            start = idx + needle.len();
        }
    }
    for needle in BARE_HTTP_CLIENT_NEEDLES {
        let mut start = 0usize;
        while let Some(rel) = source[start..].find(needle) {
            let idx = start + rel;
            if !line_is_comment_at(source, idx) && is_bare_needle_word_start(source, idx) {
                hits.push(idx);
            }
            start = idx + needle.len();
        }
    }
    for needle in REQWEST_CLIENT_ALIAS_IMPORT_NEEDLES {
        let mut start = 0usize;
        while let Some(rel) = source[start..].find(needle) {
            let idx = start + rel;
            if !line_is_comment_at(source, idx) {
                hits.push(idx);
            }
            start = idx + needle.len();
        }
    }
    hits
}

/// Word-boundary guard for [`BARE_HTTP_CLIENT_NEEDLES`]: true unless the byte immediately
/// before `idx` continues an identifier (letter/digit/`_`) — rejects `MyClient::new(` (a
/// same-shaped but unrelated local type) while accepting both a bare `Client::new(` and the
/// fully-qualified `reqwest::Client::new(` (preceded by `:`, not an identifier char).
fn is_bare_needle_word_start(source: &str, idx: usize) -> bool {
    match source[..idx].chars().next_back() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_'),
    }
}

/// Extracts each variant identifier from a `enum <enum_name> { .. }` block in `source` — same
/// shape as [`parse_degrade_variant_names`] but for a plain `enum` (not the `degrade_code!`
/// macro) and tolerant of data-carrying variants (`Foo(Bar)` counts as `Foo`, matching
/// `OutboundPurpose`'s three private-data variants that each carry an `EgressPermit`).
/// Doc-comment (`///`) and attribute (`#[..]`) lines are skipped.
fn parse_enum_variant_names(source: &str, enum_name: &str) -> Vec<String> {
    let needle = format!("enum {enum_name}");
    let Some(rel) = source.find(&needle) else {
        return Vec::new();
    };
    let after = rel + needle.len();
    let Some(brace_rel) = source[after..].find('{') else {
        return Vec::new();
    };
    let open = after + brace_rel;
    let Some(close) = matching_brace_end(source, open) else {
        return Vec::new();
    };
    let block = &source[open + 1..close - 1];
    let mut out = Vec::new();
    for line in block.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        let ident: String = t
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if ident.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            out.push(ident);
        }
    }
    out
}

/// §83.4 判据3: same `enum <enum_name> { .. }` block [`parse_enum_variant_names`] walks, but
/// keeps each variant's tuple payload text verbatim instead of discarding it — the payload
/// shape is exactly what 判据3 ("标为 private-data 的 purpose 在类型上只能由 EgressPermit
/// 构造") needs to check. One line per variant is assumed (this codebase's own style for
/// `OutboundPurpose`, matched by every fixture in this module's tests): a variant's payload,
/// if any, must open and close its parens on the same line.
fn parse_enum_variant_payloads(source: &str, enum_name: &str) -> Vec<(String, Option<String>)> {
    let needle = format!("enum {enum_name}");
    let Some(rel) = source.find(&needle) else {
        return Vec::new();
    };
    let after = rel + needle.len();
    let Some(brace_rel) = source[after..].find('{') else {
        return Vec::new();
    };
    let open = after + brace_rel;
    let Some(close) = matching_brace_end(source, open) else {
        return Vec::new();
    };
    let block = &source[open + 1..close - 1];
    let mut out = Vec::new();
    for line in block.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            continue;
        }
        let ident: String = t
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            continue;
        }
        let rest = t[ident.len()..].trim_start();
        let payload = if let Some(inner) = rest.strip_prefix('(') {
            inner.find(')').map(|end| inner[..end].trim().to_string())
        } else {
            None
        };
        out.push((ident, payload));
    }
    out
}

/// §83.4 判据0 (workspace 正哨兵): `crates/infra-network` must be a real, live workspace
/// member with its transport file present — any one of the three missing is red before
/// 判据1/2 are even evaluated. Without this, deleting the whole crate would make the
/// raw-client scan below vacuously report "0 hits outside the expected file" (there is no
/// file left to hit) — the exact 恒真闸 shape §59.1/§80.1 call out elsewhere in this module.
/// `metadata_json` is injectable so tests do not need to shell out to a real `cargo metadata`
/// against a fixture directory that has no real workspace `Cargo.toml`.
fn g80_3_workspace_sentinel(root: &Path, metadata_json: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    if !root.join("crates/infra-network/Cargo.toml").is_file() {
        problems.push("正哨兵缺失: crates/infra-network/Cargo.toml 不存在".to_string());
    }
    if !root.join(INFRA_NETWORK_HTTP_RS).is_file() {
        problems.push(format!("正哨兵缺失: {INFRA_NETWORK_HTTP_RS} 不存在"));
    }
    // Exact match against `packages[].name`, not a substring scan over the raw JSON text: a
    // substring match on `"humaux-infra-network"` stays true even after the crate is dropped
    // from the workspace `members` list, as long as *some* other member still path-depends on
    // it by name (that dependency edge's own JSON also contains the literal string) — the
    // 注错 0b fixture below pins this against regressing back to `.contains`.
    let member_present = metadata_json
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|v| v.get("packages").and_then(|p| p.as_array()).cloned())
        .is_some_and(|packages| {
            packages
                .iter()
                .any(|p| p.get("name").and_then(|n| n.as_str()) == Some("humaux-infra-network"))
        });
    if !member_present {
        problems.push("正哨兵缺失: cargo metadata members 不含 humaux-infra-network".to_string());
    }
    problems
}

/// ADR-0003 / §83.4 判据0 补充: Layer 1's two capability-wrapper crates
/// (`humaux-infra-egress` external egress, `humaux-infra-cell` same-Cell access) must both be
/// real, live workspace members — same three-part shape [`g80_3_workspace_sentinel`] already
/// checks for Layer 0, one crate at a time so a missing member names exactly which crate/file
/// is gone rather than one merged, ambiguous line.
fn g80_3_layer1_crates_sentinel(root: &Path, metadata_json: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    let member_names: std::collections::HashSet<String> = metadata_json
        .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
        .and_then(|v| v.get("packages").and_then(|p| p.as_array()).cloned())
        .map(|packages| {
            packages
                .iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    for (crate_dir, manifest_name, sentinel_file) in [
        (
            "crates/infra-egress",
            "humaux-infra-egress",
            INFRA_EGRESS_HTTP_RS_LAYER1A,
        ),
        (
            "crates/infra-cell",
            "humaux-infra-cell",
            INFRA_CELL_RESOURCE_RS,
        ),
    ] {
        if !root.join(format!("{crate_dir}/Cargo.toml")).is_file() {
            problems.push(format!("正哨兵缺失: {crate_dir}/Cargo.toml 不存在"));
        }
        if !root.join(sentinel_file).is_file() {
            problems.push(format!("正哨兵缺失: {sentinel_file} 不存在"));
        }
        if !member_names.contains(manifest_name) {
            problems.push(format!(
                "正哨兵缺失: cargo metadata members 不含 {manifest_name}"
            ));
        }
    }
    problems
}

/// §83.4 判据1 补充 (manifest-level positive check, 注错 a 的第二重防线): the *set* of
/// workspace-member manifests that declare a `reqwest`/`hyper` dependency must equal exactly
/// `{crates/infra-network/Cargo.toml}`. A raw client call needs a matching `[dependencies]`
/// entry to even compile, so this catches a second crate reaching for `reqwest`/`hyper` at the
/// manifest level — before any source-text needle (bare-alias or otherwise) even has a call
/// site to find. Uses the same `cargo metadata` document [`g80_3_workspace_sentinel`] already
/// requires, parsed the same way §78.3's `dependency_rule_from_metadata_json` parses it.
fn g80_3_manifest_dependency_check(metadata_json: &str, root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(metadata_json) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("cargo metadata output not valid JSON: {e}"));
            return problems;
        }
    };
    let Some(packages) = parsed.get("packages").and_then(|p| p.as_array()) else {
        problems.push("cargo metadata output has no `packages` array".to_string());
        return problems;
    };

    // `cargo metadata`'s `manifest_path` is always an absolute, canonicalized path — `root`
    // here is typically `CARGO_MANIFEST_DIR/..` (a literal, un-canonicalized `..` component),
    // so a plain `display()` (component-wise `strip_prefix`) never matches it. Canonicalizing
    // `root` once fixes the real-repo case; fixture tests pass a nonexistent root (e.g.
    // `/fixture-root`) where `canonicalize` fails, so this falls back to comparing against
    // `root` as given — exactly [`display`]'s existing behavior for those fixtures.
    let root_for_display = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let mut actual: BTreeSet<String> = BTreeSet::new();
    for pkg in packages {
        let deps = pkg
            .get("dependencies")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        let depends_on_http_client = deps.iter().any(|d| {
            matches!(
                d.get("name").and_then(|n| n.as_str()),
                Some("reqwest") | Some("hyper")
            )
        });
        if !depends_on_http_client {
            continue;
        }
        let Some(manifest_path) = pkg.get("manifest_path").and_then(|m| m.as_str()) else {
            continue;
        };
        actual.insert(display(&root_for_display, Path::new(manifest_path)));
    }

    let mut expected = BTreeSet::new();
    expected.insert("crates/infra-network/Cargo.toml".to_string());
    if actual != expected {
        problems.push(format!(
            "reqwest/hyper 依赖声明的 manifest 集合 != {{crates/infra-network/Cargo.toml}}，实际: \
             {actual:?}"
        ));
    }
    problems
}

/// §83.4 判据1 补充, second backstop: `pub use reqwest;` (`crates/infra-network/src/lib.rs`)
/// lets any crate reach `reqwest::Client`/`reqwest::Error` *types* through
/// `humaux_infra_network::reqwest` without ever listing `reqwest` in its own manifest — which
/// means [`g80_3_manifest_dependency_check`] alone cannot see a new crate that starts depending
/// on `humaux-infra-network` for exactly that purpose. This asserts the *dependents* of
/// `humaux-infra-network` are exactly the two Layer 1 crates ADR-0003 names — a third crate
/// (e.g. `humaux-adapters`) adding `humaux-infra-network = { path = ... }` to reach the
/// re-export is red here even if [`find_raw_http_client_calls`]'s needles somehow miss the
/// resulting call site.
fn g80_3_infra_network_dependents_check(metadata_json: &str, root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let parsed: serde_json::Value = match serde_json::from_str(metadata_json) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("cargo metadata output not valid JSON: {e}"));
            return problems;
        }
    };
    let Some(packages) = parsed.get("packages").and_then(|p| p.as_array()) else {
        problems.push("cargo metadata output has no `packages` array".to_string());
        return problems;
    };
    let root_for_display = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let mut actual: BTreeSet<String> = BTreeSet::new();
    for pkg in packages {
        let deps = pkg
            .get("dependencies")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        let depends_on_infra_network = deps
            .iter()
            .any(|d| d.get("name").and_then(|n| n.as_str()) == Some("humaux-infra-network"));
        if !depends_on_infra_network {
            continue;
        }
        let Some(manifest_path) = pkg.get("manifest_path").and_then(|m| m.as_str()) else {
            continue;
        };
        actual.insert(display(&root_for_display, Path::new(manifest_path)));
    }

    let expected: BTreeSet<String> = [
        "crates/infra-egress/Cargo.toml",
        "crates/infra-cell/Cargo.toml",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    if actual != expected {
        problems.push(format!(
            "humaux-infra-network 的依赖方 manifest 集合 != \
             {{crates/infra-egress/Cargo.toml, crates/infra-cell/Cargo.toml}}，实际: {actual:?}"
        ));
    }
    problems
}

/// §83.4 判据1/2 pure comparator over an already-scanned `.rs` file set — separated from
/// [`g80_3_outbound_choke_point`] so tests can inject a small fixture file list instead of
/// scanning (or faking) the whole workspace.
fn g80_3_transport_and_registry_check(files: &[(PathBuf, String)], root: &Path) -> Vec<String> {
    let mut problems = Vec::new();

    // 判据1: raw client construction path set == {infra-network/src/http.rs}
    let mut raw_sites: BTreeSet<String> = BTreeSet::new();
    for (path, source) in files {
        if !find_raw_http_client_calls(source).is_empty() {
            raw_sites.insert(display(root, path));
        }
    }
    let mut expected_raw = BTreeSet::new();
    expected_raw.insert(INFRA_NETWORK_HTTP_RS.to_string());
    if raw_sites != expected_raw {
        problems.push(format!(
            "raw HTTP client (reqwest::Client::new/builder, hyper::Client::new/builder) 构造 \
             点集合 != {{{INFRA_NETWORK_HTTP_RS}}}，实际: {raw_sites:?}"
        ));
    }

    // 判据2: OutboundPurpose 变体集合 == external-egress-registry 第一列，逐字相等
    match files
        .iter()
        .find(|(p, _)| display(root, p) == "crates/domain/src/egress.rs")
    {
        None => problems.push(
            "missing object: crates/domain/src/egress.rs::OutboundPurpose (§83.4 判据2 尚未\
             交付)"
                .to_string(),
        ),
        Some((_, source)) => {
            let actual: BTreeSet<String> = parse_enum_variant_names(source, "OutboundPurpose")
                .into_iter()
                .collect();
            let expected: BTreeSet<String> = EXTERNAL_EGRESS_REGISTRY
                .iter()
                .map(|s| s.to_string())
                .collect();
            if actual.is_empty() {
                problems.push(
                    "positive control missing: OutboundPurpose 变体集合为空 —— matcher 坏了或\
                     枚举未落地，两者都必须报红，不得默认放行"
                        .to_string(),
                );
            } else if actual != expected {
                problems.push(format!(
                    "OutboundPurpose 变体集合 != external-egress-registry 第一列，实际: \
                     {actual:?}，期望: {expected:?}"
                ));
            }

            // 判据3: 每个 private-data 变体的 tuple payload 必须逐字是 `EgressPermit` ——
            // "标为 private-data 的 purpose 在类型上只能由 EgressPermit 构造" is a claim
            // about *this enum's definition text*, not about `authorize`'s behavior, so it
            // belongs here alongside 判据2 rather than in a trybuild fixture that can only
            // ever exercise `EgressPermit`'s own construction path (§7.3), never this enum's
            // payload shape. `EXTERNAL_EGRESS_REGISTRY`'s first three entries are exactly the
            // private-data rows (registry column order, pinned by 判据2's own comparison).
            let payloads = parse_enum_variant_payloads(source, "OutboundPurpose");
            for private_variant in &EXTERNAL_EGRESS_REGISTRY[..3] {
                match payloads.iter().find(|(name, _)| name == private_variant) {
                    None => {} // absence is already reported by 判据2 above.
                    Some((_, None)) => problems.push(format!(
                        "判据3 违反: OutboundPurpose::{private_variant} 是裸变体，未携带 \
                         EgressPermit —— private-data purpose 必须类型化携带 permit"
                    )),
                    Some((_, Some(payload))) if payload != "EgressPermit" => {
                        problems.push(format!(
                            "判据3 违反: OutboundPurpose::{private_variant} 携带的是 \
                             `{payload}`，不是 `EgressPermit`"
                        ))
                    }
                    Some((_, Some(_))) => {}
                }
            }
        }
    }

    problems
}

/// ADR-0003 / §83.4 Layer 1B's own registry-consistency judgment — the sibling of 判据2 above,
/// scanning `crates/infra-cell/src/resource.rs`'s `IntraCellResource` enum instead of
/// `domain::egress::OutboundPurpose`. Pure comparator over an already-scanned file set, same
/// shape [`g80_3_transport_and_registry_check`] uses, so tests can inject a small fixture
/// instead of scanning the whole workspace.
fn g80_3_intra_cell_registry_check(files: &[(PathBuf, String)], root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    match files
        .iter()
        .find(|(p, _)| display(root, p) == INFRA_CELL_RESOURCE_RS)
    {
        None => problems.push(format!(
            "missing object: {INFRA_CELL_RESOURCE_RS}::IntraCellResource (ADR-0003 判据1 尚未\
             交付)"
        )),
        Some((_, source)) => {
            let actual: BTreeSet<String> = parse_enum_variant_names(source, "IntraCellResource")
                .into_iter()
                .collect();
            let expected: BTreeSet<String> = INTRA_CELL_RESOURCE_REGISTRY
                .iter()
                .map(|s| s.to_string())
                .collect();
            if actual.is_empty() {
                problems.push(
                    "positive control missing: IntraCellResource 变体集合为空 —— matcher 坏了\
                     或枚举未落地，两者都必须报红，不得默认放行"
                        .to_string(),
                );
            } else if actual != expected {
                problems.push(format!(
                    "IntraCellResource 变体集合 != intra-cell-resource-registry，实际: \
                     {actual:?}，期望: {expected:?}"
                ));
            }
            problems.extend(g80_3_no_string_to_resource_constructor_fn(source));
        }
    }
    problems
}

/// Byte offset of the `)` matching the `(` at `s`'s own start (`s.as_bytes()[0]` must be `(`).
/// Depth-counting sibling of [`matching_brace_end`] for parens instead of braces.
fn find_matching_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether `ident` appears in `header` as a whole identifier, not merely a substring —
/// `"IntraCellResourceRegistry"` must not match a search for `"IntraCellResource"` (both the
/// byte before the match and the byte after it must not continue an identifier). Word-boundary
/// sibling of [`is_bare_needle_word_start`], checked on both ends since `header` here is a
/// short, already-located slice rather than a whole-file scan.
fn header_names_ident_exactly(header: &str, ident: &str) -> bool {
    let mut start = 0usize;
    while let Some(rel) = header[start..].find(ident) {
        let idx = start + rel;
        let end = idx + ident.len();
        let before_ok = match header[..idx].chars().next_back() {
            None => true,
            Some(c) => !(c.is_alphanumeric() || c == '_'),
        };
        let after_ok = match header[end..].chars().next() {
            None => true,
            Some(c) => !(c.is_alphanumeric() || c == '_'),
        };
        if before_ok && after_ok {
            return true;
        }
        start = end;
    }
    false
}

/// §83.4 判据1, 注错 f's real mechanism: no `fn` inside `IntraCellResource`'s own `impl`
/// surface (`impl IntraCellResource { .. }` or `impl <Trait> for IntraCellResource { .. }`)
/// may accept a `&str`/`String` parameter and return `Self` — the general "no string
/// constructs this enum" property, scoped to this enum's own impls specifically so an
/// unrelated type's legitimate `&str -> Result<Self, _>` (e.g. `CellCidr::from_str`, in the
/// same file) is never a false hit.
///
/// A single fixed-name trybuild fixture (`tests/ui/fail_resource_from_raw_url_string.rs`)
/// cannot pin this property on its own: it only ever exercises a *direct literal* coerced to
/// `IntraCellResource`, which stays compile-fail regardless of whether some differently-named
/// associated fn (`from_url`, `parse_legacy`, …) exists that does the equivalent conversion
/// through a normal function call instead of a literal — `IntraCellResource::from_url("x")`
/// compiles fine even though the trybuild fixture's own literal-coercion line still doesn't.
/// This scan is the check that actually observes the property 判据1 claims: decisive proof is
/// that adding `pub fn from_url(_u: &str) -> Self { Self::QDRANT_REST }` inside `impl
/// IntraCellResource` left both the trybuild suite and `architecture-check` green before this
/// function existed.
fn g80_3_no_string_to_resource_constructor_fn(source: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find("impl ") {
        let idx = search_from + rel;
        if line_is_comment_at(source, idx) {
            search_from = idx + 5;
            continue;
        }
        let Some(brace_rel) = source[idx..].find('{') else {
            break;
        };
        let open = idx + brace_rel;
        let header = &source[idx..open];
        search_from = open + 1;
        if !header_names_ident_exactly(header, "IntraCellResource") {
            continue;
        }
        let Some(close) = matching_brace_end(source, open) else {
            continue;
        };
        let body = &source[open + 1..close - 1];
        let body_start_abs = open + 1;
        for (fn_rel, _) in body.match_indices("fn ") {
            if line_is_comment_at(source, body_start_abs + fn_rel) {
                continue;
            }
            let name_start = fn_rel + 3;
            let Some(paren_rel) = body[name_start..].find('(') else {
                continue;
            };
            let paren_abs_in_body = name_start + paren_rel;
            let Some(close_paren_rel) = find_matching_paren(&body[paren_abs_in_body..]) else {
                continue;
            };
            let params = &body[paren_abs_in_body + 1..paren_abs_in_body + close_paren_rel];
            let after_params = &body[paren_abs_in_body + close_paren_rel + 1..];
            let sig_end = after_params.find('{').unwrap_or(after_params.len());
            let return_part = after_params[..sig_end].trim_start();
            let takes_string = params.contains("&str") || params.contains("String");
            let returns_self = return_part.starts_with("->") && return_part.contains("Self");
            if takes_string && returns_self {
                let name: String = body[name_start..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                problems.push(format!(
                    "判据1 违反: {header_trimmed} 内存在字符串构造函数 fn {name}(...) -> Self \
                     形状 —— 任意命名的 fn 均不得从 &str/String 构造 Self（不止 From/FromStr \
                     两个固定名字）",
                    header_trimmed = header.trim()
                ));
            }
        }
    }
    problems
}

/// ADR-0003 reverse sentinel: `EXTERNAL_EGRESS_REGISTRY` and `INTRA_CELL_RESOURCE_REGISTRY`
/// must name disjoint sets — a resource nameable through *both* registries at once is exactly
/// the "Qdrant snuck into external-egress-registry" back door ADR-0003 exists to close (the
/// two enums' own 判据2/判据1-sibling checks each independently compare against *one* of these
/// two registries and would both report PASS if someone edited `OutboundPurpose` and
/// `EXTERNAL_EGRESS_REGISTRY` together to add a variant that is also still a live
/// `IntraCellResource` entry — this check is the only one that looks at both at once). Pure
/// comparator over injectable registry slices so the fault test below does not have to mutate
/// the real consts.
fn intra_cell_registry_disjoint_from_external(
    external: &[&str],
    intra_cell: &[&str],
) -> Vec<String> {
    let external_set: BTreeSet<&str> = external.iter().copied().collect();
    intra_cell
        .iter()
        .filter(|r| external_set.contains(*r))
        .map(|r| {
            format!(
                "ADR-0003 反向哨兵违反: {r:?} 同时出现在 external-egress-registry 与 \
                 intra-cell-resource-registry —— 一个资源不得同时可经两条 registry 命名"
            )
        })
        .collect()
}

/// §83.4 G80-3 full check: Layer 0/1A/1B 判据0/1/2/3, folding in real `cargo metadata` for the
/// workspace positive sentinel.
fn g80_3_outbound_choke_point(root: &Path) -> Verdict {
    // No early `NotApplicable` return for a missing `crates/infra-network` directory: T4.1 has
    // already delivered this crate, so its absence from here on is a regression (someone
    // deleted it), not "not yet built" — 注错 0a's whole point. Falling straight into the
    // workspace sentinel below reports that as `Fail` with the three named-missing-object
    // lines it already produces, instead of the vacuous "nothing to scan, so nothing is wrong"
    // `NotApplicable` a directory-existence early-return would produce.
    // dep: subprocess(cargo) — cargo metadata, workspace dependency graph read
    let metadata_json = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());

    let mut problems = g80_3_workspace_sentinel(root, metadata_json.as_deref());
    problems.extend(g80_3_layer1_crates_sentinel(root, metadata_json.as_deref()));
    if !problems.is_empty() {
        // 判据0 任一为假 -> 先红：前提不成立时继续判 1/2/3 只会制造噪声，不会制造信息。
        return Verdict::Fail(problems);
    }

    // 判据0 通过意味着 `metadata_json` 一定是 `Some`（sentinel 的 member_present 检查在
    // `None` 时必产生 problem，已在上面提前返回）——`expect` 而非静默跳过，manifest 依赖检查
    // 不是可选项。
    let metadata_json =
        metadata_json.expect("g80_3_workspace_sentinel passed with no metadata_json");
    problems.extend(g80_3_manifest_dependency_check(&metadata_json, root));
    problems.extend(g80_3_infra_network_dependents_check(&metadata_json, root));

    let files = walk_workspace_rs(root);
    problems.extend(g80_3_transport_and_registry_check(&files, root));
    problems.extend(g80_3_intra_cell_registry_check(&files, root));
    problems.extend(intra_cell_registry_disjoint_from_external(
        EXTERNAL_EGRESS_REGISTRY,
        INTRA_CELL_RESOURCE_REGISTRY,
    ));

    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// ADR-0039 / §11.4 — an outbound client dials only through the checked resolver.
// ============================================================================

/// ADR-0039's own sentinel files: the ONLY three `.rs` files that may name
/// `build_client_with_resolver(` at a call site.
///
/// - `crates/infra-network/src/http.rs` is where the function is defined (its own unit tests
///   call it);
/// - `crates/infra-egress/src/resolver.rs` (Layer 1A) and `crates/infra-cell/src/transport.rs`
///   (Layer 1B) are the two modules that install a *validating* resolver into the client.
///
/// A fourth call site would mean somebody built an outbound client with a resolver of their own
/// choosing, bypassing whichever of those two modules owns that destination's policy — which is
/// exactly the shape of the bug this gate exists for.
const CHECKED_CLIENT_CALL_SITES: [&str; 3] = [
    "crates/infra-network/src/http.rs",
    "crates/infra-egress/src/resolver.rs",
    "crates/infra-cell/src/transport.rs",
];

/// The two Layer 1 resolver modules — each must actually still contain a call (living sentinel:
/// if a refactor drops the pinned-client construction entirely, the "no offenders" scan above
/// would go green on an empty world).
const LAYER1_RESOLVER_MODULES: [&str; 2] = [
    "crates/infra-egress/src/resolver.rs",
    "crates/infra-cell/src/transport.rs",
];

const INFRA_NETWORK_HTTP_RS_ADR_0039: &str = "crates/infra-network/src/http.rs";

/// The BYOK transport's resolver may only be chosen in two places: the derived constructor
/// (`OpenAiCompatibleProvider::with_egress_transport`, which passes one resolver to both the
/// §11.4 check and the dial) and the rebinding acceptance test, which deliberately drives the
/// dial leg on its own to prove the refusal happens before the connection.
const EGRESS_TRANSPORT_RESOLVER_SITES: [&str; 2] = [
    "crates/adapters/src/byok.rs",
    "crates/adapters/tests/byok_egress_rebinding.rs",
];

/// The file that must keep defining the derived constructor (living sentinel for 判据8).
const ADAPTERS_BYOK_RS_ADR_0039: &str = "crates/adapters/src/byok.rs";

/// This file's own text contains every needle below as a string literal — it must be excluded
/// or the gate reports itself (same `this_file` exclusion
/// `crates/projection/tests/no_handwritten_filter_scan.rs` uses).
const ARCHITECTURE_CHECK_SELF: &str = "xtask/src/architecture_check.rs";

/// Non-comment occurrences of `needle` in `source`.
fn code_occurrences(source: &str, needle: &str) -> usize {
    let mut n = 0usize;
    let mut from = 0usize;
    while let Some(rel) = source[from..].find(needle) {
        let at = from + rel;
        if !line_is_comment_at(source, at) {
            n += 1;
        }
        from = at + needle.len();
    }
    n
}

/// ADR-0039 判据, as a pure comparator over an already-scanned file set so tests can inject a
/// small fixture instead of scanning the whole workspace (same shape as
/// [`g80_3_transport_and_registry_check`]).
///
/// 判据1 — the resolver-less constructor stays deleted: `build_client(` must not appear as a
/// call anywhere. While it existed, `infra-egress`'s two transports dialed with the system
/// resolver while §11.4's SSRF gate checked with an injected one; "the address that was
/// checked" and "the address that is connected to" were two different lookups, which is the
/// DNS-rebinding window on the path that carries user provider API keys.
///
/// 判据2 — the checked constructor's call-site set ⊆ [`CHECKED_CLIENT_CALL_SITES`]: a fourth
/// caller means an outbound client built with a resolver that answers to nobody's policy.
///
/// 判据3 — living sentinels: `build_client_with_resolver` still defined in
/// `infra-network/src/http.rs`, no `pub fn build_client(` re-added there, and both Layer 1
/// resolver modules still call it. Without these, deleting the mechanism outright reads as pass.
///
/// 判据4 — `.dns_resolver(` (the `reqwest::ClientBuilder` method that installs a resolver) may
/// only be named in the Layer 0 construction point, so the "which resolver does this client
/// dial through" decision cannot be re-made anywhere else.
///
/// 判据5–8 close what 判据1–4 could not observe, and which the card-17 review caught in
/// production: 判据1–4 pin *where* an outbound client is built, never *which resolver a caller
/// injects*. `bins/private-worker` handed the operator's `HUMAUX_PRIVATE_WORKER_DNS_PINS`
/// resolver to `OpenAiCompatibleProvider::new` (the check) while `EgressHttpTransport::new`
/// hardwired `ssrf::SystemDnsResolver` for the dial — two different resolvers, the exact gap
/// this ADR exists to close, and on a DNS-pinned node also a hard availability regression.
///
/// 判据5 — `EgressHttpTransport::new(` is gone repo-wide: a constructor that picks the dial
/// resolver for you is a constructor that can disagree with the check.
///
/// 判据6 — `EgressHttpTransport::with_resolver(` call sites ⊆
/// [`EGRESS_TRANSPORT_RESOLVER_SITES`]: anywhere else is a caller choosing the dial resolver
/// independently of the check resolver again.
///
/// 判据7 — no file under `bins/<x>/src/` calls `OpenAiCompatibleProvider::new(`: production
/// goes through `with_egress_transport`, which takes the resolver **once** and derives both
/// legs from it, so the two cannot be given different values.
///
/// 判据8 — living sentinel: `crates/adapters/src/byok.rs` still defines
/// `pub fn with_egress_transport` and still builds its transport with
/// `EgressHttpTransport::with_resolver(`. Delete the derived constructor and 判据5/6/7 would
/// all go green on an empty world.
fn checked_resolver_dial_problems(files: &[(PathBuf, String)], root: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let mut call_sites: BTreeSet<String> = BTreeSet::new();
    let mut resolver_install_sites: BTreeSet<String> = BTreeSet::new();
    let mut transport_resolver_sites: BTreeSet<String> = BTreeSet::new();

    for (path, source) in files {
        let rel = display(root, path);
        if rel == ARCHITECTURE_CHECK_SELF {
            continue;
        }
        // `build_client_with_resolver(` does not contain `build_client(` (the `_with` is in the
        // way), so the two needles never alias each other.
        let unchecked = code_occurrences(source, "build_client(");
        if unchecked > 0 {
            problems.push(format!(
                "ADR-0039 判据1 违反: {rel} 调用了 build_client(（{unchecked} 处）—— \
                 无 resolver 的出网 client 构造已删除，检查过的地址与拨号地址会重新分叉 \
                 (§11.4 DNS rebinding)"
            ));
        }
        if code_occurrences(source, "build_client_with_resolver(") > 0 {
            call_sites.insert(rel.clone());
        }
        if code_occurrences(source, ".dns_resolver(") > 0 {
            resolver_install_sites.insert(rel.clone());
        }

        byok_constructor_problems(&rel, source, &mut transport_resolver_sites, &mut problems);
    }

    let allowed: BTreeSet<String> = CHECKED_CLIENT_CALL_SITES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for site in &call_sites {
        if !allowed.contains(site) {
            problems.push(format!(
                "ADR-0039 判据2 违反: {site} 构造了出网 client —— 构造点必须是 \
                 {CHECKED_CLIENT_CALL_SITES:?} 之一（各自装的是那条路自己的已检查 resolver）"
            ));
        }
    }

    let expected_install: BTreeSet<String> =
        std::iter::once(INFRA_NETWORK_HTTP_RS_ADR_0039.to_string()).collect();
    if !resolver_install_sites.is_empty() && resolver_install_sites != expected_install {
        problems.push(format!(
            "ADR-0039 判据4 违反: .dns_resolver( 的出现点集合 != \
             {{{INFRA_NETWORK_HTTP_RS_ADR_0039}}}，实际: {resolver_install_sites:?}"
        ));
    }

    match files
        .iter()
        .find(|(p, _)| display(root, p) == INFRA_NETWORK_HTTP_RS_ADR_0039)
    {
        None => problems.push(format!(
            "missing object: {INFRA_NETWORK_HTTP_RS_ADR_0039}（ADR-0039 判据3 的活哨兵对象）"
        )),
        Some((_, source)) => {
            if !source.contains("pub fn build_client_with_resolver") {
                problems.push(format!(
                    "ADR-0039 判据3 违反: {INFRA_NETWORK_HTTP_RS_ADR_0039} 不再定义 \
                     build_client_with_resolver —— 唯一构造点消失，本闸会在空世界上误绿"
                ));
            }
            if source.contains("pub fn build_client(") {
                problems.push(format!(
                    "ADR-0039 判据3 违反: {INFRA_NETWORK_HTTP_RS_ADR_0039} 重新导出了无 \
                     resolver 的 build_client —— 这正是 card 17 删掉的那条路"
                ));
            }
        }
    }

    problems.extend(byok_constructor_site_problems(
        &transport_resolver_sites,
        files,
        root,
    ));

    for module in LAYER1_RESOLVER_MODULES {
        if !call_sites.contains(module) {
            problems.push(format!(
                "ADR-0039 判据3 违反: {module} 不再调用 build_client_with_resolver —— \
                 Layer 1 的已检查 resolver 装配丢失（missing object，不是「没有违规」）"
            ));
        }
    }

    problems
}

/// 判据5/6/7 for one file (split out of [`checked_resolver_dial_problems`] only to keep that
/// function under clippy's `too_many_lines`; the criteria are documented there).
fn byok_constructor_problems(
    rel: &str,
    source: &str,
    transport_resolver_sites: &mut BTreeSet<String>,
    problems: &mut Vec<String>,
) {
    let hardwired = code_occurrences(source, "EgressHttpTransport::new(");
    if hardwired > 0 {
        problems.push(format!(
            "ADR-0039 判据5 违反: {rel} 调用了 EgressHttpTransport::new(（{hardwired} 处）\
             —— 那个构造硬接 ssrf::SystemDnsResolver，检查用的 resolver 与拨号用的 \
             resolver 会再次分叉（§11.4 DNS rebinding，且在 DNS pin 节点上直接拨不通）"
        ));
    }
    if code_occurrences(source, "EgressHttpTransport::with_resolver(") > 0 {
        transport_resolver_sites.insert(rel.to_owned());
    }
    if rel.starts_with("bins/") && rel.contains("/src/") {
        let hand_paired = code_occurrences(source, "OpenAiCompatibleProvider::new(");
        if hand_paired > 0 {
            problems.push(format!(
                "ADR-0039 判据7 违反: {rel} 调用了 OpenAiCompatibleProvider::new(\
                 （{hand_paired} 处）—— 生产必须走 with_egress_transport（resolver 只传\
                 一次，检查与拨号由同一个值派生）；new( 把两者当成两个独立实参，正是 \
                 card 17 复审在 bins/private-worker 抓到的 P0"
            ));
        }
    }
}

/// 判据6's allowlist comparison and 判据8's living sentinel.
fn byok_constructor_site_problems(
    transport_resolver_sites: &BTreeSet<String>,
    files: &[(PathBuf, String)],
    root: &Path,
) -> Vec<String> {
    let mut problems = Vec::new();
    let allowed_transport_sites: BTreeSet<String> = EGRESS_TRANSPORT_RESOLVER_SITES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    for site in transport_resolver_sites {
        if !allowed_transport_sites.contains(site) {
            problems.push(format!(
                "ADR-0039 判据6 违反: {site} 自己挑了 BYOK transport 的拨号 resolver —— \
                 允许的只有 {EGRESS_TRANSPORT_RESOLVER_SITES:?}（派生构造点 + rebinding 验收）"
            ));
        }
    }

    match files
        .iter()
        .find(|(p, _)| display(root, p) == ADAPTERS_BYOK_RS_ADR_0039)
    {
        None => problems.push(format!(
            "missing object: {ADAPTERS_BYOK_RS_ADR_0039}（ADR-0039 判据8 的活哨兵对象）"
        )),
        Some((_, source)) => {
            if !source.contains("pub fn with_egress_transport") {
                problems.push(format!(
                    "ADR-0039 判据8 违反: {ADAPTERS_BYOK_RS_ADR_0039} 不再定义 \
                     with_egress_transport —— 「resolver 只传一次」的派生构造点消失，\
                     判据5/6/7 会在空世界上误绿"
                ));
            }
            if code_occurrences(source, "EgressHttpTransport::with_resolver(") == 0 {
                problems.push(format!(
                    "ADR-0039 判据8 违反: {ADAPTERS_BYOK_RS_ADR_0039} 的派生构造点不再用 \
                     EgressHttpTransport::with_resolver( 造 transport —— 拨号那条腿的 \
                     resolver 来源已经不是同一个值了"
                ));
            }
        }
    }

    problems
}

/// Real-repository entry point for [`checked_resolver_dial_problems`].
fn checked_resolver_dial_gate(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    if files.is_empty() {
        return Verdict::NotApplicable(
            "missing object: workspace .rs sources (crates/bins/xtask)".to_string(),
        );
    }
    let problems = checked_resolver_dial_problems(&files, root);
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// ADR-0012 §决定1/2 — the RPC transport must stay a Unix domain socket + kernel
// peer-credential identity, never TCP.
// ============================================================================

const RETRIEVAL_WORKER_SRC_DIR: &str = "bins/retrieval-worker/src";
const GATEWAY_RETRIEVAL_CLIENT_FILE: &str = "bins/gateway/src/retrieval_embedding_client.rs";

/// ADR-0012 is binding on the *transport*, not just on which symbols may cross the gateway/
/// worker boundary — swapping `UnixListener`/`UnixStream` for `TcpListener`/`TcpStream` in
/// either the worker's RPC listener or the gateway's dial would silently drop the
/// `peer_cred()`-based identity check (§决定2) that the ADR calls "读 body 之前" enforcement,
/// while every other gate here (which only greps for worker-only *symbols*) would keep saying
/// pass. This gate fails on any literal `TcpListener`/`TcpStream` in the two RPC-specific
/// files, and requires the corresponding Unix type to actually appear — so a same-host TCP
/// swap (or the two files simply losing their transport code entirely) both go red.
fn adr_0012_uds_transport_gate(root: &Path) -> Verdict {
    let worker_dir = root.join(RETRIEVAL_WORKER_SRC_DIR);
    let gateway_file = root.join(GATEWAY_RETRIEVAL_CLIENT_FILE);
    if !worker_dir.is_dir() || !gateway_file.is_file() {
        return Verdict::NotApplicable(format!(
            "missing object: {RETRIEVAL_WORKER_SRC_DIR} or {GATEWAY_RETRIEVAL_CLIENT_FILE}"
        ));
    }
    let mut files = read_files(&walk_files(&worker_dir, &["rs"]));
    let Ok(gateway_source) = std::fs::read_to_string(&gateway_file) else {
        return Verdict::NotApplicable(format!("unreadable: {GATEWAY_RETRIEVAL_CLIENT_FILE}"));
    };
    files.push((gateway_file.clone(), gateway_source));

    const FORBIDDEN: [&str; 2] = ["TcpListener", "TcpStream"];
    let mut problems = Vec::new();
    let mut has_unix_listener = false;
    let mut has_unix_stream = false;
    for (path, source) in &files {
        for needle in FORBIDDEN {
            let mut search_from = 0;
            while let Some(offset) = source[search_from..].find(needle) {
                let idx = search_from + offset;
                if !line_is_comment_at(source, idx) {
                    problems.push(format!(
                        "ADR-0012 决定1/2 违反: {} 使用了 TCP 传输 {needle:?}（必须是 UDS + peer_cred）",
                        display(root, path)
                    ));
                }
                search_from = idx + needle.len();
            }
        }
        if source.contains("UnixListener") {
            has_unix_listener = true;
        }
        if source.contains("UnixStream") {
            has_unix_stream = true;
        }
    }
    if !has_unix_listener {
        problems.push(format!(
            "ADR-0012 决定1 违反: {RETRIEVAL_WORKER_SRC_DIR} 未见 UnixListener — RPC 监听器传输丢失或被替换"
        ));
    }
    if !has_unix_stream {
        problems.push(format!(
            "ADR-0012 决定1 违反: {GATEWAY_RETRIEVAL_CLIENT_FILE} 未见 UnixStream — 网关拨号传输丢失或被替换"
        ));
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// ADR-0012 — gateway↔retrieval-worker query-embedding RPC boundary
// ============================================================================

const GATEWAY_SRC_DIR: &str = "bins/gateway/src";

/// §4.2 / ADR-0012 决定3: `bins/gateway` may authorize
/// [`IntraCellResource::RETRIEVAL_EMBEDDING_RPC`](crate) via the shared registry/permit gate,
/// but the DashScope provider credential, `role_retrieval_worker` pool, and the platform
/// retrieval credential env var stay `humaux-retrieval-worker`-only (ADR-0012's own
/// consequence: "gateway 与 retrieval-worker 以不同 OS 用户运行" presumes gateway never even
/// links the code that would need that credential). A literal hit for any of the three needles
/// outside a comment line is a regression of that boundary, not a style nit.
fn adr_0012_gateway_boundary_gate(root: &Path) -> Verdict {
    let dir = root.join(GATEWAY_SRC_DIR);
    if !dir.is_dir() {
        return Verdict::NotApplicable(format!("missing object: {GATEWAY_SRC_DIR}"));
    }
    let files = read_files(&walk_files(&dir, &["rs"]));
    if files.is_empty() {
        return Verdict::NotApplicable(format!("missing object: {GATEWAY_SRC_DIR}/*.rs"));
    }
    const FORBIDDEN: [&str; 3] = [
        "DashscopeEmbeddingProvider",
        "RetrievalWorkerDbPool",
        "DASHSCOPE_API_KEY",
    ];
    let mut problems = Vec::new();
    for (path, source) in &files {
        for needle in FORBIDDEN {
            let mut search_from = 0;
            while let Some(offset) = source[search_from..].find(needle) {
                let idx = search_from + offset;
                if !line_is_comment_at(source, idx) {
                    problems.push(format!(
                        "ADR-0012 决定3 违反: {} 引用了 worker-only 符号 {needle:?}",
                        display(root, path)
                    ));
                }
                search_from = idx + needle.len();
            }
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// ADR-0014: gateway's own `IntraCellResource::QDRANT_REST` registry entry must always carry
/// `CellAccessMode::QdrantReadOnly` — a static source-scan companion to
/// `crates/infra-cell`'s runtime enforcement (`HttpIntraCellTransport::execute`'s method/path
/// allowlist), catching a `bootstrap.rs` regression that drops
/// `.with_access_mode(CellAccessMode::QdrantReadOnly)` or explicitly reaches for
/// `CellAccessMode::ReadWrite` before it ever reaches a running process.
fn adr_0014_gateway_qdrant_read_only_gate(root: &Path) -> Verdict {
    let dir = root.join(GATEWAY_SRC_DIR);
    if !dir.is_dir() {
        return Verdict::NotApplicable(format!("missing object: {GATEWAY_SRC_DIR}"));
    }
    let files = read_files(&walk_files(&dir, &["rs"]));
    if files.is_empty() {
        return Verdict::NotApplicable(format!("missing object: {GATEWAY_SRC_DIR}/*.rs"));
    }
    let mut found_qdrant_entry = false;
    let mut problems = Vec::new();
    for (path, source) in &files {
        let needle = "IntraCellResource::QDRANT_REST";
        let mut search_from = 0;
        while let Some(offset) = source[search_from..].find(needle) {
            let idx = search_from + offset;
            if !line_is_comment_at(source, idx) {
                // Only a registry-entry *construction* site is in scope — e.g.
                // `entries.insert(IntraCellResource::QDRANT_REST, ResourceEntry::new(...)
                // .with_access_mode(...))`. A plain reference to the variant (minting a permit,
                // `authorize_cell_access(&registry, IntraCellResource::QDRANT_REST, ttl)`,
                // rustdoc prose) is not — this scan would otherwise demand
                // `CellAccessMode::QdrantReadOnly` appear near every read-only permit request
                // too, which has nothing to configure.
                let window_end = (idx + 800).min(source.len());
                let window = &source[idx..window_end];
                if window.contains("ResourceEntry::new(") {
                    found_qdrant_entry = true;
                    if !window.contains("CellAccessMode::QdrantReadOnly") {
                        problems.push(format!(
                            "ADR-0014 违反: {} 注册 QDRANT_REST 时未见 CellAccessMode::QdrantReadOnly（附近 800 字符窗口内）",
                            display(root, path)
                        ));
                    }
                }
            }
            search_from = idx + needle.len();
        }
        let mut search_from = 0;
        while let Some(offset) = source[search_from..].find("CellAccessMode::ReadWrite") {
            let idx = search_from + offset;
            if !line_is_comment_at(source, idx) {
                problems.push(format!(
                    "ADR-0014 违反: {} 显式构造了 CellAccessMode::ReadWrite（gateway 的 Qdrant 访问必须只读）",
                    display(root, path)
                ));
            }
            search_from = idx + "CellAccessMode::ReadWrite".len();
        }
    }
    if !found_qdrant_entry {
        return Verdict::NotApplicable(
            "gateway 尚未注册 IntraCellResource::QDRANT_REST resource entry".to_owned(),
        );
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// entry point
// ============================================================================

fn report(name: &str, verdict: &Verdict) -> bool {
    match verdict {
        Verdict::Pass => {
            println!("architecture-check: pass — {name}");
            false
        }
        Verdict::Fail(details) => {
            eprintln!("architecture-check: fail — {name}");
            for d in details {
                eprintln!("  {d}");
            }
            true
        }
        Verdict::NotApplicable(missing) => {
            println!("architecture-check: not_applicable — {name} (missing object: {missing})");
            false
        }
    }
}

// ============================================================================
// §6.2.3 G80-40 static side — typed DB pool topology
// ============================================================================

/// Counts non-comment occurrences of the `PgPool` *type* in `src`: matches the word
/// `PgPool` whether written bare (after `use sqlx::PgPool`) or qualified (`sqlx::PgPool`),
/// but not `PgPoolOptions` (the builder is not the pool handle) and not comment mentions.
/// This is the raw-pool-naming signal for G80-40 — the encapsulation check counts it in
/// `postgres.rs` (must be >0, live sentinel) and everywhere else (must be 0).
fn count_pgpool_type(src: &str) -> usize {
    let mut n = 0usize;
    for line in src.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = line[from..].find("PgPool") {
            let at = from + rel;
            let after = at + "PgPool".len();
            // exclude PgPoolOptions and any PgPool<ident> continuation
            let next_is_ident = bytes
                .get(after)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
            if !next_is_ident {
                n += 1;
            }
            from = after;
        }
    }
    n
}

/// G80-40 static side (§6.2.3): raw `sqlx::PgPool` may be *named* only inside the single
/// encapsulation point `crates/adapters/src/postgres.rs`; the seven wrapper types must each
/// be declared exactly once there. The deliberate compile-fail fixtures under
/// `crates/adapters/tests/ui/` are this scan's positive sentinel — they contain the raw
/// type on purpose, so zero hits there means the scanner went blind (§53.3 规则3 同款).
/// The runtime half of G80-40 (SELECT current_user + SQL 双向夹具) lives in
/// `crates/adapters/tests/` and is judged by `cargo test`, not here.
pub fn g6_db_pool_topology(root: &Path) -> Verdict {
    let postgres_rs = root.join("crates/adapters/src/postgres.rs");
    let Ok(pool_src) = fs::read_to_string(&postgres_rs) else {
        return Verdict::NotApplicable(
            "crates/adapters/src/postgres.rs (§6.2.3 唯一封装点尚未交付)".to_string(),
        );
    };

    let mut problems = Vec::new();

    // Nine wrappers (eight role pools + ADR-0059 D-E MigratorDbPool), each declared exactly once,
    // all in the encapsulation point.
    for wrapper in [
        "RuntimeDbPool",
        "BatchIssuerDbPool",
        "ConsolidationDbPool",
        "PrivateWorkerDbPool",
        "RetrievalWorkerDbPool",
        "MaintenanceDbPool",
        "PublicWorkerDbPool",
        "AdminDbPool",
        "MigratorDbPool",
    ] {
        let decl = format!("pub struct {wrapper}");
        let n = pool_src.matches(&decl).count();
        if n != 1 {
            problems.push(format!(
                "§6.2.3 wrapper `{wrapper}` 声明数 {n} != 1（唯一封装点 postgres.rs）"
            ));
        }
    }

    // Positive control (scanner-is-alive): the encapsulation point itself must name the
    // raw type at least once — the seven wrappers each hold a `sqlx::PgPool` inner field.
    // If this drops to 0 the scanner (or postgres.rs) is broken; a dead scanner would
    // otherwise report "no violations" forever. (The ui/ compile-fail fixtures test field
    // *privacy* via `.0`, not raw-type naming, so they are not a naming sentinel.)
    let home_hits = count_pgpool_type(&pool_src);
    if home_hits == 0 {
        problems.push(
            "positive sentinel dead: postgres.rs names sqlx::PgPool 0 times (§53.3 规则3 \
             同款——扫描器失明或封装点被掏空)"
                .to_string(),
        );
    }

    // Raw `sqlx::PgPool` naming outside the encapsulation point.
    for file in walk_files(&root.join("crates"), &["rs"]) {
        let disp = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(src) = fs::read_to_string(&file) else {
            continue;
        };
        let hits = count_pgpool_type(&src);
        if hits == 0 {
            continue;
        }
        if disp.ends_with("crates/adapters/src/postgres.rs") {
            continue; // the one legal home
        }
        problems.push(format!(
            "raw PgPool type named outside encapsulation point: {disp} ({hits} hit(s))"
        ));
    }

    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

// ============================================================================
// §20#G20-2 / G80-39 — online recall/context/continuity: zero static dependency on any
// reasoning provider (T6.2, §20.0)
// ============================================================================

/// The online-lane file set §20.0 names: `application::retrieve` (T6.2's own orchestration
/// entry point), its sibling online lanes `application::continuity` and `domain::context`
/// (§25.4 Mandatory Context Lane), `adapters::retrieve` — the one DB-backed online recall
/// path already shipped (T3.8's `recall_with_overlay`; see that module's own doc comment for
/// why real I/O lives there and not in `application::retrieve`) — plus the §20 Planner
/// (`crates/retrieval/src/*.rs`) and its process entry point (`bins/retrieval-worker/src/
/// main.rs`): a generative query rewrite inserted in the Planner is exactly as much a §20.0
/// violation as one inserted in `application::retrieve`, and prior to this fix the Planner
/// wasn't scanned at all. A listed file that does not exist yet contributes 0 hits, not a
/// violation — §20.0's rule is "MUST NOT call", and an absent file trivially satisfies that;
/// see [`g20_2_no_hidden_generative_recall`] for how a *placeholder* file (present but
/// content-free) is treated instead of silently counting toward a green Pass.
const ONLINE_LANE_FILES: &[&str] = &[
    "crates/application/src/retrieve.rs",
    "crates/application/src/continuity.rs",
    "crates/domain/src/context.rs",
    "crates/adapters/src/retrieve.rs",
    "crates/retrieval/src/lib.rs",
    "crates/retrieval/src/planner.rs",
    "crates/retrieval/src/candidate.rs",
    "crates/retrieval/src/fusion.rs",
    "crates/retrieval/src/rerank.rs",
    "crates/retrieval/src/compiler.rs",
    "crates/retrieval/src/completeness.rs",
    "crates/retrieval/src/envelope.rs",
    "crates/retrieval/src/predicate_eval.rs",
    "crates/retrieval/src/predicate_registry.rs",
    "crates/retrieval/src/signals.rs",
    "bins/retrieval-worker/src/main.rs",
];

/// The needles §20.0/G20-2 forbids anywhere in the online call graph, each paired with
/// whether a hit additionally requires a non-identifier byte on the *right* (see
/// [`count_identifier_hits`]):
///
/// - the two provider *type* names (naming either — bare, `dyn`-bound, or as a generic
///   bound — is how Rust code reaches either provider's methods at all) — `true`: a full
///   identifier match, so `UserReasoningProviderFactory` (a different type) does not count;
/// - the literal method name from the spec's own 注错 text ("在 recall 前插一个
///   complete_structured() query rewrite") — `false`, a left-bounded *prefix* match: the
///   workspace's one real generative call site is
///   `complete_structured_with_bounded_repair` (`crates/adapters/src/byok.rs`), whose name
///   starts with `complete_structured` but continues with an identifier byte (`_`) — a
///   right-boundary requirement here silently exempted the exact call the rule exists to
///   catch (confirmed by injecting a caller of it into `application::retrieve` under the old
///   matcher: the check stayed green);
/// - `byok`, the adapter module that owns both provider traits and every generative call
///   into them — belt-and-suspenders against a call site that reaches a provider through a
///   local re-export/alias and so names neither the trait nor `complete_structured*`
///   directly (e.g. `use humaux_adapters::byok::complete_structured_with_bounded_repair as
///   rewrite;`). Confirmed zero false positives against the current online lane: the only
///   pre-existing occurrence of the substring `byok` in the scan domain is this file's own
///   `//!` doc line naming it in prose, which the comment-skip rule already excludes.
const FORBIDDEN_GENERATIVE_NEEDLES: &[(&str, bool)] = &[
    ("UserReasoningProvider", true),
    ("PublicReasoningProvider", true),
    ("complete_structured", false),
    ("byok", true),
];

/// `application::retrieve`'s own placeholder convention (T0.x scaffold modules across this
/// workspace share the exact `占位模块` marker in their sole doc comment, e.g.
/// `crates/application/src/continuity.rs`) — a file matching this is present but carries no
/// real call graph, so it must not count as scanned coverage the way a real online-lane file
/// does (see [`g20_2_no_hidden_generative_recall`]).
fn is_online_lane_placeholder(src: &str) -> bool {
    src.contains("占位模块")
}

/// Word-boundary, comment-aware occurrence count of `needle` in `src` — same matching
/// discipline as [`count_pgpool_type`] (prev byte not an identifier byte, `//`-comment lines
/// excluded), generalized to an arbitrary needle instead of one hardcoded type name.
/// `require_right_boundary` additionally requires the byte after the match not be an
/// identifier byte either; pass `false` for a needle whose real-world violations extend past
/// the needle itself (see [`FORBIDDEN_GENERATIVE_NEEDLES`]'s doc for why `complete_structured`
/// needs this).
fn count_identifier_hits(src: &str, needle: &str, require_right_boundary: bool) -> usize {
    let mut n = 0usize;
    for line in src.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(needle) {
            let at = from + rel;
            let after = at + needle.len();
            let prev_is_ident = at > 0 && is_ident_byte(bytes[at - 1]);
            let next_is_ident = bytes.get(after).is_some_and(|b| is_ident_byte(*b));
            if !prev_is_ident && (!require_right_boundary || !next_is_ident) {
                n += 1;
            }
            from = after;
        }
    }
    n
}

/// §20#G20-2 / G80-39: `application::retrieve` and its online-lane siblings (now including
/// the §20 Planner, see [`ONLINE_LANE_FILES`]) must have zero static dependency on either
/// reasoning provider — recall/context/continuity MUST NOT implicitly call USER_REASONING or
/// PLATFORM_PUBLIC (§20.0). Pure text scan, same class as [`g6_db_pool_topology`] —
/// deliberately not a `cargo tree`/dependency-graph query: the ban is about the *call graph*
/// (or a re-export of it, hence the `byok` needle) naming either provider at all inside the
/// online lane's own source text, not about a crate-level `Cargo.toml` dependency edge — e.g.
/// `adapters::retrieve` legitimately lives in the same crate as `byok.rs` today, which is
/// fine as long as `adapters/retrieve.rs`'s own source never spells out either provider or
/// `byok`/`complete_structured*`.
///
/// There is deliberately no permanent positive-occurrence sentinel *inside* this scan domain
/// (unlike [`g6_db_pool_topology`]'s `home_hits`): the rule here is "must be 0 everywhere in
/// this domain, forever" — a legitimate non-zero home inside the domain would itself be the
/// violation §20.0 forbids, so there is no legal place to put one. Scanner-aliveness is
/// instead proven the way a rule with no legal positive home has to prove it (§53.3 规则3's
/// own reasoning, applied without a permanent fixture): the `g20_2_fault_*` mutation tests
/// below flip a synthetic copy of this same file set from 0 hits to >0 and assert the check
/// goes red, plus a standalone `count_identifier_hits` unit test proves the matcher itself
/// recognizes the needle text independent of any file.
///
/// A `Pass` additionally requires at least one scanned file to carry real content: a file
/// that is either absent or a bare T0.x `占位模块` placeholder (see
/// [`is_online_lane_placeholder`]) is tracked separately and, if *every* listed file is in
/// that state, the check reports `NotApplicable` instead of a vacuous `Pass` — there being no
/// real online call graph yet to have scanned in the first place.
fn g20_2_no_hidden_generative_recall(root: &Path) -> Verdict {
    let mut problems = Vec::new();
    let mut not_yet_real = Vec::new();
    for rel in ONLINE_LANE_FILES {
        let path = root.join(rel);
        let src = match fs::read_to_string(&path) {
            Ok(src) => src,
            Err(_) => {
                not_yet_real.push(format!("{rel} (absent)"));
                continue; // absent file ⇒ 0 hits, not a violation (see ONLINE_LANE_FILES doc)
            }
        };
        if is_online_lane_placeholder(&src) {
            not_yet_real.push(format!("{rel} (T0.x placeholder)"));
        }
        for (needle, require_right_boundary) in FORBIDDEN_GENERATIVE_NEEDLES {
            let hits = count_identifier_hits(&src, needle, *require_right_boundary);
            if hits > 0 {
                problems.push(format!(
                    "{rel}: 静态依赖 {needle} 命中 {hits} 次（§20.0 online recall/context/\
                     continuity 禁止隐式调用生成式 provider）"
                ));
            }
        }
    }
    if !problems.is_empty() {
        return Verdict::Fail(problems);
    }
    if not_yet_real.len() == ONLINE_LANE_FILES.len() {
        return Verdict::NotApplicable(not_yet_real.join(", "));
    }
    Verdict::Pass
}

/// §22.5 / §23.1②: the A1 identity (`done + open_gaps + pending == expected`) must have
/// **exactly one** implementation workspace-wide. §22.5 freezes it verbatim: 「A1 的算式全库
/// 只此一处，不会两边各写一遍再漂移」—— `retrieval::completeness::ledger::close`（三次独立
/// 取数）与 `projection::stream::advance_prefix`（watermark 推进）都必须调用同一个判定，
/// 不得各写一份表达式。
///
/// 扫描的是**算式形态**而不是函数名：一个复制回来的 `done + open_gaps + pending` 即使换了
/// 变量名也会被 `open_gaps + pending` / `pending + open_gaps` 这两个片段抓到。允许出现的地方
/// 只有算式的家（`crates/domain/src/ledger.rs`）与本检查器自己。
pub fn g22_5_a1_sole_implementation(root: &Path) -> Verdict {
    const HOME: &str = "crates/domain/src/ledger.rs";
    // 算式的两种书写顺序；任一出现在 HOME 之外即为第二份实现。
    const ARITHMETIC_SHAPES: [&str; 2] = ["open_gaps + pending", "pending + open_gaps"];

    let mut strays = Vec::new();
    let home_hits = fs::read_to_string(root.join(HOME))
        // 带左括号做词边界：否则 `a1_holds_renamed` 含子串 `a1_holds`，改名不会被抓到
        // （本闸自己第一版就踩了这个，变异测试当场抓出）。
        .map(|s| s.matches("pub fn a1_holds(").count())
        .unwrap_or(0);
    for (path, source) in read_files(&walk_files(root, &["rs"])) {
        let disp = display(root, &path);
        if disp.ends_with(SELF_FILE) {
            continue; // 本文件逐字包含这些片段作为判据
        }
        let hits: usize = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| {
                ARITHMETIC_SHAPES
                    .iter()
                    .map(|shape| l.matches(shape).count())
                    .sum::<usize>()
            })
            .sum();
        if hits == 0 {
            continue;
        }
        if disp.ends_with(HOME) {
            continue; // 家里怎么写算式由它自己决定（当前是 saturating_add，防回绕）
        } else {
            strays.push(format!(
                "{disp}: A1 arithmetic written here ({hits} site(s))"
            ));
        }
    }

    // 活哨兵（§53.3 规则3 同款）：家里必须**恰好**定义一次 `a1_holds`。算式的书写形式由家
    // 自己决定（当前是 `saturating_add`，防回绕成假闭合），所以哨兵钉在定义上而不是字面算式
    // 上——否则家一改写法，整道闸就会静默失明。
    if home_hits != 1 {
        strays.push(format!(
            "positive sentinel: {HOME} defines `pub fn a1_holds` {home_hits} time(s), expected \
             exactly 1 (§53.3 规则3 同款——扫描器失明或算式的家被掏空)"
        ));
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}

// ============================================================================
// §19 "Provider Plane Architecture Gate" — seven CI checks, spec text verbatim (module doc's
// own §80.1.1 registry note): this section carries **no** G80-*/INV-*/D*-style id ("本段无
// G80-*/INV-* 形式编号" — the p7 task digest's own instruction is "勿发明编号"), so each check
// below is named descriptively, the same way [`dependency_rule_check`]/[`env_var_scan`]
// already are for rules with no spec-assigned number.
// ============================================================================

/// DashScope SDK-specific identifier hits in `src`, line by line, skipping `//`-comment lines
/// (same discipline as [`count_identifier_hits`]). Deliberately **not** a bare
/// case-insensitive `"dashscope"` substring match: the bare lowercase word `"dashscope"` is
/// this crate's own `ProviderId`/business-data value (a routing/health/pricing lookup key
/// threaded through `router.rs`/`admission.rs`/`health.rs`/`metrics.rs`/test fixtures
/// entirely legitimately) — matching on it would flag that data, not "importing the SDK".
/// The needles here instead target the SDK-*shape* surface a real DashScope adapter carries
/// and nothing else legitimately would: `Dashscope`-prefixed PascalCase type names
/// (`DashscopeEmbeddingProvider`, `DashscopeEmbeddingRequest`, …), `dashscope_`-embedded
/// snake_case names (`map_dashscope_status`), the literal API host, and a `dashscope::` path
/// segment (`use dashscope::Client;`, `dashscope::embeddings::create(...)`) — the most likely
/// real shape of the violation these gates name ("Domain does not import DashScope SDK"),
/// added after a review found the original three-needle set scored zero hits on exactly that
/// shape. The `::` suffix cannot collide with the bare lowercase `"dashscope"` `ProviderId`
/// business-data string this crate's routing/health/pricing code legitimately carries (no
/// `::` follows a string literal's contents). Confirmed against the real repo
/// (`crates/retrieval-provider/src/adapters.rs` and its own `tests/`) to hit only there — see
/// this function's own unit tests for the positive/negative pair that pins the distinction.
fn provider_plane_dashscope_sdk_hits(src: &str) -> usize {
    const NEEDLES: [&str; 4] = [
        "Dashscope",
        "dashscope_",
        "dashscope.aliyuncs.com",
        "dashscope::",
    ];
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| NEEDLES.iter().map(|n| l.matches(n).count()).sum::<usize>())
        .sum()
}

/// Provider Plane Architecture Gate check 1/7: "Domain does not import DashScope SDK". Scans
/// `crates/domain/src/**/*.rs` only — a real, fully-populated crate (not a T0.x placeholder),
/// so `Pass` on zero hits is a genuine finding, not a vacuous one (contrast
/// [`g20_2_no_hidden_generative_recall`]'s `NotApplicable`-when-all-placeholder branch, which
/// does not apply here because `crates/domain` has never been a placeholder).
fn provider_plane_gate1_domain_no_dashscope_sdk(root: &Path) -> Verdict {
    let mut problems = Vec::new();
    for (path, source) in read_files(&walk_files(&root.join("crates/domain/src"), &["rs"])) {
        let hits = provider_plane_dashscope_sdk_hits(&source);
        if hits > 0 {
            problems.push(format!(
                "{}: DashScope SDK identifier hits {hits} (§19 Provider Plane Architecture \
                 Gate: \"Domain does not import DashScope SDK\")",
                display(root, &path)
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// Provider Plane Architecture Gate check 2/7: "Application does not call DashScope directly".
/// Same shape as check 1/7 against `crates/application/src/**/*.rs`.
fn provider_plane_gate2_application_no_dashscope_direct(root: &Path) -> Verdict {
    let mut problems = Vec::new();
    for (path, source) in read_files(&walk_files(&root.join("crates/application/src"), &["rs"])) {
        let hits = provider_plane_dashscope_sdk_hits(&source);
        if hits > 0 {
            problems.push(format!(
                "{}: DashScope SDK identifier hits {hits} (§19 Provider Plane Architecture \
                 Gate: \"Application does not call DashScope directly\")",
                display(root, &path)
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// Provider Plane Architecture Gate check 3/7 home: the one module/tests pair allowed to name
/// the DashScope SDK surface at all — `retrieval-provider::adapters` itself, plus its own
/// `tests/` (a test file importing the adapter's public types to exercise it is not "a second
/// importer of the provider client", it is the adapter's own test surface — same allowance
/// [`SELF_FILE`] grants this checker over itself).
fn provider_plane_gate3_home(disp: &str) -> bool {
    disp == "crates/retrieval-provider/src/adapters.rs"
        || disp.starts_with("crates/retrieval-provider/tests/")
}

/// Provider Plane Architecture Gate check 3/7: "Only retrieval-provider/adapters may import
/// provider client". Whole-workspace scan ([`walk_workspace_rs`], same domain
/// §20#G20-2/G80-39 uses) — any DashScope SDK identifier hit outside
/// [`provider_plane_gate3_home`] is a second importer.
fn provider_plane_gate3_only_adapters_import_provider_client(root: &Path) -> Verdict {
    let mut problems = Vec::new();
    for (path, source) in walk_workspace_rs(root) {
        let disp = display(root, &path);
        if provider_plane_gate3_home(&disp) {
            continue;
        }
        let hits = provider_plane_dashscope_sdk_hits(&source);
        if hits > 0 {
            problems.push(format!(
                "{disp}: DashScope SDK identifier hits {hits} outside retrieval-provider/\
                 adapters (§19 Provider Plane Architecture Gate: \"Only retrieval-provider/\
                 adapters may import provider client\")"
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// Provider Plane Architecture Gate checks 4-6/7 share one scan domain and one "is this
/// feature even built yet" precondition: every source file in
/// `crates/retrieval-provider/src/`, not just `adapters.rs` alone (§19 review: the original
/// single-file scan meant a second external-call-carrying file — an eventual rerank or
/// custom-endpoint adapter — would go unscanned entirely, so "every external retrieval call"
/// was enforced against one file, not "every"). A directory that is absent, or whose every
/// file is still a bare T0.x `占位模块` placeholder (see [`is_online_lane_placeholder`],
/// reused here), has no real call graph to judge — `NotApplicable`, not a vacuous `Pass`, same
/// precondition split [`g20_2_no_hidden_generative_recall`] applies to its own online-lane
/// file set.
const PROVIDER_PLANE_SRC_DIR: &str = "crates/retrieval-provider/src";

/// External-call-site count for one file: `.call(`/`::call(` occurrences (non-comment lines),
/// counted only in a file that also names the `ExternalCall` trait or its `HttpExternalCall`
/// implementor (both contain the substring `"ExternalCall"`) — scoping the scan to files that
/// actually deal with that trait, rather than the field name (`self.transport`) today's sole
/// adapter happens to use. §19 review: the old needle (`".transport.call("`) failed open on a
/// renamed field or an aliased/`.await`-chained call shape; driving detection off the trait's
/// own method name instead survives both.
fn provider_plane_external_call_sites(source: &str) -> usize {
    if !source.contains("ExternalCall") {
        return 0;
    }
    count_code_line_hits(source, ".call(") + count_code_line_hits(source, "::call(")
}

/// Blanks every `/* ... */` block-comment span in `source` (bytes replaced with spaces,
/// newlines preserved so line numbers are unaffected — same discipline
/// [`strip_cfg_test_module`] uses for its own brace-matched span). Block comments nest, as in Rust, and an
/// unterminated `/*` blanks to the end of the string rather than panicking or looping.
///
/// A `/*` opens a comment only where the lexer would see one: not inside a `//` comment (`/// see migrations/*.sql`),
/// a string literal (`b"/*"`), a raw string or a char literal. A naive `find("/*")` read all of those as comment
/// starts and blanked the code after them, up to the next `*/` or the end of the file (G-M08-2 review W2: 6 adapters
/// and bins files, `bins/maintenance/src/migrate.rs` lost 496 of its 691 lines). Everything outside block comments
/// is copied unchanged, line comments and string contents included: [`code_before_line_comment`] is the line step.
///
/// ponytail: a lexer-lite, not a parser (no macro-body or `#[doc = "..."]` awareness), upgrade to `proc_macro2`
/// tokenizing if a file ever mis-blanks.
// ponytail: C-string literals (`c"..."`, `cr#"..."#`) are not recognised (`cr#"..."#` is read as a plain identifier
// then a plain string, so a `"` inside it ends it early) and `code_before_line_comment` is not escape-aware, upgrade by
// sharing this lexer with that function.
fn strip_block_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let starts_token = |at: usize| at == 0 || !is_ident_byte(bytes[at - 1]);
    let mut out = String::with_capacity(source.len());
    let (mut i, mut copied) = (0usize, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i = source[i..].find('\n').map_or(bytes.len(), |n| i + n);
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                out.push_str(&source[copied..i]);
                let end = block_comment_end(bytes, i);
                out.extend(
                    source[i..end]
                        .chars()
                        .map(|c| if c == '\n' { '\n' } else { ' ' }),
                );
                (i, copied) = (end, end);
            }
            b'"' => i = string_end(bytes, i + 1),
            b'r' if starts_token(i) || (bytes[i - 1] == b'b' && starts_token(i - 1)) => {
                i = raw_string_end(bytes, i).unwrap_or(i + 1);
            }
            b'\'' => i = char_literal_end(source, i),
            _ => i += 1,
        }
    }
    out.push_str(&source[copied..]);
    out
}

/// Exclusive end of the block comment opening at `start` (`bytes[start..]` begins with `/*`); `bytes.len()` when it
/// is never closed. `/*/` does not close itself.
fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let (mut depth, mut i) = (0usize, start);
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1)) {
            (b'/', Some(b'*')) => {
                depth += 1;
                i += 2;
            }
            (b'*', Some(b'/')) => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Index just past the `"` that closes the string whose body starts at `from` (a backslash skips the byte after it);
/// `bytes.len()` when it is never closed.
fn string_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// Index just past the raw string (`r"..."`, `r#"..."#`, also behind a `b`) whose `r` is at `r_at`, or `None` when
/// that `r` is not the start of one (`r#type`, a bare identifier).
fn raw_string_end(bytes: &[u8], r_at: usize) -> Option<usize> {
    let hashes = bytes[r_at + 1..].iter().take_while(|b| **b == b'#').count();
    let body = r_at + 1 + hashes;
    if bytes.get(body) != Some(&b'"') {
        return None;
    }
    let closes = |at: usize| {
        bytes[at + 1..]
            .iter()
            .take(hashes)
            .filter(|b| **b == b'#')
            .count()
            == hashes
    };
    let close = (body + 1..bytes.len()).find(|&at| bytes[at] == b'"' && closes(at));
    Some(close.map_or(bytes.len(), |at| at + 1 + hashes))
}

/// Index just past the char literal (`'x'`, `'\n'`, `'"'`) opening at `at`, or `at + 1` for a lifetime or label.
fn char_literal_end(source: &str, at: usize) -> usize {
    let mut chars = source[at + 1..].chars();
    match (chars.next(), chars.next()) {
        (Some('\\'), escaped) => {
            let after = at + 2 + escaped.map_or(0, char::len_utf8);
            source[after..].find('\'').map_or(at + 1, |n| after + n + 1)
        }
        (Some(c), Some('\'')) => at + 1 + c.len_utf8() + 1,
        _ => at + 1,
    }
}

/// The prefix of `line` up to (excluding) its first `//` that is not inside a `"..."` string
/// literal — a trailing comment (`let n = 1; // needle`) must not count as real code (§19
/// review: `count_code_line_hits` previously only skipped a line whose *leading* trimmed text
/// was `//`, so a trailing comment on an otherwise-real code line still counted). No escape
/// handling — this codebase's own needle strings never place an escaped `"` before a same-line
/// `//` (see this function's own tests for the shapes it does handle). A leading full-line
/// comment reduces to `""` here too, so this alone replaces the old leading-only filter.
fn code_before_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// Non-comment-line occurrence count of `needle` in `src` (plain substring, no identifier
/// boundary — the companion needles this feeds are multi-word/qualified paths like
/// `"admission::decide("`, not bare identifiers [`count_identifier_hits`] is built for).
/// Strips `/* */` block comments over the whole source first, then a trailing `//` comment (if
/// any, outside a string literal) from each remaining line before matching.
fn count_code_line_hits(src: &str, needle: &str) -> usize {
    strip_block_comments(src)
        .lines()
        .map(|l| code_before_line_comment(l).matches(needle).count())
        .sum()
}

/// Shared body for Architecture Gate checks 4-6/7: `companion_needles` is the evidence a real
/// external-call site must also carry (egress permit minting / ModelCallLedger write /
/// admission participation); `rule_name` and `not_yet_wired_note` are this check's own §19
/// quote and the missing-object explanation for the "call site exists, companion integration
/// does not yet" state.
///
/// Three-way split on the companion evidence, not two: real code-line hits ⇒ `Pass`; **zero**
/// code-line hits but the companion is named somewhere in a `//`-comment ⇒ `Fail` — a doc
/// comment claiming the integration exists without a line of code that does it is exactly the
/// 伪修复 shape repo CLAUDE.md's 交付准则 names ("拒绝伪修复：改表层没动根因"); zero hits
/// anywhere at all ⇒ `NotApplicable`, the honest "not yet wired, a separate task's
/// deliverable" state — not a silent `Pass`.
fn provider_plane_call_site_companion_check(
    root: &Path,
    companion_needles: &[&str],
    rule_name: &str,
    not_yet_wired_note: &str,
) -> Verdict {
    let files = read_files(&walk_files(&root.join(PROVIDER_PLANE_SRC_DIR), &["rs"]));
    if files.is_empty() {
        return Verdict::NotApplicable(format!(
            "{PROVIDER_PLANE_SRC_DIR}/ (absent) — §19 Provider Plane Architecture Gate: \
             \"{rule_name}\""
        ));
    }
    if files.iter().all(|(_, s)| is_online_lane_placeholder(s)) {
        return Verdict::NotApplicable(format!(
            "{PROVIDER_PLANE_SRC_DIR}/ (T0.x placeholder) — §19 Provider Plane Architecture \
             Gate: \"{rule_name}\""
        ));
    }

    let mut call_sites = 0usize;
    let mut real_hits = 0usize;
    let mut comment_only_files: Vec<String> = Vec::new();
    for (path, source) in &files {
        let sites = provider_plane_external_call_sites(source);
        if sites == 0 {
            continue;
        }
        call_sites += sites;
        let file_real: usize = companion_needles
            .iter()
            .map(|n| count_code_line_hits(source, n))
            .sum();
        if file_real > 0 {
            real_hits += file_real;
            continue;
        }
        let file_comment: usize = companion_needles
            .iter()
            .map(|n| source.matches(n).count()) // includes comment lines, unlike count_code_line_hits
            .sum();
        if file_comment > 0 {
            comment_only_files.push(display(root, path));
        }
    }

    if call_sites == 0 {
        // §19 review: this used to be a vacuous `Pass` ("no call site found, no violation
        // possible") — indistinguishable from the needle simply missing a real call site (a
        // renamed field, an aliased call). `NotApplicable` names the gap instead of silently
        // going green either way when needle drift, not a genuinely-empty call graph, is the
        // cause.
        return Verdict::NotApplicable(format!(
            "{PROVIDER_PLANE_SRC_DIR}/*.rs: no external call site matched (`.call(`/`::call(` \
             in a file naming `ExternalCall`) — §19 Provider Plane Architecture Gate: \
             \"{rule_name}\""
        ));
    }
    if real_hits > 0 {
        return Verdict::Pass;
    }
    if !comment_only_files.is_empty() {
        return Verdict::Fail(vec![format!(
            "{call_sites} external call site(s) across {PROVIDER_PLANE_SRC_DIR}/ \
             ({comment_only_files:?}), and {not_yet_wired_note} appears only in a comment, \
             never in real code — §19 Provider Plane Architecture Gate: \"{rule_name}\""
        )]);
    }
    Verdict::NotApplicable(format!(
        "{PROVIDER_PLANE_SRC_DIR}/*.rs: {call_sites} external call site(s) found, but no \
         {not_yet_wired_note} — §19 Provider Plane Architecture Gate: \"{rule_name}\" (a \
         separate task's deliverable not yet wired into the real call path)"
    ))
}

/// Provider Plane Architecture Gate check 4/7: "Every external retrieval call passes
/// EgressPolicy". Real positive finding today: `DashscopeEmbeddingProvider::embed` mints an
/// `EgressPermit` via `egress::authorize(...)` before its one `.transport.call(` — this is the
/// one of the seven checks whose real target already exists end to end (T4.1's `EgressPermit`
/// topology + T7.1's adapter wiring), so this check is a real `Pass`, not `NotApplicable`.
fn provider_plane_gate4_egress_policy_before_external_call(root: &Path) -> Verdict {
    provider_plane_call_site_companion_check(
        root,
        &["authorize("],
        "Every external retrieval call passes EgressPolicy",
        "EgressPermit-minting `authorize(` call",
    )
}

/// Provider Plane Architecture Gate check 5/7: "Every external retrieval call creates
/// ModelCallLedger entry". `adapters::model_call_ledger::reserve_call`/`finalize` (§19.1) are
/// real (T7.4) but not yet called from `DashscopeEmbeddingProvider::embed` — the digest's own
/// task 4 ("ModelCallLedger + Pricing Registry") wires the *table*; wiring it into *this* call
/// site is out of this task's file ownership (`adapters.rs` belongs to T7.1). `NotApplicable`
/// is the honest state, not a silently-passing `Pass`.
fn provider_plane_gate5_ledger_entry_per_external_call(root: &Path) -> Verdict {
    provider_plane_call_site_companion_check(
        root,
        &["model_call_ledger", "ModelCallLedger"],
        "Every external retrieval call creates ModelCallLedger entry",
        "ModelCallLedger reserve/finalize reference",
    )
}

/// Provider Plane Architecture Gate check 6/7: "Every call participates in provider admission
/// control". `admission::decide`/`AdmissionRequest` (§19 Admission Controller) are real (T7.3)
/// but not yet called from `DashscopeEmbeddingProvider::embed` — same "table built, call site
/// not yet wired to it, out of this task's file ownership" state as check 5/7.
fn provider_plane_gate6_admission_participation(root: &Path) -> Verdict {
    provider_plane_call_site_companion_check(
        root,
        &["admission::decide(", "AdmissionRequest"],
        "Every call participates in provider admission control",
        "admission::decide/AdmissionRequest reference",
    )
}

/// The tail of `source` starting at `insert_idx` (the byte offset of an `INSERT INTO
/// private.processing_runs` match), up to the closing `"` of the enclosing Rust string literal
/// — i.e. the SQL statement text itself, not the whole file. No escape handling: this
/// codebase's own INSERT-statement string literals never place an escaped `"` inside the SQL
/// text (see this function's own tests). Falls back to the rest of `source` if no closing
/// quote is found (malformed/truncated fixture — better to over-scan than panic).
fn insert_statement_text(source: &str, insert_idx: usize) -> &str {
    let bytes = source.as_bytes();
    let mut i = insert_idx;
    while i < bytes.len() {
        if bytes[i] == b'"' && bytes.get(i.wrapping_sub(1)) != Some(&b'\\') {
            return &source[insert_idx..i];
        }
        i += 1;
    }
    &source[insert_idx..]
}

/// Provider Plane Architecture Gate check 7/7: "Embedding projection write contains
/// provider/model/version metadata". `private.processing_runs.model_provider`/`model_id`/
/// `model_revision` are already `NOT NULL` at the DB layer (`migrations/0064_processing_runs_
/// axes_and_retrieval_cards_model_fix.sql`); whole-workspace scan of every `INSERT INTO
/// private.processing_runs` call site.
///
/// `**/tests/**` is excluded from the evidence set (§19 review): a test fixture proves the
/// matcher works, not that a real production write path exists —
/// `crates/adapters/tests/processing_runs_fingerprint_rerun.rs`'s own fixture is the *only*
/// hit in the workspace today, so counting it would green this gate on a test double, exactly
/// the false-assurance shape §57.1's three-state rule exists to prevent. `NotApplicable` until
/// a real (non-`tests/`) call site lands.
///
/// The three metadata-field checks are scoped to the matched INSERT statement's own text
/// ([`insert_statement_text`]), not the whole file — a file whose INSERT omits a column but
/// happens to mention its name elsewhere (a struct field, an unrelated `SELECT`) must not
/// count as carrying it.
fn provider_plane_gate7_projection_write_has_model_metadata(root: &Path) -> Verdict {
    const INSERT_NEEDLE: &str = "INSERT INTO private.processing_runs";
    const METADATA_FIELDS: [&str; 3] = ["model_provider", "model_id", "model_revision"];

    let mut insert_sites: Vec<String> = Vec::new();
    let mut incomplete: Vec<String> = Vec::new();
    for (path, source) in walk_workspace_rs(root) {
        let disp = display(root, &path);
        if disp.contains("/tests/") {
            continue;
        }
        let mut search = 0usize;
        while let Some(rel) = source[search..].find(INSERT_NEEDLE) {
            let idx = search + rel;
            insert_sites.push(disp.clone());
            let stmt = insert_statement_text(&source, idx);
            let missing: Vec<&str> = METADATA_FIELDS
                .iter()
                .copied()
                .filter(|f| !stmt.contains(f))
                .collect();
            if !missing.is_empty() {
                incomplete.push(format!(
                    "{disp}: INSERT INTO private.processing_runs missing {missing:?} (§19 \
                     Provider Plane Architecture Gate: \"Embedding projection write contains \
                     provider/model/version metadata\")"
                ));
            }
            search = idx + INSERT_NEEDLE.len();
        }
    }
    if !incomplete.is_empty() {
        return Verdict::Fail(incomplete);
    }
    if insert_sites.is_empty() {
        return Verdict::NotApplicable(
            "no `INSERT INTO private.processing_runs` call site outside tests/ yet (§19 \
             embedding-projection write path, a later Phase's deliverable — only a test \
             fixture exists today) — §19 Provider Plane Architecture Gate: \"Embedding \
             projection write contains provider/model/version metadata\""
                .to_string(),
        );
    }
    Verdict::Pass
}

// ============================================================================
// §19 Embedding Provider Failover 硬规则 — sole decision point. Added per code review
// (blocker): `failover::decide_embedding_failover`'s own rustdoc claims to be "the only place
// in the workspace that may declare two ProjectionContracts failover-compatible", but
// `router.rs::projection_compatible` independently hand-rolled the identical
// provider_id/model_id/dimension comparison (via its own `ProjectionRef` type) without ever
// calling through it — and, per its own module doc, without `normalization`/`projection_version`
// at all.
//
// Fixed by extracting the actual 5-axis comparison out of `decide_embedding_failover` into
// `failover::projection_contracts_compatible` — a permit-free pure function
// `decide_embedding_failover` itself now calls after its own permit checks. `router.rs` cannot
// call `decide_embedding_failover` directly: that function requires a live `EgressPermit`, and
// `router::resolve` runs *before* a route (and therefore a `ProcessorId` a permit could be
// minted for) has been chosen (`router::projection_compatible`'s own doc). Calling either
// function is still routing through the one real comparison — this gate accepts both, so a
// second *independently hand-rolled* comparison remains exactly as impossible as it was when
// only `decide_embedding_failover` existed.
// ============================================================================

/// Pure comparator: `hits` is every file (outside `failover.rs`) that names the `ProjectionRef`
/// type — router.rs's own embedding-projection-compatibility reference type — without calling
/// through either `failover::decide_embedding_failover` (the permit-gated real egress call
/// site) or `failover::projection_contracts_compatible` (the permit-free pure comparator that
/// function itself delegates to, and the one a pre-permit caller like `router.rs` uses
/// instead — see this section's own module comment). Empty ⇒ the sole decision point holds;
/// any hit ⇒ a second, independently-maintained comparison exists that can silently diverge
/// from the 5-axis rule.
pub fn embedding_failover_sole_decision_point_check(hits: &[String]) -> Verdict {
    if hits.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(
            hits.iter()
                .map(|f| {
                    format!(
                        "{f}: defines/uses `ProjectionRef` without calling \
                         `failover::decide_embedding_failover` or \
                         `failover::projection_contracts_compatible` — §19 Embedding Provider \
                         Failover 硬规则 names those the sole places that may declare two \
                         projection contracts failover-compatible"
                    )
                })
                .collect(),
        )
    }
}

const EMBEDDING_FAILOVER_HOME: &str = "crates/retrieval-provider/src/failover.rs";

fn provider_plane_embedding_failover_sole_decision_point(root: &Path) -> Verdict {
    let hits: Vec<String> = walk_workspace_rs(root)
        .into_iter()
        .filter_map(|(path, source)| {
            let disp = display(root, &path);
            if disp == EMBEDDING_FAILOVER_HOME {
                return None;
            }
            let has_projection_ref = source.contains("ProjectionRef");
            let delegates = source.contains("decide_embedding_failover(")
                || source.contains("projection_contracts_compatible(");
            (has_projection_ref && !delegates).then_some(disp)
        })
        .collect();
    embedding_failover_sole_decision_point_check(&hits)
}

// ============================================================================
// §19 DOD-028 Retrieval Credential Boundary — added per code review (minor): the credential
// boundary this task introduced (`HttpExternalCall::call`'s purpose guard binding the platform
// retrieval credential to `RetrievalEmbedding`/`RetrievalRerank`, and `EgressSecret::expose`'s
// own doc claim of "exactly one hit per call site") shipped with no CI gate asserting either
// stayed true. Two checks, same `== 1`/set-equality shape the file's other sole-construction-
// point checks (`payload_sha256`, `Authority::new`) already use.
// ============================================================================

const EGRESS_SECRET_HOME: &str = "crates/infra-egress/src/http.rs";

/// (a) `EgressSecret::expose` call-site set == `{crates/infra-egress/src/http.rs}`. A file
/// counts as a call site only if it also names `EgressSecret` itself — a bare `.expose(` text
/// match alone would also hit `crates/adapters/src/byok.rs`'s unrelated
/// `PlaintextApiKey::expose`, a different credential type for a different trust domain
/// (USER_REASONING BYOK, not the platform retrieval credential this check is about).
/// `walk_workspace_rs` already strips `#[cfg(test)]` bodies, so this file's own test-only
/// `secret.expose()` assertion does not count as a second site.
fn g_egress_secret_expose_sole_call_site(root: &Path) -> Verdict {
    let hits: Vec<String> = walk_workspace_rs(root)
        .into_iter()
        .map(|(p, s)| (display(root, &p), s))
        .filter(|(disp, s)| {
            disp != EGRESS_SECRET_HOME && s.contains("EgressSecret") && s.contains(".expose(")
        })
        .map(|(disp, _)| {
            format!(
                "{disp}: reads an `EgressSecret` via `.expose()` outside the one sanctioned \
                 call site {EGRESS_SECRET_HOME} (that module's own doc, \"Credential \
                 injection\": \"a grep for who reads a raw egress credential has exactly one \
                 hit per call site\")"
            )
        })
        .collect();
    if hits.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(hits)
    }
}

/// (b) the §19 DOD-028 purpose guard from the blocker/major review finding actually exists:
/// `HttpExternalCall::call` must bind the platform retrieval credential to
/// `RetrievalEmbedding`/`RetrievalRerank` before it ever resolves that credential — "任何 User
/// BYOK MUST NOT 被 Retrieval Provider Plane 自动借用". Textual, like this file's other checks:
/// looks for the exact guard shape rather than parsing control flow, so a rewrite that keeps
/// the same restriction under different wording would need this needle updated too — same
/// trade-off every other check in this file already accepts.
fn g_retrieval_credential_purpose_guard_exists(root: &Path) -> Verdict {
    let files = walk_workspace_rs(root);
    let Some((_, source)) = files
        .iter()
        .find(|(p, _)| display(root, p) == EGRESS_SECRET_HOME)
    else {
        return Verdict::NotApplicable(format!("{EGRESS_SECRET_HOME} not found"));
    };
    let has_guard = source
        .contains("PrivateDataPurpose::RetrievalEmbedding | PrivateDataPurpose::RetrievalRerank");
    if has_guard {
        Verdict::Pass
    } else {
        Verdict::Fail(vec![format!(
            "{EGRESS_SECRET_HOME}: `HttpExternalCall::call` has no guard binding the platform \
             retrieval credential to RetrievalEmbedding/RetrievalRerank permits — §19 DOD-028"
        )])
    }
}

/// The seven §19 Provider Plane Architecture Gate checks, factored out of [`run`] so that
/// function stays under clippy's `too_many_lines` threshold — same reason this file already
/// splits other check families into their own functions.
fn provider_plane_architecture_gate_checks(root: &Path) -> Vec<(&'static str, Verdict)> {
    vec![
        (
            "§19 Provider Plane Architecture Gate 1/7 (Domain does not import DashScope SDK)",
            provider_plane_gate1_domain_no_dashscope_sdk(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 2/7 (Application does not call DashScope \
             directly)",
            provider_plane_gate2_application_no_dashscope_direct(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 3/7 (Only retrieval-provider/adapters may \
             import provider client)",
            provider_plane_gate3_only_adapters_import_provider_client(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 4/7 (Every external retrieval call passes \
             EgressPolicy)",
            provider_plane_gate4_egress_policy_before_external_call(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 5/7 (Every external retrieval call creates \
             ModelCallLedger entry)",
            provider_plane_gate5_ledger_entry_per_external_call(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 6/7 (Every call participates in provider \
             admission control)",
            provider_plane_gate6_admission_participation(root),
        ),
        (
            "§19 Embedding Provider Failover 硬规则 (decide_embedding_failover / \
             projection_contracts_compatible sole decision point)",
            provider_plane_embedding_failover_sole_decision_point(root),
        ),
        (
            "§19 Provider Plane Architecture Gate 7/7 (Embedding projection write contains \
             provider/model/version metadata)",
            provider_plane_gate7_projection_write_has_model_metadata(root),
        ),
        (
            "§19 DOD-028 (a) EgressSecret::expose sole call site",
            g_egress_secret_expose_sole_call_site(root),
        ),
        (
            "§19 DOD-028 (b) retrieval credential purpose guard exists",
            g_retrieval_credential_purpose_guard_exists(root),
        ),
        (
            "§11.10#G11-2 / G80-43 (Grounding validity / recheck debt)",
            g80_43_grounding_validity(root),
        ),
        (
            "§25.4 A1 (Candidate 唯一构造点)",
            g25_4_candidate_sole_construction_point(root),
        ),
        (
            "§25.4 A2 (context_bindings 唯一写入点)",
            g25_4_binding_insert_sole_site(root),
        ),
        (
            "§25.4 A3 (authorize_mandatory/pinned 唯一调用点)",
            g25_4_authorize_sole_caller(root),
        ),
        (
            "§25.4 A3b (task_binding_grants 唯一写入点 / 任务授权唯一铸造点)",
            g25_4_task_grant_sole_site(root),
        ),
    ]
}

/// 统计 `needle` 在**非注释行**上的出现次数，跳过本文件自身（它逐字包含这些片段作为判据）。
/// 返回 `(总数, 逐文件明细)`。
fn count_outside_allowed(root: &Path, needle: &str, allowed: &[&str]) -> (usize, Vec<String>) {
    let mut total = 0usize;
    let mut sites = Vec::new();
    for (path, source) in read_files(&walk_files(root, &["rs"])) {
        let disp = display(root, &path);
        // 精确路径排除，**不按子串**：子串匹配会连带排除任何路径含该片段的文件
        // （`candidate_helpers.rs` 之类），真违规藏进去就永远数不到（ADR-0006 决定 2）。
        if disp.ends_with(SELF_FILE) || allowed.iter().any(|a| disp.ends_with(a)) {
            continue;
        }
        // `crates/<pkg>/tests/*.rs` 是 cargo 的集成测试目录——**按路径结构判定**
        // （第三段恰好是 `tests`），不是 `contains("/tests/")` 那种子串匹配：
        // 结构判定不会把一个碰巧叫 tests 的业务目录也放行。夹具造候选/写 binding 不是
        // 本闸要抓的违规，生产代码那么做才是。
        let segments: Vec<&str> = disp.split('/').collect();
        if segments.first() == Some(&"crates") && segments.get(2) == Some(&"tests") {
            continue;
        }
        // 同理剥掉 `src/*.rs` 尾部的 `#[cfg(test)] mod` 区。
        // ponytail: 沿用 `env_var_scan` 的同一前缀启发式（第一个 `#[cfg(test)] mod` 之后全免），
        // 天花板一致——生产代码若排在 cfg(test) 之后会被误免；真需要时一起换成 span 解析。
        let source = match cfg_test_mod_offset(&source) {
            Some(off) => &source[..off],
            None => source.as_str(),
        };
        let n = source
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("///")
            })
            .map(|l| l.matches(needle).count())
            .sum::<usize>();
        if n > 0 {
            sites.push(format!("{disp}: {n}"));
            total += n;
        }
    }
    (total, sites)
}

/// §25.4 A1：`Candidate` 只能在它自己的模块里造。
///
/// 机制①（Mandatory 不可被 rerank 淘汰）的一条腿。`Candidate` 的字段已经是私有的，
/// 所以「手搓一个字面量」由编译器挡住；本闸挡的是**另一种失效**：有人把字段改回 `pub`，
/// 或在别处加一个 `Candidate::new(...)` 把 Mandatory 行包装成普通候选送进排序。
/// 前者编译器不会说话，后者编译得过——两种都只有静态扫描看得见。
fn g25_4_candidate_sole_construction_point(root: &Path) -> Verdict {
    const HOME: [&str; 1] = ["crates/retrieval/src/candidate.rs"];

    let files = read_files(&walk_files(root, &["rs"]));
    // 三态：被测对象是 `Candidate` 这个类型本身。
    if !files
        .iter()
        .any(|(_, s)| s.contains("pub struct Candidate {"))
    {
        return Verdict::NotApplicable(
            "missing object: §24 `pub struct Candidate` 尚未交付".to_string(),
        );
    }

    let mut strays = Vec::new();

    // ① 别处不得调用构造函数。
    let (calls, call_sites) = count_outside_allowed(root, "Candidate::new(", &HOME);
    if calls > 0 {
        strays.push(format!(
            "§24 `Candidate::new(` 只允许出现在 {}，实得 {calls} 处: {call_sites:?}",
            HOME[0]
        ));
    }

    // ② 字段必须仍是私有的。字段改回 `pub` 时编译器一声不吭，而「手搓一个
    //    `Candidate { fusion_score: 0.0, .. }` 把 Mandatory 伪装成普通候选」就又成立了
    //    ——这正是本闸存在的原因（实测过：收口前全仓字段全 pub）。
    if let Some((_, home)) = files
        .iter()
        .find(|(p, _)| display(root, p).ends_with(HOME[0]))
    {
        for field in [
            "pub id: String",
            "pub facet: Facet",
            "pub fusion_score: f32",
            "pub estimated_rerank_tokens: u32",
        ] {
            if home.contains(field) {
                strays.push(format!(
                    "{}: `Candidate` 的字段 `{field}` 又变回 pub —— 字段公开之后\
                     「Mandatory 不可被淘汰」只能是纪律，不再是拓扑",
                    HOME[0]
                ));
            }
        }
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}

/// §25.4 A2：`private.context_bindings` 的写入点唯一。
///
/// 绕过 `domain::context` 的三个 `authorize_*` 直接写 binding，就是 §25.4 那条攻击路径
/// （把低 origin 内容永久钉进每次 Context）的落地形态。
fn g25_4_binding_insert_sole_site(root: &Path) -> Verdict {
    const INSERT_HOME: [&str; 1] = ["crates/adapters/src/context_repo.rs"];
    const GRANT_HOME: [&str; 1] = ["crates/domain/src/context.rs"];

    let files = read_files(&walk_files(root, &["rs"]));
    if !files
        .iter()
        .any(|(_, s)| s.contains("INSERT INTO private.context_bindings"))
    {
        return Verdict::NotApplicable(
            "missing object: §25.4 `INSERT INTO private.context_bindings` 写入路径尚未交付"
                .to_string(),
        );
    }

    let mut strays = Vec::new();
    let (inserts, sites) =
        count_outside_allowed(root, "INSERT INTO private.context_bindings", &INSERT_HOME);
    if inserts > 0 {
        strays.push(format!(
            "§25.4 binding 写入点只允许在 {}，实得 {inserts} 处: {sites:?}",
            INSERT_HOME[0]
        ));
    }
    // `BindingGrant` 的字面量同理：它是写入口唯一接受的类型，能在别处造出来就等于
    // 绕过了三个 authorize_*。
    let (grants, gsites) = count_outside_allowed(root, "BindingGrant {", &GRANT_HOME);
    if grants > 0 {
        strays.push(format!(
            "§25.4 `BindingGrant {{` 字面量只允许在 {}，实得 {grants} 处: {gsites:?}",
            GRANT_HOME[0]
        ));
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}

/// §25.4 A3：`authorize_mandatory` / `authorize_pinned` 的调用点收敛，连同 ADR-0019 D-A 的
/// actor 铸造点 `ConfirmedUserActor::from_consumed_confirmation`——它是 pub fn，可见性挡不住
/// consolidation / retention / private-worker 代码调它，这条 needle 才是把「只在 consume 之后
/// 铸造」钉死的东西。
///
/// **零调用点在这条闸里是合法的 Pass，与 G80-4 相反**——两者的规则方向不同：
/// G80-4 说的是「检索侧**必须**经过 serving_version」，零调用点就是违规本身；
/// 本闸说的是「**只有** context_repo 可以调 authorize_*」，零调用点意味着没人违规。
/// 同样是计数，NA/Pass 的语义相反，照着 G80-4 的形状改这里会改错（ADR-0006）。
fn g25_4_authorize_sole_caller(root: &Path) -> Verdict {
    // 定义点 + 允许的调用方 + 测试目录（夹具自己要调它们）。测试目录按**精确路径**列出，
    // 不用 `contains("/tests/")`：那会把任何路径含 tests 的生产文件也放行。
    const ALLOWED: [&str; 4] = [
        "crates/domain/src/context.rs",
        "crates/adapters/src/context_repo.rs",
        "crates/adapters/tests/mandatory_context_lane.rs",
        "crates/domain/tests/context_authorize.rs",
    ];

    let files = read_files(&walk_files(root, &["rs"]));
    if !files
        .iter()
        .any(|(_, s)| s.contains("pub fn authorize_mandatory("))
    {
        return Verdict::NotApplicable(
            "missing object: §25.4 `pub fn authorize_mandatory(` 尚未交付".to_string(),
        );
    }

    let mut strays = Vec::new();
    for needle in [
        "authorize_mandatory(",
        "authorize_pinned(",
        "from_consumed_confirmation(",
    ] {
        let (n, sites) = count_outside_allowed(root, needle, &ALLOWED);
        if n > 0 {
            strays.push(format!(
                "§25.4 `{needle}` 的调用点越界（只允许 {ALLOWED:?}），实得 {n} 处: {sites:?}"
            ));
        }
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}
/// §25.4 A3b（card 22c, ADR-0046）：任务授权的两个唯一点。
///
/// 和 A2/A3 同一形态，钉的是 **I-TASK** 与 **I-NONINHERIT** 在源码层的可执行形态：
///
/// 1. **`private.task_binding_grants` 只有一个写入点**。`INSERT INTO private.task_binding_grants`
///    与 `UPDATE private.task_binding_grants` 这两段 SQL 文本只允许出现在 `context_repo.rs`
///    与迁移里（迁移不是 `.rs`，天然不在扫描范围）。别处多出一处 INSERT，就是多了一条
///    能凭空造出「当前任务批准过」的路径——而那正是整张卡要关掉的东西。
/// 2. **`VerifiedTaskGrant` / `AuthorizedTaskItem` 只有一个铸造点**。两者的字段私有，
///    可见性在同 crate 内挡不住（`domain` 的任何模块都能写字面量），所以「只有
///    `authorize_task_item` 能造」必须由这条 needle 钉住，而不是靠 `_priv: ()` 的善意。
///
/// 零调用点合法（同 A3 的方向）：本闸说的是「**只有**这里可以」，不是「必须有人这么做」。
/// 被测对象未交付时返回 `not_applicable` 并点名（§57.1 第 2 条）。
fn g25_4_task_grant_sole_site(root: &Path) -> Verdict {
    /// 写入点：只有 adapters 的 context_repo（迁移是 .sql，不在 `walk_files(.., &["rs"])` 里）。
    const WRITE_ALLOWED: [&str; 1] = ["crates/adapters/src/context_repo.rs"];
    /// 铸造点：只有 domain 的 context 模块。**adapters 不在名单里**——它拿得到
    /// `authorize_task_item` 的返回值，但造不出返回值本身。
    const MINT_ALLOWED: [&str; 1] = ["crates/domain/src/context.rs"];

    let files = read_files(&walk_files(root, &["rs"]));
    if !files
        .iter()
        .any(|(_, s)| s.contains("pub fn authorize_task_item("))
    {
        return Verdict::NotApplicable(
            "missing object: §25.4 v2 `pub fn authorize_task_item(` 尚未交付".to_string(),
        );
    }

    let mut strays = Vec::new();
    for needle in [
        "INSERT INTO private.task_binding_grants",
        "UPDATE private.task_binding_grants",
    ] {
        let (n, sites) = count_outside_allowed(root, needle, &WRITE_ALLOWED);
        if n > 0 {
            strays.push(format!(
                "§25.4 A3b `{needle}` 的写入点越界（只允许 {WRITE_ALLOWED:?}），实得 {n} 处: {sites:?}"
            ));
        }
    }
    for needle in ["VerifiedTaskGrant {", "AuthorizedTaskItem {"] {
        let (n, sites) = count_outside_allowed(root, needle, &MINT_ALLOWED);
        if n > 0 {
            strays.push(format!(
                "§25.4 A3b `{needle}` 的铸造点越界（只允许 {MINT_ALLOWED:?}），实得 {n} 处: {sites:?}"
            ));
        }
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}

/// §80.1 `G80-43` Grounding validity / recheck debt —— 判据 §11.10#G11-2。
///
/// **这道闸证明结构，不证明语义。** 说清楚边界，免得有人把它当成 §11.10#G11-2 的全部：
/// 「version 变了要判 RECHECK_REQUIRED」「resolver error 不能伪装成 Missing」这类**语义**，
/// 由 `crates/domain/src/grounding.rs` 的夹具 A–H 在运行时证明（spec §11.10 点名的三条注错
/// 已逐条实测红转绿）。本闸负责的是**那些夹具还在不在、派生点还是不是唯一一处、有没有人
/// 另开一个可手改的 stale 真源**——静态可扫、运行时测不到的那一面。
///
/// 因此 DOD-092 的 verifier 不能只写这道闸：它得同时点名那组夹具。**本闸绿 ≠ 语义成立。**
///
/// 四条断言，各自钉一个**不同**的失效面（缺一都会让判据变成看起来在跑的空壳）：
///
/// 1. **八条固定夹具 A–H 逐名在场**（§11.10#G11-2 逐条列了它们）。夹具被删掉时判据会静默
///    变弱——测试数量下降没人看得见，而 `cargo test` 照样全绿。
/// 2. **`derive_grounding_state` 恰好定义一次**（活哨兵，§53.3 规则3 同款）。`GroundingState`
///    的字段是私有的，本模块外造不出来；哨兵防的是家本身被掏空或改名后扫描器失明。
/// 3. **没有可手改的 stale 真源**（DOD-092 原话「不存在可手改 `memory.stale=true` 真源」）：
///    全 workspace 不允许出现给 memory 赋 stale 布尔的写法。
///
/// 三态：`crates/domain/src/grounding.rs` 不存在时返回 `not_applicable` 并点名（§57.1 第2条），
/// 不静默 pass——Phase 4 之前这道闸本来就没有被测对象。
pub fn g80_43_grounding_validity(root: &Path) -> Verdict {
    const HOME: &str = "crates/domain/src/grounding.rs";
    /// §11.10#G11-2 逐条列出的八条夹具，按 A–H 的函数名前缀。判据正文在 spec，这里只钉
    /// 「它们在场」——不复制判据内容（CLAUDE.md：判据正文不得复制到第二处）。
    const FIXTURE_PREFIXES: [&str; 8] = [
        "fn fixture_a_",
        "fn fixture_b_",
        "fn fixture_c_",
        "fn fixture_d_",
        "fn fixture_e_",
        "fn fixture_f_",
        "fn fixture_g_",
        "fn fixture_h_",
    ];
    /// 「可手改的 stale 真源」的书写形态。
    ///
    /// **`stale: bool` 排在第一位不是凑数**：DOD-092 禁的是「真源」，而真源是**字段本身**——
    /// 先有可写的 `stale` 字段，才谈得上给它赋值。只钉赋值语法的话，`*stale_ref = true`
    /// 这类间接写法就绕过去了；钉在字段声明上是堵上游，赋值那几条只是补网。
    ///
    /// 反过来，**读** stale 做判断不是 DOD-092 禁的事（`fn is_stale(&self) -> bool` 不含
    /// `stale: bool`，天然不命中），所以这里不会误报合法读路径——见
    /// `g80_43_reading_a_stale_field_is_not_a_violation`。
    /// 派生点被掏空的形态。**这条是被对抗审查打出来的**：先前三条断言只看
    /// `pub fn derive_grounding_state(` 在不在，于是函数体写成 `{ todo!() }` 照样判 Pass
    /// ——闸绿着，而 spec §11.10 点名的注错（删掉 version compare）它一点都感觉不到。
    /// 这里不去匹配「比较逻辑长什么样」（那是脆的，改个写法就瞎），只钉一件无歧义的事：
    /// **唯一派生点不能是桩**。
    const STUB_BODIES: [&str; 2] = ["todo!()", "unimplemented!()"];
    const HAND_SET_STALE_SHAPES: [&str; 5] = [
        "stale: bool",
        "stale = true",
        "stale: true",
        "set_stale(",
        "stale=true",
    ];

    let Ok(home_src) = fs::read_to_string(root.join(HOME)) else {
        return Verdict::NotApplicable(format!(
            "missing object: {HOME} (§8.8 Grounding Validity 派生点，Phase 4 交付物)"
        ));
    };

    let mut strays = Vec::new();

    // 1. 八条夹具逐名在场。
    for prefix in FIXTURE_PREFIXES {
        if !home_src.contains(prefix) {
            strays.push(format!(
                "§11.10#G11-2 夹具缺失：{HOME} 中找不到 `{prefix}…`（八条 A–H 缺一即判据变弱）"
            ));
        }
    }

    // 2. 活哨兵：派生点恰好一处。带左括号做词边界——`derive_grounding_state_v2` 含子串，
    //    不带括号的话改名不会被抓到（G80-22.5 的同款教训，见 g22_5_a1_sole_implementation）。
    let home_hits = home_src.matches("pub fn derive_grounding_state(").count();
    if home_hits != 1 {
        strays.push(format!(
            "positive sentinel: {HOME} defines `pub fn derive_grounding_state` {home_hits} \
             time(s), expected exactly 1（§53.3 规则3 同款——扫描器失明或派生点被掏空）"
        ));
    }

    // 3. 派生点不是桩（见 STUB_BODIES 的 doc：这是补上来的第四个失效面）。
    if let Some(at) = home_src.find("pub fn derive_grounding_state(") {
        // 只看这个函数往后的一小段，免得把文件别处的 todo!() 算到它头上。
        let body = &home_src[at..(at + 600).min(home_src.len())];
        for stub in STUB_BODIES {
            if body.contains(stub) {
                strays.push(format!(
                    "{HOME}: 唯一派生点 `derive_grounding_state` 的函数体是桩（含 `{stub}`）\
                     ——结构在场但语义空缺，§11.10#G11-2 的四态派生无从谈起"
                ));
            }
        }
    }

    // 4. DOD-092：全 workspace 不得出现手改 stale 的写法。
    for (path, source) in read_files(&walk_files(root, &["rs"])) {
        let disp = display(root, &path);
        if disp.ends_with(SELF_FILE) {
            continue; // 本文件逐字包含这些形态作为判据
        }
        let hits: usize = source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && !l.trim_start().starts_with("///"))
            .map(|l| {
                HAND_SET_STALE_SHAPES
                    .iter()
                    .map(|shape| l.matches(shape).count())
                    .sum::<usize>()
            })
            .sum();
        if hits > 0 {
            strays.push(format!(
                "{disp}: DOD-092 禁止的可手改 stale 真源（{hits} 处）——GroundingState 只能由 \
                 `derive_grounding_state` 推导"
            ));
        }
    }

    if strays.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(strays)
    }
}

/// R3 is intentionally admission-time only.  This parser is small but structural: it scopes
/// every resolver assertion to the actual 0130 function body, so a comment or a second helper
/// cannot satisfy a missing decision predicate.  The live migration is the contract; tests
/// inject mutations into a self-contained fixture below.
fn r3_health_migration_contract(source: &str) -> Verdict {
    let sql = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut failures = Vec::new();
    r3_health_table_contract(&sql, &mut failures);

    let resolver_start = "CREATE FUNCTION control.resolve_user_reasoning_admission(";
    let Some(start) = sql.find(resolver_start) else {
        failures.push("missing exact R3 admission resolver signature".to_string());
        return Verdict::Fail(failures);
    };
    let resolver = &sql[start..];
    let Some(body_start) = resolver.find("AS $$") else {
        failures.push("resolver is missing a SQL body".to_string());
        return Verdict::Fail(failures);
    };
    let body_end = resolver[body_start..]
        .find("$$;")
        .map(|end| body_start + end + 3)
        .unwrap_or(resolver.len());
    let resolver = &resolver[..body_end];
    r3_health_resolver_contract(&sql, resolver, &mut failures);

    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

fn r3_health_table_contract(sql: &str, failures: &mut Vec<String>) {
    for table in [
        "ops.reasoning_provider_health_observations",
        "ops.reasoning_account_health_observations",
    ] {
        let create = format!("CREATE TABLE {table}");
        if !sql.contains(&create) {
            failures.push(format!("missing append-only health authority {table}"));
        }
        if !sql.contains(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            || !sql.contains(&format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        {
            failures.push(format!("{table}: ENABLE + FORCE RLS are both required"));
        }
    }
    let provider_start = sql.find("CREATE TABLE ops.reasoning_provider_health_observations");
    let account_start = sql.find("CREATE TABLE ops.reasoning_account_health_observations");
    let account_end = sql.find("CREATE INDEX reasoning_account_health_latest");
    for (name, block) in [
        (
            "provider",
            provider_start.zip(account_start).map(|(a, b)| &sql[a..b]),
        ),
        (
            "account",
            account_start.zip(account_end).map(|(a, b)| &sql[a..b]),
        ),
    ] {
        let Some(block) = block else {
            continue;
        };
        if !block.contains("source_kind text NOT NULL CHECK (btrim(source_kind) <> '')")
            || !block.contains(
                "reason_code text CHECK (reason_code IS NULL OR btrim(reason_code) <> '')",
            )
        {
            failures.push(format!(
                "{name} health observation needs audit-only source_kind/reason_code shape"
            ));
        }
    }
    if sql.contains("_health_current") {
        failures.push("R3 forbids mutable *_health_current projection tables".to_string());
    }
    if !sql.contains("ops.reasoning_health_observation_reject_mutation()")
        || !sql.contains("CREATE TRIGGER reasoning_provider_health_append_only")
        || !sql.contains("CREATE TRIGGER reasoning_account_health_append_only")
        || !sql.contains("CREATE TRIGGER reasoning_provider_health_reject_truncate")
        || !sql.contains("CREATE TRIGGER reasoning_account_health_reject_truncate")
    {
        failures.push("both R3 health histories need explicit append-only guards".to_string());
    }
}

fn r3_health_resolver_contract(sql: &str, resolver: &str, failures: &mut Vec<String>) {
    if !resolver.contains("SECURITY DEFINER") || !resolver.contains("SET search_path = pg_catalog")
    {
        failures.push("resolver must be SECURITY DEFINER with search_path=pg_catalog".to_string());
    }
    if resolver.matches("clock_timestamp()").count() != 1 {
        failures.push("resolver must capture clock_timestamp() exactly once".to_string());
    }
    if resolver
        .matches("ORDER BY observation.observed_at DESC, observation.observation_id DESC")
        .count()
        != 2
        || resolver.matches("LIMIT 1").count() < 2
    {
        failures.push(
            "resolver must select one latest provider and account row before verdict".to_string(),
        );
    }
    for predicate in [
        "observed_at <= route.admitted_at",
        "route.admitted_at <",
        "lifecycle_state = 'SERVING'",
        "strategy = 'PINNED'",
        "fallback_class = 'NONE'",
        "1 = (\n       SELECT count(*)",
        "b.effective_to IS NULL",
    ] {
        if !resolver.contains(predicate) {
            failures.push(format!(
                "resolver missing R3 decision predicate {predicate:?}"
            ));
        }
    }
    if resolver.contains("COALESCE(provider_health") || resolver.contains("COALESCE(account_health")
    {
        failures.push(
            "resolver may not fallback from the deterministically latest health row".to_string(),
        );
    }
    let grant = "GRANT EXECUTE ON FUNCTION control.resolve_user_reasoning_admission(uuid, bigint, uuid, text)";
    let revoke = sql[..sql.find(grant).unwrap_or(0)]
        .rfind("REVOKE ALL ON FUNCTION")
        .map(|start| &sql[start..sql.find(grant).unwrap_or(start)]);
    if !sql.contains(grant)
        || !sql.contains("TO role_private_worker")
        || !revoke.is_some_and(|block| {
            block.contains("control.resolve_user_reasoning_admission(uuid, bigint, uuid, text)")
                && block.contains("FROM PUBLIC")
        })
    {
        failures.push(
            "resolver must be private-worker-only; PUBLIC EXECUTE must be revoked".to_string(),
        );
    }
}

fn r3_health_migration_gate(root: &Path) -> Verdict {
    let path = root.join("migrations/0130_reasoning_route_health_admission.sql");
    match fs::read_to_string(&path) {
        Ok(source) => r3_health_migration_contract(&source),
        Err(_) => Verdict::NotApplicable(
            "migrations/0130_reasoning_route_health_admission.sql is not present yet; R3 health activation is not integrated"
                .to_string(),
        ),
    }
}

/// The R3 call ledger is not an optional receipt beside the real provider call.  The migration
/// owns the coupled shape (ledger snapshot, disclosure link, candidate reference); the runtime
/// owns the transaction order.  Keep the two static halves separate so a comment or an
/// unrelated retrieval ledger cannot green the contribution path.
fn r3_contribution_ledger_migration_contract(source: &str) -> Verdict {
    let sql = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut failures = Vec::new();
    let ledger = sql
        .find("ALTER TABLE ops.model_call_ledger")
        .map(|start| &sql[start..]);
    let Some(ledger) = ledger else {
        return Verdict::Fail(vec![
            "R3 requires an ops.model_call_ledger expansion in 0130, not a second receipt table"
                .to_string(),
        ]);
    };
    for column in [
        "call_kind",
        "intent_sha256",
        "reasoning_domain_id",
        "binding_id",
        "binding_version",
        "route_policy_id",
        "route_policy_version",
        "profile_id",
        "profile_version",
        "provider_account_id",
        "provider_endpoint_id",
        "credential_ref",
        "billing_account_id",
        "billing_instrument_id",
        "provider_health_observation_id",
        "account_health_observation_id",
        "billing_responsibility",
        "admitted_at",
        "egress_processor_id",
    ] {
        if !ledger.contains(column) {
            failures.push(format!("model_call_ledger R3 snapshot missing {column}"));
        }
    }
    for invariant in [
        "CONTRIBUTION_DEIDENTIFY",
        "model_call_ledger_reasoning_snapshot_shape",
        "ops.reasoning_model_call_validate()",
        "reasoning_model_call_validate",
        "model_call_ledger_reasoning_recipient_unique",
        "model_call_ledger_reasoning_binding_unique",
        "model_call_ledger_reasoning_endpoint_fk",
        "data_disclosures_tenant_model_call_unique",
        "data_disclosures_reasoning_model_call_fk",
        "data_disclosure_reasoning_model_call_validate",
        "contribution_candidates_reasoning_model_call_exact_fk",
        "contribution_candidate_reasoning_route_validate",
        "provider_endpoints_tenant_endpoint_egress_unique",
        "endpoint.egress_processor_id",
        "endpoint.egress_processor_id IS NOT NULL",
        "route.egress_processor_id",
    ] {
        if !sql.contains(invariant) {
            failures.push(format!("R3 ledger linkage/guard missing {invariant}"));
        }
    }
    if !ledger.contains("estimated_cost IS NULL") || !ledger.contains("actual_cost IS NULL") {
        failures.push(
            "CONTRIBUTION_DEIDENTIFY must keep estimated_cost and actual_cost NULL".to_string(),
        );
    }
    for idempotency_invariant in [
        "model_call_ledger_reasoning_call_kind_known",
        "call_kind IN ('COVERAGE_PROBE', 'TYPED_ASSESSMENT')",
        "octet_length(intent_sha256) = 32",
        "OLD.call_kind IS DISTINCT FROM NEW.call_kind",
        "OLD.intent_sha256 IS DISTINCT FROM NEW.intent_sha256",
    ] {
        if !ledger.contains(idempotency_invariant) {
            failures.push(format!(
                "R3 idempotency requires immutable call kind and intent fingerprint: missing {idempotency_invariant}"
            ));
        }
    }
    if !ledger.contains("request_id <> '00000000-0000-0000-0000-000000000000'::uuid") {
        failures.push(
            "R3 ledger shape must reject the nil UUID request_id for CONTRIBUTION_DEIDENTIFY"
                .to_string(),
        );
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

fn r3_function_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start = source.find(signature)?;
    let open = start + source[start..].find('{')?;
    let close = matching_brace_end(source, open)?;
    Some(&source[open..close])
}

fn r3_ordered(body: &str, markers: &[&str]) -> bool {
    let mut cursor = 0;
    for marker in markers {
        let Some(relative) = body[cursor..].find(marker) else {
            return false;
        };
        cursor += relative + marker.len();
    }
    true
}

/// The `let permit = authorize(` window the R3 reserve leg is judged on: inline in the
/// reserve helper, or one level down in `authorize_structured_egress` when the reserve leg
/// delegates to it with the resolver-derived `&admission` (never a config-derived processor).
fn r3_authorize_window<'a>(contribution: &'a str, reserve: &'a str) -> Option<&'a str> {
    if let Some(start) = reserve.find("let permit = authorize(") {
        return Some(&reserve[start..reserve.len().min(start + 512)]);
    }
    let call = reserve.find("authorize_structured_egress(")?;
    let call_window = &reserve[call..reserve.len().min(call + 512)];
    if !call_window.contains("&admission") {
        return None;
    }
    let helper = r3_function_body(contribution, "fn authorize_structured_egress")?;
    let start = helper.find("let permit = authorize(")?;
    Some(&helper[start..helper.len().min(start + 512)])
}

/// The provider-call marker the R3 call leg is ordered on. `complete_structured_timed(` is
/// accepted only when that shared helper is itself a single `.complete_structured(` with no
/// retry loop — otherwise the literal direct call is required, as before.
fn r3_provider_call_marker(contribution: &str, call: &str) -> &'static str {
    if call.contains("complete_structured_timed(")
        && let Some(helper) = r3_function_body(contribution, "async fn complete_structured_timed")
    {
        let single_call = helper.matches(".complete_structured(").count() == 1;
        let no_retry = !helper.contains("loop {") && !helper.contains("retry");
        if single_call && no_retry {
            return "complete_structured_timed(";
        }
    }
    "complete_structured("
}

fn r3_contribution_runtime_contract(
    contribution: &str,
    ledger: &str,
    disclosure: &str,
    byok: &str,
) -> Verdict {
    let required = [
        "resolve_and_reserve_reasoning_call",
        "complete_structured(",
        "finalize_reasoning_call",
    ];
    let mut missing: Vec<String> = required
        .iter()
        .filter(|needle| !contribution.contains(**needle))
        .map(|needle| format!("missing contribution runtime marker {needle}"))
        .collect();
    for (source, marker) in [
        (ledger, "reserve_reasoning_call_in_txn"),
        (ledger, "finalize_reasoning_call_in_txn"),
        (ledger, "egress_processor_id"),
        (disclosure, "reserve_reasoning_in_txn"),
        (disclosure, "finalize_reasoning_in_txn"),
        (disclosure, "model_call_id"),
        (byok, "endpoint_ref"),
    ] {
        if !source.contains(marker) {
            missing.push(format!("missing R3 runtime marker {marker}"));
        }
    }
    if !missing.is_empty() {
        return Verdict::Fail(std::mem::take(&mut missing));
    }
    let reserve = r3_function_body(contribution, "async fn resolve_and_reserve_reasoning_call");
    let call = r3_function_body(contribution, "async fn call_structured");
    let finalize = r3_function_body(contribution, "async fn finalize_reasoning_call");
    let ledger_reserve = r3_function_body(ledger, "async fn reserve_reasoning_call_in_txn");
    let disclosure_reserve = r3_function_body(disclosure, "async fn reserve_reasoning_in_txn");
    let Some((reserve, call, finalize)) =
        reserve.zip(call).zip(finalize).map(|((a, b), c)| (a, b, c))
    else {
        return Verdict::Fail(vec![
            "R3 contribution helper body is missing or malformed".to_string(),
        ]);
    };
    let Some((ledger_reserve, disclosure_reserve)) = ledger_reserve.zip(disclosure_reserve) else {
        return Verdict::Fail(vec![
            "R3 in-transaction reserve helper body is missing or malformed".to_string(),
        ]);
    };
    // §11.2.5 R3 + ADR-0015 D5: the authorize leg may live in the shared `pub(crate)`
    // helper `authorize_structured_egress` (one provider path for Contribution and
    // Consolidate). The gate follows exactly one level of indirection and still demands
    // the resolver-derived processor at the actual `authorize(` call.
    let authorize_window = r3_authorize_window(contribution, reserve);
    if !r3_ordered(
        reserve,
        &[
            "load_with_admission",
            "reserve_reasoning_call_in_txn",
            "reserve_reasoning_in_txn",
            "txn.commit()",
        ],
    ) || !authorize_window.is_some_and(|window| window.contains("admission.egress_processor_id"))
    {
        return Verdict::Fail(vec![
            "R3 reserve helper must use resolver-derived processor and atomically resolve -> ledger reserve -> disclosure reserve -> commit"
                .to_string(),
        ]);
    }
    if !ledger_reserve.contains("locator.egress_processor_id")
        || !disclosure_reserve.contains("model_call_id")
        || !disclosure_reserve.contains("reserve_in_txn")
    {
        return Verdict::Fail(vec![
            "R3 ledger/disclosure reserve helpers must carry resolver processor and exact model_call_id"
                .to_string(),
        ]);
    }
    let provider_marker = r3_provider_call_marker(contribution, call);
    if !r3_ordered(
        call,
        &[
            "resolve_and_reserve_reasoning_call",
            provider_marker,
            "self.finalize_reasoning_call",
        ],
    ) || !r3_ordered(
        finalize,
        &[
            "finalize_reasoning_in_txn",
            "finalize_reasoning_call_in_txn",
            "txn.commit()",
        ],
    ) {
        return Verdict::Fail(vec![
            "R3 actual call must be reserve -> provider -> dual finalize, with no provider retry path"
                .to_string(),
        ]);
    }
    Verdict::Pass
}

/// A committed RESERVED row is the idempotency authority. This structural gate keeps its lookup
/// ahead of a fresh resolver call, so current health cannot turn a crashed attempt into a retry.
fn r3_contribution_idempotency_contract(
    contribution: &str,
    ledger: &str,
    application: &str,
    contribute: &str,
    pg_tests: &str,
) -> Verdict {
    let mut failures = Vec::new();
    if contribution.contains("Uuid::now_v7") {
        failures.push("ContributionReasoner must not mint a retry request id".to_string());
    }
    r3_application_idempotency_contract(application, contribution, contribute, &mut failures);
    let reserve = r3_function_body(contribution, "async fn resolve_and_reserve_reasoning_call");
    let lookup = r3_function_body(ledger, "async fn lookup_reasoning_call_in_txn");
    if !reserve.is_some_and(|body| {
        r3_ordered(
            body,
            &[
                "lookup_reasoning_call_in_txn",
                "load_with_admission",
                "reserve_reasoning_call_in_txn",
                "reserve_reasoning_in_txn",
                "txn.commit()",
            ],
        ) && body.contains("ReasoningCallLookup::ExistingReserved")
            && body.contains("existing_reservation")
    }) {
        failures.push(
            "R3 retry must lookup ExistingReserved before current admission and return before provider dispatch"
                .to_string(),
        );
    }
    r3_ledger_idempotency_contract(ledger, reserve, lookup, pg_tests, &mut failures);
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

fn r3_application_idempotency_contract(
    application: &str,
    contribution: &str,
    contribute: &str,
    failures: &mut Vec<String>,
) {
    for marker in [
        "ContributionReasoningCallKind",
        "CoverageProbe",
        "TypedAssessment",
        "LogicalReasoningCallId",
        "ReasoningIntentSha256",
        "contribution_attempt",
        "with_contribution_attempt",
        "contribution_attempt_is_canonical",
    ] {
        if !application.contains(marker) {
            failures.push(format!(
                "caller-carried R3 idempotency contract missing {marker}"
            ));
        }
    }
    let canonical_attempt =
        r3_function_body(application, "pub fn contribution_attempt_is_canonical");
    if !canonical_attempt.is_some_and(|body| {
        body.contains("(ContributionReasoningCallKind::CoverageProbe, None)")
            && body.contains("(ContributionReasoningCallKind::TypedAssessment, Some(_))")
    }) || !contribution.contains("contribution_attempt_is_canonical(coverage_digest)")
        || !contribute.contains("ContributionReasoningCallKind::CoverageProbe,\n                None")
        || !contribute.contains("ContributionReasoningCallKind::TypedAssessment,\n                Some(public_coverage.binding().digest_sha256())")
    {
        failures.push(
            "R3 coverage shape requires probe=None and typed assessment=exact canonical coverage digest"
                .to_string(),
        );
    }
    let intent_builder = r3_function_body(application, "pub fn with_contribution_attempt");
    let intent_encoder = r3_function_body(application, "fn contribution_reasoning_intent_sha256");
    if !intent_builder.is_some_and(|body| {
        body.contains("intent_schema_version: CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION")
            && body.contains("contribution_reasoning_intent_sha256(")
            && body.contains("CONTRIBUTION_REASONING_INTENT_SCHEMA_VERSION,")
    }) || !intent_encoder.is_some_and(|body| {
        body.contains("b\"intent_schema_version\\0\"")
            && body.contains("intent_schema_version.to_be_bytes()")
    }) {
        failures.push(
            "R3 canonical intent must explicitly version intent_schema_version before hashing"
                .to_string(),
        );
    }
}

fn r3_ledger_idempotency_contract(
    ledger: &str,
    reserve: Option<&str>,
    lookup: Option<&str>,
    pg_tests: &str,
    failures: &mut Vec<String>,
) {
    let tenant_scoped_lock = ledger.contains(
        "const REASONING_REQUEST_ADVISORY_LOCK_SQL: &str = \"SELECT pg_advisory_xact_lock(hashtextextended('model-call-request:' || $1::uuid::text || ':' || $2::uuid::text,0))\"",
    ) && lookup.is_some_and(|body| {
        body.contains("sqlx::query(REASONING_REQUEST_ADVISORY_LOCK_SQL)")
            && r3_ordered(body, &[".bind(tenant_id)", ".bind(logical_call_id.0)"])
    });
    if !lookup.is_some_and(|body| {
        tenant_scoped_lock
            && body.contains("WHERE call.tenant_id=$1 AND call.request_id=$2")
            && body.contains("FOR UPDATE OF call")
            && body.contains("status")
            && body.contains("call_kind")
            && body.contains("intent_sha256")
            && body.contains("ReasoningReservationConflict")
    }) {
        failures.push(
            "R3 retry lookup must serialize the tenant+request key and reject terminal or intent-mismatched rows"
                .to_string(),
        );
    }
    if !reserve.is_some_and(|body| body.contains("attempt.logical_call_id.0.is_nil()")) {
        failures.push(
            "R3 Reasoner must fail closed on a nil caller-carried logical_call_id".to_string(),
        );
    }
    if !ledger.contains("input.logical_call_id.0")
        || !ledger.contains("input.call_kind.as_db_str()")
        || !ledger.contains("input.intent_sha256.0.as_slice()")
    {
        failures.push(
            "R3 ledger insert must persist caller logical id plus independent kind and intent hash"
                .to_string(),
        );
    }
    let test_name = "fn reasoning_attempt_ledger_disclosure_candidate_and_atomicity()";
    if !pg_tests.contains(test_name)
        || !pg_tests.contains("existing_reserved_after_health_change")
        || !pg_tests.contains("same tenant/request key serializes before authority query")
        || !pg_tests.contains("same request UUID across tenants does not serialize")
        || !pg_tests.contains("model-call-request:' || $1::uuid::text || ':' || $2::uuid::text")
        || !pg_tests.contains("ledger_intent_mutation")
    {
        failures.push(
            "R3 PostgreSQL idempotency fault test must cover tenant-scoped locking, health drift, and intent mutation"
                .to_string(),
        );
    }
}

fn r3_contribution_ledger_gate(root: &Path) -> Verdict {
    let migration =
        match fs::read_to_string(root.join("migrations/0130_reasoning_route_health_admission.sql"))
        {
            Ok(source) => source,
            Err(e) => return Verdict::Fail(vec![format!("cannot read 0130 R3 migration: {e}")]),
        };
    let contribution =
        match fs::read_to_string(root.join("crates/adapters/src/contribution_reasoner.rs")) {
            Ok(source) => source,
            Err(e) => return Verdict::Fail(vec![format!("cannot read ContributionReasoner: {e}")]),
        };
    let ledger = fs::read_to_string(root.join("crates/adapters/src/model_call_ledger.rs"));
    let disclosure = fs::read_to_string(root.join("crates/adapters/src/disclosure.rs"));
    let byok = fs::read_to_string(root.join("crates/adapters/src/byok.rs"));
    let application = fs::read_to_string(root.join("crates/application/src/consolidate.rs"));
    let contribute = fs::read_to_string(root.join("crates/application/src/contribute.rs"));
    let pg_tests =
        fs::read_to_string(root.join("crates/adapters/tests/reasoning_route_health_admission.rs"));
    let mut failures = match r3_contribution_ledger_migration_contract(&migration) {
        Verdict::Fail(items) => items,
        Verdict::Pass => Vec::new(),
        Verdict::NotApplicable(detail) => vec![detail],
    };
    let (Ok(ledger), Ok(disclosure), Ok(byok), Ok(application), Ok(contribute), Ok(pg_tests)) =
        (ledger, disclosure, byok, application, contribute, pg_tests)
    else {
        return Verdict::Fail(vec![
            "cannot read one or more R3 contribution runtime/idempotency modules".to_string(),
        ]);
    };
    match r3_contribution_runtime_contract(&contribution, &ledger, &disclosure, &byok) {
        Verdict::Fail(items) => failures.extend(items),
        Verdict::Pass => {}
        Verdict::NotApplicable(detail) => failures.push(detail),
    }
    match r3_contribution_idempotency_contract(
        &contribution,
        &ledger,
        &application,
        &contribute,
        &pg_tests,
    ) {
        Verdict::Fail(items) => failures.extend(items),
        Verdict::Pass => {}
        Verdict::NotApplicable(detail) => failures.push(detail),
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// W1's storage writer is intentionally one SQL-owned protocol. This companion check keeps
/// the marker a function-local scope switch and prevents a second Rust/application CAS.
#[allow(clippy::too_many_lines)]
fn w1_continuity_contract_from(
    migration: &str,
    domain: &str,
    adapter: &str,
    marker_sets_outside_publish: usize,
) -> Verdict {
    let mut failures = Vec::new();
    for needle in [
        "CREATE TABLE private.continuity_projects",
        "CREATE TABLE private.continuity_facet_versions",
        "CREATE TABLE private.continuity_facet_memory_links",
        "CREATE TABLE private.continuity_facet_evidence_links",
        "CREATE TABLE private.continuity_facet_slots",
        "ALTER TABLE private.continuity_projects FORCE ROW LEVEL SECURITY;",
        "ALTER TABLE private.continuity_facet_versions FORCE ROW LEVEL SECURITY;",
        "ALTER TABLE private.continuity_facet_memory_links FORCE ROW LEVEL SECURITY;",
        "ALTER TABLE private.continuity_facet_evidence_links FORCE ROW LEVEL SECURITY;",
        "ALTER TABLE private.continuity_facet_slots FORCE ROW LEVEL SECURITY;",
        "CONSTRAINT continuity_facet_versions_kind_closed CHECK",
        "CONSTRAINT continuity_facet_slots_kind_closed CHECK",
        "CONSTRAINT continuity_facet_slots_current_fkey FOREIGN KEY",
        "DEFERRABLE INITIALLY DEFERRED",
        "CREATE POLICY continuity_evidence_owner_exact_allow",
        "AS PERMISSIVE FOR SELECT TO role_migration_owner",
        "current_setting('humaux.continuity_publish',true)='1' AND CASE",
        "CREATE POLICY continuity_evidence_owner_exact_guard",
        "AS RESTRICTIVE FOR SELECT TO role_migration_owner",
        "CREATE POLICY continuity_evidence_owner_lock_allow",
        "AS PERMISSIVE FOR UPDATE TO role_migration_owner",
        "END) WITH CHECK (false);",
        "CREATE POLICY continuity_evidence_owner_lock_guard",
        "AS RESTRICTIVE FOR UPDATE TO role_migration_owner",
        "END) WITH CHECK (\n      current_setting('humaux.continuity_publish',true) IS DISTINCT FROM '1');",
        "current_setting('humaux.continuity_publish',true) IS DISTINCT FROM '1' OR CASE",
        "pg_catalog.pg_input_is_valid(current_setting('humaux.tenant_id',true),'uuid')",
        "pg_catalog.pg_input_is_valid(current_setting('humaux.workspace_id',true),'uuid')",
        "pg_catalog.pg_input_is_valid(current_setting('humaux.user_id',true),'uuid')",
        "SET humaux.continuity_publish TO '1'",
        "AND slot.project_id=p_project_id AND slot.facet_kind=p_facet_kind\n    FOR UPDATE;",
        "locked_version<>p_expected_slot_version",
        "slot.slot_version=p_expected_slot_version",
        "GET DIAGNOSTICS affected=ROW_COUNT",
        "IF affected<>1",
        "ORDER BY memory.memory_id FOR SHARE OF memory",
        "ORDER BY evidence.evidence_id FOR SHARE OF evidence",
        "SELECT count(*) INTO locked_source_count FROM (",
        ") locked_memory;",
        ") locked_evidence;",
    ] {
        if !migration.contains(needle) {
            failures.push(format!("0136 continuity contract missing `{needle}`"));
        }
    }
    for forbidden in [
        "ON CONFLICT",
        "MERGE INTO",
        "MAX(facet_version)",
        "Scope::Project",
        "compute_contribution_source_backing_closure_v1",
        "set_config('humaux.continuity_publish'",
        "GET DIAGNOSTICS locked_source_count=ROW_COUNT",
    ] {
        if migration.contains(forbidden) {
            failures.push(format!(
                "0136 continuity contract contains forbidden `{forbidden}`"
            ));
        }
    }
    if migration
        .matches("SET humaux.continuity_publish TO '1'")
        .count()
        != 1
        || marker_sets_outside_publish != 0
    {
        failures
            .push("continuity marker must be set only by publish function proconfig".to_string());
    }
    for derived in ["'HANDOFF'", "'COVERAGE'"] {
        if migration.contains(derived) {
            failures.push(format!(
                "derived facet has writable storage literal {derived}"
            ));
        }
    }
    for needle in [
        "continuity_uuid_v7!(ProjectId)",
        "continuity_uuid_v7!(ContinuityFacetVersionId)",
        "pub const ALL: [Self; 15]",
    ] {
        if !domain.contains(needle) {
            failures.push(format!("domain continuity surface missing `{needle}`"));
        }
    }
    for needle in [
        "pool: &RuntimeDbPool",
        "authorization: &AuthorizationScope",
        "authorization.narrow(command.workspace_id)",
        "private.register_continuity_project",
        "private.publish_continuity_facet",
    ] {
        if !adapter.contains(needle) {
            failures.push(format!("adapter continuity surface missing `{needle}`"));
        }
    }
    if adapter.contains("slot_version + 1") || adapter.contains("expected_slot_version + 1") {
        failures.push("Rust adapter independently computes continuity CAS successor".to_string());
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

fn w1_continuity_gate(root: &Path) -> Verdict {
    let paths = [
        "migrations/0136_project_continuity.sql",
        "crates/domain/src/continuity.rs",
        "crates/adapters/src/continuity_repo.rs",
    ];
    let mut sources = Vec::new();
    for path in paths {
        match fs::read_to_string(root.join(path)) {
            Ok(source) => sources.push(source),
            Err(_) => return Verdict::NotApplicable(format!("missing object: {path}")),
        }
    }
    let sql_marker_sets = walk_files(&root.join("migrations"), &["sql"])
        .into_iter()
        .filter(|path| !path.ends_with("0136_project_continuity.sql"))
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|source| {
            source.matches("SET humaux.continuity_publish").count()
                + source
                    .matches("set_config('humaux.continuity_publish'")
                    .count()
        })
        .sum::<usize>();
    let rust_marker_sets = walk_workspace_rs(root)
        .into_iter()
        .filter(|(path, _)| {
            path.strip_prefix(root).is_ok_and(|relative| {
                let mut components = relative.components();
                components
                    .next()
                    .is_some_and(|part| part.as_os_str() == "crates")
                    && components.any(|part| part.as_os_str() == "src")
            })
        })
        .map(|(_, source)| {
            source.matches("SET humaux.continuity_publish").count()
                + source
                    .matches("set_config('humaux.continuity_publish'")
                    .count()
        })
        .sum::<usize>();
    w1_continuity_contract_from(
        &sources[0],
        &sources[1],
        &sources[2],
        sql_marker_sets + rust_marker_sets,
    )
}

/// §25.3.1 W2: one native Continuity read route backed by one Gateway-only
/// SECURITY DEFINER reader and one application-owned RR READ ONLY transaction.
#[allow(clippy::too_many_lines)]
fn w2_continuity_contract_from(
    migration: &str,
    manifest: &str,
    application: &str,
    adapter: &str,
    gateway: &str,
    guard: &str,
    dispatch: &str,
) -> Verdict {
    let mut failures = Vec::new();
    let manifest: toml::Value = match toml::from_str(manifest) {
        Ok(value) => value,
        Err(error) => {
            return Verdict::Fail(vec![format!(
                "0137 continuity manifest is invalid TOML: {error}"
            )]);
        }
    };
    if manifest.get("migration_id").and_then(toml::Value::as_str)
        != Some("0137_project_continuity_read")
    {
        failures.push("0137 continuity manifest must bind its exact migration_id".to_string());
    }
    if manifest.get("class").and_then(toml::Value::as_str) != Some("FORWARD_ONLY") {
        failures.push("0137 continuity manifest must remain FORWARD_ONLY".to_string());
    }
    for (field, needle) in [
        (
            "precheck",
            "to_regprocedure('private.read_continuity_project_storage_v1(uuid,uuid,uuid,uuid,uuid,uuid[])') is null",
        ),
        (
            "precheck",
            "to_regclass('private.continuity_projects') is not null",
        ),
        ("precheck", "private.publish_continuity_facet("),
        (
            "postcheck",
            "select count(*)=1 from reader where prosecdef and provolatile='s'",
        ),
        ("postcheck", "array['search_path=pg_catalog']::text[]"),
        (
            "postcheck",
            "pg_get_userbyid(proowner)='role_migration_owner'",
        ),
        ("postcheck", "not has_function_privilege('public'"),
        ("postcheck", "role.name='role_gateway'"),
        (
            "postcheck",
            "SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER",
        ),
        ("postcheck", "strpos(definition,'INSERT ') = 0"),
        ("postcheck", "strpos(definition,'UPDATE ') = 0"),
        ("postcheck", "strpos(definition,'DELETE ') = 0"),
    ] {
        if !manifest
            .get(field)
            .and_then(toml::Value::as_str)
            .is_some_and(|value| value.contains(needle))
        {
            failures.push(format!(
                "0137 continuity manifest {field} missing `{needle}`"
            ));
        }
    }
    for needle in [
        "CREATE FUNCTION private.read_continuity_project_storage_v1(",
        "LANGUAGE plpgsql STABLE SECURITY DEFINER",
        "SET search_path TO pg_catalog",
        "ALTER FUNCTION private.read_continuity_project_storage_v1(",
        ") OWNER TO role_migration_owner;",
        "project.workspace_id=ANY(p_authorized_workspace_ids)",
        "project.lifecycle_state='ACTIVE'",
        "p_requested_workspace_id IS NULL",
        "pg_catalog.pg_input_is_valid(tenant_setting,'uuid')",
        "memory_links_exact boolean",
        "evidence_links_exact boolean",
        "stored_body_sha256 bytea",
        "ORDER BY slot.facet_kind NULLS FIRST",
        "REVOKE ALL ON FUNCTION private.read_continuity_project_storage_v1(",
        ") FROM PUBLIC;",
        "GRANT EXECUTE ON FUNCTION private.read_continuity_project_storage_v1(",
        ") TO role_gateway;",
        "array_agg(link.memory_id ORDER BY link.memory_id)",
        "array_agg(link.memory_sha256 ORDER BY link.memory_id)",
        "array_agg(link.evidence_id ORDER BY link.evidence_id)",
        "array_agg(link.evidence_sha256 ORDER BY link.evidence_id)",
    ] {
        if !migration.contains(needle) {
            failures.push(format!("0137 continuity reader missing `{needle}`"));
        }
    }
    for forbidden in [
        "CREATE TABLE",
        "INSERT INTO",
        "UPDATE private.",
        "DELETE FROM",
    ] {
        if migration.contains(forbidden) {
            failures.push(format!(
                "0137 continuity reader contains forbidden `{forbidden}`"
            ));
        }
    }
    for needle in [
        "pub const W2_FORCED_UNAVAILABLE: [ContinuityFacetKind; 6]",
        "VerifiedCurrentFacet::from_authoritative_jsonb_text",
        "humaux.continuity.result.v1\\0",
        "ContinuityFacetKind::ALL",
        "if accounted != 17",
        "if counts[0] == 17 && !closed.handoff.counts.overflow",
    ] {
        if !application.contains(needle) {
            failures.push(format!("application continuity surface missing `{needle}`"));
        }
    }
    for needle in [
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
        "private.read_continuity_project_storage_v1",
        "install_lookup_context(&mut tx, authorization).await?;",
        "install_workspace_context(&mut tx, workspace).await?;",
        "let frozen = fetch_frozen_in_txn",
        "final_memory_ids_in_txn",
        "DiagnosticCode::VisibilityRevalidationFailed",
        "TOMBSTONED",
        "count(stream.commit_seq) AS association_count",
        "let body_sha256 = digest(raw.stored_body_sha256)?;",
    ] {
        if !adapter.contains(needle) {
            failures.push(format!("adapter continuity reader missing `{needle}`"));
        }
    }
    if adapter.contains("fetch_frozen(") || adapter.contains("assemble_materialized(") {
        failures.push("W2 reader opens a forbidden second materialization path".to_string());
    }
    for needle in ["read_project_continuity", "PostgresContinuityReadPort"] {
        if !gateway.contains(needle) {
            failures.push(format!("Gateway continuity route missing `{needle}`"));
        }
    }
    let needle = "WorkspaceAdmission::PreserveContinuityFilter => None";
    if !guard.contains(needle) {
        failures.push(format!("Gateway continuity guard missing `{needle}`"));
    }
    if guard
        .matches("operation.operation_key() != \"continuity.get\"")
        .count()
        != 2
    {
        failures.push(
            "Gateway continuity guard must preserve both Continuity scope branches".to_string(),
        );
    }
    for needle in [
        "SUPPORTED_OPERATION_KEYS: [&str; 27]",
        "\"continuity.get\" =>",
    ] {
        if !dispatch.contains(needle) {
            failures.push(format!("Gateway continuity dispatch missing `{needle}`"));
        }
    }
    if dispatch
        .matches("catalog.validate_output(ToolName::Continuity, &value)")
        .count()
        != 2
    {
        failures.push(
            "Gateway continuity dispatch must validate both Continuity result paths".to_string(),
        );
    }
    for source in [application, adapter, gateway, guard, dispatch] {
        for forbidden in ["Scope::Project", "embedding", "rerank", "USER_REASONING"] {
            if source.contains(forbidden) {
                failures.push(format!(
                    "W2 production path contains forbidden `{forbidden}`"
                ));
            }
        }
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

// ============================================================================
// card 22 — §33 Canonical MCP Tool Details「工具面交付实况」
// ============================================================================

/// One closed operation-key family the gateway dispatches through a domain table rather than
/// a literal (§78.2: the key is spelled once, in `domain`). `variants` is `(path, key)` where
/// `path` is the exact Rust text the dispatch writes, e.g. `DestructiveOp::MemoryPin`.
struct OperationKeyFamily {
    name: &'static str,
    variants: Vec<(String, &'static str)>,
}

/// Built from the domain's own `ALL` tables — never a second list of keys to keep in sync.
fn operation_key_families() -> Vec<OperationKeyFamily> {
    use humaux_domain::{affect::AffectWriteOp, confirm::DestructiveOp, subject::SubjectWriteOp};
    vec![
        OperationKeyFamily {
            name: "DestructiveOp",
            variants: DestructiveOp::ALL
                .iter()
                .map(|op| (format!("DestructiveOp::{op:?}"), op.operation_key()))
                .collect(),
        },
        OperationKeyFamily {
            name: "SubjectWriteOp",
            variants: SubjectWriteOp::ALL
                .iter()
                .map(|op| (format!("SubjectWriteOp::{op:?}"), op.operation_key()))
                .collect(),
        },
        OperationKeyFamily {
            name: "AffectWriteOp",
            variants: AffectWriteOp::ALL
                .iter()
                .map(|op| (format!("AffectWriteOp::{op:?}"), op.operation_key()))
                .collect(),
        },
    ]
}

/// The `SUPPORTED_OPERATION_KEYS` array, resolved to real keys. `Err` carries the reason the
/// array could not be read at all (a missing array, an entry neither a literal nor a known
/// family variant, or a declared length that disagrees with the entry count).
fn supported_operation_keys(dispatch: &str) -> Result<BTreeSet<String>, Vec<String>> {
    let mut failures = Vec::new();
    let Some(head) = dispatch.find("pub const SUPPORTED_OPERATION_KEYS: [&str; ") else {
        return Err(vec!["SUPPORTED_OPERATION_KEYS array is absent".to_string()]);
    };
    let after = &dispatch[head + "pub const SUPPORTED_OPERATION_KEYS: [&str; ".len()..];
    let declared: usize = after
        .split(']')
        .next()
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0);
    let Some(open) = after.find("= [") else {
        return Err(vec![
            "SUPPORTED_OPERATION_KEYS has no array body".to_string(),
        ]);
    };
    let body_start = open + "= [".len();
    let Some(close) = after[body_start..].find("\n];") else {
        return Err(vec![
            "SUPPORTED_OPERATION_KEYS body is unterminated".to_string(),
        ]);
    };
    let families = operation_key_families();
    let mut keys = BTreeSet::new();
    let mut count = 0usize;
    for entry in after[body_start..body_start + close].split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        count += 1;
        let resolved = if entry.starts_with('"') && entry.ends_with('"') && entry.len() >= 2 {
            Some(entry[1..entry.len() - 1].to_string())
        } else {
            families
                .iter()
                .flat_map(|f| f.variants.iter())
                .find(|(path, _)| entry == format!("{path}.operation_key()"))
                .map(|(_, key)| (*key).to_string())
        };
        match resolved {
            Some(key) => {
                if !keys.insert(key.clone()) {
                    failures.push(format!("SUPPORTED_OPERATION_KEYS repeats `{key}`"));
                }
            }
            None => failures.push(format!(
                "SUPPORTED_OPERATION_KEYS entry `{entry}` is neither a literal key nor a \
                 closed-table `<Family>::<Variant>.operation_key()`"
            )),
        }
    }
    if declared != count {
        failures.push(format!(
            "SUPPORTED_OPERATION_KEYS declares [&str; {declared}] but carries {count} entries"
        ));
    }
    if failures.is_empty() {
        Ok(keys)
    } else {
        Err(failures)
    }
}

/// Every operation key the `invoke` dispatch actually has an arm for, read from the same
/// source file. The `_ =>` fallback (`reject_unsupported`) ends the scan — routes below it are
/// exactly the declared-only surface.
fn dispatched_operation_keys(dispatch: &str) -> Result<BTreeSet<String>, Vec<String>> {
    let Some(head) = dispatch.find("match operation.operation_key() {") else {
        return Err(vec!["invoke dispatch match is absent".to_string()]);
    };
    let body = &dispatch[head..];
    let body = body
        .find("\n            _ => {")
        .map_or(body, |end| &body[..end]);
    let mut keys = BTreeSet::new();
    for piece in body.split(" =>") {
        if let Some(open) = piece.rfind('"') {
            let prefix = &piece[..open];
            if let Some(start) = prefix.rfind('"')
                && piece[open..].trim() == "\""
            {
                keys.insert(prefix[start + 1..].to_string());
            }
        }
    }
    for family in operation_key_families() {
        let catch_all = format!("{}::parse_operation_key", family.name);
        let pinned = format!("{}::parse_operation_key(key) == Some(", family.name);
        for (path, key) in &family.variants {
            let named = body.contains(&format!("{path}.operation_key()"))
                || (body.contains(&pinned) && body.contains(path.as_str()))
                || (body.contains(&catch_all) && !body.contains(&pinned));
            if named {
                keys.insert((*key).to_string());
            }
        }
    }
    if keys.is_empty() {
        return Err(vec!["invoke dispatch names no operation key".to_string()]);
    }
    Ok(keys)
}

/// The keys listed inside one `<!-- humaux:<marker>:begin -->` … `:end` block of the Baseline.
fn baseline_key_block(baseline: &str, marker: &str) -> Result<BTreeSet<String>, Vec<String>> {
    let begin = format!("<!-- humaux:{marker}:begin -->");
    let end = format!("<!-- humaux:{marker}:end -->");
    let (Some(from), Some(to)) = (baseline.find(&begin), baseline.find(&end)) else {
        return Err(vec![format!("Baseline block `{marker}` is absent")]);
    };
    if to < from {
        return Err(vec![format!("Baseline block `{marker}` is inverted")]);
    }
    let mut keys = BTreeSet::new();
    for line in baseline[from + begin.len()..to].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("```") {
            continue;
        }
        keys.insert(line.to_string());
    }
    if keys.is_empty() {
        return Err(vec![format!("Baseline block `{marker}` lists no key")]);
    }
    Ok(keys)
}

fn name_diff(
    label: &str,
    left: &BTreeSet<String>,
    right: &BTreeSet<String>,
    out: &mut Vec<String>,
) {
    for key in left.difference(right) {
        out.push(format!("{label}: `{key}`"));
    }
}

/// Card 22: the delivery-point tool surface is ONE fact, and it lives in three places that
/// must agree — the `SUPPORTED_OPERATION_KEYS` array, the `invoke` dispatch that actually has
/// the arms, and §33's 「工具面交付实况」 table in the Baseline. Before this gate the array was
/// read by nobody (three string pins only checked its declared length), so it had already
/// drifted three keys behind the dispatch while the document claimed the whole 8-tool surface.
///
/// The fourth set closes the other direction: every key the canonical catalog admits is either
/// wired or listed as declared-only, so a contract can never grow a route that the document
/// silently calls delivered.
fn mcp_tool_surface_truth_from(
    dispatch: &str,
    baseline: &str,
    catalog: &BTreeSet<String>,
) -> Verdict {
    let mut failures = Vec::new();
    let supported = match supported_operation_keys(dispatch) {
        Ok(keys) => keys,
        Err(errors) => {
            failures.extend(errors);
            BTreeSet::new()
        }
    };
    let dispatched = match dispatched_operation_keys(dispatch) {
        Ok(keys) => keys,
        Err(errors) => {
            failures.extend(errors);
            BTreeSet::new()
        }
    };
    let wired = match baseline_key_block(baseline, "wired-operation-keys") {
        Ok(keys) => keys,
        Err(errors) => {
            failures.extend(errors);
            BTreeSet::new()
        }
    };
    let declared_only = match baseline_key_block(baseline, "declared-only-operation-keys") {
        Ok(keys) => keys,
        Err(errors) => {
            failures.extend(errors);
            BTreeSet::new()
        }
    };
    if !supported.is_empty() && !dispatched.is_empty() {
        name_diff(
            "SUPPORTED_OPERATION_KEYS lists a key the invoke dispatch has no arm for",
            &supported,
            &dispatched,
            &mut failures,
        );
        name_diff(
            "invoke dispatch routes a key SUPPORTED_OPERATION_KEYS omits",
            &dispatched,
            &supported,
            &mut failures,
        );
    }
    if !supported.is_empty() && !wired.is_empty() {
        name_diff(
            "SUPPORTED_OPERATION_KEYS lists a key §33's wired table omits",
            &supported,
            &wired,
            &mut failures,
        );
        name_diff(
            "§33's wired table claims a key SUPPORTED_OPERATION_KEYS omits",
            &wired,
            &supported,
            &mut failures,
        );
    }
    if !wired.is_empty() && !declared_only.is_empty() {
        for key in wired.intersection(&declared_only) {
            failures.push(format!("§33 lists `{key}` as both wired and declared-only"));
        }
        let documented: BTreeSet<String> = wired.union(&declared_only).cloned().collect();
        name_diff(
            "§33 documents an operation key the canonical catalog does not admit",
            &documented,
            catalog,
            &mut failures,
        );
        name_diff(
            "the canonical catalog admits an operation key §33 documents nowhere",
            catalog,
            &documented,
            &mut failures,
        );
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// Reads the four real sources. Any absent object is `not_applicable` naming it (§57.1 第2条).
fn mcp_tool_surface_truth(root: &Path) -> Verdict {
    let dispatch_path = root.join("bins/gateway/src/mcp_application.rs");
    let baseline_path = root.join("docs/architecture/Baseline_2.9.md");
    let Ok(dispatch) = fs::read_to_string(&dispatch_path) else {
        return Verdict::NotApplicable("bins/gateway/src/mcp_application.rs".to_string());
    };
    let Ok(baseline) = fs::read_to_string(&baseline_path) else {
        return Verdict::NotApplicable("docs/architecture/Baseline_2.9.md".to_string());
    };
    let catalog = match catalog_operation_keys(root) {
        Ok(keys) => keys,
        // §57.1 第2条's `not_applicable` is for an object that is ABSENT. A contract that is
        // present but shaped differently is not absent — and letting it degrade to
        // `not_applicable` made this arm switchable off by a contract edit (renaming `oneOf`
        // to `anyOf` stopped the whole wired ∪ declared-only == catalog leg from judging
        // anything while the run still exited 0). Present-but-unreadable is a red gate.
        Err(CatalogDefect::Missing(object)) => return Verdict::NotApplicable(object),
        Err(CatalogDefect::Malformed(object)) => {
            return Verdict::Fail(vec![format!(
                "canonical MCP catalog is present but unreadable, so the catalog leg of this \
                 gate would judge nothing: {object}"
            )]);
        }
    };
    mcp_tool_surface_truth_from(&dispatch, &baseline, &catalog)
}

/// Why a contract could not be turned into a key set. `Missing` = the file is not there at all
/// (§57.1 `not_applicable`); `Malformed` = it is there and does not have the shape the catalog
/// is defined by (a failure — see `mcp_tool_surface_truth`).
#[derive(Debug)]
enum CatalogDefect {
    Missing(String),
    Malformed(String),
}

/// Every `x-humaux-operation.operation_key` the canonical catalog admits, read from the same
/// `contracts/mcp` documents `protocol::mcp_catalog` embeds.
fn catalog_operation_keys(root: &Path) -> Result<BTreeSet<String>, CatalogDefect> {
    let dir = root.join("contracts/mcp");
    let manifest = read_contract(&dir, "manifest.json")?;
    let tools = manifest
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            CatalogDefect::Malformed("contracts/mcp/manifest.json#/tools".to_string())
        })?;
    let mut keys = BTreeSet::new();
    for tool in tools {
        let file = tool
            .get("input_schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CatalogDefect::Malformed(
                    "contracts/mcp/manifest.json#/tools/*/input_schema".to_string(),
                )
            })?;
        let schema = read_contract(&dir, file)?;
        let branches = schema
            .get("oneOf")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| CatalogDefect::Malformed(format!("contracts/mcp/{file}#/oneOf")))?;
        for branch in branches {
            let key = branch
                .get("x-humaux-operation")
                .and_then(|op| op.get("operation_key"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CatalogDefect::Malformed(format!(
                        "contracts/mcp/{file}#/oneOf/*/x-humaux-operation"
                    ))
                })?;
            keys.insert(key.to_string());
        }
    }
    Ok(keys)
}

/// Card 22 review fix: `x-humaux-v1-supported` was an inert annotation. §33 and ADR-0044 both
/// said it was 「由 architecture-check 与 guard 对表」 and nothing in the tree read the key —
/// deleting `"semantic"` from it left every gate green, which is the same unbacked-claim defect
/// this card exists to remove (§80.1: a criterion no input can falsify is not a criterion).
///
/// This arm makes the key load-bearing in BOTH directions. The schema declares, per field,
/// which of the closed enum's values this delivery point accepts; the guard in
/// `bins/gateway/src/recall.rs` is the runtime authority and must name exactly the complement.
/// Two spellings are admitted because the guard legitimately uses both: an ACCEPT clause
/// (`!=` / `!matches!`) must name exactly `x-humaux-v1-supported`, a REFUSE clause (`==` /
/// `matches!`) must name exactly `enum − x-humaux-v1-supported`. Either side moving alone is red.
fn recall_v1_supported_lanes_from(schema: &str, guard_src: &str) -> Verdict {
    let Ok(schema) = serde_json::from_str::<serde_json::Value>(schema) else {
        return Verdict::Fail(vec![
            "contracts/mcp/recall.schema.json is present but is not JSON".to_string(),
        ]);
    };
    let Some(properties) = schema
        .pointer("/oneOf/0/properties")
        .and_then(serde_json::Value::as_object)
    else {
        return Verdict::Fail(vec![
            "contracts/mcp/recall.schema.json#/oneOf/0/properties is absent or not an object"
                .to_string(),
        ]);
    };
    let Some(guard) = recall_guard_block(guard_src) else {
        return Verdict::Fail(vec![
            "bins/gateway/src/recall.rs: no `DependencyUnavailable` lane guard found in \
             `pub async fn search(`"
                .to_string(),
        ]);
    };
    let mut failures = Vec::new();
    let mut declared = 0usize;
    for (field, spec) in properties {
        let Some(supported) = spec.get("x-humaux-v1-supported") else {
            continue;
        };
        declared += 1;
        let (Some(supported), Some(closed)) =
            (string_set(supported), spec.get("enum").and_then(string_set))
        else {
            failures.push(format!(
                "`{field}`: `x-humaux-v1-supported` and `enum` must both be arrays of strings"
            ));
            continue;
        };
        name_diff(
            &format!("`{field}`: x-humaux-v1-supported names a value outside the closed enum"),
            &supported,
            &closed,
            &mut failures,
        );
        let refused: BTreeSet<String> = closed.difference(&supported).cloned().collect();
        let clauses: Vec<&str> = guard
            .split("||")
            .filter(|clause| clause.contains(&format!("input.{field}")))
            .collect();
        // A field whose whole enum is delivered needs no clause at all — and must not have one,
        // or the guard would be refusing a value the contract says is supported.
        if refused.is_empty() {
            if !clauses.is_empty() {
                failures.push(format!(
                    "`{field}`: every enum value is declared supported, yet the recall.rs guard \
                     still has a clause naming `input.{field}`"
                ));
            }
            continue;
        }
        let [clause] = clauses.as_slice() else {
            failures.push(format!(
                "`{field}`: the recall.rs guard must have exactly one clause naming \
                 `input.{field}` ({} found; enum − supported = {refused:?})",
                clauses.len()
            ));
            continue;
        };
        let named = clause_literals(clause);
        let (expected, shape) = if clause.contains("!=") || clause.contains("!matches!") {
            (&supported, "accepts")
        } else {
            (&refused, "refuses")
        };
        if &named != expected {
            failures.push(format!(
                "`{field}`: recall.rs {shape} {named:?} while recall.schema.json declares \
                 x-humaux-v1-supported = {supported:?} (so it must {shape} {expected:?})"
            ));
        }
    }
    if declared == 0 {
        failures.push(
            "contracts/mcp/recall.schema.json declares no `x-humaux-v1-supported` — §33's \
             narrowed Tool 2 claim has nothing left to check"
                .to_string(),
        );
    }
    if failures.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(failures)
    }
}

/// The `if … { return Err(ErrorCode::DependencyUnavailable); }` condition at the head of
/// `recall::search` — the lane guard, and nothing else in the function.
fn recall_guard_block(src: &str) -> Option<&str> {
    let body = &src[src.find("pub async fn search(")?..];
    let end = body.find("return Err(ErrorCode::DependencyUnavailable);")?;
    let condition = &body[..end];
    let start = condition.rfind("\n    if ")?;
    Some(&condition[start..])
}

/// Every `"…"` literal in one guard clause.
fn clause_literals(clause: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = clause;
    while let Some(open) = rest.find('"') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.insert(after[..close].to_string());
        rest = &after[close + 1..];
    }
    out
}

fn string_set(value: &serde_json::Value) -> Option<BTreeSet<String>> {
    value
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Reads the two real objects. Absent ⇒ `not_applicable` naming it; present-but-unreadable is
/// a failure, never a silent skip (same rule as `mcp_tool_surface_truth`).
fn recall_v1_supported_lanes(root: &Path) -> Verdict {
    let schema_path = root.join("contracts/mcp/recall.schema.json");
    let guard_path = root.join("bins/gateway/src/recall.rs");
    let Ok(schema) = fs::read_to_string(&schema_path) else {
        return Verdict::NotApplicable("contracts/mcp/recall.schema.json".to_string());
    };
    let Ok(guard) = fs::read_to_string(&guard_path) else {
        return Verdict::NotApplicable("bins/gateway/src/recall.rs".to_string());
    };
    recall_v1_supported_lanes_from(&schema, &guard)
}

/// One contract document: absent ⇒ `Missing`, present-but-not-JSON ⇒ `Malformed`.
fn read_contract(dir: &Path, file: &str) -> Result<serde_json::Value, CatalogDefect> {
    let raw = fs::read_to_string(dir.join(file))
        .map_err(|_| CatalogDefect::Missing(format!("contracts/mcp/{file}")))?;
    serde_json::from_str(&raw)
        .map_err(|_| CatalogDefect::Malformed(format!("contracts/mcp/{file} (not JSON)")))
}

fn w2_continuity_gate(root: &Path) -> Verdict {
    let paths = [
        "migrations/0137_project_continuity_read.sql",
        "migrations/0137_project_continuity_read.manifest.toml",
        "crates/application/src/continuity.rs",
        "crates/adapters/src/continuity_read.rs",
        "bins/gateway/src/continuity.rs",
        "bins/gateway/src/guard.rs",
        "bins/gateway/src/mcp_application.rs",
    ];
    let mut sources = Vec::new();
    for path in paths {
        match fs::read_to_string(root.join(path)) {
            Ok(source) => sources.push(source),
            Err(_) => return Verdict::NotApplicable(format!("missing object: {path}")),
        }
    }
    w2_continuity_contract_from(
        &sources[0],
        &sources[1],
        &sources[2],
        &sources[3],
        &sources[4],
        &sources[5],
        &sources[6],
    )
}

// ============================================================================
// M24-7 / G-M24-7 (§79, #101): a test binary whose sources carry a derived-job, outbox or provider-slot marker is in nextest's `global-db` group
// ============================================================================

/// The nextest config the completeness gate reads. §79: nextest runs test binaries in parallel, so a binary that
/// shares cluster-global DB state is only safe inside a `max-threads = 1` test group.
const NEXTEST_CONFIG_FILE: &str = ".config/nextest.toml";

/// The one nextest test group that serialises every binary touching cluster-global DB state.
const GLOBAL_DB_GROUP: &str = "global-db";

/// Closed list of literal markers of the cluster-global DB state this gate knows, `(marker, why it is shared)`: the
/// derived jobs and their claim, the outbox rows that enqueue them, the four provider slots and the fixtures whose
/// teardown toggles triggers on shared tables. It is not every kind of cluster-global state: at #145, 36 of the 67
/// integration binaries in `global-db` (54%) carry a marker, the other 31 were grouped from observed failures or review,
/// and a binary that shares some other state is invisible here. A test binary whose sources (its test file plus every
/// module it pulls in) contain one must be in [`GLOBAL_DB_GROUP`] or be listed in [`GLOBAL_DB_EXEMPT`].
///
/// Derived from the header of `.config/nextest.toml` (provider slots, the outbox-to-job triggers, the claim of derived
/// jobs, the fixtures whose teardown toggles triggers) and from what the binaries already in the group reference.
/// `ops.jobs` is deliberately not a marker: 21 binaries name it only in a tenant-scoped teardown DELETE, which shares
/// nothing; the derived-job mechanism is marked through the job types, the claim functions and the outbox event that
/// enqueues it. Whole-line and trailing `//` comments and `/* */` blocks never count (a module header lists tables).
// ponytail: substring match on code text, not a call graph. A binary that reaches a marker only through a helper
// outside its `mod`/`#[path]` closure is invisible; upgrade = template database per test binary (M24-7a/7b), after
// which the group itself goes away.
const GLOBAL_DB_MARKERS: &[(&str, &str)] = &[
    (
        "provider_slots",
        "the four provider slots are global rows: a test that binds, resets or counts them sees every other binary's claims (§67.2)",
    ),
    (
        "dispatch_fence",
        "the private-worker fixture that releases and asserts every provider slot",
    ),
    (
        "operation_receipt_fixture",
        "the shared-database fixture: it seeds tenants through remember.put and its teardown toggles triggers on shared tables",
    ),
    (
        "continuity_0137_fixture",
        "seeds shared-database continuity projects through EVIDENCE_ACCEPTED outbox rows and deletes the jobs they enqueue",
    ),
    (
        "remember.put",
        "the remember operation writes an EVIDENCE_ACCEPTED outbox row",
    ),
    (
        "RememberCommand",
        "a direct call of the remember write path writes the same outbox row",
    ),
    (
        "EVIDENCE_ACCEPTED",
        "the outbox event whose 0164/0235 trigger enqueues a DERIVED_DISTILL job and whose 0190 trigger admits the tenant to distill_tenant_scheduler",
    ),
    (
        "DERIVED_DISTILL",
        "a derived job that the cross-tenant claim of any other binary can serve",
    ),
    (
        "DERIVED_CONSOLIDATE",
        "a derived job that the cross-tenant claim of any other binary can serve",
    ),
    (
        "DerivedJobType",
        "the typed enqueue and claim of derived jobs",
    ),
    (
        "claim_distill",
        "the fair-share claim across every tenant's DERIVED_DISTILL jobs and the four provider slots",
    ),
    (
        "claim_derived_work",
        "the cross-tenant claim of derived jobs, distill and consolidation (claim_derived_work_consolidation is the consolidation worker's entry)",
    ),
    (
        "distill_tenant_scheduler",
        "the scheduler rows the fair-share claim serves; a tenant admitted concurrently is not fenced (#101)",
    ),
    (
        "DISABLE TRIGGER",
        "a teardown that switches a trigger off on a shared table (the audit and continuity append-only guards) for every other binary",
    ),
];

/// Test binaries that carry a marker yet are safe outside [`GLOBAL_DB_GROUP`], `(nextest binary id, why)`. The reason
/// names the mechanism, not the intent: every one of these opens only a database it created itself. A row whose binary
/// no longer exists, no longer carries a marker or is now in the group is red (stale), so the list cannot outlive its
/// reasons.
const GLOBAL_DB_EXEMPT: &[(&str, &str)] = &[
    (
        "humaux-adapters::rebuild",
        "every fixture (S1Fixture, S2Fixture, S3Fixture, S1Contract) creates its own throwaway database with throwaway_db::create and connects only to it",
    ),
    (
        "humaux-admin::probes",
        "its fixture runs CREATE DATABASE per test and every connection of the test goes to that database",
    ),
    (
        "humaux-maintenance::drill",
        "every test opens a throwaway database or a scratch container cluster (throwaway::db, Handle::in_throwaway_at), never the shared one",
    ),
    (
        "humaux-maintenance::measure",
        "every test opens a throwaway database or a scratch container cluster (throwaway::db, Handle::in_throwaway_at), never the shared one",
    ),
    (
        "humaux-maintenance::onboarding",
        "fixture() runs CREATE DATABASE per test and connects only to it",
    ),
    (
        "humaux-maintenance::partitions",
        "every test migrates and uses a throwaway database (throwaway::db, throwaway::db_through), so its trigger toggles act on that database only",
    ),
];

// ----------------------------------------------------------------------------
// M24-7b (§79, #145): DDL on the shared catalog runs only in a `lane(a:disposable)` test
// ----------------------------------------------------------------------------

/// Closed list of DDL that rewrites the catalog or takes a table-wide lock, `(first words, words that must follow in the
/// same statement, why it is unsafe on a database other test binaries use)`. The `global-db` group serialises a binary
/// only against its own members and most test binaries are ungrouped, so none of these may run in a plain test: every
/// hit in a test binary's sources must sit inside a `#[test]` fn whose `#[ignore]` reason is `lane(a:disposable)` (the
/// serial lane gives it a database no other binary writes, docs/ops/serial-lane.md) or the binary must be a row of
/// [`SHARED_CATALOG_DDL_EXEMPT`].
///
/// Words are lowercase and single-spaced. The scan reads the word tokens of the code text (strings included, comments
/// blanked), so case, line breaks and `\` string continuations never hide a statement; a statement ends at `;` or at a
/// `"`.
// ponytail: token match on code text, not a SQL parser or a call graph. Invisible: DDL assembled from pieces, a
// `LOCK TABLE` with no `IN .. MODE` (ACCESS EXCLUSIVE by default), a statement that holds an escaped quote before its
// mode, DDL in a library's or binary's own unit tests (they carry no sources), and DDL reached from a plain test through
// a helper (the helper's text is a hit, so it has to sit inside the `lane(a:disposable)` test itself). Upgrade = syn.
const SHARED_CATALOG_DDL: &[(&str, Option<&str>, &str)] = &[
    (
        "rename column",
        None,
        "RENAME COLUMN takes ACCESS EXCLUSIVE and changes the catalog every concurrent statement of every other binary is planned against",
    ),
    (
        "add column",
        None,
        "ADD COLUMN takes ACCESS EXCLUSIVE; a writable column swapped in under a generated one gives every concurrent insert different semantics (#145)",
    ),
    (
        "drop column",
        None,
        "DROP COLUMN takes ACCESS EXCLUSIVE and removes a column other binaries' statements name",
    ),
    (
        "alter role",
        None,
        "a role is one cluster-global row: its attributes and password change for every database and for every binary that logs in as it (BYPASSRLS on role_gateway lifts row-level security for all of them)",
    ),
    (
        "alter system",
        None,
        "rewrites the configuration file of the whole cluster",
    ),
    (
        "alter database",
        None,
        "changes a setting of the database that every concurrent session of every other binary is connected to",
    ),
    (
        "lock table",
        Some("access exclusive"),
        "ACCESS EXCLUSIVE blocks every reader and writer of the table, so ungrouped binaries queue behind it or fail on their lock_timeout (55P03)",
    ),
];

/// Test binaries that carry shared-catalog DDL outside a `lane(a:disposable)` test, `(nextest binary id, why)`. The
/// reason names the mechanism that keeps the DDL off the shared database, or says plainly that it is an open hazard. A
/// row whose binary is gone, or no longer carries a hit outside a `lane(a:disposable)` test, is red (stale), so the list
/// cannot outlive its reasons. A row exempts the whole binary: a new DDL statement in it is not seen until the row goes.
const SHARED_CATALOG_DDL_EXEMPT: &[(&str, &str)] = &[
    (
        "humaux-gateway::cross_tenant_canary",
        "its ALTER ROLE role_gateway BYPASSRLS / NOBYPASSRLS sits in RlsOutOfThePath::lift and Drop, which exactly one test builds: foreign_ids_are_not_found_with_row_level_security_out_of_the_path, lane(a:disposable); lift refuses unless HUMAUX_TEST_DISPOSABLE_CLUSTER=1 (set on the CI serial-lane step only) and the database is humaux_thread_*",
    ),
    (
        "humaux-gateway::mcp_gateway",
        "OPEN HAZARD, not a safety claim: the five native_mcp_*_final_metric_* tests call assert_local_read_final_metric_after_settlement, whose barrier holds LOCK TABLE private.memory_records IN ACCESS EXCLUSIVE MODE on the shared database against ungrouped readers; they belong in lane(a:disposable) and mcp_gateway.rs was outside the files of the card that added this gate (#145); follow-up humaux/humaux-thread#149. Drop the row when they move",
    ),
    (
        "humaux-maintenance::backup",
        "ALTER ROLE role_maintenance PASSWORD runs on the test's own scratch container cluster (Source::start, connected through source.owner_dsn on that cluster's port), never on the shared one",
    ),
    (
        "humaux-maintenance::drill",
        "ALTER ROLE and ALTER SYSTEM run on the test's own scratch container cluster (Source::prepare, connected through source.owner_dsn on that cluster's port), never on the shared one",
    ),
    (
        "humaux-maintenance::roles_hygiene",
        "ALTER ROLE .. LOGIN targets the role the fixture generated for itself (Fixture::role: hx33_<pid>_<token>_own), which no other binary logs in as",
    ),
];

/// One nextest test binary: its id as `binary_id(..)` names it, and the code it is built from as `(display path,
/// text with comments blanked)`. A library's or binary's own unit-test binary has no sources: its code is the
/// crate's production code, which holds the markers by design.
struct NextestBinary {
    id: String,
    sources: Vec<(String, String)>,
}

/// What `profile.ci.overrides` of the nextest config says about test groups.
struct GroupMembership {
    /// Binary id -> the test group of the first override that selects it (nextest takes the first matching override
    /// per setting, so a binary named by an earlier group is not in a later one).
    group_of: BTreeMap<String, String>,
    /// The ids named by the `global-db` overrides' filters, in file order.
    global_db_ids: Vec<String>,
}

/// The names a filterset selects, for the one shape this gate reads: `binary_id(<name>)` terms joined by `|`. `name`
/// is a literal (nextest's default matcher for `binary_id` is a glob, and a name without glob characters is exact).
/// `Err` carries the first term of any other shape, so a filter this parser cannot read is red, never silently
/// treated as empty.
fn filter_binary_ids(filter: &str) -> Result<Vec<String>, String> {
    filter
        .split('|')
        .map(|term| {
            let term = term.trim();
            term.strip_prefix("binary_id(")
                .and_then(|rest| rest.strip_suffix(')'))
                .filter(|name| {
                    !name.is_empty()
                        && name.bytes().all(|b| {
                            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'/')
                        })
                })
                .map(str::to_owned)
                .ok_or_else(|| term.to_owned())
        })
        .collect()
}

/// The group membership in `config`. `Ok(None)` when no override puts anything in [`GLOBAL_DB_GROUP`]; `Err` is the
/// `Fail` detail for a config that is not TOML or has a filter this gate cannot read.
fn read_groups(config: &str) -> Result<Option<GroupMembership>, String> {
    let doc: toml::Value = toml::from_str(config)
        .map_err(|e| format!("{NEXTEST_CONFIG_FILE} is not valid TOML: {e}"))?;
    let overrides = doc
        .get("profile")
        .and_then(|p| p.get("ci"))
        .and_then(|c| c.get("overrides"))
        .and_then(toml::Value::as_array);
    let mut groups = GroupMembership {
        group_of: BTreeMap::new(),
        global_db_ids: Vec::new(),
    };
    let mut has_global_db = false;
    for entry in overrides.into_iter().flatten() {
        let Some(group) = entry.get("test-group") else {
            continue;
        };
        let extra: Vec<&str> = entry
            .as_table()
            .into_iter()
            .flat_map(|table| table.keys().map(String::as_str))
            .filter(|key| !matches!(*key, "test-group" | "filter"))
            .collect();
        if !extra.is_empty() {
            return Err(format!(
                "{NEXTEST_CONFIG_FILE}: an override with `test-group` also sets {extra:?}; this gate reads only `filter` and \
                 `test-group`, so a `platform` or any other key would move binaries in or out of the group unseen \
                 (give that setting an override of its own)"
            ));
        }
        let (Some(group), Some(filter)) = (
            group.as_str(),
            entry.get("filter").and_then(toml::Value::as_str),
        ) else {
            return Err(format!(
                "{NEXTEST_CONFIG_FILE}: an override with `test-group` needs a string `test-group` and a string `filter`; one \
                 without a filter applies to every test, which this gate does not read"
            ));
        };
        let ids = filter_binary_ids(filter).map_err(|term| {
            format!(
                "{NEXTEST_CONFIG_FILE}: the `{group}` override has a filter term this gate does not read: `{term}` \
                 (only `binary_id(<literal name>)` terms joined by `|`; teach filter_binary_ids the new form before using it)"
            )
        })?;
        has_global_db |= group == GLOBAL_DB_GROUP;
        for id in ids {
            if group == GLOBAL_DB_GROUP {
                groups.global_db_ids.push(id.clone());
            }
            groups
                .group_of
                .entry(id)
                .or_insert_with(|| group.to_owned());
        }
    }
    Ok(has_global_db.then_some(groups))
}

/// The value of a `path = ".."` attribute body (what sits between `#[` and `]`).
fn path_attribute_value(attr: &str) -> Option<&str> {
    let value = attr
        .trim()
        .strip_prefix("path")?
        .trim_start()
        .strip_prefix('=')?
        .trim_start()
        .strip_prefix('"')?;
    value.split_once('"').map(|(path, _)| path)
}

/// The module name of a `mod name;` item (any visibility), `None` for every other line, inline `mod name { .. }` included.
fn module_declaration(item: &str) -> Option<&str> {
    let mut rest = item.trim_start();
    if let Some(after_pub) = rest.strip_prefix("pub") {
        rest = after_pub.trim_start();
        if rest.starts_with('(') {
            rest = rest[rest.find(')')? + 1..].trim_start();
        }
    }
    let name = rest.strip_prefix("mod ")?.trim().strip_suffix(';')?.trim();
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .then_some(name)
}

/// A file a test binary pulls in, with whether it owns its directory (a crate root, a `mod.rs`, a `#[path]`-loaded or
/// `include!`-loaded file: its nested `mod x;` sit beside it) or not (a plain `mod x;` loaded from `x.rs`: they sit
/// under `<stem>/`).
type LoadedFiles = Vec<(PathBuf, bool)>;

/// What `code` (the comment-blanked text of `file`) pulls in, as `(files that exist, declarations that resolve to no
/// file)`: `mod x;`, `#[path = ".."] mod x;` and `include!("..")`. A `#[path]` and an `include!` path are relative to the
/// directory of the file that holds them. A plain `mod x;` is looked up by the kind of `file`, the way rustc does:
/// beside a file that owns its directory (`owns_dir`) it is `x.rs`, then `x/mod.rs`; beside any other file it is
/// `<stem>/x.rs`, then `<stem>/x/mod.rs` and nothing else, so an unrelated sibling `x.rs` is never read for it. A
/// declaration that finds nothing, and an `include!` whose argument is not a string literal, come back unresolved: the
/// binary's sources are then unreadable and a marker in them would go unseen.
fn declared_module_files(file: &Path, owns_dir: bool, code: &str) -> (LoadedFiles, Vec<String>) {
    let dir = file.parent().unwrap_or_else(|| Path::new("."));
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let nested = if owns_dir {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    let mut found = Vec::new();
    let mut unresolved = Vec::new();
    let mut path_attr: Option<String> = None;
    for line in code.lines() {
        if let Some((_, arg)) = line.split_once("include!(") {
            let arg = arg.trim_start();
            match arg.strip_prefix('"').and_then(|a| a.split_once('"')) {
                Some((path, _)) if dir.join(path).is_file() => found.push((dir.join(path), true)),
                _ => unresolved.push(format!(
                    "include!({})",
                    arg.split(')').next().unwrap_or("").trim()
                )),
            }
        }
        let mut rest = line.trim();
        // Attributes first: a `#[path]` may share its line with the `mod x;` or sit above other attributes.
        while let Some(attr) = rest.strip_prefix("#[") {
            let Some(end) = attr.find(']') else { break };
            if let Some(value) = path_attribute_value(&attr[..end]) {
                path_attr = Some(value.to_owned());
            }
            rest = attr[end + 1..].trim_start();
        }
        if rest.is_empty() {
            continue;
        }
        let Some(name) = module_declaration(rest) else {
            path_attr = None;
            continue;
        };
        let loaded_by_path = path_attr.is_some();
        let candidates = match path_attr.take() {
            Some(path) => vec![dir.join(path)],
            None => vec![
                nested.join(format!("{name}.rs")),
                nested.join(name).join("mod.rs"),
            ],
        };
        match candidates.into_iter().find(|c| c.is_file()) {
            Some(module) => {
                let owns = loaded_by_path || module.file_name().is_some_and(|n| n == "mod.rs");
                found.push((module, owns));
            }
            None => unresolved.push(format!("mod {name};")),
        }
    }
    (found, unresolved)
}

/// `(path, text with comments blanked)` of each source file of a test binary.
type CodeFiles = Vec<(PathBuf, String)>;

/// `(declaring file, declaration)` of each `mod x;` / `include!` that resolves to no file.
type Unresolved = Vec<(PathBuf, String)>;

/// `entry` plus every file it pulls in, followed transitively (a `#[path]` module may declare modules of its own),
/// as `(path, text with comments blanked)`, entry first; a file reached twice is read once. The second list holds
/// the declarations that resolve to no file, as `(declaring file, declaration)` ([`declared_module_files`]).
fn test_binary_sources(entry: &Path) -> (CodeFiles, Unresolved) {
    let canonical = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let mut files = vec![(entry.to_path_buf(), true)];
    let mut seen = BTreeSet::from([canonical(entry)]);
    let mut out = Vec::new();
    let mut unresolved = Vec::new();
    let mut next = 0;
    while next < files.len() {
        let (path, owns_dir) = files[next].clone();
        next += 1;
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let code = code_without_comments(&text);
        let (modules, missing) = declared_module_files(&path, owns_dir, &code);
        unresolved.extend(missing.into_iter().map(|decl| (path.clone(), decl)));
        for (module, owns) in modules {
            if seen.insert(canonical(module.as_path())) {
                files.push((module, owns));
            }
        }
        out.push((path, code));
    }
    (out, unresolved)
}

/// The entries of `dir`, sorted; empty when it cannot be read.
fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    entries
}

/// The member package directories of the workspace at `root`: each `members` entry of its `Cargo.toml` is `dir/*`
/// (every subdirectory with a manifest) or a literal path.
fn workspace_member_dirs(root: &Path) -> Result<Vec<PathBuf>, String> {
    let text = fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("Cargo.toml unreadable: {e}"))?;
    let manifest: toml::Value =
        toml::from_str(&text).map_err(|e| format!("Cargo.toml is not valid TOML: {e}"))?;
    let members = manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "Cargo.toml has no [workspace] members".to_owned())?;
    let mut dirs = Vec::new();
    for member in members.iter().filter_map(toml::Value::as_str) {
        if let Some(parent) = member.strip_suffix("/*") {
            dirs.extend(
                sorted_entries(&root.join(parent))
                    .into_iter()
                    .filter(|p| p.join("Cargo.toml").is_file()),
            );
        } else if root.join(member).join("Cargo.toml").is_file() {
            dirs.push(root.join(member));
        }
    }
    Ok(dirs)
}

/// Every test binary of the workspace at `root`, named the way nextest names it: `<package>` for a library's unit
/// tests, `<package>::bin/<name>` for a binary's, `<package>::<file stem>` for each top-level `tests/*.rs` (or
/// `tests/<dir>/main.rs`, named after the directory). Only the integration binaries carry sources.
/// `Err` is the `Fail` detail; a member that declares its own targets is one, because cargo then names them freely
/// and this enumeration would silently disagree with nextest.
fn nextest_binaries(root: &Path) -> Result<Vec<NextestBinary>, String> {
    let mut out = Vec::new();
    for dir in workspace_member_dirs(root)? {
        let manifest_file = display(root, &dir.join("Cargo.toml"));
        let text = fs::read_to_string(dir.join("Cargo.toml"))
            .map_err(|e| format!("{manifest_file} unreadable: {e}"))?;
        let manifest: toml::Value =
            toml::from_str(&text).map_err(|e| format!("{manifest_file} is not valid TOML: {e}"))?;
        let package = manifest
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{manifest_file} has no [package] name"))?;
        let opted_out = |key: &str| {
            manifest
                .get("package")
                .and_then(|p| p.get(key))
                .and_then(toml::Value::as_bool)
                == Some(false)
        };
        if manifest.get("test").is_some()
            || manifest.get("bin").is_some()
            || opted_out("autotests")
            || opted_out("autobins")
        {
            return Err(format!(
                "{manifest_file} declares [[test]], [[bin]], autotests = false or autobins = false; \
                 nextest_binaries names only auto-discovered targets, extend it before a member declares its own"
            ));
        }
        let unit = |id: String| NextestBinary {
            id,
            sources: Vec::new(),
        };
        if dir.join("src/lib.rs").is_file() {
            out.push(unit(package.to_owned()));
        }
        if dir.join("src/main.rs").is_file() {
            out.push(unit(format!("{package}::bin/{package}")));
        }
        for path in sorted_entries(&dir.join("src/bin")) {
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if (path.is_file() && path.extension().is_some_and(|e| e == "rs"))
                || path.join("main.rs").is_file()
            {
                out.push(unit(format!("{package}::bin/{name}")));
            }
        }
        for path in sorted_entries(&dir.join("tests")) {
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let entry = if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
                path.clone()
            } else if path.join("main.rs").is_file() {
                path.join("main.rs")
            } else {
                continue;
            };
            let (sources, unresolved) = test_binary_sources(&entry);
            if !unresolved.is_empty() {
                let list = unresolved
                    .iter()
                    .map(|(file, decl)| format!("`{decl}` in {}", display(root, file)))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "M24-7: {package}::{name} pulls in {list}, which resolve to no file (tried x.rs then x/mod.rs beside a \
                     crate root, a mod.rs or a `#[path]`-loaded file, <stem>/x.rs then <stem>/x/mod.rs beside any other file, the \
                     `#[path]` itself, a string-literal `include!`): its sources cannot be read, so a marker or DDL statement in \
                     them would go unseen. Fix the declaration, or teach declared_module_files the form"
                ));
            }
            out.push(NextestBinary {
                id: format!("{package}::{name}"),
                sources: sources
                    .into_iter()
                    .map(|(file, code)| (display(root, &file), code))
                    .collect(),
            });
        }
    }
    Ok(out)
}

/// The markers `binary` carries as `(marker, why, first file that holds it)`, in [`GLOBAL_DB_MARKERS`] order.
fn carried_markers(binary: &NextestBinary) -> Vec<(&'static str, &'static str, &str)> {
    GLOBAL_DB_MARKERS
        .iter()
        .filter_map(|&(marker, why)| {
            binary
                .sources
                .iter()
                .find(|(_, code)| code.contains(marker))
                .map(|(file, _)| (marker, why, file.as_str()))
        })
        .collect()
}

/// The word tokens of `code` as `(token, 1-based line)`: lowercase runs of ASCII letters, digits and `_`, plus `;` and
/// `"` as tokens of their own (where [`ddl_hit_lines`] ends a statement).
fn ddl_tokens(code: &str) -> Vec<(String, usize)> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut line = 1;
    for c in code.chars().chain(std::iter::once('\n')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            word.push(c.to_ascii_lowercase());
            continue;
        }
        if !word.is_empty() {
            tokens.push((std::mem::take(&mut word), line));
        }
        match c {
            '\n' => line += 1,
            ';' | '"' => tokens.push((c.to_string(), line)),
            _ => {}
        }
    }
    tokens
}

/// The lines where the phrase `head` starts in `tokens`, when `tail` (if any) follows in the same statement.
fn ddl_hit_lines(tokens: &[(String, usize)], head: &str, tail: Option<&str>) -> Vec<usize> {
    let phrase_at = |at: usize, phrase: &str| {
        phrase
            .split(' ')
            .enumerate()
            .all(|(k, word)| tokens.get(at + k).is_some_and(|t| t.0 == word))
    };
    let head_len = head.split(' ').count();
    (0..tokens.len())
        .filter(|&at| phrase_at(at, head))
        .filter(|&at| {
            tail.is_none_or(|tail| {
                (at + head_len..tokens.len())
                    .take_while(|&i| tokens[i].0 != ";" && tokens[i].0 != "\"")
                    .any(|i| phrase_at(i, tail))
            })
        })
        .map(|at| tokens[at].1)
        .collect()
}

/// The 1-based `(first, last)` line spans of the tests in `code` whose `#[ignore]` sits on one of `ignore_lines`: from
/// that line to the `}` that closes the fn body it belongs to. Found on the code with strings and chars blanked, so a
/// brace inside a SQL string never unbalances the match.
fn disposable_spans(code: &str, ignore_lines: &[usize]) -> Vec<(usize, usize)> {
    let masked = mask_comments_and_literals(code);
    ignore_lines
        .iter()
        .filter_map(|&line| {
            let from: usize = masked
                .split_inclusive('\n')
                .take(line.saturating_sub(1))
                .map(str::len)
                .sum();
            let open = from + masked[from..].find('{')?;
            let close = matching_brace_end(&masked, open)?;
            Some((line, masked[..close].matches('\n').count() + 1))
        })
        .collect()
}

/// The shared-catalog DDL `binary` carries outside every `lane(a:disposable)` test, as `(file, line, phrase, why)` in
/// source order. `disposable` is `(display path, line)` of each `#[ignore = "lane(a:disposable) .."]` in the tree.
fn bare_catalog_ddl(
    binary: &NextestBinary,
    disposable: &[(String, usize)],
) -> Vec<(String, usize, String, &'static str)> {
    let mut out = Vec::new();
    for (file, code) in &binary.sources {
        let ignores: Vec<usize> = disposable
            .iter()
            .filter(|(f, _)| f == file)
            .map(|&(_, line)| line)
            .collect();
        let spans = disposable_spans(code, &ignores);
        let tokens = ddl_tokens(code);
        let mut hits: Vec<(usize, String, &'static str)> = SHARED_CATALOG_DDL
            .iter()
            .flat_map(|&(head, tail, why)| {
                let phrase = tail.map_or_else(|| head.to_owned(), |t| format!("{head} … {t}"));
                ddl_hit_lines(&tokens, head, tail)
                    .into_iter()
                    .map(move |line| (line, phrase.clone(), why))
            })
            .filter(|(line, _, _)| {
                !spans
                    .iter()
                    .any(|&(first, last)| (first..=last).contains(line))
            })
            .collect();
        hits.sort();
        hits.dedup();
        out.extend(
            hits.into_iter()
                .map(|(line, phrase, why)| (file.clone(), line, phrase, why)),
        );
    }
    out
}

/// M24-7b over the test binaries: one line for each binary that carries shared-catalog DDL outside a `lane(a:disposable)`
/// test and is not an `exempt` row, and one for each stale `exempt` row (binary gone, or no hit left outside a
/// `lane(a:disposable)` test).
fn shared_ddl_problems(
    binaries: &[NextestBinary],
    disposable: &[(String, usize)],
    exempt: &[(&str, &str)],
) -> Vec<String> {
    let mut problems = Vec::new();
    for binary in binaries {
        let bare = bare_catalog_ddl(binary, disposable);
        let Some((_, _, _, why)) = bare.first() else {
            continue;
        };
        if exempt.iter().any(|&(id, _)| binary.id == id) {
            continue;
        }
        let id = &binary.id;
        let carried = bare
            .iter()
            .map(|(file, line, phrase, _)| format!("`{phrase}` ({file}:{line})"))
            .collect::<Vec<_>>()
            .join(", ");
        problems.push(format!(
            "M24-7b: {id} runs {carried} outside a test whose `#[ignore]` reason is `lane(a:disposable)`: {why}. Mark the test \
             that runs it `#[ignore = \"lane(a:disposable) ..\"]` (docs/ops/serial-lane.md) and keep the DDL text inside that \
             test, or list {id} in SHARED_CATALOG_DDL_EXEMPT with the reason it is safe on the shared database"
        ));
    }
    for &(id, _) in exempt {
        let stale = match binaries.iter().find(|b| b.id == id) {
            None => Some("names no test binary of the workspace"),
            Some(b) if bare_catalog_ddl(b, disposable).is_empty() => {
                Some("carries no shared-catalog DDL outside a lane(a:disposable) test any more")
            }
            Some(_) => None,
        };
        if let Some(reason) = stale {
            problems.push(format!(
                "M24-7b: SHARED_CATALOG_DDL_EXEMPT lists {id}, which {reason} (stale exemption); drop the row"
            ));
        }
    }
    problems
}

/// M24-7 over a nextest config text and the workspace's test binaries.
/// * fail: a binary that carries a marker and is not in the `global-db` group (and not in `exempt`); a
///   `binary_id(..)` in a `global-db` filter that names no binary (stale); an `exempt` row whose binary is gone, carries
///   no marker or is now in the group (stale); a config or filter this gate cannot read;
/// * not_applicable, naming the missing object: the config has no `global-db` override and no binary carries a marker
///   (with a marker somewhere, the missing override is a fail);
/// * pass otherwise.
fn global_db_verdict(config: &str, binaries: &[NextestBinary], exempt: &[(&str, &str)]) -> Verdict {
    let groups = match read_groups(config) {
        Ok(Some(groups)) => groups,
        Ok(None) => {
            let carriers: Vec<&str> = binaries
                .iter()
                .filter(|b| !carried_markers(b).is_empty())
                .map(|b| b.id.as_str())
                .collect();
            return match carriers.first() {
                None => Verdict::NotApplicable(format!(
                    "missing object: a [[profile.ci.overrides]] entry with test-group = \"{GLOBAL_DB_GROUP}\" in {NEXTEST_CONFIG_FILE}"
                )),
                Some(first) => Verdict::Fail(vec![format!(
                    "M24-7: {NEXTEST_CONFIG_FILE} has no [[profile.ci.overrides]] entry with test-group = \"{GLOBAL_DB_GROUP}\" while {} \
                     test binaries carry a cluster-global marker (first: {first}); restore the override, its absence is not \
                     \"nothing to check\"",
                    carriers.len()
                )]),
            };
        }
        Err(detail) => return Verdict::Fail(vec![detail]),
    };
    let in_group = |id: &str| groups.group_of.get(id).map(String::as_str) == Some(GLOBAL_DB_GROUP);
    let mut problems = Vec::new();
    for id in &groups.global_db_ids {
        if !binaries.iter().any(|b| b.id == *id) {
            problems.push(format!(
                "M24-7: binary_id({id}) in the `{GLOBAL_DB_GROUP}` filter of {NEXTEST_CONFIG_FILE} names no test binary of the workspace (stale: renamed or deleted); remove it"
            ));
        }
    }
    for binary in binaries {
        let markers = carried_markers(binary);
        let Some(&(_, why, _)) = markers.first() else {
            continue;
        };
        if in_group(binary.id.as_str()) || exempt.iter().any(|&(id, _)| binary.id == id) {
            continue;
        }
        let id = &binary.id;
        let placed = match groups.group_of.get(id) {
            Some(other) => {
                format!("in the `{other}` group, which takes it before `{GLOBAL_DB_GROUP}`")
            }
            None => "in no test group".to_owned(),
        };
        let carried = markers
            .iter()
            .map(|(marker, _, file)| format!("`{marker}` ({file})"))
            .collect::<Vec<_>>()
            .join(", ");
        problems.push(format!(
            "M24-7: {id} is {placed} but carries {carried}: {why}. Add binary_id({id}) to the `{GLOBAL_DB_GROUP}` \
             filter in {NEXTEST_CONFIG_FILE}, or list it in GLOBAL_DB_EXEMPT with the reason it is safe outside the group"
        ));
    }
    for &(id, _) in exempt {
        let stale = match binaries.iter().find(|b| b.id == id) {
            None => Some("names no test binary of the workspace"),
            Some(b) if carried_markers(b).is_empty() => Some("carries no marker any more"),
            Some(_) if in_group(id) => Some("is in the `global-db` group now"),
            Some(_) => None,
        };
        if let Some(reason) = stale {
            problems.push(format!(
                "M24-7: GLOBAL_DB_EXEMPT lists {id}, which {reason} (stale exemption); drop the row"
            ));
        }
    }
    if problems.is_empty() {
        Verdict::Pass
    } else {
        Verdict::Fail(problems)
    }
}

/// M24-7 / G-M24-7 over the real workspace.
fn m24_7_global_db_completeness(root: &Path) -> Verdict {
    m24_7_over_tree(root, GLOBAL_DB_EXEMPT, SHARED_CATALOG_DDL_EXEMPT)
}

/// M24-7 (`global-db` completeness) and M24-7b (shared-catalog DDL, [`SHARED_CATALOG_DDL`]) over the workspace at `root`
/// with the given exemption rows. `not_applicable` only when `.config/nextest.toml` is absent or has no `global-db`
/// override and no binary carries a marker, and it names that object (§57.1 第2条); any M24-7b problem is a `Fail`
/// whatever the first part says.
fn m24_7_over_tree(root: &Path, exempt: &[(&str, &str)], ddl_exempt: &[(&str, &str)]) -> Verdict {
    let (config, missing) = match fs::read_to_string(root.join(NEXTEST_CONFIG_FILE)) {
        Ok(config) => (config, false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), true),
        Err(e) => {
            return Verdict::Fail(vec![format!("{NEXTEST_CONFIG_FILE} unreadable: {e}")]);
        }
    };
    let binaries = match nextest_binaries(root) {
        Ok(binaries) => binaries,
        Err(_) if missing => {
            return Verdict::NotApplicable(format!("missing object: {NEXTEST_CONFIG_FILE}"));
        }
        Err(detail) => return Verdict::Fail(vec![detail]),
    };
    let ddl = shared_ddl_problems(
        &binaries,
        &crate::serial_lane::disposable_ignores(root),
        ddl_exempt,
    );
    match global_db_verdict(&config, &binaries, exempt) {
        Verdict::Fail(mut problems) => {
            problems.extend(ddl);
            Verdict::Fail(problems)
        }
        Verdict::NotApplicable(object) if ddl.is_empty() => Verdict::NotApplicable(object),
        _ if ddl.is_empty() => Verdict::Pass,
        _ => Verdict::Fail(ddl),
    }
}

// ============================================================================
// T-LANG-1: no-python-in-system — the system is Rust; CI and test tooling may use Python
// ============================================================================

/// Owner rule (2026-10-22): the system itself — product code and the production runtime — is Rust, while Python may
/// be used where it helps testing or CI. A path under one of these prefixes is tooling, never the system, so Python
/// there is allowed: the CI workflows, helper scripts, the clean-node rehearsal's tooling (ADR-0066 §5), experiment
/// territory and xtask's own tests. A rehearsal- or test-profile compose service is allowed by profile instead
/// ([`NO_PYTHON_TOOLING_PROFILES`]). This is the whole allowlist (fail closed): anything else that is scanned and
/// Python is red. §57.1 第2条 three-state, §80.1 (the gate exists only with its injected-fault record).
const NO_PYTHON_ALLOWED_PREFIXES: [&str; 5] = [
    ".github/workflows/",
    "scripts/",
    "deploy/rehearsal/",
    "experiments/",
    "xtask/tests/",
];

/// Directories whose `*.py` files are product code or product data. Scanned by extension with [`walk_files`], which
/// skips target/.git/node_modules; on a clean CI checkout that is exactly the tracked set. The repo-root
/// `experiments/` and `scripts/` are not listed because they are allowed; `crates/`, `bins/`, `migrations/` and
/// `config/` are the system.
const NO_PYTHON_SOURCE_ROOTS: [&str; 4] = ["crates", "bins", "migrations", "config"];

/// Where Compose documents are discovered: every `.yml` / `.yaml` under `deploy/compose/`, plus a Compose-named file
/// (`compose*.{yml,yaml}` or `docker-compose*.{yml,yaml}`) anywhere else under `deploy/`. That is the old scanner's
/// `deploy/**` scope restricted to documents Compose itself can render; Prometheus / Qdrant YAML is not a Compose
/// document and is not fed to the CLI. ci.yml's lint job renders exactly this set ([`is_compose_file`]), so anchors,
/// `<<` merges, `extends`, flow style and quoted keys are resolved by Compose and never by a hand-written YAML subset
/// (xtask takes no new dependency).
const NO_PYTHON_COMPOSE_ROOT: &str = "deploy";

/// The directory whose every `.yml` / `.yaml` is a Compose document (the node's deploy bundle).
const NO_PYTHON_COMPOSE_DIR: &str = "deploy/compose";

/// The env var ci.yml sets to the directory it renders each Compose document into, at `<repo-relative path>.json`. One
/// name for producer and consumer, so the render step and this gate cannot drift; unset (a local run) it falls back to
/// [`NO_PYTHON_COMPOSE_JSON_DIR`]. A relative value resolves against the workspace root, exactly as the shell step that
/// writes it.
const NO_PYTHON_COMPOSE_JSON_ENV: &str = "HUMAUX_NO_PYTHON_COMPOSE_JSON";

/// The fallback render directory (`target/no-python-compose/deploy/compose/prod.yml.json`), under `target/`.
const NO_PYTHON_COMPOSE_JSON_DIR: &str = "target/no-python-compose";

/// Roots whose files are scanned for a Python shebang regardless of extension. Dockerfiles are scanned from the repo
/// root instead: a product image build anywhere in this tree is the system.
const NO_PYTHON_SHEBANG_ROOTS: [&str; 3] = ["crates", "bins", "deploy"];

/// The compose profiles that mark a service as test / rehearsal tooling. A Python-image service must list profiles and
/// every one of them must be here; a service with no `profiles:` key of its own (including one that would inherit it
/// through a YAML merge) is not limited and is red.
const NO_PYTHON_TOOLING_PROFILES: [&str; 2] = ["rehearsal", "test"];

/// Whether `path` (repo-relative, `/`-separated) is in the allowed tooling territory.
fn no_python_allowed(path: &str) -> bool {
    NO_PYTHON_ALLOWED_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// `Dockerfile`, `Dockerfile.<suffix>`, `Dockerfile-<suffix>`, `<name>.Dockerfile`, `<name>.dockerfile`, Buildah's
/// `Containerfile` or `Containerfile.<suffix>`. A `.md` suffix is documentation, not a build file, so it is not scanned.
fn is_dockerfile_name(name: &str) -> bool {
    !name.ends_with(".md")
        && (name == "Dockerfile"
            || name.starts_with("Dockerfile.")
            || name.starts_with("Dockerfile-")
            || name.ends_with(".Dockerfile")
            || name.ends_with(".dockerfile")
            || name == "Containerfile"
            || name.starts_with("Containerfile."))
}

/// Whether a repo-relative `deploy/` path is a Compose document the gate judges and ci.yml renders. Every
/// `deploy/compose/*.{yml,yaml}` is one; elsewhere under `deploy/` only a Compose-named file is.
fn is_compose_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if !(name.ends_with(".yml") || name.ends_with(".yaml")) {
        return false;
    }
    path.strip_prefix(NO_PYTHON_COMPOSE_DIR)
        .is_some_and(|rest| rest.starts_with('/'))
        || name.starts_with("compose")
        || name.starts_with("docker-compose")
}

/// Every Compose document under [`NO_PYTHON_COMPOSE_ROOT`] (the [`walk_all_files`] set: no dot-directories, no
/// `target`), sorted.
fn walk_compose_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    walk_all_files(&root.join(NO_PYTHON_COMPOSE_ROOT), &mut files);
    let mut out: Vec<PathBuf> = files
        .into_iter()
        .filter(|path| is_compose_file(&display(root, path)))
        .collect();
    out.sort();
    out
}

/// Every regular file under `dir`, skipping `target`/`node_modules` and every dot-directory: `.git`, but also a local
/// `.worktrees/` checkout whose images are not this tree's product.
fn walk_all_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !name.starts_with('.') && !matches!(name, "target" | "node_modules") {
                walk_all_files(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

/// Every Dockerfile under `dir` (skipping the same paths as [`walk_all_files`]).
fn walk_dockerfiles(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut files = Vec::new();
    walk_all_files(dir, &mut files);
    out.extend(files.into_iter().filter(|path| {
        is_dockerfile_name(path.file_name().and_then(|n| n.to_str()).unwrap_or(""))
    }));
}

/// Whether a Dockerfile line (comment lines are skipped by the caller) names Python: the word `python` anywhere
/// (`python3`, `python:3.13-slim`, `python3-pip`) or the bare `pip` / `pip3` command.
fn mentions_python(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("python")
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|token| token == "pip" || token == "pip3")
}

/// The first whole Python command token of a rendered compose `command:` / `entrypoint:` word: `python`, `python2`,
/// `python3`, a versioned `python3.12` / `python312`, `pip` or `pip3`. `env python` matches on its `python` word and
/// `/usr/bin/python3` on its last path segment; `pythonic` matches neither.
fn python_command_token(value: &str) -> Option<String> {
    value
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .map(str::to_ascii_lowercase)
        .find(|token| {
            matches!(
                token.as_str(),
                "python" | "python2" | "python3" | "pip" | "pip3"
            ) || token.strip_prefix("python").is_some_and(|rest| {
                rest.chars().next().is_some_and(|c| c.is_ascii_digit())
                    && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
            })
        })
}

/// One service of a compose document rendered by Compose, with the fields T-LANG-1 judges.
#[derive(Debug, PartialEq, Eq)]
struct ComposeService {
    name: String,
    image: Option<String>,
    profiles: Vec<String>,
    command: Vec<String>,
    entrypoint: Vec<String>,
}

/// The words of a rendered `command:` / `entrypoint:` / `profiles:` field: absent or `null` is empty, a string is one
/// word (a block scalar Compose keeps as text), an array is its words. Any other shape is not judged.
fn compose_strings(value: Option<&serde_json::Value>) -> Result<Vec<String>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(serde_json::Value::String(text)) => Ok(vec![text.clone()]),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "an array item is not a string".to_owned())
            })
            .collect(),
        Some(_) => Err("expected a string or an array of strings".to_owned()),
    }
}

/// Every service of a compose document rendered by `docker compose config --format json` (ci.yml's lint job), sorted
/// by name. An unparseable document or service is an error, never an empty service list: a compose file this gate
/// cannot resolve cannot be shown Python-free.
fn compose_services(json: &str) -> Result<Vec<ComposeService>, String> {
    let doc: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let services = doc
        .get("services")
        .ok_or_else(|| "no `services` object".to_owned())?
        .as_object()
        .ok_or_else(|| "`services` is not an object".to_owned())?;
    let mut found = Vec::with_capacity(services.len());
    for (name, service) in services {
        let fields = service
            .as_object()
            .ok_or_else(|| format!("service `{name}` is not an object"))?;
        let image = match fields.get("image") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(image)) => Some(image.clone()),
            Some(_) => return Err(format!("service `{name}`: `image` is not a string")),
        };
        found.push(ComposeService {
            name: name.clone(),
            image,
            profiles: compose_strings(fields.get("profiles"))
                .map_err(|e| format!("service `{name}`: `profiles`: {e}"))?,
            command: compose_strings(fields.get("command"))
                .map_err(|e| format!("service `{name}`: `command`: {e}"))?,
            entrypoint: compose_strings(fields.get("entrypoint"))
                .map_err(|e| format!("service `{name}`: `entrypoint`: {e}"))?,
        });
    }
    found.sort_unstable_by_key(|service| service.name.clone());
    Ok(found)
}

impl ComposeService {
    /// Whether the service's own `profiles:` limits it to the test / rehearsal tooling (absent or empty = not limited).
    fn limited_to_tooling(&self) -> bool {
        !self.profiles.is_empty()
            && self
                .profiles
                .iter()
                .all(|profile| NO_PYTHON_TOOLING_PROFILES.contains(&profile.as_str()))
    }

    /// `(service, image)` when the service runs a Python image and is not limited to the tooling profiles.
    fn python_outside_tooling(&self) -> Option<(&str, &str)> {
        // ponytail: an image whose name does not contain `python` (for example `pytorch`) is not caught; upgrade by
        // mapping known base images to their runtime instead of matching the image name.
        let image = self.image.as_deref()?;
        (image.to_ascii_lowercase().contains("python") && !self.limited_to_tooling())
            .then_some((self.name.as_str(), image))
    }

    /// `(service, key, token)` for the first `command:` / `entrypoint:` token naming Python while not limited to the
    /// tooling profiles; `key` is `"command"` or `"entrypoint"`.
    fn python_commands_outside_tooling(&self) -> Option<(&str, &'static str, String)> {
        if self.limited_to_tooling() {
            return None;
        }
        self.command
            .iter()
            .map(|value| (value, "command"))
            .chain(self.entrypoint.iter().map(|value| (value, "entrypoint")))
            .find_map(|(value, key)| {
                python_command_token(value).map(|token| (self.name.as_str(), key, token))
            })
    }
}

/// The pure core of the gate, over repo-relative paths: Python source files, Dockerfiles, rendered compose documents
/// as `(path, json)` and shebang candidates as `(path, first line)`. Paths in the tooling territory
/// ([`NO_PYTHON_ALLOWED_PREFIXES`]) are skipped.
fn no_python_problems(
    py_files: &[String],
    dockerfiles: &[(String, String)],
    compose_files: &[(String, String)],
    shebang_files: &[(String, String)],
) -> Vec<String> {
    let mut problems = Vec::new();
    for path in py_files {
        if !no_python_allowed(path) {
            problems.push(format!(
                "{path}: a Python source file in the system tree; the system is Rust, Python is allowed only as CI / test tooling (T-LANG-1)"
            ));
        }
    }
    for (path, text) in dockerfiles {
        if no_python_allowed(path) {
            continue;
        }
        for (idx, line) in text.lines().enumerate() {
            if !line.trim_start().starts_with('#') && mentions_python(line) {
                problems.push(format!(
                    "{path}:{}: python in a product image build: {} (T-LANG-1)",
                    idx + 1,
                    line.trim()
                ));
            }
        }
    }
    for (path, first_line) in shebang_files {
        if !no_python_allowed(path)
            && first_line.starts_with("#!")
            && first_line.to_ascii_lowercase().contains("python")
        {
            problems.push(format!(
                "{path}:1: Python shebang in the system tree: {}; the system is Rust, Python is allowed only as CI / test tooling (T-LANG-1)",
                first_line.trim()
            ));
        }
    }
    let tooling = NO_PYTHON_TOOLING_PROFILES.join("/");
    for (path, json) in compose_files {
        if no_python_allowed(path) {
            continue;
        }
        let services = match compose_services(json) {
            Ok(services) => services,
            Err(e) => {
                problems.push(format!(
                    "{path}: the rendered compose config is unusable ({e}); a compose file this gate cannot resolve cannot be shown Python-free (T-LANG-1)"
                ));
                continue;
            }
        };
        for service in services {
            if let Some((service, image)) = service.python_outside_tooling() {
                problems.push(format!(
                    "{path}: compose service `{service}` runs the Python image `{image}` but its `profiles:` is not limited to {tooling}; the system is Rust (T-LANG-1)"
                ));
            } else if let Some((service, key, token)) = service.python_commands_outside_tooling() {
                problems.push(format!(
                    "{path}: compose service `{service}` runs the Python command `{token}` in its `{key}:` but its `profiles:` is not limited to {tooling}; the system is Rust (T-LANG-1)"
                ));
            }
        }
    }
    problems
}

/// Reads `paths` as `(repo-relative path, text)`. An unreadable file is a problem, never a silent skip: a file this
/// gate cannot read cannot be shown Python-free (fail closed).
fn read_for_no_python(
    root: &Path,
    paths: &[PathBuf],
    problems: &mut Vec<String>,
) -> Vec<(String, String)> {
    let mut read = Vec::new();
    for path in paths {
        let shown = display(root, path);
        match fs::read_to_string(path) {
            Ok(text) => read.push((shown, text)),
            Err(e) => problems.push(format!(
                "{shown}: unreadable ({e}); a file this gate cannot read cannot be shown Python-free"
            )),
        }
    }
    read
}

/// The first line of `path` (lossy: a non-UTF-8 first line cannot start with the ASCII `#!`).
fn read_first_line(path: &Path) -> std::io::Result<String> {
    let file = fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    reader.read_until(b'\n', &mut buf)?;
    let line = String::from_utf8_lossy(&buf);
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

/// Reads the first line of `paths` as `(repo-relative path, first line)`, skipping the allowed tooling territory. An
/// unreadable file is a problem, never a silent skip: a file this gate cannot read cannot be shown Python-free.
fn read_for_shebang(
    root: &Path,
    paths: &[PathBuf],
    problems: &mut Vec<String>,
) -> Vec<(String, String)> {
    let mut read = Vec::new();
    for path in paths {
        let shown = display(root, path);
        if no_python_allowed(&shown) {
            continue;
        }
        match read_first_line(path) {
            Ok(line) => read.push((shown, line)),
            Err(e) => problems.push(format!(
                "{shown}: unreadable ({e}); a file this gate cannot read cannot be shown Python-free"
            )),
        }
    }
    read
}

/// The render directory: [`NO_PYTHON_COMPOSE_JSON_ENV`] when the CI step set it (a relative value against the
/// workspace root, as the shell step resolves it), otherwise [`NO_PYTHON_COMPOSE_JSON_DIR`].
fn no_python_compose_json_dir(root: &Path) -> PathBuf {
    match std::env::var(NO_PYTHON_COMPOSE_JSON_ENV) {
        Ok(dir) if !dir.is_empty() => {
            let dir = PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                root.join(dir)
            }
        }
        _ => root.join(NO_PYTHON_COMPOSE_JSON_DIR),
    }
}

/// Whether a missing render is a failure instead of `not_applicable`: CI declares the dependency
/// (`GITHUB_ACTIONS=true`, or the `HUMAUX_REQUIRE_DOCKER=1` the lint job already sets), so a dropped render step or a
/// path drift cannot turn the gate green (§57.1 第2条, T-LANG-1).
fn no_python_render_required() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true")
        || std::env::var("HUMAUX_REQUIRE_DOCKER").is_ok_and(|value| value == "1")
}

/// T-LANG-1 / `no-python-in-system`: no `*.py` under `crates/` `bins/` `migrations/` `config/`; no `python` / `pip` in
/// any `Dockerfile`, `Dockerfile-*`, `*.Dockerfile`, `*.dockerfile` or `Containerfile` in the repo (dot-directories
/// such as a nested `.worktrees/` are not walked); a compose service in every Compose document under `deploy/`
/// (discovered by [`is_compose_file`], rendered into [`NO_PYTHON_COMPOSE_JSON_ENV`]) fails on a Python image, `command:`
/// or `entrypoint:` unless its own `profiles:` are rehearsal / test only; no Python shebang in `crates/`, `bins/` or
/// `deploy/`. A missing render is `not_applicable` naming the file outside CI and a failure inside it, and a rendered
/// file the scan does not know is a failure, so the render set and the scan set cannot drift. `not_applicable` when
/// none of the scanned directories exists (§57.1 第2条).
fn no_python_in_system(root: &Path) -> Verdict {
    no_python_in_system_with(root, no_python_render_required())
}

/// [`no_python_in_system`] with the render requirement injected, so a scratch-tree test does not depend on the
/// environment it runs in.
fn no_python_in_system_with(root: &Path, require_render: bool) -> Verdict {
    let dirs: Vec<&str> = NO_PYTHON_SOURCE_ROOTS
        .iter()
        .copied()
        .chain([NO_PYTHON_COMPOSE_ROOT])
        .collect();
    if !dirs.iter().any(|dir| root.join(dir).is_dir()) {
        return Verdict::NotApplicable(dirs.join(", "));
    }
    let py_files: Vec<String> = NO_PYTHON_SOURCE_ROOTS
        .iter()
        .flat_map(|dir| walk_files(&root.join(dir), &["py"]))
        .map(|path| display(root, &path))
        .collect();
    let mut docker_paths = Vec::new();
    walk_dockerfiles(root, &mut docker_paths);
    docker_paths.sort();
    let compose_paths = walk_compose_files(root);
    let json_dir = no_python_compose_json_dir(root);
    let mut shebang_paths = Vec::new();
    for dir in NO_PYTHON_SHEBANG_ROOTS {
        walk_all_files(&root.join(dir), &mut shebang_paths);
    }
    let mut problems = Vec::new();
    let mut compose_files = Vec::new();
    let mut unrendered = Vec::new();
    let mut scanned = Vec::new();
    for path in &compose_paths {
        let shown = display(root, path);
        let json = json_dir.join(format!("{shown}.json"));
        match fs::read_to_string(&json) {
            Ok(rendered) => compose_files.push((shown.clone(), rendered)),
            Err(_) if require_render => problems.push(format!(
                "{shown}: missing rendered compose config at {}; CI must render every scanned compose file (T-LANG-1)",
                display(root, &json)
            )),
            Err(_) => unrendered.push(shown.clone()),
        }
        scanned.push(shown);
    }
    for json in walk_files(&json_dir, &["json"]) {
        let Some(rendered) = display(&json_dir, &json)
            .strip_suffix(".json")
            .map(str::to_owned)
        else {
            continue;
        };
        if require_render && !scanned.iter().any(|compose| compose == &rendered) {
            problems.push(format!(
                "{}.json: rendered compose config for no scanned compose file ({rendered}); the render set and the scan set must be identical (T-LANG-1)",
                rendered
            ));
        }
    }
    let dockerfiles = read_for_no_python(root, &docker_paths, &mut problems);
    let shebang_files = read_for_shebang(root, &shebang_paths, &mut problems);
    problems.extend(no_python_problems(
        &py_files,
        &dockerfiles,
        &compose_files,
        &shebang_files,
    ));
    if !problems.is_empty() {
        Verdict::Fail(problems)
    } else if !unrendered.is_empty() {
        Verdict::NotApplicable(format!("compose config JSON for {}", unrendered.join(", ")))
    } else {
        Verdict::Pass
    }
}

/// ADR-0084 D-B: the release image's rerank / ONNX Runtime fetches. Since T-CI-4 (#190) their pins live in
/// [`RERANK_PARITY_ACTION`], which both ci.yml's required `rerank-parity` job and targeted.yml's dispatch call; the
/// image repeats them, and this gate is what refuses a drift between the two (otherwise parity could test an artifact
/// other than the one production ships).
const RERANK_DOCKERFILE: &str = "deploy/images/humaux/Dockerfile";
/// The composite action that carries the one source of the pins (ADR-0084 D-G, T-CI-4).
const RERANK_PARITY_ACTION: &str = ".github/actions/rerank-parity/action.yml";
/// The Dockerfile build stage that fetches the two artifacts; only its `ADD --checksum` lines are pins.
const RERANK_STAGE: &str = "rerank-fetch";

/// One `ADD --checksum=sha256:<sha256> <url> …` pin: the artifact URL and the digest the image refuses to deviate from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactPin {
    url: String,
    sha256: String,
}

/// The text of the `rerank-fetch` stage: its `FROM … AS rerank-fetch` line up to the next `FROM`. `None` when the
/// stage is gone — the caller reports the missing object, §57.1 第2条.
fn rerank_fetch_stage(dockerfile: &str) -> Option<String> {
    let mut stage = Vec::new();
    let mut inside = false;
    for line in dockerfile.lines() {
        let body = line.trim_start();
        if body.split_whitespace().next() == Some("FROM") {
            if inside {
                break;
            }
            inside = body.split_whitespace().last() == Some(RERANK_STAGE);
        } else if inside {
            stage.push(line);
        }
    }
    inside.then(|| stage.join("\n"))
}

/// Every `ADD --checksum=sha256:<sha256> <url>` pin in `text`, in file order (comment lines are not pins).
fn artifact_pins(text: &str) -> Vec<ArtifactPin> {
    text.lines()
        .filter_map(|line| {
            let body = line.trim_start();
            if body.starts_with('#') {
                return None;
            }
            let rest = body.strip_prefix("ADD ")?;
            let mut words = rest.split_whitespace();
            let sha256 = words.next()?.strip_prefix("--checksum=sha256:")?;
            let url = words.next()?;
            Some(ArtifactPin {
                url: url.to_owned(),
                sha256: sha256.to_ascii_lowercase(),
            })
        })
        .collect()
}

/// The input names an action declares, in order: the indent-2 `name:` lines under `inputs:`.
fn action_input_names(action: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_inputs = false;
    for line in action.lines() {
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let indent = line.len() - body.len();
        if indent == 0 {
            in_inputs = body == "inputs:";
        } else if in_inputs
            && indent == 2
            && let Some(name) = body.strip_suffix(':')
        {
            names.push(name.to_owned());
        }
    }
    names
}

/// A YAML scalar without its trailing ` # comment` and surrounding quotes.
fn yaml_scalar(raw: &str) -> &str {
    raw.split(" #")
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\''])
}

/// The `default:` value of input `name` in `action`, as a YAML scalar (the action's values are plain scalars).
fn action_input_default(action: &str, name: &str) -> Option<String> {
    let mut in_input = false;
    for line in action.lines() {
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        let indent = line.len() - body.len();
        if indent <= 2 {
            in_input = indent == 2 && body.strip_suffix(':') == Some(name);
        } else if in_input && let Some(value) = body.strip_prefix("default:") {
            return Some(yaml_scalar(value).to_owned());
        }
    }
    None
}

/// Readable pins keyed by sha input, plus the url inputs whose default or sha256 default is missing.
type ActionPins = (Vec<(String, ArtifactPin)>, Vec<String>);

/// Every readable pin `action` declares: each `inputs.<prefix>_url` default and its `<prefix>_sha256` default,
/// keyed by the sha input (`ort_sha256` / `rerank_sha256`). The second element names a url input whose default or
/// sha256 default is missing: with at least one readable pin those are `fail` lines, not `not_applicable`
/// (§57.1 第2条). `Err` only when the action has no `_url` input at all.
fn action_pins(action: &str) -> Result<ActionPins, String> {
    let url_inputs: Vec<String> = action_input_names(action)
        .into_iter()
        .filter(|name| name.ends_with("_url"))
        .collect();
    if url_inputs.is_empty() {
        return Err(format!("{RERANK_PARITY_ACTION}: inputs.*_url"));
    }
    let mut pins = Vec::new();
    let mut unreadable = Vec::new();
    for url_input in url_inputs {
        let Some(url) = action_input_default(action, &url_input) else {
            unreadable.push(format!(
                "{RERANK_PARITY_ACTION}: inputs.{url_input}.default"
            ));
            continue;
        };
        let prefix = url_input
            .strip_suffix("_url")
            .expect("filtered by ends_with(\"_url\")");
        let sha_input = format!("{prefix}_sha256");
        let Some(sha256) = action_input_default(action, &sha_input) else {
            unreadable.push(format!(
                "{RERANK_PARITY_ACTION}: inputs.{sha_input}.default"
            ));
            continue;
        };
        pins.push((
            sha_input,
            ArtifactPin {
                url,
                sha256: sha256.to_ascii_lowercase(),
            },
        ));
    }
    Ok((pins, unreadable))
}

/// Pins equal (`Ok` empty), a URL or sha256 differs (`Ok` one reason per unmatched pin on either side, naming both
/// files and the action input), or ALL pins on one side are absent (`Err`, naming it). §57.1 第2条 reserves
/// `not_applicable` for an object that is absent, so two pins that both differ are a `fail`, not a missing object.
/// ADR-0084 D-B / T-CI-4: the image's `rerank-fetch` stage and `.github/actions/rerank-parity/action.yml` must fetch
/// the same bytes, so G-RET-11/G-RET-14 and the release image cannot drift apart.
fn rerank_pin_problems(dockerfile: &str, action: &str) -> Result<Vec<String>, String> {
    let Some(stage) = rerank_fetch_stage(dockerfile) else {
        return Err(format!(
            "{RERANK_DOCKERFILE}: `FROM … AS {RERANK_STAGE}` stage"
        ));
    };
    let image = artifact_pins(&stage);
    if image.is_empty() {
        return Err(format!(
            "{RERANK_DOCKERFILE}: `ADD --checksum=sha256:<sha256> <url>` pin in the {RERANK_STAGE} stage"
        ));
    }
    let (declared, unreadable) = action_pins(action)?;
    if declared.is_empty() {
        return Err(unreadable
            .into_iter()
            .next()
            .unwrap_or_else(|| format!("{RERANK_PARITY_ACTION}: inputs.*_url")));
    }
    let mut problems: Vec<String> = unreadable
        .into_iter()
        .map(|missing| {
            format!(
                "{RERANK_DOCKERFILE}: no `ADD --checksum` pin comparable with {missing} — the image and the parity test must fetch the same artifact"
            )
        })
        .collect();
    for (sha_key, pin) in &declared {
        let matching: Vec<&ArtifactPin> =
            image.iter().filter(|found| found.url == pin.url).collect();
        if matching.is_empty() {
            // Same bytes under another URL: the URL differs, the pin is not missing (§57.1 第2条).
            if let Some(found) = image.iter().find(|found| found.sha256 == pin.sha256) {
                problems.push(format!(
                    "{RERANK_DOCKERFILE}: `ADD --checksum` for {} is sha256:{}, but {RERANK_PARITY_ACTION} inputs.{sha_key} pins the same sha256 at {} — the image and the parity test must fetch the same artifact",
                    found.url, found.sha256, pin.url
                ));
                continue;
            }
            problems.push(format!(
                "{RERANK_DOCKERFILE}: no `ADD --checksum` pin for {} (action input {RERANK_PARITY_ACTION} inputs.{sha_key}) — the image and the parity test must fetch the same artifact",
                pin.url
            ));
            continue;
        }
        for found in matching {
            if found.sha256 != pin.sha256 {
                problems.push(format!(
                    "{RERANK_DOCKERFILE}: `ADD --checksum` for {} is sha256:{}, but {RERANK_PARITY_ACTION} inputs.{sha_key} is {} — the image and the parity test must fetch the same artifact",
                    pin.url, found.sha256, pin.sha256
                ));
            }
        }
    }
    for pin in &image {
        if declared.iter().any(|(_, found)| found.url == pin.url) {
            continue;
        }
        // The URL difference was reported above while the bytes are still pinned; a sha256 that appears in neither
        // file is an unmatched image pin, not an absent action input.
        if declared.iter().any(|(_, found)| found.sha256 == pin.sha256) {
            continue;
        }
        problems.push(format!(
            "{RERANK_DOCKERFILE}: `ADD --checksum` for {} has no {RERANK_PARITY_ACTION} `inputs.*_url` pin — the image and the parity test must fetch the same artifact",
            pin.url
        ));
    }
    Ok(problems)
}

/// `rerank-pin-parity` (ADR-0084 D-B, T-CI-4): the Dockerfile's rerank/ORT pins equal the parity action's inputs.
/// Three states (§57.1 第2条): a missing file, stage or pin is `not_applicable` and names it; a differing URL or
/// sha256 is `fail`, naming both files and the action input; equality passes.
fn rerank_pin_parity(root: &Path) -> Verdict {
    let Ok(dockerfile) = fs::read_to_string(root.join(RERANK_DOCKERFILE)) else {
        return Verdict::NotApplicable(RERANK_DOCKERFILE.to_owned());
    };
    let Ok(action) = fs::read_to_string(root.join(RERANK_PARITY_ACTION)) else {
        return Verdict::NotApplicable(RERANK_PARITY_ACTION.to_owned());
    };
    match rerank_pin_problems(&dockerfile, &action) {
        Ok(problems) if problems.is_empty() => Verdict::Pass,
        Ok(problems) => Verdict::Fail(problems),
        Err(missing) => Verdict::NotApplicable(missing),
    }
}

#[allow(clippy::too_many_lines)] // §57.1: one flat, closed registry of every gate in declaration order — splitting it would hide the list this file exists to make visible.
pub fn run(_args: &[String]) -> i32 {
    let root = workspace_root();
    let mut checks: Vec<(&str, Verdict)> = vec![
        (
            "§53.3 规则1 (Outcome<_> fallback outside abstain)",
            rule1_forbidden_fallback(&root),
        ),
        (
            "§53.3 规则2（前两项：DegradeCode ↔ fault test 文件名一一对应；标签基数由 \
             degrade.rs::fold_is_injective_over_all_variants 静态代理覆盖）",
            rule2_degrade_fault_parity(&root),
        ),
        (
            "§53.3 规则3 (sentinels positive control)",
            rule3_positive_sentinels(&root),
        ),
        (
            "§52.4 G52-1 (ErrorCode sole at error_code position)",
            g52_1_error_code_uniqueness(&root),
        ),
        (
            "§59.1 G59-3 (Authority::new sole construction point)",
            g59_3_authority_construction_point(&root),
        ),
        (
            "§78.3 Workspace Dependency Rule",
            dependency_rule_check(&root),
        ),
        (
            "M01 D1 / G-M01-1 (workspace members == module_ownership.toml rows; every member declares edition core|cloud)",
            m01_1_workspace_members(&root),
        ),
        (
            "M01 D1 / G-M01-2 / ADR-0073 D-B (no core package depends on a cloud package)",
            m01_2_core_cloud_edges(&root),
        ),
        (
            "M01 D5 / G-M01-3 (crate boundary table: reqwest, sqlx, qdrant client, L0 kernel)",
            m01_3_crate_boundary(&root),
        ),
        (
            "M01 D4 / G-M01-4 (a DegradeCode variant with a production emit site is tested through it, not through abstain; the others are rows of tests/fault/dormant.toml)",
            m01_4_real_path_or_dormant(&root),
        ),
        (
            "§78 boundary lint (no env::var outside config/bootstrap)",
            env_var_scan(&root),
        ),
        (
            "§55.1 G80-2 (build_request sole construction point)",
            g80_2_build_request_unique(&root),
        ),
        (
            "§55.6 G55-6 ① / G80-27 (no caller-assignable retrieval depth name on RetrievalRequest or build_request)",
            g55_6_1_caller_depth_names(&root),
        ),
        (
            "§16.2 G80-4 (serving_version sole retrieval entry point)",
            g80_4_serving_version_sole_entry_point(&root),
        ),
        (
            "§48.0① G80-22 (payload_sha256 sole construction point)",
            g80_22_payload_sha256_unique(&root),
        ),
        (
            "§78.1/§15.1 (ticket-family triple spelled once)",
            g78_1_ticket_family_literals(&root),
        ),
        (
            "§1.3/§48.0 G80-11 (source_hash sole construction point)",
            g80_11_source_hash_unique(&root),
        ),
        (
            "§6.2.3 G80-40 static (typed DB pool topology)",
            g6_db_pool_topology(&root),
        ),
        (
            "§83.4 G80-3 (outbound network choke point real RHS)",
            g80_3_outbound_choke_point(&root),
        ),
        (
            "§11.8 (classify sole construction point)",
            g11_8_classify_sole_construction_point(&root),
        ),
        (
            "§20#G20-2 / G80-39 (online recall 无隐藏生成调用)",
            g20_2_no_hidden_generative_recall(&root),
        ),
        (
            "§23.1② (LedgerCounts 字段集恰为 6)",
            g23_1_ledger_counts_exactly_six_fields(&root),
        ),
        (
            "§22.5 (A1 算式全库只此一处)",
            g22_5_a1_sole_implementation(&root),
        ),
        (
            "§11.2.4–11.2.5 R3 (append-only exact-health admission contract)",
            r3_health_migration_gate(&root),
        ),
        (
            "§11.2.5 R3 (actual contribution call ledger/disclosure transaction)",
            r3_contribution_ledger_gate(&root),
        ),
        (
            "§25.3.1 W1 (Project Continuity storage/CAS/marker boundary)",
            w1_continuity_gate(&root),
        ),
        (
            "§25.3.1 W2 (Project Continuity native RR read boundary)",
            w2_continuity_gate(&root),
        ),
        (
            "ADR-0012 (gateway↔retrieval-worker boundary, worker-only symbols)",
            adr_0012_gateway_boundary_gate(&root),
        ),
        (
            "ADR-0012 (RPC transport stays UDS + peer_cred, never TCP)",
            adr_0012_uds_transport_gate(&root),
        ),
        (
            "ADR-0014 (gateway Qdrant access is QdrantReadOnly, never ReadWrite)",
            adr_0014_gateway_qdrant_read_only_gate(&root),
        ),
        (
            "ADR-0039 / §11.4 (outbound client dials only through the checked resolver)",
            checked_resolver_dial_gate(&root),
        ),
        (
            "§33 card 22 (tool surface truth: SUPPORTED_OPERATION_KEYS ↔ invoke dispatch ↔ \
             Baseline 工具面交付实况 ↔ canonical catalog)",
            mcp_tool_surface_truth(&root),
        ),
        (
            "§33 card 22 (Tool 2 semantic lane: recall.schema.json x-humaux-v1-supported ↔ the \
             recall.rs DEPENDENCY_UNAVAILABLE guard)",
            recall_v1_supported_lanes(&root),
        ),
        (
            "ADR-0059 D-E/D-F (role DDL and 0011 placeholder parsing: one call site each)",
            adr0059_role_hygiene_sole_call_sites(&root),
        ),
        (
            "ADR-0059 D-G (token key install and the token field parser: one production call site each)",
            adr0059_token_sole_call_sites(&root),
        ),
        (
            "ADR-0060 D-B T31 (one RouteProviders::new, one ReasoningProviderDescriptor literal under bins, one capabilities read)",
            adr0060_route_provider_sole_sites(&root),
        ),
        (
            "ADR-0061 D-A (no Box::leak in crates/telemetry or bins: metric labels stay closed &'static str)",
            adr0061_no_box_leak_labels(&root),
        ),
        (
            "M07 D9 / G-M07-1 (Evidence and Memory INSERT doors: one statement each in non-test code)",
            m07_1_insert_doors(&root),
        ),
        (
            "M09 D1 / G-M09-1 (stream_log INSERT and commit_seq nextval: one statement each, in stream_repo.rs, non-test code)",
            m09_1_ticket_doors(&root),
        ),
        (
            "M04 D2 / G-M04-1 (plans are data: no plan_key of the values file and no price_cents / lease_block integer literal in crates and bins non-test code, or in migrations above the scan floor)",
            m04_1_plans_are_data(&root),
        ),
        (
            "M29 T04c / G-T04c-3 (private.evidence_task_runs INSERT: one statement, in remember.rs, non-test code)",
            t04c_3_carrier_door(&root),
        ),
        (
            "M29 T06c / G-T06c-3 (private.evidence_projects INSERT: one statement, in remember.rs, non-test code)",
            t06c_door(&root),
        ),
        (
            "M29 T06b / G-M29-5(b) (correction@1 literal: one, in RuleId's closed set, non-test code)",
            t06b_correction_rule_site(&root),
        ),
        (
            "M29 T07 / ADR-0078 D-D reader (no direct private.memory_projects read; one memory_projects_live reader, in attribution_repo.rs, non-test code)",
            m29_attribution_reader(&root),
        ),
        (
            "ADR-0078 / G-M29-5(a) (attribution port: one call, inside insert_memory_in_txn, required parameter; one implementation)",
            m29_5a_attribution_site(&root),
        ),
        (
            "ADR-0078 / G-N09-1 (no provider / inference / embedding name in the memory_projects write path)",
            n09_1_no_model_source(&root),
        ),
        (
            "M08 D1 / G-M08-2 (can_read( call sites in adapters and bins non-test code == the declared read-gate set)",
            m08_2_can_read_one_home(&root),
        ),
        (
            "M24-7 / G-M24-7 (§79, #101, #145: every test binary that carries a derived-job, outbox or provider-slot marker is in nextest's global-db group; shared-catalog DDL runs only in a lane(a:disposable) test; no stale binary_id or exemption)",
            m24_7_global_db_completeness(&root),
        ),
        (
            "T-LANG-1 / no-python-in-system (no *.py under crates, bins, migrations, config; no python in any Dockerfile, Dockerfile-*, *.Dockerfile, *.dockerfile or Containerfile; a compose service in every Compose document under deploy/ rendered by Compose is limited to the rehearsal / test profiles; a missing render fails in CI and is not_applicable elsewhere; the render set must equal the scan set; no Python shebang under crates, bins, deploy; CI, scripts, rehearsal and experiments may use Python)",
            no_python_in_system(&root),
        ),
        (
            "ADR-0084 D-B / T-CI-4 (the rerank image's rerank/ORT ADD pins equal .github/actions/rerank-parity/action.yml; a missing file, stage or pin is not_applicable naming it)",
            rerank_pin_parity(&root),
        ),
    ];
    checks.extend(provider_plane_architecture_gate_checks(&root));

    let mut had_fail = false;
    for (name, verdict) in &checks {
        if report(name, verdict) {
            had_fail = true;
        }
    }
    if had_fail { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn real_root() -> PathBuf {
        workspace_root()
    }

    // -- T-LANG-1: no-python-in-system ----------------------------------------------------------

    /// A rendered compose document (`docker compose config --format json`) with the given `services` object body.
    fn np_json(services: &str) -> String {
        format!("{{\"name\":\"np\",\"services\":{{{services}}}}}")
    }

    /// The problems over one rendered compose document at the production path.
    fn np_problems(json: &str) -> Vec<String> {
        no_python_problems(
            &[],
            &[],
            &[("deploy/compose/prod.yml".to_string(), json.to_string())],
            &[],
        )
    }

    /// The one-line problem for `service` running the Python image `image`.
    fn np_image_problem(service: &str, image: &str) -> String {
        format!(
            "deploy/compose/prod.yml: compose service `{service}` runs the Python image `{image}` but its `profiles:` is not limited to rehearsal/test; the system is Rust (T-LANG-1)"
        )
    }

    /// The one-line problem for `service` running `token` in its `key:`.
    fn np_command_problem(service: &str, key: &str, token: &str) -> String {
        format!(
            "deploy/compose/prod.yml: compose service `{service}` runs the Python command `{token}` in its `{key}:` but its `profiles:` is not limited to rehearsal/test; the system is Rust (T-LANG-1)"
        )
    }

    /// `run()` must list the gate exactly once (a deleted call tuple leaves a gate that never runs).
    #[test]
    fn run_wires_the_no_python_gate_exactly_once() {
        assert_eq!(own_source_count("no_python_in_", "system(&root),"), 1);
    }

    /// Without the lint job's render, every real compose file is named and nothing is judged: `not_applicable`, never a
    /// pass (§57.1). The requirement is injected as false: this test runs in a job where CI does set the require flag,
    /// and its subject is the non-CI three-state, not the environment. An actual Python source / Dockerfile / shebang
    /// problem in the real tree would still be `fail`, so this also asserts the real tree carries none of those.
    #[test]
    fn no_python_gate_names_the_real_compose_json_it_needs() {
        assert_eq!(
            no_python_in_system_with(&real_root(), false),
            Verdict::NotApplicable(
                "compose config JSON for deploy/compose/a5-load.yml, deploy/compose/backup.yml, deploy/compose/dev.yml, deploy/compose/drill.yml, deploy/compose/prod.yml".to_string()
            )
        );
    }

    /// r1 shape: a `*.py` under a system root is a problem; the same file in the tooling territory is not.
    #[test]
    fn no_python_gate_flags_a_python_file_in_the_system_tree() {
        let red = no_python_problems(&["crates/x/foo.py".to_string()], &[], &[], &[]);
        assert_eq!(red.len(), 1, "{red:?}");
        assert!(red[0].starts_with("crates/x/foo.py:"), "{red:?}");
        for allowed in [
            "scripts/a.py",
            "deploy/rehearsal/alert_sink.py",
            ".github/workflows/x.py",
            "experiments/a/b.py",
            "xtask/tests/t.py",
        ] {
            let found = no_python_problems(&[allowed.to_string()], &[], &[], &[]);
            assert!(found.is_empty(), "{allowed}: {found:?}");
        }
    }

    /// `python` or `pip` on a non-comment line of a product Dockerfile is a problem; `pipefail` and comments are not.
    #[test]
    fn no_python_gate_flags_python_in_a_product_image_build() {
        let path = "deploy/images/humaux/Dockerfile".to_string();
        let dirty = vec![(
            path.clone(),
            "# python is fine in a comment\nFROM debian\nRUN apt-get install -y python3-pip\nRUN pip install x\n"
                .to_string(),
        )];
        let red = no_python_problems(&[], &dirty, &[], &[]);
        assert_eq!(red.len(), 2, "{red:?}");
        assert!(
            red[0].starts_with("deploy/images/humaux/Dockerfile:3:"),
            "{red:?}"
        );
        let clean = vec![(path, "FROM scratch\nRUN set -o pipefail\n".to_string())];
        assert!(no_python_problems(&[], &clean, &[], &[]).is_empty());
    }

    /// r1 shape widened: a product image build outside `deploy/images/` is caught too, under every name Buildah and
    /// Docker accept; the tooling territory is still exempt by path and the walk starts at the repo root, so a fixture
    /// outside `bins/` proves the walker was not narrowed to a system root.
    #[test]
    fn no_python_gate_walks_dockerfiles_outside_deploy_images() {
        for name in [
            "svc/img/Dockerfile",
            "svc/img/Dockerfile-dev",
            "svc/img/Dockerfile.release",
            "svc/img/build.Dockerfile",
            "svc/img/build.dockerfile",
            "svc/img/Containerfile",
        ] {
            let dirty = vec![(
                name.to_string(),
                "FROM debian\nRUN pip install x\n".to_string(),
            )];
            let red = no_python_problems(&[], &dirty, &[], &[]);
            assert_eq!(red.len(), 1, "{name}: {red:?}");
            assert!(red[0].starts_with(&format!("{name}:2:")), "{name}: {red:?}");
        }
        let tooling = vec![(
            "scripts/Dockerfile".to_string(),
            "FROM python:3.13-slim\n".to_string(),
        )];
        assert!(no_python_problems(&[], &tooling, &[], &[]).is_empty());

        let dir = std::env::temp_dir().join(format!("np-docker-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("crates/x")).unwrap();
        fs::create_dir_all(dir.join("svc/img")).unwrap();
        fs::write(
            dir.join("svc/img/Dockerfile"),
            "FROM debian\nRUN pip install x\n",
        )
        .unwrap();
        fs::write(
            dir.join("svc/img/makefile"),
            "FROM debian\nRUN pip install x\n",
        )
        .unwrap();
        let verdict = no_python_in_system_with(&dir, false);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            verdict,
            Verdict::Fail(vec![
                "svc/img/Dockerfile:2: python in a product image build: RUN pip install x (T-LANG-1)"
                    .to_string()
            ])
        );
    }

    /// The file-name filter itself, one exact expectation per documented form: `Dockerfile`, `Dockerfile.<suffix>`,
    /// `Dockerfile-<suffix>`, `<name>.Dockerfile`, `<name>.dockerfile`, `Containerfile` and `Containerfile.<suffix>`.
    /// `Dockerfile.md` is a doc, not a build file, so it is false. A name handed to [`no_python_problems`] bypasses this
    /// filter, so this table is the only proof the walk's positives and negatives are the intended set.
    #[test]
    fn dockerfile_name_filter_covers_every_documented_form() {
        let cases: [(&str, bool); 14] = [
            ("Dockerfile", true),
            ("Dockerfile.dev", true),
            ("Dockerfile.release", true),
            ("Dockerfile-", true),
            ("Dockerfile-dev", true),
            ("svc/build.Dockerfile", true),
            ("build.Dockerfile", true),
            ("svc/build.dockerfile", true),
            ("Containerfile", true),
            ("Containerfile.prod", true),
            ("Dockerfile.md", false),
            ("Dockerfilex", false),
            ("notDockerfile.txt", false),
            ("makefile", false),
        ];
        for (name, expected) in cases {
            assert_eq!(is_dockerfile_name(name), expected, "{name}");
        }
    }

    /// #162: the anchor/`<<`-inherited image the line scanner lost is just `image` in Compose's own render, and the
    /// gate names the exact service and image.
    #[test]
    fn no_python_gate_rejects_an_inherited_python_image() {
        let json = np_json(r#""worker":{"image":"python:3.13-slim"}"#);
        assert_eq!(
            np_problems(&json),
            [np_image_problem("worker", "python:3.13-slim")]
        );
    }

    /// #162: a flow-style `services:` mapping and a quoted service key are resolved by Compose; the service name is
    /// judged verbatim.
    #[test]
    fn no_python_gate_rejects_a_flow_style_service_with_a_quoted_key() {
        let json = np_json(r#""quoted worker":{"image":"python:3.12-slim@sha256:abc"}"#);
        assert_eq!(
            np_problems(&json),
            [np_image_problem(
                "quoted worker",
                "python:3.12-slim@sha256:abc"
            )]
        );
    }

    /// #162: a service is exempt only when its own `profiles:` are all rehearsal / test; absent, empty, mixed or other
    /// profiles keep the Python image red.
    #[test]
    fn no_python_gate_exempts_only_the_tooling_profiles() {
        for profiles in [r#"["rehearsal"]"#, r#"["rehearsal","test"]"#, r#"["test"]"#] {
            let json = np_json(&format!(
                r#""sink":{{"image":"python:3.13-slim","command":["python3","x.py"],"profiles":{profiles}}}"#
            ));
            assert_eq!(np_problems(&json), Vec::<String>::new(), "{profiles}");
        }
        for profiles in [r#"[]"#, r#"["ops"]"#, r#"["rehearsal","ops"]"#] {
            let json = np_json(&format!(
                r#""sink":{{"image":"python:3.13-slim","profiles":{profiles}}}"#
            ));
            assert_eq!(
                np_problems(&json),
                [np_image_problem("sink", "python:3.13-slim")],
                "{profiles}"
            );
        }
        let no_profiles = np_json(r#""sink":{"image":"python:3.13-slim"}"#);
        assert_eq!(
            np_problems(&no_profiles),
            [np_image_problem("sink", "python:3.13-slim")]
        );
        let non_python = np_json(r#""sink":{"image":"alpine:3","command":["sleep","1"]}"#);
        assert_eq!(np_problems(&non_python), Vec::<String>::new());
    }

    /// #162: every Python command token is caught as a whole word — bare, versioned, `pip`, and what a path prefix
    /// leaves behind — while `pythonic` is not.
    #[test]
    fn no_python_gate_rejects_every_python_command_token() {
        for token in [
            "python",
            "python2",
            "python3",
            "python3.12",
            "python312",
            "pip",
            "pip3",
        ] {
            let json = np_json(&format!(
                r#""sink":{{"image":"debian:13","command":["{token}","-c","x"]}}"#
            ));
            assert_eq!(
                np_problems(&json),
                [np_command_problem("sink", "command", token)],
                "{token}"
            );
        }
        let block = np_json(r#""sink":{"image":"debian:13","command":"python3.12 -c print(1)"}"#);
        assert_eq!(
            np_problems(&block),
            [np_command_problem("sink", "command", "python3.12")]
        );
        let clean = np_json(
            r#""sink":{"image":"debian:13","command":["pythonic","x"],"entrypoint":["/bin/sh","-c","exec ./app"]}"#,
        );
        assert_eq!(np_problems(&clean), Vec::<String>::new());
    }

    /// #162 / r1: an exec-form `entrypoint` that reaches Python only through `/usr/bin/env` is still a Python
    /// `entrypoint`, named as one; dropping the entrypoint leg loses exactly this.
    #[test]
    fn no_python_gate_rejects_a_python_entrypoint() {
        let json = np_json(
            r#""sink":{"image":"debian:13","entrypoint":["/usr/bin/env","python","x.py"]}"#,
        );
        assert_eq!(
            np_problems(&json),
            [np_command_problem("sink", "entrypoint", "python")]
        );
        let shell =
            np_json(r#""sink":{"image":"debian:13","entrypoint":"/bin/sh -c 'pip3 install x'"}"#);
        assert_eq!(
            np_problems(&shell),
            [np_command_problem("sink", "entrypoint", "pip3")]
        );
    }

    /// A render this gate cannot read is a problem naming the file, never an empty service list.
    #[test]
    fn no_python_gate_fails_on_an_unusable_compose_render() {
        let not_json = np_problems("services: {}");
        assert_eq!(not_json.len(), 1, "{not_json:?}");
        assert!(
            not_json[0].starts_with(
                "deploy/compose/prod.yml: the rendered compose config is unusable (not JSON:"
            ),
            "{not_json:?}"
        );
        let no_services = np_problems(&np_json("").replace("\"services\":{}", "\"jobs\":{}"));
        assert_eq!(no_services.len(), 1, "{no_services:?}");
        assert!(
            no_services[0].contains("unusable (no `services` object)"),
            "{no_services:?}"
        );
    }

    /// The rehearsal tooling territory is exempt by path, and a Python compose service elsewhere is still red.
    #[test]
    fn no_python_gate_exempts_the_tooling_paths_only() {
        let json = np_json(r#""sink":{"image":"python:3.13-slim"}"#);
        let files = vec![
            ("deploy/compose/prod.yml".to_string(), json.clone()),
            ("deploy/rehearsal/compose.yml".to_string(), json),
        ];
        assert_eq!(
            no_python_problems(&[], &[], &files, &[]),
            [np_image_problem("sink", "python:3.13-slim")]
        );
    }

    /// Three states over a scratch tree: no scanned directory is `not_applicable` and names them, a clean tree passes,
    /// a planted `crates/x/foo.py` fails.
    #[test]
    fn no_python_gate_is_three_state_over_a_scratch_tree() {
        let dir = std::env::temp_dir().join(format!("np-gate-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            no_python_in_system_with(&dir, false),
            Verdict::NotApplicable("crates, bins, migrations, config, deploy".to_string())
        );
        fs::create_dir_all(dir.join("crates/x")).unwrap();
        assert_eq!(no_python_in_system_with(&dir, false), Verdict::Pass);
        fs::write(dir.join("crates/x/foo.py"), "print(1)\n").unwrap();
        let verdict = no_python_in_system_with(&dir, false);
        fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&verdict, Verdict::Fail(p) if p.len() == 1 && p[0].starts_with("crates/x/foo.py:")),
            "{verdict:?}"
        );
    }

    /// A compose file with no render is `not_applicable` naming it outside CI; the render ci.yml writes (its exact path)
    /// makes the same tree pass, and a Python service in that render fails.
    #[test]
    fn no_python_gate_names_a_compose_file_without_a_render() {
        let dir = std::env::temp_dir().join(format!("np-compose-json-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("crates/x")).unwrap();
        fs::create_dir_all(dir.join("deploy/compose")).unwrap();
        fs::write(dir.join("deploy/compose/prod.yml"), "services: {}\n").unwrap();
        assert_eq!(
            no_python_in_system_with(&dir, false),
            Verdict::NotApplicable("compose config JSON for deploy/compose/prod.yml".to_string())
        );

        let rendered = dir.join("target/no-python-compose/deploy/compose");
        fs::create_dir_all(&rendered).unwrap();
        fs::write(
            rendered.join("prod.yml.json"),
            np_json(r#""gateway":{"image":"humaux-gateway:1"}"#),
        )
        .unwrap();
        assert_eq!(no_python_in_system_with(&dir, false), Verdict::Pass);

        fs::write(
            rendered.join("prod.yml.json"),
            np_json(r#""sink":{"image":"python:3.13-slim"}"#),
        )
        .unwrap();
        let verdict = no_python_in_system_with(&dir, false);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            verdict,
            Verdict::Fail(vec![np_image_problem("sink", "python:3.13-slim")])
        );
    }

    /// The discovery rule restores the old `deploy/**` scope for Compose files: every file of `deploy/compose/` plus a
    /// Compose-named file elsewhere; a Prometheus / Qdrant / rules YAML is not a Compose document.
    #[test]
    fn compose_discovery_covers_every_compose_document_under_deploy() {
        let cases: [(&str, bool); 12] = [
            ("deploy/compose/a5-load.yml", true),
            ("deploy/compose/prod.yml", true),
            ("deploy/compose/backup.yaml", true),
            ("deploy/compose/nested/dev.yml", true),
            ("deploy/other/compose.yml", true),
            ("deploy/other/compose.override.yaml", true),
            ("deploy/other/docker-compose.yml", true),
            ("deploy/rehearsal/compose.yml", true),
            ("deploy/prometheus/prometheus.yml", false),
            ("deploy/prometheus/alerts.rules.yml", false),
            ("deploy/qdrant/config.yaml", false),
            ("deploy/compose/README.md", false),
        ];
        for (path, expected) in cases {
            assert_eq!(is_compose_file(path), expected, "{path}");
        }
    }

    /// r3 shape: with the require flag set (CI), every scanned Compose document must have its render; a missing one is
    /// a failure naming the file, never `not_applicable`. A rendered file the scan does not know is a failure too, so
    /// the render set and the scan set cannot drift.
    #[test]
    fn no_python_gate_requires_every_render_in_ci() {
        let dir = std::env::temp_dir().join(format!("np-compose-required-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("crates/x")).unwrap();
        fs::create_dir_all(dir.join("deploy/compose")).unwrap();
        fs::create_dir_all(dir.join("deploy/other")).unwrap();
        fs::write(dir.join("deploy/compose/prod.yml"), "services: {}\n").unwrap();
        fs::write(
            dir.join("deploy/other/compose.override.yml"),
            "services: {}\n",
        )
        .unwrap();
        let rendered = dir.join("target/no-python-compose/deploy");
        fs::create_dir_all(rendered.join("compose")).unwrap();
        fs::create_dir_all(rendered.join("other")).unwrap();
        fs::write(
            rendered.join("compose/prod.yml.json"),
            np_json(r#""gateway":{"image":"humaux-gateway:1"}"#),
        )
        .unwrap();
        fs::write(
            rendered.join("other/compose.override.yml.json"),
            np_json(r#""sink":{"image":"alpine:3"}"#),
        )
        .unwrap();
        assert_eq!(no_python_in_system_with(&dir, true), Verdict::Pass);

        fs::remove_file(rendered.join("compose/prod.yml.json")).unwrap();
        assert_eq!(
            no_python_in_system_with(&dir, true),
            Verdict::Fail(vec![
                "deploy/compose/prod.yml: missing rendered compose config at target/no-python-compose/deploy/compose/prod.yml.json; CI must render every scanned compose file (T-LANG-1)".to_string(),
            ])
        );
        fs::write(
            rendered.join("compose/prod.yml.json"),
            np_json(r#""gateway":{"image":"humaux-gateway:1"}"#),
        )
        .unwrap();
        assert_eq!(no_python_in_system_with(&dir, true), Verdict::Pass);

        fs::write(
            rendered.join("compose/stale.yml.json"),
            np_json(r#""sink":{"image":"alpine:3"}"#),
        )
        .unwrap();
        let drifted = no_python_in_system_with(&dir, true);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            drifted,
            Verdict::Fail(vec![
                "deploy/compose/stale.yml.json: rendered compose config for no scanned compose file (deploy/compose/stale.yml); the render set and the scan set must be identical (T-LANG-1)".to_string()
            ])
        );
    }

    /// r2: the root walk does not enter dot-directories, so a nested `.worktrees/` checkout's Dockerfile is not this
    /// tree's product image.
    #[test]
    fn no_python_gate_skips_dot_directories_in_the_root_walk() {
        let dir = std::env::temp_dir().join(format!("np-dotdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("crates/x")).unwrap();
        fs::create_dir_all(dir.join(".worktrees/x")).unwrap();
        fs::write(
            dir.join(".worktrees/x/Dockerfile"),
            "FROM debian\nRUN pip install x\n",
        )
        .unwrap();
        let verdict = no_python_in_system_with(&dir, false);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(verdict, Verdict::Pass);
    }

    /// r1 shape widened: a Python shebang fails even without a `.py` extension; a non-Python shebang and the tooling
    /// territory are not caught, and the real walk reads the first line of an extensionless file.
    #[test]
    fn no_python_gate_flags_a_python_shebang_without_a_py_extension() {
        let dirty = vec![(
            "bins/gateway/run".to_string(),
            "#!/usr/bin/env python3".to_string(),
        )];
        let red = no_python_problems(&[], &[], &[], &dirty);
        assert_eq!(red.len(), 1, "{red:?}");
        assert!(red[0].starts_with("bins/gateway/run:1:"), "{red:?}");
        let clean = vec![
            ("bins/gateway/run".to_string(), "#!/bin/sh".to_string()),
            (
                "bins/gateway/README".to_string(),
                "python is not a shebang here".to_string(),
            ),
            (
                "scripts/tool".to_string(),
                "#!/usr/bin/env python3".to_string(),
            ),
        ];
        assert!(no_python_problems(&[], &[], &[], &clean).is_empty());

        let dir = std::env::temp_dir().join(format!("np-shebang-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("bins/gateway")).unwrap();
        fs::write(dir.join("bins/gateway/run"), "#!/usr/bin/env python3\n").unwrap();
        let verdict = no_python_in_system_with(&dir, false);
        fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&verdict, Verdict::Fail(p) if p.len() == 1 && p[0].starts_with("bins/gateway/run:1:")),
            "{verdict:?}"
        );
    }

    // -- ADR-0084 D-B / T-CI-4: the image's rerank pins equal the parity action's -----------------

    const RERANK_DOCKERFILE_FIXTURE: &str = "\
FROM rust:1.99.0-slim-trixie@sha256:24e6 AS rerank-fetch
ADD --checksum=sha256:e16a27a8ed330bbc698df7330b0cf56e722f354e3bcc92118682c74ef3c3e3da https://example.test/ort.tgz /fetch/ort.tgz
ADD --checksum=sha256:cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c2f https://example.test/rerank.tar.gz /fetch/rerank.tar.gz
FROM runtime AS gateway
";

    const RERANK_ACTION_FIXTURE: &str = "\
name: rerank parity
inputs:
  ort_url:
    description: o
    required: false
    default: https://example.test/ort.tgz
  ort_sha256:
    description: s
    required: false
    default: e16a27a8ed330bbc698df7330b0cf56e722f354e3bcc92118682c74ef3c3e3da
  rerank_url:
    description: o
    required: false
    default: https://example.test/rerank.tar.gz
  rerank_sha256:
    description: s
    required: false
    default: cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c2f
  runtime_image:
    description: i
    required: false
    default: gcr.io/distroless/cc-debian13@sha256:e792
runs:
  using: composite
";

    /// The real tree's image and parity action carry the same two pins; a drift would mean parity tests an artifact
    /// other than the one production ships (ADR-0084 D-B).
    #[test]
    fn rerank_pin_gate_passes_on_the_real_tree() {
        assert_eq!(rerank_pin_parity(&real_root()), Verdict::Pass);
    }

    /// `run()` must list the gate exactly once: a dropped call leaves it green forever (§57.1).
    #[test]
    fn run_wires_the_rerank_pin_gate_exactly_once() {
        assert_eq!(own_source_count("rerank_pin_", "parity(&root),"), 1);
    }

    /// Equal pins pass; one differing sha256 fails, naming both files, the action input and the URL it belongs to.
    #[test]
    fn rerank_pin_gate_fails_when_one_sha_differs() {
        assert!(
            rerank_pin_problems(RERANK_DOCKERFILE_FIXTURE, RERANK_ACTION_FIXTURE)
                .expect("both fixtures carry both pins")
                .is_empty()
        );
        let mutant = RERANK_DOCKERFILE_FIXTURE.replace(
            "cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c2f",
            "cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c20",
        );
        let red = rerank_pin_problems(&mutant, RERANK_ACTION_FIXTURE)
            .expect("a differing value is a failure, not a missing object");
        assert_eq!(red.len(), 1, "{red:?}");
        assert!(red[0].contains(RERANK_DOCKERFILE), "{red:?}");
        assert!(red[0].contains(RERANK_PARITY_ACTION), "{red:?}");
        assert!(red[0].contains("inputs.rerank_sha256"), "{red:?}");
        assert!(
            red[0].contains("https://example.test/rerank.tar.gz"),
            "{red:?}"
        );
        assert!(
            red[0].contains("cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c20"),
            "{red:?}"
        );
    }

    /// The same sha256 under another URL is a URL difference: `fail`, naming both files and the action input, not
    /// `not_applicable` (§57.1 第2条 keeps that for an absent object).
    #[test]
    fn rerank_pin_gate_fails_when_one_url_differs() {
        let mutant = RERANK_ACTION_FIXTURE.replace(
            "default: https://example.test/rerank.tar.gz",
            "default: https://example.test/rerank-v2.tar.gz",
        );
        let red = rerank_pin_problems(RERANK_DOCKERFILE_FIXTURE, &mutant)
            .expect("a differing URL is a failure, not a missing object");
        assert_eq!(red.len(), 1, "{red:?}");
        assert!(red[0].contains(RERANK_DOCKERFILE), "{red:?}");
        assert!(red[0].contains(RERANK_PARITY_ACTION), "{red:?}");
        assert!(red[0].contains("inputs.rerank_sha256"), "{red:?}");
        assert!(
            red[0].contains("https://example.test/rerank.tar.gz"),
            "{red:?}"
        );
        assert!(
            red[0].contains("https://example.test/rerank-v2.tar.gz"),
            "{red:?}"
        );
    }

    /// Write a rerank Dockerfile/action pair into a unique temp root and run the gate over it, so tests exercise the
    /// same three-state mapping `run()` uses.
    fn rerank_verdict(tag: &str, dockerfile: &str, action: &str) -> Verdict {
        let dir = std::env::temp_dir().join(format!("{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for (path, text) in [
            (RERANK_DOCKERFILE, dockerfile),
            (RERANK_PARITY_ACTION, action),
        ] {
            let p = dir.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
        let verdict = rerank_pin_parity(&dir);
        fs::remove_dir_all(&dir).unwrap();
        verdict
    }

    /// URL and sha256 both differ — one artifact version bumped in one file only. Both sides still carry pins, so
    /// the gate is `fail`, one line per unmatched pin, each naming both files and its action input, not
    /// `not_applicable` (#200, §57.1 第2条).
    #[test]
    fn rerank_pin_gate_fails_when_url_and_sha_both_differ() {
        let action = RERANK_ACTION_FIXTURE
            .replace(
                "default: https://example.test/rerank.tar.gz",
                "default: https://example.test/rerank-v2.tar.gz",
            )
            .replace(
                "default: cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c2f",
                "default: cd90976aa97eee7a29221a1bd136e3b44545e1df1dec2008b613b67711b82c20",
            );
        let verdict = rerank_verdict("rerank-both-differ", RERANK_DOCKERFILE_FIXTURE, &action);
        assert!(
            matches!(&verdict, Verdict::Fail(_)),
            "both pins differ must be fail, got {verdict:?}"
        );
        let Verdict::Fail(lines) = verdict else {
            unreachable!("checked above")
        };
        assert_eq!(
            lines.len(),
            2,
            "one fail per unmatched pin (action side + image side): {lines:?}"
        );
        assert!(
            lines.iter().all(|l| l.contains(RERANK_DOCKERFILE)
                && l.contains(RERANK_PARITY_ACTION)
                && l.contains("inputs.")),
            "every fail names both files and its action input: {lines:?}"
        );
        let image_url = "https://example.test/rerank.tar.gz";
        let action_url = "https://example.test/rerank-v2.tar.gz";
        assert_eq!(
            lines.iter().filter(|l| l.contains(action_url)).count(),
            1,
            "the action-side unmatched pin names only the action URL: {lines:?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains(image_url)).count(),
            1,
            "the image-side unmatched pin names only the image URL: {lines:?}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("inputs.rerank_sha256"))
                .count(),
            1,
            "the action-side line names its sha input: {lines:?}"
        );
        assert_eq!(
            lines.iter().filter(|l| l.contains("inputs.*_url")).count(),
            1,
            "the image-side line names the url-input family: {lines:?}"
        );
    }

    /// `_url` inputs exist but no default is readable: there is nothing to compare, so the gate is `not_applicable`
    /// naming the missing default, never a pass or a `fail` with an empty problem list (§57.1 第2条).
    #[test]
    fn rerank_pin_gate_is_not_applicable_when_every_action_default_is_missing() {
        let no_defaults = RERANK_ACTION_FIXTURE
            .lines()
            .filter(|line| !line.trim_start().starts_with("default:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            rerank_verdict(
                "rerank-no-defaults",
                RERANK_DOCKERFILE_FIXTURE,
                &no_defaults
            ),
            Verdict::NotApplicable(format!("{RERANK_PARITY_ACTION}: inputs.ort_url.default"))
        );
    }

    /// A missing file, stage, or ALL pins on one side is `not_applicable` naming the object — never a silent pass.
    /// One unmatched pin while the other side still has pins is a `fail` instead (§57.1 第2条; #200).
    #[test]
    fn rerank_pin_gate_is_not_applicable_only_when_an_object_is_absent() {
        assert_eq!(
            rerank_pin_parity(Path::new("/nonexistent-humaux-ds-ci-194")),
            Verdict::NotApplicable(RERANK_DOCKERFILE.to_string())
        );
        let no_stage = RERANK_DOCKERFILE_FIXTURE.replace(" AS rerank-fetch", "");
        assert_eq!(
            rerank_pin_problems(&no_stage, RERANK_ACTION_FIXTURE).unwrap_err(),
            format!("{RERANK_DOCKERFILE}: `FROM … AS {RERANK_STAGE}` stage")
        );
        let no_image_pin = RERANK_DOCKERFILE_FIXTURE
            .lines()
            .filter(|line| !line.starts_with("ADD --checksum"))
            .collect::<Vec<_>>()
            .join("\n");
        let missing = rerank_pin_problems(&no_image_pin, RERANK_ACTION_FIXTURE).unwrap_err();
        assert!(missing.contains(RERANK_DOCKERFILE), "{missing}");
        assert!(missing.contains("ADD --checksum"), "{missing}");
        let no_action_pin = RERANK_ACTION_FIXTURE.replace("_url:", "_renamed:");
        assert_eq!(
            rerank_pin_problems(RERANK_DOCKERFILE_FIXTURE, &no_action_pin).unwrap_err(),
            format!("{RERANK_PARITY_ACTION}: inputs.*_url")
        );
        // One image pin gone while the image still carries the other: both sides have pins, so it is a failure.
        let no_pin = RERANK_DOCKERFILE_FIXTURE
            .lines()
            .filter(|line| !line.contains("rerank.tar.gz"))
            .collect::<Vec<_>>()
            .join("\n");
        let unmatched = rerank_pin_problems(&no_pin, RERANK_ACTION_FIXTURE)
            .expect("one missing pin is a failure, not a missing object");
        assert_eq!(unmatched.len(), 1, "{unmatched:?}");
        assert!(unmatched[0].contains(RERANK_DOCKERFILE), "{unmatched:?}");
        assert!(unmatched[0].contains(RERANK_PARITY_ACTION), "{unmatched:?}");
        assert!(
            unmatched[0].contains("inputs.rerank_sha256"),
            "{unmatched:?}"
        );
        assert!(
            unmatched[0].contains("https://example.test/rerank.tar.gz"),
            "{unmatched:?}"
        );
        // One action pin unreadable while the action still carries the other: also a failure.
        let no_sha_input =
            RERANK_ACTION_FIXTURE.replace("  rerank_sha256:", "  rerank_sha256_renamed:");
        let unreadable = rerank_pin_problems(RERANK_DOCKERFILE_FIXTURE, &no_sha_input)
            .expect("an unreadable pin beside a readable one is a failure");
        assert_eq!(unreadable.len(), 2, "{unreadable:?}");
        assert!(
            unreadable
                .iter()
                .all(|p| p.contains(RERANK_DOCKERFILE) && p.contains(RERANK_PARITY_ACTION)),
            "{unreadable:?}"
        );
        assert!(
            unreadable
                .iter()
                .any(|p| p.contains("inputs.rerank_sha256")),
            "{unreadable:?}"
        );
    }

    fn w1_real_sources() -> (String, String, String) {
        let root = real_root();
        (
            fs::read_to_string(root.join("migrations/0136_project_continuity.sql")).unwrap(),
            fs::read_to_string(root.join("crates/domain/src/continuity.rs")).unwrap(),
            fs::read_to_string(root.join("crates/adapters/src/continuity_repo.rs")).unwrap(),
        )
    }

    #[test]
    fn adr0061_box_leak_sentinel_is_green_on_the_tree_and_red_on_a_leak() {
        assert_eq!(adr0061_no_box_leak_labels(&real_root()), Verdict::Pass);
        let encoder = (
            METRICS_ENCODER_FILE.to_string(),
            "//! Box::leak is refused\n".to_string(),
        );
        let leak = (
            "bins/gateway/src/x.rs".to_string(),
            "fn f(t: String) -> &'static str {\n    Box::leak(t.into_boxed_str())\n}\n".to_string(),
        );
        assert_eq!(
            adr0061_box_leak_verdict(std::slice::from_ref(&encoder)),
            Verdict::Pass
        );
        assert_eq!(
            adr0061_box_leak_verdict(&[encoder, leak.clone()]),
            Verdict::Fail(vec!["bins/gateway/src/x.rs:2: Box::leak".to_string()])
        );
        assert!(
            matches!(adr0061_box_leak_verdict(&[leak]), Verdict::Fail(p) if p[0].contains("positive sentinel dead"))
        );
    }

    /// ADR-0061 review-fix 3 (F11): the scan covers the label-recording crates, not only telemetry and the bins,
    /// and every std leak path. Fault: the narrower `crates/telemetry/src` + `bins/*/src` domain ⇒ red.
    #[test]
    fn adr0061_leak_sentinel_scans_retrieval_crates_and_every_leak_path() {
        for path in [
            "crates/retrieval/src/completeness.rs",
            "crates/retrieval-provider/src/metrics.rs",
            "crates/telemetry/src/health.rs",
            "bins/gateway/src/guard.rs",
        ] {
            assert!(in_leak_scan_domain(path), "{path} is outside the leak scan");
        }
        assert!(!in_leak_scan_domain("crates/adapters/src/health.rs"));
        let src = "fn f(s: String, v: Vec<u8>) {\n    let _ = String::leak(s);\n    let _ = Vec::leak(v);\n    let _ = t.leak();\n}\n";
        assert_eq!(
            box_leak_hits("crates/retrieval/src/x.rs", src),
            [
                "crates/retrieval/src/x.rs:2: String::leak",
                "crates/retrieval/src/x.rs:3: Vec::leak",
                "crates/retrieval/src/x.rs:4: .leak(",
            ]
        );
    }

    #[test]
    fn w1_continuity_real_repository_gate_is_green() {
        assert_eq!(w1_continuity_gate(&real_root()), Verdict::Pass);
    }

    #[test]
    fn w1_continuity_contract_mutations_are_red() {
        let (migration, domain, adapter) = w1_real_sources();
        for needle in [
            "ALTER TABLE private.continuity_projects FORCE ROW LEVEL SECURITY;",
            "CONSTRAINT continuity_facet_slots_kind_closed CHECK",
            "CONSTRAINT continuity_facet_slots_current_fkey FOREIGN KEY",
            "ORDER BY memory.memory_id FOR SHARE OF memory",
            "ORDER BY evidence.evidence_id FOR SHARE OF evidence",
            "AND slot.project_id=p_project_id AND slot.facet_kind=p_facet_kind\n    FOR UPDATE;",
            "slot.slot_version=p_expected_slot_version",
            "GET DIAGNOSTICS affected=ROW_COUNT",
            "IF affected<>1",
            "SET humaux.continuity_publish TO '1'",
            "CREATE POLICY continuity_evidence_owner_lock_allow",
            "END) WITH CHECK (false);",
            "CREATE POLICY continuity_evidence_owner_lock_guard",
            "END) WITH CHECK (\n      current_setting('humaux.continuity_publish',true) IS DISTINCT FROM '1');",
        ] {
            let broken = migration.replacen(needle, "", 1);
            assert!(
                matches!(
                    w1_continuity_contract_from(&broken, &domain, &adapter, 0),
                    Verdict::Fail(_)
                ),
                "mutation removing `{needle}` must fail the actual W1 gate"
            );
        }
        assert!(matches!(
            w1_continuity_contract_from(
                &format!("{migration}\n-- 'HANDOFF'"),
                &domain,
                &adapter,
                0
            ),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            w1_continuity_contract_from(&migration, &domain, &adapter, 1),
            Verdict::Fail(_)
        ));
        assert!(matches!(
            w1_continuity_contract_from(
                &migration,
                &domain.replacen("continuity_uuid_v7!(ProjectId)", "", 1),
                &adapter,
                0,
            ),
            Verdict::Fail(_)
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn w2_continuity_real_repository_and_boundary_mutations() {
        let root = real_root();
        let paths = [
            "migrations/0137_project_continuity_read.sql",
            "migrations/0137_project_continuity_read.manifest.toml",
            "crates/application/src/continuity.rs",
            "crates/adapters/src/continuity_read.rs",
            "bins/gateway/src/continuity.rs",
            "bins/gateway/src/guard.rs",
            "bins/gateway/src/mcp_application.rs",
        ];
        let sources: Vec<_> = paths
            .iter()
            .map(|path| fs::read_to_string(root.join(path)).unwrap())
            .collect();
        assert_eq!(
            w2_continuity_contract_from(
                &sources[0],
                &sources[1],
                &sources[2],
                &sources[3],
                &sources[4],
                &sources[5],
                &sources[6]
            ),
            Verdict::Pass
        );
        for (index, needle) in [
            (0, "LANGUAGE plpgsql STABLE SECURITY DEFINER"),
            (
                0,
                "ALTER FUNCTION private.read_continuity_project_storage_v1(",
            ),
            (0, ") OWNER TO role_migration_owner;"),
            (
                0,
                "REVOKE ALL ON FUNCTION private.read_continuity_project_storage_v1(",
            ),
            (0, ") FROM PUBLIC;"),
            (0, "project.workspace_id=ANY(p_authorized_workspace_ids)"),
            (0, "p_requested_workspace_id IS NULL"),
            (0, "pg_catalog.pg_input_is_valid(tenant_setting,'uuid')"),
            (0, "memory_links_exact boolean"),
            (0, "evidence_links_exact boolean"),
            (0, "stored_body_sha256 bytea"),
            (0, "array_agg(link.memory_id ORDER BY link.memory_id)"),
            (0, "array_agg(link.memory_sha256 ORDER BY link.memory_id)"),
            (0, "array_agg(link.evidence_id ORDER BY link.evidence_id)"),
            (
                0,
                "array_agg(link.evidence_sha256 ORDER BY link.evidence_id)",
            ),
            (1, "migration_id = \"0137_project_continuity_read\""),
            (
                1,
                "to_regprocedure('private.read_continuity_project_storage_v1(uuid,uuid,uuid,uuid,uuid,uuid[])') is null",
            ),
            (1, "to_regclass('private.continuity_projects') is not null"),
            (1, "private.publish_continuity_facet("),
            (
                1,
                "select count(*)=1 from reader where prosecdef and provolatile='s'",
            ),
            (1, "array['search_path=pg_catalog']::text[]"),
            (1, "pg_get_userbyid(proowner)='role_migration_owner'"),
            (1, "not has_function_privilege('public'"),
            (1, "role.name='role_gateway'"),
            (1, "SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER"),
            (1, "strpos(definition,'INSERT ') = 0"),
            (
                2,
                "pub const W2_FORCED_UNAVAILABLE: [ContinuityFacetKind; 6]",
            ),
            (2, "humaux.continuity.result.v1\\0"),
            (2, "if accounted != 17"),
            (2, "if counts[0] == 17 && !closed.handoff.counts.overflow"),
            (
                3,
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            ),
            (3, "let frozen = fetch_frozen_in_txn"),
            (3, "TOMBSTONED"),
            (3, "install_lookup_context(&mut tx, authorization).await?;"),
            (3, "install_workspace_context(&mut tx, workspace).await?;"),
            (3, "count(stream.commit_seq) AS association_count"),
            (3, "let body_sha256 = digest(raw.stored_body_sha256)?;"),
            (5, "WorkspaceAdmission::PreserveContinuityFilter => None"),
            (5, "operation.operation_key() != \"continuity.get\""),
            (6, "catalog.validate_output(ToolName::Continuity, &value)"),
            (6, "SUPPORTED_OPERATION_KEYS: [&str; 27]"),
            (6, "\"continuity.get\" =>"),
        ] {
            let mut broken = sources.clone();
            broken[index] = broken[index].replacen(needle, "", 1);
            assert!(
                matches!(
                    w2_continuity_contract_from(
                        &broken[0], &broken[1], &broken[2], &broken[3], &broken[4], &broken[5],
                        &broken[6]
                    ),
                    Verdict::Fail(_)
                ),
                "mutation removing `{needle}` must fail the actual W2 gate"
            );
        }
    }

    // ------------------------------------------------------------------
    // card 22 — §33 tool surface truth
    // ------------------------------------------------------------------

    fn tool_surface_sources() -> (String, String, BTreeSet<String>) {
        let root = real_root();
        (
            fs::read_to_string(root.join("bins/gateway/src/mcp_application.rs")).unwrap(),
            fs::read_to_string(root.join("docs/architecture/Baseline_2.9.md")).unwrap(),
            catalog_operation_keys(&root).unwrap(),
        )
    }

    #[test]
    fn mcp_tool_surface_truth_real_sources_are_green() {
        let (dispatch, baseline, catalog) = tool_surface_sources();
        assert_eq!(
            mcp_tool_surface_truth_from(&dispatch, &baseline, &catalog),
            Verdict::Pass
        );
    }

    /// The array, the dispatch, the document and the catalog are four independent places; the
    /// gate exists because one of them drifting silently is exactly what happened (card 22
    /// found `memory.correct` / `memory.confirm` / `memory.reject` dispatched for two ADRs
    /// while the array still said 15). Every single-place mutation must be red.
    #[test]
    fn mcp_tool_surface_truth_faults_every_single_place_drift() {
        let (dispatch, baseline, catalog) = tool_surface_sources();

        // (1) the array loses a key the dispatch still routes.
        let shrunk = dispatch
            .replace("    DestructiveOp::MemoryConfirm.operation_key(),\n", "")
            .replace(
                "SUPPORTED_OPERATION_KEYS: [&str; 27]",
                "SUPPORTED_OPERATION_KEYS: [&str; 26]",
            );
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&shrunk, &baseline, &catalog),
                Verdict::Fail(_)
            ),
            "dropping a dispatched key from SUPPORTED_OPERATION_KEYS must fail"
        );

        // (2) the array's declared length stops matching its entries.
        let miscounted = dispatch.replace(
            "SUPPORTED_OPERATION_KEYS: [&str; 27]",
            "SUPPORTED_OPERATION_KEYS: [&str; 28]",
        );
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&miscounted, &baseline, &catalog),
                Verdict::Fail(_)
            ),
            "a declared length that disagrees with the entries must fail"
        );

        // (3) the document drops a wired key.
        let doc_short = baseline.replacen("\nmemory.annotate_affect\n", "\n", 1);
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&dispatch, &doc_short, &catalog),
                Verdict::Fail(_)
            ),
            "a wired key missing from §33's table must fail"
        );

        // (4) the document calls a wired key declared-only — the exact shape that makes an
        //     honest fail-closed refusal look like a bug, and vice versa.
        let doc_moved = baseline.replacen("\nmemory.pin\n", "\n", 1).replacen(
            "\nremember.put_batch\n",
            "\nremember.put_batch\nmemory.pin\n",
            1,
        );
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&dispatch, &doc_moved, &catalog),
                Verdict::Fail(_)
            ),
            "moving a wired key into the declared-only block must fail"
        );

        // (5) the catalog grows a route the document names nowhere.
        let mut wider = catalog.clone();
        wider.insert("coordinate.canvas_delete".to_string());
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&dispatch, &baseline, &wider),
                Verdict::Fail(_)
            ),
            "an undocumented catalog operation key must fail"
        );

        // (6) the marked blocks themselves are load-bearing.
        let unmarked = baseline.replacen("<!-- humaux:wired-operation-keys:begin -->", "", 1);
        assert!(
            matches!(
                mcp_tool_surface_truth_from(&dispatch, &unmarked, &catalog),
                Verdict::Fail(_)
            ),
            "removing the wired-key block marker must fail, not silently pass"
        );
    }

    /// `not_applicable` (never `pass`) when a source object is absent — §57.1 第2条.
    #[test]
    fn mcp_tool_surface_truth_is_not_applicable_without_its_sources() {
        assert_eq!(
            mcp_tool_surface_truth(Path::new("/nonexistent-humaux-root")),
            Verdict::NotApplicable("bins/gateway/src/mcp_application.rs".to_string())
        );
    }

    /// …but a contract that is PRESENT and shaped differently is not an absent object, and
    /// letting it degrade to `not_applicable` made the catalog leg switchable off by a contract
    /// edit while the run still exited 0. `oneOf` → `anyOf` in one schema must be red.
    #[test]
    fn mcp_tool_surface_truth_faults_a_present_but_malformed_contract() {
        let root = real_root();
        let tmp = std::env::temp_dir().join(format!(
            "arch-check-catalog-malformed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // A root whose non-contract sources are the real ones, so the ONLY变量 is the contract.
        fs::create_dir_all(tmp.join("bins/gateway/src")).unwrap();
        fs::create_dir_all(tmp.join("docs/architecture")).unwrap();
        fs::create_dir_all(tmp.join("contracts/mcp")).unwrap();
        for path in [
            "bins/gateway/src/mcp_application.rs",
            "docs/architecture/Baseline_2.9.md",
        ] {
            fs::copy(root.join(path), tmp.join(path)).unwrap();
        }
        for entry in fs::read_dir(root.join("contracts/mcp")).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                fs::copy(
                    entry.path(),
                    tmp.join("contracts/mcp").join(entry.file_name()),
                )
                .unwrap();
            }
        }
        // Control: the copied tree is green before the mutation.
        assert_eq!(mcp_tool_surface_truth(&tmp), Verdict::Pass);

        let victim = tmp.join("contracts/mcp/coordinate.schema.json");
        let mutated = fs::read_to_string(&victim)
            .unwrap()
            .replacen("\"oneOf\"", "\"anyOf\"", 1);
        fs::write(&victim, mutated).unwrap();
        let verdict = mcp_tool_surface_truth(&tmp);
        assert!(
            matches!(verdict, Verdict::Fail(_)),
            "a present-but-unreadable contract must fail the gate, not switch it off: {verdict:?}"
        );

        // And unreadable-because-not-JSON is the same class.
        fs::write(&victim, "{ not json").unwrap();
        assert!(matches!(mcp_tool_surface_truth(&tmp), Verdict::Fail(_)));

        // …while an ABSENT contract is still §57.1's not_applicable.
        fs::remove_file(&victim).unwrap();
        assert_eq!(
            mcp_tool_surface_truth(&tmp),
            Verdict::NotApplicable("contracts/mcp/coordinate.schema.json".to_string())
        );
        fs::remove_dir_all(&tmp).ok();
    }

    // ------------------------------------------------------------------
    // card 22 review fix — x-humaux-v1-supported ↔ the recall.rs lane guard
    // ------------------------------------------------------------------

    fn recall_lane_sources() -> (String, String) {
        let root = real_root();
        (
            fs::read_to_string(root.join("contracts/mcp/recall.schema.json")).unwrap(),
            fs::read_to_string(root.join("bins/gateway/src/recall.rs")).unwrap(),
        )
    }

    #[test]
    fn recall_v1_supported_lanes_real_sources_are_green() {
        let (schema, guard) = recall_lane_sources();
        assert_eq!(
            recall_v1_supported_lanes_from(&schema, &guard),
            Verdict::Pass
        );
    }

    /// The mutation the review named: deleting `"semantic"` from `x-humaux-v1-supported` used
    /// to leave every gate green, which is what made the key inert. Every single-place drift
    /// between the declaration and the guard must now be red.
    #[test]
    fn recall_v1_supported_lanes_faults_every_single_place_drift() {
        let (schema, guard) = recall_lane_sources();

        for (label, mutated) in [
            (
                "the declaration drops the one supported mode",
                schema.replacen(
                    r#""x-humaux-v1-supported":["semantic"]"#,
                    r#""x-humaux-v1-supported":[]"#,
                    1,
                ),
            ),
            (
                "the declaration claims a lane the guard refuses",
                schema.replacen(
                    r#""x-humaux-v1-supported":["semantic"]"#,
                    r#""x-humaux-v1-supported":["semantic","literal"]"#,
                    1,
                ),
            ),
            (
                "the declaration claims a completeness value the guard refuses",
                schema.replacen(
                    r#""x-humaux-v1-supported":["best_effort"]"#,
                    r#""x-humaux-v1-supported":["best_effort","required"]"#,
                    1,
                ),
            ),
            (
                "x-humaux-v1-supported names a value outside the closed enum",
                schema.replacen(
                    r#""x-humaux-v1-supported":["semantic"]"#,
                    r#""x-humaux-v1-supported":["semantic","sql"]"#,
                    1,
                ),
            ),
        ] {
            let verdict = recall_v1_supported_lanes_from(&mutated, &guard);
            assert!(matches!(verdict, Verdict::Fail(_)), "{label}: {verdict:?}");
        }

        for (label, mutated) in [
            (
                "the guard starts accepting a lane the declaration does not",
                guard.replacen(
                    r#"mode != "semantic""#,
                    r#"!matches!(mode, "semantic" | "literal")"#,
                    1,
                ),
            ),
            (
                "the guard stops refusing completeness_request = required",
                guard.replacen(
                    r#"|| input.completeness_request.as_deref() == Some("required")"#,
                    "",
                    1,
                ),
            ),
            (
                "the guard refuses the only supported mode",
                guard.replacen(r#"mode != "semantic""#, r#"mode != "literal""#, 1),
            ),
        ] {
            let verdict = recall_v1_supported_lanes_from(&schema, &mutated);
            assert!(matches!(verdict, Verdict::Fail(_)), "{label}: {verdict:?}");
        }

        // The guard itself disappearing is red, not a silent pass.
        let no_guard = guard.replacen("return Err(ErrorCode::DependencyUnavailable);", "", 1);
        assert!(matches!(
            recall_v1_supported_lanes_from(&schema, &no_guard),
            Verdict::Fail(_)
        ));

        // Positive control for the other direction — the day a lane is actually delivered, the
        // declaration grows to the whole enum AND the clause goes away, together. That pair is
        // the only green way out, so the gate cannot be read as "the guard must always refuse".
        let delivered_schema = schema.replacen(
            r#""x-humaux-v1-supported":["best_effort"]"#,
            r#""x-humaux-v1-supported":["best_effort","required"]"#,
            1,
        );
        let delivered_guard = guard.replacen(
            r#"|| input.completeness_request.as_deref() == Some("required")"#,
            "",
            1,
        );
        assert_eq!(
            recall_v1_supported_lanes_from(&delivered_schema, &delivered_guard),
            Verdict::Pass,
            "declaring a value supported and deleting its refusal in the same change is green"
        );
    }

    #[test]
    fn recall_v1_supported_lanes_is_not_applicable_without_its_sources() {
        assert_eq!(
            recall_v1_supported_lanes(Path::new("/nonexistent-humaux-root")),
            Verdict::NotApplicable("contracts/mcp/recall.schema.json".to_string())
        );
    }

    #[test]
    fn r3_health_contract_real_migration_is_green() {
        let source = fs::read_to_string(
            real_root().join("migrations/0130_reasoning_route_health_admission.sql"),
        )
        .unwrap();
        assert_eq!(r3_health_migration_contract(&source), Verdict::Pass);
    }

    #[test]
    fn r3_health_contract_faults_current_projection_latest_order_and_fallback() {
        let source = fs::read_to_string(
            real_root().join("migrations/0130_reasoning_route_health_admission.sql"),
        )
        .unwrap();
        for (label, broken) in [
            (
                "current projection",
                format!("{source}\nCREATE TABLE ops.provider_health_current ();"),
            ),
            (
                "latest order",
                source.replacen(
                    "ORDER BY observation.observed_at DESC, observation.observation_id DESC",
                    "ORDER BY observation.observation_id DESC",
                    1,
                ),
            ),
            (
                "fallback candidate",
                source.replacen(
                    "candidate.fallback_class = 'NONE'",
                    "candidate.fallback_class = 'ANY'",
                    1,
                ),
            ),
            (
                "health audit receipt",
                source.replacen(
                    "source_kind text NOT NULL CHECK (btrim(source_kind) <> ''),",
                    "source_kind text,",
                    1,
                ),
            ),
        ] {
            assert!(
                matches!(r3_health_migration_contract(&broken), Verdict::Fail(_)),
                "{label} fault escaped"
            );
        }
    }

    fn r3_contribution_runtime_fixture() -> (&'static str, &'static str, &'static str, &'static str)
    {
        (
            "async fn resolve_and_reserve_reasoning_call() { load_with_admission(); let permit = authorize(admission.egress_processor_id); reserve_reasoning_call_in_txn(); reserve_reasoning_in_txn(); txn.commit(); }\nasync fn finalize_reasoning_call() { finalize_reasoning_in_txn(); finalize_reasoning_call_in_txn(); txn.commit(); }\nasync fn call_structured() { resolve_and_reserve_reasoning_call(); complete_structured(); self.finalize_reasoning_call(); }",
            "async fn reserve_reasoning_call_in_txn() { locator.egress_processor_id; }\nasync fn finalize_reasoning_call_in_txn() {}\negress_processor_id",
            "async fn reserve_reasoning_in_txn(model_call_id: Uuid) { model_call_id; reserve_in_txn(); }\nasync fn finalize_reasoning_in_txn() {}\nmodel_call_id",
            "fn endpoint_ref() {}",
        )
    }

    #[test]
    fn r3_contribution_runtime_contract_accepts_atomic_reserve_and_finalize_order() {
        let (contribution, ledger, disclosure, byok) = r3_contribution_runtime_fixture();
        assert_eq!(
            r3_contribution_runtime_contract(contribution, ledger, disclosure, byok),
            Verdict::Pass
        );
    }

    #[test]
    fn r3_contribution_runtime_contract_faults_reversed_reserves_and_config_authority() {
        let (contribution, ledger, disclosure, byok) = r3_contribution_runtime_fixture();
        let provider_before_reserve = contribution.replacen(
            "reserve_reasoning_call_in_txn(); reserve_reasoning_in_txn();",
            "reserve_reasoning_in_txn(); reserve_reasoning_call_in_txn();",
            1,
        );
        assert!(matches!(
            r3_contribution_runtime_contract(&provider_before_reserve, ledger, disclosure, byok),
            Verdict::Fail(_)
        ));
        let config_authority = contribution.replacen(
            "authorize(admission.egress_processor_id)",
            "authorize(self.config.allowed_egress_processor_id)",
            1,
        );
        assert!(matches!(
            r3_contribution_runtime_contract(&config_authority, ledger, disclosure, byok),
            Verdict::Fail(_)
        ));
    }

    fn r3_contribution_runtime_shared_helper_fixture() -> String {
        concat!(
            "async fn resolve_and_reserve_reasoning_call() { load_with_admission(); ",
            "let (wire_payload, permit) = authorize_structured_egress(tenant_id, &admission, &descriptor); ",
            "reserve_reasoning_call_in_txn(); reserve_reasoning_in_txn(); txn.commit() }\n",
            "async fn call_structured() { self.resolve_and_reserve_reasoning_call(); ",
            "complete_structured_timed(self.provider); self.finalize_reasoning_call() }\n",
            "async fn finalize_reasoning_call() { finalize_reasoning_in_txn(); ",
            "finalize_reasoning_call_in_txn(); txn.commit() }\n",
            "pub(crate) fn authorize_structured_egress() { let permit = authorize(admission.egress_processor_id); }\n",
            "pub(crate) async fn complete_structured_timed() { provider.complete_structured(context, request).await }\n",
        )
        .to_string()
    }

    #[test]
    fn r3_contribution_runtime_contract_follows_shared_helpers_one_level() {
        let (_, ledger, disclosure, byok) = r3_contribution_runtime_fixture();
        let contribution = r3_contribution_runtime_shared_helper_fixture();
        assert_eq!(
            r3_contribution_runtime_contract(&contribution, ledger, disclosure, byok),
            Verdict::Pass
        );
        for (label, broken) in [
            (
                "helper authorizes with config processor",
                contribution.replacen(
                    "authorize(admission.egress_processor_id)",
                    "authorize(self.config.allowed_egress_processor_id)",
                    1,
                ),
            ),
            (
                "reserve leg passes a non-resolver admission",
                contribution.replacen("&admission, &descriptor", "&self.config, &descriptor", 1),
            ),
            (
                "timed helper grows a retry loop",
                contribution.replacen(
                    "provider.complete_structured(context, request).await",
                    "loop { provider.complete_structured(context, request).await }",
                    1,
                ),
            ),
        ] {
            assert!(
                matches!(
                    r3_contribution_runtime_contract(&broken, ledger, disclosure, byok),
                    Verdict::Fail(_)
                ),
                "{label} fault escaped"
            );
        }
    }

    #[test]
    fn r3_idempotency_contract_real_sources_are_green() {
        let root = real_root();
        let contribution =
            fs::read_to_string(root.join("crates/adapters/src/contribution_reasoner.rs")).unwrap();
        let ledger =
            fs::read_to_string(root.join("crates/adapters/src/model_call_ledger.rs")).unwrap();
        let application =
            fs::read_to_string(root.join("crates/application/src/consolidate.rs")).unwrap();
        let contribute =
            fs::read_to_string(root.join("crates/application/src/contribute.rs")).unwrap();
        let pg_tests = fs::read_to_string(
            root.join("crates/adapters/tests/reasoning_route_health_admission.rs"),
        )
        .unwrap();
        assert_eq!(
            r3_contribution_idempotency_contract(
                &contribution,
                &ledger,
                &application,
                &contribute,
                &pg_tests,
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn r3_idempotency_contract_faults_reasoner_minted_key_and_late_lookup() {
        let root = real_root();
        let contribution =
            fs::read_to_string(root.join("crates/adapters/src/contribution_reasoner.rs")).unwrap();
        let ledger =
            fs::read_to_string(root.join("crates/adapters/src/model_call_ledger.rs")).unwrap();
        let application =
            fs::read_to_string(root.join("crates/application/src/consolidate.rs")).unwrap();
        let contribute =
            fs::read_to_string(root.join("crates/application/src/contribute.rs")).unwrap();
        let pg_tests = fs::read_to_string(
            root.join("crates/adapters/tests/reasoning_route_health_admission.rs"),
        )
        .unwrap();
        for broken in [
            format!("Uuid::now_v7();\n{contribution}"),
            contribution.replacen("lookup_reasoning_call_in_txn", "lookup_removed", 1),
        ] {
            assert!(matches!(
                r3_contribution_idempotency_contract(
                    &broken,
                    &ledger,
                    &application,
                    &contribute,
                    &pg_tests,
                ),
                Verdict::Fail(_)
            ));
        }
        let typed_without_coverage = application.replacen(
            "ContributionReasoningCallKind::TypedAssessment, Some(_)",
            "ContributionReasoningCallKind::TypedAssessment, None",
            1,
        );
        assert!(matches!(
            r3_contribution_idempotency_contract(
                &contribution,
                &ledger,
                &typed_without_coverage,
                &contribute,
                &pg_tests,
            ),
            Verdict::Fail(_)
        ));
        let unversioned_intent =
            application.replacen("b\"intent_schema_version\\0\"", "b\"version\\0\"", 1);
        assert!(matches!(
            r3_contribution_idempotency_contract(
                &contribution,
                &ledger,
                &unversioned_intent,
                &contribute,
                &pg_tests,
            ),
            Verdict::Fail(_)
        ));
        let request_only_lock = ledger.replacen(
            "'model-call-request:' || $1::uuid::text || ':' || $2::uuid::text",
            "'model-call-request:' || $2::uuid::text",
            1,
        );
        assert!(matches!(
            r3_contribution_idempotency_contract(
                &contribution,
                &request_only_lock,
                &application,
                &contribute,
                &pg_tests,
            ),
            Verdict::Fail(_)
        ));
        let nil_allowed = contribution.replacen("attempt.logical_call_id.0.is_nil()", "false", 1);
        assert!(matches!(
            r3_contribution_idempotency_contract(
                &nil_allowed,
                &ledger,
                &application,
                &contribute,
                &pg_tests,
            ),
            Verdict::Fail(_)
        ));
    }

    // -- §53.3 规则1/规则3: scan_outcome_fallback_violations ------------------------------

    #[test]
    fn rule1_flags_unwrap_or_default_outside_abstain() {
        let src = "fn pick(pool: &[i32]) -> Outcome<i32> {\n    let c = pool.first().copied().unwrap_or_default();\n    Outcome::Decided(c)\n}\n";
        let hits = scan_outcome_fallback_violations("f.rs", src);
        assert_eq!(hits.len(), 1, "{hits:?}");
    }

    #[test]
    fn rule1_flags_unwrap_or_paren() {
        let src = "fn r(x: Option<i32>) -> Outcome<i32> {\n    let v = x.unwrap_or(0);\n    Outcome::Decided(v)\n}\n";
        assert_eq!(scan_outcome_fallback_violations("f.rs", src).len(), 1);
    }

    #[test]
    fn rule1_flags_ok_none() {
        let src = "fn l() -> Outcome<Result<Option<i32>, E>> {\n    return Outcome::Decided(Ok(None));\n}\n";
        assert_eq!(scan_outcome_fallback_violations("f.rs", src).len(), 1);
    }

    #[test]
    fn rule1_flags_ok_vec_new() {
        let src = "fn l() -> Outcome<Result<Vec<i32>, E>> {\n    return Outcome::Decided(Ok(Vec::new()));\n}\n";
        assert_eq!(scan_outcome_fallback_violations("f.rs", src).len(), 1);
    }

    #[test]
    fn rule1_allows_fallback_on_the_abstain_call_chain() {
        let src = "fn r(x: Option<i32>) -> Outcome<i32> {\n    x.map(Outcome::Decided).unwrap_or_else(|| abstain(DegradeCode::X, 0))\n}\n";
        assert!(scan_outcome_fallback_violations("f.rs", src).is_empty());
    }

    #[test]
    fn rule1_ignores_functions_not_returning_outcome() {
        let src = "fn plain(x: Option<i32>) -> i32 {\n    x.unwrap_or_default()\n}\n";
        assert!(scan_outcome_fallback_violations("f.rs", src).is_empty());
    }

    #[test]
    fn rule1_ignores_comment_mentioning_the_pattern() {
        let src = "// example: unwrap_or_default() inside Outcome<T> is forbidden\nfn real() -> Outcome<i32> {\n    Outcome::Decided(1)\n}\n";
        assert!(scan_outcome_fallback_violations("f.rs", src).is_empty());
    }

    #[test]
    fn rule1_real_repo_source_is_clean() {
        // §80.1 准入条件的另一半：真实代码今天必须是绿的，不是靠样本硬凑出来的绿。
        let root = real_root();
        assert_eq!(rule1_forbidden_fallback(&root), Verdict::Pass);
    }

    // -- §53.3 规则3: real sentinels hit exactly 3 -----------------------------------------

    #[test]
    fn rule3_real_sentinels_hit_exactly_three() {
        let root = real_root();
        assert_eq!(rule3_positive_sentinels(&root), Verdict::Pass);
    }

    /// 注错 (G80-1, §80.1.1): rename `sentinels/` away → 0 hits ≠ 3 → red. Uses a tempdir
    /// copy of the real fixtures, never the repo's own sentinels/ directory.
    #[test]
    fn rule3_fault_renamed_sentinels_dir_is_red() {
        let tmp = std::env::temp_dir().join(format!(
            "arch-check-rule3-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(tmp.join("crates/testkit/sentinels_renamed")).unwrap();
        // deliberately NOT named "sentinels" — simulates the injected fault.
        let verdict = rule3_positive_sentinels(&tmp);
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照：把真实 3 个正哨兵样本复制进 tempdir 的正确路径 → 必须绿，证明红转绿真的
    /// 是「目录名」这一个变量在起作用，不是 fixture 本身写死了红。
    #[test]
    fn rule3_fixture_copy_at_correct_path_is_green() {
        let root = real_root();
        let real_sentinels = root.join("crates/testkit/sentinels");
        let tmp = std::env::temp_dir().join(format!(
            "arch-check-rule3-green-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let dest = tmp.join("crates/testkit/sentinels");
        fs::create_dir_all(&dest).unwrap();
        for entry in fs::read_dir(&real_sentinels).unwrap().flatten() {
            let p = entry.path();
            fs::copy(&p, dest.join(p.file_name().unwrap())).unwrap();
        }
        assert_eq!(rule3_positive_sentinels(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §53.3 规则2 ---------------------------------------------------------------------

    #[test]
    fn pascal_to_snake_matches_spec_examples() {
        assert_eq!(
            pascal_to_snake("ProjectionInvisibleLoss"),
            "projection_invisible_loss"
        );
        assert_eq!(
            pascal_to_snake("RerankProviderTimeout"),
            "rerank_provider_timeout"
        );
    }

    #[test]
    fn parse_degrade_variant_names_matches_real_degrade_rs() {
        let root = real_root();
        let src = fs::read_to_string(root.join("crates/telemetry/src/degrade.rs")).unwrap();
        let variants = parse_degrade_variant_names(&src);
        // T-RET-6c-1 (ADR-0083 D-C) added `SparseLaneUnavailable`: Baseline §53.2 now lists 12 variants.
        assert_eq!(variants.len(), 12, "{variants:?}");
        assert!(variants.contains(&"ProjectionInvisibleLoss".to_string()));
        assert!(variants.contains(&"LaneSubstituted".to_string()));
        assert!(variants.contains(&"SparseLaneUnavailable".to_string()));
        assert!(variants.contains(&"RerankProviderTimeout".to_string()));
    }

    #[test]
    fn rule2_check_passes_when_names_match_exactly() {
        let variants = vec!["FooBar".to_string(), "Baz".to_string()];
        let mut stems = BTreeSet::new();
        stems.insert("foo_bar".to_string());
        stems.insert("baz".to_string());
        assert_eq!(rule2_check(&variants, &stems), Verdict::Pass);
    }

    /// T0.4 (§53.4 fault test files) lands in the same wave as this checker, in parallel —
    /// an oracle test rather than a hardcoded verdict: independently re-derives the expected
    /// verdict from the same two real inputs (`degrade.rs`'s variant list, the live
    /// `tests/fault/` directory listing) via [`rule2_check`], and asserts the wired-up
    /// [`rule2_degrade_fault_parity`] agrees — true whether T0.4 has landed yet or not, so it
    /// can't go stale/racy against the other group's concurrent progress (task hard rule ⑤:
    /// never weaken the judgment to chase "currently green").
    #[test]
    fn rule2_real_repo_matches_independently_recomputed_expectation() {
        let root = real_root();
        let degrade_src = fs::read_to_string(root.join("crates/telemetry/src/degrade.rs")).unwrap();
        let variants = parse_degrade_variant_names(&degrade_src);
        let fault_dir = root.join("crates/testkit/tests/fault");
        let stems: BTreeSet<String> = fs::read_dir(&fault_dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                    p.file_stem().and_then(|s| s.to_str()).map(String::from)
                } else {
                    None
                }
            })
            .collect();
        let expected = rule2_check(&variants, &stems);
        assert_eq!(rule2_degrade_fault_parity(&root), expected);
    }

    /// 注错: fault file present for a variant that no longer exists in DegradeCode → 红
    /// (orphaned fault file, extra != []).
    #[test]
    fn rule2_fault_orphaned_fault_file_is_red() {
        let variants = vec!["FooBar".to_string()];
        let mut stems = BTreeSet::new();
        stems.insert("foo_bar".to_string());
        stems.insert("stale_variant".to_string());
        assert!(matches!(rule2_check(&variants, &stems), Verdict::Fail(_)));
    }

    // -- §52.4 G52-1 ---------------------------------------------------------------------

    #[test]
    fn find_error_code_field_types_captures_pascal_case_type() {
        let src = "struct M {\n    pub error_code: ErrorCode,\n}\n";
        assert_eq!(
            find_error_code_field_types(src),
            vec!["ErrorCode".to_string()]
        );
    }

    #[test]
    fn find_error_code_field_types_ignores_lowercase_value_construction() {
        let src = "M { error_code: code, other: 1 }";
        assert!(find_error_code_field_types(src).is_empty());
    }

    #[test]
    fn find_error_code_field_types_ignores_str_field() {
        let src = "struct P {\n    pub error_code: &'static str,\n}\n";
        assert!(find_error_code_field_types(src).is_empty());
    }

    #[test]
    fn find_error_code_field_types_ignores_error_codes_plural() {
        let src = "let error_codes: std::collections::HashSet<&str> = HashSet::new();";
        assert!(find_error_code_field_types(src).is_empty());
    }

    #[test]
    fn g52_1_check_passes_on_exactly_error_code() {
        let mut set = BTreeSet::new();
        set.insert("ErrorCode".to_string());
        assert_eq!(g52_1_check(&set), Verdict::Pass);
    }

    #[test]
    fn g52_1_check_fails_on_empty_set_positive_control_missing() {
        assert!(matches!(g52_1_check(&BTreeSet::new()), Verdict::Fail(_)));
    }

    /// 注错: a second enum (e.g. `crates/billing::BillingError`) shows up at an
    /// `error_code` position → red (§52.4 G52-1's own named injection).
    #[test]
    fn g52_1_check_fails_when_second_enum_present() {
        let mut set = BTreeSet::new();
        set.insert("ErrorCode".to_string());
        set.insert("BillingError".to_string());
        assert!(matches!(g52_1_check(&set), Verdict::Fail(_)));
    }

    #[test]
    fn g52_1_real_repo_passes() {
        let root = real_root();
        assert_eq!(g52_1_error_code_uniqueness(&root), Verdict::Pass);
    }

    // -- §59.1 G59-3 ---------------------------------------------------------------------

    #[test]
    fn find_authority_struct_literals_matches_bare_authority_brace() {
        let src = "let a = Authority { class, confidence };";
        assert_eq!(find_authority_struct_literals(src).len(), 1);
    }

    #[test]
    fn find_authority_struct_literals_ignores_authority_class() {
        let src = "let c = AuthorityClass::PublicKnowledge; let s = AuthorityStatus::Active; let p = AuthorityPolicy {};";
        assert!(find_authority_struct_literals(src).is_empty());
    }

    #[test]
    fn find_authority_struct_literals_ignores_comment() {
        let src = "// Authority { .. } must be built only by Authority::new\nlet x = 1;";
        assert!(find_authority_struct_literals(src).is_empty());
    }

    #[test]
    fn g59_3_check_fails_on_zero_hits() {
        assert!(matches!(g59_3_check(&[], None), Verdict::Fail(_)));
    }

    /// 注错 a (§59.1 G59-3): a second `Authority {` literal appears in `evals/` → count 1→2 → 红.
    #[test]
    fn g59_3_check_fails_on_two_hits() {
        let hits = vec![
            ("crates/domain/src/authority.rs".to_string(), 100),
            ("evals/probe.rs".to_string(), 5),
        ];
        assert!(matches!(
            g59_3_check(&hits, Some((0, 200))),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn g59_3_check_fails_when_sole_hit_outside_new() {
        let hits = vec![("crates/domain/src/authority.rs".to_string(), 500)];
        // range (0,200) does not contain 500 -> outside new()
        assert!(matches!(
            g59_3_check(&hits, Some((0, 200))),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn g59_3_check_passes_when_sole_hit_inside_new_in_authority_rs() {
        let hits = vec![("crates/domain/src/authority.rs".to_string(), 150)];
        assert_eq!(g59_3_check(&hits, Some((100, 200))), Verdict::Pass);
    }

    #[test]
    fn authority_new_body_range_finds_real_shape() {
        let src = "impl Authority {\n    pub fn new(x: i32) -> Self {\n        Authority { x }\n    }\n}\n";
        let range = authority_new_body_range(src);
        assert!(range.is_some());
        let (s, e) = range.unwrap();
        let hit = find_authority_struct_literals(src)[0];
        assert!((s..e).contains(&hit), "hit {hit} not in range {s}..{e}");
    }

    /// T0.7 has landed `Authority::new` as the sole real construction point (`crates/domain/src
    /// /authority.rs`) — this must be a hard `Pass`, not a Fail/Pass-both-accepted assertion.
    /// A tautological version of this test (accepting either verdict) would keep passing even
    /// while the matcher itself is broken, exactly the "恒真闸" shape §59.1 exists to rule out.
    #[test]
    fn g59_3_real_repo_hits_exactly_once_inside_authority_new() {
        let root = real_root();
        assert_eq!(g59_3_authority_construction_point(&root), Verdict::Pass);
    }

    // -- §78.3 Workspace Dependency Rule ---------------------------------------------------

    fn metadata_fixture(domain_deps: &[&str]) -> String {
        let dom: Vec<String> = domain_deps
            .iter()
            .map(|d| format!(r#"{{"name":"{d}"}}"#))
            .collect();
        format!(
            r#"{{"packages":[{{"name":"humaux-domain","dependencies":[{}]}}]}}"#,
            dom.join(",")
        )
    }

    #[test]
    fn dependency_rule_passes_on_clean_fixture() {
        let json = metadata_fixture(&["uuid"]);
        assert_eq!(dependency_rule_from_metadata_json(&json), Verdict::Pass);
    }

    /// 注错 (§78.3): domain gains an sqlx dependency → red.
    #[test]
    fn dependency_rule_fails_when_domain_depends_on_sqlx() {
        let json = metadata_fixture(&["uuid", "sqlx"]);
        assert!(matches!(
            dependency_rule_from_metadata_json(&json),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn dependency_rule_fails_on_sdk_substring_catch_all() {
        let json = metadata_fixture(&["aws-sdk-dynamodb"]);
        assert!(matches!(
            dependency_rule_from_metadata_json(&json),
            Verdict::Fail(_)
        ));
    }

    /// 注错 (§78.3): domain gains a dashscope dependency → red (the item the old list was
    /// missing entirely — §78.3's verbatim seven-item list names it).
    #[test]
    fn dependency_rule_fails_when_domain_depends_on_dashscope() {
        let json = metadata_fixture(&["dashscope"]);
        assert!(matches!(
            dependency_rule_from_metadata_json(&json),
            Verdict::Fail(_)
        ));
    }

    /// 注错 (Architecture Boundary Lints 第1行 "adapters/protocol/runtime"): domain gains a
    /// humaux-protocol dependency → red.
    #[test]
    fn dependency_rule_fails_when_domain_depends_on_protocol() {
        let json = metadata_fixture(&["humaux-protocol"]);
        assert!(matches!(
            dependency_rule_from_metadata_json(&json),
            Verdict::Fail(_)
        ));
    }

    /// §59.1 G59-3 同款「恒真闸」: `humaux-domain` absent from the metadata document must be a
    /// red, not a silent pass — a matcher whose target package went missing must never read as
    /// "nothing to report".
    #[test]
    fn dependency_rule_fails_when_domain_package_missing_from_metadata() {
        let json = r#"{"packages":[{"name":"humaux-application","dependencies":[]}]}"#;
        assert!(matches!(
            dependency_rule_from_metadata_json(json),
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn dependency_rule_real_repo_passes() {
        let root = real_root();
        assert_eq!(dependency_rule_check(&root), Verdict::Pass);
    }

    // -- M01 D1 / ADR-0074 edition gates (G-M01-1, G-M01-2) --------------------------------

    fn ed_dep(name: &str, kind: Option<&str>) -> serde_json::Value {
        serde_json::json!({"name": name, "kind": kind, "optional": false})
    }

    fn ed_pkg(
        name: &str,
        edition: Option<&str>,
        deps: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        let metadata = edition.map_or(
            serde_json::Value::Null,
            |e| serde_json::json!({"humaux": {"edition": e}}),
        );
        serde_json::json!({"name": name, "metadata": metadata, "dependencies": deps})
    }

    fn ed_doc(pkgs: &[serde_json::Value]) -> String {
        serde_json::json!({ "packages": pkgs }).to_string()
    }

    fn ownership_rows(names: &[&str]) -> String {
        let rows: String = names.iter().map(|n| format!("{n} = \"M01\"\n")).collect();
        format!("[crates]\n{rows}")
    }

    fn fail_lines(v: Verdict) -> String {
        match v {
            Verdict::Fail(lines) => lines.join("\n"),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn g_m01_1_passes_when_members_equal_rows_and_editions_valid() {
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![]),
            ed_pkg("b", Some("cloud"), vec![]),
        ]);
        assert_eq!(
            workspace_members_from(&doc, &ownership_rows(&["a", "b"])),
            Verdict::Pass
        );
    }

    /// 注错 (G-M01-1): a member without an edition → red naming it.
    #[test]
    fn g_m01_1_fails_naming_a_member_without_edition() {
        let doc = ed_doc(&[ed_pkg("a", Some("core"), vec![]), ed_pkg("b", None, vec![])]);
        let out = fail_lines(workspace_members_from(&doc, &ownership_rows(&["a", "b"])));
        assert!(
            out.contains("package `b` has no [package.metadata.humaux] edition"),
            "{out}"
        );
        assert!(!out.contains("`a`"), "{out}");
    }

    #[test]
    fn g_m01_1_fails_on_an_unknown_edition_value() {
        let doc = ed_doc(&[ed_pkg("a", Some("enterprise"), vec![])]);
        let out = fail_lines(workspace_members_from(&doc, &ownership_rows(&["a"])));
        assert!(
            out.contains("package `a` declares unknown edition `enterprise`"),
            "{out}"
        );
    }

    /// 注错 (G-M01-1): a member deleted from module_ownership.toml → red naming it.
    #[test]
    fn g_m01_1_fails_on_a_member_missing_from_the_ownership_file() {
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![]),
            ed_pkg("b", Some("core"), vec![]),
        ]);
        let out = fail_lines(workspace_members_from(&doc, &ownership_rows(&["a"])));
        assert!(out.contains("workspace member `b` has no row in"), "{out}");
    }

    #[test]
    fn g_m01_1_fails_on_an_extra_ownership_row() {
        let doc = ed_doc(&[ed_pkg("a", Some("core"), vec![])]);
        let out = fail_lines(workspace_members_from(
            &doc,
            &ownership_rows(&["a", "ghost"]),
        ));
        assert!(
            out.contains("row `ghost` names no workspace member"),
            "{out}"
        );
    }

    #[test]
    fn g_m01_1_fails_on_a_row_whose_module_is_not_a_module_id() {
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![]),
            ed_pkg("b", Some("core"), vec![]),
        ]);
        let rows = "[crates]\na = \"M29\"\nb = \"core\"\n";
        let out = fail_lines(workspace_members_from(&doc, rows));
        assert!(out.contains("row `a` has module \"M29\""), "{out}");
        assert!(out.contains("row `b` has module \"core\""), "{out}");
    }

    #[test]
    fn g_m01_1_fails_on_a_missing_table_invalid_toml_or_an_empty_workspace() {
        let doc = ed_doc(&[ed_pkg("a", Some("core"), vec![])]);
        assert!(fail_lines(workspace_members_from(&doc, "")).contains("no [crates] table"));
        assert!(fail_lines(workspace_members_from(&doc, "[crates")).contains("not valid TOML"));
        assert!(
            fail_lines(workspace_members_from(&ed_doc(&[]), &ownership_rows(&[])))
                .contains("no workspace package")
        );
    }

    #[test]
    fn g_m01_1_real_repo_passes() {
        assert_eq!(m01_1_workspace_members(&real_root()), Verdict::Pass);
    }

    /// 注错 (G-M01-2): a core package with a normal dependency on a cloud package → red naming the edge.
    #[test]
    fn g_m01_2_fails_on_a_core_to_cloud_normal_dependency() {
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![ed_dep("c", None)]),
            ed_pkg("c", Some("cloud"), vec![]),
        ]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains("core package `a` depends on cloud package `c` (normal dependency;"),
            "{out}"
        );
    }

    /// 注错 (G-M01-2): the dev- and build-dependency kinds and an optional (feature-gated) edge count too.
    #[test]
    fn g_m01_2_fails_on_a_core_to_cloud_dev_build_or_optional_dependency() {
        let optional = serde_json::json!({"name": "c", "kind": null, "optional": true});
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![ed_dep("c", Some("dev"))]),
            ed_pkg("b", Some("core"), vec![ed_dep("c", Some("build"))]),
            ed_pkg("d", Some("core"), vec![optional]),
            ed_pkg("c", Some("cloud"), vec![]),
        ]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains("`a` depends on cloud package `c` (dev dependency;"),
            "{out}"
        );
        assert!(
            out.contains("`b` depends on cloud package `c` (build dependency;"),
            "{out}"
        );
        assert!(
            out.contains("`d` depends on cloud package `c` (normal dependency, optional;"),
            "{out}"
        );
    }

    #[test]
    fn g_m01_2_allows_cloud_to_core_and_core_to_core() {
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![ed_dep("b", None)]),
            ed_pkg("b", Some("core"), vec![]),
            ed_pkg(
                "c",
                Some("cloud"),
                vec![ed_dep("a", None), ed_dep("b", Some("dev"))],
            ),
        ]);
        assert_eq!(core_cloud_edges_from(&doc), Verdict::Pass);
    }

    /// §57.1 第2条: with no cloud package there is nothing to guard (the open-source repository after the
    /// split) — `not_applicable`, naming the missing object, never a bare pass.
    #[test]
    fn g_m01_2_is_not_applicable_naming_the_missing_cloud_package() {
        let doc = ed_doc(&[ed_pkg("a", Some("core"), vec![])]);
        assert_eq!(
            core_cloud_edges_from(&doc),
            Verdict::NotApplicable("package with edition = \"cloud\"".to_string())
        );
    }

    #[test]
    fn g_m01_2_fails_on_unparsable_metadata() {
        assert!(fail_lines(core_cloud_edges_from("not json")).contains("not valid JSON"));
        assert!(fail_lines(core_cloud_edges_from("{}")).contains("no `packages` array"));
    }

    /// 注错 (G-M01-2): a target-specific dev dependency (`[target.'cfg(unix)'.dev-dependencies]`) is still an edge.
    #[test]
    fn g_m01_2_fails_on_a_target_specific_core_to_cloud_dev_dependency() {
        let targeted = serde_json::json!({"name": "c", "kind": "dev", "optional": false, "target": "cfg(unix)"});
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![targeted]),
            ed_pkg("c", Some("cloud"), vec![]),
        ]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains("`a` depends on cloud package `c` (dev dependency, target `cfg(unix)`;"),
            "{out}"
        );
    }

    /// 注错 (G-M01-2): `pw = { package = "c", .. }` — metadata keeps the package name in `name` and the alias in
    /// `rename`, so a renamed dependency is caught under the real package name.
    #[test]
    fn g_m01_2_fails_on_a_renamed_core_to_cloud_dependency() {
        let renamed =
            serde_json::json!({"name": "c", "kind": null, "optional": false, "rename": "pw"});
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![renamed]),
            ed_pkg("c", Some("cloud"), vec![]),
        ]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains("`a` depends on cloud package `c` (normal dependency, renamed `pw`;"),
            "{out}"
        );
    }

    /// Fail-closed shape: a core package whose `dependencies` array is absent cannot prove the absence of a
    /// cloud edge, and neither can a nameless dependency entry.
    #[test]
    fn g_m01_2_fails_closed_on_a_missing_dependencies_array_or_nameless_dependency() {
        let no_deps = serde_json::json!({"name": "a", "metadata": {"humaux": {"edition": "core"}}});
        let nameless = ed_pkg("b", Some("core"), vec![serde_json::json!({"kind": null})]);
        let doc = ed_doc(&[no_deps, nameless, ed_pkg("c", Some("cloud"), vec![])]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains("core package `a` has no `dependencies` array"),
            "{out}"
        );
        assert!(
            out.contains("core package `b` lists a dependency without a `name`"),
            "{out}"
        );
    }

    /// Member-closed graph: a core path dependency on a package that is not a workspace member is red; a path
    /// dependency on a member and a registry dependency (no `path`) are fine.
    #[test]
    fn g_m01_2_fails_on_a_core_path_dependency_outside_the_workspace() {
        let outside =
            serde_json::json!({"name": "x", "kind": null, "optional": false, "path": "/w/x"});
        let member =
            serde_json::json!({"name": "b", "kind": null, "optional": false, "path": "/w/b"});
        let registry = ed_dep("serde", None);
        let doc = ed_doc(&[
            ed_pkg("a", Some("core"), vec![outside, member, registry]),
            ed_pkg("b", Some("core"), vec![]),
            ed_pkg("c", Some("cloud"), vec![]),
        ]);
        let out = fail_lines(core_cloud_edges_from(&doc));
        assert!(
            out.contains(
                "core package `a` has a path dependency on `x`, which is not a workspace member"
            ),
            "{out}"
        );
        assert_eq!(out.lines().count(), 1, "{out}");
    }

    #[test]
    fn is_module_id_accepts_m01_to_m28_only() {
        for ok in ["M01", "M09", "M28"] {
            assert!(is_module_id(ok), "{ok}");
        }
        for bad in ["M00", "M29", "M1", "M100", "m01", "X01", "M+1", "M0a", ""] {
            assert!(!is_module_id(bad), "{bad}");
        }
    }

    /// Non-comment occurrences of `head` + `tail` in this file's own source. The needle is passed in two halves
    /// so that this test's source does not contain it and cannot count itself.
    fn own_source_count(head: &str, tail: &str) -> usize {
        let needle = format!("{head}{tail}");
        std::fs::read_to_string(real_root().join(SELF_FILE))
            .expect("read architecture_check.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(&needle))
            .count()
    }

    /// `run()` must list both edition gates: a deleted or commented-out call tuple leaves a gate that never runs
    /// and reads as green (the 恒真闸 shape §57.1 exists to prevent). Counted `== 1`, not `>= 1`.
    #[test]
    fn run_wires_each_m01_edition_gate_exactly_once() {
        assert_eq!(own_source_count("m01_1_workspace_", "members(&root),"), 1);
        assert_eq!(own_source_count("m01_2_core_cloud_", "edges(&root),"), 1);
    }

    // ponytail: pins `humaux-public-worker` as this private repository's one cloud member. The open-source export
    // (card M24-14) has no cloud package: there this test and the `humaux-public-worker` row of
    // module_ownership.toml go stale and are dropped at the split (ADR-0074 "Split checklist").
    /// The real workspace has a cloud member (`humaux-public-worker`), so this must be `Pass`, not
    /// `not_applicable`: an edition flip that empties the cloud set must not read as green.
    #[test]
    fn g_m01_2_real_repo_passes_with_a_cloud_member_present() {
        assert_eq!(m01_2_core_cloud_edges(&real_root()), Verdict::Pass);
    }

    // -- M01 D5 crate boundary table (G-M01-3) ---------------------------------------------

    /// The four L0 packages the table requires, plus `extra` packages; telemetry depends on the domain.
    fn bt_doc(extra: Vec<serde_json::Value>) -> String {
        let mut pkgs = vec![
            ed_pkg("humaux-domain", None, vec![]),
            ed_pkg("humaux-contracts", None, vec![]),
            ed_pkg("humaux-fail-closed-macro", None, vec![]),
            ed_pkg(
                "humaux-telemetry",
                None,
                vec![ed_dep("humaux-domain", None)],
            ),
            ed_pkg("humaux-adapters", None, vec![]),
        ];
        pkgs.extend(extra);
        ed_doc(&pkgs)
    }

    fn no_ledger() -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// Green: each table dependency in an allowed package, and a dev-dependency sqlx anywhere ("testing").
    #[test]
    fn g_m01_3_passes_on_allowed_packages_and_a_dev_dependency_sqlx() {
        let doc = bt_doc(vec![
            ed_pkg("humaux-infra-network", None, vec![ed_dep("reqwest", None)]),
            ed_pkg(
                "humaux-projection",
                None,
                vec![ed_dep("qdrant-client", None)],
            ),
            ed_pkg("humaux-adapters-x", None, vec![ed_dep("sqlx", Some("dev"))]),
        ]);
        assert_eq!(
            crate_boundary_from(&doc, &no_ledger()),
            (Verdict::Pass, vec![])
        );
        // sqlx in humaux-adapters itself is the table's own row
        let own = ed_doc(&[
            ed_pkg("humaux-domain", None, vec![]),
            ed_pkg("humaux-contracts", None, vec![]),
            ed_pkg("humaux-fail-closed-macro", None, vec![]),
            ed_pkg("humaux-telemetry", None, vec![]),
            ed_pkg("humaux-adapters", None, vec![ed_dep("sqlx", None)]),
        ]);
        assert_eq!(crate_boundary_from(&own, &no_ledger()).0, Verdict::Pass);
    }

    /// 注错 (G-M01-3): a normal sqlx dependency outside humaux-adapters, not in the ledger → red naming it.
    #[test]
    fn g_m01_3_fails_on_an_unledgered_violation() {
        let doc = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("sqlx", None)],
        )]);
        let out = fail_lines(crate_boundary_from(&doc, &no_ledger()).0);
        assert!(
            out.contains("`humaux-gateway` declares `sqlx` (normal dependency)"),
            "{out}"
        );
        assert!(
            out.contains("not in xtask/known_red.toml [[crate_boundary]]"),
            "{out}"
        );
    }

    /// A ledgered violation is not green-silent: the verdict passes, the log gets a known-red line.
    #[test]
    fn g_m01_3_reports_a_ledgered_violation_as_known_red() {
        let doc = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("sqlx", None)],
        )]);
        let ledgered = BTreeSet::from(["humaux-gateway -> sqlx (normal)".to_string()]);
        let (verdict, notes) = crate_boundary_from(&doc, &ledgered);
        assert_eq!(verdict, Verdict::Pass);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].starts_with(
                "known-red: ledgered [crate_boundary] humaux-gateway -> sqlx (normal):"
            ),
            "{notes:?}"
        );
        // the row covers that edge only
        let other = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("sqlx", None), ed_dep("reqwest", None)],
        )]);
        let out = fail_lines(crate_boundary_from(&other, &ledgered).0);
        assert!(out.contains("`humaux-gateway` declares `reqwest`"), "{out}");
        assert!(!out.contains("`sqlx`"), "{out}");
    }

    /// The dev exemption is sqlx's only: a dev-dependency on reqwest outside humaux-infra-network is red.
    #[test]
    fn g_m01_3_dev_exemption_does_not_cover_reqwest() {
        let doc = bt_doc(vec![ed_pkg(
            "humaux-adapters-x",
            None,
            vec![ed_dep("reqwest", Some("dev"))],
        )]);
        let out = fail_lines(crate_boundary_from(&doc, &no_ledger()).0);
        assert!(out.contains("`reqwest` (dev dependency)"), "{out}");
    }

    /// 注错 (G-M01-3): `pg = { package = "sqlx", .. }` — metadata keeps the package name in `name`.
    #[test]
    fn g_m01_3_fails_on_a_renamed_dependency() {
        let renamed =
            serde_json::json!({"name": "sqlx", "kind": null, "optional": false, "rename": "pg"});
        let doc = bt_doc(vec![ed_pkg("humaux-gateway", None, vec![renamed])]);
        let out = fail_lines(crate_boundary_from(&doc, &no_ledger()).0);
        assert!(out.contains("`humaux-gateway` declares `sqlx`"), "{out}");
    }

    /// 注错 (G-M01-3): `[target.'cfg(unix)'.dependencies]` counts; the same target under dev-dependencies is
    /// still "testing".
    #[test]
    fn g_m01_3_fails_on_a_target_specific_dependency() {
        let normal = serde_json::json!({"name": "sqlx", "kind": null, "optional": false, "target": "cfg(unix)"});
        let dev = serde_json::json!({"name": "sqlx", "kind": "dev", "optional": false, "target": "cfg(unix)"});
        let red = bt_doc(vec![ed_pkg("humaux-gateway", None, vec![normal])]);
        assert!(matches!(
            crate_boundary_from(&red, &no_ledger()).0,
            Verdict::Fail(_)
        ));
        let green = bt_doc(vec![ed_pkg("humaux-gateway", None, vec![dev])]);
        assert_eq!(crate_boundary_from(&green, &no_ledger()).0, Verdict::Pass);
    }

    /// 注错 (G-M01-3): an optional (feature-gated) and a build dependency count like a normal one.
    #[test]
    fn g_m01_3_counts_optional_and_build_dependencies() {
        let optional = serde_json::json!({"name": "reqwest", "kind": null, "optional": true});
        let build = ed_dep("sqlx", Some("build"));
        let doc = bt_doc(vec![
            ed_pkg("humaux-a", None, vec![optional]),
            ed_pkg("humaux-b", None, vec![build]),
        ]);
        let out = fail_lines(crate_boundary_from(&doc, &no_ledger()).0);
        assert!(out.contains("`humaux-a` declares `reqwest`"), "{out}");
        assert!(
            out.contains("`humaux-b` declares `sqlx` (build dependency)"),
            "{out}"
        );
    }

    /// 注错 (G-M01-3, L0 rows): the domain depending on another workspace package, and telemetry on a package
    /// outside the L0 kernel, are red; telemetry on the kernel stays green.
    #[test]
    fn g_m01_3_keeps_the_l0_kernel_free_of_upward_workspace_edges() {
        let mut pkgs = vec![
            ed_pkg("humaux-domain", None, vec![ed_dep("humaux-adapters", None)]),
            ed_pkg("humaux-contracts", None, vec![]),
            ed_pkg("humaux-fail-closed-macro", None, vec![]),
            ed_pkg(
                "humaux-telemetry",
                None,
                vec![
                    ed_dep("humaux-contracts", None),
                    ed_dep("humaux-adapters", Some("dev")),
                ],
            ),
            ed_pkg("humaux-adapters", None, vec![]),
        ];
        let out = fail_lines(crate_boundary_from(&ed_doc(&pkgs), &no_ledger()).0);
        assert!(
            out.contains(
                "L0 package `humaux-domain` depends on workspace package `humaux-adapters`"
            ),
            "{out}"
        );
        assert!(
            out.contains("L0 package `humaux-telemetry` depends on workspace package `humaux-adapters` (dev dependency)"),
            "{out}"
        );
        assert!(!out.contains("humaux-contracts` ("), "{out}");
        pkgs[0] = ed_pkg("humaux-domain", None, vec![ed_dep("uuid", None)]);
        pkgs[3] = ed_pkg(
            "humaux-telemetry",
            None,
            vec![ed_dep("humaux-contracts", None)],
        );
        assert_eq!(
            crate_boundary_from(&ed_doc(&pkgs), &no_ledger()).0,
            Verdict::Pass
        );
    }

    /// Fail-closed shape: nothing to check, a missing L0 package, a package without `dependencies` and a
    /// nameless dependency are red, never skipped and never ledgerable.
    #[test]
    fn g_m01_3_fails_closed_on_a_malformed_document() {
        assert!(
            fail_lines(crate_boundary_from("not json", &no_ledger()).0).contains("not valid JSON")
        );
        assert!(
            fail_lines(crate_boundary_from(&ed_doc(&[]), &no_ledger()).0)
                .contains("no workspace package")
        );
        let missing_l0 = ed_doc(&[ed_pkg("humaux-domain", None, vec![])]);
        assert!(
            fail_lines(crate_boundary_from(&missing_l0, &no_ledger()).0)
                .contains("L0 package `humaux-contracts` not found")
        );
        let no_deps = bt_doc(vec![serde_json::json!({"name": "x", "metadata": null})]);
        assert!(
            fail_lines(crate_boundary_from(&no_deps, &no_ledger()).0)
                .contains("package `x` has no `dependencies` array")
        );
        let nameless = bt_doc(vec![ed_pkg(
            "y",
            None,
            vec![serde_json::json!({"kind": null})],
        )]);
        assert!(
            fail_lines(crate_boundary_from(&nameless, &no_ledger()).0)
                .contains("package `y` lists a dependency without a `name`")
        );
    }

    /// 注错 (G-M01-3, qdrant row): the client crate outside adapters/projection is red as a normal and as a dev
    /// dependency (no exemption), in humaux-adapters and humaux-projection it is green.
    #[test]
    fn g_m01_3_fails_on_a_qdrant_client_outside_adapters_and_projection() {
        let normal = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("qdrant-client", None)],
        )]);
        assert_eq!(
            fail_lines(crate_boundary_from(&normal, &no_ledger()).0),
            "`humaux-gateway` declares `qdrant-client` (normal dependency) but only [\"humaux-adapters\", \"humaux-projection\"] may (§78: the Qdrant client lives in the projection adapter); not in xtask/known_red.toml [[crate_boundary]]"
        );
        let dev = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("qdrant-client", Some("dev"))],
        )]);
        assert_eq!(
            fail_lines(crate_boundary_from(&dev, &no_ledger()).0),
            "`humaux-gateway` declares `qdrant-client` (dev dependency) but only [\"humaux-adapters\", \"humaux-projection\"] may (§78: the Qdrant client lives in the projection adapter); not in xtask/known_red.toml [[crate_boundary]]"
        );
        let allowed = bt_doc(vec![
            ed_pkg(
                "humaux-projection",
                None,
                vec![ed_dep("qdrant-client", None)],
            ),
            ed_pkg("humaux-adapters-y", None, vec![]),
        ]);
        assert_eq!(crate_boundary_from(&allowed, &no_ledger()).0, Verdict::Pass);
    }

    /// 注错 (G-M01-3, L0 rows): a workspace edge out of humaux-contracts, and out of humaux-fail-closed-macro, is
    /// red on its own row.
    #[test]
    fn g_m01_3_fails_on_a_workspace_edge_from_contracts_or_the_macro_crate() {
        let doc = |contracts: Vec<serde_json::Value>, mac: Vec<serde_json::Value>| {
            ed_doc(&[
                ed_pkg("humaux-domain", None, vec![]),
                ed_pkg("humaux-contracts", None, contracts),
                ed_pkg("humaux-fail-closed-macro", None, mac),
                ed_pkg("humaux-telemetry", None, vec![]),
                ed_pkg("humaux-adapters", None, vec![]),
            ])
        };
        let contracts = doc(vec![ed_dep("humaux-adapters", None)], vec![]);
        assert_eq!(
            fail_lines(crate_boundary_from(&contracts, &no_ledger()).0),
            "L0 package `humaux-contracts` depends on workspace package `humaux-adapters` (normal dependency) but may depend only on [] (M01 design §4); not in xtask/known_red.toml [[crate_boundary]]"
        );
        let mac = doc(vec![], vec![ed_dep("humaux-domain", Some("dev"))]);
        assert_eq!(
            fail_lines(crate_boundary_from(&mac, &no_ledger()).0),
            "L0 package `humaux-fail-closed-macro` depends on workspace package `humaux-domain` (dev dependency) but may depend only on [] (M01 design §4); not in xtask/known_red.toml [[crate_boundary]]"
        );
    }

    /// The ledger id carries the dependency kind: a ledgered dev edge does not silence a later normal edge of the
    /// same pair.
    #[test]
    fn g_m01_3_ledgered_dev_edge_does_not_cover_a_normal_edge_of_the_same_pair() {
        let doc = bt_doc(vec![ed_pkg(
            "humaux-gateway",
            None,
            vec![ed_dep("reqwest", Some("dev")), ed_dep("reqwest", None)],
        )]);
        let ledgered = BTreeSet::from(["humaux-gateway -> reqwest (dev)".to_string()]);
        let (verdict, notes) = crate_boundary_from(&doc, &ledgered);
        let out = fail_lines(verdict);
        assert!(out.contains("`reqwest` (normal dependency)"), "{out}");
        assert!(!out.contains("(dev dependency)"), "{out}");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("humaux-gateway -> reqwest (dev):"),
            "{notes:?}"
        );
    }

    /// 注错 (G-M01-3, sqlx family): a direct dependency on a `sqlx-*` sub-crate is the same access, dev exempt too.
    #[test]
    fn g_m01_3_catches_sqlx_sub_crates() {
        let doc = bt_doc(vec![
            ed_pkg("humaux-a", None, vec![ed_dep("sqlx-core", None)]),
            ed_pkg("humaux-b", None, vec![ed_dep("sqlx-postgres", Some("dev"))]),
            ed_pkg("humaux-c", None, vec![ed_dep("sqlxx", None)]),
        ]);
        let out = fail_lines(crate_boundary_from(&doc, &no_ledger()).0);
        assert!(
            out.contains("`humaux-a` declares `sqlx-core` (normal dependency)"),
            "{out}"
        );
        assert!(!out.contains("humaux-b"), "{out}");
        assert!(!out.contains("humaux-c"), "{out}");
    }

    #[test]
    fn ledgered_boundary_ids_reads_the_section_and_rejects_bad_shapes() {
        assert_eq!(ledgered_boundary_ids("").unwrap(), BTreeSet::new());
        assert_eq!(
            ledgered_boundary_ids(
                "[[dod]]\nid = \"d\"\n[[crate_boundary]]\nid = \"a -> sqlx (normal)\"\nowner = \"M23\"\n"
            )
            .unwrap(),
            BTreeSet::from(["a -> sqlx (normal)".to_string()])
        );
        assert!(ledgered_boundary_ids("[crate_boundary]\nid = \"a\"\n").is_err());
        assert!(ledgered_boundary_ids("[[crate_boundary]]\nowner = \"M23\"\n").is_err());
        assert!(ledgered_boundary_ids("not toml [").is_err());
    }

    /// `run()` must list G-M01-3 exactly once (a deleted call tuple leaves a gate that never runs).
    #[test]
    fn run_wires_the_crate_boundary_gate_exactly_once() {
        assert_eq!(own_source_count("m01_3_crate_", "boundary(&root),"), 1);
    }

    /// The real workspace is clean against the table: gateway's sqlx is a dev-dependency, maintenance's already was.
    #[test]
    fn g_m01_3_real_repo_passes() {
        assert_eq!(m01_3_crate_boundary(&real_root()), Verdict::Pass);
    }

    // -- M01 D4 / G-M01-4: real path or declared dormant ----------------------------------

    fn m01_4_names(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn m01_4_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// A ledger with one valid row per variant.
    fn m01_4_rows(variants: &[&str]) -> String {
        variants
            .iter()
            .map(|v| {
                format!("[[dormant]]\nvariant = \"{v}\"\nowner = \"M11\"\nreason = \"later\"\n")
            })
            .collect()
    }

    /// Fault tests that reach the exit themselves (through `abstain` and through `.also`), and one that goes through a
    /// production function.
    const M01_4_SYNTHETIC: &str = "use humaux_telemetry::degrade::{DegradeCode, abstain};\n#[test]\nfn t() {\n    let _ = abstain(DegradeCode::Alpha, ());\n}\n";
    const M01_4_ALSO: &str = "use humaux_telemetry::degrade::{DegradeCode, Outcome};\n#[test]\nfn t() {\n    let _ = Outcome::clean(String::new())\n        .also(DegradeCode::Alpha);\n}\n";
    const M01_4_REAL_PATH: &str = "use humaux_retrieval::envelope::build_projection_block;\n#[test]\nfn t() {\n    let _ = build_projection_block;\n}\n";

    /// A `fault_main.rs` that wires both fixture fault files.
    const M01_4_MAIN: &str =
        "#[path = \"fault/alpha.rs\"]\nmod alpha;\n#[path = \"fault/beta.rs\"]\nmod beta;\n";

    /// The scan over one synthetic production file.
    fn m01_4_scan(src: &str) -> (BTreeMap<String, String>, Vec<String>) {
        degrade_emit_sites(
            &[("crates/x/src/a.rs".to_string(), src.to_string())],
            &m01_4_names(&["Alpha", "Beta", "AlphaTwo"]),
        )
    }

    fn m01_4_sites(src: &str) -> BTreeMap<String, String> {
        m01_4_scan(src).0
    }

    /// The comparator with no unclassified exits and the fixture wiring.
    fn m01_4_check(
        variants: &[String],
        sites: &BTreeMap<String, String>,
        tests: &BTreeMap<String, String>,
        toml: &str,
    ) -> (Verdict, Vec<String>) {
        real_path_from(variants, sites, &[], tests, M01_4_MAIN, toml)
    }

    #[test]
    fn g_m01_4_real_repo_passes() {
        assert_eq!(m01_4_real_path_or_dormant(&real_root()), Verdict::Pass);
    }

    /// Positive control: the scanner is not blind on the real tree. The three emitters the M01 design names must be
    /// found (a subset check, so a later card that adds an emitter does not have to edit this test), and no exit call
    /// on the real tree is unclassifiable.
    #[test]
    fn g_m01_4_scanner_finds_the_three_known_emitters_on_the_real_tree() {
        let root = real_root();
        let degrade = fs::read_to_string(root.join(DEGRADE_HOME)).unwrap();
        let variants = parse_degrade_variant_names(&degrade);
        let (sites, unclassified) = degrade_emit_sites(&degrade_scan_files(&root), &variants);
        for v in [
            "ProjectionLag",
            "ProjectionInvisibleLoss",
            "LaneSubstituted",
        ] {
            assert!(
                sites
                    .get(v)
                    .is_some_and(|s| s.starts_with("crates/retrieval/src/envelope.rs:")),
                "{v}: {sites:?}"
            );
        }
        assert!(unclassified.is_empty(), "{unclassified:?}");
    }

    /// 注错 (G-M01-4 a): a live variant whose fault test names `abstain` → red naming the variant, file and line.
    #[test]
    fn g_m01_4_live_variant_whose_test_names_abstain_is_red() {
        let (verdict, _) = m01_4_check(
            &m01_4_names(&["Alpha", "Beta"]),
            &m01_4_map(&[("Alpha", "crates/x/src/a.rs:3")]),
            &m01_4_map(&[("Alpha", M01_4_SYNTHETIC), ("Beta", M01_4_SYNTHETIC)]),
            &m01_4_rows(&["Beta"]),
        );
        let out = fail_lines(verdict);
        assert!(
            out.contains("Alpha: production emit site crates/x/src/a.rs:3, but crates/testkit/tests/fault/alpha.rs:1 names the degrade exit `abstain`"),
            "{out}"
        );
        assert!(
            !out.contains("Beta"),
            "a dormant variant keeps its synthetic test: {out}"
        );
    }

    /// 注错 (M01-3 review B1): a fault test that builds the outcome with `.also(DegradeCode::V)` reaches the exit
    /// without writing `abstain`; the bypass check must refuse it as well.
    #[test]
    fn g_m01_4_live_variant_whose_test_calls_also_is_red() {
        let (verdict, _) = m01_4_check(
            &m01_4_names(&["Alpha"]),
            &m01_4_map(&[("Alpha", "crates/x/src/a.rs:3")]),
            &m01_4_map(&[("Alpha", M01_4_ALSO)]),
            "",
        );
        let out = fail_lines(verdict);
        assert!(
            out.contains("alpha.rs:5 names the degrade exit `also`"),
            "{out}"
        );
    }

    /// The bypass predicate and the emit-site scan read one callee list; comments, string literals and longer
    /// identifiers are not mentions.
    #[test]
    fn g_m01_4_exit_predicate_catches_abstain_and_also_and_ignores_prose() {
        let prose = "//! abstain() and .also(x) are never named here\n/* abstain(DegradeCode::Alpha) */\nfn t() { // abstain(x)\n    let s = \"abstain(.also(\";\n}\n";
        assert_eq!(degrade_exit_named(prose), None);
        let lookalikes =
            "fn abstained() {}\nfn not_abstain_x() {}\nfn t(also: u8) { let _ = also; }\n";
        assert_eq!(degrade_exit_named(lookalikes), None);
        assert_eq!(
            degrade_exit_named("use telemetry::degrade::abstain as raise;\n"),
            Some((1, "abstain"))
        );
        assert_eq!(degrade_exit_named(M01_4_SYNTHETIC), Some((1, "abstain")));
        assert_eq!(degrade_exit_named(M01_4_ALSO), Some((5, "also")));
        assert_eq!(
            degrade_exit_named("let f = Outcome::also;\n"),
            Some((1, "also"))
        );
        assert_eq!(
            degrade_exit_named("let _ = x\n    .also(DegradeCode::A);\n"),
            Some((2, "also"))
        );
        assert_eq!(degrade_exit_named(M01_4_REAL_PATH), None);
    }

    /// 注错 (G-M01-4 b): a dormant row for a variant that has an emit site → red, the row must go.
    #[test]
    fn g_m01_4_dormant_row_for_a_live_variant_is_red() {
        let (verdict, _) = m01_4_check(
            &m01_4_names(&["Alpha"]),
            &m01_4_map(&[("Alpha", "crates/x/src/a.rs:3")]),
            &m01_4_map(&[("Alpha", M01_4_REAL_PATH)]),
            &m01_4_rows(&["Alpha"]),
        );
        let out = fail_lines(verdict);
        assert!(
            out.contains("Alpha: crates/testkit/tests/fault/dormant.toml still lists it"),
            "{out}"
        );
        assert!(out.contains("delete the row"), "{out}");
    }

    /// 注错 (G-M01-4 c): no emit site and no row → red; the ledger cannot grow silently.
    #[test]
    fn g_m01_4_variant_without_emit_site_or_row_is_red() {
        let (verdict, _) = m01_4_check(
            &m01_4_names(&["Alpha"]),
            &BTreeMap::new(),
            &m01_4_map(&[("Alpha", M01_4_SYNTHETIC)]),
            "",
        );
        let out = fail_lines(verdict);
        assert!(out.contains("Alpha: no production emit site"), "{out}");
        assert!(out.contains("no [[dormant]] row"), "{out}");
    }

    /// 注错 (M01-3 review W3): a fault file that `fault_main.rs` does not pull in is never compiled, so its injection
    /// record proves nothing. A commented-out pair, a `#[cfg(..)]` between the two lines and a `#[path]` that points at
    /// another file are all unwired.
    #[test]
    fn g_m01_4_fault_file_that_fault_main_does_not_wire_is_red() {
        let variants = m01_4_names(&["Alpha", "Beta"]);
        let tests = m01_4_map(&[("Alpha", M01_4_REAL_PATH), ("Beta", M01_4_SYNTHETIC)]);
        let sites = m01_4_map(&[("Alpha", "crates/x/src/a.rs:3")]);
        let rows = m01_4_rows(&["Beta"]);
        let run = |main: &str| real_path_from(&variants, &sites, &[], &tests, main, &rows).0;
        assert_eq!(run(M01_4_MAIN), Verdict::Pass);
        let alpha = "#[path = \"fault/alpha.rs\"]\nmod alpha;\n";
        let unwired = [
            ("absent", alpha.to_string()),
            (
                "commented out",
                format!("{alpha}// #[path = \"fault/beta.rs\"]\n// mod beta;\n"),
            ),
            (
                "cfg-gated",
                format!("{alpha}#[path = \"fault/beta.rs\"]\n#[cfg(any())]\nmod beta;\n"),
            ),
            (
                "wrong path",
                format!("{alpha}#[path = \"fault/alpha.rs\"]\nmod beta;\n"),
            ),
        ];
        for (shape, main) in unwired {
            let out = fail_lines(run(&main));
            assert!(
                out.contains("Beta: crates/testkit/tests/fault/beta.rs exists but crates/testkit/tests/fault_main.rs has no `#[path = \"fault/beta.rs\"] mod beta;` pair"),
                "{shape}: {out}"
            );
            assert!(!out.contains("Alpha:"), "{shape}: {out}");
        }
    }

    /// An exit call that [`degrade_emit_sites`] could not attribute is red on its own, whatever else is covered.
    #[test]
    fn g_m01_4_unclassified_exit_call_is_red_even_when_every_variant_is_covered() {
        let line = "crates/x/src/a.rs:9: `abstain(` is a degrade exit whose first argument `c` names no DegradeCode variant".to_string();
        let (verdict, _) = real_path_from(
            &m01_4_names(&["Alpha"]),
            &BTreeMap::new(),
            std::slice::from_ref(&line),
            &BTreeMap::new(),
            "",
            &m01_4_rows(&["Alpha"]),
        );
        assert!(fail_lines(verdict).contains("crates/x/src/a.rs:9"));
    }

    #[test]
    fn g_m01_4_green_shapes_pass_and_the_notes_show_the_ledger() {
        let variants = m01_4_names(&["Alpha", "Beta"]);
        let (verdict, notes) = m01_4_check(
            &variants,
            &m01_4_map(&[("Alpha", "crates/x/src/a.rs:3")]),
            &m01_4_map(&[("Alpha", M01_4_REAL_PATH), ("Beta", M01_4_SYNTHETIC)]),
            &m01_4_rows(&["Beta"]),
        );
        assert_eq!(verdict, Verdict::Pass);
        assert!(
            notes[0].contains(
                "1 variant(s) driven through their production emit site; dormant rows: 1"
            ),
            "{notes:?}"
        );
        assert!(
            notes[1].contains("dormant Beta (owner M11): later"),
            "{notes:?}"
        );
    }

    #[test]
    fn g_m01_4_malformed_ledgers_are_red() {
        let variants = m01_4_names(&["Alpha"]);
        let live = m01_4_map(&[("Alpha", "crates/x/src/a.rs:1")]);
        let check =
            |toml: &str| fail_lines(m01_4_check(&variants, &live, &BTreeMap::new(), toml).0);
        let row = |variant: &str, owner: &str, reason: &str| {
            format!(
                "[[dormant]]\nvariant = \"{variant}\"\nowner = \"{owner}\"\nreason = \"{reason}\"\n"
            )
        };
        assert!(check(&row("Nope", "M11", "r")).contains("names no DegradeCode variant"));
        let twice = format!("{0}{0}", row("Alpha", "M11", "r"));
        assert!(check(&twice).contains("`Alpha` is listed twice"));
        assert!(check(&row("Alpha", "team", "r")).contains("is not a module card"));
        assert!(check(&row("Alpha", "M11", "")).contains("missing `reason`"));
        assert!(
            check(&format!("{}why = \"x\"\n", row("Alpha", "M11", "r")))
                .contains("unknown key `why`")
        );
        assert!(check("[other]\nx = 1\n").contains("unknown top-level key `other`"));
        assert!(check("[dormant]\nvariant = \"Alpha\"\n").contains("must be an array of tables"));
        assert!(check("[[dormant").contains("not valid TOML"));
    }

    #[test]
    fn degrade_emit_sites_recognise_abstain_and_also_across_line_breaks() {
        let src = [
            "fn f() {",
            "    abstain(DegradeCode::Alpha, ())",
            "}",
            "fn g(o: O) -> O {",
            "    o",
            "        .also(",
            "            DegradeCode::Beta,",
            "        )",
            "}",
        ]
        .join("\n");
        let (sites, unclassified) = m01_4_scan(&src);
        assert_eq!(sites["Alpha"], "crates/x/src/a.rs:2");
        assert_eq!(sites["Beta"], "crates/x/src/a.rs:6");
        assert!(unclassified.is_empty(), "{unclassified:?}");
    }

    /// M01-3 review W1: the shapes the old "text before `DegradeCode::` ends in `(`" test missed.
    #[test]
    fn degrade_emit_sites_see_qualified_aliased_glob_and_turbofish_calls() {
        let cases = [
            (
                "qualified",
                "fn f() { abstain(humaux_telemetry::degrade::DegradeCode::Alpha, ()); }",
                "Alpha",
            ),
            (
                "aliased",
                "use humaux_telemetry::degrade::DegradeCode as C;\nfn f() { abstain(C::Beta, ()); }",
                "Beta",
            ),
            (
                "glob-imported",
                "use humaux_telemetry::degrade::DegradeCode::*;\nfn f() { abstain(AlphaTwo, ()); }",
                "AlphaTwo",
            ),
            (
                "turbofish",
                "fn f() { abstain::<()>(DegradeCode::Alpha, ()); }",
                "Alpha",
            ),
            (
                "nested turbofish",
                "fn f() { abstain::< Vec<Vec<u8>> >(\n    DegradeCode::Beta,\n    Vec::new(),\n); }",
                "Beta",
            ),
            (
                "qualified method",
                "fn f(o: O) -> O { o.also(humaux_telemetry::degrade::DegradeCode::Beta) }",
                "Beta",
            ),
            (
                "path-qualified callee",
                "fn f() { humaux_telemetry::degrade::abstain(DegradeCode::Alpha, ()); }",
                "Alpha",
            ),
        ];
        for (shape, src, variant) in cases {
            let (sites, unclassified) = m01_4_scan(src);
            assert_eq!(
                sites.keys().map(String::as_str).collect::<Vec<_>>(),
                [variant],
                "{shape}"
            );
            assert!(unclassified.is_empty(), "{shape}: {unclassified:?}");
        }
    }

    /// M01-3 review W1: a call whose first argument names no variant cannot be attributed, so it is red (naming
    /// file:line) instead of letting the variant it emits read as dormant. `degrade.rs` itself is exempt.
    #[test]
    fn degrade_emit_sites_fail_closed_on_an_exit_that_names_no_variant() {
        let src = [
            "fn a(c: DegradeCode) { abstain(c, ()); }",
            "fn b() { let code = DegradeCode::Alpha; abstain(code, ()); }",
            "fn c(o: O, k: DegradeCode) -> O { o.also(k) }",
            "fn d(o: O) -> O { Outcome::also(o, DegradeCode::Beta) }",
            "fn e() { abstain(pick(DegradeCode::Alpha), ()); }",
        ]
        .join("\n");
        let (sites, unclassified) = m01_4_scan(&src);
        assert!(sites.is_empty(), "{sites:?}");
        assert_eq!(unclassified.len(), 5, "{unclassified:?}");
        for line in 1..=5 {
            let at = format!("crates/x/src/a.rs:{line}: ");
            assert!(
                unclassified.iter().any(|p| p.starts_with(&at)),
                "line {line}: {unclassified:?}"
            );
        }
        assert!(
            unclassified[0].contains(
                "`abstain(` is a degrade exit whose first argument `c` names no DegradeCode variant"
            ),
            "{unclassified:?}"
        );
        let home = degrade_emit_sites(
            &[(
                DEGRADE_HOME.to_string(),
                "pub fn also(self, c: DegradeCode) -> Self { abstain(c, ()); self }".to_string(),
            )],
            &m01_4_names(&["Alpha"]),
        );
        assert_eq!(home, (BTreeMap::new(), Vec::new()));
    }

    /// An exit named inside a string or raw string (a metric help text, an assertion message) is not an exit, and a
    /// local called `also` is not the method.
    #[test]
    fn degrade_emit_sites_ignore_exits_quoted_in_strings() {
        let src = [
            r#"const HELP: &str = "Fail-open exits through abstain(DegradeCode::Alpha, ()).";"#,
            r##"const RAW: &str = r#"o.also(DegradeCode::Beta)"#;"##,
            r#"const CH: char = '"'; const NEXT: &str = ".also(DegradeCode::AlphaTwo)";"#,
            "fn f(also: u8) -> u8 { also + 1 }",
        ]
        .join("\n");
        let (sites, unclassified) = m01_4_scan(&src);
        assert!(sites.is_empty(), "{sites:?}");
        assert!(unclassified.is_empty(), "{unclassified:?}");
    }

    #[test]
    fn mask_comments_and_literals_keeps_the_layout_and_the_code() {
        let src = "let a = \"x(\"; // y(\nlet b = '\"'; /* z( */ f(1);\nlet c = r#\"w(\"#;\n";
        let out = mask_comments_and_literals(src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(out.contains("let a =") && out.contains("f(1);") && out.contains("let c ="));
        for quoted in ["x(", "y(", "z(", "w("] {
            assert!(!out.contains(quoted), "{quoted}: {out}");
        }
    }

    #[test]
    fn degrade_emit_sites_skip_readers_comments_and_prefix_names() {
        let src = [
            "// abstain(DegradeCode::Alpha, ())",
            "fn f(c: DegradeCode) -> u64 {",
            "    let n = degrade_total_count(DegradeCode::Alpha);",
            "    match c { DegradeCode::Beta => 1, _ => 0 };",
            "    let all = DegradeCode::ALL;",
            "    abstain(DegradeCode::AlphaTwo, ());",
            "    n",
            "}",
        ]
        .join("\n");
        let (sites, unclassified) = m01_4_scan(&src);
        assert_eq!(
            sites.keys().map(String::as_str).collect::<Vec<_>>(),
            ["AlphaTwo"]
        );
        assert!(unclassified.is_empty(), "{unclassified:?}");
    }

    /// `degrade.rs` and `envelope.rs` gate a `fn` before their gated `mod`s, and `envelope.rs` has two test modules:
    /// every gated item is test code, only the production `fn` between them is not.
    #[test]
    fn degrade_emit_sites_ignore_every_cfg_test_item() {
        let src = [
            "#[cfg(test)]",
            "fn helper() { abstain(DegradeCode::Alpha, ()); }",
            "fn prod() { abstain(DegradeCode::Beta, ()); }",
            "#[cfg(test)]",
            "mod tests {",
            "    fn a() { abstain(DegradeCode::AlphaTwo, ()); }",
            "}",
            "#[cfg(test)]",
            "mod more {",
            "    fn b() { abstain(DegradeCode::Alpha, ()); }",
            "}",
        ]
        .join("\n");
        let sites = m01_4_sites(&src);
        assert_eq!(
            sites.keys().map(String::as_str).collect::<Vec<_>>(),
            ["Beta"]
        );
        assert_eq!(sites["Beta"], "crates/x/src/a.rs:3");
    }

    #[test]
    fn blank_cfg_test_items_keeps_lines_and_production_code() {
        let src = "fn a() {}\n#[cfg(test)]\nmod t {\n    fn x() {}\n}\nfn b() {}\n";
        let out = blank_cfg_test_items(src);
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(out.contains("fn a() {}") && out.contains("fn b() {}") && !out.contains("fn x"));
        let not_test = "#[cfg(not(test))]\nfn p() {}\n";
        assert_eq!(blank_cfg_test_items(not_test), not_test);
    }

    /// `run()` must list G-M01-4 exactly once (a deleted call tuple leaves a gate that never runs).
    #[test]
    fn run_wires_the_real_path_gate_exactly_once() {
        assert_eq!(
            own_source_count("m01_4_real_path_or_", "dormant(&root),"),
            1
        );
    }

    /// A scratch tree holding what G-M01-4 reads: the real `degrade.rs`, the real emitters `envelope.rs` and `rerank.rs`,
    /// the real fault tests, their `fault_main.rs` and the real ledger. The gate runs over it through [`m01_4_real_path_or_dormant`],
    /// paths and all.
    fn m01_4_tree(tag: &str) -> PathBuf {
        let tmp =
            std::env::temp_dir().join(format!("arch-check-m01-4-{tag}-{}", std::process::id()));
        fs::remove_dir_all(&tmp).ok();
        let fault = "crates/testkit/tests/fault";
        let mut rels: Vec<String> = [
            DEGRADE_HOME,
            "crates/retrieval/src/envelope.rs",
            "crates/retrieval/src/rerank.rs",
            DORMANT_FILE,
            FAULT_MAIN_FILE,
        ]
        .iter()
        .map(|r| (*r).to_string())
        .collect();
        for entry in fs::read_dir(real_root().join(fault)).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".rs") {
                rels.push(format!("{fault}/{name}"));
            }
        }
        for rel in rels {
            let to = tmp.join(&rel);
            fs::create_dir_all(to.parent().unwrap()).unwrap();
            fs::copy(real_root().join(&rel), &to).unwrap();
        }
        tmp
    }

    /// Runs the gate over a fresh scratch tree, asserts it is green, applies `edit`, and returns the failure text.
    fn m01_4_red(tag: &str, edit: impl FnOnce(&Path)) -> String {
        let tmp = m01_4_tree(tag);
        assert_eq!(
            m01_4_real_path_or_dormant(&tmp),
            Verdict::Pass,
            "{tag}: the unedited tree must be green"
        );
        edit(&tmp);
        let out = fail_lines(m01_4_real_path_or_dormant(&tmp));
        fs::remove_dir_all(&tmp).ok();
        out
    }

    /// Replaces the one occurrence of `from` in `tmp/rel` with `to`.
    fn m01_4_replace(tmp: &Path, rel: &str, from: &str, to: &str) {
        let path = tmp.join(rel);
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.matches(from).count(),
            1,
            "{rel}: `{from}` moved: update this fixture"
        );
        fs::write(path, text.replace(from, to)).unwrap();
    }

    /// Appends `extra` to `tmp/rel`.
    fn m01_4_append(tmp: &Path, rel: &str, extra: &str) {
        let path = tmp.join(rel);
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str(extra);
        fs::write(path, text).unwrap();
    }

    const M01_4_LAG_TEST: &str = "crates/testkit/tests/fault/projection_lag.rs";
    const M01_4_ENVELOPE: &str = "crates/retrieval/src/envelope.rs";

    /// r1: projection_lag.rs reaches the exit itself again.
    #[test]
    fn g_m01_4_scratch_tree_r1_fault_test_imports_abstain_is_red() {
        let out = m01_4_red("r1", |tmp| {
            let lag = fs::read_to_string(tmp.join(M01_4_LAG_TEST)).unwrap();
            let edited = format!("use humaux_telemetry::degrade::abstain;\n{lag}");
            fs::write(tmp.join(M01_4_LAG_TEST), edited).unwrap();
        });
        assert!(
            out.contains("ProjectionLag: production emit site crates/retrieval/src/envelope.rs:"),
            "{out}"
        );
        assert!(
            out.contains("projection_lag.rs:1 names the degrade exit `abstain`"),
            "{out}"
        );
    }

    /// r1b (M01-3 review B1): projection_lag.rs reaches the exit through `.also` and never writes `abstain`.
    #[test]
    fn g_m01_4_scratch_tree_r1b_fault_test_calls_also_is_red() {
        let out = m01_4_red("r1b", |tmp| {
            m01_4_append(
                tmp,
                M01_4_LAG_TEST,
                "\n#[test]\nfn bypass() {\n    let _ = humaux_telemetry::degrade::Outcome::clean(String::new()).also(DegradeCode::ProjectionLag);\n}\n",
            );
        });
        assert!(
            out.contains("ProjectionLag: production emit site crates/retrieval/src/envelope.rs:"),
            "{out}"
        );
        assert!(
            out.contains("projection_lag.rs:") && out.contains("names the degrade exit `also`"),
            "{out}"
        );
    }

    /// r2: a dormant row for a variant that has an emit site.
    #[test]
    fn g_m01_4_scratch_tree_r2_dormant_row_for_a_live_variant_is_red() {
        let out = m01_4_red("r2", |tmp| {
            m01_4_append(
                tmp,
                DORMANT_FILE,
                &format!("\n{}", m01_4_rows(&["ProjectionLag"])),
            );
        });
        assert!(
            out.contains("ProjectionLag: crates/testkit/tests/fault/dormant.toml still lists it"),
            "{out}"
        );
    }

    /// r3 (static half): the production emit is removed, so the variant is neither live nor listed.
    #[test]
    fn g_m01_4_scratch_tree_r3_removed_emit_is_red() {
        let out = m01_4_red("r3", |tmp| {
            m01_4_replace(
                tmp,
                M01_4_ENVELOPE,
                "out.also(DegradeCode::ProjectionLag)",
                "out",
            );
        });
        assert!(
            out.contains("ProjectionLag: no production emit site"),
            "{out}"
        );
    }

    /// W1: a qualified-path production emit of a dormant variant used to be invisible to the scan.
    #[test]
    fn g_m01_4_scratch_tree_w1_qualified_emit_of_a_dormant_variant_is_red() {
        let out = m01_4_red("w1", |tmp| {
            m01_4_append(
                tmp,
                M01_4_ENVELOPE,
                "\npub fn w1_probe() {\n    let _ = humaux_telemetry::degrade::abstain(humaux_telemetry::degrade::DegradeCode::EgressDenied, ());\n}\n",
            );
        });
        assert!(
            out.contains("EgressDenied: crates/testkit/tests/fault/dormant.toml still lists it, but it now has a production emit site (crates/retrieval/src/envelope.rs:"),
            "{out}"
        );
    }

    /// W1: an exit whose code is a parameter cannot be attributed, so it is red naming file:line.
    #[test]
    fn g_m01_4_scratch_tree_w1_exit_with_a_parameter_code_is_red() {
        let out = m01_4_red("w1b", |tmp| {
            m01_4_append(
                tmp,
                M01_4_ENVELOPE,
                "\npub fn w1_param(c: humaux_telemetry::degrade::DegradeCode) {\n    let _ = humaux_telemetry::degrade::abstain(c, ());\n}\n",
            );
        });
        assert!(
            out.contains("crates/retrieval/src/envelope.rs:")
                && out.contains("names no DegradeCode variant"),
            "{out}"
        );
    }

    /// W3: a fault file whose `mod` line is deleted from fault_main.rs is never compiled.
    #[test]
    fn g_m01_4_scratch_tree_w3_unwired_fault_file_is_red() {
        let out = m01_4_red("w3", |tmp| {
            m01_4_replace(
                tmp,
                FAULT_MAIN_FILE,
                "#[path = \"fault/lane_substituted.rs\"]\nmod lane_substituted;\n",
                "",
            );
        });
        assert!(
            out.contains("LaneSubstituted: crates/testkit/tests/fault/lane_substituted.rs exists but crates/testkit/tests/fault_main.rs has no"),
            "{out}"
        );
    }

    // -- §78 env::var boundary lint --------------------------------------------------------

    #[test]
    fn env_var_scan_flags_std_env_var() {
        let src = "fn f() {\n    let x = std::env::var(\"X\");\n}\n";
        assert_eq!(scan_env_var_violations("f.rs", src).len(), 1);
    }

    #[test]
    fn env_var_scan_ignores_comment() {
        let src = "// std::env::var(\"X\") is forbidden here\nfn f() {}\n";
        assert!(scan_env_var_violations("f.rs", src).is_empty());
    }

    #[test]
    fn env_var_scan_real_repo_passes() {
        let root = real_root();
        assert_eq!(env_var_scan(&root), Verdict::Pass);
    }

    /// 注错 (§78 boundary lints): inject `std::env::var` into a fixture file outside the
    /// contracts/bins exemption → red. Uses a tempdir copy, never the real crates tree.
    #[test]
    fn env_var_scan_fault_injected_call_outside_exemption_is_red() {
        let tmp = std::env::temp_dir().join(format!(
            "arch-check-envvar-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let crate_dir = tmp.join("crates/some_adapter/src");
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(
            crate_dir.join("lib.rs"),
            "pub fn f() { let _ = std::env::var(\"NOT_ALLOWED\"); }\n",
        )
        .unwrap();
        assert!(matches!(env_var_scan(&tmp), Verdict::Fail(_)));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn env_var_scan_exempts_contracts_dir() {
        let tmp = std::env::temp_dir().join(format!(
            "arch-check-envvar-exempt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let crate_dir = tmp.join("crates/contracts/src");
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(
            crate_dir.join("lib.rs"),
            "pub fn f() { let _ = std::env::var(\"OK_HERE\"); }\n",
        )
        .unwrap();
        assert_eq!(env_var_scan(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    // -- G80-2 / G80-22 --------------------------------------------------------------------

    #[test]
    fn g80_2_real_repo_passes() {
        let root = real_root();
        assert_eq!(g80_2_build_request_unique(&root), Verdict::Pass);
    }

    /// T1.6 delivers `evidence::payload_sha256` / `EvidencePayloadSha256` (§48.0① G80-22): the
    /// real-repo check flips from `NotApplicable` (Phase 6 undelivered) to `Pass` (exactly one
    /// construction site, in `crates/domain/src/evidence.rs`).
    #[test]
    fn g80_22_real_repo_passes() {
        let root = real_root();
        assert_eq!(g80_22_payload_sha256_unique(&root), Verdict::Pass);
    }

    /// Card 21 self-test for [`count_call_sites`] — the G80-4 needle. A **definition** of the
    /// function, in any file (a `tests/` helper is a definition too), is not a call site; a
    /// longer identifier that merely ends in the name is not a call site; a doc comment is not
    /// a call site. Exactly one of the six lines below is.
    ///
    /// This is the case the old raw-substring count got wrong: it scored 4 here.
    /// T18 (ADR-0059): one call site each is green; a second call site of any of the three names,
    /// or none at all, is red naming it. Then the live workspace is green.
    #[test]
    fn adr0059_role_ddl_and_parser_have_one_call_site_each() {
        let root = Path::new("/w");
        let one = "pub fn alter_role_password_sql(r: &str) {}\n\
                   fn a() { alter_role_password_sql(r); create_role_sql(r); parse_roles_sql(t); }\n";
        let files = vec![(root.join("a.rs"), one.to_owned())];
        assert!(sole_call_site_problems(root, &files).is_empty());
        let mut two = files.clone();
        two.push((
            root.join("b.rs"),
            "fn b() { create_role_sql(x); }".to_owned(),
        ));
        let problems = sole_call_site_problems(root, &two);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`create_role_sql(` call site, found 2"));
        let none = vec![(root.join("c.rs"), "fn c() {}".to_owned())];
        assert_eq!(sole_call_site_problems(root, &none).len(), 3);
        assert!(matches!(
            adr0059_role_hygiene_sole_call_sites(&workspace_root()),
            Verdict::Pass
        ));
    }

    /// T18 (ADR-0059 D-G): one production call of `install_token_keys(` and of
    /// `parse_token_fields(` is green; a test-tree call does not count; a second production call
    /// site is red naming it. Then the live workspace is green.
    #[test]
    fn adr0059_token_install_and_parser_have_one_production_call_site_each() {
        let root = Path::new("/w");
        let files = vec![
            (
                root.join("bins/gateway/src/bootstrap.rs"),
                "fn b() { install_token_keys(k); }".to_owned(),
            ),
            (
                root.join("crates/adapters/src/retrieve.rs"),
                "fn parse_token_fields(p: &str) {}\nfn v() { parse_token_fields(p); }".to_owned(),
            ),
            (
                root.join("crates/adapters/tests/support/token_keys.rs"),
                "fn i() { install_token_keys(k); }".to_owned(),
            ),
        ];
        assert!(token_sole_call_problems(root, &files).is_empty());
        let mut two = files.clone();
        two.push((
            root.join("bins/private-worker/src/main.rs"),
            "fn m() { install_token_keys(k); }".to_owned(),
        ));
        let problems = token_sole_call_problems(root, &two);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("`install_token_keys(` call site, found 2"));
        assert!(matches!(
            adr0059_token_sole_call_sites(&workspace_root()),
            Verdict::Pass
        ));
    }

    /// T31 (ADR-0060 D-B) — fault: a process descriptor literal in main.rs ⇒ 2 literals ⇒ red;
    /// the real workspace is green.
    #[test]
    fn route_provider_sources_are_single() {
        let root = Path::new("/r");
        let files = vec![
            (
                root.join("bins/private-worker/src/main.rs"),
                "fn b() { let r = RouteProviders::new(a, b, c, d, e); }".to_owned(),
            ),
            (
                root.join("bins/private-worker/src/route_providers.rs"),
                "fn p() { let d = ReasoningProviderDescriptor { x }; }".to_owned(),
            ),
            (
                root.join("crates/adapters/src/reasoning_route_admission.rs"),
                "fn w() { q(\"SELECT reasoning_profile_capabilities($1,$2)\"); }".to_owned(),
            ),
        ];
        assert!(route_provider_sole_site_problems(root, &files).is_empty());
        let mut two = files.clone();
        two.push((
            root.join("bins/private-worker/src/main.rs"),
            "fn m() { let d = ReasoningProviderDescriptor { y }; }".to_owned(),
        ));
        let problems = route_provider_sole_site_problems(root, &two);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("found 2"), "{problems:?}");
        assert!(matches!(
            adr0060_route_provider_sole_sites(&workspace_root()),
            Verdict::Pass
        ));
    }

    #[test]
    fn g80_4_needle_counts_calls_not_definitions_or_lookalikes() {
        let src = "\
pub async fn serving_version(f: &F) -> u8 { 0 }
/// doc that mentions serving_version(f)
fn other_serving_version(f: &F) -> u8 { 0 }
fn helper() { let _ = tenant_serving_version(f); }
fn consumer() { let _ = serving_version(&family); }
// serving_version(&family) in a comment
";
        assert_eq!(count_call_sites(src, "serving_version"), 1);
    }

    /// The specific shape the card names: a **test function whose name contains the needle**
    /// must not be an offender. `walk_workspace_rs` strips `#[cfg(test)]` modules, but a
    /// `crates/*/tests/*.rs` integration test is not one — so before card 21 this file would
    /// have pushed G80-4 to 2 and turned the gate red with no retrieval code changed at all.
    #[test]
    fn g80_4_a_test_function_named_after_the_needle_is_not_an_offender() {
        let integration_test = "\
#[tokio::test]
async fn serving_version(/* the fixture under test */) {
    let _ = 1;
}
#[tokio::test]
async fn serving_version_in_txn() {}
";
        assert_eq!(count_call_sites(integration_test, "serving_version"), 0);
        assert_eq!(
            count_call_sites(integration_test, "serving_version_in_txn"),
            0
        );
    }

    // -- §78.1/§15.1 ticket-family triple (card 21) -----------------------------------------

    #[test]
    fn ticket_family_gate_real_repo_passes() {
        assert_eq!(g78_1_ticket_family_literals(&real_root()), Verdict::Pass);
    }

    /// 注错: reintroduce one of the three literals into production source ⇒ red and named.
    /// This is the card's own fault-injection requirement ("reintroduce one literal and the
    /// scan must go red"), run as a fixture tree rather than a mutation of the real repo.
    #[test]
    fn ticket_family_gate_red_when_a_literal_comes_back() {
        let tmp = fresh_tmp("ticket-family-literal");
        let home = tmp.join("crates/domain/src");
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join("ticket_family.rs"),
            "pub enum TicketFamily { PrivateMemory }\n             impl TicketFamily { pub fn domain(self) -> &'static str { \"private_memory\" } }\n",
        )
        .unwrap();
        let victim = tmp.join("crates/adapters/src");
        fs::create_dir_all(&victim).unwrap();
        fs::write(
            victim.join("consolidate_repo.rs"),
            "pub fn key() -> (String, String) { (\"private_memory\".to_owned(), \"PRIVATE_MEMORY\".to_owned()) }\n",
        )
        .unwrap();
        match g78_1_ticket_family_literals(&tmp) {
            Verdict::Fail(f) => {
                let joined = f.join(" ");
                assert!(joined.contains("consolidate_repo.rs"), "{joined}");
                assert!(joined.contains("private_memory"), "{joined}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        // Removing the literal returns it to green — a red that cannot go green is not a gate.
        fs::write(
            victim.join("consolidate_repo.rs"),
            "pub fn key(f: TicketFamily) -> (&'static str, &'static str) { (f.domain(), f.projection_kind()) }\n",
        )
        .unwrap();
        assert_eq!(g78_1_ticket_family_literals(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// ADR-0006: `not_applicable` must name the missing object and must NOT coincide with the
    /// violation. With no `TicketFamily` at all the gate is NA, not silently green.
    #[test]
    fn ticket_family_gate_is_not_applicable_without_the_closed_set() {
        let tmp = fresh_tmp("ticket-family-na");
        let victim = tmp.join("crates/adapters/src");
        fs::create_dir_all(&victim).unwrap();
        fs::write(
            victim.join("x.rs"),
            "pub const D: &str = \"private_memory\";\n",
        )
        .unwrap();
        match g78_1_ticket_family_literals(&tmp) {
            Verdict::NotApplicable(m) => assert!(m.contains("TicketFamily"), "{m}"),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// Card 21 G80-22 widened 口径: a construction site outside the domain module is red, and
    /// a third site inside it is red. Fixture tree, never the real repo.
    #[test]
    fn g80_22_red_on_a_construction_site_outside_the_domain_module() {
        let tmp = fresh_tmp("g80-22-foreign");
        let home = tmp.join("crates/domain/src");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("evidence.rs"), COMPLIANT_EVIDENCE_FIXTURE).unwrap();
        let foreign = tmp.join("bins/gateway/src");
        fs::create_dir_all(&foreign).unwrap();
        fs::write(
            foreign.join("main.rs"),
            "fn f() { let _ = EvidencePayloadSha256([0u8; 32]); }\n",
        )
        .unwrap();
        match g80_22_payload_sha256_unique(&tmp) {
            Verdict::Fail(f) => assert!(f.join(" ").contains("bins/gateway/src/main.rs")),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// The read-back must stay a read-back: make it hash and the widened 口径 is void.
    #[test]
    fn g80_22_red_when_the_read_back_hashes() {
        let tmp = fresh_tmp("g80-22-rehash");
        let home = tmp.join("crates/domain/src");
        fs::create_dir_all(&home).unwrap();
        fs::write(
            home.join("evidence.rs"),
            "pub struct EvidencePayloadSha256([u8; 32]);\n             pub fn payload_sha256(b: &[u8]) -> EvidencePayloadSha256 { EvidencePayloadSha256(h(b)) }\n             impl EvidencePayloadSha256 {\n    pub fn from_stored_digest(s: &[u8]) -> Option<Self> {\n        Some(EvidencePayloadSha256(Sha256::digest(s).into()))\n    }\n}\n",
        )
        .unwrap();
        match g80_22_payload_sha256_unique(&tmp) {
            Verdict::Fail(f) => assert!(f.join(" ").contains("read-back must adopt")),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // ---- G80-43 (§11.10#G11-2) 注错族：fixture 树，不在真仓上变异 ----

    /// 最小合规 fixture：一个 `grounding.rs`，八条夹具齐、派生点恰一处、无手改 stale。
    /// `stub = true` 时派生点写成 `todo!()`——那是 G80-43 第 3 条断言要抓的形态，
    /// 不是合规 fixture 的默认长相（先前默认就是 todo!()，导致「闸对桩无感」这个洞
    /// 被自己的绿色测试盖住了，由对抗审查打出来）。
    fn grounding_fixture_inner(dir: &Path, fixtures: &[&str], derive_sites: usize, stub: bool) {
        fs::create_dir_all(dir).unwrap();
        let body = if stub {
            "{ todo!() }"
        } else {
            // 最小但**不是桩**的真函数体：形状够真，判据只看「不是 todo!()/unimplemented!()」。
            "{ let _ = i; GroundingState(GroundingStateKind::Current) }"
        };
        let mut src = String::new();
        for _ in 0..derive_sites {
            src.push_str(&format!(
                "pub fn derive_grounding_state(i: GroundingInputs<'_>) -> GroundingState {body}\n"
            ));
        }
        for f in fixtures {
            src.push_str(&format!("#[test]\nfn {f}() {{}}\n"));
        }
        fs::write(dir.join("grounding.rs"), src).unwrap();
    }

    /// 合规 fixture（非桩）。
    fn grounding_fixture(dir: &Path, fixtures: &[&str], derive_sites: usize) {
        grounding_fixture_inner(dir, fixtures, derive_sites, false);
    }

    const ALL_EIGHT: [&str; 8] = [
        "fixture_a_same_version_is_current",
        "fixture_b_changed_version_is_recheck_required",
        "fixture_c_missing_resource_is_unresolved",
        "fixture_d_resolver_error_is_cannot_establish_not_missing",
        "fixture_e_relocation_with_same_token_stays_current",
        "fixture_f_source_changed_mid_revalidation_is_stale_input",
        "fixture_g_recheck_required_must_not_enter_mandatory_context",
        "fixture_h_after_confirm_rebinding_returns_to_current",
    ];

    #[test]
    fn g80_43_green_on_compliant_fixture() {
        let tmp = fresh_tmp("g80-43-green");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 1);
        assert_eq!(g80_43_grounding_validity(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ①：删掉夹具 D（「resolver error 不能伪装 Missing」那条）→ 红并点名。
    /// 这正是判据静默变弱的形态：`cargo test` 少跑一条，全绿如故。
    #[test]
    fn g80_43_red_when_a_fixture_is_deleted() {
        let tmp = fresh_tmp("g80-43-red-fixture");
        let seven: Vec<&str> = ALL_EIGHT
            .iter()
            .copied()
            .filter(|f| !f.starts_with("fixture_d_"))
            .collect();
        grounding_fixture(&tmp.join("crates/domain/src"), &seven, 1);
        match g80_43_grounding_validity(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter().any(|m| m.contains("fn fixture_d_")),
                "必须点名缺失的那条夹具，而不是只说「有东西不对」: {v:?}"
            ),
            other => panic!("删掉夹具 D 必须红，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ②：派生点被掏空（0 处）→ 活哨兵红。没有这条的话，`grounding.rs` 被清空成一个
    /// 只剩八条空测试的壳，前一条断言照样绿。
    #[test]
    fn g80_43_red_when_derivation_point_is_gone() {
        let tmp = fresh_tmp("g80-43-red-nohome");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 0);
        match g80_43_grounding_validity(&tmp) {
            Verdict::Fail(v) => assert!(v.iter().any(|m| m.contains("positive sentinel")), "{v:?}"),
            other => panic!("派生点消失必须红，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ③：出现第二个派生点 → 活哨兵同样红（`!= 1` 不是 `< 1`）。
    #[test]
    fn g80_43_red_on_second_derivation_point() {
        let tmp = fresh_tmp("g80-43-red-two");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 2);
        assert!(
            matches!(g80_43_grounding_validity(&tmp), Verdict::Fail(_)),
            "两个派生点必须红"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ④：派生点**在场但是桩** → 红。
    ///
    /// 这条是对抗审查的产物：先前三条断言只看 `pub fn derive_grounding_state(` 在不在，
    /// 于是 `{ todo!() }` 也判 Pass——闸绿着，而 spec §11.10 点名的注错（删掉 version
    /// compare）它一点感觉都没有。审查员正是拿本 fixture 当时的绿色证明了这个洞。
    #[test]
    fn g80_43_red_when_derivation_point_is_a_stub() {
        let tmp = fresh_tmp("g80-43-red-stub");
        grounding_fixture_inner(&tmp.join("crates/domain/src"), &ALL_EIGHT, 1, true);
        match g80_43_grounding_validity(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter()
                    .any(|m| m.contains("是桩") && m.contains("derive_grounding_state")),
                "必须点名「派生点是桩」，而不是含糊报错: {v:?}"
            ),
            other => panic!("桩化的派生点必须红，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ⑤：DOD-092 —— 别处冒出一个可手改的 stale 真源 → 红并点名文件。
    #[test]
    fn g80_43_red_on_hand_settable_stale_flag() {
        let tmp = fresh_tmp("g80-43-red-stale");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 1);
        let other = tmp.join("crates/adapters/src");
        fs::create_dir_all(&other).unwrap();
        fs::write(
            other.join("repo.rs"),
            "fn mark(m: &mut Memory) {\n    m.stale = true;\n}\n",
        )
        .unwrap();
        match g80_43_grounding_validity(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter()
                    .any(|m| m.contains("repo.rs") && m.contains("DOD-092")),
                "{v:?}"
            ),
            other => panic!("手改 stale 必须红，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 ⑤：连赋值都没有，只是**声明**了一个可写的 `stale: bool` 字段 -> 仍然红。
    /// 这条钉的是 DOD-092 的「真源」二字：字段一旦存在，`*r = true` 之类的间接赋值就有了
    /// 落点，而那些写法逃得过赋值形态的匹配。
    #[test]
    fn g80_43_red_on_stale_field_declaration_even_without_assignment() {
        let tmp = fresh_tmp("g80-43-red-field");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 1);
        let other = tmp.join("crates/domain/src");
        fs::write(
            other.join("memory.rs"),
            "pub struct MemoryRow {\n    pub stale: bool,\n}\n",
        )
        .unwrap();
        match g80_43_grounding_validity(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter()
                    .any(|m| m.contains("memory.rs") && m.contains("DOD-092")),
                "{v:?}"
            ),
            other => panic!("可写 stale 字段的声明必须红，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 反向对照：**读** stale 不是 DOD-092 禁的事，只有赋值才是。没有这条的话，判据可能被
    /// 写成粗暴匹配 `stale`，把合法的读判定也误报成违规（G80-3 上线首日就是这类误报）。
    #[test]
    fn g80_43_reading_a_stale_field_is_not_a_violation() {
        let tmp = fresh_tmp("g80-43-green-read");
        grounding_fixture(&tmp.join("crates/domain/src"), &ALL_EIGHT, 1);
        let other = tmp.join("crates/adapters/src");
        fs::create_dir_all(&other).unwrap();
        fs::write(
            other.join("repo.rs"),
            "fn is_stale(m: &Memory) -> bool {\n    m.stale\n}\n",
        )
        .unwrap();
        assert_eq!(g80_43_grounding_validity(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 三态：被测对象整个不存在（Phase 4 之前）→ `not_applicable` 并**点名缺失对象**，
    /// 不是静默 pass（§57.1 第2条）。
    #[test]
    fn g80_43_not_applicable_without_the_grounding_module() {
        let tmp = fresh_tmp("g80-43-na");
        fs::create_dir_all(tmp.join("crates/domain/src")).unwrap();
        match g80_43_grounding_validity(&tmp) {
            Verdict::NotApplicable(m) => {
                assert!(m.contains("missing object"), "{m}");
                assert!(m.contains("grounding.rs"), "{m}");
            }
            other => panic!("缺被测对象时必须 not_applicable 并点名，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 真仓现状：Phase 4 的 grounding 已交付 → pass。
    #[test]
    fn g80_43_real_repo_passes() {
        assert_eq!(g80_43_grounding_validity(&real_root()), Verdict::Pass);
    }

    // ---- G80-4 (§16.2 换代期读路由) 注错族 ----

    /// 造一棵最小树：`serving_repo.rs` 里有定义，`consumers` 里各放一个调用点。
    fn serving_version_fixture(root: &Path, consumers: &[(&str, usize)]) {
        let def = root.join("crates/adapters/src");
        fs::create_dir_all(&def).unwrap();
        fs::write(
            def.join("serving_repo.rs"),
            "pub async fn serving_version(pool: &P, f: &F) -> R { todo!() }\n",
        )
        .unwrap();
        for (rel, n) in consumers {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let body: String = (0..*n)
                .map(|_| "    let _ = serving_version(pool, &f).await;\n".to_string())
                .collect();
            fs::write(&path, format!("pub async fn consume() {{\n{body}}}\n")).unwrap();
        }
    }

    #[test]
    fn g80_4_passes_with_exactly_one_consumer_call_site() {
        let tmp = fresh_tmp("g80-4-green");
        serving_version_fixture(&tmp, &[("crates/adapters/src/retrieve.rs", 1)]);
        assert_eq!(g80_4_serving_version_sole_entry_point(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn g80_4_transaction_form_preserves_the_single_consumer_constraint() {
        let tmp = fresh_tmp("g80-4-transaction");
        let consumer = "crates/adapters/src/retrieve.rs";
        serving_version_fixture(&tmp, &[(consumer, 1)]);
        let path = tmp.join(consumer);
        let original = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            original.replace("serving_version(", "serving_version_in_txn("),
        )
        .unwrap();
        assert_eq!(g80_4_serving_version_sole_entry_point(&tmp), Verdict::Pass);

        // One caller of each spelling is still two consumers, not two independent passes.
        fs::write(tmp.join("crates/adapters/src/second.rs"), original).unwrap();
        assert!(matches!(
            g80_4_serving_version_sole_entry_point(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// **本族最重要的一条。** 零调用点 = §16.2 被违反的状态本身，必须判 `Fail` 而**不是**
    /// `NotApplicable`。先前那版正是在这里判 NA，于是闸在违规最严重时最安静（ADR-0006）。
    #[test]
    fn g80_4_zero_call_sites_is_fail_not_not_applicable() {
        let tmp = fresh_tmp("g80-4-zero");
        serving_version_fixture(&tmp, &[]);
        match g80_4_serving_version_sole_entry_point(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter().any(|m| m.contains("消费侧调用点为 0")),
                "必须点名「一个调用点都没有」而不是含糊报错: {v:?}"
            ),
            other => panic!(
                "零调用点必须红——那正是违规状态本身，判 not_applicable 等于把违规当成\
                 「没什么可判的」。实得 {other:?}"
            ),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 三态：被测对象（`serving_version` 函数本身）真的不存在时才 NA，且必须点名。
    #[test]
    fn g80_4_not_applicable_only_when_the_function_itself_is_absent() {
        let tmp = fresh_tmp("g80-4-na");
        fs::create_dir_all(tmp.join("crates/adapters/src")).unwrap();
        fs::write(
            tmp.join("crates/adapters/src/retrieve.rs"),
            "pub fn nothing() {}\n",
        )
        .unwrap();
        match g80_4_serving_version_sole_entry_point(&tmp) {
            Verdict::NotApplicable(m) => {
                assert!(m.contains("missing object"), "{m}");
                assert!(m.contains("serving_version"), "{m}");
            }
            other => panic!("函数本身不存在时才该 NA，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 第二个调用点 → 红（`== 1` 不是 `>= 1`）。
    #[test]
    fn g80_4_red_on_a_second_consumer_call_site() {
        let tmp = fresh_tmp("g80-4-two");
        serving_version_fixture(
            &tmp,
            &[
                ("crates/adapters/src/retrieve.rs", 1),
                ("crates/retrieval/src/planner.rs", 1),
            ],
        );
        assert!(
            matches!(
                g80_4_serving_version_sole_entry_point(&tmp),
                Verdict::Fail(_)
            ),
            "两个消费侧调用点必须红"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 排除按**精确路径**而非子串：调用点藏进一个路径含 `serving_repo` 子串的文件里，
    /// 照样要被数到。先前那版 `disp.contains("serving_repo")` 会把它整个排除 = 假绿。
    #[test]
    fn g80_4_substring_named_file_does_not_escape_the_count() {
        let tmp = fresh_tmp("g80-4-substr");
        serving_version_fixture(
            &tmp,
            &[
                ("crates/adapters/src/retrieve.rs", 1),
                ("crates/adapters/src/serving_repo_client.rs", 1),
            ],
        );
        match g80_4_serving_version_sole_entry_point(&tmp) {
            Verdict::Fail(v) => assert!(
                v.iter().any(|m| m.contains("serving_repo_client.rs")),
                "藏在子串同名文件里的调用点必须被点名: {v:?}"
            ),
            other => panic!("子串同名文件不得逃过计数，实得 {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 真仓现状：读路径已接入 ⇒ 恰好一处 ⇒ pass。
    #[test]
    fn g80_4_real_repo_passes() {
        assert_eq!(
            g80_4_serving_version_sole_entry_point(&real_root()),
            Verdict::Pass
        );
    }

    /// The card-21-compliant shape of `crates/domain/src/evidence.rs`: exactly two construction
    /// sites in the one module — the hasher and the non-hashing read-back.
    const COMPLIANT_EVIDENCE_FIXTURE: &str = "struct EvidencePayloadSha256([u8; 32]);\npub fn payload_sha256(bytes: &[u8]) -> EvidencePayloadSha256 {\n    EvidencePayloadSha256([0; 32])\n}\nimpl EvidencePayloadSha256 {\n    pub fn from_stored_digest(s: &[u8]) -> Option<Self> {\n        Some(EvidencePayloadSha256(<[u8; 32]>::try_from(s).ok()?))\n    }\n}\n";

    fn fresh_tmp(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "arch-check-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn g80_2_passes_with_exactly_one_construction_site() {
        let tmp = fresh_tmp("g80-2-green");
        let dir = tmp.join("crates/retrieval/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("lib.rs"),
            "struct RetrievalRequest { limit: usize }\npub fn build_request() -> RetrievalRequest {\n    RetrievalRequest { limit: 5 }\n}\n",
        )
        .unwrap();
        assert_eq!(g80_2_build_request_unique(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G80-2, §80.1.1): a second construction site in the real top-level `evals/` — a
    /// sibling of `crates/`, **not** nested under it — → count 1→2 → 红. Placing it as a true
    /// sibling (rather than `crates/evals_stand_in/`) is the point: the old crates/-only scan
    /// domain would have missed this fault entirely (evals/ sits outside crates/), so this
    /// test only passes because the scan domain is now the whole workspace root.
    #[test]
    fn g80_2_fails_with_second_construction_site_in_real_evals_dir() {
        let tmp = fresh_tmp("g80-2-red-evals");
        let dir = tmp.join("crates/retrieval/src");
        let evals_dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&evals_dir).unwrap();
        fs::write(
            dir.join("lib.rs"),
            "struct RetrievalRequest { limit: usize }\npub fn build_request() -> RetrievalRequest {\n    RetrievalRequest { limit: 5 }\n}\n",
        )
        .unwrap();
        fs::write(
            evals_dir.join("probe.rs"),
            "fn shortcut() { let _ = RetrievalRequest { limit: 60 }; }\n",
        )
        .unwrap();
        assert!(matches!(g80_2_build_request_unique(&tmp), Verdict::Fail(_)));
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §55.6 G55-6 ① -------------------------------------------------------------------

    /// A request type whose depth values are private or `pub(crate)` and whose constructor takes only the intent and
    /// the registered profile.
    const G55_6_COMPLIANT: &str = "pub struct RetrievalRequest {\n    intent: IntentKind,\n    top_k: u32,\n    pub(crate) cand_k: u32,\n}\npub fn build_request(\n    intent: RetrievalIntent,\n    profile: &RegisteredRetrievalProfile,\n) -> Result<RetrievalRequest, RequestBuildError> {\n    todo!()\n}\n";

    /// Positive control for G55-6 ①: the matcher reads the real request type and constructor, finds exactly the two
    /// parameters, and the real tree passes.
    #[test]
    fn g55_6_1_real_repo_passes_and_the_matcher_is_not_blind() {
        let root = real_root();
        let request = fs::read_to_string(root.join("crates/retrieval/src/request.rs")).unwrap();
        assert_eq!(
            g55_6_caller_assignable_names(&request),
            BTreeSet::from(["intent".to_string(), "profile".to_string()])
        );
        assert_eq!(g55_6_1_caller_depth_names(&root), Verdict::Pass);
    }

    #[test]
    fn g55_6_1_private_depth_fields_are_not_caller_input() {
        assert!(g55_6_offenders(G55_6_COMPLIANT).is_empty());
    }

    /// 注错 ① (Baseline §55.6): `top_k_override: Option<usize>` on `build_request` → the intersection is {top_k} → 红.
    #[test]
    fn g55_6_1_top_k_override_parameter_is_red() {
        let injected = G55_6_COMPLIANT.replace(
            "profile: &RegisteredRetrievalProfile,",
            "profile: &RegisteredRetrievalProfile,\n    top_k_override: Option<usize>,",
        );
        assert_eq!(
            g55_6_offenders(&injected),
            vec!["`top_k_override` carries `top_k`".to_string()]
        );
    }

    /// 注错 (T-RET-6c-1, T-RET-6c-2, ADR-0083 D-D): each of the five registry names, as a `build_request` parameter and as a
    /// plain-`pub` field, → 红. The list here is deliberately a second copy: dropping a name from
    /// [`G55_6_FORBIDDEN_NAMES`] makes its row red.
    #[test]
    fn g55_6_1_each_hybrid_registry_name_is_refused_as_parameter_and_pub_field() {
        for name in [
            "cand_multiplier",
            "leg_depth",
            "rrf_k",
            "sparse_leg_enabled",
            "sparse_timeout_ms",
        ] {
            assert!(
                G55_6_FORBIDDEN_NAMES.contains(&name),
                "{name} is in the set"
            );
            let as_param =
                G55_6_COMPLIANT.replace("profile: &", &format!("{name}: u32,\n    profile: &"));
            assert_eq!(g55_6_offenders(&as_param).len(), 1, "{name} as a parameter");
            let as_field =
                G55_6_COMPLIANT.replace("    top_k: u32,", &format!("    pub {name}: u32,"));
            assert_eq!(g55_6_offenders(&as_field).len(), 1, "{name} as a pub field");
        }
    }

    /// 注错 (T-RET-7d-2, ADR-0084 D-E): each of the five rerank registry names, as a `build_request` parameter and as a
    /// plain-`pub` field, → 红. `rerank_depth` is caught by the word `depth` and is not in the set; the other four are
    /// in it. The list here is deliberately a second copy: dropping a name from [`G55_6_FORBIDDEN_NAMES`] makes its row red.
    #[test]
    fn g55_6_1_each_rerank_registry_name_is_refused_as_parameter_and_pub_field() {
        for name in [
            "rerank_enabled",
            "rerank_depth",
            "rerank_max_len",
            "rerank_timeout_ms",
            "rerank_threads",
        ] {
            assert_eq!(
                G55_6_FORBIDDEN_NAMES.contains(&name),
                name != "rerank_depth",
                "{name}: in the set exactly when `depth` does not already catch it"
            );
            let as_param =
                G55_6_COMPLIANT.replace("profile: &", &format!("{name}: u32,\n    profile: &"));
            assert_eq!(g55_6_offenders(&as_param).len(), 1, "{name} as a parameter");
            let as_field =
                G55_6_COMPLIANT.replace("    top_k: u32,", &format!("    pub {name}: u32,"));
            assert_eq!(g55_6_offenders(&as_field).len(), 1, "{name} as a pub field");
        }
    }

    fn g55_6_tree(label: &str, lib_rs: Option<&str>) -> PathBuf {
        let tmp = fresh_tmp(label);
        fs::create_dir_all(&tmp).unwrap();
        if let Some(source) = lib_rs {
            let dir = tmp.join("crates/retrieval/src");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("lib.rs"), source).unwrap();
        }
        tmp
    }

    /// G55-6 ① `Fail` branch, over a fixture tree like G80-2's: a caller-assignable `top_k_override` parameter in a
    /// `build_request` → red, naming the parameter and the file.
    #[test]
    fn g55_6_1_fails_on_a_caller_assignable_depth_parameter_in_a_tree() {
        let tmp = g55_6_tree(
            "g55-6-red",
            Some(
                "pub struct RetrievalRequest {\n    intent: u8,\n}\npub fn build_request(\n    intent: u8,\n    top_k_override: Option<usize>,\n) -> RetrievalRequest {\n    RetrievalRequest { intent }\n}\n",
            ),
        );
        match g55_6_1_caller_depth_names(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines
                    .iter()
                    .any(|l| l.contains("top_k_override") && l.contains("lib.rs")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// G55-6 ① `NotApplicable` branch: a tree with no request type and no constructor → not applicable, naming
    /// the missing object (§57.1 第2条).
    #[test]
    fn g55_6_1_is_not_applicable_on_an_empty_tree_and_names_the_missing_object() {
        let tmp = g55_6_tree("g55-6-na", None);
        match g55_6_1_caller_depth_names(&tmp) {
            Verdict::NotApplicable(object) => assert!(
                object.contains("RetrievalRequest") && object.contains("build_request"),
                "{object}"
            ),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// G55-6 ① fails closed: the type exists but only as `pub(crate) struct RetrievalRequest`, a spelling the matcher
    /// does not read → red naming the file, never `not_applicable` and never a pass.
    #[test]
    fn g55_6_1_fails_closed_when_the_request_type_is_spelled_beyond_the_matcher() {
        let tmp = g55_6_tree(
            "g55-6-loose",
            Some(
                "pub(crate) struct RetrievalRequest {\n    pub top_k: u32,\n}\npub fn build_request() {}\n",
            ),
        );
        match g55_6_1_caller_depth_names(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines
                    .iter()
                    .any(|l| l.contains("lib.rs") && l.contains("cannot read")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// Card 21 widened the 口径: the compliant fixture now carries BOTH legs — the hasher and
    /// the non-hashing read-back — and both must live in `crates/domain/src/evidence.rs`.
    #[test]
    fn g80_22_passes_with_the_hasher_and_the_read_back_in_the_domain_module() {
        let tmp = fresh_tmp("g80-22-green");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("evidence.rs"), COMPLIANT_EVIDENCE_FIXTURE).unwrap();
        assert_eq!(g80_22_payload_sha256_unique(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// The hasher alone is no longer enough: without the read-back leg the §16.1 fingerprint
    /// cannot be recomputed from storage, which is the defect card 21 fixed.
    #[test]
    fn g80_22_red_when_the_read_back_leg_is_missing() {
        let tmp = fresh_tmp("g80-22-red-no-readback");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("evidence.rs"),
            "struct EvidencePayloadSha256([u8; 32]);\npub fn payload_sha256(bytes: &[u8]) -> EvidencePayloadSha256 {\n    EvidencePayloadSha256([0; 32])\n}\n",
        )
        .unwrap();
        match g80_22_payload_sha256_unique(&tmp) {
            Verdict::Fail(f) => assert!(f.join(" ").contains("from_stored_digest")),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// A THIRD construction site inside the home module is still red — the widening added one
    /// named operation, it did not open the module up.
    #[test]
    fn g80_22_red_on_a_third_construction_site_in_the_home_module() {
        let tmp = fresh_tmp("g80-22-red-third");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        let mut src = COMPLIANT_EVIDENCE_FIXTURE.to_string();
        src.push_str(
            "pub fn sneaky() -> EvidencePayloadSha256 { EvidencePayloadSha256([1; 32]) }\n",
        );
        fs::write(dir.join("evidence.rs"), src).unwrap();
        match g80_22_payload_sha256_unique(&tmp) {
            Verdict::Fail(f) => assert!(f.join(" ").contains("exactly 2 construction sites")),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G80-22, §48.0①): matcher's type name typo'd to a nonexistent name → 0 hits → 红
    /// (same shape as §59.1 G59-3 注错 b — this is exercised at the pure-fn level directly).
    #[test]
    fn g80_22_fails_when_object_exists_but_zero_construction_sites_found() {
        let tmp = fresh_tmp("g80-22-red-zero");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        // object exists (fn payload_sha256 defined) but never actually constructs the newtype
        // under its real name — simulates the matcher-typo failure mode.
        fs::write(
            dir.join("evidence.rs"),
            "struct EvidencePayloadSha256([u8; 32]);\npub fn payload_sha256(bytes: &[u8]) -> EvidencePayloadSha256 {\n    todo!()\n}\n",
        )
        .unwrap();
        assert!(matches!(
            g80_22_payload_sha256_unique(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G80-22, §48.0①): same shape as `g80_2_fails_with_second_construction_site_in_real_evals_dir`
    /// — the second site lives in a real top-level `evals/`, outside the old crates/-only scan
    /// domain, proving the widened workspace-root walk (not a crates/-nested stand-in) is what
    /// catches it.
    #[test]
    fn g80_22_fails_with_second_construction_site_in_real_evals_dir() {
        let tmp = fresh_tmp("g80-22-red-evals");
        let dir = tmp.join("crates/domain/src");
        let evals_dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&evals_dir).unwrap();
        fs::write(dir.join("evidence.rs"), COMPLIANT_EVIDENCE_FIXTURE).unwrap();
        fs::write(
            evals_dir.join("probe.rs"),
            "fn shortcut() { let _ = EvidencePayloadSha256([1; 32]); }\n",
        )
        .unwrap();
        assert!(matches!(
            g80_22_payload_sha256_unique(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §1.3/§48.0 G80-11 (source_hash leg, T5.1) -------------------------------------------

    /// T5.1 delivers `projection::fingerprint::source_hash` / `SourceHash`: the real-repo
    /// check flips from `NotApplicable` to `Pass` (exactly one construction site, in
    /// `crates/projection/src/fingerprint.rs`) the same way G80-22 did for T1.6.
    #[test]
    fn g80_11_real_repo_passes() {
        let root = real_root();
        assert_eq!(g80_11_source_hash_unique(&root), Verdict::Pass);
    }

    #[test]
    fn g80_11_passes_with_exactly_one_construction_site() {
        let tmp = fresh_tmp("g80-11-green");
        let dir = tmp.join("crates/projection/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("fingerprint.rs"),
            "struct SourceHash([u8; 32]);\npub fn source_hash(x: u64) -> SourceHash {\n    SourceHash([0; 32])\n}\n",
        )
        .unwrap();
        assert_eq!(g80_11_source_hash_unique(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G80-11): matcher's type name typo'd to a nonexistent name → 0 hits → 红 (same
    /// shape as G80-22's zero-construction-sites 注错).
    #[test]
    fn g80_11_fails_when_object_exists_but_zero_construction_sites_found() {
        let tmp = fresh_tmp("g80-11-red-zero");
        let dir = tmp.join("crates/projection/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("fingerprint.rs"),
            "struct SourceHash([u8; 32]);\npub fn source_hash(x: u64) -> SourceHash {\n    todo!()\n}\n",
        )
        .unwrap();
        assert!(matches!(g80_11_source_hash_unique(&tmp), Verdict::Fail(_)));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G80-11): a second construction site in the real top-level `evals/` — same shape
    /// as G80-22's evals/ 注错, proving the workspace-root scan (not a crates/-only one)
    /// catches a second crate re-deriving the fingerprint encoding.
    #[test]
    fn g80_11_fails_with_second_construction_site_in_real_evals_dir() {
        let tmp = fresh_tmp("g80-11-red-evals");
        let dir = tmp.join("crates/projection/src");
        let evals_dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&evals_dir).unwrap();
        fs::write(
            dir.join("fingerprint.rs"),
            "struct SourceHash([u8; 32]);\npub fn source_hash(x: u64) -> SourceHash {\n    SourceHash([0; 32])\n}\n",
        )
        .unwrap();
        fs::write(
            evals_dir.join("probe.rs"),
            "fn shortcut() { let _ = SourceHash([1; 32]); }\n",
        )
        .unwrap();
        assert!(matches!(g80_11_source_hash_unique(&tmp), Verdict::Fail(_)));
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M07 D9 / G-M07-1: one INSERT statement per door ------------------------------------

    const M07_EVIDENCE_HOME: &str = "crates/adapters/src/evidence_repo.rs";
    const M07_MEMORY_HOME: &str = "crates/adapters/src/memory_repo.rs";
    const M07_EVIDENCE_DOOR: &str =
        "fn door() { let _ = \"INSERT INTO private.evidence_objects (tenant_id) VALUES ($1)\"; }\n";
    const M07_MEMORY_DOOR: &str =
        "fn door() { let _ = \"INSERT INTO private.memory_records (tenant_id) VALUES ($1)\"; }\n";

    fn m07_write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    fn m07_fail_lines(root: &Path) -> Vec<String> {
        match m07_1_insert_doors(root) {
            Verdict::Fail(lines) => lines,
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The tree as M07-1 leaves it: one statement per door, in its home file.
    #[test]
    fn m07_1_real_repo_passes() {
        assert_eq!(m07_1_insert_doors(&real_root()), Verdict::Pass);
    }

    /// Green fixture, plus everything that must NOT count: a comment naming the statement, an integration-test
    /// tree, `bins/*/tests` and `xtask/tests` trees, and a statement after a file's trailing `#[cfg(test)] mod`.
    #[test]
    fn m07_1_passes_with_one_statement_per_door_and_ignores_test_and_comment_text() {
        let tmp = fresh_tmp("m07-1-green");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "// the single INSERT INTO private.memory_records lives in memory_repo\n\
             fn f() {}\n\
             #[cfg(test)]\n\
             mod tests { fn t() { let _ = \"INSERT INTO private.memory_records (x) VALUES (1)\"; } }\n",
        );
        m07_write(
            &tmp,
            "crates/adapters/tests/seed.rs",
            "fn seed() { let _ = \"INSERT INTO private.evidence_objects (x) VALUES (1)\"; }\n",
        );
        m07_write(
            &tmp,
            "bins/worker/tests/seed.rs",
            "fn seed() { let _ = \"INSERT INTO private.memory_records (x) VALUES (1)\"; }\n",
        );
        m07_write(
            &tmp,
            "xtask/tests/seed.rs",
            "fn seed() { let _ = \"INSERT INTO private.evidence_objects (x) VALUES (1)\"; }\n",
        );
        assert_eq!(m07_1_insert_doors(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// `not_applicable` names the missing objects (§57.1 第2条): neither home file exists yet.
    #[test]
    fn m07_1_is_not_applicable_naming_both_missing_door_files() {
        let tmp = fresh_tmp("m07-1-na");
        fs::create_dir_all(&tmp).unwrap();
        match m07_1_insert_doors(&tmp) {
            Verdict::NotApplicable(detail) => {
                assert!(detail.contains(M07_EVIDENCE_HOME), "{detail}");
                assert!(detail.contains(M07_MEMORY_HOME), "{detail}");
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1): a second `INSERT INTO private.memory_records` in the Distill hop's file → 红, naming the file.
    #[test]
    fn m07_1_fails_on_a_duplicate_memory_insert_in_another_src_file() {
        let tmp = fresh_tmp("m07-1-red-memory");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(&tmp, "crates/adapters/src/distill_repo.rs", M07_MEMORY_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("INSERT INTO private.memory_records"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("crates/adapters/src/distill_repo.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1): a second Evidence INSERT in a bin's `src/` → 红. The memory door's file is absent here, so this
    /// also pins that a failing door is not masked by the other door's `not_applicable`.
    #[test]
    fn m07_1_fails_on_a_duplicate_evidence_insert_even_when_the_other_door_is_missing() {
        let tmp = fresh_tmp("m07-1-red-evidence");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, "bins/worker/src/seed.rs", M07_EVIDENCE_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert!(
            lines[0].contains("INSERT INTO private.evidence_objects"),
            "{lines:?}"
        );
        assert!(lines[0].contains("bins/worker/src/seed.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1): the home file exists but its statement is gone → 红 with 0 found, never "no duplicates, pass".
    #[test]
    fn m07_1_fails_when_the_home_file_exists_but_holds_no_statement() {
        let tmp = fresh_tmp("m07-1-red-zero");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, "fn door() {}\n");
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("found 0"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1): exactly one statement, but outside the door's file (the old home) → 红.
    #[test]
    fn m07_1_fails_when_the_only_statement_sits_outside_the_home_file() {
        let tmp = fresh_tmp("m07-1-red-moved");
        m07_write(&tmp, M07_EVIDENCE_HOME, "fn door() {}\n");
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(&tmp, "crates/adapters/src/remember.rs", M07_EVIDENCE_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("found 1"), "{lines:?}");
        assert!(
            lines[0].contains("crates/adapters/src/remember.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W1): the home file is renamed away and the statement lives on in two stray files. A missing
    /// home must not turn the scan into `not_applicable`: the statement exists, so it is 红 and names the missing home.
    #[test]
    fn m07_1_fails_naming_the_missing_home_when_the_statement_exists_elsewhere() {
        let tmp = fresh_tmp("m07-1-red-renamed-home");
        m07_write(
            &tmp,
            "crates/adapters/src/evidence_store.rs",
            M07_EVIDENCE_DOOR,
        );
        m07_write(&tmp, "crates/adapters/src/remember.rs", M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(M07_EVIDENCE_HOME), "{lines:?}");
        assert!(lines[0].contains("does not exist"), "{lines:?}");
        assert!(lines[0].contains("found 2"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W1): even ONE statement elsewhere with the home file gone is 红, not `not_applicable`.
    #[test]
    fn m07_1_fails_when_the_only_statement_exists_and_the_home_file_is_missing() {
        let tmp = fresh_tmp("m07-1-red-home-missing");
        m07_write(&tmp, "crates/adapters/src/remember.rs", M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("does not exist"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W2): a `tests` directory INSIDE a crate's `src/` is production code, not a test tree.
    #[test]
    fn m07_1_counts_a_statement_in_a_src_tests_directory() {
        let tmp = fresh_tmp("m07-1-red-src-tests-dir");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(&tmp, "crates/adapters/src/tests/writer.rs", M07_MEMORY_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert!(
            lines[0].contains("crates/adapters/src/tests/writer.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W2): a crate that is itself called `tests` (`crates/tests/src/lib.rs`) is production code.
    #[test]
    fn m07_1_counts_a_statement_in_a_crate_named_tests() {
        let tmp = fresh_tmp("m07-1-red-tests-crate");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(&tmp, "crates/tests/src/lib.rs", M07_EVIDENCE_DOOR);
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("crates/tests/src/lib.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W3): a stray copy spelled in lowercase is still the statement.
    #[test]
    fn m07_1_counts_a_lowercase_statement() {
        let tmp = fresh_tmp("m07-1-red-lowercase");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "fn f() { let _ = \"insert into private.memory_records (a) values ($1)\"; }\n",
        );
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("distill_repo.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W3): doubled spaces between the keywords do not hide the statement.
    #[test]
    fn m07_1_counts_a_statement_with_extra_whitespace() {
        let tmp = fresh_tmp("m07-1-red-whitespace");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "fn f() { let _ = \"INSERT   INTO  private.memory_records (a) VALUES ($1)\"; }\n",
        );
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("distill_repo.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M07-1, review W3): a `\`-newline continuation inside the string (rustc joins the lines) is the statement.
    #[test]
    fn m07_1_counts_a_backslash_continued_statement() {
        let tmp = fresh_tmp("m07-1-red-continuation");
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "fn f() { let _ = \"INSERT INTO \\\n        private.memory_records (a) VALUES ($1)\"; }\n",
        );
        let lines = m07_fail_lines(&tmp);
        assert!(lines[0].contains("distill_repo.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M09 D1 / G-M09-1: one stream_log INSERT, one commit_seq nextval ---------------------

    const M09_HOME: &str = "crates/adapters/src/stream_repo.rs";
    const M09_FIXTURE: &str = "xtask/src/e2e_onboard.rs";
    const M09_STREAM_LOG: &str =
        "fn f() { let _ = \"INSERT INTO projection.stream_log (tenant_id) VALUES ($1)\"; }\n";
    const M09_NEXTVAL: &str = "fn f() { let _ = \"SELECT nextval('ops.commit_seq_seq')\"; }\n";
    /// The door file as M09-1 leaves it: both statements, once.
    const M09_DOOR: &str = "fn door() { let _ = \"INSERT INTO projection.stream_log (tenant_id) VALUES ($1)\"; \
         let _ = \"SELECT nextval('ops.commit_seq_seq')\"; }\n";

    fn m09_fail_lines(root: &Path) -> Vec<String> {
        match m09_1_ticket_doors(root) {
            Verdict::Fail(lines) => lines,
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The tree as M09-1 leaves it: the real repo is green, which includes the onboarding e2e fixture exemption.
    #[test]
    fn m09_1_real_repo_passes() {
        assert_eq!(m09_1_ticket_doors(&real_root()), Verdict::Pass);
    }

    /// Green fixture, plus everything that must NOT count: a comment naming a statement, an integration-test tree, a
    /// statement after a file's trailing `#[cfg(test)] mod`, and the named e2e fixture file within its bounds.
    #[test]
    fn m09_1_passes_with_one_statement_each_and_ignores_test_comment_and_fixture_text() {
        let tmp = fresh_tmp("m09-1-green");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "// the single INSERT INTO projection.stream_log lives in stream_repo\n\
             fn f() {}\n\
             #[cfg(test)]\n\
             mod tests { fn t() { let _ = \"INSERT INTO projection.stream_log (x) VALUES (1)\"; } }\n",
        );
        m07_write(&tmp, "crates/adapters/tests/seed.rs", M09_STREAM_LOG);
        m07_write(&tmp, "bins/gateway/tests/seed.rs", M09_NEXTVAL);
        m07_write(&tmp, M09_FIXTURE, M09_DOOR);
        assert_eq!(m09_1_ticket_doors(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// `not_applicable` names the missing object once (§57.1 第2条): both statements share one home file.
    #[test]
    fn m09_1_is_not_applicable_naming_the_missing_door_file_once() {
        let tmp = fresh_tmp("m09-1-na");
        fs::create_dir_all(&tmp).unwrap();
        match m09_1_ticket_doors(&tmp) {
            Verdict::NotApplicable(detail) => {
                assert_eq!(detail.matches(M09_HOME).count(), 1, "{detail}");
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): a second `INSERT INTO projection.stream_log` in the Distill hop's file → 红, `found 2`, naming it.
    #[test]
    fn m09_1_fails_on_a_duplicate_stream_log_insert_in_another_src_file() {
        let tmp = fresh_tmp("m09-1-red-stream-log");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(&tmp, "crates/adapters/src/distill_repo.rs", M09_STREAM_LOG);
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("G-M09-1"), "{lines:?}");
        assert!(
            lines[0].contains("INSERT INTO projection.stream_log"),
            "{lines:?}"
        );
        assert!(lines[0].contains("found 2"), "{lines:?}");
        assert!(lines[0].contains("distill_repo.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): a second `commit_seq` allocation outside the door file → 红, naming it.
    #[test]
    fn m09_1_fails_on_a_second_commit_seq_nextval() {
        let tmp = fresh_tmp("m09-1-red-nextval");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(&tmp, "crates/adapters/src/remember.rs", M09_NEXTVAL);
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("nextval('ops.commit_seq_seq'"),
            "{lines:?}"
        );
        assert!(lines[0].contains("found 2"), "{lines:?}");
        assert!(lines[0].contains("remember.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): the door file exists but lost a statement → 红 with `found 0`, never "no duplicates, pass".
    #[test]
    fn m09_1_fails_when_the_door_file_holds_no_nextval() {
        let tmp = fresh_tmp("m09-1-red-zero");
        m07_write(&tmp, M09_HOME, M09_STREAM_LOG);
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("nextval('ops.commit_seq_seq'"),
            "{lines:?}"
        );
        assert!(lines[0].contains("found 0"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): the old home (`remember.rs`) keeps the only statement and the door file has none → 红.
    #[test]
    fn m09_1_fails_when_the_only_stream_log_insert_sits_outside_the_door_file() {
        let tmp = fresh_tmp("m09-1-red-moved");
        m07_write(&tmp, M09_HOME, M09_NEXTVAL);
        m07_write(&tmp, "crates/adapters/src/remember.rs", M09_STREAM_LOG);
        let lines = m09_fail_lines(&tmp);
        assert!(lines[0].contains("found 1"), "{lines:?}");
        assert!(lines[0].contains("remember.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): the fixture bound belongs to the one exact path, not a directory — a sibling file is production.
    #[test]
    fn m09_1_fixture_bound_covers_only_the_named_file() {
        let tmp = fresh_tmp("m09-1-red-sibling");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(&tmp, "xtask/src/e2e_other.rs", M09_STREAM_LOG);
        let lines = m09_fail_lines(&tmp);
        assert!(lines[0].contains("xtask/src/e2e_other.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): the named fixture is bounded, not exempt — a second `stream_log` INSERT in it is 红, naming it.
    #[test]
    fn m09_1_fails_when_the_fixture_grows_past_its_bound() {
        let tmp = fresh_tmp("m09-1-red-fixture-grows");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(
            &tmp,
            M09_FIXTURE,
            "fn f() { let _ = \"INSERT INTO projection.stream_log (a) VALUES (1)\"; \
             let _ = \"INSERT INTO projection.stream_log (b) VALUES (2)\"; }\n",
        );
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("INSERT INTO projection.stream_log"),
            "{lines:?}"
        );
        assert!(lines[0].contains(M09_FIXTURE), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): a second allocation spelled with a `::regclass` cast evades a needle that pins the closing `)`.
    #[test]
    fn m09_1_counts_a_nextval_with_a_regclass_cast() {
        let tmp = fresh_tmp("m09-1-red-regclass");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "pub const _RED: &str = \"SELECT nextval('ops.commit_seq_seq'::regclass)\";\n",
        );
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("found 2"), "{lines:?}");
        assert!(lines[0].contains("distill_repo.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M09-1): spaces inside the parentheses (`nextval( '…' )`) do not hide the allocation.
    #[test]
    fn m09_1_counts_a_nextval_with_spaces_inside_the_parentheses() {
        let tmp = fresh_tmp("m09-1-red-spaced-nextval");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/remember.rs",
            "pub const _RED: &str = \"SELECT nextval( 'ops.commit_seq_seq' )\";\n",
        );
        let lines = m09_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("found 2"), "{lines:?}");
        assert!(lines[0].contains("remember.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// The normaliser removes spaces around parentheses and nothing else that separates tokens.
    #[test]
    fn door_normalised_strips_spaces_around_parentheses_only() {
        assert_eq!(
            door_normalised("SELECT  nextval( 'X' ) ,\n  y"),
            "select nextval('x'), y"
        );
        assert_eq!(
            door_normalised("INSERT INTO t (a, b) VALUES ($1)"),
            "insert into t(a, b)values($1)"
        );
    }

    /// The two gates share one scan but not their doors: an M07 statement in an M09 tree (and the reverse) is not
    /// counted by the other gate.
    #[test]
    fn m09_1_and_m07_1_count_only_their_own_statements() {
        let tmp = fresh_tmp("m09-1-isolated");
        m07_write(&tmp, M09_HOME, M09_DOOR);
        m07_write(&tmp, M07_EVIDENCE_HOME, M07_EVIDENCE_DOOR);
        m07_write(&tmp, M07_MEMORY_HOME, M07_MEMORY_DOOR);
        assert_eq!(m09_1_ticket_doors(&tmp), Verdict::Pass);
        assert_eq!(m07_1_insert_doors(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M04 D2 / G-M04-1: plan names, prices and lease blocks are data ---------------------------

    /// A values file naming two plans; the names exist only here, in the fixture.
    const M04_CATALOGUE: &str =
        r#"{"plan_versions":[{"plan_key":"tier_a"},{"plan_key":"tier_b"}]}"#;

    /// A values file that also names `free`, for the migration fixtures that spell that plan.
    const M04_CATALOGUE_WITH_FREE: &str =
        r#"{"plan_versions":[{"plan_key":"tier_a"},{"plan_key":"tier_b"},{"plan_key":"free"}]}"#;

    /// A fixture tree: the values file, one clean production file (so the scan reads something), and `extra`.
    fn m04_tree(label: &str, extra: &[(&str, &str)]) -> PathBuf {
        let tmp = fresh_tmp(label);
        m07_write(&tmp, M04_CATALOGUE_FILE, M04_CATALOGUE);
        m07_write(&tmp, "crates/domain/src/plan.rs", "pub fn clean() {}\n");
        for (rel, body) in extra {
            m07_write(&tmp, rel, body);
        }
        tmp
    }

    /// The single red line of a failing tree.
    fn m04_fail_line(root: &Path) -> String {
        match m04_1_plans_are_data(root) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                lines.into_iter().next().unwrap()
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The tree as M04-1 leaves it, the migrations above the floor included: the real repo is green. 注错 (G-M04-1): a
    /// plan-key literal such as a `"pro"` branch, or an integer given to `price_cents` or `lease_block`, in any
    /// `crates/` or `bins/` production file, or a plan-key / price literal in a migration above the floor, turns this
    /// red.
    #[test]
    fn m04_1_real_repo_passes() {
        assert_eq!(m04_1_plans_are_data(&real_root()), Verdict::Pass);
    }

    /// 注错 (G-M04-1, migrations): a plan-key literal in a migration above the floor is red, naming the file and the
    /// literal. The header comment spells the same plan in prose and must not count.
    #[test]
    fn m04_1_fails_on_a_plan_key_in_a_new_migration() {
        let tmp = m04_tree(
            "m04-1-red-migration-plan-key",
            &[
                (M04_CATALOGUE_FILE, M04_CATALOGUE_WITH_FREE),
                (
                    "migrations/0263_onboarding.sql",
                    "-- the free plan is a row of the catalogue; 'free' here is prose\n\
                     CREATE FUNCTION onboard_default_plan() RETURNS void LANGUAGE sql AS $$\n\
                       INSERT INTO plans (plan_key) VALUES ('free');\n\
                     $$;\n",
                ),
            ],
        );
        let line = m04_fail_line(&tmp);
        assert!(
            line.contains(
                "migrations/0263_onboarding.sql: line 3: plan key 'free' spelled as a literal"
            ),
            "{line}"
        );
        assert!(line.contains("spells 1 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// A migration at or below the floor predates the rule and is not rescanned: the same body passes at 0262 and below.
    #[test]
    fn m04_1_does_not_rescan_migrations_at_or_below_the_floor() {
        let body = "-- the free plan is a row of the catalogue; 'free' here is prose\n\
                    CREATE FUNCTION onboard_default_plan() RETURNS void LANGUAGE sql AS $$\n\
                      INSERT INTO plans (plan_key) VALUES ('free');\n\
                    $$;\n";
        for name in [
            "migrations/0262_onboarding.sql",
            "migrations/0001_onboarding.sql",
        ] {
            let tmp = m04_tree(
                "m04-1-migration-floor",
                &[(M04_CATALOGUE_FILE, M04_CATALOGUE_WITH_FREE), (name, body)],
            );
            assert_eq!(m04_1_plans_are_data(&tmp), Verdict::Pass, "{name}");
            fs::remove_dir_all(&tmp).ok();
        }
    }

    /// 注错 (G-M04-1, migrations): a price given an integer in a plan-version statement is red, whether it is an
    /// assignment or a quoted key, one hit per spelling.
    #[test]
    fn m04_1_fails_on_a_price_literal_in_a_new_migration() {
        let tmp = m04_tree(
            "m04-1-red-migration-price",
            &[(
                "migrations/0263_price_update.sql",
                "UPDATE plan_versions SET price_cents = 4900 WHERE version = 1;\n\
                 SELECT jsonb_build_object('price_cents', 4900);\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        assert!(
            line.contains(
                "migrations/0263_price_update.sql: line 1: `price_cents` given an integer literal"
            ),
            "{line}"
        );
        assert!(
            line.contains(
                "migrations/0263_price_update.sql: line 2: the quoted price / limit key price_cents given an integer literal"
            ),
            "{line}"
        );
        assert!(line.contains("spells 2 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// The scan dates a migration by the four leading digits of its file name; a name without them is not a migration
    /// it can place, so the gate names it instead of treating it as old.
    #[test]
    fn m04_1_reads_the_migration_number_from_the_file_name() {
        for (name, want) in [
            ("0262_plan_catalogue.sql", Some(262)),
            ("0263_onboarding.sql", Some(263)),
            ("0001_initial.sql", Some(1)),
            ("0263.sql", Some(263)),
        ] {
            assert_eq!(m04_migration_number(Path::new(name)), want, "{name}");
        }
        for name in ["plan_catalogue.sql", "262_plan.sql", "026x_plan.sql"] {
            assert_eq!(m04_migration_number(Path::new(name)), None, "{name}");
        }
    }

    /// The SQL scan reads statements, not prose: a plan key quoted in a `--` or `/* */` comment does not count, a `--`
    /// inside a quoted token is not a comment, and a statement literal does count.
    #[test]
    fn m04_1_sql_scan_ignores_comments_and_reads_statement_literals() {
        let source = "-- 'free' in a header\n\
                      SELECT 'free'; /* 'free' in a block */\n\
                      SELECT 'a--b';\n";
        let code = m04_sql_code(source);
        assert_eq!(code.lines().count(), 3, "{code:?}");
        assert!(!code.contains("header"), "{code:?}");
        assert!(!code.contains("block"), "{code:?}");
        assert!(code.contains("'a--b'"), "{code:?}");
        let hits = m04_sql_plan_literal_hits(source, &BTreeSet::from(["free".to_owned()]));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].starts_with("line 2:"), "{hits:?}");
        assert!(hits[0].contains("'free'"), "{hits:?}");
    }

    /// Everything that must NOT count: a comment naming a plan, a test tree, a trailing `#[cfg(test)]` module, tooling
    /// under `xtask/`, a literal that merely contains a plan key, and the shapes that mention the identifiers without
    /// giving them an integer.
    #[test]
    fn m04_1_passes_and_ignores_comments_tests_tooling_and_look_alikes() {
        let tmp = m04_tree(
            "m04-1-green",
            &[
                (
                    "crates/adapters/src/looks.rs",
                    "// the plan \"tier_a\" is a row of the catalogue\n\
                     fn f(price_cents: i64, lease_block: u32) -> bool {\n\
                         let label = \"tier_ab\";\n\
                         price_cents < 0 || lease_block >= 1 || label.is_empty()\n\
                     }\n\
                     #[cfg(test)]\n\
                     mod tests { fn t() { let _ = (\"tier_a\", 5); let price_cents = 980; } }\n",
                ),
                (
                    "crates/adapters/tests/seed.rs",
                    "fn t() { let _ = \"tier_a\"; let lease_block = 16; }\n",
                ),
                (
                    "xtask/src/tooling.rs",
                    "fn t() { let _ = \"tier_a\"; let price_cents = 980; }\n",
                ),
            ],
        );
        assert_eq!(m04_1_plans_are_data(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a branch on a plan key, in double quotes, names the file and the line; removing it returns to green.
    #[test]
    fn m04_1_fails_on_a_plan_name_branch_and_recovers() {
        let tmp = m04_tree(
            "m04-1-red-name",
            &[(
                "bins/gateway/src/guard.rs",
                "fn allowed(plan: &str) -> bool {\n    plan == \"tier_b\"\n}\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        assert!(line.contains("bins/gateway/src/guard.rs: line 2"), "{line}");
        assert!(line.contains("tier_b"), "{line}");
        assert!(line.contains("spells 1 of them"), "{line}");
        m07_write(
            &tmp,
            "bins/gateway/src/guard.rs",
            "fn allowed(allowed: bool) -> bool {\n    allowed\n}\n",
        );
        assert_eq!(m04_1_plans_are_data(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a plan key inside a SQL string in single quotes is the same branch.
    #[test]
    fn m04_1_fails_on_a_plan_key_in_a_sql_literal() {
        let tmp = m04_tree(
            "m04-1-red-sql",
            &[(
                "crates/adapters/src/quota_repo.rs",
                "const Q: &str = \"SELECT 1 WHERE plan_key = 'tier_a'\";\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        assert!(
            line.contains("crates/adapters/src/quota_repo.rs: line 1"),
            "{line}"
        );
        assert!(line.contains("spells 1 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a price or a lease block given an integer in Rust is red, one hit per spelled number.
    #[test]
    fn m04_1_fails_on_a_price_or_lease_block_literal() {
        let tmp = m04_tree(
            "m04-1-red-number",
            &[(
                "crates/domain/src/pricing.rs",
                "pub struct P { price_cents: i64 }\n\
                 pub fn p() -> P { P { price_cents: 980 } }\n\
                 pub fn b() -> i32 { let lease_block = 16; lease_block }\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        assert!(
            line.contains("crates/domain/src/pricing.rs: line 2"),
            "{line}"
        );
        assert!(
            line.contains("crates/domain/src/pricing.rs: line 3"),
            "{line}"
        );
        assert!(line.contains("spells 2 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// `not_applicable` names the missing values file (§57.1 第2条); a file with no plan key, and a scan that reads no
    /// production source, are red rather than a silent green.
    #[test]
    fn m04_1_is_not_applicable_without_the_file_and_red_when_blind() {
        let tmp = fresh_tmp("m04-1-na");
        m07_write(&tmp, "crates/domain/src/plan.rs", "pub fn clean() {}\n");
        match m04_1_plans_are_data(&tmp) {
            Verdict::NotApplicable(detail) => {
                assert!(detail.contains(M04_CATALOGUE_FILE), "{detail}")
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        m07_write(&tmp, M04_CATALOGUE_FILE, r#"{"plan_versions":[]}"#);
        assert!(m04_fail_line(&tmp).contains("lists no plan_key"));
        m07_write(&tmp, M04_CATALOGUE_FILE, "not json");
        assert!(m04_fail_line(&tmp).contains(M04_CATALOGUE_FILE));
        fs::remove_dir_all(&tmp).ok();

        let empty = fresh_tmp("m04-1-blind");
        m07_write(&empty, M04_CATALOGUE_FILE, M04_CATALOGUE);
        assert!(m04_fail_line(&empty).contains("scan is blind"));
        fs::remove_dir_all(&empty).ok();
    }

    /// The plan keys come from the data, exactly.
    #[test]
    fn m04_1_reads_the_plan_keys_from_the_values_file() {
        assert_eq!(
            m04_catalogue_plan_keys(M04_CATALOGUE).unwrap(),
            BTreeSet::from(["tier_a".to_owned(), "tier_b".to_owned()])
        );
        assert!(m04_catalogue_plan_keys("{}").is_err());
    }

    /// Which lines give an identifier an integer: `:`, `=`, `==` and `!=` followed by a digit, whole words only.
    #[test]
    fn m04_1_integer_assignment_scan_matches_exactly_these_shapes() {
        let hits = [
            "price_cents: 980,",
            "price_cents:5",
            "let price_cents = 5;",
            "price_cents == 0",
            "price_cents != 0",
            "price_cents : 7",
        ];
        let misses = [
            "price_cents: i64,",
            "if price_cents < 0 {",
            "price_cents >= 1",
            "price_cents::MAX",
            "my_price_cents: 5",
            "price_cents_total: 5",
            "price_cents => 5",
            "price_cents,",
        ];
        for line in hits {
            assert!(m04_assigns_integer(line, "price_cents"), "{line}");
        }
        for line in misses {
            assert!(!m04_assigns_integer(line, "price_cents"), "{line}");
        }
        assert!(!m04_assigns_integer("price_cents: 980,", "lease_block"));
    }

    /// 注错 (G-M04-1, quota limits): a `PeriodQuota { limit: 200_000, .. }` or `Allowance { limit: .. }` literal with an
    /// integer limit is red, on one line or across several; one hit per literal, naming the file and the line.
    #[test]
    fn m04_1_fails_on_a_quota_limit_literal() {
        let tmp = m04_tree(
            "m04-1-red-quota",
            &[(
                "crates/domain/src/quota.rs",
                "fn q() -> TemplateValue { TemplateValue::PeriodQuota { limit: 200_000, period: QuotaPeriod::SubscriptionPeriod, charge_policy: ChargePolicy::SuccessOnly } }\n\
                 fn a() -> TemplateValue {\n\
                     TemplateValue::Allowance {\n\
                         limit: 100_000,\n\
                     }\n\
                 }\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        assert!(
            line.contains("crates/domain/src/quota.rs: line 1:"),
            "{line}"
        );
        assert!(
            line.contains("crates/domain/src/quota.rs: line 3:"),
            "{line}"
        );
        assert!(line.contains("spells 2 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M04-1, quota limits): a quoted limit key, a quoted entitlement key and the quota identifiers
    /// `hard_limit` / `granted_slots` given an integer are red, one hit per spelling.
    #[test]
    fn m04_1_fails_on_a_limit_key_a_window_key_or_a_quota_identifier_with_a_number() {
        let tmp = m04_tree(
            "m04-1-red-limit-keys",
            &[(
                "bins/gateway/src/limits.rs",
                "fn a() { let _ = json!({\"limit\": 5}); }\n\
                 const B: &str = \"SELECT jsonb_build_object('hard_limit', 7)\";\n\
                 const C: (&str, u64) = (\"mcp.billable_operations.emergency\", 500);\n\
                 struct W { hard_limit: i64 }\n\
                 fn d() -> W { W { hard_limit: 12 } }\n\
                 fn e() { let granted_slots = 16; drop(granted_slots); }\n",
            )],
        );
        let line = m04_fail_line(&tmp);
        for at in [1, 2, 3, 5, 6] {
            assert!(
                line.contains(&format!("bins/gateway/src/limits.rs: line {at}:")),
                "line {at}: {line}"
            );
        }
        assert!(!line.contains("limits.rs: line 4:"), "{line}");
        assert!(line.contains("spells 5 of them"), "{line}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// The values-file path passes: the numbers live in the JSON file, and production code that reads them (a limit from
    /// a field, a pattern binding, a `.get("limit")`, a bare shape check) states none.
    #[test]
    fn m04_1_passes_when_the_limits_come_from_the_values_file() {
        let tmp = m04_tree(
            "m04-1-green-values-file",
            &[
                (
                    M04_CATALOGUE_FILE,
                    r#"{"plan_versions":[{"plan_key":"tier_a","price_cents":100,"lease_block":256,"entitlement_template":{"mcp.billable_operations.per_period":{"limit":200000,"period":"subscription_period","charge_policy":"success_only"},"mcp.billable_operations.emergency":{"limit":500}}}]}"#,
                ),
                (
                    "crates/adapters/src/reads.rs",
                    "fn q(quota: &Raw) -> TemplateValue { TemplateValue::PeriodQuota { limit: quota.limit, period, charge_policy } }\n\
                     fn a(raw: &Raw) -> TemplateValue { TemplateValue::Allowance { limit: raw.limit } }\n\
                     fn j(limit: u64) -> Value { json!({ \"limit\": limit }) }\n\
                     fn g(v: &Value) -> Option<&Value> { v.get(\"limit\") }\n\
                     fn s(limit: usize) -> bool { limit == 0 }\n\
                     fn p(v: TemplateValue) { match v { TemplateValue::Allowance { limit } => drop(limit), _ => {} } }\n\
                     const K: &str = \"mcp.billable_operations.per_period\";\n\
                     fn w(hard_limit: i64) -> i64 { hard_limit }\n",
                ),
            ],
        );
        assert_eq!(m04_1_plans_are_data(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// Which lines give a quoted limit key an integer: `:` or `,` then a digit, the key quoted on both sides.
    #[test]
    fn m04_1_quoted_limit_scan_matches_exactly_these_shapes() {
        let hits = [
            "json!({\"limit\": 5})",
            "json!({\"query\":\"x\",\"limit\":101})",
            "jsonb_build_object('limit', 50)",
            "\"hard_limit\": 7",
            "\"emergency_limit\" : 3",
        ];
        let misses = [
            "v.get(\"limit\")",
            "\"limit\": query.limit,",
            "[\"project_id\", \"limit\"]",
            "\"limit\": limit,",
            "limit: 5",
            "let limit = 5;",
            "\"limit\"",
        ];
        for line in hits {
            assert!(m04_quoted_limit_integer(line), "{line}");
        }
        for line in misses {
            assert!(!m04_quoted_limit_integer(line), "{line}");
        }
        assert!(m04_quoted_key_integer(
            "(\"storage.retained_bytes\", 9)",
            "storage.retained_bytes"
        ));
        assert!(!m04_quoted_key_integer(
            "(\"storage.retained_bytes\", bytes)",
            "storage.retained_bytes"
        ));
        assert!(!m04_quoted_key_integer(
            "(\"storage.retained_bytes\")",
            "storage.retained_bytes"
        ));
    }

    /// The template-literal scan reports line numbers, skips comment lines and reads a pattern as no literal.
    #[test]
    fn m04_1_quota_literal_scan_reports_lines_and_skips_comments_and_patterns() {
        let source = "// TemplateValue::PeriodQuota { limit: 5 } is a doc example\n\
                      fn a() {\n\
                          let _ = TemplateValue::Allowance { limit: 7 };\n\
                      }\n\
                      fn b(v: TemplateValue) { if let TemplateValue::Allowance { limit } = v { drop(limit) } }\n";
        let hits = m04_quota_literal_hits(source);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].starts_with("line 3:"), "{hits:?}");
    }

    // -- M29 T04c / G-T04c-3: one INSERT INTO private.evidence_task_runs, in remember.rs ----------------

    const T04C_HOME: &str = "crates/adapters/src/remember.rs";
    const T04C_DOOR: &str = "fn door() { let _ = \"INSERT INTO private.evidence_task_runs (tenant_id) VALUES ($1)\"; }\n";

    /// The tree as T04c leaves it: one carrier INSERT, in `remember.rs`.
    #[test]
    fn t04c_3_real_repo_passes() {
        assert_eq!(t04c_3_carrier_door(&real_root()), Verdict::Pass);
    }

    /// `not_applicable` names the missing home file (§57.1 第2条).
    #[test]
    fn t04c_3_is_not_applicable_naming_the_missing_door_file() {
        let tmp = fresh_tmp("t04c-3-na");
        fs::create_dir_all(&tmp).unwrap();
        match t04c_3_carrier_door(&tmp) {
            Verdict::NotApplicable(detail) => assert!(detail.contains(T04C_HOME), "{detail}"),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-T04c-3): a second carrier INSERT in another module → 红, `found 2`, naming that file; a test-tree copy
    /// does not count.
    #[test]
    fn t04c_3_fails_on_a_second_carrier_insert_in_another_src_file() {
        let tmp = fresh_tmp("t04c-3-red");
        m07_write(&tmp, T04C_HOME, T04C_DOOR);
        m07_write(&tmp, "crates/adapters/tests/seed.rs", T04C_DOOR);
        assert_eq!(t04c_3_carrier_door(&tmp), Verdict::Pass);
        m07_write(&tmp, "crates/adapters/src/coord_repo.rs", T04C_DOOR);
        match t04c_3_carrier_door(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("found 2"), "{lines:?}");
                assert!(
                    lines[0].contains("crates/adapters/src/coord_repo.rs"),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M29 T06c / G-T06c-3: one INSERT INTO private.evidence_projects, in remember.rs ---------------------------------

    const T06C_HOME: &str = "crates/adapters/src/remember.rs";
    const T06C_DOOR: &str = "fn door() { let _ = \"INSERT INTO private.evidence_projects (tenant_id) VALUES ($1)\"; }\n";

    /// The tree as T06c leaves it: one declared-project INSERT, in `remember.rs`.
    #[test]
    fn t06c_door_real_repo_passes() {
        assert_eq!(t06c_door(&real_root()), Verdict::Pass);
    }

    /// `not_applicable` names the missing home file (§57.1 第2条).
    #[test]
    fn t06c_door_is_not_applicable_naming_the_missing_door_file() {
        let tmp = fresh_tmp("t06c-door-na");
        fs::create_dir_all(&tmp).unwrap();
        match t06c_door(&tmp) {
            Verdict::NotApplicable(detail) => assert!(detail.contains(T06C_HOME), "{detail}"),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-T06c-3): a second declared-project INSERT in another module → 红, `found 2`, naming that file; a
    /// test-tree copy does not count.
    #[test]
    fn t06c_door_fails_on_a_second_insert_in_another_src_file() {
        let tmp = fresh_tmp("t06c-door-red");
        m07_write(&tmp, T06C_HOME, T06C_DOOR);
        m07_write(&tmp, "crates/adapters/tests/seed.rs", T06C_DOOR);
        assert_eq!(t06c_door(&tmp), Verdict::Pass);
        m07_write(&tmp, "crates/adapters/src/operation_receipt.rs", T06C_DOOR);
        match t06c_door(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("found 2"), "{lines:?}");
                assert!(
                    lines[0].contains("crates/adapters/src/operation_receipt.rs"),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M29 T06b / G-M29-5(b): one "correction@1" literal, in attribution.rs ------------------------------------------

    const T06B_HOME: &str = "crates/domain/src/attribution.rs";
    const T06B_RULE: &str = "fn wire() -> &'static str { \"correction@1\" }\n";

    /// The tree as T06b leaves it: the literal only in `RuleId`'s closed set (rls_check's SQL probes do not count).
    #[test]
    fn t06b_correction_rule_real_repo_passes() {
        assert_eq!(t06b_correction_rule_site(&real_root()), Verdict::Pass);
    }

    /// `not_applicable` names the missing home file (§57.1 第2条).
    #[test]
    fn t06b_correction_rule_is_not_applicable_naming_the_missing_home() {
        let tmp = fresh_tmp("t06b-rule-na");
        fs::create_dir_all(&tmp).unwrap();
        match t06b_correction_rule_site(&tmp) {
            Verdict::NotApplicable(detail) => assert!(detail.contains(T06B_HOME), "{detail}"),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M29-5(b)): a second `"correction@1"` literal in an adapters module → 红, `found 2`, naming that file;
    /// a test-tree copy and a SQL string merely containing `correction@1` do not count; `RuleId::Correction1` outside
    /// the home → 红.
    #[test]
    fn t06b_correction_rule_fails_on_a_second_literal_in_another_src_file() {
        let tmp = fresh_tmp("t06b-rule-red");
        m07_write(&tmp, T06B_HOME, T06B_RULE);
        m07_write(&tmp, "crates/adapters/tests/seed.rs", T06B_RULE);
        m07_write(
            &tmp,
            "bins/maintenance/src/rls_check.rs",
            "fn probe() { let _ = \"SELECT 1 WHERE prosrc LIKE '%correction@1%'\"; }\n",
        );
        assert_eq!(t06b_correction_rule_site(&tmp), Verdict::Pass);
        m07_write(&tmp, "crates/adapters/src/attribution_repo.rs", T06B_RULE);
        match t06b_correction_rule_site(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("found 2"), "{lines:?}");
                assert!(
                    lines[0].contains("crates/adapters/src/attribution_repo.rs"),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        m07_write(
            &tmp,
            "crates/adapters/src/attribution_repo.rs",
            "fn rule() -> RuleId { RuleId::Correction1 }\n",
        );
        match t06b_correction_rule_site(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("RuleId::Correction1"), "{lines:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M29 T07 / ADR-0078 D-D: the one attribution reader reads only the live view ---------------------------------

    const T07_HOME: &str = "crates/adapters/src/attribution_repo.rs";
    const T07_READER: &str = "const READ: &str = \"SELECT project_id \\\n  FROM private.memory_projects_live WHERE memory_id = $1\";\nconst A1: &str = \"INSERT INTO private.memory_projects (memory_id) SELECT $1\";\n";

    /// The tree as T07 leaves it: one view reader, in attribution_repo.rs; the writers and rls_check do not count.
    #[test]
    fn t07_attribution_reader_real_repo_passes() {
        assert_eq!(m29_attribution_reader(&real_root()), Verdict::Pass);
    }

    /// `not_applicable` names the missing home file (§57.1 第2条).
    #[test]
    fn t07_attribution_reader_is_not_applicable_naming_the_missing_home() {
        let tmp = fresh_tmp("t07-reader-na");
        fs::create_dir_all(&tmp).unwrap();
        match m29_attribution_reader(&tmp) {
            Verdict::NotApplicable(detail) => assert!(detail.contains(T07_HOME), "{detail}"),
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a second view reader in another src file → 红, `found 2`, naming that file; a test-tree reader does not
    /// count.
    #[test]
    fn t07_attribution_reader_fails_on_a_second_reader() {
        let tmp = fresh_tmp("t07-reader-second");
        m07_write(&tmp, T07_HOME, T07_READER);
        m07_write(&tmp, "crates/adapters/tests/seed.rs", T07_READER);
        assert_eq!(m29_attribution_reader(&tmp), Verdict::Pass);
        m07_write(
            &tmp,
            "crates/adapters/src/recall.rs",
            "const R: &str = \"SELECT 1 FROM x JOIN private.memory_projects_live l ON true\";\n",
        );
        match m29_attribution_reader(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("found 2"), "{lines:?}");
                assert!(
                    lines[0].contains("crates/adapters/src/recall.rs"),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a direct `FROM private.memory_projects` (case and line breaks aside) in another src file → 红 naming it,
    /// even with the home file absent; the `INSERT INTO private.memory_projects` writer is no read.
    #[test]
    fn t07_attribution_reader_fails_on_a_direct_table_read() {
        let tmp = fresh_tmp("t07-reader-direct");
        m07_write(&tmp, T07_HOME, T07_READER);
        m07_write(
            &tmp,
            "crates/adapters/src/recall.rs",
            "const R: &str = \"select project_id from \\\n  private.memory_projects mp\";\n",
        );
        match m29_attribution_reader(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(
                    lines[0].contains("reads private.memory_projects directly"),
                    "{lines:?}"
                );
                assert!(
                    lines[0].contains("crates/adapters/src/recall.rs"),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_file(tmp.join(T07_HOME)).unwrap();
        assert!(
            matches!(m29_attribution_reader(&tmp), Verdict::Fail(_)),
            "a direct read is red even before the reader exists"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: the direct read spelled with SQL quoting, spaces around the dot, `ONLY`, or as a comma join (on the
    /// same line or the next) → 红 each time.
    #[test]
    fn t07_attribution_reader_fails_on_quoted_and_comma_join_reads() {
        let tmp = fresh_tmp("t07-reader-spellings");
        m07_write(&tmp, T07_HOME, T07_READER);
        for read in [
            "SELECT 1 FROM \\\"private\\\".\\\"memory_projects\\\" mp",
            "SELECT 1 FROM private.\\\"memory_projects\\\" mp",
            "SELECT 1 FROM private . memory_projects mp",
            "SELECT 1 FROM ONLY private.memory_projects",
            "SELECT 1 FROM private.memory_records r, private.memory_projects mp",
            "SELECT 1 FROM private.memory_records r, \\\n  private.memory_projects mp",
        ] {
            m07_write(
                &tmp,
                "crates/adapters/src/recall.rs",
                &format!("const R: &str = \"{read}\";\n"),
            );
            match m29_attribution_reader(&tmp) {
                Verdict::Fail(lines) => {
                    assert_eq!(lines.len(), 1, "{read}: {lines:?}");
                    assert!(
                        lines[0].contains("reads private.memory_projects directly"),
                        "{read}: {lines:?}"
                    );
                }
                other => panic!("{read}: expected Fail, got {other:?}"),
            }
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// A commented-out view read (trailing `//` or a `/* */` block) is no reader: still exactly 1.
    #[test]
    fn t07_attribution_reader_ignores_commented_reads() {
        let tmp = fresh_tmp("t07-reader-comments");
        m07_write(&tmp, T07_HOME, T07_READER);
        m07_write(
            &tmp,
            "crates/adapters/src/recall.rs",
            "fn f() {} // FROM private.memory_projects_live\n/* SELECT 1\n   FROM private.memory_projects_live */\n",
        );
        assert_eq!(m29_attribution_reader(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a direct read after a doc-comment glob (`/*` in a `///` line), after a `//` inside a string literal, or
    /// glued to `FROM` by SQL quoting → 红 each time (the comment stripper lexes literals; `"` becomes a space).
    #[test]
    fn t07_attribution_reader_sees_reads_past_literals_and_globs() {
        let tmp = fresh_tmp("t07-reader-lexer");
        m07_write(&tmp, T07_HOME, T07_READER);
        for source in [
            "/// see crates/*/src\nconst R: &str = \"SELECT 1 FROM private.memory_projects mp\";\n",
            "fn f() { let u = \"https://x\"; let q = \"SELECT 1 FROM private.memory_projects\"; }\n",
            "const R: &str = \"SELECT 1 FROM\\\"private\\\".\\\"memory_projects\\\" mp\";\n",
        ] {
            m07_write(&tmp, "crates/adapters/src/recall.rs", source);
            match m29_attribution_reader(&tmp) {
                Verdict::Fail(lines) => {
                    assert_eq!(lines.len(), 1, "{source}: {lines:?}");
                    assert!(
                        lines[0].contains("reads private.memory_projects directly"),
                        "{source}: {lines:?}"
                    );
                }
                other => panic!("{source}: expected Fail, got {other:?}"),
            }
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (`== 1` pinned from below): the home file present with no view read → 红, `found 0`.
    #[test]
    fn t07_attribution_reader_fails_on_zero_readers() {
        let tmp = fresh_tmp("t07-reader-zero");
        m07_write(&tmp, T07_HOME, "pub fn x() {}\n");
        match m29_attribution_reader(&tmp) {
            Verdict::Fail(lines) => {
                assert_eq!(lines.len(), 1, "{lines:?}");
                assert!(lines[0].contains("found 0"), "{lines:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- ADR-0078 / G-M29-5(a) and G-N09-1 (M29 T06a) ---------------------------------------------------------------

    const M29_DOOR: &str = "pub async fn insert_memory_in_txn(\n    txn: &mut Txn<'_>,\n    attribution: &dyn MemoryAttribution,\n) -> Result<Uuid, Error> {\n    let _ = \"INSERT INTO private.memory_evidence (memory_id) VALUES ($1)\";\n    link_memory_in_txn(txn).await?;\n    attribution\n        .link_memory_projects(txn)\n        .await?;\n}\n";
    const M29_LADDER: &str = "impl MemoryAttribution for AttributionLadder {}\n";
    const M29_DOMAIN: &str = "pub enum SourceKind { Declared }\n";

    /// The tree as T06a leaves it.
    #[test]
    fn m29_5a_real_repo_passes() {
        assert_eq!(m29_5a_attribution_site(&real_root()), Verdict::Pass);
    }

    #[test]
    fn n09_1_real_repo_passes() {
        assert_eq!(n09_1_no_model_source(&real_root()), Verdict::Pass);
    }

    /// `not_applicable` names the missing files (§57.1 第2条).
    #[test]
    fn m29_5a_and_n09_1_are_not_applicable_naming_the_missing_files() {
        let tmp = fresh_tmp("m29-5a-na");
        fs::create_dir_all(&tmp).unwrap();
        for verdict in [m29_5a_attribution_site(&tmp), n09_1_no_model_source(&tmp)] {
            match verdict {
                Verdict::NotApplicable(detail) => {
                    assert!(detail.contains(M29_LADDER_HOME), "{detail}")
                }
                other => panic!("expected NotApplicable, got {other:?}"),
            }
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M29-5(a)): a second port call in another module (`found 2`), an `Option` port parameter, a call before
    /// the subject hook, and a second implementation are each red; a test-tree copy does not count.
    #[test]
    fn m29_5a_fails_on_each_fault() {
        let tmp = fresh_tmp("m29-5a-red");
        let seed = |door: &str| {
            fs::remove_dir_all(&tmp).ok();
            m07_write(&tmp, M29_DOOR_HOME, door);
            m07_write(&tmp, M29_LADDER_HOME, M29_LADDER);
            m07_write(&tmp, "crates/adapters/tests/seed.rs", M29_DOOR);
        };
        seed(M29_DOOR);
        assert_eq!(m29_5a_attribution_site(&tmp), Verdict::Pass);
        let second = "fn f() { attribution.link_memory_projects(txn); }\n";
        m07_write(&tmp, "crates/adapters/src/note_repo.rs", second);
        let red = |verdict: Verdict, needle: &str| match verdict {
            Verdict::Fail(lines) => assert!(lines.iter().any(|l| l.contains(needle)), "{lines:?}"),
            other => panic!("expected Fail, got {other:?}"),
        };
        red(m29_5a_attribution_site(&tmp), "found 2");
        seed(&M29_DOOR.replace("&dyn MemoryAttribution", "Option<&dyn MemoryAttribution>"));
        red(m29_5a_attribution_site(&tmp), "optional");
        seed(
            &M29_DOOR
                .replace("link_memory_in_txn(txn).await?;\n", "")
                .replace("}\n", "    link_memory_in_txn(txn).await?;\n}\n"),
        );
        red(m29_5a_attribution_site(&tmp), "before");
        seed(M29_DOOR);
        m07_write(
            &tmp,
            "crates/adapters/src/noop.rs",
            "impl MemoryAttribution for Noop {}\n",
        );
        red(m29_5a_attribution_site(&tmp), "found 2");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-N09-1): a provider / embedding import in either file is red; the same name in a comment is not.
    #[test]
    fn n09_1_fails_on_a_model_import() {
        let tmp = fresh_tmp("n09-1-red");
        m07_write(
            &tmp,
            M29_LADDER_HOME,
            &format!("// a provider is never consulted\n{M29_LADDER}"),
        );
        m07_write(&tmp, "crates/domain/src/attribution.rs", M29_DOMAIN);
        assert_eq!(n09_1_no_model_source(&tmp), Verdict::Pass);
        m07_write(
            &tmp,
            M29_LADDER_HOME,
            &format!("use crate::byok::complete_structured;\n{M29_LADDER}"),
        );
        match n09_1_no_model_source(&tmp) {
            Verdict::Fail(lines) => {
                assert!(lines.iter().any(|l| l.contains("`byok`")), "{lines:?}")
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- M08 D1 / G-M08-2: per-file `can_read` and `visibility_readable` token counts == the declared sites ----

    const M08_CALL: &str = "fn f() { let _ = can_read(auth, &visibility); }\n";
    const M08_DOOR_CALL: &str = "fn f() { let _ = visibility_readable(auth, &visibility); }\n";
    const M08_GATE: &str = M08_GATE_HOME;

    /// A file body holding exactly `n` bare `can_read` tokens.
    fn m08_uses(n: usize) -> String {
        M08_CALL.repeat(n)
    }

    /// A file body holding exactly `n` bare `visibility_readable` tokens.
    fn m08_door_uses(n: usize) -> String {
        M08_DOOR_CALL.repeat(n)
    }

    /// The declared count of one site.
    fn m08_count(file: &str) -> usize {
        M08_CAN_READ_SITES
            .iter()
            .find(|(site, _, _)| *site == file)
            .unwrap_or_else(|| panic!("{file} is not a declared site"))
            .1
    }

    /// The declared `visibility_readable` count of one row-level caller.
    fn m08_door_count(file: &str) -> usize {
        M08_VISIBILITY_READABLE_SITES
            .iter()
            .find(|(site, _, _)| *site == file)
            .unwrap_or_else(|| panic!("{file} is not a declared caller"))
            .1
    }

    /// The tree as the gate declares it: every declared file holds exactly its declared count of each token, and
    /// nothing else does.
    fn m08_declared_tree(label: &str) -> PathBuf {
        let tmp = fresh_tmp(label);
        for (file, count, _) in M08_CAN_READ_SITES {
            m07_write(&tmp, file, &m08_uses(count));
        }
        for (file, count, _) in M08_VISIBILITY_READABLE_SITES {
            m07_write(&tmp, file, &m08_door_uses(count));
        }
        tmp
    }

    fn m08_fail_lines(root: &Path) -> Vec<String> {
        match m08_2_can_read_one_home(root) {
            Verdict::Fail(lines) => lines,
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// The declared tree plus one undeclared adapters file with `body`: red, one line, naming that file.
    fn m08_undeclared_use_is_red(label: &str, body: &str) {
        let tmp = m08_declared_tree(label);
        m07_write(&tmp, "crates/adapters/src/grep_repo.rs", body);
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("G-M08-2: can_read( call outside the read gate"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("crates/adapters/src/grep_repo.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// The declared tree plus one undeclared file `path` holding `body`: red, one line, naming that file as an
    /// undeclared `visibility_readable` site.
    fn m08_undeclared_door_use_is_red(label: &str, path: &str, body: &str) {
        let tmp = m08_declared_tree(label);
        m07_write(&tmp, path, body);
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{path}: {lines:?}");
        assert!(
            lines[0].contains("G-M08-2: visibility_readable use outside its declared sites"),
            "{lines:?}"
        );
        assert!(lines[0].contains(path), "{lines:?}");
        assert!(lines[0].contains("is not a declared site"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// The real tree: every file holding a `can_read` or `visibility_readable` token has exactly its declared count.
    #[test]
    fn m08_2_real_repo_passes() {
        assert_eq!(m08_2_can_read_one_home(&real_root()), Verdict::Pass);
    }

    /// The ratchet: the gate is the only declared site, with a count and a reason. A second declared site is an edit
    /// to this test as well as to the const, so an exception to "one home" cannot be added by the const alone.
    #[test]
    fn m08_2_declares_the_gate_as_the_only_site() {
        assert_eq!(M08_CAN_READ_SITES.len(), 1);
        for (file, count, why) in M08_CAN_READ_SITES {
            assert_eq!(file, M08_GATE);
            assert!(count > 0, "{file}");
            assert!(!why.is_empty(), "{file}");
        }
    }

    /// The ratchet on the door: four row-level callers outside the gate, each with a count and a reason, and the gate
    /// file is not one of them. A fifth is an edit to this test as well as to the const.
    #[test]
    fn m08_2_declares_the_four_row_level_callers_of_the_door() {
        assert_eq!(M08_VISIBILITY_READABLE_SITES.len(), 4);
        for (file, count, why) in M08_VISIBILITY_READABLE_SITES {
            assert_ne!(file, M08_GATE);
            assert!(count > 0, "{file}");
            assert!(!why.is_empty(), "{file}");
        }
    }

    /// 注错 (G-M08-2, M08-7): a `can_read` use back in a row-level caller is red, naming that file as an undeclared
    /// `can_read` site; the caller's own `visibility_readable` count still holds.
    #[test]
    fn m08_2_fails_when_a_row_level_caller_names_can_read_again() {
        for (file, count, _) in M08_VISIBILITY_READABLE_SITES {
            let tmp = m08_declared_tree("m08-2-red-routed");
            assert_eq!(m08_2_can_read_one_home(&tmp), Verdict::Pass, "{file}");
            m07_write(&tmp, file, &format!("{}{M08_CALL}", m08_door_uses(count)));
            let lines = m08_fail_lines(&tmp);
            assert_eq!(lines.len(), 1, "{file}: {lines:?}");
            assert!(lines[0].contains(file), "{lines:?}");
            assert!(lines[0].contains("is not a declared site"), "{lines:?}");
            assert!(
                lines[0].contains("G-M08-2: can_read( call outside the read gate"),
                "{lines:?}"
            );
            fs::remove_dir_all(&tmp).ok();
        }
    }

    /// 注错 (G-M08-2, M08-7 review P1-a): a fifth file calling the gate's row-level door is red as an undeclared site.
    /// The same shape written with `can_read` was red before the door existed; the door must not be a way around it.
    #[test]
    fn m08_2_fails_on_a_new_caller_of_the_row_level_door() {
        m08_undeclared_door_use_is_red(
            "m08-2-red-door-new-file",
            "crates/adapters/src/new_read.rs",
            "use crate::read_gate::visibility_readable;\n\
             fn f(a: &AuthorizationScope, m: &VisibilityDescriptor) -> bool { visibility_readable(a, m) }\n",
        );
        m08_undeclared_door_use_is_red(
            "m08-2-red-door-bin",
            "bins/gateway/src/memory.rs",
            M08_DOOR_CALL,
        );
    }

    /// 注错 (G-M08-2, M08-7 review P1-a): the door named without a call, an alias import and a function pointer are
    /// uses too, exactly like the `can_read` shapes.
    #[test]
    fn m08_2_counts_the_door_under_every_spelling() {
        for (label, body) in [
            (
                "m08-2-red-door-alias",
                "use crate::read_gate::visibility_readable as vr;\nfn f() { let _ = vr(a, &b); }\n",
            ),
            (
                "m08-2-red-door-pointer",
                "fn f() { let g = read_gate::visibility_readable; let _ = g(a, &b); }\n",
            ),
            (
                "m08-2-red-door-space",
                "fn f() { let _ = visibility_readable (a, &b); }\n",
            ),
        ] {
            m08_undeclared_door_use_is_red(label, "crates/adapters/src/grep_repo.rs", body);
        }
    }

    /// 注错 (G-M08-2, M08-7 review P1-a): one MORE use of the door in a declared caller is red, naming the file and
    /// both counts.
    #[test]
    fn m08_2_fails_on_an_extra_use_of_the_door_in_a_declared_caller() {
        for (file, count, _) in M08_VISIBILITY_READABLE_SITES {
            let tmp = m08_declared_tree("m08-2-red-door-extra");
            m07_write(&tmp, file, &m08_door_uses(count + 1));
            let lines = m08_fail_lines(&tmp);
            assert_eq!(lines.len(), 1, "{file}: {lines:?}");
            assert!(lines[0].contains(file), "{lines:?}");
            assert!(
                lines[0].contains("G-M08-2: visibility_readable use outside its declared sites"),
                "{lines:?}"
            );
            assert!(
                lines[0].contains(&format!("holds {} `visibility_readable` tokens", count + 1)),
                "{lines:?}"
            );
            assert!(lines[0].contains(&format!("expected {count}")), "{lines:?}");
            assert_eq!(m08_door_count(file), count);
            fs::remove_dir_all(&tmp).ok();
        }
    }

    /// 注错 (G-M08-2, M08-7 review P1-a): one FEWER use of the door in a declared caller is red too (`==`, never
    /// `<=`), so a caller leaves the const only by an edit to it.
    #[test]
    fn m08_2_fails_when_a_declared_caller_loses_a_use_of_the_door() {
        for (file, count, _) in M08_VISIBILITY_READABLE_SITES {
            let tmp = m08_declared_tree("m08-2-red-door-fewer");
            m07_write(&tmp, file, &m08_door_uses(count - 1));
            let lines = m08_fail_lines(&tmp);
            assert_eq!(lines.len(), 1, "{file}: {lines:?}");
            assert!(lines[0].contains(file), "{lines:?}");
            assert!(
                lines[0].contains(&format!("holds {} `visibility_readable` tokens", count - 1)),
                "{lines:?}"
            );
            assert!(lines[0].contains(&format!("expected {count}")), "{lines:?}");
            assert!(
                !lines[0].contains("outside its declared sites"),
                "{lines:?}"
            );
            fs::remove_dir_all(&tmp).ok();
        }
    }

    /// The gate file defines the door and applies it inside `readable_memory_ids`, so its own `visibility_readable`
    /// tokens are not pinned (its `can_read` count still is).
    #[test]
    fn m08_2_does_not_pin_the_door_inside_the_gate_file() {
        let tmp = m08_declared_tree("m08-2-door-in-gate");
        m07_write(
            &tmp,
            M08_GATE,
            &format!(
                "{}fn visibility_readable() {{}}\n{}",
                m08_uses(m08_count(M08_GATE)),
                m08_door_uses(5)
            ),
        );
        assert_eq!(m08_2_can_read_one_home(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// `run()` must list the gate: a deleted or commented-out call tuple leaves a gate that never runs and reads as
    /// green (the 恒真闸 shape §57.1 exists to prevent). Counted `== 1`, not `>= 1`.
    #[test]
    fn run_wires_the_m08_one_home_gate_exactly_once() {
        assert_eq!(own_source_count("m08_2_can_read_one_", "home(&root),"), 1);
    }

    /// Green fixture, plus everything that must NOT count: comments of every kind, other identifiers that merely
    /// contain the name (`cannot_read(` as code, `my_can_read(`, `can_read_all(`), a use after the file's trailing
    /// `#[cfg(test)] mod`, integration-test trees, and production code outside adapters and bins (`domain` defines
    /// `can_read`, `projection` mirrors it).
    #[test]
    fn m08_2_passes_on_the_declared_counts_and_ignores_comments_tests_and_other_crates() {
        let tmp = m08_declared_tree("m08-2-green");
        m07_write(
            &tmp,
            "crates/adapters/src/distill_repo.rs",
            "// can_read(a, &b) lives in the read gate\n\
             /// can_read(a, &b) in a doc comment\n\
             //! can_read(a, &b) in an inner doc comment\n\
             fn f() { let n = 1; // can_read(a, &b) trailing\n\
             }\n\
             /* can_read(a, &b) in a block comment */\n\
             fn g() { let _ = cannot_read(a, &b); let _ = my_can_read(a, &b); }\n\
             fn h() { let _ = can_read_all(a, &b); let _ = a.can_readable(&b); }\n\
             /// visibility_readable(a, &b) in a doc comment\n\
             fn i() { let _ = my_visibility_readable(a, &b); let _ = visibility_readable_all(a, &b); }\n\
             #[cfg(test)]\n\
             mod tests { fn t() { let _ = can_read(a, &b); let _ = visibility_readable(a, &b); } }\n",
        );
        m07_write(&tmp, "crates/adapters/tests/seed.rs", M08_CALL);
        m07_write(&tmp, "bins/gateway/tests/seed.rs", M08_CALL);
        m07_write(&tmp, "crates/domain/src/identity.rs", M08_CALL);
        m07_write(&tmp, "crates/projection/src/sparse.rs", M08_CALL);
        m07_write(&tmp, "xtask/src/other.rs", M08_CALL);
        assert_eq!(m08_2_can_read_one_home(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// `not_applicable` names the missing object (§57.1 第2条): there is no adapters crate to scan.
    #[test]
    fn m08_2_is_not_applicable_naming_the_missing_adapters_src() {
        let tmp = fresh_tmp("m08-2-na");
        fs::create_dir_all(&tmp).unwrap();
        match m08_2_can_read_one_home(&tmp) {
            Verdict::NotApplicable(detail) => {
                assert!(detail.contains("crates/adapters/src"), "{detail}");
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2): a `can_read(` call in `context_repo.rs`, the file the closure moved out of → 红, naming it.
    #[test]
    fn m08_2_fails_on_a_call_in_context_repo() {
        let tmp = m08_declared_tree("m08-2-red-context-repo");
        m07_write(&tmp, "crates/adapters/src/context_repo.rs", M08_CALL);
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("G-M08-2: can_read( call outside the read gate"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("crates/adapters/src/context_repo.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2): a call in a bin's `src/` is outside the gate too.
    #[test]
    fn m08_2_fails_on_a_call_in_a_bin() {
        let tmp = m08_declared_tree("m08-2-red-bin");
        m07_write(&tmp, "bins/gateway/src/memory.rs", M08_CALL);
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("bins/gateway/src/memory.rs"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2): a `tests` directory INSIDE `src/` is production code, not a test tree.
    #[test]
    fn m08_2_counts_a_call_in_a_src_tests_directory() {
        let tmp = m08_declared_tree("m08-2-red-src-tests-dir");
        m07_write(&tmp, "crates/adapters/src/tests/helper.rs", M08_CALL);
        let lines = m08_fail_lines(&tmp);
        assert!(
            lines[0].contains("crates/adapters/src/tests/helper.rs"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2): a path-qualified call (`identity::can_read(..)`) is a use.
    #[test]
    fn m08_2_counts_a_path_qualified_call() {
        m08_undeclared_use_is_red(
            "m08-2-red-qualified",
            "fn f() { let _ = humaux_domain::identity::can_read(a, &b); }\n",
        );
    }

    /// 注错 (G-M08-2, review W1): one MORE use in a declared file is red, naming the file and both counts. A gate that
    /// only pinned the file set stayed green here.
    #[test]
    fn m08_2_fails_on_an_extra_use_in_a_declared_site() {
        let tmp = m08_declared_tree("m08-2-red-extra");
        let expected = m08_count(M08_GATE);
        m07_write(&tmp, M08_GATE, &m08_uses(expected + 1));
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(M08_GATE), "{lines:?}");
        assert!(
            lines[0].contains(&format!("holds {} `can_read` tokens", expected + 1)),
            "{lines:?}"
        );
        assert!(
            lines[0].contains(&format!("expected {expected}")),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("G-M08-2: can_read( call outside the read gate"),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2, review W1): one FEWER use in a declared file is red too (`==`, never `<=`), naming both counts,
    /// so a count shrinks only by an edit to the const.
    #[test]
    fn m08_2_fails_when_a_declared_site_loses_a_use() {
        let tmp = m08_declared_tree("m08-2-red-fewer");
        let expected = m08_count(M08_GATE);
        m07_write(&tmp, M08_GATE, &m08_uses(expected - 1));
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(M08_GATE), "{lines:?}");
        assert!(
            lines[0].contains(&format!("holds {} `can_read` tokens", expected - 1)),
            "{lines:?}"
        );
        assert!(
            lines[0].contains(&format!("expected {expected}")),
            "{lines:?}"
        );
        assert!(!lines[0].contains("outside the read gate"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2): a declared file that was renamed away is red, not a skip: the old name holds 0 of its expected
    /// count and the new name is an undeclared site.
    #[test]
    fn m08_2_fails_when_a_declared_site_does_not_exist() {
        let tmp = m08_declared_tree("m08-2-red-missing");
        fs::remove_file(tmp.join(M08_GATE)).unwrap();
        m07_write(&tmp, "crates/adapters/src/read_gates.rs", M08_CALL);
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("outside the read gate") && l.contains("read_gates.rs")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains(&format!("{M08_GATE} holds 0 `can_read` tokens, expected"))),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2, review W2): `use ...::can_read as cr; cr(..)` never spells `can_read(`, but the import names it.
    #[test]
    fn m08_2_counts_an_aliased_import() {
        m08_undeclared_use_is_red(
            "m08-2-red-alias",
            "use humaux_domain::identity::can_read as cr;\nfn f() { let _ = cr(a, &b); }\n",
        );
    }

    /// 注错 (G-M08-2, review W2): the alias import raises the count of a DECLARED site as well.
    #[test]
    fn m08_2_counts_an_aliased_import_in_a_declared_site() {
        let tmp = m08_declared_tree("m08-2-red-alias-declared");
        let expected = m08_count(M08_GATE);
        m07_write(
            &tmp,
            M08_GATE,
            &format!(
                "{}use humaux_domain::identity::can_read as cr;\nfn g() {{ let _ = cr(a, &b); }}\n",
                m08_uses(expected)
            ),
        );
        let lines = m08_fail_lines(&tmp);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(M08_GATE), "{lines:?}");
        assert!(
            lines[0].contains(&format!("expected {expected}")),
            "{lines:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (G-M08-2, review W2): a function pointer (`let g = identity::can_read; g(..)`) has no `(` after the name.
    #[test]
    fn m08_2_counts_a_function_pointer() {
        m08_undeclared_use_is_red(
            "m08-2-red-fn-pointer",
            "fn f() { let g = humaux_domain::identity::can_read; let _ = g(a, &b); }\n",
        );
    }

    /// 注错 (G-M08-2, review W2): passing the function as an argument.
    #[test]
    fn m08_2_counts_the_name_passed_as_an_argument() {
        m08_undeclared_use_is_red("m08-2-red-argument", "fn f() { helper(can_read, v); }\n");
    }

    /// 注错 (G-M08-2, review W2): a macro that forwards the name as an `$f:ident` argument.
    #[test]
    fn m08_2_counts_the_name_passed_to_a_macro() {
        m08_undeclared_use_is_red(
            "m08-2-red-macro",
            "macro_rules! judge { ($f:ident, $a:expr) => { $f($a) }; }\nfn f() { judge!(can_read, 1); }\n",
        );
    }

    /// 注错 (G-M08-2, review W2): `can_read (` with a space is still a call.
    #[test]
    fn m08_2_counts_a_call_with_a_space_before_the_paren() {
        m08_undeclared_use_is_red("m08-2-red-space", "fn f() { let _ = can_read (a, &b); }\n");
    }

    /// 注错 (G-M08-2, review W2): a `/*` inside a `//` doc comment (`migrations/*.sql`) is not a block comment, so the
    /// call after it is still seen. The naive helper blanked everything up to the next `*/` or the end of the file.
    #[test]
    fn m08_2_sees_a_call_after_a_slash_star_in_a_line_comment() {
        m08_undeclared_use_is_red(
            "m08-2-red-doc-slash-star",
            "/// every `migrations/*.sql` file\nfn f() { let _ = can_read(a, &b); }\n",
        );
    }

    /// 注错 (G-M08-2, review W2): a `/*` inside a byte string (`bins/maintenance/src/migration_manifest.rs:158`) is not
    /// a block comment either.
    #[test]
    fn m08_2_sees_a_call_after_a_slash_star_in_a_string_literal() {
        m08_undeclared_use_is_red(
            "m08-2-red-string-slash-star",
            "fn f(b: &[u8]) -> bool { b.starts_with(b\"/*\") }\nfn g() { let _ = can_read(a, &b); }\n",
        );
    }

    /// `strip_block_comments` outside the gate: the squeezed text is what survives.
    fn squeezed(source: &str) -> String {
        strip_block_comments(source)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A block comment is blanked to spaces with its newlines kept, so line numbers and byte columns survive.
    #[test]
    fn strip_block_comments_blanks_a_comment_and_keeps_the_layout() {
        let source = "a /* x\ny */ b";
        let out = strip_block_comments(source);
        assert_eq!(out.len(), source.len());
        assert_eq!(out.lines().count(), 2);
        assert_eq!(squeezed(source), "a b");
    }

    /// Rust block comments nest; an unterminated one runs to the end.
    #[test]
    fn strip_block_comments_nests_and_blanks_an_unterminated_comment_to_the_end() {
        assert_eq!(squeezed("a /* o /* i */ still */ b"), "a b");
        assert_eq!(squeezed("a /*/ b */ c"), "a c");
        assert_eq!(squeezed("a /* never closed\nb"), "a");
    }

    /// A `/*` inside a line comment, a string, a byte string, a raw string or a char literal opens nothing.
    #[test]
    fn strip_block_comments_ignores_a_slash_star_that_is_not_a_comment_start() {
        for source in [
            "// see tests/*.rs\nfn f() {}\n",
            "/// see migrations/*.sql\nfn f() {}\n",
            "let a = \"/*\"; let b = 1;",
            "let a = b\"/*\"; let b = 1;",
            "let a = r#\"/* \"quoted\" */\"#; let b = 1;",
            "let a = br\"/*\"; let b = 1;",
            // The `/*` sits after an inner `"#` that does not close a two-hash raw string, so only hash counting and
            // the hash-aware close keep it inside the string.
            "r##\"x\"# /* y */ z\"##",
            "br#\"a\"b /* c\"#",
            "let a = '/'; let s = \"*/\"; let b = 1;",
            "let a = \"escaped \\\" /* still a string\"; let b = 1;",
            "let a = \"é/*\"; let b = 1;",
        ] {
            assert_eq!(strip_block_comments(source), source, "{source}");
        }
    }

    /// A real block comment after those is still blanked, and a `'"'` char literal does not open a string.
    #[test]
    fn strip_block_comments_still_blanks_a_comment_after_a_literal() {
        assert_eq!(
            squeezed("let a = \"/*\"; /* x */ let b = 1;"),
            "let a = \"/*\"; let b = 1;"
        );
        assert_eq!(
            squeezed("let q = '\"'; /* x */ let z = 1;"),
            "let q = '\"'; let z = 1;"
        );
        assert_eq!(
            squeezed("let q = '\\''; /* x */ let z = 1;"),
            "let q = '\\''; let z = 1;"
        );
        // The escape arm of the char literal: `'\"'` must not open a string.
        assert_eq!(
            squeezed("let q = '\\\"'; /* x */ let z = 1;"),
            "let q = '\\\"'; let z = 1;"
        );
        // `'a` followed by a comma is a lifetime: lexed as a char literal it would swallow the comment's start.
        assert_eq!(squeezed("fn f<'a, /* c */ 'b>() {}"), "fn f<'a, 'b>() {}");
        assert_eq!(
            squeezed("fn f<'a>(x: &'a str) { /* c */ let y = 1; }"),
            "fn f<'a>(x: &'a str) { let y = 1; }"
        );
        assert_eq!(
            squeezed("let a = r#\"x\"#; /* c */ let b = 1;"),
            "let a = r#\"x\"#; let b = 1;"
        );
        assert_eq!(
            squeezed("let r = 1; /* c */ let b = r;"),
            "let r = 1; let b = r;"
        );
    }

    /// The other user of the helper, the provider-plane call-site counter, now sees code after a `/*` in a doc comment.
    #[test]
    fn count_code_line_hits_sees_code_after_a_slash_star_in_a_doc_comment() {
        let source =
            "/// every `migrations/*.sql` file\nfn f() { self.transport.call(&permit); }\n";
        assert_eq!(count_code_line_hits(source, ".call("), 1);
    }

    // -- widened scan domain: bins/ / evals/ now genuinely inside the four workspace-wide
    // -- checks' territory, not just crates/ (§80.1.1 / §48.0① / §59.1 / §52.4) -------------

    /// 注错 (§52.4 G52-1 "扫全 workspace"): a second error enum at an `error_code` position in
    /// `bins/`, previously outside the old crates/-only scan domain.
    #[test]
    fn g52_1_fails_on_second_enum_found_in_bins_dir() {
        let tmp = fresh_tmp("g52-1-red-bins");
        let dir = tmp.join("bins/worker/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("main.rs"),
            "struct M {\n    pub error_code: BillingError,\n}\n",
        )
        .unwrap();
        assert!(matches!(
            g52_1_error_code_uniqueness(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 a (§59.1 G59-3, integration level): a second `Authority {` literal in the real
    /// top-level `evals/` — the exact site named by the spec's own G59-3 注错a — was invisible
    /// to the old crates/domain-only scan domain; the widened workspace-root walk must catch
    /// it via the wired-up [`g59_3_authority_construction_point`], not just the pure comparator.
    #[test]
    fn g59_3_fails_on_second_hit_in_real_evals_dir() {
        let tmp = fresh_tmp("g59-3-red-evals");
        let dir = tmp.join("crates/domain/src");
        let evals_dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&evals_dir).unwrap();
        fs::write(
            dir.join("authority.rs"),
            "impl Authority {\n    pub fn new() -> Self {\n        Authority { x: 1 }\n    }\n}\n",
        )
        .unwrap();
        fs::write(
            evals_dir.join("probe.rs"),
            "fn shortcut() { let _ = Authority { x: 2 }; }\n",
        )
        .unwrap();
        assert!(matches!(
            g59_3_authority_construction_point(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 for the same fixture: with the second site removed, the sole real hit is inside
    /// `authority.rs::Authority::new`'s body → green — proves the red above is really about the
    /// second site, not some other defect in the fixture.
    #[test]
    fn g59_3_passes_with_only_the_real_evals_dir_present_and_empty() {
        let tmp = fresh_tmp("g59-3-green-evals");
        let dir = tmp.join("crates/domain/src");
        let evals_dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(&evals_dir).unwrap();
        fs::write(
            dir.join("authority.rs"),
            "impl Authority {\n    pub fn new() -> Self {\n        Authority { x: 1 }\n    }\n}\n",
        )
        .unwrap();
        assert_eq!(g59_3_authority_construction_point(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§78 boundary lints, widened domain): `std::env::var` planted in the real top-level
    /// `evals/` — not `bins/`, not `xtask/`, so no exemption applies — was invisible to the old
    /// crates/-only scan domain.
    #[test]
    fn env_var_scan_fails_on_call_in_real_evals_dir() {
        let tmp = fresh_tmp("envvar-red-evals");
        let dir = tmp.join("evals");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("probe.rs"),
            "pub fn f() { let _ = std::env::var(\"X\"); }\n",
        )
        .unwrap();
        assert!(matches!(env_var_scan(&tmp), Verdict::Fail(_)));
        fs::remove_dir_all(&tmp).ok();
    }

    /// §78 boundary lint: `xtask/` is bootstrap/CI-gate tooling, exempt like `bins/*` — a real
    /// call there (mirroring `contract_impact.rs`'s own `std::env::var("CI")`) must stay green.
    /// 豁免必须是**窄**的：同一个文件里读一个不带测试前缀的变量，照旧算违规。
    /// 没有这条，`TEST_CONTROL_ENV_PREFIXES` 就等于把 env 扫描整体关掉了。
    #[test]
    fn env_var_scan_test_control_exemption_does_not_cover_production_config() {
        let src = "pub fn a() { let _ = std::env::var(\"HUMAUX_REQUIRE_DB\"); }\n\
                   pub fn b() { let _ = std::env::var(\"DATABASE_URL\"); }\n";
        let hits = scan_env_var_violations("crates/testkit/src/lib.rs", src);
        assert_eq!(
            hits.len(),
            1,
            "只有第 2 行（DATABASE_URL，生产配置）该被抓；第 1 行是测试控制量: {hits:?}"
        );
        assert!(hits[0].ends_with(":2"), "抓错行了: {hits:?}");
    }

    /// 反向：名字由变量传入、静态看不出读的是什么 —— 不豁免（宁可误报也不放过）。
    #[test]
    fn env_var_scan_does_not_exempt_a_dynamically_named_read() {
        let src = "pub fn a(name: &str) { let _ = std::env::var(name); }\n";
        assert_eq!(
            scan_env_var_violations("crates/testkit/src/lib.rs", src).len(),
            1,
            "名字看不见时不得豁免"
        );
    }

    #[test]
    fn env_var_scan_exempts_xtask_dir() {
        let tmp = fresh_tmp("envvar-exempt-xtask");
        let dir = tmp.join("xtask/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("some_tool.rs"),
            "pub fn f() { let _ = std::env::var(\"CI\"); }\n",
        )
        .unwrap();
        assert_eq!(env_var_scan(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// §78 short-form spelling: `use std::env;` then bare `env::var(` must be caught, not just
    /// the fully-qualified `std::env::var`.
    #[test]
    fn env_var_scan_flags_short_form_after_use_std_env() {
        let src = "use std::env;\nfn f() {\n    let x = env::var(\"X\");\n}\n";
        assert_eq!(scan_env_var_violations("f.rs", src).len(), 1);
    }

    /// §78 re-exported short form: `use std::env::var;` then a bare `var(` call must be caught.
    #[test]
    fn env_var_scan_flags_bare_var_after_use_std_env_var() {
        let src = "use std::env::var;\nfn f() {\n    let x = var(\"X\");\n}\n";
        assert_eq!(scan_env_var_violations("f.rs", src).len(), 1);
    }

    /// A bare `var(` call with no `use std::env::var` import anywhere in the file is not an
    /// env-var access at all (some unrelated local fn named `var`) and must not be flagged.
    #[test]
    fn env_var_scan_ignores_unrelated_bare_var_call_without_the_import() {
        let src = "fn var(x: i32) -> i32 { x }\nfn f() -> i32 { var(1) }\n";
        assert!(scan_env_var_violations("f.rs", src).is_empty());
    }

    // -- §59.1 G59-3: `Self {}` construction inside `impl Authority` scope ------------------

    /// The real spelling `Authority::new` is free to use: `Ok(Self { .. })`, the idiomatic
    /// form `clippy::use_self` prefers — must be recognized as a construction site exactly
    /// like the bare `Authority { .. }` spelling.
    #[test]
    fn find_authority_struct_literals_matches_self_inside_impl_authority() {
        let src = "impl Authority {\n    pub fn new(x: i32) -> Result<Self, E> {\n        Ok(Self { x })\n    }\n}\n";
        assert_eq!(find_authority_struct_literals(src).len(), 1);
    }

    /// `Self { .. }` outside any `impl Authority` block (a different type's own constructor)
    /// must not be mistaken for an Authority construction site.
    #[test]
    fn find_authority_struct_literals_ignores_self_outside_impl_authority() {
        let src = "impl Other {\n    fn new() -> Self {\n        Self { x: 1 }\n    }\n}\n";
        assert!(find_authority_struct_literals(src).is_empty());
    }

    /// `-> Self {` is `Authority::new`'s own fn-signature body brace, not a `Self { .. }`
    /// struct literal — must not double-count alongside the real `Authority { .. }` literal in
    /// the same body.
    #[test]
    fn find_authority_struct_literals_does_not_miscount_arrow_self_as_a_literal() {
        let src = "impl Authority {\n    pub fn new(x: i32) -> Self {\n        Authority { x }\n    }\n}\n";
        assert_eq!(find_authority_struct_literals(src).len(), 1);
    }
    /// G80-40 static: real repo must pass (seven wrappers once each, no raw pool outside,
    /// ui fixtures keep the sentinel alive).
    #[test]
    fn g80_40_real_repo_is_green() {
        assert_eq!(g6_db_pool_topology(&real_root()), Verdict::Pass);
    }

    /// 注错 a：把 raw `sqlx::PgPool` 写进封装点之外的生产文件 ⇒ 红并点名文件。
    #[test]
    fn g80_40_fault_raw_pool_outside_encapsulation_is_red() {
        let tmp = fresh_tmp("g80-40-raw-pool");
        copy_adapters_fixture(&tmp);
        fs::write(
            tmp.join("crates/other/src/lib.rs"),
            "pub struct Svc { pool: sqlx::PgPool }\n",
        )
        .unwrap();
        match g6_db_pool_topology(&tmp) {
            Verdict::Fail(lines) => {
                assert!(lines.iter().any(|l| l.contains("crates/other/src/lib.rs")))
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// 注错 b：掏空封装点里 `sqlx::PgPool` 的实际命名（只留注释提及） ⇒ 红——
    /// 扫描器失明（永远匹配 0）必须可观察。
    #[test]
    fn g80_40_fault_dead_sentinel_is_red() {
        let tmp = fresh_tmp("g80-40-sentinel");
        copy_adapters_fixture(&tmp);
        // wrappers still declared (so the seven-count check passes) but their inner field
        // no longer *names* the raw type — only a comment mentions it. A live scanner
        // must notice the naming sentinel went to 0.
        fs::write(
            tmp.join("crates/adapters/src/postgres.rs"),
            "// inner is a sqlx::PgPool, morally\n\
             pub struct RuntimeDbPool(());\n\
             pub struct BatchIssuerDbPool(());\n\
             pub struct ConsolidationDbPool(());\n\
             pub struct PrivateWorkerDbPool(());\n\
             pub struct RetrievalWorkerDbPool(());\n\
             pub struct MaintenanceDbPool(());\n\
             pub struct PublicWorkerDbPool(());\n\
             pub struct AdminDbPool(());\n\
             pub struct MigratorDbPool(());\n",
        )
        .unwrap();
        match g6_db_pool_topology(&tmp) {
            Verdict::Fail(lines) => assert!(lines.iter().any(|l| l.contains("sentinel"))),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// fixture: minimal adapters crate shape for the two injections above.
    fn copy_adapters_fixture(tmp: &Path) {
        for d in [
            "crates/adapters/src",
            "crates/adapters/tests/ui",
            "crates/other/src",
        ] {
            fs::create_dir_all(tmp.join(d)).unwrap();
        }
        fs::write(
            tmp.join("crates/adapters/src/postgres.rs"),
            "pub struct RuntimeDbPool { inner: sqlx::PgPool }\n\
             pub struct BatchIssuerDbPool { inner: sqlx::PgPool }\n\
             pub struct ConsolidationDbPool { inner: sqlx::PgPool }\n\
             pub struct PrivateWorkerDbPool { inner: sqlx::PgPool }\n\
             pub struct RetrievalWorkerDbPool { inner: sqlx::PgPool }\n\
             pub struct MaintenanceDbPool { inner: sqlx::PgPool }\n\
             pub struct PublicWorkerDbPool { inner: sqlx::PgPool }\n\
             pub struct AdminDbPool { inner: sqlx::PgPool }\n\
             pub struct MigratorDbPool { inner: sqlx::PgPool }\n",
        )
        .unwrap();
        fs::write(
            tmp.join("crates/adapters/tests/ui/fail_raw_pool_field.rs"),
            "struct Bad { pool: sqlx::PgPool }\nfn main() {}\n",
        )
        .unwrap();
        fs::write(tmp.join("crates/other/src/lib.rs"), "\n").unwrap();
    }

    // -- §83.4 G80-3: Outbound Network Choke Point ------------------------------------------

    fn outbound_purpose_fixture() -> String {
        "pub enum OutboundPurpose {\n    \
             USER_REASONING(EgressPermit),\n    \
             RETRIEVAL_EMBEDDING(EgressPermit),\n    \
             RETRIEVAL_RERANK(EgressPermit),\n    \
             PUBLIC_REASONING,\n    \
             BILLING,\n    \
             TRANSACTIONAL_EMAIL,\n    \
             GIT_PROVIDER,\n    \
             OAUTH_METADATA,\n    \
             PUBLIC_SOURCE_FETCH,\n    \
             DEADMAN_HEALTHCHECK,\n\
         }\n"
        .to_string()
    }

    // --- ADR-0039: outbound client dials only through the checked resolver ---

    /// The three files ADR-0039's gate expects to exist, in their post-card-17 shape.
    fn adr_0039_clean_fixture(root: &Path) -> Vec<(PathBuf, String)> {
        vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn build_client_with_resolver<R>(c: ClientConfig, r: Arc<R>) -> Out {\n    \
                 client_builder(c).dns_resolver(r).build()\n}\n\
                 #[cfg(test)]\nmod t { fn x() { build_client_with_resolver(cfg, res); } }\n"
                    .to_string(),
            ),
            (
                root.join("crates/infra-egress/src/resolver.rs"),
                "pub fn build_pinned_client(c: ClientConfig) -> Out {\n    \
                 build_client_with_resolver(c, Arc::new(PinnedResolver::new()))\n}\n"
                    .to_string(),
            ),
            (
                root.join("crates/infra-cell/src/transport.rs"),
                "fn with_resolver() { let c = build_client_with_resolver(cfg, resolver)?; }\n"
                    .to_string(),
            ),
            (
                root.join("crates/adapters/src/byok.rs"),
                "pub fn with_egress_transport(r: Arc<dyn ssrf::DnsResolver>) -> Out {\n    \
                 let t = EgressHttpTransport::with_resolver(timeout, Arc::clone(&r))?;\n    \
                 Self::new(d, url, t, key, policy, r.as_ref())\n}\n"
                    .to_string(),
            ),
        ]
    }

    /// Positive control: the clean fixture scans clean, so a later red is the injected fault
    /// and not a matcher that is broken by construction.
    #[test]
    fn adr_0039_clean_fixture_has_no_problems() {
        let root = PathBuf::from("/fixture-root");
        let problems = checked_resolver_dial_problems(&adr_0039_clean_fixture(&root), &root);
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// 注错 a — **the card's own fault injection**: a caller reintroduces a system-DNS dial by
    /// calling the resolver-less `build_client(`. The scan must go red and name the file.
    #[test]
    fn adr_0039_fault_system_dns_dial_reintroduced_in_a_caller_is_red_and_named() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("crates/infra-egress/src/raw.rs"),
            "pub fn new(t: Duration) -> Out {\n    \
             let client = build_client(ClientConfig { request_timeout: t })?;\n    \
             Ok(Self { client })\n}\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/infra-egress/src/raw.rs") && p.contains("判据1")),
            "reintroducing build_client( must go red: {problems:?}"
        );
    }

    /// 注错 b: a fourth crate builds its own outbound client through the checked constructor
    /// but with a resolver of its own choosing — no Layer 1 policy owns that destination.
    #[test]
    fn adr_0039_fault_fourth_call_site_is_red_and_named() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("crates/adapters/src/dashscope.rs"),
            "fn c() { let _ = build_client_with_resolver(cfg, Arc::new(MyOwnResolver)); }\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/src/dashscope.rs") && p.contains("判据2")),
            "a fourth outbound-client construction site must go red: {problems:?}"
        );
    }

    /// 注错 c: the resolver-less constructor is re-exported from Layer 0 (nobody calls it yet)
    /// — the living sentinel must still go red, because the next caller is one edit away.
    #[test]
    fn adr_0039_fault_build_client_reexported_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files[0]
            .1
            .push_str("pub fn build_client(c: ClientConfig) -> Out { unimplemented!() }\n");
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems.iter().any(|p| p.contains("判据3")),
            "re-adding pub fn build_client must go red: {problems:?}"
        );
    }

    /// 注错 d: a Layer 1 resolver module stops installing its resolver entirely. "No offender
    /// found" must not read as pass when the mechanism itself is gone.
    #[test]
    fn adr_0039_fault_layer1_resolver_module_stops_calling_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files[1].1 = "pub fn build_pinned_client() { todo!() }\n".to_string();
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/infra-egress/src/resolver.rs") && p.contains("判据3")),
            "a Layer 1 module that stops installing its resolver must go red: {problems:?}"
        );
    }

    /// 注错 e: `.dns_resolver(` named outside Layer 0 — the "which resolver" decision re-made
    /// somewhere the gate does not govern.
    #[test]
    fn adr_0039_fault_dns_resolver_installed_outside_layer0_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("crates/adapters/src/qdrant.rs"),
            "fn c(b: ClientBuilder) { let _ = b.dns_resolver(Arc::new(Whatever)); }\n".to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems.iter().any(|p| p.contains("判据4")),
            "installing a resolver outside Layer 0 must go red: {problems:?}"
        );
    }

    /// Negative control: a *comment* mentioning the deleted constructor is documentation, not a
    /// call — the gate must not be a grep that punishes rustdoc for naming what it removed.
    #[test]
    fn adr_0039_comments_naming_build_client_are_not_offenders() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("crates/infra-egress/src/raw.rs"),
            "/// ADR-0039: the resolver-less build_client( is deleted.\n\
             // build_client(cfg) used to live here.\n\
             pub struct RawHttpPost;\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// 注错 f — **the P0 the card-17 review found in production**: a bin rebuilds the
    /// resolver-hardwiring transport constructor's call. 判据5 must name the file.
    #[test]
    fn adr_0039_fault_hardwired_transport_constructor_is_red_and_named() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("bins/private-worker/src/main.rs"),
            "fn boot() { let t = EgressHttpTransport::new(http_timeout)?; }\n".to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("bins/private-worker/src/main.rs") && p.contains("判据5")),
            "reintroducing EgressHttpTransport::new( must go red: {problems:?}"
        );
    }

    /// 注错 g: a fourth file picks the BYOK transport's dial resolver by itself — the dial
    /// resolver and the check resolver are two independent values again.
    #[test]
    fn adr_0039_fault_transport_resolver_chosen_outside_the_derived_constructor_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("bins/consolidation-worker/src/main.rs"),
            "fn boot() { let t = EgressHttpTransport::with_resolver(t, Arc::new(Other))?; }\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems.iter().any(
                |p| p.contains("bins/consolidation-worker/src/main.rs") && p.contains("判据6")
            ),
            "choosing the dial resolver outside the derived constructor must go red: {problems:?}"
        );
    }

    /// 注错 h — the exact production shape the review caught: a bin calls
    /// `OpenAiCompatibleProvider::new(`, i.e. supplies the check resolver by hand next to a
    /// separately built transport. 判据7 must go red **even though** the transport line itself
    /// looks innocent (that is why 判据1–4 stayed green on it).
    #[test]
    fn adr_0039_fault_bin_hand_pairs_check_resolver_and_transport_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("bins/private-worker/src/main.rs"),
            "fn boot() {\n    let p = OpenAiCompatibleProvider::new(d, url, transport, k, \
             policy, resolver.as_ref())?;\n}\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("bins/private-worker/src/main.rs") && p.contains("判据7")),
            "a bin supplying the check resolver by hand must go red: {problems:?}"
        );
    }

    /// 注错 i: the derived constructor is deleted. 判据5/6/7 would all be vacuously green —
    /// the living sentinel must go red instead.
    #[test]
    fn adr_0039_fault_derived_constructor_deleted_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files[3].1 = "pub struct EgressHttpTransport;\n".to_string();
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/src/byok.rs") && p.contains("判据8")),
            "deleting with_egress_transport must go red: {problems:?}"
        );
    }

    /// Negative control for 判据7: an integration test may still call
    /// `OpenAiCompatibleProvider::new(` — that is how a fake transport gets injected, and the
    /// rule is about production bins, not about every mention of the name.
    #[test]
    fn adr_0039_tests_may_still_call_the_generic_constructor() {
        let root = PathBuf::from("/fixture-root");
        let mut files = adr_0039_clean_fixture(&root);
        files.push((
            root.join("bins/private-worker/tests/distill_hop_e2e.rs"),
            "fn p() { OpenAiCompatibleProvider::new(d, url, AlwaysFail, k, pol, r).unwrap() }\n"
                .to_string(),
        ));
        let problems = checked_resolver_dial_problems(&files, &root);
        assert!(problems.is_empty(), "{problems:?}");
    }

    /// The real repository passes the gate.
    #[test]
    fn adr_0039_real_repo_is_green() {
        assert_eq!(checked_resolver_dial_gate(&real_root()), Verdict::Pass);
    }

    /// §80.1 准入条件: the real repo, once T4.1 lands, must be green end to end (includes a
    /// real `cargo metadata` shell-out — this is the one test in this section that is not a
    /// pure-fixture unit test).
    #[test]
    fn g80_3_real_repo_is_green() {
        assert_eq!(g80_3_outbound_choke_point(&real_root()), Verdict::Pass);
    }

    /// Positive control: the exact fixture shape above, scanned in isolation, must itself be
    /// clean — proves a later red is the injected fault, not a matcher that is broken by
    /// construction.
    #[test]
    fn g80_3_clean_fixture_has_no_problems() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (
                root.join("crates/domain/src/egress.rs"),
                outbound_purpose_fixture(),
            ),
        ];
        assert!(g80_3_transport_and_registry_check(&files, &root).is_empty());
    }

    /// 注错 a (§83.4): a raw `reqwest::Client::new` written in some other crate must turn
    /// 判据1 red and name the offending file, alongside the legitimate one.
    #[test]
    fn g80_3_fault_raw_client_outside_http_rs_is_red_and_named() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (
                root.join("crates/domain/src/egress.rs"),
                outbound_purpose_fixture(),
            ),
            (
                root.join("crates/adapters/src/retrieval.rs"),
                "pub fn g() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(!problems.is_empty());
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/src/retrieval.rs"))
        );
    }

    /// 注错 a, bare-alias variant (§83.4): the exact loophole a real reviewer found —
    /// `use reqwest::Client; Client::new()` (also `Client::default()` and
    /// `ClientBuilder::new()`) — must be caught even though it never spells `reqwest::` at the
    /// call site. Before [`BARE_HTTP_CLIENT_NEEDLES`] this whole file scanned clean.
    #[test]
    fn g80_3_fault_bare_alias_raw_client_is_red_and_named() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (
                root.join("crates/domain/src/egress.rs"),
                outbound_purpose_fixture(),
            ),
            (
                root.join("crates/adapters/src/_tmp_review_probe.rs"),
                "use reqwest::Client;\n\
                 pub fn a() -> Client { Client::new() }\n\
                 pub fn b() -> Client { Client::default() }\n\
                 pub fn c() -> reqwest::ClientBuilder { ClientBuilder::new() }\n"
                    .to_string(),
            ),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/src/_tmp_review_probe.rs")),
            "bare `Client::new()`/`Client::default()`/`ClientBuilder::new()` must be caught: \
             {problems:?}"
        );
    }

    /// Negative control for [`is_bare_needle_word_start`]: a same-shaped but unrelated local
    /// type (`MyClient::new(`) must not be mistaken for `reqwest`/`hyper`'s `Client`.
    #[test]
    fn g80_3_bare_needle_does_not_match_unrelated_client_suffix_type() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (
                root.join("crates/domain/src/egress.rs"),
                outbound_purpose_fixture(),
            ),
            (
                root.join("crates/adapters/src/redis.rs"),
                "struct MyClient;\nimpl MyClient { fn f() -> Self { MyClient::new() } }\n"
                    .to_string(),
            ),
        ];
        assert!(g80_3_transport_and_registry_check(&files, &root).is_empty());
    }

    // -- §83.4 判据1, 注错 f: IntraCellResource string-constructor scan ---------------------

    /// Baseline: `IntraCellResource`'s real `impl` (closed enum, an `ALL` const, no fn
    /// converting a string to `Self`) must scan clean.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_clean_impl_is_empty() {
        let src = "pub enum IntraCellResource {\n    QDRANT_REST,\n}\n\
                   impl IntraCellResource {\n    \
                       pub const ALL: [IntraCellResource; 1] = [Self::QDRANT_REST];\n\
                   }\n";
        assert!(g80_3_no_string_to_resource_constructor_fn(src).is_empty());
    }

    /// Decisive blindness proof (the exact injection the review found): an arbitrarily-named
    /// associated fn — not `From::from`, not `FromStr::parse` — taking `&str` and returning
    /// `Self` inside `impl IntraCellResource` is exactly the raw-URL construction path 判据1
    /// forbids, and no fixed-name trybuild fixture would ever exercise it.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_flags_arbitrarily_named_fn() {
        let src = "pub enum IntraCellResource {\n    QDRANT_REST,\n}\n\
                   impl IntraCellResource {\n    \
                       pub fn from_url(_u: &str) -> Self {\n        Self::QDRANT_REST\n    }\n\
                   }\n";
        let problems = g80_3_no_string_to_resource_constructor_fn(src);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("from_url"));
    }

    /// The standard-trait spellings (`From<&str>`, `FromStr::parse` returning `Self`) must
    /// also be caught — this scan is meant to subsume, not merely supplement, what a
    /// `From<&str>`-shaped trybuild fixture would catch.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_flags_from_str_impl() {
        let src = "pub enum IntraCellResource {\n    QDRANT_REST,\n}\n\
                   impl From<&str> for IntraCellResource {\n    \
                       fn from(_s: &str) -> Self {\n        Self::QDRANT_REST\n    }\n\
                   }\n";
        let problems = g80_3_no_string_to_resource_constructor_fn(src);
        assert_eq!(problems.len(), 1);
    }

    /// Negative control for [`header_names_ident_exactly`]: an unrelated type whose name
    /// merely *contains* `IntraCellResource` as a substring (`IntraCellResourceRegistry`) must
    /// not be scanned as if it were `IntraCellResource`'s own impl — a real `&str -> Self`
    /// fn on that unrelated type is not a 判据1 violation.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_ignores_registry_type_name_collision() {
        let src = "impl IntraCellResourceRegistry {\n    \
                       pub fn from_str(_s: &str) -> Self {\n        todo!()\n    }\n\
                   }\n";
        assert!(g80_3_no_string_to_resource_constructor_fn(src).is_empty());
    }

    /// Negative control: an unrelated type in the *same file* with a legitimate
    /// `&str -> Result<Self, _>` (`CellCidr::from_str`, real production shape) must never be a
    /// false hit — the scan is scoped to `IntraCellResource`'s own impl blocks only.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_ignores_unrelated_type_from_str() {
        let src = "impl FromStr for CellCidr {\n    \
                       type Err = CellCidrParseError;\n    \
                       fn from_str(s: &str) -> Result<Self, Self::Err> {\n        todo!()\n    }\n\
                   }\n\
                   impl IntraCellResource {\n    \
                       pub const ALL: [IntraCellResource; 1] = [Self::QDRANT_REST];\n\
                   }\n";
        assert!(g80_3_no_string_to_resource_constructor_fn(src).is_empty());
    }

    /// The real `crates/infra-cell/src/resource.rs` must scan clean end to end.
    #[test]
    fn g80_3_no_string_to_resource_constructor_fn_real_file_is_clean() {
        let source = fs::read_to_string(real_root().join(INFRA_CELL_RESOURCE_RS)).unwrap();
        assert!(g80_3_no_string_to_resource_constructor_fn(&source).is_empty());
    }

    /// 注错 c (§83.4 判据3): a private-data variant that stops carrying `EgressPermit` (the
    /// spec's own "改成 generic NetworkPermit" wording, reproduced here as a bare variant —
    /// same red either way, since 判据3 checks the payload's *name*) must turn 判据3 red. Before
    /// this check existed, the module doc merely *claimed* trybuild fixtures covered this —
    /// they never did (none of `egress_topology_ui.rs`'s three fixtures touch `OutboundPurpose`
    /// at all), so this fault ran clean end to end.
    #[test]
    fn g80_3_fault_private_variant_without_permit_is_red() {
        let root = PathBuf::from("/fixture-root");
        let egress_src = outbound_purpose_fixture()
            .replace("RETRIEVAL_RERANK(EgressPermit),\n", "RETRIEVAL_RERANK,\n");
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (root.join("crates/domain/src/egress.rs"), egress_src),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("RETRIEVAL_RERANK") && p.contains("判据3")),
            "{problems:?}"
        );
    }

    /// 判据3 must also catch the payload being swapped for a *different* named type (the
    /// spec's literal "改成 generic NetworkPermit" wording), not just a bare variant.
    #[test]
    fn g80_3_fault_private_variant_wrong_payload_type_is_red() {
        let root = PathBuf::from("/fixture-root");
        let egress_src = outbound_purpose_fixture().replace(
            "USER_REASONING(EgressPermit),\n",
            "USER_REASONING(NetworkPermit),\n",
        );
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (root.join("crates/domain/src/egress.rs"), egress_src),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("USER_REASONING") && p.contains("NetworkPermit")),
            "{problems:?}"
        );
    }

    /// 注错 b (§83.4): `OutboundPurpose` growing an unregistered variant must turn 判据2 red.
    #[test]
    fn g80_3_fault_unregistered_purpose_variant_is_red() {
        let root = PathBuf::from("/fixture-root");
        let mut egress_src = outbound_purpose_fixture();
        egress_src = egress_src.replace(
            "DEADMAN_HEALTHCHECK,\n",
            "DEADMAN_HEALTHCHECK,\n    MYSTERY_PROVIDER,\n",
        );
        let files = vec![
            (
                root.join("crates/infra-network/src/http.rs"),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (root.join("crates/domain/src/egress.rs"), egress_src),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(problems.iter().any(|p| p.contains("MYSTERY_PROVIDER")));
    }

    /// 注错 0a (§83.4): deleting `infra-network/src/http.rs` must flip the positive sentinel
    /// red, even when `cargo metadata` still (on paper) lists the crate as a member.
    #[test]
    fn g80_3_sentinel_flags_deleted_http_rs() {
        let tmp = fresh_tmp("g80-3-deleted-http-rs");
        fs::create_dir_all(tmp.join("crates/infra-network/src")).unwrap();
        fs::write(tmp.join("crates/infra-network/Cargo.toml"), "").unwrap();
        // http.rs deliberately not written.
        let fake_metadata = r#"{"packages":[{"name":"humaux-infra-network"}]}"#;
        let problems = g80_3_workspace_sentinel(&tmp, Some(fake_metadata));
        assert!(problems.iter().any(|p| p.contains(INFRA_NETWORK_HTTP_RS)));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 0b (§83.4): removing the crate from `cargo metadata`'s member list (e.g. dropped
    /// from the workspace `Cargo.toml`) must flip the positive sentinel red even though the
    /// files themselves are still on disk.
    #[test]
    fn g80_3_sentinel_flags_missing_metadata_member() {
        let tmp = fresh_tmp("g80-3-missing-member");
        fs::create_dir_all(tmp.join("crates/infra-network/src")).unwrap();
        fs::write(tmp.join("crates/infra-network/Cargo.toml"), "").unwrap();
        fs::write(tmp.join(INFRA_NETWORK_HTTP_RS), "").unwrap();
        let fake_metadata = r#"{"packages":[{"name":"humaux-domain"}]}"#;
        let problems = g80_3_workspace_sentinel(&tmp, Some(fake_metadata));
        assert!(problems.iter().any(|p| p.contains("cargo metadata")));
        fs::remove_dir_all(&tmp).ok();
    }

    /// Regression pin for the `member_present` fix: `"humaux-infra-network"` appearing only as
    /// a *substring* of some other package's dependency listing (a plausible shape once a
    /// second crate path-depends on it by name) must NOT read as the crate itself being a
    /// workspace member — the bug this test would have caught: `.contains("humaux-infra-network")`
    /// over the raw JSON text stays true here even though no `packages[].name` equals it.
    #[test]
    fn g80_3_sentinel_member_present_requires_exact_name_not_substring() {
        let tmp = fresh_tmp("g80-3-substring-not-member");
        fs::create_dir_all(tmp.join("crates/infra-network/src")).unwrap();
        fs::write(tmp.join("crates/infra-network/Cargo.toml"), "").unwrap();
        fs::write(tmp.join(INFRA_NETWORK_HTTP_RS), "").unwrap();
        // No package here is literally named `humaux-infra-network` — it only appears inside
        // another package's dependency list (e.g. after the crate was dropped from `members`
        // but a stale path-dependency edge to it still resolves in the lockfile/graph).
        let fake_metadata = r#"{"packages":[{"name":"humaux-domain","dependencies":[]},
            {"name":"humaux-other","dependencies":[{"name":"humaux-infra-network"}]}]}"#;
        let problems = g80_3_workspace_sentinel(&tmp, Some(fake_metadata));
        assert!(
            problems.iter().any(|p| p.contains("cargo metadata")),
            "a dependency edge naming the crate must not be mistaken for workspace membership: \
             {problems:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// §83.4 判据0, full-path 注错 0a: with `crates/infra-network` already delivered, deleting
    /// the whole directory must flip [`g80_3_outbound_choke_point`] itself to `Fail`, not
    /// `NotApplicable` — the early-return this test replaces made deletion vacuously
    /// undetectable (判据1's raw-client scan finds nothing to complain about when there is
    /// nothing left to scan).
    #[test]
    fn g80_3_outbound_choke_point_fails_when_infra_egress_directory_is_deleted() {
        let tmp = fresh_tmp("g80-3-deleted-crate-full-path");
        fs::create_dir_all(&tmp).unwrap();
        // No `crates/infra-network` at all, and no workspace `Cargo.toml` for `cargo metadata`
        // to succeed against either — both read as absence, which is exactly the point: once
        // delivered, absence is a fault, never a legitimate "nothing to check" state.
        let mut expected = g80_3_workspace_sentinel(&tmp, None);
        expected.extend(g80_3_layer1_crates_sentinel(&tmp, None));
        assert_eq!(g80_3_outbound_choke_point(&tmp), Verdict::Fail(expected));
        fs::remove_dir_all(&tmp).ok();
    }

    /// Positive control for [`g80_3_manifest_dependency_check`]: the real repo's own `cargo
    /// metadata` document must show exactly one `reqwest`/`hyper`-dependent manifest.
    #[test]
    fn g80_3_manifest_dependency_check_real_repo_is_clean() {
        let root = real_root();
        // dep: subprocess(cargo) — positive-control real-repo cargo metadata read
        let output = Command::new("cargo")
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(&root)
            .output()
            .expect("cargo metadata");
        assert!(output.status.success());
        let metadata_json = String::from_utf8_lossy(&output.stdout);
        assert!(g80_3_manifest_dependency_check(&metadata_json, &root).is_empty());
    }

    /// 注错 a, manifest-level (§83.4 判据1 补充): a second workspace member declaring a
    /// `reqwest` dependency must be reported even before any source line calls it.
    #[test]
    fn g80_3_manifest_dependency_check_fault_second_crate_depends_on_reqwest() {
        let root = PathBuf::from("/fixture-root");
        let metadata_json = r#"{"packages":[
            {"name":"humaux-infra-network",
             "manifest_path":"/fixture-root/crates/infra-network/Cargo.toml",
             "dependencies":[{"name":"reqwest"}]},
            {"name":"humaux-adapters",
             "manifest_path":"/fixture-root/crates/adapters/Cargo.toml",
             "dependencies":[{"name":"reqwest"}]}
        ]}"#;
        let problems = g80_3_manifest_dependency_check(metadata_json, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/Cargo.toml")),
            "{problems:?}"
        );
    }

    /// Positive control for [`g80_3_infra_network_dependents_check`]: the real repo's own
    /// `cargo metadata` document must show exactly the two Layer 1 crates depending on
    /// `humaux-infra-network`.
    #[test]
    fn g80_3_infra_network_dependents_check_real_repo_is_clean() {
        let root = real_root();
        // dep: subprocess(cargo) — positive-control real-repo cargo metadata read
        let output = Command::new("cargo")
            .args(["metadata", "--no-deps", "--format-version", "1"])
            .current_dir(&root)
            .output()
            .expect("cargo metadata");
        assert!(output.status.success());
        let metadata_json = String::from_utf8_lossy(&output.stdout);
        assert!(g80_3_infra_network_dependents_check(&metadata_json, &root).is_empty());
    }

    /// Decisive proof, reproducing the exact exploit the review found: a third crate
    /// (`humaux-adapters`) adding a path dependency on `humaux-infra-network` — to reach the
    /// `reqwest` re-export without ever listing `reqwest` itself — must be reported by this
    /// dependents-set check even though [`g80_3_manifest_dependency_check`] alone stays clean
    /// for it (it never lists `reqwest`/`hyper` directly).
    #[test]
    fn g80_3_infra_network_dependents_check_fault_third_crate_depends_on_infra_network() {
        let root = PathBuf::from("/fixture-root");
        let metadata_json = r#"{"packages":[
            {"name":"humaux-infra-egress",
             "manifest_path":"/fixture-root/crates/infra-egress/Cargo.toml",
             "dependencies":[{"name":"humaux-infra-network"}]},
            {"name":"humaux-infra-cell",
             "manifest_path":"/fixture-root/crates/infra-cell/Cargo.toml",
             "dependencies":[{"name":"humaux-infra-network"}]},
            {"name":"humaux-adapters",
             "manifest_path":"/fixture-root/crates/adapters/Cargo.toml",
             "dependencies":[{"name":"humaux-infra-network"}]}
        ]}"#;
        let problems = g80_3_infra_network_dependents_check(metadata_json, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/Cargo.toml")),
            "{problems:?}"
        );
    }

    /// §83.4 判据1, decisive proof (the exact injected-alias exploit the review found): `use
    /// humaux_infra_network::reqwest::Client as HttpClient; HttpClient::new()` must be caught —
    /// [`BARE_HTTP_CLIENT_NEEDLES`]'s word-boundary guard rejects the call site itself (the
    /// byte before `Client::new(` inside `HttpClient::new(` is `p`), but
    /// [`REQWEST_CLIENT_ALIAS_IMPORT_NEEDLES`] catches the import line regardless of the
    /// alias's chosen name.
    #[test]
    fn find_raw_http_client_calls_catches_renamed_alias_import_regardless_of_call_site() {
        let src = "use humaux_infra_network::reqwest::Client as HttpClient;\n\
                   pub fn injected_alias() -> HttpClient { HttpClient::new() }\n";
        assert_eq!(find_raw_http_client_calls(src).len(), 1);
    }

    // ============================================================================
    // ADR-0003 / §83.4 Layer 1B: intra-cell-resource-registry checks + the two注错 tests the
    // task explicitly names — (a) adapters constructing `reqwest::Client` directly, (b) Qdrant
    // sneaking into `external-egress-registry`. (c) ("`IntraCellResource` accepts a raw URL")
    // is a compile-time property, not a source-scan one — proved by
    // `crates/infra-cell/tests/intra_cell_topology_ui.rs`'s `trybuild` fixture instead.
    // ============================================================================

    /// The clean fixture enumerates exactly the registry's variants — derived from
    /// [`INTRA_CELL_RESOURCE_REGISTRY`] so a registry addition (RETRIEVAL_EMBEDDING_RPC /
    /// PRIVATE_INFERENCE_RPC landed with the Distill/embedding hops) cannot leave this fixture
    /// stale and red for an unrelated card.
    fn intra_cell_resource_fixture() -> String {
        let mut src = String::from("pub enum IntraCellResource {\n");
        for variant in INTRA_CELL_RESOURCE_REGISTRY {
            src.push_str("    ");
            src.push_str(variant);
            src.push_str(",\n");
        }
        src.push_str("}\n");
        src
    }

    #[test]
    fn g80_3_intra_cell_registry_clean_fixture_has_no_problems() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![(
            root.join(INFRA_CELL_RESOURCE_RS),
            intra_cell_resource_fixture(),
        )];
        assert!(g80_3_intra_cell_registry_check(&files, &root).is_empty());
    }

    /// ADR-0003 判据1 sibling of 注错 b: `IntraCellResource` growing an unregistered variant
    /// must turn this check red, same shape [`g80_3_fault_unregistered_purpose_variant_is_red`]
    /// already proves for `OutboundPurpose`.
    #[test]
    fn g80_3_intra_cell_registry_fault_unregistered_resource_is_red() {
        let root = PathBuf::from("/fixture-root");
        let src = intra_cell_resource_fixture()
            .replace("QDRANT_REST,\n", "QDRANT_REST,\n    MYSTERY_RESOURCE,\n");
        let files = vec![(root.join(INFRA_CELL_RESOURCE_RS), src)];
        let problems = g80_3_intra_cell_registry_check(&files, &root);
        assert!(problems.iter().any(|p| p.contains("MYSTERY_RESOURCE")));
    }

    /// 注错 (a) (task item, source-level): a raw `reqwest::Client::new` written directly inside
    /// `adapters/src/qdrant.rs` — the exact file ADR-0003 wires to `IntraCellHttpTransport`
    /// instead of a raw client — must turn 判据1 red and name that file. Same mechanism
    /// [`g80_3_fault_raw_client_outside_http_rs_is_red_and_named`] already proves generically,
    /// pinned here against the specific file/crate the task calls out by name.
    #[test]
    fn g80_3_fault_adapters_qdrant_constructs_raw_reqwest_client_is_red() {
        let root = PathBuf::from("/fixture-root");
        let files = vec![
            (
                root.join(INFRA_NETWORK_HTTP_RS),
                "pub fn f() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
            (
                root.join("crates/domain/src/egress.rs"),
                outbound_purpose_fixture(),
            ),
            (
                root.join("crates/adapters/src/qdrant.rs"),
                "pub fn sneaky() -> reqwest::Client { reqwest::Client::new() }\n".to_string(),
            ),
        ];
        let problems = g80_3_transport_and_registry_check(&files, &root);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("crates/adapters/src/qdrant.rs")),
            "{problems:?}"
        );
    }

    /// 注错 (b) (task item): Qdrant sneaking into `external-egress-registry` while still
    /// present in `intra-cell-resource-registry` — the coordinated double-registration
    /// [`intra_cell_registry_disjoint_from_external`] exists to catch, which neither registry's
    /// own single-sided set-equality check (判据2 / this module's intra-cell sibling) can see on
    /// its own (both would independently read PASS if `OutboundPurpose`/`EXTERNAL_EGRESS_
    /// REGISTRY` were edited together to add the same name `IntraCellResource` already has).
    #[test]
    fn g80_3_fault_qdrant_added_to_external_egress_registry_is_red() {
        let external_with_qdrant: Vec<&str> = EXTERNAL_EGRESS_REGISTRY
            .iter()
            .copied()
            .chain(std::iter::once("QDRANT_REST"))
            .collect();
        let problems = intra_cell_registry_disjoint_from_external(
            &external_with_qdrant,
            INTRA_CELL_RESOURCE_REGISTRY,
        );
        assert!(
            problems.iter().any(|p| p.contains("QDRANT_REST")),
            "{problems:?}"
        );
    }

    /// Positive control: the real workspace's two registries must in fact be disjoint today.
    #[test]
    fn g80_3_real_registries_are_disjoint() {
        assert!(
            intra_cell_registry_disjoint_from_external(
                EXTERNAL_EGRESS_REGISTRY,
                INTRA_CELL_RESOURCE_REGISTRY,
            )
            .is_empty()
        );
    }

    // -- §20#G20-2 / G80-39: online recall/context/continuity — zero static dependency on
    // any reasoning provider ----------------------------------------------------------------

    /// Standalone proof the matcher itself recognizes the needle text — independent of any
    /// file — since this rule has no legal permanent positive-hit fixture inside its own scan
    /// domain (see [`g20_2_no_hidden_generative_recall`]'s doc for why not).
    #[test]
    fn count_identifier_hits_word_boundary_and_comment_rules() {
        assert_eq!(
            count_identifier_hits(
                "let x = UserReasoningProvider::default();",
                "UserReasoningProvider",
                true
            ),
            1
        );
        assert_eq!(
            count_identifier_hits(
                "// UserReasoningProvider mentioned only in prose",
                "UserReasoningProvider",
                true
            ),
            0
        );
        // `UserReasoningProviderFactory` shares the needle as a prefix but is a different
        // identifier — next byte is still an ident byte, so with `require_right_boundary:
        // true` it must not count as a hit.
        assert_eq!(
            count_identifier_hits(
                "struct UserReasoningProviderFactory;",
                "UserReasoningProvider",
                true
            ),
            0
        );
    }

    /// Decisive: with `require_right_boundary: false`, `complete_structured` must count a
    /// call to `complete_structured_with_bounded_repair` — this is the exact real call site
    /// (`crates/adapters/src/byok.rs`) the old always-full-identifier matcher silently missed
    /// (0 hits under the pre-fix matcher; see [`FORBIDDEN_GENERATIVE_NEEDLES`]'s doc).
    #[test]
    fn count_identifier_hits_prefix_mode_catches_bounded_repair_call() {
        assert_eq!(
            count_identifier_hits(
                "rewrite::complete_structured_with_bounded_repair(req).await",
                "complete_structured",
                false
            ),
            1
        );
        // Same source, `require_right_boundary: true` (the old behavior) — 0 hits, proving
        // this is a genuine regression the prefix mode fixes, not a redundant belt.
        assert_eq!(
            count_identifier_hits(
                "rewrite::complete_structured_with_bounded_repair(req).await",
                "complete_structured",
                true
            ),
            0
        );
    }

    /// The `byok` module-path needle: catches an aliased re-export that names neither
    /// provider trait nor `complete_structured*` directly.
    #[test]
    fn count_identifier_hits_byok_needle() {
        assert_eq!(
            count_identifier_hits(
                "use humaux_adapters::byok::complete_structured_with_bounded_repair as rewrite;",
                "byok",
                true
            ),
            1
        );
        // The current repo's only pre-existing mention is prose in a `//!` doc comment —
        // must not count.
        assert_eq!(
            count_identifier_hits(
                "//! names either type and never imports `humaux_adapters::byok` or anything",
                "byok",
                true
            ),
            0
        );
    }

    /// Minimal, realistic fixture for the four §20.0 online-lane files; `retrieve_extra` is
    /// spliced into `application::retrieve`'s body to carry the injected fault in the tests
    /// below (empty string ⇒ the clean/green baseline).
    fn write_online_lane_fixture(tmp: &Path, retrieve_extra: &str) {
        for d in [
            "crates/application/src",
            "crates/domain/src",
            "crates/adapters/src",
        ] {
            fs::create_dir_all(tmp.join(d)).unwrap();
        }
        fs::write(
            tmp.join("crates/application/src/retrieve.rs"),
            format!(
                "//! application::retrieve — pure orchestration entry point (§20.0).\n\
                 pub enum QueryTransform {{ Deterministic }}\n\
                 pub fn resolve_profile() -> QueryTransform {{ QueryTransform::Deterministic }}\n\
                 {retrieve_extra}"
            ),
        )
        .unwrap();
        fs::write(
            tmp.join("crates/application/src/continuity.rs"),
            "//! application::continuity — placeholder.\n",
        )
        .unwrap();
        fs::write(
            tmp.join("crates/domain/src/context.rs"),
            "//! domain::context — placeholder (§25.4 Mandatory Context Lane).\n",
        )
        .unwrap();
        fs::write(
            tmp.join("crates/adapters/src/retrieve.rs"),
            "//! adapters::retrieve — recall_with_overlay (§15.5) lives here.\n\
             pub fn recall_with_overlay() {}\n",
        )
        .unwrap();
    }

    /// Positive control: the real workspace's online-lane files are clean today.
    #[test]
    fn g20_2_real_repo_is_green() {
        assert_eq!(
            g20_2_no_hidden_generative_recall(&real_root()),
            Verdict::Pass
        );
    }

    #[test]
    fn g20_2_clean_fixture_is_green() {
        let tmp = fresh_tmp("g20-2-green");
        write_online_lane_fixture(&tmp, "");
        assert_eq!(g20_2_no_hidden_generative_recall(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 a: a bare `dyn UserReasoningProvider` reference sneaks into the orchestration
    /// entry point ⇒ static dependency 0→1 ⇒ red, and the offending file is named.
    #[test]
    fn g20_2_fault_user_reasoning_provider_reference_is_red() {
        let tmp = fresh_tmp("g20-2-user");
        write_online_lane_fixture(
            &tmp,
            "fn sneaky(p: &dyn UserReasoningProvider) { let _ = p; }\n",
        );
        match g20_2_no_hidden_generative_recall(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines
                    .iter()
                    .any(|l| l.contains("UserReasoningProvider") && l.contains("retrieve.rs")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// Same shape, `PublicReasoningProvider` half — proves both needles are live, not just
    /// whichever one happens to have a real trait definition in the workspace today.
    #[test]
    fn g20_2_fault_public_reasoning_provider_reference_is_red() {
        let tmp = fresh_tmp("g20-2-public");
        write_online_lane_fixture(
            &tmp,
            "fn sneaky(p: &dyn PublicReasoningProvider) { let _ = p; }\n",
        );
        match g20_2_no_hidden_generative_recall(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines.iter().any(|l| l.contains("PublicReasoningProvider")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (task item 3, decisive acceptance): insert one `complete_structured()` generative
    /// query rewrite call ahead of recall ⇒ static dependency 0→1 on both the trait name and
    /// the method name ⇒ red. This is the exact injection the spec's own G20-2/G80-39 text
    /// names ("在 recall 前插一个 complete_structured() query rewrite").
    #[test]
    fn g20_2_fault_complete_structured_call_before_recall_is_red() {
        let tmp = fresh_tmp("g20-2-rewrite");
        write_online_lane_fixture(
            &tmp,
            "async fn recall(provider: &dyn UserReasoningProvider) {\n    \
             let _rewritten = provider.complete_structured().await;\n    \
             // then the real deterministic recall would run\n\
             }\n",
        );
        match g20_2_no_hidden_generative_recall(&tmp) {
            Verdict::Fail(lines) => {
                assert!(
                    lines.iter().any(|l| l.contains("complete_structured")),
                    "{lines:?}"
                );
                assert!(
                    lines.iter().any(|l| l.contains("UserReasoningProvider")),
                    "{lines:?}"
                );
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (real-world repro that exposed the blocker this fix closes): the aliased-import
    /// shape from the spec's own `byok.rs` — `complete_structured_with_bounded_repair` reached
    /// through a `use ... as rewrite;` re-export, called from a `pub` fn that never spells out
    /// `UserReasoningProvider` at the call site at all. Under the pre-fix matcher (full-
    /// identifier `complete_structured` + no `byok` needle) this fixture stayed
    /// `Verdict::Pass`; it must now be red on both needles.
    #[test]
    fn g20_2_fault_bounded_repair_via_byok_alias_is_red() {
        let tmp = fresh_tmp("g20-2-byok-alias");
        write_online_lane_fixture(
            &tmp,
            "use humaux_adapters::byok::complete_structured_with_bounded_repair as rewrite;\n\
             pub async fn sneaky_rewrite() {\n    \
             let _ = rewrite(Default::default()).await;\n\
             }\n",
        );
        match g20_2_no_hidden_generative_recall(&tmp) {
            Verdict::Fail(lines) => {
                assert!(
                    lines.iter().any(|l| l.contains("complete_structured")),
                    "{lines:?}"
                );
                assert!(lines.iter().any(|l| l.contains("byok")), "{lines:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// A scan domain where every listed file is either absent or a bare T0.x placeholder must
    /// report `NotApplicable`, not a vacuous `Pass` — there is no real call graph to have
    /// cleared the rule against yet (see [`g20_2_no_hidden_generative_recall`]'s doc).
    #[test]
    fn g20_2_all_placeholder_scan_domain_is_not_applicable() {
        let tmp = fresh_tmp("g20-2-na");
        for d in [
            "crates/application/src",
            "crates/domain/src",
            "crates/adapters/src",
        ] {
            fs::create_dir_all(tmp.join(d)).unwrap();
        }
        for rel in [
            "crates/application/src/retrieve.rs",
            "crates/application/src/continuity.rs",
            "crates/domain/src/context.rs",
            "crates/adapters/src/retrieve.rs",
        ] {
            fs::write(tmp.join(rel), "//! 占位模块（T0.x 任务填充）。\n").unwrap();
        }
        match g20_2_no_hidden_generative_recall(&tmp) {
            Verdict::NotApplicable(missing) => {
                assert!(missing.contains("retrieve.rs"), "{missing}");
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §11.8 / §22.5: classify() sole-construction-point sites, path-qualified ----------

    /// Positive control against the real repo: both known sites have landed
    /// (`domain::consolidate::classify` from an earlier wave, `retrieval::completeness::
    /// classify` from this task) and the workspace-wide total matches — no stray third
    /// `fn classify(` exists anywhere else.
    #[test]
    fn classify_sole_construction_passes_on_real_repo() {
        assert_eq!(
            g11_8_classify_sole_construction_point(&real_root()),
            Verdict::Pass
        );
    }

    fn write_classify_sites_fixture(
        tmp: &Path,
        consolidate_count: usize,
        completeness_count: usize,
    ) {
        let domain_dir = tmp.join("crates/domain/src");
        let retrieval_dir = tmp.join("crates/retrieval/src");
        fs::create_dir_all(&domain_dir).unwrap();
        fs::create_dir_all(&retrieval_dir).unwrap();
        let mut consolidate_src = String::new();
        for i in 0..consolidate_count {
            consolidate_src.push_str(&format!("pub fn classify(id: u64) -> u64 {{ id + {i} }}\n"));
        }
        let mut completeness_src = String::new();
        for i in 0..completeness_count {
            completeness_src.push_str(&format!(
                "pub(crate) fn classify(x: u64) -> u64 {{ x + {i} }}\n"
            ));
        }
        fs::write(domain_dir.join("consolidate.rs"), consolidate_src).unwrap();
        fs::write(retrieval_dir.join("completeness.rs"), completeness_src).unwrap();
    }

    #[test]
    fn classify_sole_construction_passes_with_exactly_one_each() {
        let tmp = fresh_tmp("g11-8-green");
        write_classify_sites_fixture(&tmp, 1, 1);
        assert_eq!(g11_8_classify_sole_construction_point(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (this task's own finding, decisive acceptance): a second `fn classify(` landing
    /// in `retrieval::completeness.rs` alongside the first (e.g. a copy-paste duplicate) ⇒
    /// that file's own count is 2 != 1 ⇒ red. This is exactly the regression a bare
    /// workspace-wide `== 1` could no longer detect once two legitimate sites coexist — the
    /// per-path assertion is what makes it observable again.
    #[test]
    fn classify_sole_construction_fault_duplicate_in_completeness_is_red() {
        let tmp = fresh_tmp("g11-8-red-duplicate");
        write_classify_sites_fixture(&tmp, 1, 2);
        match g11_8_classify_sole_construction_point(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines
                    .iter()
                    .any(|l| l.contains("completeness.rs") && l.contains("found 2")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (stray-site regression): a third, unlisted `fn classify(` appearing anywhere else
    /// in the workspace must still be red even though both known sites individually hold
    /// exactly 1 — this is the cross-check the workspace-wide total/`applicable` comparison
    /// exists for.
    #[test]
    fn classify_sole_construction_fault_stray_third_site_is_red() {
        let tmp = fresh_tmp("g11-8-red-stray");
        write_classify_sites_fixture(&tmp, 1, 1);
        let stray_dir = tmp.join("crates/retrieval/src");
        fs::write(
            stray_dir.join("stray.rs"),
            "pub fn classify(x: u64) -> u64 { x }\n",
        )
        .unwrap();
        match g11_8_classify_sole_construction_point(&tmp) {
            Verdict::Fail(lines) => assert!(
                lines.iter().any(|l| l.contains("workspace-wide")),
                "{lines:?}"
            ),
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §23.1② G23-1: LedgerCounts field set is exactly 6 --------------------------------

    /// Positive control against the real repo: `ledger::close` has landed (this task), and
    /// `LedgerCounts`'s six fields must match §23.1②'s frozen set exactly.
    #[test]
    fn ledger_counts_six_fields_passes_on_real_repo() {
        assert_eq!(
            g23_1_ledger_counts_exactly_six_fields(&real_root()),
            Verdict::Pass
        );
    }

    fn write_ledger_counts_fixture(tmp: &Path, body: &str) {
        let dir = tmp.join("crates/retrieval/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("completeness.rs"),
            format!("pub struct LedgerCounts {{\n{body}}}\n"),
        )
        .unwrap();
    }

    #[test]
    fn ledger_counts_six_fields_passes_with_exactly_six() {
        let tmp = fresh_tmp("g23-1-green");
        write_ledger_counts_fixture(
            &tmp,
            "    expected: u64,\n    done: u64,\n    deleted: u64,\n    skipped: u64,\n    \
             open_gaps: u64,\n    pending: u64,\n",
        );
        assert_eq!(g23_1_ledger_counts_exactly_six_fields(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (decisive acceptance, §23.1②'s own worked example): adding a 7th `visible: u64`
    /// field ⇒ `7 != 6` ⇒ red. This is the exact regression §23.1② names as the one that
    /// would let G23-2's two injections stop being observable (numerator folded back into the
    /// ledger struct, all counts taken from PostgreSQL only).
    #[test]
    fn ledger_counts_fault_seven_fields_with_visible_is_red() {
        let tmp = fresh_tmp("g23-1-red");
        write_ledger_counts_fixture(
            &tmp,
            "    expected: u64,\n    done: u64,\n    deleted: u64,\n    skipped: u64,\n    \
             open_gaps: u64,\n    pending: u64,\n    visible: u64,\n",
        );
        match g23_1_ledger_counts_exactly_six_fields(&tmp) {
            Verdict::Fail(lines) => {
                assert!(lines.iter().any(|l| l.contains('7')), "{lines:?}");
                assert!(lines.iter().any(|l| l.contains("visible")), "{lines:?}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn ledger_counts_not_applicable_when_type_absent() {
        let tmp = fresh_tmp("g23-1-na");
        fs::create_dir_all(&tmp).unwrap();
        assert_eq!(
            g23_1_ledger_counts_exactly_six_fields(&tmp),
            Verdict::NotApplicable(
                "retrieval::completeness::LedgerCounts (§22.5, ledger::close 尚未交付)".to_string()
            )
        );
        fs::remove_dir_all(&tmp).ok();
    }
    /// §22.5 A1 闸：真仓库必须绿（算式只在 domain::ledger 一处）。
    #[test]
    fn g22_5_a1_real_repo_is_green() {
        assert_eq!(g22_5_a1_sole_implementation(&real_root()), Verdict::Pass);
    }

    /// 注错 a：把算式抄回第二个 crate ⇒ 红并点名文件。
    #[test]
    fn g22_5_a1_fault_second_copy_elsewhere_is_red() {
        let tmp = fresh_tmp("a1-second-copy");
        write_a1_fixture(&tmp, "pub fn a1_holds(e: u64) -> bool { e == e }");
        fs::create_dir_all(tmp.join("crates/projection/src")).unwrap();
        fs::write(
            tmp.join("crates/projection/src/stream.rs"),
            "fn advance() -> bool { expected == done + open_gaps + pending }\n",
        )
        .unwrap();
        match g22_5_a1_sole_implementation(&tmp) {
            Verdict::Fail(lines) => {
                assert!(
                    lines
                        .iter()
                        .any(|l| l.contains("crates/projection/src/stream.rs"))
                )
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// 注错 b：算式的家被掏空（定义没了）⇒ 哨兵必须红，否则整道闸静默失明。
    #[test]
    fn g22_5_a1_fault_dead_home_sentinel_is_red() {
        let tmp = fresh_tmp("a1-dead-home");
        write_a1_fixture(&tmp, "// the judgment used to live here\n");
        match g22_5_a1_sole_implementation(&tmp) {
            Verdict::Fail(lines) => assert!(lines.iter().any(|l| l.contains("sentinel"))),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    /// 注错 c：家里改名（`a1_holds_renamed`）——子串仍含 `a1_holds`，
    /// 没有词边界的匹配会漏掉它。本闸第一版正是这么漏的。
    #[test]
    fn g22_5_a1_fault_renamed_home_fn_is_red() {
        let tmp = fresh_tmp("a1-renamed-home");
        write_a1_fixture(&tmp, "pub fn a1_holds_renamed(e: u64) -> bool { e == e }");
        match g22_5_a1_sole_implementation(&tmp) {
            Verdict::Fail(lines) => assert!(lines.iter().any(|l| l.contains("sentinel"))),
            other => panic!("expected Fail (word-boundary), got {other:?}"),
        }
    }

    fn write_a1_fixture(tmp: &Path, home_body: &str) {
        fs::create_dir_all(tmp.join("crates/domain/src")).unwrap();
        fs::write(tmp.join("crates/domain/src/ledger.rs"), home_body).unwrap();
    }

    // ========================================================================================
    // §19 Provider Plane Architecture Gate — 7 checks
    // ========================================================================================

    /// Positive/negative pin for [`provider_plane_dashscope_sdk_hits`]'s own core claim: the
    /// bare business-data string `"dashscope"` (a `ProviderId` value, legitimate everywhere)
    /// must NOT count, while the real SDK-shape needles (PascalCase type name, snake_case
    /// name fragment, literal API host) must.
    #[test]
    fn provider_plane_dashscope_sdk_hits_distinguishes_data_from_sdk_surface() {
        assert_eq!(
            provider_plane_dashscope_sdk_hits("let p = ProviderId(\"dashscope\".into());"),
            0,
            "the bare provider_id string value must not count as SDK-surface"
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits("pub struct DashscopeEmbeddingProvider {}"),
            1
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits("pub fn map_dashscope_status(s: u16) {}"),
            1
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits(
                "const URL: &str = \"https://dashscope.aliyuncs.com/v1\";"
            ),
            1
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits("// mentions Dashscope only in a comment"),
            0,
            "comment lines are skipped, same discipline as count_identifier_hits"
        );
        // §19 review: the original three-needle set scored 0 on exactly this shape — a Rust
        // path import of the SDK crate — despite it being the rule's own named example
        // ("Domain does not import DashScope SDK").
        assert_eq!(
            provider_plane_dashscope_sdk_hits("use dashscope::Client;"),
            1,
            "a bare `use dashscope::...` import must count as an SDK hit"
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits("dashscope::embeddings::create(&req).await?;"),
            1
        );
        assert_eq!(
            provider_plane_dashscope_sdk_hits("let p = ProviderId(\"dashscope\".into());"),
            0,
            "the `dashscope::` needle must still not collide with the bare business-data \
             string — no `::` follows a string literal's contents"
        );
    }

    // -- Gate 1/7: Domain does not import DashScope SDK -------------------------------------

    #[test]
    fn provider_plane_gate1_real_repo_is_clean() {
        assert_eq!(
            provider_plane_gate1_domain_no_dashscope_sdk(&real_root()),
            Verdict::Pass
        );
    }

    /// 注错: inject a `Dashscope`-named type into `crates/domain/src/` → red.
    #[test]
    fn provider_plane_gate1_fault_dashscope_type_in_domain_is_red() {
        let tmp = fresh_tmp("pp-gate1-fault");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("leak.rs"),
            "pub struct DashscopeEmbeddingProvider;\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate1_domain_no_dashscope_sdk(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§19 review): a bare `use dashscope::...` import — the rule's own named example,
    /// and the shape the original three-needle set missed entirely (0 hits) — must also be
    /// caught.
    #[test]
    fn provider_plane_gate1_fault_dashscope_path_import_in_domain_is_red() {
        let tmp = fresh_tmp("pp-gate1-fault-import");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("leak.rs"), "use dashscope::Client;\n").unwrap();
        assert!(matches!(
            provider_plane_gate1_domain_no_dashscope_sdk(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照: the same domain dir with only the legitimate business-data string is green —
    /// proves the fault above is the SDK-shape needle, not any mention of the word.
    #[test]
    fn provider_plane_gate1_business_data_string_alone_is_green() {
        let tmp = fresh_tmp("pp-gate1-green");
        let dir = tmp.join("crates/domain/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ok.rs"), "let provider = \"dashscope\";\n").unwrap();
        assert_eq!(
            provider_plane_gate1_domain_no_dashscope_sdk(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    // -- Gate 2/7: Application does not call DashScope directly -----------------------------

    #[test]
    fn provider_plane_gate2_real_repo_is_clean() {
        assert_eq!(
            provider_plane_gate2_application_no_dashscope_direct(&real_root()),
            Verdict::Pass
        );
    }

    /// 注错: inject a direct DashScope call into `crates/application/src/` → red.
    #[test]
    fn provider_plane_gate2_fault_dashscope_call_in_application_is_red() {
        let tmp = fresh_tmp("pp-gate2-fault");
        let dir = tmp.join("crates/application/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("leak.rs"),
            "fn go() { let _ = map_dashscope_status(200); }\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate2_application_no_dashscope_direct(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    // -- Gate 3/7: Only retrieval-provider/adapters may import provider client --------------

    #[test]
    fn provider_plane_gate3_real_repo_is_clean() {
        assert_eq!(
            provider_plane_gate3_only_adapters_import_provider_client(&real_root()),
            Verdict::Pass
        );
    }

    /// 注错: a second importer of the DashScope SDK surface outside retrieval-provider/
    /// adapters (here: `crates/retrieval-provider/src/router.rs`, a sibling module in the
    /// *same* crate — proves the home is the `adapters.rs` file, not the whole crate) → red.
    #[test]
    fn provider_plane_gate3_fault_second_importer_outside_adapters_is_red() {
        let tmp = fresh_tmp("pp-gate3-fault");
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("router.rs"),
            "pub struct DashscopeEmbeddingProvider;\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate3_only_adapters_import_provider_client(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照: the identical SDK-shape identifier inside the real home
    /// (`crates/retrieval-provider/src/adapters.rs`) is green — proves the fault above fires
    /// on *location*, not on the identifier's mere presence anywhere.
    #[test]
    fn provider_plane_gate3_same_identifier_inside_home_is_green() {
        let tmp = fresh_tmp("pp-gate3-green");
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("adapters.rs"),
            "pub struct DashscopeEmbeddingProvider;\n",
        )
        .unwrap();
        assert_eq!(
            provider_plane_gate3_only_adapters_import_provider_client(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照: the adapter's own `tests/` directory is exempt too (§19's "adapters" reading
    /// includes the module's own test surface, module doc).
    #[test]
    fn provider_plane_gate3_own_tests_dir_is_exempt() {
        let tmp = fresh_tmp("pp-gate3-tests-green");
        let dir = tmp.join("crates/retrieval-provider/tests");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("dashscope_live_smoke.rs"),
            "pub struct DashscopeEmbeddingProvider;\n",
        )
        .unwrap();
        assert_eq!(
            provider_plane_gate3_only_adapters_import_provider_client(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    // -- Gates 4-6/7: shared companion-check helper ------------------------------------------

    /// `body` is prefixed with an `ExternalCall` mention — matching the real adapter's own
    /// `use humaux_domain::egress::{ExternalCall, ...}` — since [`provider_plane_external_call_sites`]
    /// now scopes its `.call(`/`::call(` scan to files that name the trait (§19 review: no
    /// longer keyed on the one field name `self.transport`).
    fn write_adapter_home(tmp: &Path, body: &str) {
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        let full = format!("use humaux_domain::egress::ExternalCall;\n{body}");
        fs::write(dir.join("adapters.rs"), full).unwrap();
    }

    #[test]
    fn provider_plane_gate4_real_repo_egress_is_wired() {
        // Unlike 5/7 and 6/7, this one has a real, already-wired target (T7.1's adapter) —
        // pin it as a real `Pass`, not `NotApplicable`, so a regression that un-wires
        // `egress::authorize` from the real call site is caught, not swallowed.
        assert_eq!(
            provider_plane_gate4_egress_policy_before_external_call(&real_root()),
            Verdict::Pass
        );
    }

    /// §19 review: a real, non-placeholder home with the `ExternalCall` trait named but zero
    /// `.call(`/`::call(` hits ⇒ `NotApplicable` (needle found nothing to require), never the
    /// old vacuous `Pass` a caller could not distinguish from "needle drifted and missed a
    /// real call site".
    #[test]
    fn provider_plane_gate456_no_call_site_is_not_applicable() {
        let tmp = fresh_tmp("pp-gate456-no-call-site");
        write_adapter_home(&tmp, "pub struct Real;\nfn placeholder_only() {}\n");
        for check in [
            provider_plane_gate4_egress_policy_before_external_call,
            provider_plane_gate5_ledger_entry_per_external_call,
            provider_plane_gate6_admission_participation,
        ] {
            assert!(matches!(check(&tmp), Verdict::NotApplicable(_)));
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// §19 review: renaming the field the call is made through (`self.transport` →
    /// `self.http_client`) must not fail the call-site scan open — the old needle
    /// (`".transport.call("`) depended on that exact field name.
    #[test]
    fn provider_plane_gate4_call_site_detected_through_a_renamed_field() {
        let tmp = fresh_tmp("pp-gate4-renamed-field");
        write_adapter_home(
            &tmp,
            "fn embed() {\n    let permit = egress::authorize(x, y, z)?;\n    self.http_client.call(&permit, &payload);\n}\n",
        );
        assert_eq!(
            provider_plane_gate4_egress_policy_before_external_call(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// §19 review: a second file in the crate (not `adapters.rs`) carrying its own external
    /// call site must be scanned too, not silently skipped.
    #[test]
    fn provider_plane_gate4_call_site_in_a_second_crate_file_is_scanned() {
        let tmp = fresh_tmp("pp-gate4-second-file");
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("rerank_adapter.rs"),
            "use humaux_domain::egress::ExternalCall;\nfn rerank() {\n    let permit = egress::authorize(x, y, z)?;\n    self.transport.call(&permit, &payload);\n}\n",
        )
        .unwrap();
        assert_eq!(
            provider_plane_gate4_egress_policy_before_external_call(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: absent adapters.rs ⇒ `NotApplicable`, not a vacuous `Pass`.
    #[test]
    fn provider_plane_gate456_absent_home_is_not_applicable() {
        let tmp = fresh_tmp("pp-gate456-absent");
        fs::create_dir_all(&tmp).unwrap();
        for check in [
            provider_plane_gate4_egress_policy_before_external_call,
            provider_plane_gate5_ledger_entry_per_external_call,
            provider_plane_gate6_admission_participation,
        ] {
            assert!(matches!(check(&tmp), Verdict::NotApplicable(_)));
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a T0.x placeholder home ⇒ `NotApplicable`, not `Pass` (no real call graph to
    /// judge yet — same precondition [`g20_2_no_hidden_generative_recall`] applies).
    #[test]
    fn provider_plane_gate456_placeholder_home_is_not_applicable() {
        let tmp = fresh_tmp("pp-gate456-placeholder");
        write_adapter_home(&tmp, "//! retrieval-provider::adapters — 占位模块\n");
        for check in [
            provider_plane_gate4_egress_policy_before_external_call,
            provider_plane_gate5_ledger_entry_per_external_call,
            provider_plane_gate6_admission_participation,
        ] {
            assert!(matches!(check(&tmp), Verdict::NotApplicable(_)));
        }
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错: a real (non-placeholder) home with a call site but zero companion evidence at
    /// all ⇒ `NotApplicable` (honest "not yet wired"), never a silent `Pass`.
    #[test]
    fn provider_plane_gate4_fault_call_site_without_authorize_is_not_applicable() {
        let tmp = fresh_tmp("pp-gate4-fault");
        write_adapter_home(
            &tmp,
            "pub struct Real;\nfn embed() { self.transport.call(&permit, &payload); }\n",
        );
        assert!(matches!(
            provider_plane_gate4_egress_policy_before_external_call(&tmp),
            Verdict::NotApplicable(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 (红转绿): the identical fixture, with a real (non-comment) `authorize(` call
    /// added, goes green.
    #[test]
    fn provider_plane_gate4_fault_fixed_by_adding_authorize_call() {
        let tmp = fresh_tmp("pp-gate4-fixed");
        write_adapter_home(
            &tmp,
            "pub struct Real;\nfn embed() {\n    let permit = egress::authorize(x, y, z)?;\n    self.transport.call(&permit, &payload);\n}\n",
        );
        assert_eq!(
            provider_plane_gate4_egress_policy_before_external_call(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (伪修复 shape): the companion is named only in a comment, never in real code ⇒
    /// `Fail`, not `NotApplicable` and not `Pass` — this is the reachable red state 4/5/6
    /// each need (§80.1 "一道闸没有注错红转绿记录就不算存在").
    #[test]
    fn provider_plane_gate5_fault_ledger_mentioned_only_in_comment_is_red() {
        let tmp = fresh_tmp("pp-gate5-fault-comment");
        write_adapter_home(
            &tmp,
            "// TODO: write a ModelCallLedger entry here eventually\nfn embed() { self.transport.call(&permit, &payload); }\n",
        );
        assert!(matches!(
            provider_plane_gate5_ledger_entry_per_external_call(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 (红转绿): the identical fixture with a real (non-comment) ModelCallLedger
    /// reference goes green.
    #[test]
    fn provider_plane_gate5_fixed_by_real_ledger_reference() {
        let tmp = fresh_tmp("pp-gate5-fixed");
        write_adapter_home(
            &tmp,
            "fn embed() {\n    model_call_ledger::reserve_call(&pool, &req)?;\n    self.transport.call(&permit, &payload);\n}\n",
        );
        assert_eq!(
            provider_plane_gate5_ledger_entry_per_external_call(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§19 review): a trailing `//` comment on a real code line was previously counted
    /// as a real hit (`count_code_line_hits` only skipped *leading* `//` lines) — must not be.
    #[test]
    fn provider_plane_gate5_fault_ledger_mentioned_only_in_trailing_comment_is_red() {
        let tmp = fresh_tmp("pp-gate5-fault-trailing-comment");
        write_adapter_home(
            &tmp,
            "fn embed() { self.transport.call(&permit, &payload); } // model_call_ledger later\n",
        );
        assert!(matches!(
            provider_plane_gate5_ledger_entry_per_external_call(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§19 review): same shape, inside a `/* */` block comment.
    #[test]
    fn provider_plane_gate5_fault_ledger_mentioned_only_in_block_comment_is_red() {
        let tmp = fresh_tmp("pp-gate5-fault-block-comment");
        write_adapter_home(
            &tmp,
            "/* model_call_ledger wiring TODO */\nfn embed() { self.transport.call(&permit, &payload); }\n",
        );
        assert!(matches!(
            provider_plane_gate5_ledger_entry_per_external_call(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn provider_plane_gate5_real_repo_is_wired() {
        // `adapters.rs::embed` now calls `model_call_ledger::reserve_call`/`finalize_call`
        // around its external call — pin flipped from `NotApplicable` to `Pass` (this test's
        // own doc comment did exactly what it said: it started failing when the wiring
        // landed, telling this agent to update the pin instead of the gate silently staying
        // green either way).
        assert_eq!(
            provider_plane_gate5_ledger_entry_per_external_call(&real_root()),
            Verdict::Pass
        );
    }

    /// Same 伪修复 shape as gate 5/7, for admission control.
    #[test]
    fn provider_plane_gate6_fault_admission_mentioned_only_in_comment_is_red() {
        let tmp = fresh_tmp("pp-gate6-fault-comment");
        write_adapter_home(
            &tmp,
            "// should call admission::decide( before sending\nfn embed() { self.transport.call(&permit, &payload); }\n",
        );
        assert!(matches!(
            provider_plane_gate6_admission_participation(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 (红转绿): a real (non-comment) `admission::decide(` call goes green.
    #[test]
    fn provider_plane_gate6_fixed_by_real_admission_call() {
        let tmp = fresh_tmp("pp-gate6-fixed");
        write_adapter_home(
            &tmp,
            "fn embed() {\n    let d = admission::decide(&req, &budgets);\n    self.transport.call(&permit, &payload);\n}\n",
        );
        assert_eq!(
            provider_plane_gate6_admission_participation(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn provider_plane_gate6_real_repo_is_wired() {
        // `adapters.rs::admission_gate` now calls `admission::decide`/builds
        // `admission::AdmissionRequest` around the external call — pin flipped from
        // `NotApplicable` to `Pass`, same reasoning as gate 5/7's pin above.
        assert_eq!(
            provider_plane_gate6_admission_participation(&real_root()),
            Verdict::Pass
        );
    }

    // -- §19 Embedding Provider Failover 硬规则: decide_embedding_failover sole decision point -

    #[test]
    fn embedding_failover_sole_decision_point_check_passes_on_empty() {
        assert_eq!(
            embedding_failover_sole_decision_point_check(&[]),
            Verdict::Pass
        );
    }

    #[test]
    fn embedding_failover_sole_decision_point_check_fails_on_a_hit() {
        let hits = vec!["crates/retrieval-provider/src/router.rs".to_string()];
        assert!(matches!(
            embedding_failover_sole_decision_point_check(&hits),
            Verdict::Fail(_)
        ));
    }

    /// 注错 (红转绿): a fixture defining `ProjectionRef` without delegating to
    /// `decide_embedding_failover` is red.
    #[test]
    fn provider_plane_embedding_failover_fault_hand_rolled_comparison_is_red() {
        let tmp = fresh_tmp("pp-failover-fault");
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("router.rs"),
            "pub struct ProjectionRef { pub provider_id: String }\nfn projection_compatible() {}\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_embedding_failover_sole_decision_point(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 (红转绿): the identical fixture, with a real call to
    /// `decide_embedding_failover(` added, goes green.
    #[test]
    fn provider_plane_embedding_failover_fixed_by_delegating() {
        let tmp = fresh_tmp("pp-failover-fixed");
        let dir = tmp.join("crates/retrieval-provider/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("router.rs"),
            "pub struct ProjectionRef { pub provider_id: String }\nfn projection_compatible() {\n    failover::decide_embedding_failover(a, b, c, d)\n}\n",
        )
        .unwrap();
        assert_eq!(
            provider_plane_embedding_failover_sole_decision_point(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn provider_plane_embedding_failover_real_repo_is_green() {
        // Was an honest red pin (repo CLAUDE.md 交付准则「拒绝伪修复」): `router.rs::
        // ProjectionRef`/`projection_compatible` used to hand-roll the identical
        // provider_id/model_id/dimension comparison inline instead of calling through
        // `failover`. Fixed by extracting `failover::projection_contracts_compatible` (the
        // permit-free half of `decide_embedding_failover`'s own comparison) and having
        // `router::projection_compatible` call it — see this section's own module comment for
        // why `router.rs` cannot instead call the permit-gated `decide_embedding_failover`
        // directly. Both call names are the same one decision point; this pin now proves the
        // real repo actually routes through one of them, not documents a known gap.
        assert_eq!(
            provider_plane_embedding_failover_sole_decision_point(&real_root()),
            Verdict::Pass
        );
    }

    // -- §19 DOD-028 (a): EgressSecret::expose sole call site --------------------------------

    #[test]
    fn g_egress_secret_expose_sole_call_site_passes_on_real_repo() {
        assert_eq!(
            g_egress_secret_expose_sole_call_site(&real_root()),
            Verdict::Pass
        );
    }

    /// 注错 (红转绿): a second file that both names `EgressSecret` and calls `.expose()` on one
    /// — the exact "credential read outside the one sanctioned call site" shape this check
    /// exists to catch — is red.
    #[test]
    fn g_egress_secret_expose_fault_second_call_site_is_red() {
        let tmp = fresh_tmp("egress-secret-fault");
        let dir = tmp.join("crates/some-other-crate/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("lib.rs"),
            "use humaux_infra_egress::http::EgressSecret;\nfn leak(s: &EgressSecret) -> &str { s.expose() }\n",
        )
        .unwrap();
        assert!(matches!(
            g_egress_secret_expose_sole_call_site(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照: a file that calls some *other* type's `.expose()` (never naming
    /// `EgressSecret`) must not be flagged — this is exactly `byok.rs`'s unrelated
    /// `PlaintextApiKey::expose` shape.
    #[test]
    fn g_egress_secret_expose_ignores_unrelated_expose_methods() {
        let tmp = fresh_tmp("egress-secret-unrelated");
        let dir = tmp.join("crates/some-other-crate/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("lib.rs"),
            "struct PlaintextApiKey(String);\nimpl PlaintextApiKey {\n    fn expose(&self) -> &str { &self.0 }\n}\n",
        )
        .unwrap();
        assert_eq!(g_egress_secret_expose_sole_call_site(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    // -- §19 DOD-028 (b): retrieval credential purpose guard exists --------------------------

    #[test]
    fn g_retrieval_credential_purpose_guard_exists_passes_on_real_repo() {
        assert_eq!(
            g_retrieval_credential_purpose_guard_exists(&real_root()),
            Verdict::Pass
        );
    }

    /// 注错 (红转绿): a fixture standing in for `http.rs` with the purpose guard's needle
    /// text absent — proving this check would have caught finding 1 before it was fixed.
    #[test]
    fn g_retrieval_credential_purpose_guard_fault_missing_guard_is_red() {
        let tmp = fresh_tmp("purpose-guard-fault");
        let dir = tmp.join("crates/infra-egress/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("http.rs"),
            "async fn call() {\n    // no purpose guard here\n}\n",
        )
        .unwrap();
        assert!(matches!(
            g_retrieval_credential_purpose_guard_exists(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照: the identical fixture with the guard's needle text present goes green.
    #[test]
    fn g_retrieval_credential_purpose_guard_fixed_by_adding_guard() {
        let tmp = fresh_tmp("purpose-guard-fixed");
        let dir = tmp.join("crates/infra-egress/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("http.rs"),
            "async fn call() {\n    if !matches!(permit.purpose(), PrivateDataPurpose::RetrievalEmbedding | PrivateDataPurpose::RetrievalRerank) {\n        return Err(ErrorCode::Forbidden);\n    }\n}\n",
        )
        .unwrap();
        assert_eq!(
            g_retrieval_credential_purpose_guard_exists(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    // -- Gate 7/7: Embedding projection write contains provider/model/version metadata -------

    #[test]
    fn provider_plane_gate7_real_repo_projection_write_carries_model_metadata() {
        // §19 review: the Distill hop (ADR-0016, crates/adapters/src/distill_repo.rs) is now a
        // real, non-`tests/` `INSERT INTO private.processing_runs` write path, so the pin flips
        // from `NotApplicable` (the pre-Distill state, when only a test fixture wrote the table)
        // to `Pass`: the write must carry provider / model / revision metadata. If this ever
        // fails with `Fail`, a real write path dropped the §19 metadata — fix the write, not
        // this pin.
        assert_eq!(
            provider_plane_gate7_projection_write_has_model_metadata(&real_root()),
            Verdict::Pass
        );
    }

    #[test]
    fn insert_statement_text_stops_at_the_string_literals_closing_quote() {
        let source = "let q = \"INSERT INTO private.processing_runs (model_id) VALUES ($1)\"; let unrelated = \"model_provider model_revision\";";
        let idx = source.find("INSERT INTO").unwrap();
        let stmt = insert_statement_text(source, idx);
        assert!(stmt.contains("model_id"));
        assert!(
            !stmt.contains("model_provider"),
            "the metadata check must not see text after the statement's own closing quote"
        );
    }

    /// 注错: a real `INSERT INTO private.processing_runs` call site missing the metadata
    /// columns ⇒ red.
    #[test]
    fn provider_plane_gate7_fault_insert_missing_model_metadata_is_red() {
        let tmp = fresh_tmp("pp-gate7-fault");
        let dir = tmp.join("crates/adapters/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("write.rs"),
            "let q = \"INSERT INTO private.processing_runs (id) VALUES ($1)\";\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate7_projection_write_has_model_metadata(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照 (红转绿): the identical insert site with all three metadata columns present
    /// goes green.
    #[test]
    fn provider_plane_gate7_fixed_by_including_all_three_metadata_columns() {
        let tmp = fresh_tmp("pp-gate7-fixed");
        let dir = tmp.join("crates/adapters/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("write.rs"),
            "let q = \"INSERT INTO private.processing_runs (model_provider, model_id, model_revision) VALUES ($1, $2, $3)\";\n",
        )
        .unwrap();
        assert_eq!(
            provider_plane_gate7_projection_write_has_model_metadata(&tmp),
            Verdict::Pass
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§19 review, secondary weakness): the INSERT statement itself omits
    /// `model_provider`, but the same file mentions it elsewhere (an unrelated struct field) —
    /// must still be `Fail`, not swallowed into a false `Pass` by a whole-file `.contains`.
    #[test]
    fn provider_plane_gate7_fault_metadata_mentioned_only_outside_the_statement_is_red() {
        let tmp = fresh_tmp("pp-gate7-fault-outside-statement");
        let dir = tmp.join("crates/adapters/src");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("write.rs"),
            "struct Row { model_provider: String }\nlet q = \"INSERT INTO private.processing_runs (model_id, model_revision) VALUES ($1, $2)\";\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate7_projection_write_has_model_metadata(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (§19 review): the only real `INSERT INTO private.processing_runs` in a `tests/`
    /// directory must not green this gate — a test fixture proves the matcher works, not that
    /// a production write path exists.
    #[test]
    fn provider_plane_gate7_test_fixture_only_is_not_applicable() {
        let tmp = fresh_tmp("pp-gate7-tests-only");
        let dir = tmp.join("crates/adapters/tests");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("fixture.rs"),
            "let q = \"INSERT INTO private.processing_runs (model_provider, model_id, model_revision) VALUES ($1, $2, $3)\";\n",
        )
        .unwrap();
        assert!(matches!(
            provider_plane_gate7_projection_write_has_model_metadata(&tmp),
            Verdict::NotApplicable(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn adr_0014_real_gateway_bootstrap_is_green() {
        assert_eq!(
            adr_0014_gateway_qdrant_read_only_gate(&real_root()),
            Verdict::Pass
        );
    }

    fn adr_0014_tmp_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "arch-check-adr0014-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn adr_0014_write_bootstrap(tmp: &Path, body: &str) {
        let dir = tmp.join(GATEWAY_SRC_DIR);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("bootstrap.rs"), body).unwrap();
    }

    /// 注错正向对照：`.with_access_mode(CellAccessMode::QdrantReadOnly)` present → green.
    #[test]
    fn adr_0014_qdrant_read_only_entry_is_green() {
        let tmp = adr_0014_tmp_root("green");
        adr_0014_write_bootstrap(
            &tmp,
            "entries.insert(IntraCellResource::QDRANT_REST, ResourceEntry::new(host, port, cell, cidrs, callers, tls).unwrap().with_access_mode(CellAccessMode::QdrantReadOnly));",
        );
        assert_eq!(adr_0014_gateway_qdrant_read_only_gate(&tmp), Verdict::Pass);
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (红): 建了 QDRANT_REST entry 却没有 `.with_access_mode(QdrantReadOnly)` → red.
    #[test]
    fn adr_0014_qdrant_entry_missing_read_only_mode_is_red() {
        let tmp = adr_0014_tmp_root("missing-mode");
        adr_0014_write_bootstrap(
            &tmp,
            "entries.insert(IntraCellResource::QDRANT_REST, ResourceEntry::new(host, port, cell, cidrs, callers, tls).unwrap());",
        );
        assert!(matches!(
            adr_0014_gateway_qdrant_read_only_gate(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 注错 (红): 显式构造 `CellAccessMode::ReadWrite` → red, 即便同时也标了 QdrantReadOnly。
    #[test]
    fn adr_0014_explicit_read_write_mode_is_red() {
        let tmp = adr_0014_tmp_root("read-write");
        adr_0014_write_bootstrap(
            &tmp,
            "entries.insert(IntraCellResource::QDRANT_REST, ResourceEntry::new(host, port, cell, cidrs, callers, tls).unwrap().with_access_mode(CellAccessMode::QdrantReadOnly));\nlet oops = CellAccessMode::ReadWrite;",
        );
        assert!(matches!(
            adr_0014_gateway_qdrant_read_only_gate(&tmp),
            Verdict::Fail(_)
        ));
        fs::remove_dir_all(&tmp).ok();
    }

    /// 正向对照：只引用 `IntraCellResource::QDRANT_REST`（铸造 permit）而不构造 `ResourceEntry`
    /// 的文件不应被误判——这条扫描只关心注册点，不关心每一次读用途的引用。
    #[test]
    fn adr_0014_permit_reference_without_construction_is_not_flagged() {
        let tmp = adr_0014_tmp_root("permit-only");
        adr_0014_write_bootstrap(
            &tmp,
            "authorize_cell_access(&self.cell_registry, IntraCellResource::QDRANT_REST, Duration::from_secs(30))",
        );
        assert_eq!(
            adr_0014_gateway_qdrant_read_only_gate(&tmp),
            Verdict::NotApplicable(
                "gateway 尚未注册 IntraCellResource::QDRANT_REST resource entry".to_owned()
            )
        );
        fs::remove_dir_all(&tmp).ok();
    }

    // ---- M24-7 / G-M24-7 (§79, #101): nextest `global-db` completeness ----

    /// A nextest config whose `global-db` override selects `filter`.
    fn m24_7_config(filter: &str) -> String {
        format!("[[profile.ci.overrides]]\nfilter = '{filter}'\ntest-group = 'global-db'\n")
    }

    /// An integration binary `id` built from one file `file` holding `code`.
    fn m24_7_binary(id: &str, code: &str) -> NextestBinary {
        NextestBinary {
            id: id.to_owned(),
            sources: vec![("tests/f.rs".to_owned(), code.to_owned())],
        }
    }

    /// A workspace of one package `pkg` (`crates/pkg`, no lib, no bin) holding `files` (paths under the package) and a
    /// nextest config whose `global-db` filter is `filter`.
    fn m24_7_tree(label: &str, filter: &str, files: &[(&str, &str)]) -> PathBuf {
        let tmp = fresh_tmp(label);
        m07_write(
            &tmp,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        m07_write(&tmp, "crates/pkg/Cargo.toml", "[package]\nname = \"pkg\"\n");
        m07_write(&tmp, ".config/nextest.toml", &m24_7_config(filter));
        for (rel, body) in files {
            m07_write(&tmp, &format!("crates/pkg/{rel}"), body);
        }
        tmp
    }

    fn m24_7_fail_lines(verdict: Verdict) -> Vec<String> {
        match verdict {
            Verdict::Fail(lines) => lines,
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    fn m24_7_file_names(sources: &[(PathBuf, String)]) -> Vec<String> {
        let mut names: Vec<String> = sources
            .iter()
            .map(|(p, _)| p.file_name().unwrap().to_str().unwrap().to_owned())
            .collect();
        names.sort();
        names
    }

    /// Today's `main` passes: every binary that carries a marker is in `global-db` or is an exempt row.
    #[test]
    fn m24_7_real_repo_passes() {
        assert_eq!(m24_7_global_db_completeness(&real_root()), Verdict::Pass);
    }

    /// The marker list is derived from what the workspace references: a marker no binary carries is dead weight
    /// that would let its mechanism come back unmarked, and an exempt row needs a reason.
    #[test]
    fn m24_7_every_marker_is_carried_by_a_real_binary() {
        let binaries = nextest_binaries(&real_root()).unwrap();
        for (marker, why) in GLOBAL_DB_MARKERS {
            assert!(!why.is_empty(), "{marker}: a marker needs its reason");
            assert!(
                binaries
                    .iter()
                    .any(|b| carried_markers(b).iter().any(|(m, _, _)| m == marker)),
                "no test binary carries the marker `{marker}`"
            );
        }
        for (id, why) in GLOBAL_DB_EXEMPT {
            assert!(!why.is_empty(), "{id}: an exemption needs its reason");
        }
    }

    /// 注错 (§80.1, r1): the real config without `memory_attribution` in the `global-db` filter → red, naming that
    /// binary and a marker it carries. The CI record of the same fault is a `red/fix-101-r1` run.
    #[test]
    fn m24_7_real_config_without_memory_attribution_is_red() {
        let real = fs::read_to_string(real_root().join(NEXTEST_CONFIG_FILE)).unwrap();
        let injected = real.replace("binary_id(humaux-adapters::memory_attribution) | ", "");
        assert_ne!(
            real, injected,
            "the filter no longer names memory_attribution"
        );
        let binaries = nextest_binaries(&real_root()).unwrap();
        let lines = m24_7_fail_lines(global_db_verdict(&injected, &binaries, GLOBAL_DB_EXEMPT));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("humaux-adapters::memory_attribution"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("`operation_receipt_fixture`"),
            "{lines:?}"
        );
        assert_eq!(
            global_db_verdict(&real, &binaries, GLOBAL_DB_EXEMPT),
            Verdict::Pass
        );
    }

    /// 注错 (§80.1, r2): the real config with a `binary_id` that no binary has → red as stale, naming it.
    #[test]
    fn m24_7_real_config_with_a_nonexistent_binary_is_stale() {
        let real = fs::read_to_string(real_root().join(NEXTEST_CONFIG_FILE)).unwrap();
        let injected = real.replacen(
            "binary_id(humaux-adapters::auth_scope_rls)",
            "binary_id(humaux-adapters::auth_scope_rls) | binary_id(humaux-adapters::no_such_binary)",
            1,
        );
        assert_ne!(real, injected, "the filter no longer names auth_scope_rls");
        let binaries = nextest_binaries(&real_root()).unwrap();
        let lines = m24_7_fail_lines(global_db_verdict(&injected, &binaries, GLOBAL_DB_EXEMPT));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("binary_id(humaux-adapters::no_such_binary)"),
            "{lines:?}"
        );
        assert!(lines[0].contains("stale"), "{lines:?}");
    }

    /// The enumeration names binaries the way nextest does: a library's unit tests by package, a binary's as
    /// `bin/<name>` (`main.rs`, `src/bin/x.rs`, `src/bin/x/main.rs`), integration tests as `<package>::<stem>`
    /// (`tests/x.rs`, `tests/x/main.rs`); a `tests/` subdirectory without `main.rs` is support code, not a binary.
    #[test]
    fn m24_7_names_binaries_the_way_nextest_does() {
        let tmp = fresh_tmp("m24-7-names");
        m07_write(
            &tmp,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\", \"bins/bin-b\"]\n",
        );
        m07_write(
            &tmp,
            "crates/lib-a/Cargo.toml",
            "[package]\nname = \"lib-a\"\n",
        );
        m07_write(&tmp, "crates/lib-a/src/lib.rs", "");
        m07_write(&tmp, "crates/lib-a/tests/one.rs", "fn f() {}\n");
        m07_write(&tmp, "crates/lib-a/tests/dir_t/main.rs", "fn f() {}\n");
        m07_write(&tmp, "crates/lib-a/tests/support/helper.rs", "fn f() {}\n");
        m07_write(&tmp, "crates/no-manifest/src/lib.rs", "");
        m07_write(
            &tmp,
            "bins/bin-b/Cargo.toml",
            "[package]\nname = \"bin-b\"\n",
        );
        m07_write(&tmp, "bins/bin-b/src/main.rs", "fn main() {}\n");
        m07_write(&tmp, "bins/bin-b/src/bin/extra.rs", "fn main() {}\n");
        m07_write(&tmp, "bins/bin-b/src/bin/third/main.rs", "fn main() {}\n");
        m07_write(
            &tmp,
            "bins/not-a-member/Cargo.toml",
            "[package]\nname = \"other\"\n",
        );
        let binaries = nextest_binaries(&tmp).unwrap();
        let mut ids: Vec<&str> = binaries.iter().map(|b| b.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            [
                "bin-b::bin/bin-b",
                "bin-b::bin/extra",
                "bin-b::bin/third",
                "lib-a",
                "lib-a::dir_t",
                "lib-a::one",
            ]
        );
        assert!(
            binaries
                .iter()
                .filter(|b| b.id.starts_with("lib-a::"))
                .all(|b| b.sources.len() == 1),
            "an integration binary carries its sources"
        );
        assert!(
            binaries
                .iter()
                .filter(|b| !b.id.contains("::") || b.id.contains("::bin/"))
                .all(|b| b.sources.is_empty()),
            "a unit-test binary carries none"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// A member with its own targets is red, not silently mis-named.
    #[test]
    fn m24_7_fails_on_a_member_with_declared_targets() {
        let tmp = fresh_tmp("m24-7-custom-targets");
        m07_write(
            &tmp,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        m07_write(
            &tmp,
            "crates/pkg/Cargo.toml",
            "[package]\nname = \"pkg\"\n[[test]]\nname = \"x\"\npath = \"y.rs\"\n",
        );
        match nextest_binaries(&tmp) {
            Err(detail) => assert!(detail.contains("declares [[test]]"), "{detail}"),
            Ok(_) => panic!("expected Err"),
        }
        m07_write(
            &tmp,
            "crates/pkg/Cargo.toml",
            "[package]\nname = \"pkg\"\nautotests = false\n",
        );
        assert!(nextest_binaries(&tmp).is_err());
        fs::remove_dir_all(&tmp).ok();
    }

    /// `#[path = ".."]` on its own line, on the line of its `mod`, above other attributes and across crates, plain
    /// `mod x;` as `x/mod.rs`, any visibility; followed transitively; comments and inline modules are not followed.
    #[test]
    fn m24_7_follows_path_and_plain_modules() {
        let tmp = fresh_tmp("m24-7-walker");
        m07_write(
            &tmp,
            "t/a.rs",
            "#[path = \"support/fx.rs\"]\nmod fx;\n#[path = \"support/same.rs\"] mod same;\n\
             #[path = \"support/attrs.rs\"]\n#[allow(dead_code)]\npub(crate) mod attrs;\n\
             #[path = \"../other/shared.rs\"]\nmod shared;\npub mod common;\n\
             // mod ghost;\n/* mod ghost_block; */\nmod inline { fn f() {} }\n",
        );
        m07_write(
            &tmp,
            "t/support/fx.rs",
            "#[path = \"deep.rs\"]\nmod deep;\n",
        );
        m07_write(&tmp, "t/support/deep.rs", "fn deep() {}\n");
        m07_write(&tmp, "t/support/same.rs", "fn same() {}\n");
        m07_write(&tmp, "t/support/attrs.rs", "fn attrs() {}\n");
        m07_write(&tmp, "other/shared.rs", "fn shared() {}\n");
        m07_write(&tmp, "t/common/mod.rs", "fn common() {}\n");
        m07_write(&tmp, "t/ghost.rs", "fn ghost() {}\n");
        m07_write(&tmp, "t/inline.rs", "fn inline() {}\n");
        m07_write(&tmp, "t/ghost_block.rs", "fn ghost_block() {}\n");
        let (sources, unresolved) = test_binary_sources(&tmp.join("t/a.rs"));
        assert!(unresolved.is_empty(), "{unresolved:?}");
        assert_eq!(
            m24_7_file_names(&sources),
            [
                "a.rs",
                "attrs.rs",
                "deep.rs",
                "fx.rs",
                "mod.rs",
                "same.rs",
                "shared.rs"
            ]
        );
        assert_eq!(
            sources[0].0,
            tmp.join("t/a.rs"),
            "the entry file comes first"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// A `#[path]` that is separated from its `mod` by another item belongs to nothing, so that `mod` is unresolved like
    /// one that names no file; a file reached through two modules is read once; a cycle terminates.
    #[test]
    fn m24_7_walker_drops_a_stranded_path_and_survives_cycles() {
        let tmp = fresh_tmp("m24-7-walker-edge");
        m07_write(
            &tmp,
            "t/b.rs",
            "#[path = \"support/x.rs\"]\nfn f() {}\nmod x;\nmod missing;\n#[path = \"support/y.rs\"]\nmod y;\n\
             #[path = \"support/y.rs\"]\nmod y_again;\n",
        );
        m07_write(&tmp, "t/support/x.rs", "fn x() {}\n");
        m07_write(&tmp, "t/support/y.rs", "#[path = \"../b.rs\"]\nmod back;\n");
        let (sources, unresolved) = test_binary_sources(&tmp.join("t/b.rs"));
        assert_eq!(m24_7_file_names(&sources), ["b.rs", "y.rs"]);
        let declared: Vec<&str> = unresolved.iter().map(|(_, decl)| decl.as_str()).collect();
        assert_eq!(declared, ["mod x;", "mod missing;"]);
        fs::remove_dir_all(&tmp).ok();
    }

    /// P2 (a) of the #144 review: a nested `<dir>/<stem>/<name>/mod.rs` under a module file that is not a `mod.rs`, and
    /// a string-literal `include!`, are followed; a `mod x;` or `include!` that finds no file, and an `include!` whose
    /// argument is not a literal, come back unresolved with the file that declares them.
    #[test]
    fn m24_7_follows_nested_mod_rs_and_include_and_reports_what_it_cannot_resolve() {
        let tmp = fresh_tmp("m24-7-resolve");
        m07_write(
            &tmp,
            "t/a.rs",
            "mod fx;\ninclude!(\"support/inc.rs\");\nmod missing;\n\
             include!(concat!(env!(\"OUT_DIR\"), \"/gen.rs\"));\ninclude!(\"support/none.rs\");\n",
        );
        m07_write(&tmp, "t/fx.rs", "mod deep;\n");
        m07_write(&tmp, "t/fx/deep/mod.rs", "fn deep() {}\n");
        m07_write(&tmp, "t/support/inc.rs", "fn inc() {}\n");
        let (sources, unresolved) = test_binary_sources(&tmp.join("t/a.rs"));
        assert_eq!(
            m24_7_file_names(&sources),
            ["a.rs", "fx.rs", "inc.rs", "mod.rs"]
        );
        let declared: Vec<&str> = unresolved.iter().map(|(_, decl)| decl.as_str()).collect();
        assert_eq!(
            declared,
            [
                "mod missing;",
                "include!(concat!(env!(\"OUT_DIR\")",
                "include!(\"support/none.rs\")"
            ]
        );
        assert!(unresolved.iter().all(|(file, _)| file.ends_with("t/a.rs")));
        fs::remove_dir_all(&tmp).ok();
    }

    /// P2-1 of the #146 review: a plain `mod x;` is looked up by the kind of the file that holds it. Beside a file that
    /// owns its directory (the crate root, a `mod.rs`, a `#[path]`-loaded file) it is `x.rs` then `x/mod.rs`; beside any
    /// other file only `<stem>/x.rs` then `<stem>/x/mod.rs`, so an unrelated sibling `child.rs` is not read for
    /// `support.rs`'s `mod child;` and the declaration is unresolved until its own file exists.
    #[test]
    fn m24_7_reads_nested_modules_by_the_kind_of_their_file() {
        let tmp = fresh_tmp("m24-7-kinds");
        m07_write(
            &tmp,
            "t/root.rs",
            "mod support;\n#[path = \"loaded/l.rs\"]\nmod l;\nmod owned;\n",
        );
        m07_write(&tmp, "t/support.rs", "mod child;\n");
        m07_write(&tmp, "t/child.rs", "fn sibling_of_support() {}\n");
        m07_write(&tmp, "t/loaded/l.rs", "mod peer;\n");
        m07_write(&tmp, "t/loaded/peer.rs", "fn peer() {}\n");
        m07_write(&tmp, "t/owned/mod.rs", "mod twin;\n");
        m07_write(&tmp, "t/owned/twin.rs", "fn twin() {}\n");
        let (sources, unresolved) = test_binary_sources(&tmp.join("t/root.rs"));
        assert_eq!(
            m24_7_file_names(&sources),
            [
                "l.rs",
                "mod.rs",
                "peer.rs",
                "root.rs",
                "support.rs",
                "twin.rs"
            ]
        );
        let declared: Vec<&str> = unresolved.iter().map(|(_, decl)| decl.as_str()).collect();
        assert_eq!(declared, ["mod child;"]);
        assert!(unresolved[0].0.ends_with("t/support.rs"), "{unresolved:?}");
        m07_write(&tmp, "t/support/child.rs", "fn child() {}\n");
        let (sources, unresolved) = test_binary_sources(&tmp.join("t/root.rs"));
        assert!(unresolved.is_empty(), "{unresolved:?}");
        let paths: Vec<&PathBuf> = sources.iter().map(|(path, _)| path).collect();
        assert!(
            paths.contains(&&tmp.join("t/support/child.rs")),
            "{paths:?}"
        );
        assert!(!paths.contains(&&tmp.join("t/child.rs")), "{paths:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// P2 (a), through the tree: an unresolved `mod x;` is a `Fail` naming the binary, the declaration and its file, never
    /// a silently shorter source list.
    #[test]
    fn m24_7_fails_on_a_binary_whose_module_resolves_to_no_file() {
        let tmp = m24_7_tree(
            "m24-7-unresolved",
            "binary_id(pkg::b)",
            &[("tests/b.rs", "mod gone;\nfn f() {}\n")],
        );
        let lines = m24_7_fail_lines(m24_7_over_tree(&tmp, &[], &[]));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("pkg::b pulls in `mod gone;` in crates/pkg/tests/b.rs"),
            "{lines:?}"
        );
        assert!(lines[0].contains("resolve to no file"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// The filter reader accepts `binary_id(<literal>)` terms joined by `|` and nothing else.
    #[test]
    fn m24_7_filter_reader_is_closed() {
        assert_eq!(
            filter_binary_ids("binary_id(a::b) | binary_id(c-d) |binary_id(e::bin/e)"),
            Ok(vec![
                "a::b".to_owned(),
                "c-d".to_owned(),
                "e::bin/e".to_owned()
            ])
        );
        for bad in [
            "",
            "package(x)",
            "binary_id(a*)",
            "binary_id(=a)",
            "binary_id()",
            "binary_id(a) & binary_id(b)",
            "binary_id(a) | test(b)",
        ] {
            assert!(filter_binary_ids(bad).is_err(), "{bad:?} must not parse");
        }
        assert_eq!(
            filter_binary_ids("binary_id(a) | test(b)"),
            Err("test(b)".to_owned())
        );
    }

    /// 注错 (red): a binary with a marker that the filter does not name → one line, naming the binary, the marker
    /// and the file; naming it in the filter turns it green.
    #[test]
    fn m24_7_fails_on_an_ungrouped_binary_with_a_marker_and_passes_once_grouped() {
        let binaries = [
            m24_7_binary("pkg::in", "fn f() { let _ = RememberCommand; }"),
            m24_7_binary("pkg::out", "fn f() { let _ = RememberCommand; }"),
            m24_7_binary("pkg::quiet", "fn f() {}"),
        ];
        let lines = m24_7_fail_lines(global_db_verdict(
            &m24_7_config("binary_id(pkg::in)"),
            &binaries,
            &[],
        ));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("pkg::out is in no test group"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("`RememberCommand` (tests/f.rs)"),
            "{lines:?}"
        );
        assert!(lines[0].contains("GLOBAL_DB_EXEMPT"), "{lines:?}");
        assert_eq!(
            global_db_verdict(
                &m24_7_config("binary_id(pkg::in) | binary_id(pkg::out)"),
                &binaries,
                &[]
            ),
            Verdict::Pass
        );
    }

    /// Every marker is read: a binary carrying only that one is red when ungrouped.
    #[test]
    fn m24_7_every_marker_turns_an_ungrouped_binary_red() {
        for (marker, _) in GLOBAL_DB_MARKERS {
            let binaries = [
                m24_7_binary("pkg::in", "fn f() {}"),
                m24_7_binary("pkg::out", &format!("fn f() {{ let _ = \"{marker}\"; }}")),
            ];
            let lines = m24_7_fail_lines(global_db_verdict(
                &m24_7_config("binary_id(pkg::in)"),
                &binaries,
                &[],
            ));
            assert!(
                lines[0].contains(&format!("`{marker}`")),
                "{marker}: {lines:?}"
            );
        }
    }

    /// A `binary_id` in the `global-db` filter that names no binary is stale → red, naming it. A unit-test binary
    /// (no sources) is a real binary: naming it is not stale.
    #[test]
    fn m24_7_fails_on_a_stale_filter_entry() {
        let binaries = [
            m24_7_binary("pkg::c", "fn f() {}"),
            NextestBinary {
                id: "pkg".to_owned(),
                sources: Vec::new(),
            },
        ];
        assert_eq!(
            global_db_verdict(
                &m24_7_config("binary_id(pkg) | binary_id(pkg::c)"),
                &binaries,
                &[]
            ),
            Verdict::Pass
        );
        let lines = m24_7_fail_lines(global_db_verdict(
            &m24_7_config("binary_id(pkg::c) | binary_id(pkg::renamed)"),
            &binaries,
            &[],
        ));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("binary_id(pkg::renamed)"), "{lines:?}");
        assert!(lines[0].contains("stale"), "{lines:?}");
    }

    /// nextest takes the first override that selects a binary: a binary that an earlier group selects is not in
    /// `global-db` even though the `global-db` filter names it.
    #[test]
    fn m24_7_fails_when_an_earlier_group_takes_the_binary() {
        let config = "[[profile.ci.overrides]]\nfilter = 'binary_id(pkg::b)'\ntest-group = 'serial-b'\n\
                      [[profile.ci.overrides]]\nfilter = 'binary_id(pkg::b)'\ntest-group = 'global-db'\n";
        let binaries = [m24_7_binary(
            "pkg::b",
            "fn f() { let _ = RememberCommand; }",
        )];
        let lines = m24_7_fail_lines(global_db_verdict(config, &binaries, &[]));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("in the `serial-b` group"), "{lines:?}");
    }

    /// An exemption lets a marker binary stay outside the group; a row whose binary is gone, no longer carries a
    /// marker or is now in the group is red (stale).
    #[test]
    fn m24_7_exemptions_pass_and_go_stale() {
        let config = m24_7_config("binary_id(pkg::in)");
        let binaries = [
            m24_7_binary("pkg::in", "fn f() {}"),
            m24_7_binary("pkg::own_db", "fn f() { let _ = RememberCommand; }"),
        ];
        assert_eq!(
            global_db_verdict(&config, &binaries, &[("pkg::own_db", "own database")]),
            Verdict::Pass
        );
        let quiet = [
            m24_7_binary("pkg::in", "fn f() {}"),
            m24_7_binary("pkg::own_db", "fn f() {}"),
        ];
        let lines = m24_7_fail_lines(global_db_verdict(
            &config,
            &quiet,
            &[("pkg::own_db", "own database")],
        ));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("pkg::own_db") && lines[0].contains("carries no marker"),
            "{lines:?}"
        );
        let lines = m24_7_fail_lines(global_db_verdict(
            &config,
            &binaries,
            &[
                ("pkg::own_db", "own database"),
                ("pkg::gone", "was a binary"),
            ],
        ));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("pkg::gone") && lines[0].contains("names no test binary"),
            "{lines:?}"
        );
        let grouped = [m24_7_binary(
            "pkg::in",
            "fn f() { let _ = RememberCommand; }",
        )];
        let lines = m24_7_fail_lines(global_db_verdict(
            &config,
            &grouped,
            &[("pkg::in", "own database")],
        ));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("is in the `global-db` group now"),
            "{lines:?}"
        );
    }

    /// `not_applicable` names the missing object (§57.1 第2条): no nextest config at all, or a config without a
    /// `global-db` override.
    #[test]
    fn m24_7_is_not_applicable_naming_the_missing_object() {
        let tmp = fresh_tmp("m24-7-na");
        fs::create_dir_all(&tmp).unwrap();
        match m24_7_global_db_completeness(&tmp) {
            Verdict::NotApplicable(detail) => {
                assert!(detail.contains(NEXTEST_CONFIG_FILE), "{detail}")
            }
            other => panic!("expected NotApplicable, got {other:?}"),
        }
        fs::remove_dir_all(&tmp).ok();
        let other_group =
            "[[profile.ci.overrides]]\nfilter = 'binary_id(pkg::c)'\ntest-group = 'serial-c'\n";
        for config in [other_group, "[profile.ci]\nretries = 0\n", ""] {
            match global_db_verdict(config, &[m24_7_binary("pkg::c", "fn f() {}")], &[]) {
                Verdict::NotApplicable(detail) => {
                    assert!(detail.contains("test-group = \"global-db\""), "{detail}");
                    assert!(detail.contains(NEXTEST_CONFIG_FILE), "{detail}");
                }
                other => panic!("expected NotApplicable for {config:?}, got {other:?}"),
            }
        }
    }

    /// A config that is not TOML, or whose `global-db` filter is not a plain list of `binary_id` terms, is red
    /// (never an empty group that passes everything).
    #[test]
    fn m24_7_fails_on_a_config_it_cannot_read() {
        let lines = m24_7_fail_lines(global_db_verdict("[[profile", &[], &[]));
        assert!(lines[0].contains("not valid TOML"), "{lines:?}");
        let lines = m24_7_fail_lines(global_db_verdict(&m24_7_config("package(=pkg)"), &[], &[]));
        assert!(lines[0].contains("`package(=pkg)`"), "{lines:?}");
        assert!(lines[0].contains("global-db"), "{lines:?}");
    }

    /// P2 (b) of the #144 review: an override that carries `test-group` plus any key but `filter` (a `platform`, a
    /// `retries`), or no `filter` at all, is red; an override without `test-group` is not this gate's business.
    #[test]
    fn m24_7_fails_on_a_test_group_override_it_cannot_fully_read() {
        let quiet = [m24_7_binary("pkg::c", "fn f() {}")];
        for key in ["platform", "retries", "slow-timeout"] {
            let config = format!("{}{key} = 'x'\n", m24_7_config("binary_id(pkg::c)"));
            let lines = m24_7_fail_lines(global_db_verdict(&config, &quiet, &[]));
            assert_eq!(lines.len(), 1, "{key}: {lines:?}");
            assert!(lines[0].contains(&format!("[\"{key}\"]")), "{lines:?}");
        }
        let no_filter = "[[profile.ci.overrides]]\ntest-group = 'global-db'\n";
        let lines = m24_7_fail_lines(global_db_verdict(no_filter, &quiet, &[]));
        assert!(lines[0].contains("a string `filter`"), "{lines:?}");
        let unrelated = format!(
            "{}[[profile.ci.overrides]]\nplatform = 'cfg(unix)'\nretries = 1\n",
            m24_7_config("binary_id(pkg::c)")
        );
        assert_eq!(global_db_verdict(&unrelated, &quiet, &[]), Verdict::Pass);
    }

    /// 注错 (§80.1, r3, in process): the real config with `platform = 'cfg(windows)'` on the `global-db` override → red
    /// naming the key. The CI record of the same fault is a `red/fix-145-r3` run.
    #[test]
    fn m24_7_real_config_with_a_platform_on_the_global_db_override_is_red() {
        let real = fs::read_to_string(real_root().join(NEXTEST_CONFIG_FILE)).unwrap();
        let injected = real.replacen(
            "test-group = 'global-db'\n",
            "test-group = 'global-db'\nplatform = 'cfg(windows)'\n",
            1,
        );
        assert_ne!(
            real, injected,
            "the global-db override no longer ends its keys with test-group"
        );
        let binaries = nextest_binaries(&real_root()).unwrap();
        let lines = m24_7_fail_lines(global_db_verdict(&injected, &binaries, GLOBAL_DB_EXEMPT));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("[\"platform\"]"), "{lines:?}");
    }

    /// P2 (c) of the #144 review: no `global-db` override is `not_applicable` only while no binary carries a marker; with
    /// one, the config (or the whole file) losing the group is a `Fail`, never "nothing to check".
    #[test]
    fn m24_7_is_a_fail_not_na_when_the_group_is_gone_but_a_marker_is_not() {
        let carrying = [
            m24_7_binary("pkg::c", "fn f() { let _ = RememberCommand; }"),
            m24_7_binary("pkg::q", "fn f() {}"),
        ];
        let other_group =
            "[[profile.ci.overrides]]\nfilter = 'binary_id(pkg::c)'\ntest-group = 'serial-c'\n";
        for config in [other_group, "[profile.ci]\nretries = 0\n", ""] {
            let lines = m24_7_fail_lines(global_db_verdict(config, &carrying, &[]));
            assert_eq!(lines.len(), 1, "{config:?}: {lines:?}");
            assert!(
                lines[0].contains("1 test binaries") && lines[0].contains("first: pkg::c"),
                "{lines:?}"
            );
        }
        let real = fs::read_to_string(real_root().join(NEXTEST_CONFIG_FILE)).unwrap();
        let ungrouped = real.replace(
            "test-group = 'global-db'",
            "test-group = 'serial-not-global-db'",
        );
        assert_ne!(real, ungrouped);
        let binaries = nextest_binaries(&real_root()).unwrap();
        let lines = m24_7_fail_lines(global_db_verdict(&ungrouped, &binaries, GLOBAL_DB_EXEMPT));
        assert!(
            lines[0].contains("test binaries carry a cluster-global marker"),
            "{lines:?}"
        );
        let tmp = m24_7_tree(
            "m24-7-nofile",
            "binary_id(pkg::b)",
            &[("tests/b.rs", "fn f() { let _ = RememberCommand; }\n")],
        );
        fs::remove_file(tmp.join(NEXTEST_CONFIG_FILE)).unwrap();
        let lines = m24_7_fail_lines(m24_7_over_tree(&tmp, &[], &[]));
        assert!(lines[0].contains("first: pkg::b"), "{lines:?}");
        fs::remove_dir_all(&tmp).ok();
    }

    /// Through the tree: a marker that reaches the binary only through a `#[path]` module counts, a marker that is
    /// only mentioned in a comment does not; naming the binary in the filter turns the red run green.
    #[test]
    fn m24_7_tree_red_then_green_and_comments_do_not_count() {
        let files = [
            ("tests/b.rs", "#[path = \"support/fx.rs\"]\nmod fx;\n"),
            (
                "tests/support/fx.rs",
                "fn seed() { let _ = RememberCommand; }\n",
            ),
            (
                "tests/c.rs",
                "// RememberCommand\n/* DISABLE TRIGGER */\nfn quiet() {}\n",
            ),
        ];
        let red = m24_7_tree("m24-7-red", "binary_id(pkg::c)", &files);
        let lines = m24_7_fail_lines(m24_7_over_tree(&red, &[], &[]));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("pkg::b is in no test group"), "{lines:?}");
        assert!(
            lines[0].contains("`RememberCommand` (crates/pkg/tests/support/fx.rs)"),
            "{lines:?}"
        );
        fs::remove_dir_all(&red).ok();
        let green = m24_7_tree(
            "m24-7-green",
            "binary_id(pkg::b) | binary_id(pkg::c)",
            &files,
        );
        assert_eq!(m24_7_over_tree(&green, &[], &[]), Verdict::Pass);
        fs::remove_dir_all(&green).ok();
    }

    // ---- M24-7b (§79, #145): shared-catalog DDL runs only in a lane(a:disposable) test ----

    /// The `(phrase, line)` pairs of shared-catalog DDL in `code` held by a binary with no `lane(a:disposable)` test.
    fn m24_7b_hits(code: &str) -> Vec<(String, usize)> {
        bare_catalog_ddl(&m24_7_binary("pkg::b", code), &[])
            .into_iter()
            .map(|(_, line, phrase, _)| (phrase, line))
            .collect()
    }

    /// The `(display path, line)` of the `#[ignore]` on line `line` of `tests/f.rs`.
    fn m24_7b_ignore_at(line: usize) -> Vec<(String, usize)> {
        vec![("tests/f.rs".to_owned(), line)]
    }

    /// Every phrase of the closed list is read, whatever the case, the line break or the `\` continuation between its
    /// words; `LOCK TABLE` counts only with `ACCESS EXCLUSIVE` in the same statement.
    #[test]
    fn m24_7b_reads_every_listed_phrase() {
        for (code, phrase, line) in [
            ("ALTER TABLE t RENAME COLUMN a TO b;", "rename column", 1),
            ("x\nALTER TABLE t Add\n   Column a int", "add column", 2),
            ("\"ALTER TABLE t DROP \\\n  COLUMN a\"", "drop column", 1),
            ("ALTER ROLE r BYPASSRLS", "alter role", 1),
            ("ALTER SYSTEM SET archive_mode = 'on'", "alter system", 1),
            ("ALTER DATABASE d SET x = 1", "alter database", 1),
            (
                "LOCK TABLE s.t IN ACCESS EXCLUSIVE MODE",
                "lock table … access exclusive",
                1,
            ),
            (
                "lock table s.t\n  in access\n  exclusive mode",
                "lock table … access exclusive",
                1,
            ),
        ] {
            assert_eq!(m24_7b_hits(code), [(phrase.to_owned(), line)], "{code:?}");
        }
        for (head, tail, why) in SHARED_CATALOG_DDL {
            assert!(!why.is_empty(), "{head}: a phrase needs its reason");
            assert!(
                tail.is_none_or(|t| !t.is_empty()),
                "{head}: an empty tail would match nothing"
            );
        }
        for (id, why) in SHARED_CATALOG_DDL_EXEMPT {
            assert!(!why.is_empty(), "{id}: an exemption needs its reason");
        }
    }

    /// What is not shared-catalog DDL stays quiet: a lock mode below ACCESS EXCLUSIVE, an `ACCESS EXCLUSIVE` that
    /// belongs to the next statement or string, other `ALTER`s, identifiers that merely contain the words.
    #[test]
    fn m24_7b_ignores_what_is_not_listed() {
        for quiet in [
            "LOCK TABLE s.t IN SHARE MODE",
            "LOCK TABLE s.t IN SHARE ROW EXCLUSIVE MODE",
            "LOCK TABLE s.t IN ACCESS SHARE MODE; SELECT 'ACCESS EXCLUSIVE'",
            "c.batch_execute(\"LOCK TABLE s.t IN ROW SHARE MODE\"); f(\"ACCESS EXCLUSIVE\")",
            "ALTER TABLE t ADD CONSTRAINT k CHECK (a > 0); CREATE ROLE r; DROP TABLE t",
            "rename_column add_column drop_column alter_role alter_system alter_database lock_table",
            "RENAME TABLE t TO u; ADD INDEX i; DROP ROLE r",
        ] {
            assert!(m24_7b_hits(quiet).is_empty(), "{quiet:?}");
        }
    }

    /// 注错 (§80.1): DDL outside a `lane(a:disposable)` test is red naming the binary, file, line and phrase; the same
    /// text inside one passes, braces in a string do not unbalance the test's span, and a hit after the test is outside.
    #[test]
    fn m24_7b_passes_inside_a_disposable_test_and_fails_outside_it() {
        let code = [
            "const OTHER: &str = \"ALTER ROLE r NOLOGIN\";",
            "#[test]",
            "#[ignore = \"lane(a:disposable) own database\"]",
            "fn ddl() {",
            "    let open = \"{\";",
            "    run(\"ALTER TABLE t RENAME COLUMN a TO b\");",
            "}",
            "fn after() { run(\"ALTER SYSTEM SET a = 1\"); }",
        ]
        .join("\n");
        let binary = m24_7_binary("pkg::b", &code);
        let hits = bare_catalog_ddl(&binary, &m24_7b_ignore_at(3));
        let seen: Vec<(usize, &str)> = hits.iter().map(|h| (h.1, h.2.as_str())).collect();
        assert_eq!(seen, [(1, "alter role"), (8, "alter system")]);
        let lines = shared_ddl_problems(&[binary], &m24_7b_ignore_at(3), &[]);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0]
                .contains("pkg::b runs `alter role` (tests/f.rs:1), `alter system` (tests/f.rs:8)"),
            "{lines:?}"
        );
        assert!(lines[0].contains("SHARED_CATALOG_DDL_EXEMPT"), "{lines:?}");
        let binary = m24_7_binary("pkg::b", &code);
        let lines = shared_ddl_problems(&[binary], &[], &[]);
        assert!(
            lines[0].contains("`rename column` (tests/f.rs:6)"),
            "{lines:?}"
        );
    }

    /// An exemption row lets a binary keep its DDL; a row whose binary is gone or has no hit left outside a
    /// `lane(a:disposable)` test is red (stale).
    #[test]
    fn m24_7b_exemptions_pass_and_go_stale() {
        let ddl = m24_7_binary(
            "pkg::own_cluster",
            "fn f() { run(\"ALTER SYSTEM SET a = 1\"); }",
        );
        let quiet = m24_7_binary("pkg::quiet", "fn f() {}");
        let row = [("pkg::own_cluster", "its own cluster")];
        assert!(shared_ddl_problems(&[ddl], &[], &row).is_empty());
        let lines = shared_ddl_problems(
            &[quiet, m24_7_binary("pkg::own_cluster", "fn f() {}")],
            &[],
            &[
                ("pkg::own_cluster", "its own cluster"),
                ("pkg::gone", "was a binary"),
            ],
        );
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].contains("pkg::own_cluster")
                && lines[0].contains("carries no shared-catalog DDL"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("pkg::gone") && lines[1].contains("names no test binary"),
            "{lines:?}"
        );
    }

    /// Through the tree and the real serial-lane walker: the DDL inside a `lane(a:disposable)` test passes; remove the
    /// `#[ignore]`, or give it another lane resource, and the run is red naming the binary, file and line; a comment that
    /// mentions the DDL never counts.
    #[test]
    fn m24_7b_tree_removing_the_ignore_turns_the_run_red() {
        let test = "#[test]\n#[ignore = \"lane(a:disposable) own database\"]\n\
                    fn ddl() { run(\"ALTER TABLE t DROP COLUMN a\"); }\n\
                    // ALTER ROLE r NOLOGIN\n";
        let green = m24_7_tree("m24-7b-green", "binary_id(pkg::d)", &[("tests/d.rs", test)]);
        assert_eq!(m24_7_over_tree(&green, &[], &[]), Verdict::Pass);
        fs::remove_dir_all(&green).ok();
        for (label, mutated) in [
            (
                "no-ignore",
                test.replace("#[ignore = \"lane(a:disposable) own database\"]\n", ""),
            ),
            (
                "shared-db",
                test.replace("lane(a:disposable)", "lane(a:shared_db)"),
            ),
        ] {
            let red = m24_7_tree(
                &format!("m24-7b-{label}"),
                "binary_id(pkg::d)",
                &[("tests/d.rs", mutated.as_str())],
            );
            let lines = m24_7_fail_lines(m24_7_over_tree(&red, &[], &[]));
            assert_eq!(lines.len(), 1, "{label}: {lines:?}");
            assert!(
                lines[0].contains("pkg::d runs `drop column` (crates/pkg/tests/d.rs:"),
                "{label}: {lines:?}"
            );
            fs::remove_dir_all(&red).ok();
        }
    }

    /// The real tree: the DDL tests that moved are inside their `lane(a:disposable)` span, so the shared-catalog part is
    /// clean with the real rows, and every real row still has a hit to stand on.
    #[test]
    fn m24_7b_real_repo_is_clean_and_every_row_is_live() {
        let binaries = nextest_binaries(&real_root()).unwrap();
        let disposable = crate::serial_lane::disposable_ignores(&real_root());
        assert_eq!(
            shared_ddl_problems(&binaries, &disposable, SHARED_CATALOG_DDL_EXEMPT),
            Vec::<String>::new()
        );
    }

    /// 注错 (§80.1, r1, in process): the real `#[ignore = "lane(a:disposable) .."]` of a moved DDL test removed → red,
    /// naming the binary and the DDL lines in its file. The CI record of the same fault is a `red/fix-145-r1` run.
    #[test]
    fn m24_7b_real_moved_tests_without_their_ignore_are_red() {
        let binaries = nextest_binaries(&real_root()).unwrap();
        let disposable = crate::serial_lane::disposable_ignores(&real_root());
        for (id, file, phrase) in [
            (
                "humaux-adapters::mandatory_context_lane",
                "crates/adapters/tests/mandatory_context_lane.rs",
                "`rename column` (crates/adapters/tests/mandatory_context_lane.rs:",
            ),
            (
                "humaux-adapters::retrieve_read_your_writes",
                "crates/adapters/tests/retrieve_read_your_writes.rs",
                "`lock table … access exclusive` (crates/adapters/tests/retrieve_read_your_writes.rs:",
            ),
        ] {
            let injected: Vec<(String, usize)> = disposable
                .iter()
                .filter(|(f, _)| f != file)
                .cloned()
                .collect();
            assert_ne!(
                injected.len(),
                disposable.len(),
                "{file} no longer holds a lane(a:disposable) test"
            );
            let lines = shared_ddl_problems(&binaries, &injected, SHARED_CATALOG_DDL_EXEMPT);
            assert_eq!(lines.len(), 1, "{id}: {lines:?}");
            assert!(
                lines[0].contains(&format!("M24-7b: {id} runs ")),
                "{lines:?}"
            );
            assert!(lines[0].contains(phrase), "{lines:?}");
        }
    }

    /// 注错 (§80.1, r2, in process): a bare `ALTER TABLE .. RENAME COLUMN` line appended to an ungrouped real test file
    /// → red, naming the binary, file and the new line. The CI record is a `red/fix-145-r2` run.
    #[test]
    fn m24_7b_real_ungrouped_binary_with_a_bare_rename_column_is_red() {
        let mut binaries = nextest_binaries(&real_root()).unwrap();
        let disposable = crate::serial_lane::disposable_ignores(&real_root());
        let target = binaries
            .iter_mut()
            .find(|b| b.id == "humaux-adapters::mandatory_context_lane")
            .expect("an ungrouped integration binary");
        let (file, code) = &mut target.sources[0];
        let file = file.clone();
        let next_line = code.lines().count() + 1;
        code.push_str("\nconst BARE: &str = \"ALTER TABLE t RENAME COLUMN a TO b\";\n");
        let lines = shared_ddl_problems(&binaries, &disposable, SHARED_CATALOG_DDL_EXEMPT);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&format!(
                "humaux-adapters::mandatory_context_lane runs `rename column` ({file}:{next_line})"
            )),
            "{lines:?}"
        );
    }
}
