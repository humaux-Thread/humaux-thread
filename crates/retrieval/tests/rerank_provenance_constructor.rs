//! `retrieval::tests::rerank_provenance_constructor` — the rendered `provenance.rerank_model_id` has exactly one
//!   construction site in the workspace's production code, and the field is given a `used` value in exactly one place
//!   (ADR-0084 D-C, the repo's unique-constructor rule: `== 1`).
//! Depends-on: crates=[]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[]
//! Called-by: [cargo-test]
//! Invariants: [no DB or network; the scan reads the workspace's `src/` trees under `crates/` and `bins/`; a production
//!   file is the text before its first `#[cfg(test)]`, whole-line `//` comments dropped; a construction site is a
//!   `RerankModelId(` that is not the `struct` definition; a `used` assignment is the identifier `rerank_model_id`
//!   followed by `:` or `=` and then `ProvenanceValue::Used` or `Used {`, so a second site anywhere, in any file, turns
//!   the count to 2; the cloud route's `rerank_model_id` (`retrieval-provider` router) is a route descriptor
//!   `Option<String>`, not provenance, and is held out explicitly with that reason]
//! Spec: ADR-0084 D-C; ADR-0084 D-G; CLAUDE.md "唯一构造点模式"
//!
//! `RerankModelId`'s field is private, so only its own module can build one; the first scan keeps that module from growing
//! a second constructor. The second scan covers the envelope field itself, which is a plain `ProvenanceValue` any code
//! could fill with `Used { id: .. }` by hand.
// ponytail: a text scan; a `Used` value built into a variable first and assigned later is not seen. Upgrade: a typed
// `RerankProvenance` field that only `retrieval::rerank` can construct.

use std::fs;
use std::path::{Path, PathBuf};

/// The production part of `source`: the text before its first `#[cfg(test)]`, whole-line `//` comments dropped.
fn production(source: &str) -> String {
    source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or(source)
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The construction sites of `RerankModelId` in `source`'s production part.
fn constructor_sites(source: &str) -> usize {
    production(source)
        .lines()
        .map(|line| {
            line.match_indices("RerankModelId(")
                .filter(|(at, _)| !line[..*at].trim_end().ends_with("struct"))
                .count()
        })
        .sum()
}

/// The places in `source`'s production part that give the `rerank_model_id` field a `ProvenanceValue::Used` value.
fn used_assignments(source: &str) -> usize {
    let code = production(source);
    code.match_indices("rerank_model_id")
        .filter(|(at, name)| {
            let rest = code[at + name.len()..].trim_start();
            rest.strip_prefix(':')
                .or_else(|| rest.strip_prefix('='))
                .map(str::trim_start)
                .is_some_and(|value| {
                    value.starts_with("ProvenanceValue::Used") || value.starts_with("Used")
                })
        })
        .count()
}

/// Every `*.rs` file under `dir`, skipping `target` and `tests` trees.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "tests" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Positive controls: the scanner counts a second constructor, does not count the definition, a comment or test code.
#[test]
fn the_scanner_counts_constructors_and_nothing_else() {
    let one = "/// RerankModelId(x) in a doc\npub struct RerankModelId(String);\nfn render() { RerankModelId(format!(\"\")) }\n";
    assert_eq!(constructor_sites(one), 1);
    let two = format!("{one}fn again() {{ RerankModelId(String::new()) }}\n");
    assert_eq!(constructor_sites(&two), 2);
    let in_tests =
        format!("{one}#[cfg(test)]\nmod tests {{ fn t() {{ RerankModelId(String::new()); }} }}\n");
    assert_eq!(
        constructor_sites(&in_tests),
        1,
        "test code is not production code"
    );
}

/// ADR-0084 D-C: exactly one construction site of the rendered id, and it is `retrieval::rerank`'s.
/// Fault: add a second `RerankModelId(..)` expression to any production file ⇒ the count is 2 ⇒ red.
#[test]
fn the_rendered_rerank_model_id_has_exactly_one_construction_site() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for tree in ["crates", "bins"] {
        rust_files(&root.join(tree), &mut files);
    }
    assert!(
        files.len() > 100,
        "the scan found only {} files",
        files.len()
    );
    let mut sites: Vec<(String, usize)> = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file).expect("a readable source file");
        let count = constructor_sites(&source);
        if count > 0 {
            sites.push((file.display().to_string(), count));
        }
    }
    assert_eq!(
        sites.iter().map(|(_, count)| count).sum::<usize>(),
        1,
        "construction sites of RerankModelId: {sites:?}"
    );
    assert!(
        sites[0].0.ends_with("crates/retrieval/src/rerank.rs"),
        "the one site is retrieval::rerank's: {sites:?}"
    );
}

/// Every production source file of the workspace's `crates/` and `bins/` trees.
fn workspace_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for tree in ["crates", "bins"] {
        rust_files(&root.join(tree), &mut files);
    }
    assert!(
        files.len() > 100,
        "the scan found only {} files",
        files.len()
    );
    files
        .into_iter()
        .map(|file| {
            let source = fs::read_to_string(&file).expect("a readable source file");
            (file.display().to_string(), source)
        })
        .collect()
}

/// Positive controls for the field scan: a `used` value assigned to the field is counted, however it is spelled or
/// wrapped; `not_applicable`, `cannot_establish`, a forwarded value, a comment and test code are not.
#[test]
fn the_field_scanner_counts_used_assignments_and_nothing_else() {
    let used = "Block { rerank_model_id: ProvenanceValue::Used { id: x } }";
    assert_eq!(used_assignments(used), 1);
    assert_eq!(
        used_assignments("b.rerank_model_id = ProvenanceValue::Used { id: x };"),
        1
    );
    assert_eq!(
        used_assignments("rerank_model_id:\n    ProvenanceValue::Used {\n id: x }"),
        1
    );
    assert_eq!(used_assignments("rerank_model_id: Used { id: x }"), 1);
    assert_eq!(
        used_assignments("rerank_model_id: ProvenanceValue::NotApplicable {}"),
        0
    );
    assert_eq!(
        used_assignments("rerank_model_id: ProvenanceValue::CannotEstablish {}"),
        0
    );
    assert_eq!(used_assignments("rerank_model_id: rerank.model.clone()"), 0);
    assert_eq!(
        used_assignments("// rerank_model_id: ProvenanceValue::Used { id: x }"),
        0
    );
    assert_eq!(
        used_assignments("rerank_model_id == ProvenanceValue::Used { id: x }"),
        0
    );
    let in_tests = format!("fn a() {{}}\n#[cfg(test)]\nmod tests {{ {used} }}");
    assert_eq!(
        used_assignments(&in_tests),
        0,
        "test code is not production code"
    );
}

/// ADR-0084 D-C: the envelope field `rerank_model_id` is given a `used` value in exactly one place in the workspace's
/// production code, and it is `retrieval::rerank`'s. The cloud route's `rerank_model_id` is held out explicitly: it is the
/// route descriptor of `retrieval-provider` (an `Option<String>` naming the cloud route's model), never provenance.
/// Fault: give the field a `ProvenanceValue::Used { .. }` value in any other production file ⇒ the count is 2 ⇒ red.
#[test]
fn the_rerank_model_id_field_is_given_a_used_value_in_exactly_one_place() {
    let mut sites: Vec<(String, usize)> = Vec::new();
    let mut router = None;
    for (file, source) in workspace_sources() {
        if file.ends_with("crates/retrieval-provider/src/router.rs") {
            router = Some(source.clone());
        }
        let count = used_assignments(&source);
        if count > 0 {
            sites.push((file, count));
        }
    }
    assert_eq!(
        sites.iter().map(|(_, count)| count).sum::<usize>(),
        1,
        "places that give rerank_model_id a used value: {sites:?}"
    );
    assert!(
        sites[0].0.ends_with("crates/retrieval/src/rerank.rs"),
        "the one place is retrieval::rerank's: {sites:?}"
    );
    let router = router.expect("the cloud route's router is in the scan");
    assert!(
        router.contains("pub rerank_model_id: Option<String>"),
        "the cloud route's rerank_model_id is a route descriptor, an Option<String>; if it became provenance, route it \
         through retrieval::rerank instead of allowlisting it"
    );
}
