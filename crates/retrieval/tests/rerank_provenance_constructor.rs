//! `retrieval::tests::rerank_provenance_constructor` — the rendered `provenance.rerank_model_id` has exactly one
//!   construction site in the workspace's production code (ADR-0084 D-C, the repo's unique-constructor rule: `== 1`).
//! Depends-on: crates=[]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[]
//! Called-by: [cargo-test]
//! Invariants: [no DB or network; the scan reads the workspace's `src/` trees under `crates/` and `bins/`; a production
//!   file is the text before its first `#[cfg(test)]`, whole-line `//` comments dropped; a construction site is a
//!   `RerankModelId(` that is not the `struct` definition, so a second constructor anywhere, in any file, turns the count
//!   to 2]
//! Spec: ADR-0084 D-C; ADR-0084 D-G; CLAUDE.md "唯一构造点模式"
//!
//! `RerankModelId`'s field is private, so only its own module can build one; the scan keeps that module from growing a
//! second constructor and keeps the type from being re-declared elsewhere with a public field.

use std::fs;
use std::path::{Path, PathBuf};

/// The construction sites of `RerankModelId` in `source`'s production part.
fn constructor_sites(source: &str) -> usize {
    let production = source.split("#[cfg(test)]").next().unwrap_or(source);
    production
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            line.match_indices("RerankModelId(")
                .filter(|(at, _)| !line[..*at].trim_end().ends_with("struct"))
                .count()
        })
        .sum()
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
