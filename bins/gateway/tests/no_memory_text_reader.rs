//! `gateway::tests::no_memory_text_reader` — nothing in the gateway's production code reads a Memory's canonical text
//!   itself (ADR-0084 D-C 3, G-RET-13): the rerank texts come only from the hydrate transaction in `adapters::retrieve`.
//! Depends-on: crates=[]; services=[]; env=[CARGO_MANIFEST_DIR]; modules=[]
//! Called-by: [cargo-test]
//! Invariants: [no DB or network; the scan reads `bins/gateway/src/` (production code, comments dropped); the readers are
//!   `memory_texts_in_txn` and the view `private.memory_text_v`, matched as whole identifiers so `memory_text_view` is not
//!   one]
//! Spec: ADR-0084 D-C 3; ADR-0085 D-C; ADR-0084 D-G
//!
//! `private.memory_text_v` applies RLS only: it does not exclude tombstoned, archived, superseded or secret-backed
//! Memories, which the hydrate gate does. A reader in the gateway could return the text of a Memory the gate refused.

use std::fs;
use std::path::{Path, PathBuf};

/// The identifiers that read a Memory's canonical text.
const READERS: [&str; 2] = ["memory_texts_in_txn", "memory_text_v"];

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// `(line number, reader)` for every reader named in `source` outside whole-line and trailing `//` comments, as a whole
/// identifier (a string literal that names the view counts: that is a query).
fn readers_named(source: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (number, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or(line);
        let bytes = code.as_bytes();
        for reader in READERS {
            for (at, _) in code.match_indices(reader) {
                let end = at + reader.len();
                let whole = (at == 0 || !is_ident_byte(bytes[at - 1]))
                    && bytes.get(end).is_none_or(|b| !is_ident_byte(*b));
                if whole {
                    found.push((number + 1, reader));
                }
            }
        }
    }
    found
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Positive controls: a call, a query naming the view and a qualified path are found; a comment, a longer identifier
/// and the type `MemoryText` are not.
#[test]
fn the_scanner_finds_readers_and_nothing_else() {
    // The view's name is assembled so that this file, which reads no table, names none (dep-map's table scan).
    let view = format!("{}.{}", "private", "memory_text_v");
    let source = format!(
        "let t = memory_texts_in_txn(&mut txn, tenant, &ids).await?;\n\
         let q = \"SELECT body FROM {view}\";\n\
         let r = humaux_adapters::memory_repo::memory_texts_in_txn;\n\
         // memory_texts_in_txn is only named in a comment\n\
         let v = memory_text_view;\n\
         use humaux_adapters::memory_repo::MemoryText;\n"
    );
    assert_eq!(
        readers_named(&source),
        [
            (1, "memory_texts_in_txn"),
            (2, "memory_text_v"),
            (3, "memory_texts_in_txn")
        ]
    );
}

/// ADR-0084 D-C 3 / G-RET-13: no production file under `bins/gateway/src` names a Memory-text reader.
/// Fault: add a call to `memory_texts_in_txn`, or a query on `private.memory_text_v`, to any gateway source ⇒ red.
#[test]
fn nothing_under_the_gateway_reads_a_memory_text() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(
        files.len() >= 10,
        "the scan found only {} files",
        files.len()
    );
    let mut offenders = Vec::new();
    for file in files {
        let source = fs::read_to_string(&file).expect("a readable source file");
        for (line, reader) in readers_named(&source) {
            offenders.push(format!("{}:{line}: {reader}", file.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "the gateway must not read a Memory's text itself; the hydrate transaction does: {offenders:?}"
    );
}
