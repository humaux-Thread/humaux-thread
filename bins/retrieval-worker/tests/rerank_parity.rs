//! `retrieval-worker::tests::rerank_parity` — G-RET-11 (ADR-0084 D-G): the Rust path (tokenizer crate, `ort`, the
//!   int8 graph on the pinned ONNX Runtime library) reproduces the public fixtures' token ids and the Python
//!   reference scores within the fixture's tolerance, including the pairs longer than `max_len`; plus the U2 / U4
//!   measurement test (`rerank_latency`, ignored).
//! Depends-on: crates=[axum, humaux-testkit, serde_json, tokio]; services=[HTTP(loopback)];
//!   env=[HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH, HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH]; modules=[humaux-testkit, retrieval-worker::rerank,
//!   retrieval-worker::rpc]
//! Called-by: [cargo-test]
//! Invariants: [the artifact paths come from the environment; a missing one is a visible SKIP naming it, or a failure
//!   under HUMAUX_REQUIRE_RERANK_MODEL=1 (§79.2); the pins are the fixture header's, so artifacts that are not the
//!   published ones fail the load; nothing is written outside the process; one test loads the model, because `ort`
//!   allows one environment per process]
//! Spec: Baseline §79.2; ADR-0084 D-A; ADR-0084 D-C; ADR-0084 D-G
//!
//! The fixture is `fixtures/rerank/parity.v1.json` (T-RET-7b). Its header says how to compare: each group is scored as
//! ONE batch (int8 dynamic quantisation makes a score depend on its batch, so the fixture's `score_int8_batch` is the
//! like-with-like reference, not `score_int8`), the tolerance is `tolerance.abs`, and the order inside a group is
//! the reference order. Run with `HUMAUX_REQUIRE_RERANK_MODEL=1` inside the pinned distroless image by the CI job
//! `rerank-parity`.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use humaux_retrieval_worker::rerank::{
    BATCH_SIZE, ModelIdentity, RerankConfig, RerankLane, Reranker,
};
use humaux_retrieval_worker::rpc::{RERANK_ROUTE, rerank_router};
use humaux_testkit::{ExternalDep, skip_or_fail};
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/rerank/parity.v1.json");
const THREADS: usize = 4;
/// U5: the parity scoring runs this many times in the job; the run-to-run spread is reported.
const PARITY_RUNS: usize = 3;

/// One fixture pair.
struct Pair {
    id: String,
    group: String,
    query: String,
    passage: String,
    ids: Vec<u32>,
    mask: Vec<u32>,
    truncated: bool,
    reference_batch: f64,
}

/// The fixture: header facts the test asserts against, and the pairs in file order.
struct Fixture {
    identity: ModelIdentity,
    max_len: usize,
    pad_id: u32,
    tolerance: f64,
    over_max_len: usize,
    pairs: Vec<Pair>,
}

fn numbers(value: &Value) -> Vec<u32> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|n| u32::try_from(n.as_u64().expect("integer")).expect("u32"))
        .collect()
}

fn text(value: &Value) -> String {
    value.as_str().expect("string").to_owned()
}

fn bare_sha(value: &Value) -> String {
    let full = text(value);
    full.strip_prefix("sha256:")
        .expect("sha256: prefix")
        .to_owned()
}

fn load_fixture() -> Fixture {
    let root: Value = serde_json::from_str(FIXTURE).expect("fixture json");
    let header = &root["header"];
    assert_eq!(header["schema"], "humaux.rerank-parity/v1");
    assert_eq!(header["encoding"]["pair_order"], "(query, passage)");
    assert_eq!(header["encoding"]["truncation"], "longest_first");
    let model = &header["model"];
    Fixture {
        identity: ModelIdentity {
            repo: text(&model["repo"]),
            revision: text(&model["revision"]),
            recipe: text(&model["recipe"]),
            onnx_sha256: bare_sha(&model["onnx_sha256"]),
            tokenizer_sha256: bare_sha(&model["tokenizer_sha256"]),
        },
        max_len: usize::try_from(header["encoding"]["max_len"].as_u64().expect("max_len"))
            .expect("usize"),
        pad_id: u32::try_from(header["encoding"]["pad_id"].as_u64().expect("pad_id")).expect("u32"),
        tolerance: header["tolerance"]["abs"].as_f64().expect("tolerance.abs"),
        over_max_len: usize::try_from(header["counts"]["over_max_len"].as_u64().expect("count"))
            .expect("usize"),
        pairs: root["pairs"]
            .as_array()
            .expect("pairs")
            .iter()
            .map(|p| Pair {
                id: text(&p["id"]),
                group: text(&p["group"]),
                query: text(&p["query"]),
                passage: text(&p["passage"]),
                ids: numbers(&p["input_ids"]),
                mask: numbers(&p["attention_mask"]),
                truncated: p["truncated"].as_bool().expect("truncated"),
                reference_batch: p["score_int8_batch"].as_f64().expect("score_int8_batch"),
            })
            .collect(),
    }
}

/// The three artifact paths, or the name of the first missing object.
fn artifact_paths() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let path = |name: &str, what: &str| -> Result<PathBuf, String> {
        let value = std::env::var(name)
            .ok()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("{what}: {name} is not set"))?;
        let path = PathBuf::from(value);
        if path.is_file() {
            Ok(path)
        } else {
            Err(format!("{what}: no file at {}", path.display()))
        }
    };
    Ok((
        path(
            "HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH",
            "the int8 rerank model",
        )?,
        path(
            "HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH",
            "the rerank tokenizer.json",
        )?,
        path(
            "HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH",
            "the ONNX Runtime library",
        )?,
    ))
}

/// Loads the lane from the artifacts named by the environment, pinned to the fixture header's identity; `None`
/// after a visible SKIP (or a failure under `HUMAUX_REQUIRE_RERANK_MODEL=1`).
fn load(test: &str, fixture: &Fixture) -> Option<Reranker> {
    let (model_path, tokenizer_path, onnxruntime_path) = match artifact_paths() {
        Ok(paths) => paths,
        Err(missing) => {
            skip_or_fail(test, &missing, ExternalDep::RerankModel);
            return None;
        }
    };
    let config = RerankConfig {
        identity: fixture.identity.clone(),
        model_path,
        tokenizer_path,
        onnxruntime_path,
    };
    Some(Reranker::load(&config, THREADS).unwrap_or_else(|error| panic!("{test}: U1: {error}")))
}

/// Indices of `scores` from the highest to the lowest.
fn order(scores: &[f64]) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..scores.len()).collect();
    indices.sort_by(|&a, &b| scores[b].total_cmp(&scores[a]));
    indices
}

/// Consecutive pairs of one group, in file order.
fn groups(fixture: &Fixture) -> Vec<&[Pair]> {
    fixture.pairs.chunk_by(|a, b| a.group == b.group).collect()
}

/// ADR-0084 D-C 3: the Rust tokenizer reproduces every pair's `input_ids` and `attention_mask` exactly, the
/// over-`max_len` pairs are cut to `max_len` and counted as the header says, and `<pad>` is the header's pad id.
fn assert_encodings(reranker: &Reranker, fixture: &Fixture) {
    assert_eq!(reranker.pad_id(), fixture.pad_id, "pad id");
    let mut cut = 0;
    for pair in &fixture.pairs {
        let (ids, mask) = reranker
            .encode_pair(&pair.query, &pair.passage, fixture.max_len)
            .expect("encode");
        assert_eq!(ids, pair.ids, "{}: input_ids", pair.id);
        assert_eq!(mask, pair.mask, "{}: attention_mask", pair.id);
        if pair.truncated {
            cut += 1;
            assert_eq!(ids.len(), fixture.max_len, "{}: cut to max_len", pair.id);
        } else {
            assert!(ids.len() <= fixture.max_len, "{}", pair.id);
        }
    }
    assert_eq!(cut, fixture.over_max_len, "pairs over max_len");
    assert!(cut > 0, "the fixture must carry over-length pairs");
}

/// The tokenizer's truncation is re-set only when `max_len` changes: the 150-token-query pair `longq-0-0` cut at 128,
/// then 256, then 128 again comes out 128, 256, 128 tokens long. Fault: make the guard in `Engine::set_max_len` return
/// once any value is set => the first change of `max_len` keeps the old cut.
fn assert_truncation_memo(reranker: &Reranker, fixture: &Fixture) {
    let pair = fixture
        .pairs
        .iter()
        .find(|p| p.id == "longq-0-0")
        .expect("the long-query pair");
    for max_len in [128, 256, 128] {
        let (ids, mask) = reranker
            .encode_pair(&pair.query, &pair.passage, max_len)
            .expect("encode");
        assert_eq!(ids.len(), max_len, "longq-0-0 cut at {max_len}");
        assert_eq!(mask.len(), max_len, "longq-0-0 mask cut at {max_len}");
    }
}

/// Scores every group as ONE batch; returns the scores in file order.
fn score_groups(reranker: &Reranker, fixture: &Fixture) -> Vec<f64> {
    let mut all = Vec::with_capacity(fixture.pairs.len());
    for group in groups(fixture) {
        let documents: Vec<String> = group.iter().map(|p| p.passage.clone()).collect();
        let scores = reranker
            .score(
                &group[0].query,
                &documents,
                fixture.max_len,
                documents.len(),
            )
            .expect("score");
        assert_eq!(
            scores.len(),
            documents.len(),
            "{}: one score per document",
            group[0].group
        );
        all.extend(scores.into_iter().map(f64::from));
    }
    all
}

/// POSTs `body` to the rerank route and returns the response body.
fn post(addr: SocketAddr, body: &Value) -> String {
    let payload = body.to_string();
    // dep: HTTP(loopback) — the rerank route served by this test on 127.0.0.1
    let mut stream = TcpStream::connect(addr).expect("connect");
    write!(
        stream,
        "POST {RERANK_ROUTE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    )
    .expect("send");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .expect("response body")
}

/// POSTs one rerank request for `documents` against `query` and returns the reply and its scores.
fn route_scores(
    addr: SocketAddr,
    fixture: &Fixture,
    query: &str,
    documents: &[&str],
) -> (Value, Vec<f64>) {
    let body = json!({
        "schema_version": 1,
        "call_id": "00000000-0000-7000-8000-000000000001",
        "query": query,
        "documents": documents,
        "max_len": fixture.max_len,
    });
    let reply: Value = serde_json::from_str(&post(addr, &body)).expect("json reply");
    assert_eq!(reply["outcome"], "scored", "{reply}");
    let scores = reply["scores"]
        .as_array()
        .expect("scores")
        .iter()
        .map(|s| s.as_f64().expect("number"))
        .collect();
    (reply, scores)
}

fn assert_close(got: &[f64], want: &[f64], what: &str) {
    assert_eq!(got.len(), want.len(), "{what}: score count");
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        assert!((g - w).abs() <= 1e-6, "{what} {i}: {g} against {w}");
    }
}

/// The production path end to end: the real route over a loopback port with the loaded lane scores the first group
/// (one batch, like the direct call), reports the pinned identity, and answers eleven documents (a batch of 8 and a
/// batch of 3) with the two batches' scores in request order.
fn assert_route(lane: RerankLane, fixture: &Fixture, expected: &[f64]) {
    let reranker = Arc::clone(lane.reranker().expect("the lane is enabled"));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            axum::serve(listener, rerank_router::<()>(lane))
                .await
                .expect("serve");
        });
    });
    let group = groups(fixture)[0];
    assert!(
        group.len() <= BATCH_SIZE,
        "the first group is one worker batch"
    );
    let documents: Vec<&str> = group.iter().map(|p| p.passage.as_str()).collect();
    let (reply, routed) = route_scores(addr, fixture, &group[0].query, &documents);
    assert_close(&routed, expected, "route group");
    assert_eq!(reply["model"]["repo"], fixture.identity.repo);
    assert_eq!(reply["model"]["onnx_sha256"], fixture.identity.onnx_sha256);
    assert_eq!(
        reply["model"]["tokenizer_sha256"],
        fixture.identity.tokenizer_sha256
    );

    // More than one worker batch: the route's scores are the first 8 documents' batch followed by the last 3's, in
    // request order (a reversed or re-ordered chunk-extend would break this).
    let query = fixture.pairs[0].query.as_str();
    let many: Vec<&str> = fixture
        .pairs
        .iter()
        .take(BATCH_SIZE + 3)
        .map(|p| p.passage.as_str())
        .collect();
    let owned: Vec<String> = many.iter().map(|d| (*d).to_owned()).collect();
    let mut per_batch: Vec<f64> = Vec::new();
    for chunk in owned.chunks(BATCH_SIZE) {
        let scores = reranker
            .score(query, chunk, fixture.max_len, chunk.len())
            .expect("per-batch score");
        per_batch.extend(scores.into_iter().map(f64::from));
    }
    let (_, routed_many) = route_scores(addr, fixture, query, &many);
    assert_eq!(routed_many.len(), BATCH_SIZE + 3);
    assert_close(&routed_many, &per_batch, "route eleven documents");
}

/// G-RET-11: token ids identical, scores within `tolerance.abs` of `score_int8_batch`, group order equal to the
/// reference order, over-length pairs present; U1 (max |Δ| against the reference) and U5 (run-to-run spread of
/// three runs) are printed for the report. Faults: encode (document, query) => the ids differ; skip the truncation
/// (or use `only_second`) => the over-length and `longq-0-0` ids differ.
#[test]
fn rust_path_matches_the_python_reference_scores() {
    let test = "rust_path_matches_the_python_reference_scores";
    let fixture = load_fixture();
    let Some(reranker) = load(test, &fixture) else {
        return;
    };
    assert_eq!(reranker.identity(), &fixture.identity);
    // The fixture and its header, so the loops below cannot pass over a shrunken or loosened input.
    assert!(
        fixture.tolerance <= 1e-4,
        "tolerance.abs {} is looser than 1e-4",
        fixture.tolerance
    );
    assert_eq!(fixture.pairs.len(), 54, "pairs");
    assert_eq!(groups(&fixture).len(), 16, "groups");
    assert_encodings(&reranker, &fixture);
    assert_truncation_memo(&reranker, &fixture);

    let runs: Vec<Vec<f64>> = (0..PARITY_RUNS)
        .map(|_| score_groups(&reranker, &fixture))
        .collect();
    let reference: Vec<f64> = fixture.pairs.iter().map(|p| p.reference_batch).collect();
    let mut max_delta = 0.0_f64;
    for scores in &runs {
        assert_eq!(scores.len(), reference.len(), "one score per fixture pair");
        for (pair, (got, want)) in fixture.pairs.iter().zip(scores.iter().zip(&reference)) {
            let delta = (got - want).abs();
            max_delta = max_delta.max(delta);
            assert!(
                delta <= fixture.tolerance,
                "{}: score {got} against reference {want} (tolerance {})",
                pair.id,
                fixture.tolerance
            );
        }
    }
    let mut spread = 0.0_f64;
    for run in &runs[1..] {
        for (a, b) in runs[0].iter().zip(run) {
            spread = spread.max((a - b).abs());
        }
    }
    let mut start = 0;
    for group in groups(&fixture) {
        let end = start + group.len();
        assert_eq!(
            order(&runs[0][start..end]),
            order(&reference[start..end]),
            "{}: order against the reference",
            group[0].group
        );
        start = end;
    }
    println!(
        "G-RET-11 U1 pairs={} groups={} over_max_len={} max_abs_delta={max_delta:e} \
         U5 runs={PARITY_RUNS} run_to_run_max_abs={spread:e} tolerance_abs={:e}",
        fixture.pairs.len(),
        groups(&fixture).len(),
        fixture.over_max_len,
        fixture.tolerance
    );
    let first = groups(&fixture)[0].len();
    assert_route(RerankLane::enabled(reranker), &fixture, &runs[0][..first]);
}

/// `VmRSS` in kB from `/proc/self/status`.
fn vm_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmRSS:"))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

/// The value at `quantile` (nearest rank) of ascending `sorted`.
fn nearest_rank(sorted: &[f64], quantile: f64) -> f64 {
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// U2 (N2 runner only) and U4: one depth-25 call at `max_len` 256 on 4 threads in batches of 8, 2 warm-ups then 20
/// timed calls, p50 and p95, and `VmRSS` after the load and after the calls. The documents are fixture passages
/// (the over-length ones first, as 61.5% of the E-RET-5g pairs reached the cap), all public.
#[test]
#[ignore = "lane(c) ADR-0084 U2/U4 latency and memory measurement on the pinned artifacts; run only by the rerank-parity CI job (HUMAUX_REQUIRE_RERANK_MODEL=1 cargo test --test rerank_parity -- --ignored --nocapture), never in a lane"]
fn rerank_latency() {
    let test = "rerank_latency";
    let fixture = load_fixture();
    let Some(reranker) = load(test, &fixture) else {
        return;
    };
    let rss_loaded = vm_rss_kb();
    let query = fixture.pairs[0].query.clone();
    // 16 of 25 documents reach the cap (E-RET-5g: 61.5% of the pairs did): the over-length passages cycled, then the
    // longest ones that fit.
    let over: Vec<&Pair> = fixture.pairs.iter().filter(|p| p.truncated).collect();
    let mut fitting: Vec<&Pair> = fixture.pairs.iter().filter(|p| !p.truncated).collect();
    fitting.sort_by_key(|p| std::cmp::Reverse(p.ids.len()));
    let documents: Vec<String> = over
        .iter()
        .cycle()
        .take(16)
        .chain(fitting.iter().cycle().take(9))
        .map(|p| p.passage.clone())
        .collect();
    let lengths: Vec<usize> = documents
        .iter()
        .map(|d| {
            reranker
                .encode_pair(&query, d, fixture.max_len)
                .map_or(0, |(ids, _)| ids.len())
        })
        .collect();
    let capped = lengths.iter().filter(|&&n| n == fixture.max_len).count();
    let mean_tokens = lengths.iter().sum::<usize>() as f64 / lengths.len() as f64;
    for _ in 0..2 {
        reranker
            .score(&query, &documents, fixture.max_len, BATCH_SIZE)
            .expect("warm-up");
    }
    let mut seconds: Vec<f64> = (0..20)
        .map(|_| {
            let started = Instant::now();
            reranker
                .score(&query, &documents, fixture.max_len, BATCH_SIZE)
                .expect("timed call");
            started.elapsed().as_secs_f64()
        })
        .collect();
    seconds.sort_by(f64::total_cmp);
    println!(
        "U2 rerank_latency depth=25 max_len={} batch={BATCH_SIZE} threads={THREADS} reps=20 capped_pairs={capped}/25 mean_pair_tokens={mean_tokens:.1} \
         p50_s={:.3} p95_s={:.3} U4 vmrss_after_load_kb={rss_loaded} vmrss_after_calls_kb={}",
        fixture.max_len,
        nearest_rank(&seconds, 0.50),
        nearest_rank(&seconds, 0.95),
        vm_rss_kb()
    );
}
