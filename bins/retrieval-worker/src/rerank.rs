//! `retrieval-worker::rerank` — the local rerank engine of ADR-0084: the pinned-artifact check, the tokenizer, the ONNX
//!   Runtime session, and the batched scoring of (query, document) pairs into raw logits.
//! Depends-on: crates=[humaux-contracts, ort, serde, sha2, tokenizers]; services=[];
//!   env=[HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH, HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_SHA256, HUMAUX_RETRIEVAL_WORKER_RERANK_RECIPE,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_REPO, HUMAUX_RETRIEVAL_WORKER_RERANK_REVISION,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH, HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_SHA256];
//!   modules=[contracts::retrieval_config]
//! Called-by: [retrieval-worker::main, retrieval-worker::rpc, tests]
//! Invariants: [the model and tokenizer files are sha256-checked against the deployment pin before ONNX Runtime is
//!   loaded, and a mismatch is an error that names the object (G-RET-14); one session sits behind one mutex; a score is
//!   the raw logit, one per document in request order, and a call returns every score or an error; no request text
//!   reaches an error message or a log line]
//! Spec: Baseline §41.4; §78.1; ADR-0084 D-A; ADR-0084 D-B; ADR-0084 D-C; ADR-0084 D-E
//!
//! ADR-0084 D-B: only `--serve-rpc` calls [`boot`], and only when the registry's `rerank_enabled` is true; every other
//! mode never reads these keys and never loads ONNX Runtime. The library path is handed to `ort::init_from`
//! explicitly (no `ORT_DYLIB_PATH` default, no download). `ort` allows one environment per process, so a process holds
//! at most one [`Reranker`].
//!
//! ADR-0084 D-C 3 and 4: each pair is encoded (query, document) with the tokenizer's own `longest_first` truncation at
//! `max_len` (special tokens counted); pairs are batched in request order, each batch padded to its own longest pair
//! with the tokenizer's `<pad>` id and mask 0. §41.4: this path never calls `seal_query` or `seal_card`; the lane is
//! in-Cell text processing, not an egress.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use humaux_contracts::retrieval_config::{
    RERANK_ENABLED, RERANK_THREADS, RegisteredRetrievalProfile,
    resolve_registered_retrieval_profile,
};
use ort::session::Session;
use ort::value::{Tensor, TensorElementType};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;
use tokenizers::utils::truncation::{TruncationDirection, TruncationParams, TruncationStrategy};

/// ADR-0084 D-C 4: pairs per ONNX Runtime run, the shape the N1 numbers were measured with.
pub const BATCH_SIZE: usize = 8;

/// The first graph input an XLM-R sequence classifier export carries.
const INPUT_IDS: &str = "input_ids";
/// The second graph input of the same export.
const ATTENTION_MASK: &str = "attention_mask";

/// The pair template `<s> A </s> </s> B </s>` adds four special tokens (V8); the tokenizer subtracts them from
/// `max_len` before truncating, so a `max_len` at or under this number would underflow inside the crate.
const PAIR_SPECIAL_TOKENS: usize = 4;
/// The smallest `max_len` a call may carry: the four special tokens and one content token.
pub const MIN_MAX_LEN: usize = PAIR_SPECIAL_TOKENS + 1;

const KEY_REPO: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_REPO";
const KEY_REVISION: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_REVISION";
const KEY_RECIPE: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_RECIPE";
const KEY_MODEL_PATH: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH";
const KEY_MODEL_SHA256: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_SHA256";
const KEY_TOKENIZER_PATH: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH";
const KEY_TOKENIZER_SHA256: &str = "HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_SHA256";
const KEY_ONNXRUNTIME_PATH: &str = "HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH";

/// ADR-0084 D-A: the model identity `(repo, revision, recipe, onnx sha256, tokenizer sha256)`, reported on every
/// reply so the gateway's single constructor can render `provenance.rerank_model_id`. The hashes are lowercase hex
/// without a prefix, exactly as the deployment keys hold them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelIdentity {
    /// The Hugging Face repository the model was exported from.
    pub repo: String,
    /// The repository revision (commit) of that export.
    pub revision: String,
    /// The recipe version that quantised it.
    pub recipe: String,
    /// sha256 of the int8 `.onnx` file.
    pub onnx_sha256: String,
    /// sha256 of the `tokenizer.json` file.
    pub tokenizer_sha256: String,
}

/// ADR-0084 D-E: the deployment configuration of the lane (the pin is not in the registry), read only when the
/// registry turns the lane on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RerankConfig {
    /// The identity the files must be (the reported one).
    pub identity: ModelIdentity,
    /// The int8 `.onnx` file.
    pub model_path: PathBuf,
    /// The `tokenizer.json` file.
    pub tokenizer_path: PathBuf,
    /// The `libonnxruntime.so` loaded by explicit path.
    pub onnxruntime_path: PathBuf,
}

impl RerankConfig {
    /// Reads the eight deployment keys through `lookup`. A missing or empty key is an error naming the key; a hash
    /// that is not 64 hex characters is an error naming its key.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let get = |name: &str| -> Result<String, String> {
            lookup(name)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("missing required configuration: {name}"))
        };
        let sha256 = |name: &str| -> Result<String, String> {
            let value = get(name)?;
            if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
                Ok(value.to_ascii_lowercase())
            } else {
                Err(format!(
                    "invalid configuration: {name} (64 hexadecimal characters)"
                ))
            }
        };
        Ok(Self {
            identity: ModelIdentity {
                repo: get(KEY_REPO)?,
                revision: get(KEY_REVISION)?,
                recipe: get(KEY_RECIPE)?,
                onnx_sha256: sha256(KEY_MODEL_SHA256)?,
                tokenizer_sha256: sha256(KEY_TOKENIZER_SHA256)?,
            },
            model_path: get(KEY_MODEL_PATH)?.into(),
            tokenizer_path: get(KEY_TOKENIZER_PATH)?.into(),
            onnxruntime_path: get(KEY_ONNXRUNTIME_PATH)?.into(),
        })
    }
}

/// The environment key a registry entry reaches the worker under, the gateway's rule with the worker's prefix:
/// `retrieval.profile.rerank_enabled` becomes `HUMAUX_RETRIEVAL_WORKER_RETRIEVAL_PROFILE_RERANK_ENABLED`.
fn profile_env_key(registry_name: &str) -> String {
    format!(
        "HUMAUX_RETRIEVAL_WORKER_{}",
        registry_name.replace('.', "_").to_ascii_uppercase()
    )
}

/// ADR-0084 D-E: the worker's own registry read. Only the two entries that act inside the worker
/// (`rerank_enabled`: load the model or not; `rerank_threads`: the session build) can be set, each from its
/// [`profile_env_key`] and optional; the other entries keep the registry default, and the registry bounds-checks every
/// value. The defaults live in the registry and nowhere else (§78.1).
pub fn rerank_profile(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<RegisteredRetrievalProfile, String> {
    let mut raw = BTreeMap::new();
    for registry_name in [RERANK_ENABLED, RERANK_THREADS] {
        if let Some(value) = lookup(&profile_env_key(registry_name)).filter(|v| !v.is_empty()) {
            raw.insert(registry_name.to_owned(), value);
        }
    }
    resolve_registered_retrieval_profile(&raw)
        .map_err(|error| format!("invalid configuration: retrieval profile: {error}"))
}

/// Lowercase hex of the sha256 of the file at `path`, streamed.
fn file_sha256(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

/// G-RET-14 (ADR-0084 D-A): the file at `path` must hash to `expected_sha256` (lowercase hex). The error names the
/// object (`rerank model` or `rerank tokenizer`), the expected and the actual hash.
pub fn verify_pinned(object: &str, path: &Path, expected_sha256: &str) -> Result<(), String> {
    let actual = file_sha256(path)
        .map_err(|error| format!("{object}: cannot read {}: {error}", path.display()))?;
    if actual != expected_sha256 {
        return Err(format!(
            "{object}: sha256 mismatch: expected {expected_sha256}, actual {actual} ({})",
            path.display()
        ));
    }
    Ok(())
}

/// An `ort` error as a message; ONNX Runtime errors never carry request text.
fn ort_error<R>(error: ort::Error<R>) -> String {
    format!("onnxruntime: {error}")
}

/// ADR-0084 D-B: the graph must be what an XLM-R sequence classifier exports: inputs `input_ids` and
/// `attention_mask` (int64) and one float `[batch, 1]` output. Anything else is a boot refusal.
fn check_graph(session: &Session) -> Result<(), String> {
    let inputs = session.inputs();
    let mut names: Vec<&str> = inputs.iter().map(|outlet| outlet.name()).collect();
    names.sort_unstable();
    if names != [ATTENTION_MASK, INPUT_IDS] {
        return Err(format!(
            "rerank model: the graph inputs must be {ATTENTION_MASK} and {INPUT_IDS}, found {names:?}"
        ));
    }
    if inputs
        .iter()
        .any(|outlet| outlet.dtype().tensor_type() != Some(TensorElementType::Int64))
    {
        return Err("rerank model: the graph inputs must be int64 tensors".to_owned());
    }
    let outputs = session.outputs();
    let [output] = outputs else {
        return Err(format!(
            "rerank model: the graph must have exactly one output, found {}",
            outputs.len()
        ));
    };
    let shape_ok = output
        .dtype()
        .tensor_shape()
        .is_some_and(|shape| shape.len() == 2 && shape[1] == 1);
    if output.dtype().tensor_type() != Some(TensorElementType::Float32) || !shape_ok {
        return Err(
            "rerank model: the graph output must be a float32 [batch, 1] tensor".to_owned(),
        );
    }
    Ok(())
}

/// The tokenizer and the session, mutated together under one lock.
#[derive(Debug)]
struct Engine {
    tokenizer: Tokenizer,
    /// The `max_len` the tokenizer's truncation is set to (`None` before the first call). Truncation needs `&mut`,
    /// so it is re-set only when a call carries another value instead of cloning a 17 MB tokenizer per call.
    truncation_max_len: Option<usize>,
    session: Session,
}

impl Engine {
    /// Points the tokenizer's `longest_first` truncation at `max_len` (special tokens counted).
    fn set_max_len(&mut self, max_len: usize) -> Result<(), String> {
        if self.truncation_max_len == Some(max_len) {
            return Ok(());
        }
        self.tokenizer
            .with_truncation(Some(TruncationParams {
                direction: TruncationDirection::Right,
                max_length: max_len,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
            }))
            .map_err(|error| format!("rerank tokenizer: {error}"))?;
        self.truncation_max_len = Some(max_len);
        Ok(())
    }

    /// Encodes one pair as (query, document); returns the unpadded `input_ids` and `attention_mask`.
    fn encode(&self, query: &str, document: &str) -> Result<(Vec<u32>, Vec<u32>), String> {
        let encoding = self
            .tokenizer
            .encode((query, document), true)
            .map_err(|error| format!("rerank tokenizer: {error}"))?;
        Ok((
            encoding.get_ids().to_vec(),
            encoding.get_attention_mask().to_vec(),
        ))
    }

    /// One ONNX Runtime run over `documents` as a single batch padded to its longest pair.
    fn run_batch(
        &mut self,
        query: &str,
        documents: &[String],
        pad_id: i64,
    ) -> Result<Vec<f32>, String> {
        let pairs = documents
            .iter()
            .map(|document| self.encode(query, document))
            .collect::<Result<Vec<_>, _>>()?;
        let longest = pairs.iter().map(|(ids, _)| ids.len()).max().unwrap_or(0);
        let mut flat_ids = Vec::with_capacity(pairs.len() * longest);
        let mut flat_mask = Vec::with_capacity(pairs.len() * longest);
        for (ids, mask) in &pairs {
            let padding = longest - ids.len();
            flat_ids.extend(ids.iter().map(|&id| i64::from(id)));
            flat_ids.extend(std::iter::repeat_n(pad_id, padding));
            flat_mask.extend(mask.iter().map(|&bit| i64::from(bit)));
            flat_mask.extend(std::iter::repeat_n(0_i64, padding));
        }
        let rows = pairs.len();
        let ids = Tensor::from_array(([rows, longest], flat_ids)).map_err(ort_error)?;
        let mask = Tensor::from_array(([rows, longest], flat_mask)).map_err(ort_error)?;
        let outputs = self
            .session
            .run(ort::inputs![INPUT_IDS => ids, ATTENTION_MASK => mask])
            .map_err(ort_error)?;
        let (shape, logits) = outputs[0].try_extract_tensor::<f32>().map_err(ort_error)?;
        if shape.len() != 2 || logits.len() != rows {
            return Err(format!(
                "rerank model: expected {rows} scores, the output holds {} values",
                logits.len()
            ));
        }
        Ok(logits.to_vec())
    }
}

/// The loaded lane: the pinned identity, the `<pad>` id, and the tokenizer plus session behind one mutex.
// ponytail: one session behind a mutex serialises concurrent recalls; a session pool if concurrent rerank load is measured
#[derive(Debug)]
pub struct Reranker {
    identity: ModelIdentity,
    pad_id: u32,
    engine: Mutex<Engine>,
}

impl Reranker {
    /// ADR-0084 D-B: verifies both files against the pin (G-RET-14, before ONNX Runtime is touched), loads the
    /// tokenizer, loads the library from `config.onnxruntime_path`, builds the session with `intra_op = threads` and
    /// `inter_op = 1`, and checks the graph. Every failure is an error message for a boot refusal.
    pub fn load(config: &RerankConfig, threads: usize) -> Result<Self, String> {
        verify_pinned(
            "rerank model",
            &config.model_path,
            &config.identity.onnx_sha256,
        )?;
        verify_pinned(
            "rerank tokenizer",
            &config.tokenizer_path,
            &config.identity.tokenizer_sha256,
        )?;
        let tokenizer = Tokenizer::from_file(&config.tokenizer_path).map_err(|error| {
            format!(
                "rerank tokenizer: cannot load {}: {error}",
                config.tokenizer_path.display()
            )
        })?;
        let pad_id = tokenizer
            .token_to_id("<pad>")
            .ok_or_else(|| "rerank tokenizer: the vocabulary has no <pad> token".to_owned())?;
        let environment = ort::init_from(&config.onnxruntime_path)
            .map_err(|error| {
                format!(
                    "onnxruntime library {}: {error}",
                    config.onnxruntime_path.display()
                )
            })?
            .with_name("humaux-rerank")
            .with_telemetry(false)
            .build()
            .map_err(ort_error)?;
        let mut builder = Session::builder(&environment)
            .map_err(ort_error)?
            .with_intra_threads(threads)
            .map_err(ort_error)?
            .with_inter_threads(1)
            .map_err(ort_error)?;
        let session = builder
            .commit_from_file(&config.model_path)
            .map_err(ort_error)?;
        check_graph(&session)?;
        Ok(Self {
            identity: config.identity.clone(),
            pad_id,
            engine: Mutex::new(Engine {
                tokenizer,
                truncation_max_len: None,
                session,
            }),
        })
    }

    /// The pinned identity this lane reports.
    #[must_use]
    pub fn identity(&self) -> &ModelIdentity {
        &self.identity
    }

    /// The tokenizer's `<pad>` id (1 for XLM-R).
    #[must_use]
    pub fn pad_id(&self) -> u32 {
        self.pad_id
    }

    /// The unpadded `input_ids` and `attention_mask` of the pair (query, document) cut at `max_len`
    /// (ADR-0084 D-C 3). G-RET-11 compares these with the fixtures.
    pub fn encode_pair(
        &self,
        query: &str,
        document: &str,
        max_len: usize,
    ) -> Result<(Vec<u32>, Vec<u32>), String> {
        let mut engine = self.lock()?;
        engine.set_max_len(max_len)?;
        engine.encode(query, document)
    }

    /// ADR-0084 D-C 3 and 4: the raw logit of each (query, document) pair, in `documents` order, computed in batches
    /// of `batch_size` (the worker passes [`BATCH_SIZE`]; G-RET-11 passes the fixture's group size). All or nothing:
    /// one failed batch fails the call. Blocking; async callers use `spawn_blocking`.
    pub fn score(
        &self,
        query: &str,
        documents: &[String],
        max_len: usize,
        batch_size: usize,
    ) -> Result<Vec<f32>, String> {
        let pad_id = i64::from(self.pad_id);
        let mut engine = self.lock()?;
        engine.set_max_len(max_len)?;
        let mut scores = Vec::with_capacity(documents.len());
        for batch in documents.chunks(batch_size.max(1)) {
            scores.extend(engine.run_batch(query, batch, pad_id)?);
        }
        Ok(scores)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Engine>, String> {
        self.engine
            .lock()
            .map_err(|_| "rerank engine: a previous call panicked; restart the worker".to_owned())
    }
}

/// What the RPC route serves with: no model (the registry turned the lane off) or the loaded lane.
#[derive(Debug, Clone)]
pub struct RerankLane(Option<Arc<Reranker>>);

impl RerankLane {
    /// The lane switched off: the route answers `disabled`.
    #[must_use]
    pub fn disabled() -> Self {
        Self(None)
    }

    /// The lane with its model loaded.
    #[must_use]
    pub fn enabled(reranker: Reranker) -> Self {
        Self(Some(Arc::new(reranker)))
    }

    /// The loaded lane, or `None` when disabled.
    #[must_use]
    pub fn reranker(&self) -> Option<&Arc<Reranker>> {
        self.0.as_ref()
    }
}

/// ADR-0084 D-B boot of `--serve-rpc`: reads the registry's `rerank_enabled` and `rerank_threads`; with the lane off
/// nothing else is read and no model is loaded; with it on, the deployment keys are read and [`Reranker::load`] runs.
/// The error is a boot refusal message.
pub fn boot(lookup: impl Fn(&str) -> Option<String>) -> Result<RerankLane, String> {
    let profile = rerank_profile(&lookup)?;
    if !profile.rerank_enabled() {
        return Ok(RerankLane::disabled());
    }
    let config = RerankConfig::from_lookup(&lookup)?;
    let threads = usize::try_from(profile.rerank_threads())
        .map_err(|_| "invalid configuration: rerank_threads".to_owned())?;
    Reranker::load(&config, threads).map(RerankLane::enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// sha256 of the three bytes `abc` (FIPS 180-4 appendix B).
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const OTHER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn deployment(model_sha: &str, tokenizer_sha: &str) -> HashMap<String, String> {
        [
            (KEY_REPO, "cross-encoder/example"),
            (KEY_REVISION, "rev1"),
            (KEY_RECIPE, "recipe-v1"),
            (KEY_MODEL_PATH, "/nonexistent/model.onnx"),
            (KEY_MODEL_SHA256, model_sha),
            (KEY_TOKENIZER_PATH, "/nonexistent/tokenizer.json"),
            (KEY_TOKENIZER_SHA256, tokenizer_sha),
            (KEY_ONNXRUNTIME_PATH, "/nonexistent/libonnxruntime.so"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }

    /// A file holding `abc` under the temp directory, removed by the caller.
    fn abc_file(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "humaux_rerank_unit_{tag}_{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, b"abc").expect("write the fixture file");
        path
    }

    /// ADR-0084 D-E: every deployment key is required with no default, an empty value is missing, and a malformed
    /// hash is refused; each refusal names its key. Fault: default a key (`.unwrap_or_default()`) => its row is red.
    #[test]
    fn config_refuses_each_missing_or_malformed_key() {
        let full = deployment(ABC_SHA256, ABC_SHA256);
        let config = RerankConfig::from_lookup(|name| full.get(name).cloned()).expect("full");
        assert_eq!(config.identity.onnx_sha256, ABC_SHA256);
        for key in full.keys() {
            for empty in [false, true] {
                let mut env = full.clone();
                if empty {
                    env.insert(key.clone(), String::new());
                } else {
                    env.remove(key);
                }
                let error = RerankConfig::from_lookup(|name| env.get(name).cloned())
                    .expect_err("a missing or empty key is refused");
                assert!(error.contains(key.as_str()), "{key}: {error}");
            }
        }
        for key in [KEY_MODEL_SHA256, KEY_TOKENIZER_SHA256] {
            let mut env = full.clone();
            env.insert(key.to_owned(), "abc".to_owned());
            let error = RerankConfig::from_lookup(|name| env.get(name).cloned())
                .expect_err("a short hash is refused");
            assert!(error.contains(key), "{key}: {error}");
        }
    }

    /// ADR-0084 D-D / G-RET-14 (function half): a file whose hash differs from the pin is an error naming the object
    /// with both hashes; the matching hash passes. Fault: skip the comparison => the mismatch row is red.
    #[test]
    fn verify_pinned_names_the_object_on_a_mismatch() {
        let path = abc_file("pin");
        assert!(verify_pinned("rerank model", &path, ABC_SHA256).is_ok());
        let error = verify_pinned("rerank tokenizer", &path, OTHER_SHA256)
            .expect_err("a different pin is refused");
        std::fs::remove_file(&path).expect("remove the fixture file");
        assert!(
            error.starts_with("rerank tokenizer: sha256 mismatch"),
            "{error}"
        );
        assert!(
            error.contains(OTHER_SHA256) && error.contains(ABC_SHA256),
            "{error}"
        );
        let missing = verify_pinned("rerank model", Path::new("/nonexistent/x"), ABC_SHA256)
            .expect_err("an unreadable file is refused");
        assert!(
            missing.starts_with("rerank model: cannot read"),
            "{missing}"
        );
    }

    /// ADR-0084 D-B: with the registry's `rerank_enabled` false (the default) nothing else is read and the lane is
    /// disabled; true reads the deployment keys (a missing key is named) and refuses a wrong pin before ONNX Runtime
    /// is touched (the library path in this fixture does not exist, so reaching it would name the library instead).
    #[test]
    fn boot_reads_the_deployment_keys_only_when_enabled() {
        assert!(
            boot(|_| None)
                .expect("disabled by default")
                .reranker()
                .is_none()
        );

        let enabled_key = profile_env_key(RERANK_ENABLED);
        // The key operators set: the worker prefix plus the registry name's upper-cased form (built in two pieces so
        // this test names no environment variable the module does not read).
        assert_eq!(
            enabled_key,
            format!(
                "HUMAUX_RETRIEVAL_WORKER_{}",
                "RETRIEVAL_PROFILE_RERANK_ENABLED"
            )
        );
        let on = |name: &str| (name == enabled_key).then(|| "true".to_owned());
        let error = boot(on).expect_err("enabled without the pin is refused");
        assert!(error.contains(KEY_REPO), "{error}");

        let path = abc_file("boot");
        let mut env = deployment(OTHER_SHA256, ABC_SHA256);
        env.insert(KEY_MODEL_PATH.to_owned(), path.display().to_string());
        env.insert(enabled_key.clone(), "true".to_owned());
        let error = boot(|name| env.get(name).cloned()).expect_err("a wrong model pin is refused");
        std::fs::remove_file(&path).expect("remove the fixture file");
        assert!(
            error.starts_with("rerank model: sha256 mismatch"),
            "{error}"
        );
    }

    /// ADR-0084 D-E: the worker's registry read accepts the two keys it acts on, refuses an out-of-bounds value
    /// through the registry's own error, and leaves the other entries at their registry defaults.
    #[test]
    fn rerank_profile_applies_the_registry_bounds() {
        let threads_key = profile_env_key(RERANK_THREADS);
        let profile = rerank_profile(|name| (name == threads_key).then(|| "2".to_owned()))
            .expect("two threads");
        assert_eq!(profile.rerank_threads(), 2);
        assert!(!profile.rerank_enabled());
        let error = rerank_profile(|name| (name == threads_key).then(|| "0".to_owned()))
            .expect_err("zero threads is refused");
        assert!(error.contains("rerank_threads"), "{error}");
    }
}
