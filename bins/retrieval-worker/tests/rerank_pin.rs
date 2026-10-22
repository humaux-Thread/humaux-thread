//! `retrieval-worker::tests::rerank_pin` — G-RET-14 (ADR-0084 D-G): `humaux-retrieval-worker --serve-rpc` with the
//!   registry's `rerank_enabled` true refuses to start, before any connection is opened and before the socket binds,
//!   when the model or the tokenizer file differs from the pinned sha256, and names the object.
//! Depends-on: crates=[humaux-testkit, sha2]; services=[subprocess(humaux-retrieval-worker)];
//!   env=[CARGO_BIN_EXE_humaux-retrieval-worker, HUMAUX_RETRIEVAL_WORKER_DIMENSION,
//!   HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MODEL, HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID,
//!   HUMAUX_RETRIEVAL_WORKER_MODEL_REVISION, HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH, HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_SHA256,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_RECIPE, HUMAUX_RETRIEVAL_WORKER_RERANK_REPO,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_REVISION, HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH,
//!   HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_SHA256, HUMAUX_RETRIEVAL_WORKER_RETRIEVAL_PROFILE_RERANK_ENABLED,
//!   HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH, HUMAUX_RETRIEVAL_WORKER_SERVE_RPC_METRICS_ADDR]; modules=[testkit::reaped]
//! Called-by: [cargo-test]
//! Invariants: [every humaux-retrieval-worker spawn runs with a cleared environment and closed stdin and exits on its
//!   own (it is refused before it could connect or serve) under a 60 s deadline, owned by a Reaped; the two artifact
//!   files are small placeholders under the test's own temp directory, removed on drop; ONNX Runtime is never
//!   loaded, so the test needs no artifact and runs in every lane]
//! Spec: Baseline §79.2; ADR-0084 D-A; ADR-0084 D-B; ADR-0084 D-G
//!
//! The spawn gets neither `HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH` nor a database DSN: a refusal that names the
//! rerank object therefore proves the check runs before the first key the rest of the boot needs (the socket bind).

use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use humaux_testkit::reaped::SpawnReaped as _;
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_humaux-retrieval-worker");

/// Lowercase hex of the sha256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// A scratch directory holding the two placeholder artifacts; removed on drop, even on a panic.
struct Scratch(PathBuf);

impl Scratch {
    const MODEL: &'static [u8] = b"placeholder model bytes";
    const TOKENIZER: &'static [u8] = b"placeholder tokenizer bytes";

    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("humaux_g_ret_14_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the scratch directory");
        std::fs::write(dir.join("model.onnx"), Self::MODEL).expect("write the model");
        std::fs::write(dir.join("tokenizer.json"), Self::TOKENIZER).expect("write the tokenizer");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The pinned hashes a spawn is given: each is the real hash of its placeholder, or the hash of other bytes.
struct Pins {
    model: String,
    tokenizer: String,
}

impl Pins {
    fn correct() -> Self {
        Self {
            model: sha256_hex(Scratch::MODEL),
            tokenizer: sha256_hex(Scratch::TOKENIZER),
        }
    }
}

/// `--serve-rpc` with the configuration it reads before the rerank boot, the lane switched on or off through the
/// registry key, and the deployment pin `pins` over `scratch`'s files. Returns the exit code and stderr.
fn serve_rpc(
    scratch: &Scratch,
    pins: &Pins,
    enabled: Option<&str>,
    drop_key: Option<&str>,
) -> (Option<i32>, String) {
    let ops = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        listener.local_addr().expect("addr").to_string()
    };
    let model_path = scratch.0.join("model.onnx").display().to_string();
    let tokenizer_path = scratch.0.join("tokenizer.json").display().to_string();
    let missing_runtime = scratch
        .0
        .join("no-such-libonnxruntime.so")
        .display()
        .to_string();
    let mut env: Vec<(&str, String)> = vec![
        ("HUMAUX_RETRIEVAL_WORKER_SERVE_RPC_METRICS_ADDR", ops),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_MODEL",
            "text-embedding-v4".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_MODEL_REVISION",
            "2026-08".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_DIMENSION", "1024".to_owned()),
        (
            "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID",
            "4000000000".to_owned(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_RERANK_REPO",
            "cross-encoder/example".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_RERANK_REVISION", "rev1".to_owned()),
        (
            "HUMAUX_RETRIEVAL_WORKER_RERANK_RECIPE",
            "recipe-v1".to_owned(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_PATH", model_path),
        (
            "HUMAUX_RETRIEVAL_WORKER_RERANK_MODEL_SHA256",
            pins.model.clone(),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_PATH",
            tokenizer_path,
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_RERANK_TOKENIZER_SHA256",
            pins.tokenizer.clone(),
        ),
        ("HUMAUX_RETRIEVAL_WORKER_ONNXRUNTIME_PATH", missing_runtime),
    ];
    if let Some(value) = enabled {
        env.push((
            "HUMAUX_RETRIEVAL_WORKER_RETRIEVAL_PROFILE_RERANK_ENABLED",
            value.to_owned(),
        ));
    }
    if let Some(key) = drop_key {
        env.retain(|(name, _)| *name != key);
    }
    // dep: subprocess(humaux-retrieval-worker) — the binary under test, bounded and reaped (ADR-0063 "Chain stall")
    let mut child = Command::new(BIN)
        .arg("--serve-rpc")
        .env_clear()
        .envs(env.iter().map(|(name, value)| (*name, value.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn_reaped("spawn the binary under test");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        assert!(Instant::now() < deadline, "did not exit within 60 s");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    (status.code(), stderr)
}

/// G-RET-14: a model file whose hash differs from the pin refuses boot with exit 2, naming `rerank model` and both
/// hashes; the same for the tokenizer. Fault: skip the comparison in `verify_pinned` => both rows are red.
#[test]
fn a_file_that_differs_from_the_pin_refuses_boot_naming_the_object() {
    let scratch = Scratch::new("mismatch");
    let wrong = sha256_hex(b"some other file");
    for (object, pins, expected, actual) in [
        (
            "rerank model",
            Pins {
                model: wrong.clone(),
                ..Pins::correct()
            },
            wrong.clone(),
            sha256_hex(Scratch::MODEL),
        ),
        (
            "rerank tokenizer",
            Pins {
                tokenizer: wrong.clone(),
                ..Pins::correct()
            },
            wrong.clone(),
            sha256_hex(Scratch::TOKENIZER),
        ),
    ] {
        let (code, stderr) = serve_rpc(&scratch, &pins, Some("true"), None);
        assert_eq!(code, Some(2), "{object}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{object}: sha256 mismatch: expected {expected}, actual {actual}"
            )),
            "{object}: {stderr}"
        );
    }
}

/// Control: with both hashes right the boot gets past the pin and stops on the next thing the lane needs (the
/// placeholder tokenizer is not JSON), so the refusals above are the comparison's, not a missing file's. Boot order:
/// the spawn has no socket path and no DSN, yet the refusal comes from the rerank boot.
#[test]
fn matching_hashes_pass_the_pin_and_stop_later() {
    let scratch = Scratch::new("control");
    let (code, stderr) = serve_rpc(&scratch, &Pins::correct(), Some("true"), None);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.contains("sha256 mismatch"), "{stderr}");
    assert!(stderr.contains("rerank tokenizer: cannot load"), "{stderr}");
}

/// ADR-0084 D-B: with the registry's `rerank_enabled` false (unset is false) the rerank keys are never read: the
/// boot ignores the wrong pin and stops at the first key it needs after the rerank step (the socket path). Enabled
/// with a key missing, the refusal names that key.
#[test]
fn the_pin_is_read_only_when_the_lane_is_enabled() {
    let scratch = Scratch::new("disabled");
    let wrong = Pins {
        model: sha256_hex(b"some other file"),
        tokenizer: sha256_hex(b"some other file"),
    };
    for enabled in [None, Some("false")] {
        let (code, stderr) = serve_rpc(&scratch, &wrong, enabled, None);
        assert_eq!(code, Some(2), "{enabled:?}: {stderr}");
        assert!(!stderr.contains("rerank"), "{enabled:?}: {stderr}");
        assert!(
            stderr.contains("HUMAUX_RETRIEVAL_WORKER_RPC_SOCKET_PATH"),
            "{enabled:?}: {stderr}"
        );
    }
    let key = "HUMAUX_RETRIEVAL_WORKER_RERANK_REPO";
    let (code, stderr) = serve_rpc(&scratch, &Pins::correct(), Some("true"), Some(key));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains(key), "{stderr}");
}
