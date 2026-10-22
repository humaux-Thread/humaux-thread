//! `humaux-telemetry` — Humaux Thread workspace crate（布局见 §58）; the crate root also carries the process
//!   command-line surface every binary shares (ADR-0066 D-D / D-O): the `--version` line, the start line, the
//!   std-only HTTP probe behind `--readyz` / `--livez`, and the renamed-key resolution.
//! Depends-on: crates=[]; services=[HTTP(loopback)]; env=[]; modules=[telemetry::metrics]
//! Called-by: [crate(humaux-adapters), crate(humaux-admin), crate(humaux-cache), crate(humaux-consolidation-worker), crate(humaux-gateway), crate(humaux-maintenance),
//!   crate(humaux-private-worker), crate(humaux-retrieval), crate(humaux-retrieval-worker), crate(humaux-testkit), crate(xtask)]
//! Invariants: [no function here reads the environment (§78.3): each binary passes its own build values and key
//!   values in; `version_line` answers only for a 40-hex sha; `probe_http` exits 0 only on a 200 status line]
//! Spec: Baseline §3; §4.4; §58; §78.3; ADR-0037; ADR-0066 D-D; ADR-0066 D-N; ADR-0066 D-O
//!
//! 本 crate 的职责边界与依赖规则以 docs/architecture/Baseline_2.9.md 为唯一规范真源；
//! Domain 永不 import HTTP / SQLx / Qdrant / Provider SDK / ENV（§3 / §78.3）。

pub mod admission;
pub mod cache;
pub mod degrade;
pub mod direction;
pub mod dr;
pub mod health;
/// Read-only host gauges with absent samples on unavailable sources (§41.2).
pub mod host;
pub mod metrics;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;

/// The `--version` line `<binary> <version> git_sha=<40 hex> build_time=<t|missing>` (ADR-0066 D-D). `Err` names
/// the missing or malformed build value: a binary that cannot name its revision must not print a plausible one
/// (§4.4 坑4).
pub fn version_line(
    binary: &str,
    version: &str,
    git_sha: Option<&str>,
    build_time: Option<&str>,
) -> Result<String, String> {
    let sha = git_sha.ok_or("missing object: HUMAUX_BUILD_GIT_SHA (not burned in at build)")?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid object: HUMAUX_BUILD_GIT_SHA={sha:?} is not a 40-hex commit sha"
        ));
    }
    Ok(format!(
        "{binary} {version} git_sha={sha} build_time={}",
        build_time.unwrap_or("missing")
    ))
}

/// `--version`: the [`version_line`] on stdout and exit 0, or the reason on stderr and exit 2 (ADR-0066 D-N: a
/// build without its sha is something an operator must change, not retry). Reads no configuration.
pub fn version_mode(
    binary: &str,
    version: &str,
    git_sha: Option<&str>,
    build_time: Option<&str>,
) -> ExitCode {
    match version_line(binary, version, git_sha, build_time) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("{binary}: {reason}");
            ExitCode::from(2)
        }
    }
}

/// Why a mode of a binary stopped with `Err` (ADR-0037 addendum, ADR-0066 D-N): `runtime` = a restart can help (a
/// dependency down at boot, the serve loop failing) ⇒ exit 1; otherwise usage or configuration (an operator must
/// change something) ⇒ exit 2. `From<String>` / `From<&str>` build the configuration case, so every `?` on a
/// parse or required-key helper stays exit 2 and only a call site that marks itself with [`ModeFailure::runtime`]
/// exits 1 (review P1, 2026-10-08: three residents exited 2 on a database down at boot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModeFailure {
    /// `true` ⇒ exit 1 (restart helps); `false` ⇒ exit 2.
    pub runtime: bool,
    /// The one stderr line, without the binary prefix.
    pub message: String,
}

impl ModeFailure {
    /// A runtime failure: exit 1.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            runtime: true,
            message: message.into(),
        }
    }

    /// 1 for a runtime failure, 2 for usage or configuration.
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(if self.runtime { 1 } else { 2 })
    }
}

impl From<String> for ModeFailure {
    fn from(message: String) -> Self {
        Self {
            runtime: false,
            message,
        }
    }
}

impl From<&str> for ModeFailure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl std::fmt::Display for ModeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// The first stderr line of every resident mode (ADR-0066 D-D). A dev build without a sha still starts and says
/// `git_sha=missing`; only `--version` refuses.
pub fn start_line(binary: &str, mode: &str, version: &str, git_sha: Option<&str>) -> String {
    format!(
        "{binary}: start mode={mode} version={version} git_sha={}",
        git_sha.unwrap_or("missing")
    )
}

/// `--readyz` / `--livez` for a compose healthcheck that has no shell and no curl (ADR-0066 D-D): one HTTP/1.0 GET
/// of `path` on the address in `key`, bounded by [`metrics::IO_TIMEOUT`] per phase. 200 ⇒ exit 0; any other
/// status, a missing / unparsable address or a failed connect ⇒ exit 2 with the reason (and the body's first line)
/// on stderr.
pub fn probe_http(key: &str, addr: Option<&str>, path: &str) -> ExitCode {
    match probe_http_status(key, addr, path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("not ready: {reason}");
            ExitCode::from(2)
        }
    }
}

fn probe_http_status(key: &str, addr: Option<&str>, path: &str) -> Result<(), String> {
    let raw = addr
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("missing required configuration: {key}"))?;
    let target: SocketAddr = raw
        .trim()
        .parse()
        .map_err(|_| format!("invalid configuration: {key}"))?;
    let timeout = metrics::IO_TIMEOUT;
    // dep: HTTP(loopback) — the probed process's own listener (gateway bind / maintenance ops address)
    let mut stream = TcpStream::connect_timeout(&target, timeout)
        .map_err(|e| format!("GET {path} on {key}={target}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        // One write: a request split over several segments can be answered and closed after the first one.
        .and_then(|()| {
            stream.write_all(format!("GET {path} HTTP/1.0\r\nHost: {target}\r\n\r\n").as_bytes())
        })
        .map_err(|e| format!("GET {path} on {key}={target}: {e}"))?;
    // The server closes after one HTTP/1.0 response; a read that times out after the status line still decides.
    let mut reply = Vec::new();
    let mut chunk = [0u8; 1024];
    while reply.len() < 64 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => reply.extend_from_slice(&chunk[..n]),
            Err(_) if !reply.is_empty() => break,
            Err(e) => return Err(format!("GET {path} on {key}={target}: {e}")),
        }
    }
    let reply = String::from_utf8_lossy(&reply);
    let status = reply
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("none");
    if status == "200" {
        return Ok(());
    }
    let body = reply
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b.lines().next().unwrap_or(""));
    Err(format!(
        "GET {path} on {key}={target}: status {status} {body}"
    ))
}

/// ADR-0066 D-O: a configuration key renamed to its `HUMAUX_` form, readable under the old name for one release.
/// `new` / `old` are the two values (empty counts as unset). Returns the value plus the deprecation WARN to print
/// when only the old name was set; both set with different values, or neither set, is a configuration error
/// naming the key(s).
pub fn renamed_key(
    new_key: &str,
    new: Option<String>,
    old_key: &str,
    old: Option<String>,
) -> Result<(String, Option<String>), String> {
    let set = |v: Option<String>| v.filter(|v| !v.trim().is_empty());
    match (set(new), set(old)) {
        (Some(n), Some(o)) if n != o => Err(format!(
            "invalid configuration: {new_key} and its deprecated alias {old_key} are both set with different values; unset {old_key}"
        )),
        (Some(n), _) => Ok((n, None)),
        (None, Some(o)) => Ok((
            o,
            Some(format!(
                "WARN {old_key} is deprecated; rename it to {new_key} (accepted until the release after card 39)"
            )),
        )),
        (None, None) => Err(format!("missing required configuration: {new_key}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn version_line_names_sha() {
        assert_eq!(
            version_line("humaux-x", "0.1.0", Some(SHA), None).as_deref(),
            Ok(format!("humaux-x 0.1.0 git_sha={SHA} build_time=missing").as_str())
        );
    }

    /// Fault: answer without a sha (or with a short one) ⇒ red.
    #[test]
    fn version_without_sha_exits_2() {
        // §57.1: the refusal names the missing object, and a malformed sha is a different (invalid) object.
        // Fault (review, 2026-10-08): `git_sha.unwrap_or("missing")` keeps exit 2 but loses the name ⇒ red.
        assert_eq!(
            version_line("humaux-x", "0.1.0", None, None),
            Err("missing object: HUMAUX_BUILD_GIT_SHA (not burned in at build)".to_owned())
        );
        assert!(
            version_line("humaux-x", "0.1.0", Some("abc123"), None)
                .is_err_and(|e| e.starts_with("invalid object: HUMAUX_BUILD_GIT_SHA="))
        );
        assert_eq!(
            version_mode("humaux-x", "0.1.0", None, None),
            ExitCode::from(2)
        );
    }

    /// ADR-0066 D-N: a `?` on a configuration `String` exits 2, a call site marked runtime exits 1, and the
    /// message is the line as given. Fault: map both to 2 (the pre-fix residents) ⇒ red.
    #[test]
    fn mode_failure_exit_codes() {
        let config: ModeFailure = "invalid configuration: HUMAUX_X".into();
        assert_eq!(config.exit_code(), ExitCode::from(2));
        let runtime = ModeFailure::runtime("database connection failed");
        assert_eq!(runtime.exit_code(), ExitCode::from(1));
        assert_eq!(runtime.to_string(), "database connection failed");
    }

    /// One canned HTTP response on a loopback port; returns the address.
    fn answer_once(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr").to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let (mut head, mut chunk) = (Vec::new(), [0u8; 512]);
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = s.write_all(response.as_bytes());
            }
        });
        addr
    }

    /// ADR-0066 D-D: the compose healthcheck's exit code. Fault: accept any status line ⇒ the 503 case red.
    #[test]
    fn probe_http_maps_503_to_2() {
        let ok = answer_once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nlive\n");
        assert_eq!(probe_http("K", Some(&ok), "/livez"), ExitCode::SUCCESS);
        let draining = answer_once(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 22\r\n\r\n{\"status\":\"draining\"}\n",
        );
        let reason = probe_http_status("K", Some(&draining), "/readyz").unwrap_err();
        assert!(
            reason.contains("status 503 {\"status\":\"draining\"}"),
            "{reason}"
        );
        let again = answer_once("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert_eq!(probe_http("K", Some(&again), "/readyz"), ExitCode::from(2));
        assert_eq!(probe_http("K", None, "/readyz"), ExitCode::from(2));
    }

    #[test]
    fn renamed_key_resolution() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            renamed_key("NEW", s("a"), "OLD", None),
            Ok(("a".into(), None))
        );
        assert_eq!(
            renamed_key("NEW", s("a"), "OLD", s("a")),
            Ok(("a".into(), None))
        );
        let (v, warn) = renamed_key("NEW", None, "OLD", s("b")).expect("alias accepted");
        assert_eq!(v, "b");
        assert!(warn.is_some_and(|w| w.starts_with("WARN OLD is deprecated; rename it to NEW")));
        assert!(renamed_key("NEW", s("a"), "OLD", s("b")).is_err());
        assert_eq!(
            renamed_key("NEW", None, "OLD", s(" ")),
            Err("missing required configuration: NEW".into())
        );
    }
}
