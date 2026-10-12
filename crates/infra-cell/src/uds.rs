//! `infra-cell::uds` — the one bind / connect site for every worker RPC Unix domain socket (ADR-0012 transport,
//!   ADR-0066 D-K / D-L / D-M hardening): server boot policy, accept-time peer admission, guarded bind, verified dial.
//! Depends-on: crates=[tokio]; services=[UDS(serve), UDS(retrieval-worker), UDS(private-worker)]; env=[];
//!   modules=[]
//! Called-by: [consolidation-worker::inference_client, consolidation-worker::main, gateway::retrieval_embedding_client,
//!   private-worker::inference_rpc, private-worker::main, retrieval-worker::main, retrieval-worker::rpc, tests]
//! Invariants: [a server whose expected peer uid equals its own uid or 0 does not boot unless the allow key is
//!   exactly `1`; a bound socket's directory is owned by the server uid with no group-write and no other bits, and
//!   the socket itself is 0660; a stale socket file is removed only after a connect probe to it failed; a client
//!   writes no byte before the server's kernel peer uid equals the expected uid]
//! Spec: Baseline §4.2; ADR-0012; ADR-0066
//!
//! ADR-0066 D-K: the peer-credential check of ADR-0012 is vacuous when the expected client uid is the server's
//! own uid (every local process of that uid passes), so it is refused at boot, not skipped. The dev rehearsal runs
//! every process under one uid and opts in with `<PROCESS>_ALLOW_SAME_UID=1`, which is logged at boot and on every
//! accepted same-uid peer.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::OnceLock;

use tokio::net::{UnixListener, UnixStream};

/// The one socket file mode a server leaves behind (ADR-0066 D-M): owner and pair group read/write, nothing else.
pub const SOCKET_MODE: u32 = 0o660;

/// Why a verified dial ([`connect_verified`]) refused or failed. The caller maps every variant to its transport
/// failure; none of them is a wire error code (§52).
#[derive(Debug)]
pub enum UdsError {
    /// The socket file could not be inspected, or the connect / peer-credential read failed.
    Io(std::io::Error),
    /// The socket file grants permissions to `other` (ADR-0066 D-M): any local user could stand in for it.
    Mode {
        /// The socket path that was refused.
        path: String,
        /// Its permission bits.
        mode: u32,
    },
    /// The process serving the socket is not the expected server (ADR-0066 D-L).
    PeerUid {
        /// The kernel's peer uid of the serving process.
        got: u32,
        /// The registered expected server uid.
        expected: u32,
    },
}

impl std::fmt::Display for UdsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdsError::Io(e) => write!(f, "{e}"),
            UdsError::Mode { path, mode } => {
                write!(f, "socket {path} has mode {mode:04o}: other bits are set")
            }
            UdsError::PeerUid { got, expected } => {
                write!(f, "peer uid {got}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for UdsError {}

/// This process's effective uid as the kernel reports it to a socket peer: the uid of one end of a fresh socket
/// pair, read with the same `peer_cred` the admission check uses (no `libc`). Cached after the first call.
///
/// # Errors
/// The socket pair or its credential read failed. Must run inside a Tokio runtime.
pub fn own_uid() -> std::io::Result<u32> {
    // ponytail: process-wide OnceLock cache; a process that changes uid after the first call (none does) would
    // need a per-call read.
    static OWN: OnceLock<u32> = OnceLock::new();
    if let Some(uid) = OWN.get() {
        return Ok(*uid);
    }
    let (a, _b) = UnixStream::pair()?;
    let uid = a.peer_cred()?.uid();
    Ok(*OWN.get_or_init(|| uid))
}

/// ADR-0066 D-K boot rule, pure: `Ok(true)` = the same-uid opt-in is active, `Ok(false)` = the check is meaningful,
/// `Err` = refuse to boot (the caller exits 2 with this text). The allow value must be absent, empty or exactly `1`.
///
/// # Errors
/// The allow value is anything else, or the expected uid equals `own` or 0 without the opt-in.
pub fn same_uid_rule(
    expected_key: &str,
    expected: u32,
    own: u32,
    allow_key: &str,
    allow: Option<&str>,
) -> Result<bool, String> {
    let allowed = match allow.unwrap_or("") {
        "" => false,
        "1" => true,
        _ => {
            return Err(format!(
                "invalid configuration: {allow_key} must be unset or exactly 1 (dev only)"
            ));
        }
    };
    if (expected == own || expected == 0) && !allowed {
        return Err(format!(
            "invalid configuration: {expected_key}={expected} equals this process's own uid (or 0); \
             peer-credential check would be vacuous; set {allow_key}=1 only in a single-uid dev rehearsal"
        ));
    }
    Ok(allowed && (expected == own || expected == 0))
}

/// ADR-0066 D-K at server boot: applies [`same_uid_rule`] against [`own_uid`] to the caller's `allow_key` value
/// (§78: the binary reads its environment, this crate does not), and prints the dev-only WARN when the opt-in is
/// what lets the server start.
///
/// # Errors
/// The boot refusal text (exit 2 at the caller), or the own uid could not be read.
pub fn server_policy(
    process: &str,
    expected_key: &str,
    expected: u32,
    allow_key: &str,
    allow: Option<&str>,
) -> Result<(), String> {
    let own = own_uid().map_err(|e| format!("cannot read this process's own uid: {e}"))?;
    if same_uid_rule(expected_key, expected, own, allow_key, allow)? {
        eprintln!(
            "WARN {process}: {allow_key}=1 (dev only): peers with this process's own uid {own} are accepted"
        );
    }
    Ok(())
}

/// ADR-0012 §决定2 + ADR-0066 D-K at accept time: whether a connected peer may reach the handler. A refusal is
/// logged (one line per refused peer); an accepted peer with this process's own uid logs the dev-only WARN, which
/// can only happen when [`server_policy`] let the server boot under the opt-in.
pub fn admit_peer(process: &str, peer_uid: Option<u32>, expected: u32) -> bool {
    match peer_uid {
        Some(uid) if uid == expected => {
            if own_uid().is_ok_and(|own| own == uid) {
                eprintln!("WARN {process}: same-uid peer accepted uid={uid}");
            }
            true
        }
        Some(uid) => {
            eprintln!("{process}: rpc peer refused uid={uid} expected={expected}");
            false
        }
        None => {
            eprintln!("{process}: rpc peer refused uid=unknown expected={expected}");
            false
        }
    }
}

/// ADR-0066 D-M: binds a server socket at `path`. The parent directory must be owned by this process's uid with
/// mode `& 0o027 == 0` (0750 or stricter); an existing file at `path` is removed only after a connect probe to it
/// failed (a live server keeps its socket); the bound socket is chmod 0660 explicitly and re-checked.
///
/// # Errors
/// A refused directory (path and octal mode named), a live server at `path`, or a bind / chmod failure.
pub fn bind_guarded(path: &Path) -> std::io::Result<UnixListener> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let own = own_uid()?;
    let meta = std::fs::metadata(dir)?;
    let mode = meta.permissions().mode() & 0o7777;
    if !meta.is_dir() || meta.uid() != own || mode & 0o027 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "socket directory {} must be owned by uid {own} with mode 0750 or stricter \
                 (found uid {} mode {mode:04o})",
                dir.display(),
                meta.uid()
            ),
        ));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        // dep: UDS(private-worker) — stale-socket probe of the path this server is about to bind; the same site
        // probes the retrieval worker's path (UDS(retrieval-worker)) when that server boots
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("a live server already answers on {}", path.display()),
            ));
        }
        std::fs::remove_file(path)?;
    }
    // dep: UDS(serve) — the one worker RPC bind site (ADR-0012 transport)
    let listener = UnixListener::bind(path)?;
    // ADR-0066 D-M: set explicitly, never inherited from the umask.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    let bound = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if bound != SOCKET_MODE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("socket {} has mode {bound:04o}, not 0660", path.display()),
        ));
    }
    Ok(listener)
}

/// ADR-0066 D-L: dials `path` and returns the stream only when the socket file grants nothing to `other` and the
/// serving process's kernel peer uid is `expected_server_uid`. Nothing is written before both checks pass.
///
/// # Errors
/// [`UdsError::Mode`], [`UdsError::PeerUid`], or [`UdsError::Io`] for the stat / connect / credential read.
pub async fn connect_verified(
    path: &str,
    expected_server_uid: u32,
) -> Result<UnixStream, UdsError> {
    let mode = std::fs::metadata(path)
        .map_err(UdsError::Io)?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o007 != 0 {
        return Err(UdsError::Mode {
            path: path.to_owned(),
            mode,
        });
    }
    // dep: UDS(retrieval-worker) — the one worker RPC dial site; the same site dials the private worker's
    // inference socket (UDS(private-worker)) for the consolidation worker
    let stream = UnixStream::connect(path).await.map_err(UdsError::Io)?;
    let got = stream.peer_cred().map_err(UdsError::Io)?.uid();
    if got != expected_server_uid {
        return Err(UdsError::PeerUid {
            got,
            expected: expected_server_uid,
        });
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A short `/tmp` directory (a macOS temp dir plus a name overflows `sockaddr_un`), removed on drop.
    struct Dir(std::path::PathBuf);

    impl Dir {
        fn new(tag: &str, mode: u32) -> Self {
            let path =
                std::path::PathBuf::from(format!("/tmp/hq-uds-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir(&path).expect("create the socket dir");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("chmod the socket dir");
            Dir(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Fault: `own_uid` returns 0 ⇒ red (this test never runs as root).
    #[tokio::test]
    async fn own_uid_matches_a_created_files_owner() {
        let dir = Dir::new("own", 0o700);
        let file = dir.0.join("f");
        std::fs::write(&file, b"").expect("create a file");
        let owner = std::fs::metadata(&file).expect("stat the file").uid();
        assert_eq!(own_uid().expect("own uid"), owner);
    }

    /// Fault: drop the directory mode check ⇒ the bind succeeds ⇒ red.
    #[tokio::test]
    async fn dir_with_other_bits_refuses_bind() {
        let dir = Dir::new("other", 0o755);
        let err = bind_guarded(&dir.0.join("s.sock")).expect_err("a 0755 dir must refuse the bind");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("0755"), "{err}");
    }

    /// Fault: skip the explicit chmod ⇒ the socket keeps the umask mode (0755 under umask 022) ⇒ red.
    #[tokio::test]
    async fn bound_socket_is_0660() {
        let dir = Dir::new("mode", 0o750);
        let path = dir.0.join("s.sock");
        let _listener = bind_guarded(&path).expect("bind in a 0750 dir");
        let mode = std::fs::metadata(&path)
            .expect("stat the socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660, "socket mode {mode:04o}");
    }

    /// Fault: skip the peer-uid comparison ⇒ the dial succeeds ⇒ red.
    #[tokio::test]
    async fn connect_refuses_unexpected_server_uid_before_writing() {
        let dir = Dir::new("peer", 0o700);
        let path = dir.0.join("s.sock");
        let listener = bind_guarded(&path).expect("bind");
        let wrong = own_uid().expect("own uid").wrapping_add(1);
        let dial = connect_verified(path.to_str().expect("utf-8 path"), wrong).await;
        assert!(
            matches!(dial, Err(UdsError::PeerUid { got, expected }) if expected == wrong && got != wrong),
            "{dial:?}"
        );
        let (mut server_side, _) = listener
            .accept()
            .await
            .expect("the refused dial was accepted");
        let mut buf = Vec::new();
        server_side
            .read_to_end(&mut buf)
            .await
            .expect("read until the client closed");
        assert!(buf.is_empty(), "the client wrote {} bytes", buf.len());
    }

    /// Fault: accept any non-empty allow value as the opt-in ⇒ `true` boots ⇒ red.
    #[test]
    fn allow_value_other_than_1_refuses() {
        for value in ["true", "yes", "0", " 1", "1 "] {
            let err = same_uid_rule("K", 7, 7, "ALLOW", Some(value)).expect_err(value);
            assert!(
                err.contains("ALLOW must be unset or exactly 1"),
                "{value}: {err}"
            );
        }
        assert_eq!(same_uid_rule("K", 7, 7, "ALLOW", Some("1")), Ok(true));
        assert_eq!(same_uid_rule("K", 8, 7, "ALLOW", None), Ok(false));
        assert!(same_uid_rule("K", 7, 7, "ALLOW", None).is_err_and(|e| e.contains("K=7")));
        assert!(same_uid_rule("K", 0, 7, "ALLOW", Some("")).is_err());
    }

    // Review fix 9 (LENS-1 / ISO-7): one test per D-L / D-M branch the first five left unexercised, each with the
    // exact value it must name.

    /// Fault: the directory mask `0o027` → `0o007` (group-write accepted) ⇒ the bind succeeds ⇒ red.
    #[tokio::test]
    async fn dir_with_group_write_refuses_bind() {
        let dir = Dir::new("gw", 0o770);
        let err = bind_guarded(&dir.0.join("s.sock")).expect_err("a 0770 dir must refuse the bind");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("0770"), "{err}");
    }

    /// Fault: drop the client-side `mode & 0o007` check ⇒ the dial reaches the peer-uid read ⇒ red.
    #[tokio::test]
    async fn connect_refuses_a_socket_with_other_bits_before_dialling() {
        let dir = Dir::new("omode", 0o700);
        let path = dir.0.join("s.sock");
        let listener = bind_guarded(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("chmod 0666");
        let own = own_uid().expect("own uid");
        let dial = connect_verified(path.to_str().expect("utf-8 path"), own).await;
        assert!(
            matches!(dial, Err(UdsError::Mode { mode: 0o666, .. })),
            "{dial:?}"
        );
        // Nothing was dialled: an accept must not be pending.
        let pending =
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
        assert!(
            pending.is_err(),
            "a refused dial still reached the listener"
        );
    }

    /// Fault: drop the connect probe before `remove_file` (always unlink) ⇒ the second bind steals the path from
    /// the live server ⇒ red.
    #[tokio::test]
    async fn bind_over_a_live_server_is_addr_in_use_and_the_server_keeps_its_socket() {
        let dir = Dir::new("live", 0o700);
        let path = dir.0.join("s.sock");
        let listener = bind_guarded(&path).expect("first bind");
        let err = bind_guarded(&path).expect_err("a live server keeps its socket");
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}");
        let own = own_uid().expect("own uid");
        let dial = connect_verified(path.to_str().expect("utf-8 path"), own).await;
        assert!(dial.is_ok(), "the first server no longer answers: {dial:?}");
        let accepted =
            tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept()).await;
        assert!(
            accepted.is_ok_and(|a| a.is_ok()),
            "the first listener did not get the dial"
        );
    }

    /// Fault: refuse any existing file (no stale-removal arm) ⇒ a dead socket file blocks the boot ⇒ red.
    #[tokio::test]
    async fn bind_replaces_a_dead_socket_file() {
        let dir = Dir::new("dead", 0o700);
        let path = dir.0.join("s.sock");
        {
            // dep: UDS(serve) — a server that binds and dies, leaving its socket file behind
            let _dead =
                std::os::unix::net::UnixListener::bind(&path).expect("a server that then dies");
        }
        assert!(
            std::fs::symlink_metadata(&path).is_ok(),
            "the dead server left its file"
        );
        let _listener = bind_guarded(&path).expect("a dead socket file is replaced");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o660, "replacement socket mode {mode:04o}");
    }

    /// Fault: drop the owner comparison (`meta.uid() != own`) ⇒ the bind is attempted inside root's home and fails
    /// on EACCES instead of the guard's own message ⇒ red. The directory must be root's with no group-write and no
    /// other bits (`/var/root` on macOS, `/root` on Linux: 0700), so that only the uid clause can refuse it; a host
    /// without one is `not_applicable` naming it (§57.1).
    #[tokio::test]
    async fn dir_owned_by_another_uid_refuses_bind() {
        let own = own_uid().expect("own uid");
        assert_ne!(own, 0, "this test never runs as root");
        let Some(dir) = ["/var/root", "/root"].into_iter().find(|d| {
            std::fs::metadata(d)
                .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.permissions().mode() & 0o027 == 0)
        }) else {
            println!(
                "not_applicable: missing object = a root-owned 0750-or-stricter directory (/var/root, /root)"
            );
            return;
        };
        let err = bind_guarded(&Path::new(dir).join("hq-uds-foreign-owner.sock"))
            .expect_err("a root-owned dir");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            err.to_string().contains("found uid 0") && err.to_string().contains(dir),
            "{err}"
        );
    }
}
