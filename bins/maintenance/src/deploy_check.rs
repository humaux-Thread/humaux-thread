//! `maintenance::deploy_check` — the release gate modes of `humaux-maintenance deploy-check` (ADR-0066 D-R):
//!   `--compose-json` (the unresolved compose config: users, hardening, limits, socket volumes, migrator placement),
//!   `--env` (values + secret files: presence, dev-only keys, migrator and maintenance-DSN placement), the
//!   expected-uid and host-network-DSN cross-checks when both are given, `--release` (four identity comparisons
//!   against the build's release manifest plus the checkout-tree comparison, review fix 9), `--running`
//!   (`docker inspect` of the running project against the compose values) and `--secrets-readable` (names only).
//! Depends-on: crates=[humaux-adapters, serde_json]; services=[subprocess(docker), fs(env_file of the compose document)]; env=[]; modules=[adapters::retrieve]
//! Called-by: [maintenance::main, xtask::dep_map]
//! Invariants: [every check reports ALL its failing reasons, never just the first; a reason carries names (service,
//!   key, file, target) and never a value; a compose document with a resolved secret value is refused
//!   `resolved_env_input` (exit 2) before any other parsing; any failing reason ⇒ exit 3; a missing input of a
//!   check, a mode flag without its value, or no check selected is a usage error (exit 2) naming the flag — the
//!   release gate is fail-closed and its receipt has no `not_applicable` state (review fix 9, F8 / OP-7)]
//! Spec: Baseline §4.2; §4.4; §57.1; §67.2; ADR-0066 D-C, D-H, D-J, D-K, D-R
//! dep-map: allow env-undeclared — the HUMAUX_* names here are checked in values files, compose documents and container
//!   env; this module reads none of them from its own environment
//!
//! The pre-existing `deploy-check --roles-sql` (ADR-0059 D-F, five DB/env checks) stays in `maintenance::roles`;
//! `main` routes here when any flag of this module is present. Identity is checked against the release manifest
//! `build.sh` writes (`IMAGE humaux-<t>:<tag> id=<sha256> size=<bytes> binary=<bin> git_sha=<sha40>`, ADR-0066 D-A /
//! R-2), never only against what an image says about itself (RF-1).

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};

/// ADR-0066 D-K: keys that exist only for a dev host (the same-uid allowance of the two UDS servers). A non-empty
/// value in a production values file or a running container is `dev_only_key_set`; the env example generator
/// (`xtask::dep_map`, D-T) leaves them out by this same list.
pub const DEV_ONLY_KEYS: &[&str] = &[
    "HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID",
    "HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID",
];

/// ADR-0066 D-J / L-13: the superuser migrator DSN, allowed in exactly one file and on exactly one service.
pub const MIGRATOR_DSN_KEY: &str = "HUMAUX_MIGRATOR_PG_DSN";
/// ADR-0066 D-J: the one secret file that may carry [`MIGRATOR_DSN_KEY`].
pub const MIGRATOR_SECRET_FILE: &str = "migrate.secret.env";
const MIGRATOR_SERVICE: &str = "migrate";

/// ADR-0066 D-H: the one service that runs as root, with exactly this capability added.
const DR_SERVICE: &str = "dr";
/// `dr`'s two capabilities (D-H, L-14; PR #2 review P1): read every secret / the repository, and create its evidence
/// files inside the operator's 0700 evidence directory as uid 0 with ALL dropped.
const DR_CAP_ADD: [&str; 2] = ["DAC_READ_SEARCH", "DAC_OVERRIDE"];

/// ADR-0066 D-J, review fix 6: `dr`'s secret file — the maintenance DSN at the host-network address
/// (`127.0.0.1:<HUMAUX_PG_PORT>`, `dr` runs with `network_mode: host`); loaded by `dr` only.
const DR_SECRET_FILE: &str = "dr.secret.env";
/// ADR-0066 D-J, review fix 6: the maintenance DSN and its only two homes — the maintenance binary's resident and
/// `ops` file (compose-internal `pg:5432`) and [`DR_SECRET_FILE`] (same role and password, host-network address).
const MAINTENANCE_DSN_KEY: &str = "HUMAUX_MAINTENANCE_PG_DSN";
const MAINTENANCE_DSN_HOMES: [&str; 2] =
    ["secrets/maintenance.secret.env", "secrets/dr.secret.env"];

/// ADR-0066 D-C: every resource limit a Humaux service must carry.
const LIMIT_KEYS: [&str; 4] = ["mem_limit", "memswap_limit", "cpus", "pids_limit"];
/// Review fix 9 (ISO-5): the one `security_opt` entry a service may carry. Anything beside it (`seccomp:unconfined`,
/// `apparmor:unconfined`, `label:disable`) drops the daemon's default confinement; `contains` let that through.
const SECURITY_OPT: [&str; 1] = ["no-new-privileges:true"];
/// Review fix 9 (ISO-2): host roots a bind mount of any service but `dr` never reaches: the daemon socket's
/// directory, the kernel and device trees, the host's configuration and home directories. The secrets directory
/// is refused by its path segment (`secrets`, or the placeholder fixture `secret-fixture`).
const BIND_DENIED_ROOTS: [&str; 10] = [
    "/",
    "/var/run",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/var/lib/docker",
    "/root",
    "/home",
];
/// Review fix 9 (OP-3): a resident (no profile) comes back after a host reboot or a daemon restart by policy; a
/// one-shot (profiled) never restarts. The exit-2 cap of the earlier `on-failure:5` lives in the gates around
/// `up` instead (`--env` before, `--running` after: L-2).
const RESTART_RESIDENT: &str = "unless-stopped";
const RESTART_ONE_SHOT: &str = "no";

/// One UDS peer-cred pair (ADR-0066 D-C, D-K, D-L): the two services, the socket volume the server owns, the pair
/// group, the services allowed to carry that group or mount that volume, and the expected-uid keys as
/// `(process env file, key)` — the server's key names the client uid, the client's the server's.
struct Pair {
    server: &'static str,
    client: &'static str,
    volume: &'static str,
    gid: u32,
    /// ADR-0066 D-C: the server's modes, the client and `admin` (its cell probe dials both sockets and is answered
    /// 403 by each server's uid check). Any other service with the group or the volume could reach the socket.
    members: &'static [&'static str],
    client_uid_key: (&'static str, &'static str),
    server_uid_key: (&'static str, &'static str),
}

const PAIRS: [Pair; 2] = [
    Pair {
        server: "retrieval-rpc",
        client: "gateway",
        volume: "sock-retrieval",
        gid: 10201,
        members: &["retrieval-rpc", "retrieval-serve", "gateway", "admin"],
        client_uid_key: ("retrieval-worker", "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID"),
        server_uid_key: ("gateway", "HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID"),
    },
    Pair {
        server: "private-rpc",
        client: "consolidation",
        volume: "sock-inference",
        gid: 10202,
        members: &["private-rpc", "private-distill", "consolidation", "admin"],
        client_uid_key: ("private-worker", "HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID"),
        server_uid_key: (
            "consolidation-worker",
            "HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID",
        ),
    },
];

/// ADR-0066 D-C uid rule: every Humaux process identity has its own uid in this range (`dr` is root, D-H).
const IDENTITY_UIDS: std::ops::RangeInclusive<u32> = 10101..=10107;

/// ADR-0066 D-C: the only services that may share a uid — the modes of one binary run as that binary's user
/// (`ops` is the maintenance binary's one-shot doors). Every other pair of Humaux services sharing a uid is red.
const SHARED_IDENTITIES: [&[&str]; 3] = [
    &["private-rpc", "private-distill"],
    &["retrieval-rpc", "retrieval-serve"],
    &["maintenance-health", "maintenance-serve", "ops"],
];

/// ADR-0066 D-C / §5: the profile of the rehearsal-only probes (`scratch-as-*` carry their twins' uid and pair group
/// on purpose). Only a [`REHEARSAL_PROBES`] row in this profile is exempt from the identity rules; `alert-sink`
/// is in the profile too and gets every rule.
const REHEARSAL_PROFILE: &str = "rehearsal";

/// ADR-0066 D-J: the role passwords `migrate roles rotate` sets live in `migrate.secret.env` (loaded only by the
/// `migrate` one-shot), never in the resident daemon's `maintenance.secret.env`.
const ROLE_PASSWORD_PREFIX: &str = "HUMAUX_ROLE_PASSWORD_";

/// ADR-0066 D-J / runbook R1: the per-node provider route keys. Not secret-shaped, but the operator writes them in
/// `private-worker.secret.env` beside the provider key (values/private-worker.env header, runbook §O-DNS).
pub const NODE_ROUTE_KEYS: [&str; 3] = [
    "HUMAUX_PRIVATE_WORKER_DNS_PINS",
    "HUMAUX_PRIVATE_WORKER_EGRESS_RECIPIENTS",
    "HUMAUX_PRIVATE_WORKER_REGIONS",
];

/// ADR-0066 D-T: names the maintenance binary writes into a child's environment (the drill compose project,
/// drill.rs `listen_key` / `Project::env`) and never reads from its own; the env example generator leaves them out.
pub const CHILD_ONLY_KEYS: [&str; 2] = ["HUMAUX_DRILL_ID", "HUMAUX_DRILL_PG_LISTEN_ADDRESSES"];

/// ADR-0066 D-J / D-T: the secret file (`<home>.secret.env`) that holds `key` of `process`, or `None` when the key
/// belongs in `values/<process>.env`.
pub fn secret_home<'a>(process: &'a str, key: &str) -> Option<&'a str> {
    if key.starts_with(ROLE_PASSWORD_PREFIX) {
        Some("migrate")
    } else if is_secret_key(key) || NODE_ROUTE_KEYS.contains(&key) {
        Some(process)
    } else {
        None
    }
}

/// ADR-0066 D-R (a): a key whose empty value is a broken node at PRECHECK — a secret, except a rotation twin
/// (`*_PREVIOUS*`, empty outside a rotation) and the credential map runbook O4 writes after the first `up`.
fn must_be_set(key: &str) -> bool {
    is_secret_key(key) && !key.contains("_PREVIOUS") && !key.ends_with("_CREDENTIALS")
}

/// M02-3 / M02 D3: the gateway's auth MAC key. Unlike every other [`must_be_set`] secret it may be empty while
/// [`AUTH_SURFACE_ENABLED`] is not `true`; once the surface is on, an empty key is `secret_empty` like any secret.
const AUTH_HMAC_KEY: &str = "HUMAUX_GATEWAY_AUTH_HMAC_KEY";
/// The gateway key that turns the auth surface on (`bins/gateway` bootstrap, registered default `false`).
const AUTH_SURFACE_ENABLED: &str = "HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED";

/// ADR-0059 D-G / M02 D3: apply bootstrap's security floor to decoded bytes; malformed hex remains boot's check.
fn auth_key_too_short(value: &str) -> bool {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    let bytes: Option<Vec<u8>> = value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect();
    bytes.is_some_and(|bytes| humaux_adapters::retrieve::TokenKeys::new(bytes, None).is_err())
}

/// Whether any of `sources` sets [`AUTH_SURFACE_ENABLED`] to `true` for process `p`.
fn auth_surface_enabled(sources: &[&[EnvFile]], p: &str) -> bool {
    sources.iter().any(|files| {
        files
            .iter()
            .filter(|f| f.process == p)
            .filter_map(|f| f.value(AUTH_SURFACE_ENABLED))
            .any(|value| value == "true")
    })
}

/// The flags that route `deploy-check` here instead of the ADR-0059 `--roles-sql` checks.
pub const MODE_FLAGS: [&str; 5] = [
    "--compose-json",
    "--env",
    "--release",
    "--running",
    "--secrets-readable",
];

// ---------------------------------------------------------------------------------------------------------------
// --compose-json
// ---------------------------------------------------------------------------------------------------------------

/// ADR-0066 D-R / RF-3 / D-T: a secret-shaped key name — its non-empty value in a service `environment` means the
/// document was resolved (env_file values inlined), and the env example generator (`xtask::dep_map`) routes it to
/// `<process>.secret.env`. `_KEY_PREVIOUS` is the rotation twin of a `_KEY` (the gateway's previous token key).
pub fn is_secret_key(key: &str) -> bool {
    ["_DSN", "_KEY", "_KEY_PREVIOUS", "_CREDENTIALS"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
        || key.contains("_PASSWORD")
        || key.contains("_PEPPER")
}

fn services(doc: &Value) -> impl Iterator<Item = (&String, &Value)> {
    doc.get("services")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
}

/// `Some("resolved_env_input:<service>:<key>")` for the first secret-shaped key carrying a value (D-R: refused
/// without further parsing; the reason names the key, never its value). A `*_FILE` key holds the path of a mounted
/// secret, never the secret: prod.yml's `pg` sets `POSTGRES_PASSWORD_FILE=/run/secrets/pg_superuser` (D-J).
pub fn resolved_env_input(doc: &Value) -> Option<String> {
    services(doc).find_map(|(name, svc)| {
        svc.get("environment")
            .and_then(Value::as_object)?
            .iter()
            .find(|(key, value)| {
                is_secret_key(key)
                    && !key.ends_with("_FILE")
                    && value.as_str().is_some_and(|v| !v.is_empty())
            })
            .map(|(key, _)| format!("resolved_env_input:{name}:{key}"))
    })
}

/// ADR-0066 D-A: the image targets that run a Humaux binary (loadgen is never in prod.yml, D-S).
const TARGETS: [&str; 8] = [
    "gateway",
    "private-worker",
    "retrieval-worker",
    "consolidation-worker",
    "maintenance",
    "admin",
    "ops",
    "dr",
];

/// A Humaux process service: its image repository (after the last `/`) is `humaux-<target>` for a D-A target. The
/// pg image may be named `humaux-…` too, so the prefix alone is not the rule.
fn is_humaux(svc: &Value) -> bool {
    humaux_target(svc).is_some_and(|target| TARGETS.contains(&target))
}

/// The `<target>` of an image repository named `humaux-<target>` (any tag, any registry prefix); `None` otherwise.
fn humaux_target(svc: &Value) -> Option<&str> {
    svc.get("image")
        .and_then(Value::as_str)
        .and_then(|image| image.rsplit('/').next())
        .and_then(|repo| repo.split(':').next())
        .and_then(|repo| repo.strip_prefix("humaux-"))
}

/// `unknown_humaux_image:<svc>:<target>` for a `humaux-*` image outside [`TARGETS`]: a new process image (the planned
/// public worker, a typo) must be added to the target list, never run outside the Humaux rules (PR #2 independent
/// review P2-4). The pg image is `humaux-pg` and is listed as the one non-process exception.
fn unknown_humaux_image(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    if let Some(target) = humaux_target(svc)
        && target != "pg"
        && !TARGETS.contains(&target)
    {
        reasons.push(format!("unknown_humaux_image:{name}:{target}"));
    }
}

/// The numeric uid of `user: "<uid>[:<gid>]"`; `None` when absent or not numeric.
fn uid_of(svc: &Value) -> Option<u32> {
    svc.get("user")
        .and_then(Value::as_str)?
        .split(':')
        .next()?
        .parse()
        .ok()
}

fn strings(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// `env_file` entries: `{"path": …}` objects (Compose ≥ 2.24) or plain strings.
fn env_file_paths(svc: &Value) -> Vec<&str> {
    svc.get("env_file")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("path").unwrap_or(item).as_str())
                .collect()
        })
        .unwrap_or_default()
}

fn profiles(svc: &Value) -> Vec<&str> {
    strings(svc.get("profiles"))
}

/// ADR-0066 D-C / §5 (PR #2 round 4): the rehearsal probes by name, each with the exact `user` and gids (`user` gid
/// first, then `group_add`) it carries in prod.yml — its twin's uid and pair group, `scratch-client` none.
const REHEARSAL_PROBES: [(&str, &str, &[u32]); 5] = [
    ("scratch-as-gateway", "10101:10101", &[10101, 10201]),
    ("scratch-as-retrieval", "10102:10201", &[10201]),
    ("scratch-as-private", "10103:10202", &[10202]),
    ("scratch-as-consolidation", "10104:10104", &[10104, 10202]),
    ("scratch-client", "65534:65534", &[65534]),
];

/// A declared rehearsal probe (D-C §5), exempt from the identity and pair rules: a non-Humaux service only in the
/// rehearsal profile whose name, `user` and gids are one [`REHEARSAL_PROBES`] row. The profile alone exempts
/// nothing: any other rehearsal helper, or a probe whose identity drifted, is checked like every other service.
fn rehearsal_probe(name: &str, svc: &Value) -> bool {
    !is_humaux(svc)
        && profiles(svc) == [REHEARSAL_PROFILE]
        && REHEARSAL_PROBES.iter().any(|(probe, user, gids)| {
            *probe == name
                && svc.get("user").and_then(Value::as_str) == Some(*user)
                && gids_of(svc) == *gids
        })
        // Card 39b: `gids_of` reads numeric groups only, so a named one (`docker`) would slip past the row.
        && svc
            .get("group_add")
            .and_then(Value::as_array)
            .is_none_or(|groups| {
                groups.iter().all(|g| {
                    g.as_u64().is_some() || g.as_str().is_some_and(|s| s.parse::<u32>().is_ok())
                })
            })
}

/// The gids a service runs with: the `user` gid and every `group_add` entry (numeric ones only).
fn gids_of(svc: &Value) -> Vec<u32> {
    let primary = svc
        .get("user")
        .and_then(Value::as_str)
        .and_then(|u| u.split_once(':'))
        .and_then(|(_, g)| g.parse().ok());
    let extra = svc
        .get("group_add")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|g| match g {
            Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
            Value::String(s) => s.parse().ok(),
            _ => None,
        });
    primary.into_iter().chain(extra).collect()
}

/// `(type, source)` of every `volumes` entry (the long form `config` prints).
fn mounts(svc: &Value) -> Vec<(&str, &str)> {
    svc.get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|v| {
            (
                v.get("type").and_then(Value::as_str).unwrap_or(""),
                v.get("source").and_then(Value::as_str).unwrap_or(""),
            )
        })
        .collect()
}

/// A positive compose number (`mem_limit` prints as a byte string, `cpus` / `pids_limit` as numbers). `0` or `-1`
/// mean "unlimited" to Docker, so only `> 0` is a limit.
fn positive(value: Option<&Value>) -> Option<f64> {
    number(value).filter(|n| *n > 0.0)
}

fn carries_migrator_file(svc: &Value) -> bool {
    env_file_paths(svc)
        .iter()
        .any(|path| path.rsplit('/').next() == Some(MIGRATOR_SECRET_FILE))
}

/// Per-service hardening reasons of one Humaux service (ADR-0066 D-C, D-H).
fn service_reasons(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    match (svc.get("user").and_then(Value::as_str), uid_of(svc)) {
        (None, _) => reasons.push(format!("user_missing:{name}")),
        (Some(_), None) => reasons.push(format!("user_not_numeric:{name}")),
        (Some(_), Some(0)) if name != DR_SERVICE => reasons.push(format!("user_root:{name}")),
        _ => {}
    }
    if svc.get("read_only").and_then(Value::as_bool) != Some(true) {
        reasons.push(format!("read_only_missing:{name}"));
    }
    if !strings(svc.get("cap_drop")).contains(&"ALL") {
        reasons.push(format!("cap_drop_missing:{name}"));
    }
    escape_reasons(name, svc, reasons);
    let netns = svc.get("network_mode").and_then(Value::as_str);
    let allowed_netns = if name == DR_SERVICE {
        "host"
    } else {
        "service:netns"
    };
    if netns != Some(allowed_netns) {
        reasons.push(format!("network_mode_unexpected:{name}"));
    }
    for key in LIMIT_KEYS {
        if positive(svc.get(key)).is_none() {
            reasons.push(format!("limit_missing:{name}:{key}"));
        }
    }
    // D-C: memswap_limit = mem_limit (no swap).
    if positive(svc.get("memswap_limit")).is_some()
        && number(svc.get("memswap_limit")) != number(svc.get("mem_limit"))
    {
        reasons.push(format!("memswap_not_mem_limit:{name}"));
    }
    // D-C: every resident (no profile) is probed by its own --readyz; a one-shot has none.
    let test = strings(svc.pointer("/healthcheck/test"));
    let disabled = svc.pointer("/healthcheck/disable").and_then(Value::as_bool) == Some(true);
    if svc.get("profiles").is_none_or(Value::is_null)
        && (disabled || test.is_empty() || test == ["NONE"])
    {
        reasons.push(format!("healthcheck_missing:{name}"));
    }
    let names_migrator = svc
        .get("environment")
        .and_then(Value::as_object)
        .is_some_and(|env| env.contains_key(MIGRATOR_DSN_KEY));
    if names_migrator || (name != MIGRATOR_SERVICE && carries_migrator_file(svc)) {
        reasons.push(format!("migrator_dsn_service:{name}"));
    }
    // Review fix 6: dr.secret.env dials 127.0.0.1, which inside the shared netns is the netns container, not pg.
    if name != DR_SERVICE
        && env_file_paths(svc)
            .iter()
            .any(|path| path.rsplit('/').next() == Some(DR_SECRET_FILE))
    {
        reasons.push(format!("dr_secret_file_service:{name}"));
    }
}

/// The keys that undo the hardening, on EVERY service of the project (review fix 9, CC-1: pg, qdrant, netns and
/// the observability images included — the rules used to stop at `humaux-*` images): `privileged` grants every
/// capability and device whatever `cap_drop` says; a host namespace or a device escapes the container; the
/// daemon socket is root on the host (`dr` only, D-H L-5); `cap_add` beyond `dr`'s one (D-H); a `security_opt`
/// beside [`SECURITY_OPT`] drops the daemon's default confinement (ISO-5).
fn escape_reasons(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    let cap_add = strings(svc.get("cap_add"));
    let allowed: &[&str] = if name == DR_SERVICE { &DR_CAP_ADD } else { &[] };
    if cap_add != allowed {
        reasons.push(format!("cap_add_unexpected:{name}"));
    }
    let security_opt = strings(svc.get("security_opt"));
    if !security_opt.contains(&SECURITY_OPT[0]) {
        reasons.push(format!("no_new_privileges_missing:{name}"));
    } else if security_opt != SECURITY_OPT {
        reasons.push(format!("security_opt_extra:{name}"));
    }
    if svc.get("privileged").and_then(Value::as_bool) == Some(true) {
        reasons.push(format!("privileged:{name}"));
    }
    for key in ["pid", "ipc", "uts", "userns_mode", "cgroup"] {
        if svc.get(key).and_then(Value::as_str) == Some("host") {
            reasons.push(format!("host_namespace:{name}:{key}"));
        }
    }
    if svc
        .get("devices")
        .and_then(Value::as_array)
        .is_some_and(|d| !d.is_empty())
    {
        reasons.push(format!("devices_unexpected:{name}"));
    }
    if name != DR_SERVICE
        && mounts(svc)
            .iter()
            .any(|(_, source)| source.ends_with("docker.sock"))
    {
        reasons.push(format!("docker_socket_bind:{name}"));
    }
}

/// Review fix 9 (ISO-4, ruling R-7): every published port of every service binds the loopback host address —
/// Docker binds an omitted `host_ip` on every interface, and nothing else guarded the loopback-only publication.
fn port_reasons(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    for port in svc
        .get("ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if port.get("host_ip").and_then(Value::as_str) != Some("127.0.0.1") {
            let target = port.get("target").map(Value::to_string).unwrap_or_default();
            reasons.push(format!("port_not_loopback:{name}:{target}"));
        }
    }
}

/// `source` is one of [`BIND_DENIED_ROOTS`] or under it, or carries a secrets-directory segment.
fn bind_source_denied(source: &str) -> bool {
    BIND_DENIED_ROOTS
        .iter()
        .any(|root| source == *root || (*root != "/" && source.starts_with(&format!("{root}/"))))
        || source
            .split('/')
            .any(|segment| segment == "secrets" || segment == "secret-fixture")
}

/// Review fix 9 (ISO-2): a bind mount of any service but `dr` never reaches a denied host root or the secrets
/// directory (the only host-path rule used to be the docker socket's name); on a Humaux service it is read-only as
/// well — its state lives in named volumes (D-C). `dr` is exempt by D-H (the daemon socket, the repository, the
/// evidence directory).
fn bind_reasons(name: &str, svc: &Value, humaux: bool, reasons: &mut Vec<String>) {
    if name == DR_SERVICE {
        return;
    }
    for volume in svc
        .get("volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|v| v.get("type").and_then(Value::as_str) == Some("bind"))
    {
        let source = volume.get("source").and_then(Value::as_str).unwrap_or("");
        let target = volume.get("target").and_then(Value::as_str).unwrap_or("");
        if bind_source_denied(source) {
            reasons.push(format!("bind_mount_unexpected:{name}:{target}"));
        }
        if humaux && volume.get("read_only").and_then(Value::as_bool) != Some(true) {
            reasons.push(format!("bind_mount_writable:{name}:{target}"));
        }
    }
}

/// Review fix 9 (OP-3): residents `unless-stopped`, one-shots `no` (see [`RESTART_RESIDENT`]).
fn restart_reasons(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    let want = if profiles(svc).is_empty() {
        RESTART_RESIDENT
    } else {
        RESTART_ONE_SHOT
    };
    let found = svc
        .get("restart")
        .and_then(Value::as_str)
        .unwrap_or("missing");
    if found != want {
        reasons.push(format!("restart_policy:{name}:{found}"));
    }
}

/// Review fix 9 (ISO-3): a Humaux service loads only its own process's secret file (`<p>.secret.env`), `migrate`
/// its `migrate.secret.env`, `dr` its `dr.secret.env` plus `pg.secret.env` (D-J); any other `*.secret.env` in its
/// `env_file` list hands that process another process's credentials — nothing else refused it.
fn secret_file_reasons(name: &str, svc: &Value, reasons: &mut Vec<String>) {
    let process = process_of(svc).unwrap_or(name);
    for path in env_file_paths(svc) {
        let file = path.rsplit('/').next().unwrap_or(path);
        let Some(stem) = file.strip_suffix(".secret.env") else {
            continue;
        };
        let allowed = match name {
            MIGRATOR_SERVICE => stem == "migrate",
            DR_SERVICE => stem == "dr" || stem == "pg",
            _ => stem == process,
        };
        if !allowed {
            reasons.push(format!("secret_file_foreign:{name}:{file}"));
        }
    }
    // PR #2 round 8: and it loads its OWN files — the values file of its binary and its secret file(s). A release
    // that drops one passed R2 / U3 (the presence check reads `--secrets-dir`, not what a service loads) and the
    // process crash-looped after the old one had been stopped.
    let Some(target) = humaux_target(svc) else {
        return;
    };
    let own = match target {
        "ops" | "dr" => "maintenance",
        t => t,
    };
    let secrets: &[&str] = match name {
        MIGRATOR_SERVICE => &["migrate"],
        DR_SERVICE => &["dr", "pg"],
        _ => &[own],
    };
    let files: Vec<&str> = env_file_paths(svc)
        .into_iter()
        .map(|p| p.rsplit('/').next().unwrap_or(p))
        .collect();
    if process_of(svc) != Some(own) {
        reasons.push(format!("values_file_missing:{name}:values/{own}.env"));
    }
    for stem in secrets {
        let want = format!("{stem}.secret.env");
        if !files.contains(&want.as_str()) {
            reasons.push(format!("secret_file_missing:{name}:{want}"));
        }
    }
}

/// Every failing reason of an unresolved compose document (ADR-0066 D-R `--compose-json`). Call
/// [`resolved_env_input`] first.
pub fn compose_reasons(doc: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    let all: BTreeMap<&String, &Value> = services(doc).collect();
    for (name, svc) in &all {
        let humaux = is_humaux(svc);
        if humaux {
            service_reasons(name, svc, &mut reasons);
            secret_file_reasons(name, svc, &mut reasons);
        } else {
            unknown_humaux_image(name, svc, &mut reasons);
            escape_reasons(name, svc, &mut reasons);
        }
        port_reasons(name, svc, &mut reasons);
        bind_reasons(name, svc, humaux, &mut reasons);
        restart_reasons(name, svc, &mut reasons);
    }
    if !all
        .get(&MIGRATOR_SERVICE.to_owned())
        .is_some_and(|svc| carries_migrator_file(svc))
    {
        reasons.push("migrator_dsn_service:none".to_owned());
    }
    for name in PAIRS.iter().flat_map(|p| [p.server, p.client]) {
        if all
            .get(&name.to_owned())
            .and_then(|svc| uid_of(svc))
            .is_none()
        {
            reasons.push(format!("peer_service_missing:{name}"));
        }
    }
    reasons.extend(identity_reasons(&all));
    for pair in &PAIRS {
        reasons.extend(pair_reasons(pair, doc, &all));
    }
    reasons.extend(pg_service_image_reasons(&all));
    reasons.extend(service_target_reasons(&all));
    reasons
}

/// Card 39b (PR #2 Codex round 10): the release target each Humaux service must run. Two targets can carry one
/// binary (`ops` / `dr` are both the maintenance binary) but not the same image: `dr` alone has the docker CLI, so
/// `dr` on `humaux-ops` passed every other check and broke backups and drills after an upgrade.
/// `pg` has its own rule ([`pg_service_image_reasons`]).
const SERVICE_TARGETS: [(&str, &str); 12] = [
    ("gateway", "gateway"),
    ("retrieval-rpc", "retrieval-worker"),
    ("retrieval-serve", "retrieval-worker"),
    ("private-rpc", "private-worker"),
    ("private-distill", "private-worker"),
    ("consolidation", "consolidation-worker"),
    ("maintenance-health", "maintenance"),
    ("maintenance-serve", "maintenance"),
    ("ops", "ops"),
    ("migrate", "ops"),
    ("dr", "dr"),
    ("admin", "admin"),
];

/// Every [`SERVICE_TARGETS`] service exists and runs its target (`image_target_mismatch:<svc>:<target>`,
/// `service_missing:<svc>`), and no other service runs a `humaux-*` process image (`image_target_unexpected:<svc>`).
fn service_target_reasons(all: &BTreeMap<&String, &Value>) -> Vec<String> {
    let mut reasons = Vec::new();
    for (service, want) in SERVICE_TARGETS {
        match all.get(&service.to_owned()) {
            None => reasons.push(format!("service_missing:{service}")),
            Some(svc) => {
                let got = humaux_target(svc).unwrap_or("-");
                if got != want {
                    reasons.push(format!("image_target_mismatch:{service}:{got}"));
                }
            }
        }
    }
    for (name, svc) in all {
        if is_humaux(svc) && !SERVICE_TARGETS.iter().any(|(s, _)| s == name) {
            reasons.push(format!("image_target_unexpected:{name}"));
        }
    }
    reasons
}

/// PR #2 round 9: the `pg` service runs exactly the release's `humaux-pg:<tag>` — the tag every process image
/// carries — since `deploy-check --release` verifies that image (PGIMAGE line) and nothing else would notice an
/// upstream or stale PostgreSQL image lacking the bundled pgBackRest: `pg_image_unverified:<image>`.
fn pg_service_image_reasons(all: &BTreeMap<&String, &Value>) -> Vec<String> {
    fn image(svc: &Value) -> &str {
        svc.get("image").and_then(Value::as_str).unwrap_or("")
    }
    let tags: std::collections::BTreeSet<&str> = all
        .values()
        .filter(|svc| is_humaux(svc))
        .filter_map(|svc| image(svc).rsplit_once(':').map(|(_, tag)| tag))
        .collect();
    let Some(pg) = all.get(&"pg".to_owned()) else {
        return vec!["pg_image_unverified:<no pg service>".to_owned()];
    };
    let pg_image = image(pg);
    let ok = tags.len() == 1
        && pg_image
            .rsplit('/')
            .next()
            .and_then(|r| r.strip_prefix("humaux-pg:"))
            .is_some_and(|tag| tags.contains(tag));
    if ok {
        Vec::new()
    } else {
        vec![format!("pg_image_unverified:{pg_image}")]
    }
}

/// ADR-0066 D-C uid rule (review P1, 2026-10-08: the peer-only check let `admin` take the gateway's uid and be
/// admitted as the gateway): every Humaux service except `dr` runs as a uid in [`IDENTITY_UIDS`]; two Humaux
/// services share a uid only inside one [`SHARED_IDENTITIES`] group; a non-Humaux service outside the rehearsal
/// profile never runs as an identity uid.
fn identity_reasons(all: &BTreeMap<&String, &Value>) -> Vec<String> {
    let group_of = |name: &str| SHARED_IDENTITIES.iter().position(|g| g.contains(&name));
    let mut reasons = Vec::new();
    let mut humaux: Vec<(&str, u32)> = Vec::new();
    for (name, svc) in all {
        let Some(uid) = uid_of(svc) else { continue };
        if is_humaux(svc) {
            if name.as_str() != DR_SERVICE && !IDENTITY_UIDS.contains(&uid) {
                reasons.push(format!("uid_out_of_range:{name}"));
            }
            humaux.push((name.as_str(), uid));
        } else if !rehearsal_probe(name, svc) && IDENTITY_UIDS.contains(&uid) {
            reasons.push(format!("uid_identity_foreign:{name}"));
        }
    }
    for (i, (a, uid_a)) in humaux.iter().enumerate() {
        for (b, uid_b) in &humaux[i + 1..] {
            if uid_a == uid_b && (group_of(a).is_none() || group_of(a) != group_of(b)) {
                reasons.push(format!("uid_shared:{a},{b}"));
            }
        }
    }
    reasons
}

/// One pair's socket boundary: only [`Pair::members`] carry the pair gid or mount the socket volume (a non-member
/// with either could connect, and the server would see whatever uid it runs as), and the volume's tmpfs options
/// name the server uid, the pair gid and mode 0750 exactly once each (a later `mode=` overrides an earlier one).
fn pair_reasons(pair: &Pair, doc: &Value, all: &BTreeMap<&String, &Value>) -> Vec<String> {
    let mut reasons = Vec::new();
    for (name, svc) in all
        .iter()
        .filter(|(n, s)| !rehearsal_probe(n, s) && !pair.members.contains(&n.as_str()))
    {
        if gids_of(svc).contains(&pair.gid) {
            reasons.push(format!("pair_group_unexpected:{name}:{}", pair.gid));
        }
        if mounts(svc)
            .iter()
            .any(|(kind, source)| *kind == "volume" && *source == pair.volume)
        {
            reasons.push(format!("socket_volume_unexpected:{name}:{}", pair.volume));
        }
    }
    let opts = doc
        .pointer(&format!("/volumes/{}/driver_opts/o", pair.volume))
        .and_then(Value::as_str)
        .unwrap_or("");
    let values = |key: &str| -> Vec<&str> {
        opts.split(',')
            .filter_map(|o| o.trim().strip_prefix(key)?.strip_prefix('='))
            .collect()
    };
    if values("mode") != ["0750"] {
        reasons.push(format!("socket_volume_mode:{}", pair.volume));
    }
    let owner = all
        .get(&pair.server.to_owned())
        .and_then(|svc| uid_of(svc))
        .map(|uid| uid.to_string());
    let gid = pair.gid.to_string();
    if owner.is_none_or(|owner| values("uid") != [owner.as_str()])
        || values("gid") != [gid.as_str()]
    {
        reasons.push(format!("socket_volume_owner:{}", pair.volume));
    }
    reasons
}

// ---------------------------------------------------------------------------------------------------------------
// --env
// ---------------------------------------------------------------------------------------------------------------

/// One env file: its display name (`values/<p>.env` / `secrets/<p>.secret.env`), the process stem `<p>`, and its
/// `KEY=VALUE` lines (comments and blank lines dropped).
#[derive(Debug, Clone)]
pub struct EnvFile {
    /// `values/<p>.env` or `secrets/<p>.secret.env`; the only form a reason names.
    pub name: String,
    /// The process stem `<p>`.
    pub process: String,
    /// `KEY=VALUE` pairs in file order, each value as Compose hands it to the container (quotes removed).
    pub entries: Vec<(String, String)>,
    /// Keys whose value this gate cannot read the way Compose does (interpolation, escapes, inline comments,
    /// unbalanced quotes): named as `value_unreadable`, never judged on their raw text (PR #2 round 7).
    pub unreadable: Vec<String>,
}

/// One env_file value as Compose reads it, or `None` when reading it faithfully would need Compose's interpolation
/// or escape handling: `'…'` is literal (no `'` inside); `"…"` loses its quotes unless it holds `"`, `$` or `\`;
/// an unquoted value is taken as is unless it holds `$`, a quote, or ` #` (an inline comment).
fn compose_value(raw: &str) -> Option<&str> {
    let quoted = |q: char| raw.strip_prefix(q).and_then(|r| r.strip_suffix(q));
    if let Some(inner) = quoted('\'') {
        return (!inner.contains('\'')).then_some(inner);
    }
    if let Some(inner) = quoted('"') {
        return (!inner.contains(['"', '$', '\\'])).then_some(inner);
    }
    (!raw.contains(['$', '"', '\'']) && !raw.contains(" #")).then_some(raw)
}

impl EnvFile {
    /// Parses `text` as `KEY=VALUE` lines the way Compose's env_file parser does (review fix 9, ISO-8): `#`
    /// comments and blank lines are skipped and a leading `export ` is dropped; a repeated key keeps every
    /// occurrence so [`Self::value`] can take the last and [`Self::duplicated_keys`] can name the repeat.
    pub fn parse(name: &str, process: &str, text: &str) -> Self {
        let mut entries = Vec::new();
        let mut unreadable = Vec::new();
        for (key, raw) in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.strip_prefix("export ").map_or(line, str::trim_start))
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim(), value.trim()))
        {
            if let Some(value) = compose_value(raw) {
                entries.push((key.to_owned(), value.to_owned()));
            } else {
                entries.push((key.to_owned(), raw.to_owned()));
                if !unreadable.iter().any(|k| k == key) {
                    unreadable.push(key.to_owned());
                }
            }
        }
        Self {
            name: name.to_owned(),
            process: process.to_owned(),
            entries,
            unreadable,
        }
    }

    /// The value Compose hands the container: the LAST occurrence of `key` (review fix 9, ISO-8: first-wins read
    /// a different value than the container got).
    fn value(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Keys set more than once, each once, in first-occurrence order.
    fn duplicated_keys(&self) -> Vec<&str> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for (key, _) in &self.entries {
            if !seen.insert(key.as_str()) && !out.contains(&key.as_str()) {
                out.push(key.as_str());
            }
        }
        out
    }
}

/// Reads every `*<suffix>` file of `dir` as an [`EnvFile`] named `<label>/<file>` (sorted by name).
pub fn read_env_dir(dir: &Path, label: &str, suffix: &str) -> Result<Vec<EnvFile>, String> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read {label} dir: {e}"))? {
        let path = entry.map_err(|e| format!("read {label} dir: {e}"))?.path();
        let file = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        let Some(process) = file.strip_suffix(suffix) else {
            continue;
        };
        // `values/` holds `<p>.env` only; a `.secret.env` there is not a values file.
        if process.ends_with(".secret") {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {label}/{file}: {e}"))?;
        files.push(EnvFile::parse(&format!("{label}/{file}"), process, &text));
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// ADR-0066 D-R (b) placement over every values and secret file: no non-empty [`DEV_ONLY_KEYS`] entry, the
/// migrator DSN only in `secrets/migrate.secret.env`, the role passwords only there too (D-J: the resident
/// daemon's `maintenance.secret.env` never holds another role's password), and the maintenance DSN only in
/// `maintenance.secret.env` and `dr.secret.env` (review fix 6: `dr` is a mode of the same binary and role).
pub fn placement_reasons(files: &[EnvFile]) -> Vec<String> {
    let migrate = format!("secrets/{MIGRATOR_SECRET_FILE}");
    let mut reasons = Vec::new();
    for file in files {
        // Review fix 9 (ISO-8): a repeated key is an ambiguity the operator must resolve, never a silent last-wins.
        for key in file.duplicated_keys() {
            reasons.push(format!("key_duplicated:{}:{key}", file.name));
        }
        // PR #2 round 7: `KEY=""` is an empty value to Compose and `${X}` an interpolation; a value this gate cannot
        // read the way Compose does is named, not judged as non-empty text.
        for key in &file.unreadable {
            reasons.push(format!("value_unreadable:{}:{key}", file.name));
        }
        for (key, value) in &file.entries {
            if DEV_ONLY_KEYS.contains(&key.as_str()) && !value.is_empty() {
                reasons.push(format!("dev_only_key_set:{key}:{}", file.name));
            }
            if key == MIGRATOR_DSN_KEY && file.name != migrate {
                reasons.push(format!("migrator_dsn_misplaced:{}", file.name));
            }
            if key.starts_with(ROLE_PASSWORD_PREFIX) && file.name != migrate {
                reasons.push(format!("role_password_misplaced:{key}:{}", file.name));
            }
            if key == MAINTENANCE_DSN_KEY && !MAINTENANCE_DSN_HOMES.contains(&file.name.as_str()) {
                reasons.push(format!("maintenance_dsn_misplaced:{}", file.name));
            }
        }
    }
    reasons
}

/// ADR-0066 D-R (a) presence, per process `<p>` of the examples (review P1, 2026-10-08: the check never ran on a
/// node and, turned on, was red for a correct one):
/// - every example key is declared somewhere the process's containers get it from: `values/<p>.env`, its
///   [`secret_home`] file, or `compose` = the other env_files and the `environment:` of the services that load
///   `values/<p>.env` (node values such as the cell id come from node.env through `environment:`);
/// - it is not declared in both `values/<p>.env` and its secret file (`key_in_both`);
/// - a [`must_be_set`] key has a non-empty value (`secret_empty`): an empty secret file is a broken node. A
///   non-secret key may be empty: the values files declare the empty-by-design keys (`GLOBAL_DENYLIST=`, …);
/// - the migrator DSN is set in `secrets/migrate.secret.env`.
pub fn presence_reasons(
    examples: &[EnvFile],
    values: &[EnvFile],
    secrets: &[EnvFile],
    compose: &[EnvFile],
) -> Vec<String> {
    let mut reasons = Vec::new();
    let of = |files: &'_ [EnvFile], process: &str, key: &str| -> Vec<String> {
        files
            .iter()
            .filter(|f| f.process == process)
            .filter_map(|f| f.value(key))
            .map(str::to_owned)
            .collect()
    };
    for example in examples {
        let p = example.process.as_str();
        for (key, _) in &example.entries {
            let in_values = of(values, p, key);
            let in_secret = of(secrets, secret_home(p, key).unwrap_or(p), key);
            if !in_values.is_empty() && !in_secret.is_empty() {
                reasons.push(format!("key_in_both:{p}:{key}"));
                continue;
            }
            // ponytail: presence is per binary — a key one mode needs but only another mode's `environment:`
            // carries passes here; the pair-uid keys are judged per service in `uid_key_reasons`. Per-mode
            // consumption lists when a non-uid key ever splits that way (card 39b, PR #2 Codex round 10).
            let all: Vec<String> = [in_values, in_secret, of(compose, p, key)].concat();
            if all.is_empty() {
                reasons.push(format!("key_missing:{p}:{key}"));
            } else if must_be_set(key)
                && all.iter().all(String::is_empty)
                && !(key == AUTH_HMAC_KEY && !auth_surface_enabled(&[values, secrets, compose], p))
            {
                reasons.push(format!("secret_empty:{p}:{key}"));
            } else if key == AUTH_HMAC_KEY
                && auth_surface_enabled(&[values, secrets, compose], p)
                && all.iter().any(|value| auth_key_too_short(value))
            {
                reasons.push(format!("secret_short:{p}:{key}"));
            }
        }
    }
    if of(secrets, "migrate", MIGRATOR_DSN_KEY)
        .iter()
        .all(String::is_empty)
    {
        reasons.push("migrator_dsn_missing".to_owned());
    }
    reasons
}

/// PR #2 round 9: a key some example declares sits only in a secret file whose process may hold it — its own
/// example declares it there (`dr` holds what the maintenance example declares: it is a mode of that binary), or
/// it is `migrate`'s migrator DSN / a role password. A copy elsewhere hands that process another process's secret
/// (Compose injects every entry of the file) although its correct home is also set: `secret_key_foreign:<file>:<key>`.
pub fn secret_key_foreign_reasons(examples: &[EnvFile], secrets: &[EnvFile]) -> Vec<String> {
    let declares = |process: &str, key: &str| {
        examples
            .iter()
            .any(|e| e.process == process && e.entries.iter().any(|(k, _)| k == key))
    };
    let mut reasons = Vec::new();
    for file in secrets {
        let own = if file.process == DR_SERVICE {
            "maintenance"
        } else {
            file.process.as_str()
        };
        for (key, _) in &file.entries {
            let known = examples
                .iter()
                .any(|e| e.entries.iter().any(|(k, _)| k == key));
            let allowed = if file.process == MIGRATOR_SERVICE {
                key == MIGRATOR_DSN_KEY || key.starts_with(ROLE_PASSWORD_PREFIX)
            } else {
                declares(own, key) && secret_home(own, key) == Some(own)
            };
            if known && !allowed {
                reasons.push(format!("secret_key_foreign:{}:{key}", file.name));
            }
        }
    }
    reasons
}

/// The process stem `<p>` of a service: the `values/<p>.env` in its `env_file` list.
fn process_of(svc: &Value) -> Option<&str> {
    env_file_paths(svc).into_iter().find_map(|path| {
        let (dir, file) = path.rsplit_once('/')?;
        dir.ends_with("/values")
            .then(|| file.strip_suffix(".env"))
            .flatten()
    })
}

/// The `compose` sources of [`presence_reasons`]: for each Humaux service, its `environment:` and every env_file
/// that is neither its values file nor a secret file (those come from `--values-dir` / `--secrets-dir`), each as
/// an [`EnvFile`] of the service's process. An env_file this process cannot read is `env_file_unreadable` (in `dr`
/// every path is mounted at the host's path, D-H).
pub fn compose_env_sources(doc: &Value) -> (Vec<EnvFile>, Vec<String>) {
    let mut files = Vec::new();
    let mut reasons = Vec::new();
    for (name, svc) in services(doc).filter(|(_, svc)| is_humaux(svc)) {
        let Some(process) = process_of(svc) else {
            continue;
        };
        if let Some(env) = svc.get("environment").and_then(Value::as_object) {
            let entries = env
                .iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned()))
                .collect();
            files.push(EnvFile {
                name: format!("compose/{name}:environment"),
                process: process.to_owned(),
                entries,
                unreadable: Vec::new(),
            });
        }
        for path in env_file_paths(svc) {
            if path.ends_with(".secret.env") || path.ends_with(&format!("/values/{process}.env")) {
                continue;
            }
            // dep: fs(env_file of the compose document) — read as compose reads it (ADR-0066 D-R (a))
            match std::fs::read_to_string(path) {
                Ok(text) => files.push(EnvFile::parse(
                    &format!("compose/{name}:{path}"),
                    process,
                    &text,
                )),
                Err(_) => reasons.push(format!("env_file_unreadable:{name}:{path}")),
            }
        }
    }
    (files, reasons)
}

/// The service a compose source belongs to (`compose/<svc>:environment`, `compose/<svc>:<path>`); `None` for a
/// values, secret or example file, which every service of the process loads.
fn compose_service(file: &EnvFile) -> Option<&str> {
    file.name
        .strip_prefix("compose/")
        .and_then(|rest| rest.split_once(':'))
        .map(|(service, _)| service)
}

/// The host of a `scheme://[user[:password]@]host[:port][/db]` DSN; `None` when it has no `://`.
fn dsn_host(dsn: &str) -> Option<&str> {
    let rest = dsn.split_once("://")?.1;
    let authority = rest.split(['/', '?']).next().unwrap_or(rest);
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    Some(hostport.rsplit_once(':').map_or(hostport, |(h, _)| h))
}

/// ADR-0066 D-J, review fix 6 (S9 B1: `dr backup run` could not reach `pg:5432`): a service in the host's network
/// namespace cannot resolve a compose service name, so no `*_DSN` in a secret file it loads may name one —
/// `host_network_dsn_internal:<service>:secrets/<file>:<key>`. An empty value (the placeholder fixture) is not judged.
pub fn host_network_dsn_reasons(doc: &Value, secrets: &[EnvFile]) -> Vec<String> {
    let names: Vec<&str> = services(doc).map(|(name, _)| name.as_str()).collect();
    let mut reasons = Vec::new();
    for (name, svc) in services(doc)
        .filter(|(_, svc)| svc.get("network_mode").and_then(Value::as_str) == Some("host"))
    {
        for path in env_file_paths(svc) {
            let label = format!("secrets/{}", path.rsplit('/').next().unwrap_or(path));
            for file in secrets.iter().filter(|f| f.name == label) {
                for (key, value) in &file.entries {
                    if key.ends_with("_DSN") && dsn_host(value).is_some_and(|h| names.contains(&h))
                    {
                        reasons.push(format!("host_network_dsn_internal:{name}:{label}:{key}"));
                    }
                }
            }
        }
    }
    reasons
}

/// ADR-0066 D-R: with `--env` and `--compose-json` together, each expected-uid key equals its peer's `user` uid.
/// `files` is in Compose precedence order (values, secrets, the service's other env_files, then its `environment:`
/// entries) and the LAST source that sets the key wins — the value the container actually reads (PR #2 review:
/// a `compose/<svc>:environment` override of the uid key used to pass unseen).
pub fn uid_key_reasons(doc: &Value, files: &[EnvFile]) -> Vec<String> {
    let uid = |service: &str| {
        services(doc)
            .find(|(name, _)| name.as_str() == service)
            .and_then(|(_, svc)| uid_of(svc))
    };
    // Card 39b (PR #2 Codex round 10): the value EACH service of the process receives — the process-wide files
    // plus that service's own compose sources, the last one winning — not a value another mode happens to carry.
    let value = |process: &str, service: &str, key: &str| {
        files
            .iter()
            .filter(|f| f.process == process)
            .filter(|f| compose_service(f).is_none_or(|s| s == service))
            .filter_map(|f| f.value(key))
            .next_back()
            .and_then(|v| v.parse::<u32>().ok())
    };
    let mut reasons = Vec::new();
    for pair in &PAIRS {
        for ((process, key), peer) in [
            (pair.client_uid_key, pair.client),
            (pair.server_uid_key, pair.server),
        ] {
            let modes: Vec<&String> = services(doc)
                .filter(|(_, svc)| process_of(svc) == Some(process))
                .map(|(name, _)| name)
                .collect();
            if modes.is_empty()
                || modes.iter().any(|m| {
                    value(process, m, key).is_none() || value(process, m, key) != uid(peer)
                })
            {
                reasons.push(format!("expected_uid_mismatch:{key}"));
            }
        }
    }
    reasons
}

// ---------------------------------------------------------------------------------------------------------------
// --release
// ---------------------------------------------------------------------------------------------------------------

/// One `IMAGE` line of the release manifest (ADR-0066 D-A / R-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestImage {
    /// `<t>` of `humaux-<t>:<tag>`.
    pub target: String,
    /// The image id `build.sh` recorded (`sha256:…`).
    pub id: String,
    /// The binary the image's entrypoint is (`humaux-maintenance` for maintenance/ops/dr).
    pub binary: String,
    /// The commit the build was made from.
    pub git_sha: String,
}

/// Images a release manifest may carry beyond [`TARGETS`] (built with `--with-loadgen` for the A5 run, D-S; never in
/// prod.yml).
const OPTIONAL_TARGETS: [&str; 1] = ["loadgen"];

/// `manifest_image_missing:<target>` for every process image of [`TARGETS`] the manifest does not record and
/// `manifest_image_unknown:<target>` for a recorded image outside [`TARGETS`] / [`OPTIONAL_TARGETS`] (PR #2 Codex P1: a
/// truncated manifest used to be accepted and only its remaining subset inspected, while prod.yml still started the
/// omitted image).
pub fn manifest_target_reasons(images: &[ManifestImage]) -> Vec<String> {
    let mut reasons: Vec<String> = TARGETS
        .iter()
        .filter(|t| !images.iter().any(|i| i.target == **t))
        .map(|t| format!("manifest_image_missing:{t}"))
        .collect();
    reasons.extend(
        images
            .iter()
            .filter(|i| {
                !TARGETS.contains(&i.target.as_str())
                    && !OPTIONAL_TARGETS.contains(&i.target.as_str())
            })
            .map(|i| format!("manifest_image_unknown:{}", i.target)),
    );
    reasons
}

/// `manifest_line_malformed:<line number>` for every `IMAGE …` line [`parse_manifest_line`] cannot read (a missing
/// `id=` / `binary=` / `git_sha=`): such a line used to be dropped silently, so its image was never inspected and the
/// release gate passed around it (PR #2 independent review P2-3).
pub fn malformed_image_lines(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with("IMAGE ") && parse_manifest_line(line).is_none())
        .map(|(n, _)| format!("manifest_line_malformed:{}", n + 1))
        .collect()
}

/// Parses `PGIMAGE humaux-pg:<tag> id=<id> size=<n>` into `(reference, id)`; `None` for any other line.
pub fn parse_pg_manifest_line(line: &str) -> Option<(String, String)> {
    let mut words = line.split_whitespace();
    if words.next()? != "PGIMAGE" {
        return None;
    }
    let reference = words.next()?.to_owned();
    let id = words.find_map(|w| w.strip_prefix("id="))?.to_owned();
    Some((reference, id))
}

/// The PostgreSQL image's comparisons (PR #2 Codex P1: only `IMAGE` lines were parsed, so a swapped or tampered
/// `humaux-pg:<tag>` passed the release gate unchecked): the manifest carries a `PGIMAGE` line
/// (`manifest_pgimage_missing`), the local image exists (`pg_image_missing`), its id is the recorded one
/// (`pg_image_id_mismatch`) and its revision label is the expected sha (`pg_image_sha_mismatch`; build.sh labels
/// the pg image with `org.opencontainers.image.revision`).
pub fn pg_image_reasons(
    manifest: &str,
    expect_sha: &str,
    inspected: Option<(&str, &str)>,
) -> Vec<String> {
    let Some((_, want_id)) = manifest.lines().find_map(parse_pg_manifest_line) else {
        return vec!["manifest_pgimage_missing".to_owned()];
    };
    let Some((id, label)) = inspected else {
        return vec!["pg_image_missing".to_owned()];
    };
    let mut reasons = Vec::new();
    if id != want_id {
        reasons.push("pg_image_id_mismatch".to_owned());
    }
    if label != expect_sha {
        reasons.push("pg_image_sha_mismatch".to_owned());
    }
    reasons
}

/// Parses `IMAGE humaux-<t>:<tag> id=<id> size=<n> binary=<bin> git_sha=<sha40>`; `None` for any other line.
pub fn parse_manifest_line(line: &str) -> Option<ManifestImage> {
    let mut words = line.split_whitespace();
    if words.next()? != "IMAGE" {
        return None;
    }
    let (repo, _tag) = words.next()?.split_once(':')?;
    let target = repo.strip_prefix("humaux-")?.to_owned();
    let fields: BTreeMap<&str, &str> = words.filter_map(|w| w.split_once('=')).collect();
    Some(ManifestImage {
        target,
        id: (*fields.get("id")?).to_owned(),
        binary: (*fields.get("binary")?).to_owned(),
        git_sha: (*fields.get("git_sha")?).to_owned(),
    })
}

/// ADR-0066 D-R `--release`, the four comparisons, each with its own reason: (1) the inspected image id is the
/// manifest's; (2) the revision label and the manifest's `git_sha=` are the expected sha; (3) the `--version` first
/// token is the manifest's binary; (4) the `--version` line's `git_sha=` is the expected sha. `version_line` is
/// `None` while (1)–(2) are unchecked or red: the image's entrypoint runs only after its identity holds (PR #2
/// round 4), so (3)–(4) are judged only on a verified image.
pub fn release_reasons(
    image: &ManifestImage,
    expect_sha: &str,
    inspected_id: &str,
    revision_label: &str,
    version_line: Option<&str>,
) -> Vec<String> {
    let t = &image.target;
    let mut reasons = Vec::new();
    if inspected_id != image.id {
        reasons.push(format!("image_id_mismatch:{t}"));
    }
    if revision_label != expect_sha || image.git_sha != expect_sha {
        reasons.push(format!("image_sha_mismatch:{t}"));
    }
    let Some(version_line) = version_line else {
        return reasons;
    };
    if version_line.split_whitespace().next() != Some(image.binary.as_str()) {
        reasons.push(format!("image_binary_mismatch:{t}"));
    }
    let version_sha = version_line
        .split_whitespace()
        .find_map(|w| w.strip_prefix("git_sha="));
    if version_sha != Some(expect_sha) {
        reasons.push(format!("version_sha_mismatch:{t}"));
    }
    reasons
}

/// Review fix 9 (OP-4, ruling C2): the manifest's `CHECKOUT tree=<id> runbook=<id> roles=<id>` line against the
/// node checkout's `CHECKOUT_TREE` line (passed as a value: the dr container does not mount the checkout root).
/// An upgrade or rollback whose release carries another `deploy/`, runbook or 0011 than the running checkout
/// stops here instead of deploying the new images under the old bundle.
pub fn checkout_tree_reasons(manifest: &str, checkout_tree: Option<&str>) -> Vec<String> {
    let fields = |line: &str| -> BTreeMap<String, String> {
        line.split_whitespace()
            .filter_map(|w| w.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    };
    let Some(want) = manifest
        .lines()
        .find(|l| l.starts_with("CHECKOUT "))
        .map(fields)
    else {
        return vec!["checkout_tree_not_in_manifest".to_owned()];
    };
    let Some(have) = checkout_tree.filter(|v| !v.trim().is_empty()).map(fields) else {
        return vec!["checkout_tree_missing".to_owned()];
    };
    ["tree", "runbook", "roles"]
        .into_iter()
        .filter(|field| want.get(*field) != have.get(*field) || !want.contains_key(*field))
        .map(|field| format!("checkout_tree_mismatch:{field}"))
        .collect()
}

/// One docker CLI call; `Err` carries the command's stderr (never an env value: docker prints none here).
fn docker(args: &[&str]) -> Result<String, String> {
    // ponytail: no per-call timeout (a hung daemon hangs the one-shot), add one if the dr container ever needs it.
    // dep: subprocess(docker) — image inspect / run --version / ps / inspect of the node project (ADR-0066 D-R)
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("docker: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// PR #2 round 4: one image's verdict — the identity comparisons first; `run_version` (the image's entrypoint) is
/// called only when they hold, with the inspected immutable id; `None` from it is `image_version_timeout`.
fn judge_image(
    image: &ManifestImage,
    expect_sha: &str,
    id: &str,
    label: &str,
    run_version: impl FnOnce(&str) -> Option<String>,
) -> Vec<String> {
    let identity = release_reasons(image, expect_sha, id, label, None);
    if !identity.is_empty() {
        return identity;
    }
    match run_version(id) {
        Some(version) => release_reasons(image, expect_sha, id, label, Some(&version)),
        None => vec![format!("image_version_timeout:{}", image.target)],
    }
}

/// PR #2 round 4: the `--version` run of an image whose id and revision already match the manifest, by that
/// immutable id (a retargeted tag cannot swap the image in between), with no network, a read-only root, no
/// capabilities, the image's own `USER` (non-root for every process target; root for `dr`, still without
/// capabilities) and fixed memory / pid / cpu ceilings. A run that has not returned after
/// [`VERSION_TIMEOUT`] is removed by its name and yields `None`; a failed run yields `Some("")` (the comparisons
/// then name it).
fn version_of(id: &str, target: &str) -> Option<String> {
    // Card 39b: pid alone is near-constant inside the `dr` container, so two checks could collide on the name.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let name = format!(
        "humaux-release-check-{target}-{}-{nanos}",
        std::process::id()
    );
    let args: Vec<String> = [
        "run",
        "--rm",
        "--name",
        &name,
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "128m",
        "--memory-swap",
        "128m",
        "--pids-limit",
        "32",
        "--cpus",
        "1",
        id,
        "--version",
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = tx.send(docker(&args).unwrap_or_default());
    });
    if let Ok(version) = rx.recv_timeout(VERSION_TIMEOUT) {
        Some(version)
    } else {
        if docker(&["rm", "--force", &name]).is_err() {
            eprintln!(
                "deploy-check: container {name} outlived the version timeout and could not be removed"
            );
        }
        None
    }
}

/// How long one image's `--version` may take (a static binary printing one line returns in well under a second).
const VERSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `--release TAG --manifest FILE --expect-sha SHA40 [--checkout-tree LINE]` over every `IMAGE` line of the
/// manifest, then the checkout-tree comparison.
fn release_check(
    tag: &str,
    manifest: &str,
    expect_sha: &str,
    checkout_tree: Option<&str>,
) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(manifest).map_err(|e| format!("read manifest: {e}"))?;
    let images: Vec<ManifestImage> = text.lines().filter_map(parse_manifest_line).collect();
    if images.is_empty() {
        return Ok(vec!["manifest_empty".to_owned()]);
    }
    let mut reasons = malformed_image_lines(&text);
    reasons.extend(manifest_target_reasons(&images));
    // ponytail: the images are inspected and run one after another (about eight containers in series); parallel
    // `docker run`s if the release gate ever takes too long on a node.
    for image in &images {
        let reference = format!("humaux-{}:{tag}", image.target);
        let Ok(inspected) = docker(&[
            "image",
            "inspect",
            &reference,
            "--format",
            "{{.Id}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}",
        ]) else {
            reasons.push(format!("image_missing:{}", image.target));
            continue;
        };
        let (id, label) = inspected.split_once(' ').unwrap_or((&inspected, ""));
        reasons.extend(judge_image(image, expect_sha, id, label, |id| {
            version_of(id, &image.target)
        }));
    }
    let pg_reference = format!("humaux-pg:{tag}");
    let pg_inspected = docker(&[
        "image",
        "inspect",
        &pg_reference,
        "--format",
        "{{.Id}} {{index .Config.Labels \"org.opencontainers.image.revision\"}}",
    ])
    .ok();
    reasons.extend(pg_image_reasons(
        &text,
        expect_sha,
        pg_inspected
            .as_deref()
            .map(|i| i.split_once(' ').unwrap_or((i, ""))),
    ));
    reasons.extend(checkout_tree_reasons(&text, checkout_tree));
    Ok(reasons)
}

// ---------------------------------------------------------------------------------------------------------------
// --running
// ---------------------------------------------------------------------------------------------------------------

/// A compose size (`"536870912"`, `536870912`, `"512m"` is never in `config` output) as bytes / a number.
fn number(value: Option<&Value>) -> Option<f64> {
    match value? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// ADR-0066 D-R `--running`: each resident Humaux service (no profile) has a running, healthy, never-restarted
/// container whose `docker inspect` limits, user and read-only rootfs equal the compose values, which is not
/// privileged, drops ALL capabilities and adds none, has no-new-privileges and no docker socket mount; no container
/// of the project carries a non-empty [`DEV_ONLY_KEYS`] entry. `inspect` is the `docker inspect` array of the project.
#[allow(clippy::too_many_lines)] // one arm per inspected field, in the order the daemon reports them
pub fn running_reasons(doc: &Value, inspect: &Value) -> Vec<String> {
    let containers: Vec<&Value> = inspect
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let service_of = |c: &Value| {
        c.pointer("/Config/Labels/com.docker.compose.service")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let mut reasons = Vec::new();
    for (name, svc) in services(doc).filter(|(_, s)| is_humaux(s) && s.get("profiles").is_none()) {
        let mine: Vec<&&Value> = containers
            .iter()
            .filter(|c| service_of(c).as_deref() == Some(name))
            .collect();
        if mine.is_empty() {
            reasons.push(format!("service_not_running:{name}"));
        }
        for c in mine {
            let at = |p: &str| c.pointer(p);
            if at("/State/Status").and_then(Value::as_str) != Some("running") {
                reasons.push(format!("service_not_running:{name}"));
            }
            if at("/State/Health/Status").and_then(Value::as_str) != Some("healthy") {
                reasons.push(format!("service_unhealthy:{name}"));
            }
            if number(at("/RestartCount")) != Some(0.0) {
                reasons.push(format!("service_restarted:{name}"));
            }
            for (inspected, compose, label, scale) in [
                ("/HostConfig/Memory", "mem_limit", "memory", 1.0),
                ("/HostConfig/MemorySwap", "memswap_limit", "memswap", 1.0),
                ("/HostConfig/NanoCpus", "cpus", "cpus", 1e9),
                ("/HostConfig/PidsLimit", "pids_limit", "pids", 1.0),
            ] {
                let want = number(svc.get(compose)).map(|v| (v * scale).round());
                if want.is_none() || number(at(inspected)) != want {
                    reasons.push(format!("limit_mismatch:{name}:{label}"));
                }
            }
            if at("/Config/User").and_then(Value::as_str) != svc.get("user").and_then(Value::as_str)
            {
                reasons.push(format!("user_mismatch:{name}"));
            }
            if at("/HostConfig/ReadonlyRootfs").and_then(Value::as_bool) != Some(true) {
                reasons.push(format!("read_only_mismatch:{name}"));
            }
            // Review P1 (2026-10-08): what the daemon actually granted, not only what compose asked for.
            if at("/HostConfig/Privileged").and_then(Value::as_bool) != Some(false) {
                reasons.push(format!("privileged:{name}"));
            }
            if !strings(at("/HostConfig/CapDrop")).contains(&"ALL") {
                reasons.push(format!("cap_drop_mismatch:{name}"));
            }
            if !strings(at("/HostConfig/CapAdd")).is_empty() {
                reasons.push(format!("cap_add_mismatch:{name}"));
            }
            let security_opt = strings(at("/HostConfig/SecurityOpt"));
            if !security_opt.contains(&SECURITY_OPT[0]) {
                reasons.push(format!("no_new_privileges_mismatch:{name}"));
            } else if security_opt != SECURITY_OPT {
                reasons.push(format!("security_opt_extra:{name}"));
            }
            // Review fix 9 (OP-3): the policy the daemon holds, not only what compose asked for.
            if at("/HostConfig/RestartPolicy/Name").and_then(Value::as_str)
                != Some(RESTART_RESIDENT)
            {
                reasons.push(format!("restart_policy_mismatch:{name}"));
            }
            let sources = c
                .pointer("/Mounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|m| m.get("Source").and_then(Value::as_str));
            if strings(at("/HostConfig/Binds"))
                .into_iter()
                .chain(sources)
                .any(|b| {
                    b.split(':')
                        .next()
                        .is_some_and(|s| s.ends_with("docker.sock"))
                })
            {
                reasons.push(format!("docker_socket_bind:{name}"));
            }
        }
    }
    // PR #2 round 7: a third-party resident (pg, qdrant, netns, the observability stack) that stopped or restarted
    // after `up --wait` is red too; its limits and identity are judged on the compose document (`escape_reasons`).
    // Health is required where the container has a healthcheck.
    for (name, _) in services(doc).filter(|(_, s)| {
        !is_humaux(s)
            && s.get("profiles").is_none()
            && s.get("restart").and_then(Value::as_str) == Some(RESTART_RESIDENT)
    }) {
        let mine: Vec<&&Value> = containers
            .iter()
            .filter(|c| service_of(c).as_deref() == Some(name))
            .collect();
        if mine.is_empty()
            || mine
                .iter()
                .any(|c| c.pointer("/State/Status").and_then(Value::as_str) != Some("running"))
        {
            reasons.push(format!("service_not_running:{name}"));
        }
        if mine.iter().any(|c| {
            c.pointer("/State/Health/Status")
                .and_then(Value::as_str)
                .is_some_and(|h| h != "healthy")
        }) {
            reasons.push(format!("service_unhealthy:{name}"));
        }
        if mine
            .iter()
            .any(|c| number(c.pointer("/RestartCount")) != Some(0.0))
        {
            reasons.push(format!("service_restarted:{name}"));
        }
    }
    for c in &containers {
        let svc = service_of(c).unwrap_or_default();
        // Review fix 9 (ISO-4): every host port binding of every container is on the loopback address.
        for (port, bindings) in c
            .pointer("/HostConfig/PortBindings")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            for binding in bindings.as_array().into_iter().flatten() {
                if binding.get("HostIp").and_then(Value::as_str) != Some("127.0.0.1") {
                    reasons.push(format!("port_not_loopback:{svc}:{port}"));
                }
            }
        }
        for entry in strings(c.pointer("/Config/Env")) {
            if let Some((key, value)) = entry.split_once('=')
                && DEV_ONLY_KEYS.contains(&key)
                && !value.is_empty()
            {
                reasons.push(format!("dev_only_key_set:{key}:{svc}"));
            }
        }
    }
    reasons
}

fn running_check(project: &str, doc: &Value) -> Result<Vec<String>, String> {
    let ids = docker(&[
        "ps",
        "-aq",
        "--filter",
        &format!("label=com.docker.compose.project={project}"),
    ])?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    let inspect = if ids.is_empty() {
        Value::Array(Vec::new())
    } else {
        let mut args = vec!["inspect"];
        args.extend(&ids);
        serde_json::from_str(&docker(&args)?).map_err(|e| format!("docker inspect json: {e}"))?
    };
    Ok(running_reasons(doc, &inspect))
}

// ---------------------------------------------------------------------------------------------------------------
// --secrets-readable
// ---------------------------------------------------------------------------------------------------------------

/// ADR-0066 D-R / §5 `dr_reads_0600_secret`: `secret_unreadable:<path>` for every file (or directory) under `dir`
/// this process cannot read. Contents are read into a sink and never kept.
pub fn secrets_unreadable(dir: &Path) -> Vec<String> {
    let mut reasons = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return vec![format!("secret_unreadable:{}", dir.display())],
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            reasons.extend(secrets_unreadable(&path));
        } else if std::fs::File::open(&path)
            .and_then(|mut f| std::io::copy(&mut f, &mut std::io::sink()))
            .is_err()
        {
            reasons.push(format!("secret_unreadable:{}", path.display()));
        }
    }
    reasons.sort();
    reasons
}

// ---------------------------------------------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------------------------------------------

/// The value after `name`; `None` when the flag is absent. A following token that is itself a flag is not a
/// value (review fix 9, OP-7: `--compose-json` with its value dropped ran zero checks and exited 0).
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

/// Every flag that takes a value: present without one is a usage error naming it.
const VALUE_FLAGS: [&str; 10] = [
    "--compose-json",
    "--values-dir",
    "--secrets-dir",
    "--examples-dir",
    "--release",
    "--manifest",
    "--expect-sha",
    "--checkout-tree",
    "--project",
    "--secrets-readable",
];

fn flag_without_value(args: &[String]) -> Option<&'static str> {
    VALUE_FLAGS.into_iter().find(|name| {
        // Card 39b: `--compose-json=F` is not a form `flag` reads — beside another check it was silently dropped.
        let joined = format!("{name}=");
        args.iter().any(|a| a.starts_with(&joined))
            || (has(args, name) && flag(args, name).is_none())
    })
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// One check's result: `fail` iff it has reasons.
fn check(name: &str, reasons: Vec<String>) -> Value {
    let status = if reasons.is_empty() { "pass" } else { "fail" };
    json!({ "check": name, "status": status, "reasons": reasons })
}

fn read_compose(source: &str) -> Result<Value, String> {
    let mut text = String::new();
    if source == "-" {
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("read stdin: {e}"))?;
    } else {
        text = std::fs::read_to_string(source).map_err(|e| format!("read {source}: {e}"))?;
    }
    serde_json::from_str(&text).map_err(|e| format!("--compose-json is not JSON: {e}"))
}

/// What a run decided: the checks, or a usage/refusal (exit 2) or an infrastructure failure (exit 1).
type Outcome = Result<Vec<Value>, (u8, String)>;

fn env_checks(
    args: &[String],
    doc: Option<&Value>,
    checks: &mut Vec<Value>,
) -> Result<(), (u8, String)> {
    let usage = |m: &str| (2u8, m.to_owned());
    let values_dir =
        flag(args, "--values-dir").ok_or_else(|| usage("--env needs --values-dir DIR"))?;
    let secrets_dir =
        flag(args, "--secrets-dir").ok_or_else(|| usage("--env needs --secrets-dir DIR"))?;
    let values = read_env_dir(Path::new(&values_dir), "values", ".env").map_err(|e| (1, e))?;
    let secrets =
        read_env_dir(Path::new(&secrets_dir), "secrets", ".secret.env").map_err(|e| (1, e))?;
    let all: Vec<EnvFile> = values.iter().chain(&secrets).cloned().collect();
    checks.push(check("env_placement", placement_reasons(&all)));
    if !has(args, "--placement-only") {
        // Review P1 (2026-10-08): a missing --examples-dir used to make presence `not_applicable` (exit 0), so the
        // node's only pre-`up` config guard (D-N) never ran. The examples ship in every image (D-T), and the node
        // environment comes from the compose document, so both are required: a caller error, never a quiet pass.
        let (Some(dir), Some(doc)) = (flag(args, "--examples-dir"), doc) else {
            return Err(usage(
                "--env needs --examples-dir DIR and --compose-json FILE|- (or --placement-only)",
            ));
        };
        let examples = read_env_dir(Path::new(&dir), "example", ".env").map_err(|e| (1, e))?;
        if examples.is_empty() {
            return Err((1, format!("--examples-dir {dir}: no <process>.env file")));
        }
        let (compose, mut reasons) = compose_env_sources(doc);
        reasons.extend(presence_reasons(&examples, &values, &secrets, &compose));
        reasons.extend(secret_key_foreign_reasons(&examples, &secrets));
        checks.push(check("env_presence", reasons));
    }
    if let Some(doc) = doc {
        // Compose precedence: env files (values, secrets, the other env_files) then `environment:` — the last
        // source wins, so the compose sources are appended after the files.
        let (compose, _) = compose_env_sources(doc);
        let (env_files, environment): (Vec<EnvFile>, Vec<EnvFile>) = compose
            .into_iter()
            .partition(|f| !f.name.ends_with(":environment"));
        let effective: Vec<EnvFile> = all
            .iter()
            .cloned()
            .chain(env_files)
            .chain(environment)
            .collect();
        checks.push(check("expected_uid_keys", uid_key_reasons(doc, &effective)));
        checks.push(check(
            "host_network_dsn",
            host_network_dsn_reasons(doc, &secrets),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one flag → one check, in the order the receipt lists them
fn checks(args: &[String]) -> Outcome {
    if let Some(name) = flag_without_value(args) {
        return Err((2, format!("{name} needs a value")));
    }
    let mut out = Vec::new();
    let doc = match flag(args, "--compose-json") {
        None => None,
        Some(source) => {
            let doc = read_compose(&source).map_err(|e| (1, e))?;
            if let Some(refusal) = resolved_env_input(&doc) {
                return Err((2, refusal));
            }
            out.push(check("compose", compose_reasons(&doc)));
            Some(doc)
        }
    };
    if has(args, "--env") {
        env_checks(args, doc.as_ref(), &mut out)?;
    }
    if let Some(tag) = flag(args, "--release") {
        let (Some(manifest), Some(sha)) = (flag(args, "--manifest"), flag(args, "--expect-sha"))
        else {
            return Err((
                2,
                "--release TAG needs --manifest FILE --expect-sha SHA40".to_owned(),
            ));
        };
        let checkout_tree = flag(args, "--checkout-tree");
        out.push(check(
            "release",
            release_check(&tag, &manifest, &sha, checkout_tree.as_deref()).map_err(|e| (1, e))?,
        ));
    }
    if has(args, "--running") {
        let (Some(project), Some(doc)) = (flag(args, "--project"), doc.as_ref()) else {
            return Err((
                2,
                "--running needs --project P and --compose-json FILE".to_owned(),
            ));
        };
        out.push(check(
            "running",
            running_check(&project, doc).map_err(|e| (1, e))?,
        ));
    }
    if let Some(dir) = flag(args, "--secrets-readable") {
        out.push(check(
            "secrets_readable",
            secrets_unreadable(Path::new(&dir)),
        ));
    }
    if out.is_empty() {
        return Err((
            2,
            "no check selected: pass --compose-json, --env, --release, --running or --secrets-readable".to_owned(),
        ));
    }
    Ok(out)
}

/// `deploy-check (--compose-json FILE|-) (--env --values-dir D --secrets-dir S [--examples-dir E]
/// [--placement-only]) (--release TAG --manifest FILE --expect-sha SHA40 [--checkout-tree LINE])
/// (--running --project P) (--secrets-readable DIR)`: one JSON receipt on stdout; exit 0 all pass, 3 any fail,
/// 2 usage (a mode flag without its value, no check selected) or `resolved_env_input`, 1 an unreadable input
/// or a docker failure.
pub fn run(args: &[String]) -> u8 {
    match checks(args) {
        Ok(checks) => {
            let failed = checks.iter().any(|c| c["status"] == "fail");
            println!("{}", json!({ "command": "deploy-check", "checks": checks }));
            if failed { 3 } else { 0 }
        }
        Err((code, message)) => {
            eprintln!("humaux-maintenance: deploy-check: {message}");
            code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `docker compose -p humaux-fixture --env-file deploy/env/sizing-a5.env --env-file deploy/env/node.env.example
    /// -f deploy/compose/prod.yml --profile ops --profile rehearsal config --format json --no-env-resolution`
    /// (ADR-0066 D-R, RF-3: env_file paths, no values; the secrets dir is the placeholder fixture), captured in S6 with
    /// the checkout prefix rewritten to `/srv/humaux-node/repo`. Gate `c39_deploy_check_live` runs the same checks
    /// on the live prod.yml every chain, so this frozen copy cannot hide a drift.
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/prod.compose.json"))
            .expect("fixture json")
    }

    fn service<'a>(doc: &'a mut Value, name: &str) -> &'a mut serde_json::Map<String, Value> {
        doc["services"][name].as_object_mut().expect("service")
    }

    fn files(spec: &[(&str, &str, &str)]) -> Vec<EnvFile> {
        spec.iter()
            .map(|(name, process, text)| EnvFile::parse(name, process, text))
            .collect()
    }

    /// The four expected-uid keys at the fixture's uids.
    fn uid_values() -> Vec<EnvFile> {
        files(&[
            (
                "values/gateway.env",
                "gateway",
                "HUMAUX_GATEWAY_RETRIEVAL_RPC_SERVER_UID=10102",
            ),
            (
                "values/retrieval-worker.env",
                "retrieval-worker",
                "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10101",
            ),
            (
                "values/private-worker.env",
                "private-worker",
                "HUMAUX_PRIVATE_WORKER_CONSOLIDATION_UID=10104",
            ),
            (
                "values/consolidation-worker.env",
                "consolidation-worker",
                "HUMAUX_CONSOLIDATION_WORKER_RPC_SERVER_UID=10103",
            ),
        ])
    }

    /// The card fault: one Humaux service without `user:` is red, named; the fixture itself is green.
    /// Fault: drop the `user_missing` arm ⇒ red.
    #[test]
    fn compose_service_without_user_is_red() {
        let mut doc = fixture();
        assert_eq!(
            compose_reasons(&doc),
            Vec::<String>::new(),
            "the fixture is green"
        );
        service(&mut doc, "maintenance-serve").remove("user");
        assert_eq!(
            compose_reasons(&doc),
            vec!["user_missing:maintenance-serve".to_owned()]
        );
    }

    /// An expected-uid key that is not its peer's `user` uid is red, named by key. Fault: compare a key against
    /// its own service ⇒ red.
    #[test]
    fn compose_peer_uid_keys_mismatch_is_red() {
        let doc = fixture();
        assert_eq!(uid_key_reasons(&doc, &uid_values()), Vec::<String>::new());
        // PR #2 review: a `compose/<svc>:environment` entry overrides the values file (last source wins).
        let mut overridden = uid_values();
        overridden.push(EnvFile::parse(
            "compose/retrieval-rpc:environment",
            "retrieval-worker",
            "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10106",
        ));
        assert_eq!(
            uid_key_reasons(&doc, &overridden),
            vec!["expected_uid_mismatch:HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID".to_owned()]
        );
        // Card 39b (PR #2 Codex round 10): the key on retrieval-serve alone never reaches retrieval-rpc.
        let mut one_mode = uid_values();
        one_mode[1] = EnvFile::parse("values/retrieval-worker.env", "retrieval-worker", "");
        one_mode.push(EnvFile::parse(
            "compose/retrieval-serve:environment",
            "retrieval-worker",
            "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10101",
        ));
        assert_eq!(
            uid_key_reasons(&doc, &one_mode),
            vec!["expected_uid_mismatch:HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID".to_owned()]
        );
        let mut wrong = uid_values();
        wrong[1] = EnvFile::parse(
            "values/retrieval-worker.env",
            "retrieval-worker",
            "HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10102",
        );
        assert_eq!(
            uid_key_reasons(&doc, &wrong),
            vec!["expected_uid_mismatch:HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID".to_owned()]
        );
    }

    /// RF-3: an inlined `…_DSN` value means resolved input; refused, the reason names the key and never the value.
    /// Fault: skip the guard ⇒ red.
    #[test]
    fn compose_resolved_env_input_is_refused() {
        let mut doc = fixture();
        assert_eq!(resolved_env_input(&doc), None);
        service(&mut doc, "gateway").insert(
            "environment".to_owned(),
            json!({ "HUMAUX_GATEWAY_PG_DSN": "postgres://u:inline-secret@pg/db" }),
        );
        let refusal = resolved_env_input(&doc).expect("refused");
        assert_eq!(refusal, "resolved_env_input:gateway:HUMAUX_GATEWAY_PG_DSN");
        assert!(!refusal.contains("inline-secret"));
        let mut path_only = fixture();
        service(&mut path_only, "pg").insert(
            "environment".to_owned(),
            json!({ "POSTGRES_PASSWORD_FILE": "/run/secrets/pg_superuser" }),
        );
        assert_eq!(
            resolved_env_input(&path_only),
            None,
            "a *_FILE path is not a resolved secret (D-J)"
        );
        assert_eq!(
            run(&["--compose-json".to_owned(), "/nonexistent".to_owned()]),
            1,
            "an unreadable input is infrastructure, not a pass"
        );
    }

    /// RF-7: `migrate.secret.env` on `ops` as well is red, naming `ops`. Fault: skip the env_file scan ⇒ red.
    #[test]
    fn compose_migrator_env_file_on_two_services_is_red() {
        let mut doc = fixture();
        let migrate_file = doc["services"]["migrate"]["env_file"][1].clone();
        service(&mut doc, "ops")["env_file"]
            .as_array_mut()
            .expect("env_file")
            .push(migrate_file);
        assert_eq!(
            compose_reasons(&doc),
            vec![
                "migrator_dsn_service:ops".to_owned(),
                // Review fix 9 (ISO-3): the same file is also another process's secret file.
                "secret_file_foreign:ops:migrate.secret.env".to_owned()
            ]
        );
    }

    /// One mutation of the fixture ⇒ exactly the named reasons (the fixture itself is green). Each case is the fault
    /// of one arm: delete the arm and its case goes green-with-no-reason, so the assertion is red.
    fn assert_case(case: &str, mutate: impl FnOnce(&mut Value), want: &[&str]) {
        let mut doc = fixture();
        mutate(&mut doc);
        assert_eq!(compose_reasons(&doc), want, "case {case}");
    }

    /// Review P1 (2026-10-08): every per-service hardening arm of `--compose-json` (D-C, D-H), including the keys
    /// that undo the hardening (`privileged`, a host namespace, a device, the docker socket) and limits that are
    /// present but unlimited (`mem_limit: 0`). Faults: drop any arm ⇒ its case is red.
    #[test]
    #[allow(clippy::too_many_lines)] // one table: a case per arm, so a dropped arm names itself
    fn compose_hardening_arms_each_red() {
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation, &[&str]); 22] = [
            (
                "read_only",
                |d| {
                    service(d, "gateway").insert("read_only".into(), json!(false));
                },
                &["read_only_missing:gateway"],
            ),
            (
                "cap_drop",
                |d| {
                    service(d, "gateway").insert("cap_drop".into(), json!([]));
                },
                &["cap_drop_missing:gateway"],
            ),
            (
                "cap_add",
                |d| {
                    service(d, "gateway").insert("cap_add".into(), json!(["NET_ADMIN"]));
                },
                &["cap_add_unexpected:gateway"],
            ),
            (
                "dr cap_add exact",
                |d| {
                    service(d, "dr").insert(
                        "cap_add".into(),
                        json!(["DAC_READ_SEARCH", "DAC_OVERRIDE", "SYS_ADMIN"]),
                    );
                },
                &["cap_add_unexpected:dr"],
            ),
            (
                "no_new_privileges",
                |d| {
                    service(d, "gateway").insert("security_opt".into(), json!([]));
                },
                &["no_new_privileges_missing:gateway"],
            ),
            (
                "privileged",
                |d| {
                    service(d, "gateway").insert("privileged".into(), json!(true));
                },
                &["privileged:gateway"],
            ),
            (
                "network_mode",
                |d| {
                    service(d, "gateway").insert("network_mode".into(), json!("host"));
                },
                &["network_mode_unexpected:gateway"],
            ),
            (
                "pid host",
                |d| {
                    service(d, "gateway").insert("pid".into(), json!("host"));
                },
                &["host_namespace:gateway:pid"],
            ),
            (
                "devices",
                |d| {
                    service(d, "gateway").insert(
                        "devices".into(),
                        json!([{ "source": "/dev/kvm", "target": "/dev/kvm" }]),
                    );
                },
                &["devices_unexpected:gateway"],
            ),
            (
                "docker socket",
                |d| {
                    service(d, "gateway")["volumes"].as_array_mut().expect("volumes").push(
                    json!({ "type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock" }));
                },
                &[
                    "docker_socket_bind:gateway",
                    // Review fix 9 (ISO-2): the daemon socket is also a denied bind root and (on a Humaux
                    // service) a writable bind.
                    "bind_mount_unexpected:gateway:/var/run/docker.sock",
                    "bind_mount_writable:gateway:/var/run/docker.sock",
                ],
            ),
            (
                "mem_limit 0",
                |d| {
                    service(d, "gateway").insert("mem_limit".into(), json!("0"));
                },
                &[
                    "limit_missing:gateway:mem_limit",
                    "memswap_not_mem_limit:gateway",
                ],
            ),
            (
                "memswap -1",
                |d| {
                    service(d, "gateway").insert("memswap_limit".into(), json!("-1"));
                },
                &["limit_missing:gateway:memswap_limit"],
            ),
            (
                "memswap != mem",
                |d| {
                    service(d, "gateway").insert("memswap_limit".into(), json!("2147483648"));
                },
                &["memswap_not_mem_limit:gateway"],
            ),
            (
                "cpus",
                |d| {
                    service(d, "gateway").remove("cpus");
                },
                &["limit_missing:gateway:cpus"],
            ),
            (
                "pids 0",
                |d| {
                    service(d, "gateway").insert("pids_limit".into(), json!(0));
                },
                &["limit_missing:gateway:pids_limit"],
            ),
            (
                "healthcheck removed",
                |d| {
                    service(d, "retrieval-rpc").remove("healthcheck");
                },
                &["healthcheck_missing:retrieval-rpc"],
            ),
            (
                "healthcheck disabled",
                |d| {
                    service(d, "retrieval-rpc")
                        .insert("healthcheck".into(), json!({ "disable": true }));
                },
                &["healthcheck_missing:retrieval-rpc"],
            ),
            (
                "user root",
                |d| {
                    service(d, "maintenance-health").insert("user".into(), json!("0:0"));
                },
                &[
                    "user_root:maintenance-health",
                    "uid_out_of_range:maintenance-health",
                    "uid_shared:dr,maintenance-health",
                ],
            ),
            (
                "user name",
                |d| {
                    service(d, "maintenance-health").insert("user".into(), json!("humaux"));
                },
                &["user_not_numeric:maintenance-health"],
            ),
            (
                "dr network host is its exemption only",
                |d| {
                    service(d, "dr").insert("network_mode".into(), json!("service:netns"));
                },
                &["network_mode_unexpected:dr"],
            ),
            (
                "dr docker socket exempt",
                |d| {
                    service(d, "dr").insert("privileged".into(), json!(true));
                },
                &["privileged:dr"],
            ),
            (
                "dr.secret.env on a resident (review fix 6)",
                |d| {
                    let dr_file = d["services"]["dr"]["env_file"][3].clone();
                    service(d, "maintenance-serve")["env_file"]
                        .as_array_mut()
                        .expect("env_file")
                        .push(dr_file);
                },
                &[
                    "dr_secret_file_service:maintenance-serve",
                    // Review fix 9 (ISO-3): dr.secret.env is also another process's secret file.
                    "secret_file_foreign:maintenance-serve:dr.secret.env",
                ],
            ),
        ];
        assert_eq!(
            compose_reasons(&fixture()),
            Vec::<String>::new(),
            "the fixture is green"
        );
        for (case, mutate, want) in cases {
            assert_case(case, mutate, want);
        }
    }

    /// Review P1 (2026-10-08), D-C uid rule: `admin` running as the gateway's uid (it holds the retrieval pair group
    /// and mounts the socket) is red; so is any other Humaux service sharing a uid outside its binary's modes, a
    /// uid outside 10101–10107, and a non-Humaux service outside the rehearsal profile running as an identity uid.
    /// The fixture's shared uids (two modes of one binary; `ops` with the maintenance daemon) and the rehearsal
    /// probes stay green. PR #2 round 4: the rehearsal profile alone exempts nothing — an unlisted helper in it with
    /// a probe's identity, and a listed probe whose uid drifted, get the uid and pair rules. Faults: compare the four
    /// peers only ⇒ the admin case is red; drop the range ⇒ red; exempt by profile only ⇒ the two probe cases red.
    #[test]
    #[allow(clippy::too_many_lines)] // one table: a case per rule
    fn compose_identity_uid_rules() {
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation, &[&str]); 7] = [
            (
                "unlisted rehearsal helper",
                |d| {
                    let probe = d["services"]["scratch-as-gateway"].clone();
                    d["services"]
                        .as_object_mut()
                        .expect("services")
                        .insert("scratch-helper".into(), probe);
                },
                &[
                    "uid_identity_foreign:scratch-helper",
                    "pair_group_unexpected:scratch-helper:10201",
                    "socket_volume_unexpected:scratch-helper:sock-retrieval",
                    "socket_volume_unexpected:scratch-helper:sock-inference",
                ],
            ),
            (
                "probe identity drifted",
                |d| {
                    service(d, "scratch-as-consolidation")
                        .insert("user".into(), json!("10101:10101"));
                },
                &[
                    "uid_identity_foreign:scratch-as-consolidation",
                    "socket_volume_unexpected:scratch-as-consolidation:sock-retrieval",
                    "pair_group_unexpected:scratch-as-consolidation:10202",
                    "socket_volume_unexpected:scratch-as-consolidation:sock-inference",
                ],
            ),
            (
                "admin as gateway",
                |d| {
                    service(d, "admin").insert("user".into(), json!("10101:10101"));
                },
                &["uid_shared:admin,gateway"],
            ),
            (
                "consolidation as gateway",
                |d| {
                    service(d, "consolidation").insert("user".into(), json!("10101:10101"));
                },
                &["uid_shared:consolidation,gateway"],
            ),
            (
                "migrate as maintenance",
                |d| {
                    service(d, "migrate").insert("user".into(), json!("10105:10105"));
                },
                &[
                    "uid_shared:maintenance-health,migrate",
                    "uid_shared:maintenance-serve,migrate",
                    "uid_shared:migrate,ops",
                ],
            ),
            (
                "out of range",
                |d| {
                    service(d, "migrate").insert("user".into(), json!("10199:10199"));
                },
                &["uid_out_of_range:migrate"],
            ),
            (
                "foreign identity",
                |d| {
                    service(d, "prometheus").insert("user".into(), json!("10104:10104"));
                },
                &["uid_identity_foreign:prometheus"],
            ),
        ];
        for (case, mutate, want) in cases {
            assert_case(case, mutate, want);
        }
    }

    /// Card 39b (gate-reviewer round 4 P2-2/P2-3): each clause of a probe's exemption is load-bearing on its own —
    /// the profile, the `user`, the gids, and numeric-only `group_add`. Fault: drop any one clause ⇒ its case is red.
    #[test]
    fn rehearsal_probe_clauses_each_hold() {
        let doc = fixture();
        let probe = doc["services"]["scratch-as-gateway"].clone();
        assert!(
            rehearsal_probe("scratch-as-gateway", &probe),
            "the fixture probe is exempt"
        );
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation); 4] = [
            ("profile", |p| p["profiles"] = json!(["rehearsal", "ops"])),
            ("user only", |p| p["user"] = json!("10102:10101")),
            ("gids only", |p| p["group_add"] = json!(["10201", "10202"])),
            ("named group", |p| {
                p["group_add"] = json!(["10201", "docker"])
            }),
        ];
        for (case, mutate) in cases {
            let mut p = probe.clone();
            mutate(&mut p);
            assert!(!rehearsal_probe("scratch-as-gateway", &p), "case {case}");
        }
    }

    /// Review P1 (2026-10-08): only a pair's members carry its gid or mount its socket volume; a rehearsal probe is
    /// exempt, a non-Humaux service outside that profile is not. Fault: skip the membership scan ⇒ red.
    #[test]
    fn compose_pair_membership_is_closed() {
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation, &[&str]); 3] = [
            (
                "group",
                |d| {
                    service(d, "maintenance-serve").insert("group_add".into(), json!(["10201"]));
                },
                &["pair_group_unexpected:maintenance-serve:10201"],
            ),
            (
                "volume",
                |d| {
                    service(d, "maintenance-serve")["volumes"].as_array_mut().expect("volumes").push(
                    json!({ "type": "volume", "source": "sock-inference", "target": "/run/humaux/sock-inference" }));
                },
                &["socket_volume_unexpected:maintenance-serve:sock-inference"],
            ),
            (
                "foreign group",
                |d| {
                    service(d, "prometheus").insert("group_add".into(), json!([10202]));
                },
                &["pair_group_unexpected:prometheus:10202"],
            ),
        ];
        for (case, mutate, want) in cases {
            assert_case(case, mutate, want);
        }
    }

    /// Review P1 (2026-10-08): the socket volume's tmpfs options carry `mode=0750`, the server uid and the pair gid
    /// exactly once; a later `mode=0777` overrides an earlier `mode=0750` in the mount, so it is red. Faults: test
    /// `contains("mode=0750")` ⇒ the override case is red; drop the mode or owner arm ⇒ red.
    #[test]
    fn compose_socket_volume_options_are_exact() {
        let opts = |o: &str| {
            let mut doc = fixture();
            doc["volumes"]["sock-retrieval"]["driver_opts"]["o"] = json!(o);
            compose_reasons(&doc)
        };
        assert_eq!(opts("uid=10102,gid=10201,mode=0750"), Vec::<String>::new());
        assert_eq!(
            opts("uid=10102,gid=10201,mode=0750,mode=0777"),
            vec!["socket_volume_mode:sock-retrieval".to_owned()]
        );
        assert_eq!(
            opts("uid=10102,gid=10201,mode=0770"),
            vec!["socket_volume_mode:sock-retrieval".to_owned()]
        );
        assert_eq!(
            opts("uid=10101,gid=10201,mode=0750"),
            vec!["socket_volume_owner:sock-retrieval".to_owned()]
        );
        assert_eq!(
            opts("uid=10102,gid=10202,mode=0750"),
            vec!["socket_volume_owner:sock-retrieval".to_owned()]
        );
        assert_eq!(
            opts(""),
            vec![
                "socket_volume_mode:sock-retrieval".to_owned(),
                "socket_volume_owner:sock-retrieval".to_owned()
            ]
        );
    }

    /// RF-2: `ALLOW_SAME_UID=1` in a production values file is red; an empty value (the dev-off form) is not.
    /// Fault: drop the DEV_ONLY check ⇒ red.
    #[test]
    fn env_dev_only_key_set_is_red() {
        let clean = files(&[(
            "values/private-worker.env",
            "private-worker",
            "HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID=",
        )]);
        assert_eq!(placement_reasons(&clean), Vec::<String>::new());
        let set = files(&[(
            "values/private-worker.env",
            "private-worker",
            "HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID=1",
        )]);
        assert_eq!(
            placement_reasons(&set),
            vec![
                "dev_only_key_set:HUMAUX_PRIVATE_WORKER_ALLOW_SAME_UID:values/private-worker.env"
                    .to_owned()
            ]
        );
    }

    /// RF-7: the migrator key copied into another secret file is red, naming the file (not the value).
    /// Fault: accept the key in any `*.secret.env` ⇒ red.
    #[test]
    fn env_migrator_dsn_outside_migrate_is_red() {
        let spec = [
            (
                "secrets/migrate.secret.env",
                "migrate",
                "HUMAUX_MIGRATOR_PG_DSN=postgres://s3cret@pg/db",
            ),
            (
                "secrets/maintenance.secret.env",
                "maintenance",
                "HUMAUX_MIGRATOR_PG_DSN=postgres://s3cret@pg/db",
            ),
        ];
        assert_eq!(placement_reasons(&files(&spec[..1])), Vec::<String>::new());
        let reasons = placement_reasons(&files(&spec));
        assert_eq!(
            reasons,
            vec!["migrator_dsn_misplaced:secrets/maintenance.secret.env".to_owned()]
        );
        assert!(reasons.iter().all(|r| !r.contains("s3cret")));
    }

    /// D-R (a): a key declared nowhere is red, one in both the values and the secret file is red, an empty secret
    /// is red, an empty non-secret and an empty rotation twin are green, a key from the compose `environment:` is
    /// present, a role password is looked up in `migrate.secret.env`, and an empty migrator DSN is red.
    /// Faults: accept an empty secret (review P1: an empty secret file passed PRECHECK) ⇒ red; ignore the compose
    /// sources (the node values come from `environment:`) ⇒ red; look role passwords up in `<p>.secret.env` ⇒ red.
    #[test]
    fn env_key_missing_is_red() {
        let examples = files(&[
            (
                "example/gateway.env",
                "gateway",
                "HUMAUX_A=\nHUMAUX_B=\nHUMAUX_C=\nHUMAUX_GATEWAY_PG_DSN=\nHUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS=\n\
                 HUMAUX_GATEWAY_CELL_ID=\nHUMAUX_GATEWAY_TOKEN_HMAC_KEY=\n",
            ),
            (
                "example/maintenance.env",
                "maintenance",
                "HUMAUX_ROLE_PASSWORD_ADMIN=\n",
            ),
        ]);
        let values = files(&[(
            "values/gateway.env",
            "gateway",
            "HUMAUX_A=1\nHUMAUX_B=\nHUMAUX_C=3",
        )]);
        let secrets = |migrator: &str| {
            files(&[
                (
                    "secrets/gateway.secret.env",
                    "gateway",
                    "HUMAUX_C=x\nHUMAUX_GATEWAY_PG_DSN=\nHUMAUX_GATEWAY_TOKEN_HMAC_KEY_PREVIOUS=\n\
                     HUMAUX_GATEWAY_TOKEN_HMAC_KEY=k",
                ),
                (
                    "secrets/migrate.secret.env",
                    "migrate",
                    &format!("HUMAUX_MIGRATOR_PG_DSN={migrator}\nHUMAUX_ROLE_PASSWORD_ADMIN=p"),
                ),
            ])
        };
        let compose = files(&[(
            "compose/gateway:environment",
            "gateway",
            "HUMAUX_GATEWAY_CELL_ID=00000000-0000-4000-8000-000000000001",
        )]);
        assert_eq!(
            presence_reasons(&examples, &values, &secrets("x"), &compose),
            vec![
                "key_in_both:gateway:HUMAUX_C".to_owned(),
                "secret_empty:gateway:HUMAUX_GATEWAY_PG_DSN".to_owned(),
            ]
        );
        assert_eq!(
            presence_reasons(&examples, &values, &secrets(""), &[]),
            vec![
                "key_in_both:gateway:HUMAUX_C".to_owned(),
                "secret_empty:gateway:HUMAUX_GATEWAY_PG_DSN".to_owned(),
                "key_missing:gateway:HUMAUX_GATEWAY_CELL_ID".to_owned(),
                "migrator_dsn_missing".to_owned(),
            ]
        );
        let unread = json!({ "services": { "gateway": {
            "image": "humaux-gateway:t",
            "env_file": [{ "path": "/srv/x/deploy/env/values/gateway.env" },
                         { "path": "/nonexistent/humaux_c39/node.env" }],
            "environment": { "HUMAUX_GATEWAY_CELL_ID": "c" } } } });
        let (sources, reasons) = compose_env_sources(&unread);
        assert_eq!(
            reasons,
            vec!["env_file_unreadable:gateway:/nonexistent/humaux_c39/node.env".to_owned()]
        );
        assert_eq!(sources.len(), 1, "the environment, not the values file");
        assert_eq!(sources[0].process, "gateway");
    }

    /// M02-3: the gateway's auth MAC key may be empty while the auth surface is off (absent or `false`), and is
    /// `secret_empty` the moment `HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED=true` (values or compose) with the key still
    /// empty; ADR-0059 D-G requires a decoded key at the security floor. Another empty secret stays red either way.
    /// Fault: remove the key-length validation ⇒ the exact short-key refusal is red.
    #[test]
    fn env_auth_key_is_required_only_when_the_auth_surface_is_on() {
        let examples = files(&[(
            "example/gateway.env",
            "gateway",
            "HUMAUX_GATEWAY_AUTH_HMAC_KEY=\nHUMAUX_GATEWAY_AUTH_SURFACE_ENABLED=\nHUMAUX_GATEWAY_PG_DSN=\n",
        )]);
        let secrets = |auth_key: &str| {
            files(&[
                (
                    "secrets/gateway.secret.env",
                    "gateway",
                    &format!("HUMAUX_GATEWAY_AUTH_HMAC_KEY={auth_key}\nHUMAUX_GATEWAY_PG_DSN=d"),
                ),
                (
                    "secrets/migrate.secret.env",
                    "migrate",
                    "HUMAUX_MIGRATOR_PG_DSN=m",
                ),
            ])
        };
        let values = |surface: &str| {
            files(&[(
                "values/gateway.env",
                "gateway",
                &format!("HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED={surface}"),
            )])
        };
        let reasons = |surface: &str, auth_key: &str| {
            presence_reasons(&examples, &values(surface), &secrets(auth_key), &[])
        };
        assert_eq!(reasons("false", ""), Vec::<String>::new());
        assert_eq!(reasons("false", "k"), Vec::<String>::new());
        assert_eq!(reasons("false", &"ab".repeat(16)), Vec::<String>::new());
        assert_eq!(
            reasons("true", &"ab".repeat(16)),
            vec!["secret_short:gateway:HUMAUX_GATEWAY_AUTH_HMAC_KEY".to_owned()]
        );
        assert_eq!(reasons("true", &"ab".repeat(32)), Vec::<String>::new());
        assert_eq!(
            reasons("true", ""),
            vec!["secret_empty:gateway:HUMAUX_GATEWAY_AUTH_HMAC_KEY".to_owned()]
        );
        let compose = files(&[(
            "compose/gateway:environment",
            "gateway",
            "HUMAUX_GATEWAY_AUTH_SURFACE_ENABLED=true",
        )]);
        let no_values = files(&[]);
        assert_eq!(
            presence_reasons(&examples, &no_values, &secrets(""), &compose),
            vec!["secret_empty:gateway:HUMAUX_GATEWAY_AUTH_HMAC_KEY".to_owned()]
        );
    }

    /// Review P1 (2026-10-08): `--env` without `--examples-dir` (or without the compose document) is a caller error,
    /// exit 2 — it used to be `not_applicable`, exit 0, so the node's only pre-`up` guard never ran. With
    /// `--placement-only` the same inputs run. Fault: fall back to `not_applicable` ⇒ red.
    #[test]
    fn env_presence_needs_examples_and_compose() {
        let dir = std::env::temp_dir().join(format!("humaux_c39_presence_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("values")).expect("dir");
        std::fs::create_dir_all(dir.join("secrets")).expect("dir");
        std::fs::write(dir.join("values/gateway.env"), "HUMAUX_A=1\n").expect("write");
        let arg = |p: &str| dir.join(p).display().to_string();
        let base = [
            "--env".to_owned(),
            "--values-dir".to_owned(),
            arg("values"),
            "--secrets-dir".to_owned(),
            arg("secrets"),
        ];
        let no_examples = run(&base);
        let placement_only = run(&[&base[..], &["--placement-only".to_owned()]].concat());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            no_examples, 2,
            "presence without its inputs is a usage error"
        );
        assert_eq!(placement_only, 0, "placement alone needs neither");
    }

    /// D-J: a role password in the resident daemon's `maintenance.secret.env` is red (the resident would hold every
    /// role's password); in `migrate.secret.env` it is green. Fault: drop the role-password placement rule ⇒ red.
    #[test]
    fn env_role_password_outside_migrate_is_red() {
        let ok = files(&[(
            "secrets/migrate.secret.env",
            "migrate",
            "HUMAUX_ROLE_PASSWORD_ADMIN=p",
        )]);
        assert_eq!(placement_reasons(&ok), Vec::<String>::new());
        let bad = files(&[(
            "secrets/maintenance.secret.env",
            "maintenance",
            "HUMAUX_ROLE_PASSWORD_ADMIN=p",
        )]);
        assert_eq!(
            placement_reasons(&bad),
            vec![
                "role_password_misplaced:HUMAUX_ROLE_PASSWORD_ADMIN:secrets/maintenance.secret.env"
                    .to_owned()
            ]
        );
    }

    /// Review fix 6 (D-J): the maintenance DSN in `maintenance.secret.env` and `dr.secret.env` is green; a copy in
    /// any other file is red, naming the file (never the value). Fault: drop the rule ⇒ red.
    #[test]
    fn env_maintenance_dsn_outside_its_homes_is_red() {
        let spec = [
            (
                "secrets/maintenance.secret.env",
                "maintenance",
                "HUMAUX_MAINTENANCE_PG_DSN=postgres://u:s3cret@pg:5432/humaux",
            ),
            (
                "secrets/dr.secret.env",
                "dr",
                "HUMAUX_MAINTENANCE_PG_DSN=postgres://u:s3cret@127.0.0.1:5432/humaux",
            ),
            (
                "secrets/admin.secret.env",
                "admin",
                "HUMAUX_MAINTENANCE_PG_DSN=postgres://u:s3cret@pg:5432/humaux",
            ),
        ];
        assert_eq!(placement_reasons(&files(&spec[..2])), Vec::<String>::new());
        let reasons = placement_reasons(&files(&spec));
        assert_eq!(
            reasons,
            vec!["maintenance_dsn_misplaced:secrets/admin.secret.env".to_owned()]
        );
        assert!(reasons.iter().all(|r| !r.contains("s3cret")));
    }

    /// Review fix 6 (S9 B1): the fixture layout — `dr` (host network) loads dr.secret.env at 127.0.0.1, the
    /// residents (shared netns) load maintenance.secret.env at `pg:5432` — is green; `dr` loading
    /// maintenance.secret.env (the old layout) is red, naming service, file and key; an empty value is not judged;
    /// `--env` with `--compose-json` runs the check. Faults: drop the host-network filter ⇒ the residents make the
    /// green case red; drop the service-name comparison ⇒ the 127.0.0.1 DSN makes it red; drop the rule ⇒ the old
    /// layout is green; drop the wiring ⇒ no `host_network_dsn` check.
    #[test]
    fn host_network_dsn_internal_is_red() {
        let secrets = files(&[
            (
                "secrets/maintenance.secret.env",
                "maintenance",
                "HUMAUX_MAINTENANCE_PG_DSN=postgres://role_maintenance:s3cret@pg:5432/humaux",
            ),
            (
                "secrets/dr.secret.env",
                "dr",
                "HUMAUX_MAINTENANCE_PG_DSN=postgres://role_maintenance:s3cret@127.0.0.1:28701/humaux",
            ),
        ]);
        let new = fixture();
        assert_eq!(
            host_network_dsn_reasons(&new, &secrets),
            Vec::<String>::new()
        );
        let mut old = fixture();
        let path = old["services"]["dr"]["env_file"][3]["path"]
            .as_str()
            .expect("path")
            .replace(DR_SECRET_FILE, "maintenance.secret.env");
        old["services"]["dr"]["env_file"][3]["path"] = json!(path);
        let reasons = host_network_dsn_reasons(&old, &secrets);
        assert_eq!(
            reasons,
            vec![
                "host_network_dsn_internal:dr:secrets/maintenance.secret.env:HUMAUX_MAINTENANCE_PG_DSN"
                    .to_owned()
            ]
        );
        assert!(reasons.iter().all(|r| !r.contains("s3cret")));
        let empty = files(&[(
            "secrets/maintenance.secret.env",
            "maintenance",
            "HUMAUX_MAINTENANCE_PG_DSN=",
        )]);
        assert_eq!(host_network_dsn_reasons(&old, &empty), Vec::<String>::new());

        let dir = std::env::temp_dir().join(format!("humaux_c39_hostdsn_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("values")).expect("dir");
        std::fs::create_dir_all(dir.join("secrets")).expect("dir");
        std::fs::write(
            dir.join("secrets/maintenance.secret.env"),
            "HUMAUX_MAINTENANCE_PG_DSN=postgres://role_maintenance:s3cret@pg:5432/humaux\n",
        )
        .expect("write");
        let arg = |p: &str| dir.join(p).display().to_string();
        let args = [
            "--env".to_owned(),
            "--placement-only".to_owned(),
            "--values-dir".to_owned(),
            arg("values"),
            "--secrets-dir".to_owned(),
            arg("secrets"),
        ];
        let mut out = Vec::new();
        let ran = env_checks(&args, Some(&old), &mut out);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(ran.is_ok());
        let wired = out.iter().find(|c| c["check"] == "host_network_dsn");
        assert_eq!(
            wired.map(|c| c["status"].clone()),
            Some(json!("fail")),
            "--env with --compose-json runs host_network_dsn"
        );
    }

    /// RF-1: each of the four comparisons has its own reason; four cases each differ from a consistent base in
    /// exactly ONE input. Fault: drop any one comparison ⇒ its case is red.
    #[test]
    fn release_checks_each_comparison_is_load_bearing() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let other = "fedcba9876543210fedcba9876543210fedcba98";
        let line = format!(
            "IMAGE humaux-ops:0.1.0-0123456789ab id=sha256:aaa size=1 binary=humaux-maintenance git_sha={sha}"
        );
        let image = parse_manifest_line(&line).expect("manifest line");
        let version = format!("humaux-maintenance 0.1.0 git_sha={sha} build_time=t");
        let case = |id: &str, label: &str, version: &str| {
            release_reasons(&image, sha, id, label, Some(version))
        };
        assert_eq!(
            case("sha256:aaa", sha, &version),
            Vec::<String>::new(),
            "consistent base"
        );
        assert_eq!(
            case("sha256:bbb", sha, &version),
            vec!["image_id_mismatch:ops".to_owned()]
        );
        assert_eq!(
            case("sha256:aaa", other, &version),
            vec!["image_sha_mismatch:ops".to_owned()]
        );
        assert_eq!(
            case(
                "sha256:aaa",
                sha,
                &version.replace("humaux-maintenance", "humaux-gateway")
            ),
            vec!["image_binary_mismatch:ops".to_owned()]
        );
        assert_eq!(
            case("sha256:aaa", sha, &version.replace(sha, other)),
            vec!["version_sha_mismatch:ops".to_owned()]
        );
        // A manifest recorded for another commit, the image itself consistent: comparison (2)'s manifest half.
        let stale = parse_manifest_line(&line.replace(sha, other)).expect("manifest line");
        assert_eq!(
            release_reasons(&stale, sha, "sha256:aaa", sha, Some(&version)),
            vec!["image_sha_mismatch:ops".to_owned()]
        );
    }

    /// Card 39b (gate-reviewer round 4 P2-1): a stale or retargeted image never reaches its entrypoint — the
    /// version runner is not called — and a verified one is run by its inspected id; a runner that times out is
    /// named. Fault: run the version before (or regardless of) the identity ⇒ red.
    #[test]
    fn judge_image_runs_the_entrypoint_only_on_a_verified_image() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let line = format!(
            "IMAGE humaux-ops:0.1.0-0123456789ab id=sha256:aaa size=1 binary=humaux-maintenance git_sha={sha}"
        );
        let image = parse_manifest_line(&line).expect("manifest line");
        let version = format!("humaux-maintenance 0.1.0 git_sha={sha} build_time=t");
        let refused = judge_image(&image, sha, "sha256:bbb", sha, |_| -> Option<String> {
            panic!("the entrypoint of an unverified image ran")
        });
        assert_eq!(refused, vec!["image_id_mismatch:ops".to_owned()]);
        let mut ran_with = String::new();
        let ok = judge_image(&image, sha, "sha256:aaa", sha, |id| {
            ran_with = id.to_owned();
            Some(version.clone())
        });
        assert_eq!((ok, ran_with.as_str()), (Vec::new(), "sha256:aaa"));
        assert_eq!(
            judge_image(&image, sha, "sha256:aaa", sha, |_| None),
            vec!["image_version_timeout:ops".to_owned()]
        );
    }

    /// PR #2 round 4: before the entrypoint runs (`version_line = None`) only the identity comparisons are made, so
    /// a stale or retargeted image is named without its `--version` and a verified one owes no version reason yet.
    /// Fault: judge the version comparisons on `None` as an empty line ⇒ red.
    #[test]
    fn release_identity_is_judged_before_the_version_run() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let line = format!(
            "IMAGE humaux-ops:0.1.0-0123456789ab id=sha256:aaa size=1 binary=humaux-maintenance git_sha={sha}"
        );
        let image = parse_manifest_line(&line).expect("manifest line");
        assert_eq!(
            release_reasons(&image, sha, "sha256:bbb", sha, None),
            vec!["image_id_mismatch:ops".to_owned()]
        );
        assert_eq!(
            release_reasons(&image, sha, "sha256:aaa", sha, None),
            Vec::<String>::new()
        );
    }

    /// `--running`: a running container whose env carries a dev-only key is red, by name only. Fault: skip the
    /// `Config.Env` scan ⇒ red.
    #[test]
    fn running_dev_only_env_is_red() {
        let doc = json!({ "services": { "gateway": {
            "image": "humaux-gateway:t", "user": "10101:10101", "mem_limit": "536870912",
            "memswap_limit": "536870912", "cpus": 1.5, "pids_limit": 256 } } });
        let container = |env: &str| {
            json!([{ "Config": { "Labels": { "com.docker.compose.service": "gateway" },
                "User": "10101:10101", "Env": [env] },
                "State": { "Status": "running", "Health": { "Status": "healthy" } }, "RestartCount": 0,
                "HostConfig": { "Memory": 536870912u64, "MemorySwap": 536870912u64, "NanoCpus": 1500000000u64,
                    "PidsLimit": 256, "ReadonlyRootfs": true, "Privileged": false, "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": { "Name": "unless-stopped" } } }])
        };
        assert_eq!(
            running_reasons(&doc, &container("HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID=")),
            Vec::<String>::new()
        );
        assert_eq!(
            running_reasons(&doc, &container("HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID=1")),
            vec!["dev_only_key_set:HUMAUX_RETRIEVAL_WORKER_ALLOW_SAME_UID:gateway".to_owned()]
        );
    }

    /// Review P1 (2026-10-08): each `--running` arm against one changed `docker inspect` field of a green
    /// container — state, health, restarts, a limit, the user, the read-only rootfs, and what the daemon granted
    /// (privileged, CapDrop, CapAdd, SecurityOpt, a docker socket bind or mount). Faults: drop any arm ⇒ red.
    #[test]
    fn running_hardening_arms_each_red() {
        let doc = json!({ "services": { "gateway": {
            "image": "humaux-gateway:t", "user": "10101:10101", "mem_limit": "536870912",
            "memswap_limit": "536870912", "cpus": 1.5, "pids_limit": 256 } } });
        let green = json!({ "Config": { "Labels": { "com.docker.compose.service": "gateway" },
                "User": "10101:10101", "Env": [] },
            "State": { "Status": "running", "Health": { "Status": "healthy" } }, "RestartCount": 0,
            "HostConfig": { "Memory": 536870912u64, "MemorySwap": 536870912u64, "NanoCpus": 1500000000u64,
                "PidsLimit": 256, "ReadonlyRootfs": true, "Privileged": false, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"], "Binds": [], "CapAdd": null,
                "RestartPolicy": { "Name": "unless-stopped" }, "PortBindings": {} },
            "Mounts": [] });
        assert_eq!(
            running_reasons(&doc, &json!([green.clone()])),
            Vec::<String>::new()
        );
        assert_eq!(
            running_reasons(&doc, &json!([])),
            vec!["service_not_running:gateway".to_owned()]
        );
        let cases: [(&str, Value, &str); 13] = [
            (
                "/State/Status",
                json!("exited"),
                "service_not_running:gateway",
            ),
            (
                "/State/Health/Status",
                json!("unhealthy"),
                "service_unhealthy:gateway",
            ),
            ("/RestartCount", json!(1), "service_restarted:gateway"),
            (
                "/HostConfig/Memory",
                json!(0),
                "limit_mismatch:gateway:memory",
            ),
            (
                "/HostConfig/PidsLimit",
                json!(-1),
                "limit_mismatch:gateway:pids",
            ),
            ("/Config/User", json!("0:0"), "user_mismatch:gateway"),
            (
                "/HostConfig/ReadonlyRootfs",
                json!(false),
                "read_only_mismatch:gateway",
            ),
            ("/HostConfig/Privileged", json!(true), "privileged:gateway"),
            (
                "/HostConfig/CapDrop",
                json!([]),
                "cap_drop_mismatch:gateway",
            ),
            (
                "/HostConfig/CapAdd",
                json!(["SYS_ADMIN"]),
                "cap_add_mismatch:gateway",
            ),
            (
                "/HostConfig/SecurityOpt",
                json!([]),
                "no_new_privileges_mismatch:gateway",
            ),
            (
                "/HostConfig/Binds",
                json!(["/var/run/docker.sock:/var/run/docker.sock"]),
                "docker_socket_bind:gateway",
            ),
            (
                "/Mounts",
                json!([{ "Type": "bind", "Source": "/var/run/docker.sock" }]),
                "docker_socket_bind:gateway",
            ),
        ];
        for (pointer, value, want) in cases {
            let mut c = green.clone();
            *c.pointer_mut(pointer).expect(pointer) = value;
            assert_eq!(
                running_reasons(&doc, &json!([c])),
                vec![want.to_owned()],
                "case {pointer}"
            );
        }
    }

    /// §5 `dr_reads_0600_secret`: an unreadable file is reported by path, a readable one is not, and no reason
    /// carries a file's content. Fault: report every file (or its content) ⇒ red.
    #[test]
    fn secrets_readable_reports_names_only() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = std::env::temp_dir().join(format!("humaux_c39_secrets_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        // PR #2 review: under root (CI runs this crate's tests with sudo) DAC_OVERRIDE reads a 0000 file, so the
        // premise does not hold — the measurement's missing object is an unprivileged uid (§57.1).
        if std::fs::metadata(&dir).expect("dir metadata").uid() == 0 {
            println!(
                "not_applicable: missing object = an unprivileged test uid (root reads a 0000 file)"
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let readable = dir.join("gateway.secret.env");
        let unreadable = dir.join("private-worker.secret.env");
        std::fs::write(&readable, "HUMAUX_X=readable-secret-value\n").expect("write");
        std::fs::write(&unreadable, "HUMAUX_Y=hidden-secret-value\n").expect("write");
        std::fs::set_permissions(&readable, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let reasons = secrets_unreadable(&dir);
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            reasons,
            vec![format!("secret_unreadable:{}", unreadable.display())]
        );
        assert!(reasons.iter().all(|r| !r.contains("secret-value")));
    }
    // Review fix 9 (pre-PR review wf_17c25e0e-ac3): one case per new arm, each red by name on the green fixture.

    /// ISO-5 / ISO-4 / ISO-3 / ISO-2 / CC-1 / OP-3: the fixture is green under the new rules, and each arm reds
    /// its one case. Faults: drop any arm (or make `security_opt` a `contains` again) ⇒ its case is green ⇒ red.
    #[test]
    #[allow(clippy::too_many_lines)] // one table: a case per arm
    fn compose_fix9_arms_each_red() {
        type Mutation = fn(&mut Value);
        let cases: [(&str, Mutation, &[&str]); 19] = [
            (
                "security_opt extra on a Humaux service",
                |d| {
                    service(d, "gateway").insert(
                        "security_opt".into(),
                        json!(["no-new-privileges:true", "seccomp:unconfined"]),
                    );
                },
                &["security_opt_extra:gateway"],
            ),
            (
                "security_opt extra on a third-party service",
                |d| {
                    service(d, "pg").insert(
                        "security_opt".into(),
                        json!(["no-new-privileges:true", "apparmor:unconfined"]),
                    );
                },
                &["security_opt_extra:pg"],
            ),
            (
                "third-party privileged",
                |d| {
                    service(d, "qdrant").insert("privileged".into(), json!(true));
                },
                &["privileged:qdrant"],
            ),
            (
                "third-party docker socket",
                |d| {
                    service(d, "prometheus")
                        .entry("volumes")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("volumes")
                        .push(json!({ "type": "bind", "source": "/var/run/docker.sock",
                            "target": "/var/run/docker.sock", "read_only": true }));
                },
                &[
                    "docker_socket_bind:prometheus",
                    "bind_mount_unexpected:prometheus:/var/run/docker.sock",
                ],
            ),
            (
                "port without host_ip",
                |d| {
                    service(d, "pg")["ports"][0]
                        .as_object_mut()
                        .expect("port")
                        .remove("host_ip");
                },
                &["port_not_loopback:pg:5432"],
            ),
            (
                "port on every interface",
                |d| {
                    service(d, "netns")["ports"][0]["host_ip"] = json!("0.0.0.0");
                },
                &["port_not_loopback:netns:8080"],
            ),
            (
                "foreign secret file",
                |d| {
                    service(d, "gateway")["env_file"]
                        .as_array_mut()
                        .expect("env_file")
                        .push(json!({ "path": "/srv/humaux-node/repo/deploy/env/secret-fixture/maintenance.secret.env" }));
                },
                &["secret_file_foreign:gateway:maintenance.secret.env"],
            ),
            (
                "a listed service removed",
                |d| {
                    d["services"]
                        .as_object_mut()
                        .expect("services")
                        .remove("admin");
                },
                &["service_missing:admin"],
            ),
            (
                "an unlisted service on a process image",
                |d| {
                    let admin = d["services"]["admin"].clone();
                    d["services"]
                        .as_object_mut()
                        .expect("services")
                        .insert("admin-2".into(), admin);
                },
                &[
                    "uid_shared:admin,admin-2",
                    "pair_group_unexpected:admin-2:10201",
                    "socket_volume_unexpected:admin-2:sock-retrieval",
                    "pair_group_unexpected:admin-2:10202",
                    "socket_volume_unexpected:admin-2:sock-inference",
                    "image_target_unexpected:admin-2",
                ],
            ),
            (
                "dr on the ops image",
                |d| {
                    service(d, "dr").insert("image".into(), json!("humaux-ops:0.1.0-000000000000"));
                },
                &["image_target_mismatch:dr:ops"],
            ),
            (
                "pg on an upstream image",
                |d| {
                    service(d, "pg").insert("image".into(), json!("postgres:18.6"));
                },
                &["pg_image_unverified:postgres:18.6"],
            ),
            (
                "pg on another release's image",
                |d| {
                    service(d, "pg").insert("image".into(), json!("humaux-pg:0.0.9-ffffffffffff"));
                },
                &["pg_image_unverified:humaux-pg:0.0.9-ffffffffffff"],
            ),
            (
                "own secret file dropped",
                |d| {
                    service(d, "gateway")["env_file"]
                        .as_array_mut()
                        .expect("env_file")
                        .retain(|e| {
                            !e["path"]
                                .as_str()
                                .unwrap_or("")
                                .ends_with("gateway.secret.env")
                        });
                },
                &["secret_file_missing:gateway:gateway.secret.env"],
            ),
            (
                "own values file dropped",
                |d| {
                    service(d, "dr")["env_file"]
                        .as_array_mut()
                        .expect("env_file")
                        .retain(|e| {
                            !e["path"]
                                .as_str()
                                .unwrap_or("")
                                .ends_with("/values/maintenance.env")
                        });
                },
                &["values_file_missing:dr:values/maintenance.env"],
            ),
            (
                "writable bind on a Humaux service",
                |d| {
                    service(d, "gateway")
                        .entry("volumes")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("volumes")
                        .push(
                            json!({ "type": "bind", "source": "/srv/humaux-node/evidence",
                            "target": "/evidence" }),
                        );
                },
                &["bind_mount_writable:gateway:/evidence"],
            ),
            (
                "bind of the secrets directory",
                |d| {
                    service(d, "gateway")
                        .entry("volumes")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("volumes")
                        .push(
                            json!({ "type": "bind", "source": "/srv/humaux-node/secrets",
                            "target": "/s", "read_only": true }),
                        );
                },
                &["bind_mount_unexpected:gateway:/s"],
            ),
            (
                "bind under a denied root",
                |d| {
                    service(d, "retrieval-serve")
                        .entry("volumes")
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                        .expect("volumes")
                        .push(json!({ "type": "bind", "source": "/etc/humaux-extra",
                            "target": "/x", "read_only": true }));
                },
                &["bind_mount_unexpected:retrieval-serve:/x"],
            ),
            (
                "resident with the old restart policy",
                |d| {
                    service(d, "gateway").insert("restart".into(), json!("on-failure:5"));
                },
                &["restart_policy:gateway:on-failure:5"],
            ),
            (
                "one-shot that restarts",
                |d| {
                    service(d, "migrate").insert("restart".into(), json!("unless-stopped"));
                },
                &["restart_policy:migrate:unless-stopped"],
            ),
        ];
        assert_eq!(
            compose_reasons(&fixture()),
            Vec::<String>::new(),
            "the fixture is green"
        );
        for (case, mutate, want) in cases {
            assert_case(case, mutate, want);
        }
        // `/` itself is denied, a sibling of a denied root is not: the prefix rule is on path segments.
        assert!(bind_source_denied("/"));
        assert!(bind_source_denied("/run/x"));
        assert!(!bind_source_denied("/runway/x"));
        assert!(!bind_source_denied("/srv/humaux-repo"));
    }

    /// PR #2 round 9: a key copied into another process's secret file is named even though its own home is set;
    /// `dr` may hold what the maintenance example declares, `migrate` its DSN and the role passwords, nothing else.
    /// Fault: check only the key's expected home ⇒ red.
    #[test]
    fn secret_key_in_a_foreign_file_is_red() {
        let parse = |name: &str, process: &str, text: &str| EnvFile::parse(name, process, text);
        let examples = [
            parse(
                "example/gateway.env",
                "gateway",
                "HUMAUX_GATEWAY_TOKEN_HMAC_KEY=\n",
            ),
            parse(
                "example/maintenance.env",
                "maintenance",
                "HUMAUX_MAINTENANCE_PG_DSN=\nHUMAUX_ROLE_PASSWORD_ADMIN=\n",
            ),
            parse(
                "example/private-worker.env",
                "private-worker",
                "HUMAUX_PRIVATE_WORKER_PG_DSN=\n",
            ),
        ];
        let green = [
            parse(
                "secrets/gateway.secret.env",
                "gateway",
                "HUMAUX_GATEWAY_TOKEN_HMAC_KEY=k\n",
            ),
            parse(
                "secrets/dr.secret.env",
                "dr",
                "HUMAUX_MAINTENANCE_PG_DSN=d\n",
            ),
            parse(
                "secrets/migrate.secret.env",
                "migrate",
                "HUMAUX_MIGRATOR_PG_DSN=m\nHUMAUX_ROLE_PASSWORD_ADMIN=p\n",
            ),
            parse(
                "secrets/pg.secret.env",
                "pg",
                "PGBACKREST_REPO1_CIPHER_PASS=c\n",
            ),
            parse(
                "secrets/private-worker.secret.env",
                "private-worker",
                "HUMAUX_PRIVATE_WORKER_PG_DSN=d\n",
            ),
        ];
        assert_eq!(
            secret_key_foreign_reasons(&examples, &green),
            Vec::<String>::new()
        );
        let mut red = green.to_vec();
        red[4] = parse(
            "secrets/private-worker.secret.env",
            "private-worker",
            "HUMAUX_PRIVATE_WORKER_PG_DSN=d\nHUMAUX_GATEWAY_TOKEN_HMAC_KEY=k\n",
        );
        red[3] = parse(
            "secrets/pg.secret.env",
            "pg",
            "PGBACKREST_REPO1_CIPHER_PASS=c\nHUMAUX_MAINTENANCE_PG_DSN=d\n",
        );
        assert_eq!(
            secret_key_foreign_reasons(&examples, &red),
            vec![
                "secret_key_foreign:secrets/pg.secret.env:HUMAUX_MAINTENANCE_PG_DSN".to_owned(),
                "secret_key_foreign:secrets/private-worker.secret.env:HUMAUX_GATEWAY_TOKEN_HMAC_KEY".to_owned(),
            ]
        );
    }

    /// PR #2 round 7: quotes are removed the way Compose removes them, so `KEY=""` is empty (and a required secret
    /// written that way is `secret_empty`), and a value that needs interpolation, escapes or an inline-comment strip
    /// is `value_unreadable` instead of passing as non-empty text. Fault: keep the raw text ⇒ red.
    #[test]
    fn env_file_values_follow_compose_quoting() {
        let file = EnvFile::parse(
            "secrets/gateway.secret.env",
            "gateway",
            "A=\"\"\nB='lit$x'\nC=\"plain\"\nD=${UNSET}\nE=\"a$b\"\nF=v # note\nG=it's\nH=raw\n",
        );
        for (key, want) in [("A", ""), ("B", "lit$x"), ("C", "plain"), ("H", "raw")] {
            assert_eq!(file.value(key), Some(want), "{key}");
        }
        assert_eq!(file.unreadable, vec!["D", "E", "F", "G"]);
        assert_eq!(
            placement_reasons(&[file]),
            ["D", "E", "F", "G"]
                .map(|k| format!("value_unreadable:secrets/gateway.secret.env:{k}"))
                .to_vec()
        );
    }

    /// ISO-8: the parser agrees with Compose — `export ` is stripped, the last occurrence wins, and a repeated key
    /// is named by placement. Faults: first-wins, or keep the `export ` prefix ⇒ red.
    #[test]
    fn env_file_parse_follows_compose_semantics() {
        let file = EnvFile::parse(
            "values/retrieval-worker.env",
            "retrieval-worker",
            "# c\nHUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10101\nexport HUMAUX_X=1\n\nHUMAUX_RETRIEVAL_WORKER_GATEWAY_UID=10106\n",
        );
        assert_eq!(
            file.value("HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID"),
            Some("10106")
        );
        assert_eq!(file.value("HUMAUX_X"), Some("1"));
        assert_eq!(
            file.duplicated_keys(),
            vec!["HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID"]
        );
        assert_eq!(
            placement_reasons(&[file]),
            vec![
                "key_duplicated:values/retrieval-worker.env:HUMAUX_RETRIEVAL_WORKER_GATEWAY_UID"
                    .to_owned()
            ]
        );
        let exported = EnvFile::parse(
            "secrets/gateway.secret.env",
            "gateway",
            "export HUMAUX_MIGRATOR_PG_DSN=postgres://x\n",
        );
        assert_eq!(
            placement_reasons(&[exported]),
            vec!["migrator_dsn_misplaced:secrets/gateway.secret.env".to_owned()]
        );
    }

    /// `--running` review-fix-9 arms: an extra SecurityOpt, a restart policy other than unless-stopped, a port
    /// binding on every interface. Faults: drop any arm ⇒ red.
    #[test]
    fn running_fix9_arms_each_red() {
        let doc = json!({ "services": { "gateway": {
            "image": "humaux-gateway:t", "user": "10101:10101", "mem_limit": "536870912",
            "memswap_limit": "536870912", "cpus": 1.5, "pids_limit": 256 } } });
        let green = json!({ "Config": { "Labels": { "com.docker.compose.service": "gateway" },
                "User": "10101:10101", "Env": [] },
            "State": { "Status": "running", "Health": { "Status": "healthy" } }, "RestartCount": 0,
            "HostConfig": { "Memory": 536870912u64, "MemorySwap": 536870912u64, "NanoCpus": 1500000000u64,
                "PidsLimit": 256, "ReadonlyRootfs": true, "Privileged": false, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"], "Binds": [], "CapAdd": null,
                "RestartPolicy": { "Name": "unless-stopped" },
                "PortBindings": { "8080/tcp": [{ "HostIp": "127.0.0.1", "HostPort": "8080" }] } },
            "Mounts": [] });
        assert_eq!(
            running_reasons(&doc, &json!([green.clone()])),
            Vec::<String>::new()
        );
        let cases: [(&str, Value, &str); 3] = [
            (
                "/HostConfig/SecurityOpt",
                json!(["no-new-privileges:true", "seccomp:unconfined"]),
                "security_opt_extra:gateway",
            ),
            (
                "/HostConfig/RestartPolicy/Name",
                json!("on-failure"),
                "restart_policy_mismatch:gateway",
            ),
            (
                "/HostConfig/PortBindings/8080~1tcp/0/HostIp",
                json!("0.0.0.0"),
                "port_not_loopback:gateway:8080/tcp",
            ),
        ];
        for (pointer, value, want) in cases {
            let mut c = green.clone();
            *c.pointer_mut(pointer).expect(pointer) = value;
            assert_eq!(
                running_reasons(&doc, &json!([c])),
                vec![want.to_owned()],
                "case {pointer}"
            );
        }
    }

    /// PR #2 round 7: third-party residents are in the running gate — missing, exited, unhealthy (where a
    /// healthcheck exists) or restarted is red; a one-shot (`restart: "no"`) and a profiled service are not
    /// required. Fault: judge Humaux services only ⇒ red.
    #[test]
    fn running_checks_third_party_residents() {
        let doc = json!({ "services": {
            "otel-collector": { "image": "otel/collector:1", "restart": "unless-stopped" },
            "pg": { "image": "humaux-pg:t", "restart": "unless-stopped" },
            "volume-init": { "image": "busybox:1", "restart": "no" },
            "alert-sink": { "image": "python:3", "restart": "no", "profiles": ["rehearsal"] } } });
        let c = |svc: &str, status: &str, health: Option<&str>, restarts: u64| {
            let mut v = json!({ "Config": { "Labels": { "com.docker.compose.service": svc }, "Env": [] },
                "State": { "Status": status }, "RestartCount": restarts, "HostConfig": {} });
            if let Some(h) = health {
                v["State"]["Health"] = json!({ "Status": h });
            }
            v
        };
        let green = json!([
            c("otel-collector", "running", None, 0),
            c("pg", "running", Some("healthy"), 0)
        ]);
        assert_eq!(running_reasons(&doc, &green), Vec::<String>::new());
        let red = json!([
            c("otel-collector", "exited", None, 0),
            c("pg", "running", Some("unhealthy"), 2)
        ]);
        assert_eq!(
            running_reasons(&doc, &red),
            [
                "service_not_running:otel-collector",
                "service_unhealthy:pg",
                "service_restarted:pg"
            ]
            .map(str::to_owned)
            .to_vec()
        );
        assert_eq!(
            running_reasons(&doc, &json!([c("pg", "running", Some("healthy"), 0)])),
            vec!["service_not_running:otel-collector".to_owned()]
        );
    }

    /// PR #2 Codex P1 (round 3): every process image must be in the manifest, an unknown one is named, the A5
    /// `loadgen` image is allowed. Faults: drop the missing arm, or accept any target ⇒ red.
    #[test]
    fn manifest_target_reasons_each_named() {
        let line = |t: &str| {
            parse_manifest_line(&format!(
                "IMAGE humaux-{t}:x id=sha256:a size=1 binary=humaux-{t} git_sha=0"
            ))
            .expect("manifest line")
        };
        let full: Vec<ManifestImage> = TARGETS.iter().map(|t| line(t)).collect();
        assert_eq!(manifest_target_reasons(&full), Vec::<String>::new());
        let mut with_loadgen = full.clone();
        with_loadgen.push(line("loadgen"));
        assert_eq!(manifest_target_reasons(&with_loadgen), Vec::<String>::new());
        let mut short = full.clone();
        short.retain(|i| i.target != "dr");
        assert_eq!(
            manifest_target_reasons(&short),
            vec!["manifest_image_missing:dr".to_owned()]
        );
        let mut stray = full;
        stray.push(line("public-worker"));
        assert_eq!(
            manifest_target_reasons(&stray),
            vec!["manifest_image_unknown:public-worker".to_owned()]
        );
    }

    /// PR #2 Codex P1: the PostgreSQL image is compared too — each outcome by name. Faults: skip the id or the label
    /// comparison, or accept a manifest without a PGIMAGE line ⇒ red.
    #[test]
    fn pg_image_reasons_each_named() {
        let m = "IMAGE humaux-gateway:t id=sha256:a size=1 binary=humaux-gateway git_sha=0\n\
                 PGIMAGE humaux-pg:t id=sha256:b size=1\n";
        assert_eq!(
            parse_pg_manifest_line("PGIMAGE humaux-pg:t id=sha256:b size=1"),
            Some(("humaux-pg:t".to_owned(), "sha256:b".to_owned()))
        );
        assert_eq!(
            parse_pg_manifest_line("IMAGE humaux-pg:t id=sha256:b size=1"),
            None
        );
        assert_eq!(
            pg_image_reasons(m, "0", Some(("sha256:b", "0"))),
            Vec::<String>::new()
        );
        assert_eq!(
            pg_image_reasons(m, "0", Some(("sha256:x", "0"))),
            vec!["pg_image_id_mismatch".to_owned()]
        );
        assert_eq!(
            pg_image_reasons(m, "0", Some(("sha256:b", "1"))),
            vec!["pg_image_sha_mismatch".to_owned()]
        );
        assert_eq!(
            pg_image_reasons(m, "0", None),
            vec!["pg_image_missing".to_owned()]
        );
        assert_eq!(
            pg_image_reasons(
                "IMAGE humaux-gateway:t id=a size=1 binary=b git_sha=0\n",
                "0",
                Some(("a", "0"))
            ),
            vec!["manifest_pgimage_missing".to_owned()]
        );
    }

    /// PR #2 independent review P2-3 / P2-4: a malformed `IMAGE` line is named, never dropped; a `humaux-*` image
    /// outside the target list is red. Faults: drop `malformed_image_lines` / `unknown_humaux_image` ⇒ red.
    #[test]
    fn malformed_manifest_lines_and_unknown_humaux_images_are_red() {
        let m = "IMAGE humaux-gateway:t id=sha256:a size=1 binary=humaux-gateway git_sha=0\n\
                 IMAGE humaux-admin:t size=1 binary=humaux-admin\nPGIMAGE humaux-pg:t id=sha256:b size=1\n";
        assert_eq!(
            malformed_image_lines(m),
            vec!["manifest_line_malformed:2".to_owned()]
        );
        assert_eq!(
            malformed_image_lines("IMAGE humaux-x:t id=a size=1 binary=b git_sha=0\n"),
            Vec::<String>::new()
        );
        assert_case(
            "unknown humaux image",
            |d| {
                service(d, "pg").insert(
                    "image".into(),
                    json!("ghcr.io/x/humaux-public-worker:0.1.0"),
                );
            },
            &[
                "unknown_humaux_image:pg:public-worker",
                // PR #2 round 9: and pg no longer runs the release's humaux-pg image.
                "pg_image_unverified:ghcr.io/x/humaux-public-worker:0.1.0",
            ],
        );
        assert_case(
            "the pg image is the listed exception",
            |d| {
                // The release's tag (round 9: another tag is `pg_image_unverified`), behind a registry prefix.
                service(d, "pg").insert(
                    "image".into(),
                    json!("registry.local/humaux-pg:0.1.0-000000000000"),
                );
            },
            &[],
        );
    }

    /// OP-4 / C2: the checkout-tree comparison, each outcome by name. Faults: compare only `tree`, or accept a
    /// manifest without a CHECKOUT line ⇒ red.
    #[test]
    fn checkout_tree_reasons_each_named() {
        let m = "IMAGE humaux-gateway:t id=sha256:a size=1 binary=humaux-gateway git_sha=0\n\
                 CHECKOUT tree=aaa runbook=bbb roles=ccc\nPGIMAGE humaux-pg:t id=sha256:b size=1\n";
        assert_eq!(
            checkout_tree_reasons(m, Some("tree=aaa runbook=bbb roles=ccc")),
            Vec::<String>::new()
        );
        assert_eq!(
            checkout_tree_reasons(m, Some("tree=aaa runbook=ddd roles=ccc")),
            vec!["checkout_tree_mismatch:runbook".to_owned()]
        );
        assert_eq!(
            checkout_tree_reasons(m, Some("tree=x runbook=y roles=z")),
            vec![
                "checkout_tree_mismatch:tree".to_owned(),
                "checkout_tree_mismatch:runbook".to_owned(),
                "checkout_tree_mismatch:roles".to_owned()
            ]
        );
        assert_eq!(
            checkout_tree_reasons(m, None),
            vec!["checkout_tree_missing".to_owned()]
        );
        assert_eq!(
            checkout_tree_reasons(m, Some("  ")),
            vec!["checkout_tree_missing".to_owned()]
        );
        assert_eq!(
            checkout_tree_reasons(
                "IMAGE humaux-gateway:t id=x size=1 binary=b git_sha=0\n",
                Some("tree=aaa")
            ),
            vec!["checkout_tree_not_in_manifest".to_owned()]
        );
    }

    /// OP-7: a mode flag without its value, or no check at all, is usage (exit 2) — never a `{"checks":[]}`
    /// success. Faults: drop `flag_without_value` or the empty-receipt guard ⇒ red.
    #[test]
    fn checks_refuse_a_flag_without_value_and_an_empty_selection() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            checks(&args(&["--compose-json"]))
                .err()
                .map(|(code, _)| code),
            Some(2)
        );
        assert!(
            checks(&args(&["--secrets-readable", "--env"]))
                .is_err_and(|(code, m)| code == 2 && m.contains("--secrets-readable"))
        );
        assert!(
            checks(&args(&[])).is_err_and(|(code, m)| code == 2 && m.contains("no check selected"))
        );
        assert_eq!(
            flag(&args(&["--release", "--manifest", "m"]), "--release"),
            None
        );
        // Card 39b: the `=` form beside another check is a usage error, never a silently dropped check.
        assert!(
            checks(&args(&["--compose-json=x.json", "--env"]))
                .is_err_and(|(code, m)| code == 2 && m.contains("--compose-json"))
        );
    }
}
