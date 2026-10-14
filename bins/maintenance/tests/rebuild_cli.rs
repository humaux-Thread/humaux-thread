//! `maintenance::tests::rebuild_cli` — the `projection rebuild` arm of `humaux-maintenance` (ADR-0064 D-E): every
//!   required flag is refused when missing (exit 2, named, before anything is read), and a run over a throwaway
//!   database and a scratch Qdrant prints one receipt object per stream; and the `projection backfill-memory-id` arm's
//!   exit contract (ADR-0068 40d-2a).
//! Depends-on: crates=[serde_json, uuid]; services=[HTTP(loopback), PostgreSQL(owner)
//!   w=[control.tenants, projection.embedding_fingerprints, projection.stream_checkpoints,
//!   projection.tenant_placements]];
//!   env=[HUMAUX_MAINTENANCE_PG_DSN, HUMAUX_MAINTENANCE_QDRANT_CIDR, HUMAUX_MAINTENANCE_QDRANT_HOST,
//!   HUMAUX_MAINTENANCE_QDRANT_PORT, HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION, HUMAUX_RETRIEVAL_WORKER_PG_DSN];
//!   modules=[adapters::tests::support::scratch_qdrant, maintenance::tests::support::throwaway]
//! Called-by: [cargo-test]
//! Invariants: [the database is humaux_thread_c37_cli_<pid>_<n> and the Qdrant is humaux-c37-qdrant-<pid>-<n>, both
//!   created and removed by their guards (also on panic); the shared dev database and containers are never touched;
//!   each refusal is asserted by exit code and the flag named on stderr]
//! Spec: Baseline §78.1; §79.2; ADR-0053 D-F; ADR-0064 D-E; ADR-0068

#[path = "support/throwaway.rs"]
#[allow(dead_code)]
mod throwaway;

#[path = "../../../crates/adapters/tests/support/scratch_qdrant.rs"]
mod scratch_qdrant;

use std::io::{Read, Write};
use std::net::TcpStream;

use serde_json::Value;
use throwaway::{run, with_db};
use uuid::Uuid;

/// CLI (ADR-0064 D-E, §78.1): removing any one required flag of `projection rebuild` exits 2 naming it, before any
/// environment is read; with every flag, two serving streams of a tenant yield two receipt objects, each
/// `equivalent` and closed. Fault: a default for `--batch` → the run proceeds to the environment and stderr no
/// longer names `--batch` → red.
#[test]
fn projection_rebuild_requires_every_flag_and_prints_one_object_per_stream() {
    let tenant = Uuid::now_v7().to_string();
    let full = [
        "projection",
        "rebuild",
        "--tenant",
        &tenant,
        "--batch",
        "10",
        "--wait-seconds",
        "5",
    ];
    for (flag, named) in [
        ("--tenant", "--tenant"),
        ("--batch", "--batch"),
        ("--wait-seconds", "--wait-seconds"),
    ] {
        let args: Vec<&str> = full
            .chunks(2)
            .filter(|pair| pair[0] != flag)
            .flatten()
            .copied()
            .collect();
        let out = run(&args, &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            stderr.contains(named),
            "{args:?} must name {named}: {stderr}"
        );
        assert!(out.stdout.is_empty(), "nothing printed before the refusal");
    }

    let test = "projection_rebuild_requires_every_flag_and_prints_one_object_per_stream";
    let Some(mut db) = throwaway::db(test, "c37_cli") else {
        return;
    };
    let qdrant = scratch_qdrant::ScratchQdrant::start("qdrant").expect("scratch Qdrant");
    let worker_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
        .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN (§79.2: required with the DB)");
    let label = "c37-cli-embed@r1";
    let tenant = seed(&mut db, label);
    let tenant = tenant.to_string();
    let args = [
        "projection",
        "rebuild",
        "--tenant",
        &tenant,
        "--batch",
        "10",
        "--wait-seconds",
        "5",
    ];
    let out = run(
        &args,
        &[
            ("HUMAUX_MAINTENANCE_PG_DSN", db.maintenance_dsn.clone()),
            (
                "HUMAUX_RETRIEVAL_WORKER_PG_DSN",
                with_db(&worker_dsn, &db.name),
            ),
            (
                "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION",
                label.to_owned(),
            ),
            ("HUMAUX_MAINTENANCE_QDRANT_HOST", "127.0.0.1".to_owned()),
            ("HUMAUX_MAINTENANCE_QDRANT_PORT", qdrant.port.to_string()),
            ("HUMAUX_MAINTENANCE_QDRANT_CIDR", "127.0.0.1/32".to_owned()),
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let receipt: Value = serde_json::from_str(stdout.trim()).expect("one JSON receipt");
    let streams = receipt["streams"].as_array().expect("streams");
    assert_eq!(streams.len(), 2, "one object per stream: {receipt}");
    for stream in streams {
        assert_eq!(stream["verdict"], "equivalent", "{stream}");
        assert_eq!(stream["closed"], true, "{stream}");
    }
    drop(qdrant);
}

/// The environment of one `humaux-maintenance` run against `db` and `qdrant` under `label`.
fn cli_env(
    db: &throwaway::Db,
    worker_dsn: &str,
    label: &str,
    qdrant: &scratch_qdrant::ScratchQdrant,
) -> Vec<(&'static str, String)> {
    vec![
        ("HUMAUX_MAINTENANCE_PG_DSN", db.maintenance_dsn.clone()),
        (
            "HUMAUX_RETRIEVAL_WORKER_PG_DSN",
            with_db(worker_dsn, &db.name),
        ),
        (
            "HUMAUX_RETRIEVAL_WORKER_EMBEDDING_VERSION",
            label.to_owned(),
        ),
        ("HUMAUX_MAINTENANCE_QDRANT_HOST", "127.0.0.1".to_owned()),
        ("HUMAUX_MAINTENANCE_QDRANT_PORT", qdrant.port.to_string()),
        ("HUMAUX_MAINTENANCE_QDRANT_CIDR", "127.0.0.1/32".to_owned()),
    ]
}

/// One raw `PUT` to the scratch Qdrant on loopback; the status line must be 200.
fn qdrant_put(port: u16, path: &str, body: &str) {
    // dep: HTTP(loopback) — plants a point in the scratch Qdrant
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("scratch Qdrant");
    write!(
        stream,
        "PUT {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .expect("request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response");
    assert!(
        response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200"),
        "{path}: {response}"
    );
}

fn receipt_of(out: &std::process::Output) -> Value {
    serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim()).unwrap_or_else(|e| {
        panic!(
            "one JSON receipt ({e}): {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// CLI (ADR-0068 40d-2a): `projection backfill-memory-id` without its scope exits 2 before reading anything; a tenant
/// with no stream exits 3 `no_streams` (nothing was backfilled, so the switch gate must not read it as done); a clean
/// tenant exits 0 `backfilled`; a point of a stream with no registry row exits 3 `strays`, named in the receipt and
/// left in place. Faults: `refused` not set on strays ⇒ exit 0 ⇒ red; the empty-scope arm reported as `backfilled` ⇒
/// exit 0 ⇒ red.
#[test]
fn projection_backfill_memory_id_exits_3_on_strays_and_on_no_streams() {
    let out = run(&["projection", "backfill-memory-id"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--tenant"), "names the scope: {stderr}");
    assert!(out.stdout.is_empty(), "nothing printed before the refusal");

    let test = "projection_backfill_memory_id_exits_3_on_strays_and_on_no_streams";
    let Some(mut db) = throwaway::db(test, "c40_cli") else {
        return;
    };
    let qdrant = scratch_qdrant::ScratchQdrant::start("qdrant").expect("scratch Qdrant");
    let worker_dsn = std::env::var("HUMAUX_RETRIEVAL_WORKER_PG_DSN")
        .expect("HUMAUX_RETRIEVAL_WORKER_PG_DSN (§79.2: required with the DB)");
    let label = "c40-cli-embed@r1";
    let tenant_id = seed(&mut db, label);
    let tenant = tenant_id.to_string();
    let env = cli_env(&db, &worker_dsn, label, &qdrant);
    // The rebuild creates the placement collection; its two streams are empty and close equivalent.
    let rebuilt = run(
        &[
            "projection",
            "rebuild",
            "--tenant",
            &tenant,
            "--batch",
            "10",
            "--wait-seconds",
            "5",
        ],
        &env,
    );
    assert_eq!(rebuilt.status.code(), Some(0), "{}", receipt_of(&rebuilt));

    let nobody = Uuid::now_v7().to_string();
    let none = run(
        &["projection", "backfill-memory-id", "--tenant", &nobody],
        &env,
    );
    assert_eq!(none.status.code(), Some(3), "{}", receipt_of(&none));
    assert_eq!(receipt_of(&none)["outcome"], "no_streams");

    let clean = run(
        &["projection", "backfill-memory-id", "--tenant", &tenant],
        &env,
    );
    let receipt = receipt_of(&clean);
    assert_eq!(clean.status.code(), Some(0), "{receipt}");
    assert_eq!(receipt["outcome"], "backfilled", "{receipt}");
    assert_eq!(
        receipt["streams"].as_array().map(Vec::len),
        Some(2),
        "{receipt}"
    );

    let (collection, workspace): (String, Uuid) = {
        let row = db
            .client()
            .query_one(
                "SELECT p.collection_name, c.scope_id FROM projection.tenant_placements p \
                   JOIN projection.stream_checkpoints c ON c.tenant_id = p.tenant_id \
                  WHERE p.tenant_id = $1 ORDER BY c.scope_id LIMIT 1",
                &[&tenant_id],
            )
            .expect("placement and one stream");
        (row.get(0), row.get(1))
    };
    let stray = Uuid::new_v4();
    qdrant_put(
        qdrant.port,
        &format!("/collections/{collection}/points?wait=true"),
        &format!(
            r#"{{"points":[{{"id":"{stray}","vector":[0.1,0.2,0.3,0.4],"payload":{{"tenant_id":"{tenant}","workspace_id":"{workspace}","projection_version":"v1"}}}}]}}"#
        ),
    );
    let strayed = run(
        &["projection", "backfill-memory-id", "--tenant", &tenant],
        &env,
    );
    let receipt = receipt_of(&strayed);
    assert_eq!(strayed.status.code(), Some(3), "{receipt}");
    assert_eq!(receipt["outcome"], "strays", "{receipt}");
    let named = receipt["streams"]
        .as_array()
        .expect("streams")
        .iter()
        .filter_map(|stream| stream["stray_ids"].as_array())
        .flatten()
        .filter(|id| id.as_str() == Some(stray.to_string().as_str()))
        .count();
    assert_eq!(named, 1, "the stray is named once: {receipt}");
    drop(qdrant);
}

/// One tenant with a bound label, a placement and two serving (empty) workspace streams.
fn seed(db: &mut throwaway::Db, label: &str) -> Uuid {
    let tenant: Uuid = db
        .client()
        .query_one(
            "INSERT INTO control.tenants (name) VALUES ('c37 cli') RETURNING tenant_id",
            &[],
        )
        .expect("tenant")
        .get(0);
    db.client()
        .execute(
            "INSERT INTO projection.embedding_fingerprints (fingerprint_sha256, embedding_version, provider, \
               model_id, model_revision, dimension, task_type, preprocessing_version, projection_contract_version, \
               dtype, normalization, distance) \
             VALUES (sha256('c37 cli'::bytea), $1, 'c37-test', 'c37-model', 'r1', 4, 'document', 'v1-test', 'v1', \
               'float32', 'provider-raw', 'Cosine')",
            &[&label],
        )
        .expect("label binding");
    db.client()
        .execute(
            "INSERT INTO projection.tenant_placements \
               (tenant_id, projection_family, collection_name, placement_class) \
             VALUES ($1, 'private_memory_v1', $2, 'SHARED_FALLBACK')",
            &[&tenant, &format!("c37_cli_{}", Uuid::new_v4().simple())],
        )
        .expect("placement");
    for _ in 0..2 {
        db.client()
            .execute(
                "INSERT INTO projection.stream_checkpoints (tenant_id, scope_kind, scope_id, domain, \
                   projection_kind, projection_version, issued_highwater, serving) \
                 VALUES ($1, 'workspace', gen_random_uuid(), 'private_memory', 'PRIVATE_MEMORY', 'v1', 0, true)",
                &[&tenant],
            )
            .expect("serving stream");
    }
    tenant
}
