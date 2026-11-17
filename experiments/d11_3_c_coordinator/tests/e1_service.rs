//! E1.3 JSON Lines service protocol tests (J group): real process spawn over
//! stdin/stdout, five methods, consecutive requests, error responses, and a
//! clean stdout (diagnostics must go to stderr only).

use std::{
    ffi::OsString,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn tmp(label: &str, ext: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "d11_3_e1svc_{label}_{}_{n}.{ext}",
        std::process::id()
    ))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}
fn pub_b64(n: u8) -> String {
    b64(&SigningKey::from_bytes(&seed(n)).verifying_key().to_bytes())
}

/// Write a valid service config: issuer seed 7, executor seed 9, coordinator
/// signing seed 3, matching public key map. Returns (config_path, db_path).
fn write_config() -> (PathBuf, PathBuf) {
    let db = tmp("db", "sqlite");
    let cfg = tmp("cfg", "json");
    let signing_key_b64 = b64(&seed(3));
    let coordinator_pub = pub_b64(3);
    let config = json!({
        "db_path": db.to_string_lossy(),
        "issuer_id": "issuer-e13-test",
        "issuer_public_key_b64": pub_b64(7),
        "executor_public_keys": {"executor-e13-test": pub_b64(9)},
        "coordinator_key_id": "d11-coordinator-v1",
        "coordinator_signing_key_b64": signing_key_b64,
        "coordinator_public_keys": {"d11-coordinator-v1": coordinator_pub},
    });
    std::fs::write(&cfg, config.to_string()).unwrap();
    (cfg, db)
}

fn cleanup(path: &PathBuf) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
}

struct Service {
    child: std::process::Child,
    reader: BufReader<std::process::ChildStdout>,
}

fn spawn(config: &PathBuf) -> Service {
    let mut child = Command::new(env!("CARGO_BIN_EXE_e1_service"))
        .arg(config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn e1_service");
    let stdout = child.stdout.take().unwrap();
    Service {
        child,
        reader: BufReader::new(stdout),
    }
}

impl Service {
    fn request(&mut self, line: &str) -> Value {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .expect("read response line");
        assert!(!response.is_empty(), "service closed stdout unexpectedly");
        serde_json::from_str(response.trim()).expect("response is single-line JSON")
    }
    fn finish(mut self) {
        let _ = self.child.stdin.take();
        let _ = self.child.wait();
    }
}

#[test]
fn j01_health_ok() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    let r = svc.request(r#"{"request_id":"h1","method":"health","payload":{}}"#);
    assert_eq!(r["ok"], true);
    assert_eq!(r["request_id"], "h1");
    assert_eq!(r["result"]["status"], "ok");
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}

#[test]
fn j02_consecutive_requests_with_distinct_ids() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    for i in 0..5 {
        let line = format!(r#"{{"request_id":"r{i}","method":"health","payload":{{}}}}"#);
        let r = svc.request(&line);
        assert_eq!(r["request_id"], format!("r{i}"));
        assert_eq!(r["ok"], true);
    }
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}

#[test]
fn j03_unknown_method_is_stable_error() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    let r = svc.request(r#"{"request_id":"u1","method":"no_such_method","payload":{}}"#);
    assert_eq!(r["ok"], false);
    assert_eq!(r["request_id"], "u1");
    assert_eq!(r["error"]["code"], "INVALID_PUBLIC_INPUT");
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}

#[test]
fn j04_malformed_json_and_bad_envelope() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    let r = svc.request("not-json");
    assert_eq!(r["ok"], false);
    assert_eq!(r["error"]["code"], "INVALID_PUBLIC_INPUT");
    let r = svc.request(r#"{"request_id":"m1","method":"health"}"#);
    assert_eq!(r["ok"], false); // missing payload -> strict envelope
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}

#[test]
fn j05_get_operation_missing_returns_null_result() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    let line = r#"{"request_id":"g1","method":"get_operation","payload":{"operation_id":"nope","expected_binding_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","expected_metering_quote_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}"#;
    let r = svc.request(line);
    assert_eq!(r["ok"], true);
    assert!(r["result"].is_null());
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}

#[test]
fn j06_prove_method_returns_real_proof_and_instance() {
    let (cfg, db) = write_config();
    let mut svc = spawn(&cfg);
    // Build a payload matching StateWitness JSON field names.
    // Canonical Fp hex is 32-byte little-endian: byte 0 = low byte.
    let hex = |n: u64| {
        let bytes = n.to_le_bytes();
        let mut s = String::new();
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s.push_str(&"00".repeat(24));
        s
    };
    let payload = json!({
        "budget_id": hex(101),
        "period_id": hex(7),
        "quota": 100,
        "cost": 20,
        "u_old": 0,
        "u_new": 20,
        "slack": 80,
        "r_old": hex(11),
        "r_new": hex(13),
        "nf_secret": hex(17),
        "policy": hex(1),
    });
    let line = json!({"request_id":"p1","method":"prove","payload":payload}).to_string();
    let r = svc.request(&line);
    assert_eq!(r["ok"], true, "response: {r}");
    assert!(r["result"]["proof_b64"].as_str().unwrap().len() > 20);
    assert_eq!(r["result"]["instance"].as_array().unwrap().len(), 8);
    svc.finish();
    cleanup(&cfg);
    cleanup(&db);
}
