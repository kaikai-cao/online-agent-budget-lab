"""E2.2 — Journal crash recovery & reliability experiment runner.

For each scenario (F1–F4) and each trial, this parent process:

  * starts a REAL standalone Journal Service process (Named Pipe IPC, independent
    journal + idempotency SQLite files, real Ed25519 signing);
  * starts a REAL Executor Worker child process (``e2_2_worker.py``) that drives
    the real JournalBackedExecutor chain over a real ExecutionStore, with a
    test-only crash barrier at the scenario's injection point;
  * waits for the worker's marker confirmation, then FORCIBLY KILLS the worker
    (Windows TerminateProcess via terminate()/kill()) — no exception injection;
  * observes the three independent persistence domains (Journal entries, local
    ExecutionStore, external effect counter SQLite);
  * starts a fresh worker for the same operation_id (retry) and observes whether
    the receipt is recovered, whether dispatch was repeated, and the final state.

No production file is modified.  Raw records are never rewritten.

Usage:
  python run_experiment.py --trials 10 --output-dir results/run-001
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
TESTS = REPO / "tests"
WORKER = Path(__file__).with_name("e2_2_worker.py")

# Make local imports available both when run as a script and as a module.
for _p in (str(SRC), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from online_budget.canonical import private_key_bytes, public_key_bytes  # noqa: E402
from online_budget.journal_client import JournalClient  # noqa: E402
from online_budget.journal_identity import current_process_identity  # noqa: E402
from online_budget.journal_ipc import NamedPipeClient  # noqa: E402
from _e1b_helpers import make_binding_payload, make_config, write_service_config_json  # noqa: E402
from online_budget.execution_receipts import verify_execution_receipt  # noqa: E402

EXEC_ID = "exec-e22"
BASELINE = "467fa249c2c7f6971dd9f217ce0827e6f7bfc995"
SCENARIOS = ["F1", "F2", "F3", "F4"]
EXPECTED_POINT = {
    "F1": "F1_AFTER_INTENT_BEFORE_DISPATCH",
    "F2": "F2_AFTER_DISPATCH_BEFORE_RESULT",
    "F3": "F3_AFTER_RESULT_BEFORE_LOCAL_COMMIT",
    "F4": "F4_AFTER_LOCAL_COMMIT_BEFORE_RESPONSE",
}
FIELDS = [
    "scenario", "trial_id", "operation_id", "worker_pid", "worker_exit_code",
    "crash_point_confirmed", "journal_intent_count", "journal_result_count",
    "execution_store_record_exists", "external_effect_count_before_retry",
    "external_effect_count_after_retry", "retry_returned",
    "receipt_signature_valid", "receipt_identical_to_original",
    "dispatch_count_before_retry", "dispatch_count_after_retry",
    "recovery_classification", "error_code",
]


def _env() -> dict[str, str]:
    env = dict(os.environ)
    path = str(SRC) + os.pathsep + str(TESTS)
    env["PYTHONPATH"] = path + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _close_proc(proc: subprocess.Popen | None) -> int | None:
    if proc is None:
        return None
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=8)
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
    return proc.returncode


def _kill_worker(proc: subprocess.Popen) -> int | None:
    """Forcibly terminate the worker.  Returns the exit code."""
    proc.kill()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        pass
    for stream in (proc.stdout, proc.stderr):
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
    return proc.returncode


def _wait_for_marker(marker_path: Path, proc: subprocess.Popen,
                     timeout: float = 25.0) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker_path.exists():
            try:
                return json.loads(marker_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
        if proc.poll() is not None:
            return None
        time.sleep(0.02)
    return None


def _init_effect_db(path: Path) -> None:
    import sqlite3
    con = sqlite3.connect(str(path), timeout=30.0)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS dispatch_events("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                    "created_at REAL NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS effects("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                    "invoice_id TEXT NOT NULL, created_at REAL NOT NULL)")
        con.commit()
    finally:
        con.close()


def _effect_count(path: Path, op: str) -> int:
    import sqlite3
    con = sqlite3.connect(str(path), timeout=30.0)
    try:
        return int(con.execute("SELECT COUNT(*) FROM effects WHERE operation_id=?", (op,)).fetchone()[0])
    finally:
        con.close()


def _dispatch_count(path: Path, op: str) -> int:
    import sqlite3
    con = sqlite3.connect(str(path), timeout=30.0)
    try:
        return int(con.execute("SELECT COUNT(*) FROM dispatch_events WHERE operation_id=?", (op,)).fetchone()[0])
    finally:
        con.close()


def _store_record_exists(path: Path, op: str) -> bool:
    import sqlite3
    con = sqlite3.connect(str(path), timeout=30.0)
    try:
        row = con.execute("SELECT 1 FROM executions WHERE operation_id=?", (op,)).fetchone()
        return row is not None
    finally:
        con.close()


def _journal_counts(client: JournalClient, op: str) -> tuple[int, int, dict[str, Any] | None]:
    intent = client.get_entry(operation_id=op, phase="INTENT")
    result = client.get_entry(operation_id=op, phase="RESULT")
    return (1 if intent is not None else 0, 1 if result is not None else 0, result)


def _start_service(cfg_path: Path, env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(cfg_path)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def _start_worker(worker_cfg_path: Path, env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, str(WORKER), str(worker_cfg_path)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def _receipt_from_result_entry(result_entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not result_entry:
        return None
    env = result_entry.get("envelope")
    if not isinstance(env, dict):
        return None
    receipt = env.get("execution_receipt")
    return dict(receipt) if isinstance(receipt, dict) else None


def _run_trial(scenario: str, trial: int, trials: int, root: Path,
               exec_pub_b64: str) -> dict[str, Any]:
    trial_id = f"{scenario.lower()}-t{trial:02d}"
    op = f"e22-{trial_id}-{uuid.uuid4().hex[:8]}"
    wd = root / trial_id
    wd.mkdir(parents=True, exist_ok=True)

    journal_key = Ed25519PrivateKey.generate()
    exec_key = Ed25519PrivateKey.generate()
    ident = current_process_identity()
    pipe = f"e22-{os.getpid()}-{scenario.lower()}-{trial:02d}-{uuid.uuid4().hex[:8]}"
    config, raw = make_config(
        base_dir=wd, journal_key=journal_key, executor_key=exec_key,
        executor_id=EXEC_ID, os_identity=ident.account, pipe_name=pipe,
        allowed_sid=ident.sid,
    )
    cfg_path = wd / "service.json"
    write_service_config_json(cfg_path, raw)

    effect_db = wd / "external-effects.sqlite3"
    _init_effect_db(effect_db)
    store_db = wd / "exec-store.sqlite3"
    marker_path = wd / "crash-point.marker"
    release_path = wd / "crash-release.marker"

    binding, binding_digest = make_binding_payload(operation_id=op, executor_id=EXEC_ID)

    def worker_cfg(mode: str, result_path: Path) -> dict[str, Any]:
        return {
            "scenario": scenario, "mode": mode, "executor_id": EXEC_ID,
            "operation_id": op, "pipe_name": pipe,
            "exec_private_b64": base64.b64encode(private_key_bytes(exec_key)).decode(),
            "store_db": str(store_db), "effect_db": str(effect_db),
            "binding": binding, "binding_digest": binding_digest,
            "marker_path": str(marker_path), "release_path": str(release_path),
            "result_path": str(result_path),
        }

    env = _env()
    svc = _start_service(cfg_path, env)
    worker: subprocess.Popen | None = None
    retry_worker: subprocess.Popen | None = None
    rec = {f: "" for f in FIELDS}
    rec.update({
        "scenario": scenario, "trial_id": trial_id, "operation_id": op,
        "worker_pid": "", "worker_exit_code": "", "crash_point_confirmed": False,
        "journal_intent_count": 0, "journal_result_count": 0,
        "execution_store_record_exists": False,
        "external_effect_count_before_retry": 0, "external_effect_count_after_retry": 0,
        "retry_returned": False, "receipt_signature_valid": False,
        "receipt_identical_to_original": False,
        "dispatch_count_before_retry": 0, "dispatch_count_after_retry": 0,
        "recovery_classification": "INVALID", "error_code": "",
    })

    try:
        obs_client = JournalClient(NamedPipeClient(pipe, connect_retries=200), executor_id=EXEC_ID)
        obs_client.verify_integrity()  # service ready + identity OK

        # ---- crash worker ------------------------------------------------
        crash_cfg = worker_cfg("crash", wd / "crash-worker-result.json")
        crash_cfg_path = wd / "crash-worker.json"
        crash_cfg_path.write_text(json.dumps(crash_cfg, ensure_ascii=False), encoding="utf-8")
        worker = _start_worker(crash_cfg_path, env)
        marker = _wait_for_marker(marker_path, worker)
        if marker is None:
            rec["error_code"] = "MARKER_TIMEOUT_OR_WORKER_EXIT"
            _close_proc(worker)
            worker = None
            return rec

        rec["worker_pid"] = int(marker.get("pid") or 0)
        rec["crash_point_confirmed"] = (marker.get("point") == EXPECTED_POINT[scenario])
        if not rec["crash_point_confirmed"]:
            rec["error_code"] = f"UNEXPECTED_POINT:{marker.get('point')}"
        rec["worker_exit_code"] = _kill_worker(worker)
        worker = None

        # ---- observe pre-retry state -------------------------------------
        intent_c, result_c, result_entry = _journal_counts(obs_client, op)
        rec["journal_intent_count"] = intent_c
        rec["journal_result_count"] = result_c
        rec["execution_store_record_exists"] = _store_record_exists(store_db, op)
        rec["external_effect_count_before_retry"] = _effect_count(effect_db, op)
        rec["dispatch_count_before_retry"] = _dispatch_count(effect_db, op)
        original_receipt = _receipt_from_result_entry(result_entry)

        # ---- retry worker (fresh process, same operation) -----------------
        retry_result_path = wd / "retry-worker-result.json"
        retry_cfg = worker_cfg("retry", retry_result_path)
        retry_cfg_path = wd / "retry-worker.json"
        retry_cfg_path.write_text(json.dumps(retry_cfg, ensure_ascii=False), encoding="utf-8")
        retry_worker = _start_worker(retry_cfg_path, env)
        retry_deadline = time.monotonic() + 60.0
        while time.monotonic() < retry_deadline and retry_worker.poll() is None:
            if retry_result_path.exists():
                break
            time.sleep(0.05)
        # give the child a bounded chance to exit cleanly
        if retry_worker.poll() is None:
            try:
                retry_worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _close_proc(retry_worker)
        retry_worker = None

        retry_payload: dict[str, Any] = {}
        if retry_result_path.exists():
            try:
                retry_payload = json.loads(retry_result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                retry_payload = {}

        # ---- observe post-retry state ------------------------------------
        retry_receipt = retry_payload.get("receipt")
        rec["retry_returned"] = isinstance(retry_receipt, dict)
        if retry_receipt is None and result_entry is not None:
            _i2, _r2, result_entry2 = _journal_counts(obs_client, op)
            retry_receipt = _receipt_from_result_entry(result_entry2)

        if isinstance(retry_receipt, dict):
            rec["receipt_signature_valid"] = bool(
                verify_execution_receipt(retry_receipt, exec_key.public_key())
            )
            if original_receipt is not None:
                rec["receipt_identical_to_original"] = (retry_receipt == original_receipt)
            else:
                # No RESULT existed at crash time (F1/F2): the Receipt is created
                # for the first time during retry, so "identical to original" is
                # not applicable; record the signature-checked Receipt as the
                # recovered object and mark identity explicitly.
                rec["receipt_identical_to_original"] = "N/A_NO_ORIGINAL_AT_CRASH"
        rec["external_effect_count_after_retry"] = _effect_count(effect_db, op)
        rec["dispatch_count_after_retry"] = _dispatch_count(effect_db, op)

        # ---- classify by the invariant actually observed -----------------
        if not rec["crash_point_confirmed"]:
            rec["recovery_classification"] = "INVALID"
        elif scenario == "F1":
            rec["recovery_classification"] = "CONTINUED_AFTER_INTENT"
        elif scenario == "F2":
            repeated = rec["external_effect_count_after_retry"] > rec["external_effect_count_before_retry"]
            rec["recovery_classification"] = ("REPEATED_EFFECT_UNCERTAIN" if repeated
                                               else "NO_REPEAT_OBSERVED")
        elif scenario == "F3":
            rec["recovery_classification"] = (
                "RECOVERED_ORIGINAL_FROM_JOURNAL" if rec["retry_returned"]
                and rec["receipt_signature_valid"] and rec["receipt_identical_to_original"] is True
                else "RECOVERY_FAILED_OR_UNVERIFIED")
        elif scenario == "F4":
            rec["recovery_classification"] = (
                "LOCAL_IDEMPOTENT_RETURN" if rec["retry_returned"]
                and rec["receipt_signature_valid"] and rec["execution_store_record_exists"]
                else "RECOVERY_FAILED_OR_UNVERIFIED")
        return rec
    except Exception as exc:  # keep a truthful INVALID row, never fabricate
        rec["error_code"] = f"RUNNER_EXCEPTION:{type(exc).__name__}:{exc}"
        return rec
    finally:
        if worker is not None:
            _close_proc(worker)
        if retry_worker is not None:
            _close_proc(retry_worker)
        _close_proc(svc)


def compute_summary(records: list[dict[str, Any]], trials: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for sc in SCENARIOS:
        subset = [r for r in records if r["scenario"] == sc]
        valid = [r for r in subset if r["crash_point_confirmed"] and r["recovery_classification"] != "INVALID"]
        out[sc] = {
            "attempts": len(subset),
            "valid": len(valid),
            "crash_point_confirmed": sum(1 for r in valid if r["crash_point_confirmed"]),
            "journal_intent_count_at_crash": sum(r["journal_intent_count"] for r in valid),
            "journal_result_count_at_crash": sum(r["journal_result_count"] for r in valid),
            "execution_store_record_exists_at_crash": sum(1 for r in valid if r["execution_store_record_exists"]),
            "external_effect_count_before_retry": sum(r["external_effect_count_before_retry"] for r in valid),
            "external_effect_count_after_retry": sum(r["external_effect_count_after_retry"] for r in valid),
            "dispatch_count_before_retry": sum(r["dispatch_count_before_retry"] for r in valid),
            "dispatch_count_after_retry": sum(r["dispatch_count_after_retry"] for r in valid),
            "retry_returned": sum(1 for r in valid if r["retry_returned"]),
            "receipt_signature_valid": sum(1 for r in valid if r["receipt_signature_valid"]),
            "receipt_identical_to_original_true": sum(1 for r in valid if r["receipt_identical_to_original"] is True),
            "receipt_identity_na": sum(1 for r in valid if isinstance(r["receipt_identical_to_original"], str)),
            "recovery_classes": {c: sum(1 for r in valid if r["recovery_classification"] == c)
                                 for c in sorted({r["recovery_classification"] for r in valid})},
        }
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    out_dir = REPO / args.output_dir if not Path(args.output_dir).is_absolute() else Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    work_root = out_dir / "work"

    exec_pub = Ed25519PrivateKey.generate().public_key()
    exec_pub_b64 = base64.b64encode(public_key_bytes(exec_pub)).decode()

    records: list[dict[str, Any]] = []
    started = time.time()
    for scenario in SCENARIOS:
        for trial in range(args.trials):
            rec = _run_trial(scenario, trial, args.trials, work_root, exec_pub_b64)
            records.append(rec)
            print(f"[{scenario} t{trial:02d}] {rec['recovery_classification']} "
                  f"eff {rec['external_effect_count_before_retry']}->{rec['external_effect_count_after_retry']} "
                  f"ptr {rec['journal_intent_count']}/{rec['journal_result_count']} "
                  f"local={rec['execution_store_record_exists']} "
                  f"ptrconf={rec['crash_point_confirmed']} err={rec['error_code']}", flush=True)

    with (out_dir / "trials.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for r in records:
            writer.writerow({k: (str(r.get(k, "")).lower() if isinstance(r.get(k), bool) else r.get(k, ""))
                             for k in FIELDS})

    summary = compute_summary(records, args.trials)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    raw = {
        "meta": {
            "experiment": "E2.2 journal crash recovery & reliability",
            "baseline_commit": BASELINE, "branch": "exp/e2.2-journal-crash-recovery",
            "trials": args.trials, "scenarios": SCENARIOS,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
            "duration_seconds": round(time.time() - started, 3),
            "effect_db_is_independent": True,
            "journal_service_is_standalone_process": True,
            "worker_is_standalone_process": True,
            "kill_is_real_process_termination": True,
        },
        "records": records,
        "metrics": summary,
    }
    (out_dir / "raw.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
