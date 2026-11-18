"""E2.3 — Tool-side idempotency & crash recovery experiment runner.

For each variant (V0 no idempotency / V1 sink idempotency / V2 same-key different
arguments) and each trial, this parent process:

  * starts a REAL standalone Journal Service process (Named Pipe, independent
    journal + idempotency SQLite, real Ed25519 signing);
  * starts a REAL Executor Worker child (worker.py) driving the real
    JournalBackedExecutor chain, with an F2 crash barrier (after Receipt signed,
    before Journal RESULT append) writing a marker {point,pid,ts};
  * FORCIBLY KILLS the worker once the marker is confirmed (real TerminateProcess,
    no exception injection);
  * observes three INDEPENDENT persistence domains (Journal entries, local
    ExecutionStore, External Tool Sink SQLite);
  * starts a fresh retry worker for the same operation_id / idempotency key and
    observes effect count, dispatch count, dedup outcome and Receipt properties.

Two additional专项 are run: concurrent same-key requests (only one effect) and
a forced mid-transaction rollback (key + effect roll back together, then a normal
retry succeeds).

No production file is modified. Raw records are never rewritten.

Usage:
  python run_experiment.py --trials 10 --output-dir results/run-001
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
TESTS = REPO / "tests"
HERE = Path(__file__).resolve().parent
WORKER = HERE / "worker.py"

for _p in (str(SRC), str(TESTS), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from online_budget.canonical import private_key_bytes  # noqa: E402
from online_budget.journal_client import JournalClient  # noqa: E402
from online_budget.journal_identity import current_process_identity  # noqa: E402
from online_budget.journal_ipc import NamedPipeClient  # noqa: E402
from online_budget.execution_receipts import verify_execution_receipt  # noqa: E402
from _e1b_helpers import make_binding_payload, make_config, write_service_config_json  # noqa: E402
from sink import (  # noqa: E402
    ExternalToolSink,
    IdempotencyKeyConflict,
    OUTCOME_CONFLICT,
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    OUTCOME_ROLLED_BACK,
    sink_idempotency_key,
)

EXEC_ID = "exec-e23"
BASELINE = "467fa249c2c7f6971dd9f217ce0827e6f7bfc995"
VARIANTS = ["V0", "V1", "V2"]
EXPECTED_POINT = "F2_AFTER_DISPATCH_BEFORE_RESULT"

ARGS_PRIMARY = {"invoice_id": "INV-E23-SYSTEM"}
ARGS_CONFLICT = {"invoice_id": "INV-E23-ATTACK"}
INVOICE_PRIMARY = "INV-E23-SYSTEM"

FIELDS = [
    "variant", "trial_id", "operation_id", "worker_pid", "worker_exit_code",
    "crash_point_confirmed", "journal_intent_count", "journal_result_count",
    "execution_store_record_exists", "sink_effect_count_before_retry",
    "sink_effect_count_after_retry", "dispatch_count_before_retry",
    "dispatch_count_after_retry", "retry_returned", "receipt_signature_valid",
    "receipt_binding_consistent", "receipt_result_matches_sink",
    "receipt_identical_to_original", "sink_outcomes", "recovery_classification",
    "error_code",
]


def _env() -> dict[str, str]:
    env = dict(os.environ)
    path = str(SRC) + os.pathsep + str(TESTS) + os.pathsep + str(HERE)
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


def _store_record_exists(path: Path, op: str) -> bool:
    import sqlite3
    con = sqlite3.connect(str(path), timeout=30.0)
    try:
        return con.execute("SELECT 1 FROM executions WHERE operation_id=?", (op,)).fetchone() is not None
    finally:
        con.close()


def _journal_counts(client: JournalClient, op: str) -> tuple[int, int]:
    intent = client.get_entry(operation_id=op, phase="INTENT")
    result = client.get_entry(operation_id=op, phase="RESULT")
    return (1 if intent is not None else 0, 1 if result is not None else 0)


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


def _receipt_fields(receipt: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        return {}
    payload = receipt.get("payload") if isinstance(receipt.get("payload"), dict) else receipt
    return {
        "operation_id": payload.get("operation_id"),
        "binding_digest": payload.get("binding_digest"),
        "result": payload.get("result"),
        "status": payload.get("status"),
    }


def _run_trial(variant: str, trial: int, root: Path) -> dict[str, Any]:
    trial_id = f"{variant.lower()}-t{trial:02d}"
    op = f"e23-{trial_id}-{uuid.uuid4().hex[:8]}"
    wd = root / trial_id
    wd.mkdir(parents=True, exist_ok=True)

    journal_key = Ed25519PrivateKey.generate()
    exec_key = Ed25519PrivateKey.generate()
    ident = current_process_identity()
    pipe = f"e23-{os.getpid()}-{variant.lower()}-{trial:02d}-{uuid.uuid4().hex[:8]}"
    config, raw = make_config(
        base_dir=wd, journal_key=journal_key, executor_key=exec_key,
        executor_id=EXEC_ID, os_identity=ident.account, pipe_name=pipe,
        allowed_sid=ident.sid,
    )
    cfg_path = wd / "service.json"
    write_service_config_json(cfg_path, raw)

    sink_db = wd / "tool-sink.sqlite3"
    ExternalToolSink(sink_db)  # initialize schema
    store_db = wd / "exec-store.sqlite3"
    marker_path = wd / "crash-point.marker"

    binding, binding_digest = make_binding_payload(operation_id=op, executor_id=EXEC_ID)
    tool_name = binding["tool_name"]
    tool_schema_hash = binding["tool_schema_hash"]
    idem_key = sink_idempotency_key(executor_id=EXEC_ID, operation_id=op)

    def worker_cfg(mode: str, args: dict[str, Any], result_path: Path) -> dict[str, Any]:
        return {
            "variant": variant, "mode": mode, "executor_id": EXEC_ID,
            "operation_id": op, "pipe_name": pipe,
            "exec_private_b64": base64.b64encode(private_key_bytes(exec_key)).decode(),
            "store_db": str(store_db), "sink_db": str(sink_db),
            "binding": binding, "binding_digest": binding_digest,
            "tool_name": tool_name, "tool_schema_hash": tool_schema_hash,
            "arguments": args, "invoice_id": INVOICE_PRIMARY,
            "marker_path": str(marker_path), "release_path": str(wd / "crash-release.marker"),
            "result_path": str(result_path),
        }

    env = _env()
    svc = _start_service(cfg_path, env)
    worker: subprocess.Popen | None = None
    retry_worker: subprocess.Popen | None = None
    rec = {f: "" for f in FIELDS}
    rec.update({
        "variant": variant, "trial_id": trial_id, "operation_id": op,
        "crash_point_confirmed": False, "execution_store_record_exists": False,
        "journal_intent_count": 0, "journal_result_count": 0,
        "sink_effect_count_before_retry": 0, "sink_effect_count_after_retry": 0,
        "dispatch_count_before_retry": 0, "dispatch_count_after_retry": 0,
        "retry_returned": False, "receipt_signature_valid": False,
        "receipt_binding_consistent": False, "receipt_result_matches_sink": False,
        "receipt_identical_to_original": "N/A_NO_ORIGINAL_AT_CRASH",
        "sink_outcomes": "", "recovery_classification": "INVALID", "error_code": "",
    })

    try:
        obs = JournalClient(NamedPipeClient(pipe, connect_retries=200), executor_id=EXEC_ID)
        obs.verify_integrity()  # service ready

        # ---- crash worker (primary args), killed at F2 --------------------
        crash_cfg = worker_cfg("crash", ARGS_PRIMARY, wd / "crash-result.json")
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
        rec["crash_point_confirmed"] = marker.get("point") == EXPECTED_POINT
        if not rec["crash_point_confirmed"]:
            rec["error_code"] = f"UNEXPECTED_POINT:{marker.get('point')}"
        rec["worker_exit_code"] = _kill_worker(worker)
        worker = None

        # ---- observe pre-retry state -------------------------------------
        sink = ExternalToolSink(sink_db)
        i, r = _journal_counts(obs, op)
        rec["journal_intent_count"] = i
        rec["journal_result_count"] = r
        rec["execution_store_record_exists"] = _store_record_exists(store_db, op)
        rec["sink_effect_count_before_retry"] = sink.effect_count(op)
        rec["dispatch_count_before_retry"] = sink.dispatch_count(op)
        original_result = sink.original_result(idem_key)  # F2: None (RESULT not written)

        # ---- retry worker (fresh process, same key) -----------------------
        retry_args = ARGS_CONFLICT if variant == "V2" else ARGS_PRIMARY
        retry_result_path = wd / "retry-result.json"
        retry_cfg = worker_cfg("retry", retry_args, retry_result_path)
        retry_cfg_path = wd / "retry-worker.json"
        retry_cfg_path.write_text(json.dumps(retry_cfg, ensure_ascii=False), encoding="utf-8")
        retry_worker = _start_worker(retry_cfg_path, env)
        retry_deadline = time.monotonic() + 60.0
        while time.monotonic() < retry_deadline and retry_worker.poll() is None:
            if retry_result_path.exists():
                break
            time.sleep(0.05)
        if retry_worker.poll() is None:
            try:
                retry_worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _close_proc(retry_worker)
        retry_worker = None

        payload: dict[str, Any] = {}
        if retry_result_path.exists():
            try:
                payload = json.loads(retry_result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}

        # ---- observe post-retry state ------------------------------------
        retry_receipt = payload.get("receipt")
        rec["retry_returned"] = isinstance(retry_receipt, dict)
        outcomes = [o for o in payload.get("sink_outcomes", [])]
        rec["sink_outcomes"] = ",".join(outcomes)

        if isinstance(retry_receipt, dict):
            rec["receipt_signature_valid"] = bool(
                verify_execution_receipt(retry_receipt, exec_key.public_key())
            )
            rf = _receipt_fields(retry_receipt)
            rec["receipt_binding_consistent"] = (
                rf.get("operation_id") == op and rf.get("binding_digest") == binding_digest
            )
            saved = sink.original_result(idem_key)
            rec["receipt_result_matches_sink"] = bool(
                saved is not None and rf.get("result") == saved
            )
        if payload.get("error_code"):
            rec["error_code"] = payload["error_code"]
        if payload.get("conflict_seen") and not rec["error_code"]:
            rec["error_code"] = "IDEMPOTENCY_KEY_CONFLICT"

        rec["sink_effect_count_after_retry"] = sink.effect_count(op)
        rec["dispatch_count_after_retry"] = sink.dispatch_count(op)

        # ---- classify the invariant actually observed --------------------
        before = rec["sink_effect_count_before_retry"]
        after = rec["sink_effect_count_after_retry"]
        if not rec["crash_point_confirmed"]:
            rec["recovery_classification"] = "INVALID"
        elif variant == "V0":
            rec["recovery_classification"] = (
                "EFFECT_REPEATED" if after > before else "NO_REPEAT_OBSERVED"
            )
        elif variant == "V1":
            dedup_ok = OUTCOME_DEDUP_HIT in outcomes
            rec["recovery_classification"] = (
                "SINK_DEDUP_NO_REPEAT"
                if after == before == 1 and dedup_ok
                and rec["receipt_signature_valid"]
                and rec["receipt_binding_consistent"]
                and rec["receipt_result_matches_sink"]
                else "SINK_DEDUP_FAILED_OR_UNVERIFIED"
            )
        elif variant == "V2":
            conflict_ok = OUTCOME_CONFLICT in outcomes or rec["error_code"] == "IDEMPOTENCY_KEY_CONFLICT"
            rec["recovery_classification"] = (
                "IDEMPOTENCY_CONFLICT_REJECTED"
                if conflict_ok and after == before == 1
                else "CONFLICT_NOT_REJECTED"
            )
        return rec
    except Exception as exc:
        rec["error_code"] = f"RUNNER_EXCEPTION:{type(exc).__name__}:{exc}"
        return rec
    finally:
        if worker is not None:
            _close_proc(worker)
        if retry_worker is not None:
            _close_proc(retry_worker)
        _close_proc(svc)


def _concurrency_check(root: Path) -> dict[str, Any]:
    """Many concurrent requests, same key + same args: exactly one effect."""
    wd = root / "special-concurrency"
    wd.mkdir(parents=True, exist_ok=True)
    sink = ExternalToolSink(wd / "sink.sqlite3")
    op = "e23-concurrent-op"
    key = sink_idempotency_key(executor_id=EXEC_ID, operation_id=op)
    n = 8
    barrier = threading.Barrier(n)
    responses: list[dict[str, Any]] = [{} for _ in range(n)]

    def worker(i: int) -> None:
        barrier.wait()
        try:
            responses[i] = sink.dispatch(
                idempotency_key=key, operation_id=op, executor_id=EXEC_ID,
                tool_name="local.echo", tool_schema_hash="sha256:" + "d" * 64,
                arguments=ARGS_PRIMARY, result={"value": 42, "echo": "e23-sink-effect"},
                invoice_id=INVOICE_PRIMARY, enabled=True,
            )
        except IdempotencyKeyConflict:
            responses[i] = {"outcome": OUTCOME_CONFLICT}

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    execs = sum(1 for r in responses if r.get("outcome") == OUTCOME_EXECUTED)
    dedups = sum(1 for r in responses if r.get("outcome") == OUTCOME_DEDUP_HIT)
    effects = sink.effect_count(op)
    dispatches = sink.dispatch_count(op)
    return {
        "requests": n, "executed": execs, "dedup_hits": dedups,
        "committed_effects": effects, "dispatch_count": dispatches,
        "passed": execs == 1 and dedups == n - 1 and effects == 1 and dispatches == n,
    }


def _rollback_check(root: Path) -> dict[str, Any]:
    """Forced mid-transaction rollback: key + effect roll back together, then OK."""
    wd = root / "special-rollback"
    wd.mkdir(parents=True, exist_ok=True)
    sink = ExternalToolSink(wd / "sink.sqlite3")
    op = "e23-rollback-op"
    key = sink_idempotency_key(executor_id=EXEC_ID, operation_id=op)
    common = dict(
        idempotency_key=key, operation_id=op, executor_id=EXEC_ID,
        tool_name="local.echo", tool_schema_hash="sha256:" + "d" * 64,
        arguments=ARGS_PRIMARY, result={"value": 42, "echo": "e23-sink-effect"},
        invoice_id=INVOICE_PRIMARY, enabled=True,
    )
    first = sink.dispatch(rollback_once=True, **common)
    key_gone = not sink.record_exists(key)
    effect_zero = sink.effect_count(op) == 0
    second = sink.dispatch(**common)
    effect_after = sink.effect_count(op)
    return {
        "first_outcome": first["outcome"],
        "record_absent_after_rollback": key_gone,
        "effect_zero_after_rollback": effect_zero,
        "second_outcome": second["outcome"],
        "effect_after_retry": effect_after,
        "passed": (
            first["outcome"] == OUTCOME_ROLLED_BACK and key_gone and effect_zero
            and second["outcome"] == OUTCOME_EXECUTED and effect_after == 1
        ),
    }


def compute_summary(records: list[dict[str, Any]], trials: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for v in VARIANTS:
        subset = [r for r in records if r["variant"] == v]
        valid = [r for r in subset if r["crash_point_confirmed"] and r["recovery_classification"] != "INVALID"]
        out[v] = {
            "attempts": len(subset),
            "valid": len(valid),
            "crash_point_confirmed": sum(1 for r in valid if r["crash_point_confirmed"]),
            "journal_intent_count_at_crash": sum(r["journal_intent_count"] for r in valid),
            "journal_result_count_at_crash": sum(r["journal_result_count"] for r in valid),
            "execution_store_record_exists_at_crash": sum(1 for r in valid if r["execution_store_record_exists"]),
            "sink_effect_count_before_retry": sum(r["sink_effect_count_before_retry"] for r in valid),
            "sink_effect_count_after_retry": sum(r["sink_effect_count_after_retry"] for r in valid),
            "dispatch_count_before_retry": sum(r["dispatch_count_before_retry"] for r in valid),
            "dispatch_count_after_retry": sum(r["dispatch_count_after_retry"] for r in valid),
            "retry_returned": sum(1 for r in valid if r["retry_returned"]),
            "receipt_signature_valid": sum(1 for r in valid if r["receipt_signature_valid"]),
            "receipt_binding_consistent": sum(1 for r in valid if r["receipt_binding_consistent"]),
            "receipt_result_matches_sink": sum(1 for r in valid if r["receipt_result_matches_sink"]),
            "recovery_classes": {
                c: sum(1 for r in valid if r["recovery_classification"] == c)
                for c in sorted({r["recovery_classification"] for r in valid})
            },
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

    records: list[dict[str, Any]] = []
    started = time.time()
    for variant in VARIANTS:
        for trial in range(args.trials):
            rec = _run_trial(variant, trial, work_root)
            records.append(rec)
            print(f"[{variant} t{trial:02d}] {rec['recovery_classification']} "
                  f"eff {rec['sink_effect_count_before_retry']}->{rec['sink_effect_count_after_retry']} "
                  f"disp {rec['dispatch_count_before_retry']}->{rec['dispatch_count_after_retry']} "
                  f"out={rec['sink_outcomes']} rcpt={rec['receipt_signature_valid']}/"
                  f"{rec['receipt_binding_consistent']}/{rec['receipt_result_matches_sink']} "
                  f"ptr={rec['journal_intent_count']}/{rec['journal_result_count']} "
                  f"err={rec['error_code']}", flush=True)

    concurrency = _concurrency_check(work_root)
    rollback = _rollback_check(work_root)
    print(f"[special] concurrency={concurrency['passed']} rollback={rollback['passed']}", flush=True)

    with (out_dir / "trials.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        for r in records:
            writer.writerow({k: (str(r.get(k, "")).lower() if isinstance(r.get(k), bool) else r.get(k, ""))
                             for k in FIELDS})

    summary = compute_summary(records, args.trials)
    summary["special_checks"] = {"concurrency": concurrency, "rollback": rollback}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    raw = {
        "meta": {
            "experiment": "E2.3 tool-side idempotency & crash recovery",
            "baseline_commit": BASELINE, "branch": "exp/e2.3-sink-idempotency",
            "trials": args.trials, "variants": VARIANTS,
            "crash_point": EXPECTED_POINT,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(started)),
            "duration_seconds": round(time.time() - started, 3),
            "journal_service_is_standalone_process": True,
            "worker_is_standalone_process": True,
            "kill_is_real_process_termination": True,
            "sink_db_is_independent": True,
            "idempotency_key_excludes_arguments_and_binding_digest": True,
            "sink_recomputes_request_digest_from_actual_arguments": True,
        },
        "records": records,
        "metrics": summary,
    }
    (out_dir / "raw.json").write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
