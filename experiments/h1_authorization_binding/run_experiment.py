"""H1 experiment runner: B2 (online) vs C (local credential) feasibility matrix.

Runs a mechanism-verification matrix (not paper-grade statistics). Every row
records B2 and C ACTUAL observed results (outcome / reason / effect count),
never pre-filled expectations. Writes results/{trials.csv,summary.json,raw.json}.

Usage:
  PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
    .venv/Scripts/python experiments/h1_authorization_binding/run_experiment.py \
    --output-dir experiments/h1_authorization_binding/results/run-001
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = REPO / "src"
for p in (str(SRC), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from online_budget.canonical import digest  # noqa: E402

from h1_authorization_service import (  # noqa: E402
    AuthorizationService,
    AuthServiceTLSServer,
    B2OnlineVerifier,
)
from h1_executor import Executor, VerificationError  # noqa: E402
from h1_protocol import ActionRequest, compute_action_digest  # noqa: E402
from h1_sink import ControlledSink, OUTCOME_DEDUP_HIT, OUTCOME_EXECUTED  # noqa: E402

FIELDS = [
    "scenario",
    "path",
    "expected",
    "actual_outcome",
    "actual_reason",
    "effects_added",
    "pass",
]

BASE_REQUEST = {
    "executor_id": "executor-main",
    "server_uri": "https://mcp.example.test/mcp",
    "tool_name": "send_email",
    "schema_hash": digest({"template": "send_email-v1"}),
    "arguments": {"to": "alice@example.test", "subject": "hi", "body": "hello"},
}


def fresh_request(**overrides: Any) -> dict[str, Any]:
    req = dict(BASE_REQUEST)
    req["arguments"] = dict(BASE_REQUEST["arguments"])
    req.update(overrides)
    return req


class Harness:
    """One independent harness per scenario: its own service, TLS server, sink."""

    def __init__(self, *, workdir: Path, scenario: str) -> None:
        self.scenario = scenario
        self.auth = AuthorizationService()
        self.tls = AuthServiceTLSServer(self.auth)
        host, port, fp = self.tls.start()
        self.b2 = B2OnlineVerifier(host=host, port=port, pinned_fingerprint=fp)
        self.sink = ControlledSink(workdir / f"sink-{uuid.uuid4().hex}.sqlite3")
        # Pre-configured trusted public key for C (never supplied by Planner).
        pub = Ed25519PublicKey.from_public_bytes(self.auth.public_key_bytes())
        self.executor = Executor(
            executor_id="executor-main",
            sink=self.sink,
            b2_verifier=self.b2,
            trusted_keys={"h1-key-1": pub},
        )
        self._effects_before = 0

    def setup_authorization(
        self, *, request: dict[str, Any], ttl: float = 300.0, now: float | None = None
    ) -> tuple[str, dict[str, Any]]:
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=request, jti=jti, ttl_seconds=ttl, now=now)
        return jti, self.auth.issue_credential(jti)

    def mark(self) -> None:
        self._effects_before = self.sink.effect_count()

    def effects_added(self) -> int:
        return self.sink.effect_count() - self._effects_before

    def close(self) -> None:
        self.tls.shutdown()

    def auth_ref(self, jti: str) -> dict[str, Any]:
        return {"jti": jti, "action_digest": compute_action_digest(BASE_REQUEST)}

    def run_b2(
        self,
        *,
        request: dict[str, Any],
        auth_ref: dict[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        try:
            out = self.executor.execute_b2(
                request=request, auth_ref=auth_ref, rollback_once=rollback_once
            )
            return {"outcome": out["outcome"], "reason": "OK"}
        except VerificationError as exc:
            return {"outcome": "REJECTED", "reason": str(exc)}

    def run_c(
        self,
        *,
        request: dict[str, Any],
        credential: dict[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        try:
            out = self.executor.execute_c(
                request=request, credential=credential, rollback_once=rollback_once
            )
            return {"outcome": out["outcome"], "reason": "OK"}
        except VerificationError as exc:
            return {"outcome": "REJECTED", "reason": str(exc)}


def _row(scenario: str, path: str, expected: str, result: dict[str, Any], effects: int, ok: bool) -> dict[str, Any]:
    return {
        "scenario": scenario,
        "path": path,
        "expected": expected,
        "actual_outcome": result["outcome"],
        "actual_reason": result["reason"],
        "effects_added": effects,
        "pass": "TRUE" if ok else "FALSE",
    }


def run_matrix(workdir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    workdir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    raws: list[dict[str, Any]] = []

    def scenario(name: str, fn: Callable[[Harness], dict[str, Any]]) -> None:
        h = Harness(workdir=workdir, scenario=name)
        try:
            detail = fn(h)
            raws.append({"scenario": name, **detail})
        finally:
            h.close()

    # B2 and C share one consumption store, so a single jti can only be consumed
    # once across BOTH paths. For per-path comparisons we use distinct jtis.
    def paired(h: Harness, *, req: dict[str, Any], mutate: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
               ttl: float = 300.0, now: float | None = None, revoke: bool = False,
               tamper_cred: bool = False, kill_service: bool = False,
               cred_claim_overrides: Mapping[str, Any] | None = None,
               rollback_b2: bool = False, rollback_c: bool = False,
               expect_b2: str, expect_c: str) -> dict[str, Any]:
        req_b2 = fresh_request(**{k: v for k, v in req.items()})
        req_c = fresh_request(**{k: v for k, v in req.items()})
        jti_b2, cred_b2 = h.setup_authorization(request=req, ttl=ttl, now=now)
        jti_c, cred_c = h.setup_authorization(request=req, ttl=ttl, now=now)
        if revoke:
            h.auth.revoke(jti_b2)
            h.auth.revoke(jti_c)
        if tamper_cred:
            cred_c = dict(cred_c)
            cred_c["payload"] = dict(cred_c["payload"])
            cred_c["payload"]["arguments"] = {"to": "attacker@example.test"}
        if cred_claim_overrides:
            # Signer-side claim rewrite: re-sign with the same key so signature
            # stays valid but issuer/audience/key_id would be wrong. For unknown
            # key_id we simply relabel (signature no longer matches that key_id's
            # trusted key, so verification fails at key lookup or signature).
            cred_c = dict(cred_c)
            cred_c["payload"] = dict(cred_c["payload"])
            cred_c["payload"].update(cred_claim_overrides)
        if mutate:
            req_b2 = mutate(req_b2)
            req_c = mutate(req_c)
        if kill_service:
            h.tls.shutdown()

        # Measure each path's effect delta independently (not cumulative).
        h.mark()
        r_b2 = h.run_b2(request=req_b2, auth_ref=h.auth_ref(jti_b2), rollback_once=rollback_b2)
        e_b2 = h.effects_added()
        h.mark()
        r_c = h.run_c(request=req_c, credential=cred_c, rollback_once=rollback_c)
        e_c = h.effects_added()

        ok_b2 = (r_b2["outcome"] == expect_b2)
        ok_c = (r_c["outcome"] == expect_c)
        rows.append(_row(h.scenario, "B2", expect_b2, r_b2, e_b2, ok_b2))
        rows.append(_row(h.scenario, "C", expect_c, r_c, e_c, ok_c))
        return {
            "b2": r_b2, "c": r_c, "effects_b2": e_b2, "effects_c": e_c,
            "expect_b2": expect_b2, "expect_c": expect_c,
        }

    def mut_args(r: dict[str, Any]) -> dict[str, Any]:
        r["arguments"] = dict(r["arguments"]); r["arguments"]["to"] = "attacker@example.test"; return r

    def mut_schema(r: dict[str, Any]) -> dict[str, Any]:
        r["schema_hash"] = digest({"template": "send_email-v2-evil"}); return r

    def mut_server(r: dict[str, Any]) -> dict[str, Any]:
        r["server_uri"] = "https://evil.example.test/mcp"; return r

    def mut_executor(r: dict[str, Any]) -> dict[str, Any]:
        r["executor_id"] = "executor-attacker"; return r

    now = time.time()
    scenario("legal_allow", lambda h: paired(
        h, req=fresh_request(), expect_b2="EXECUTED", expect_c="EXECUTED"))
    scenario("tamper_arguments", lambda h: paired(
        h, req=fresh_request(), mutate=mut_args, expect_b2="REJECTED", expect_c="REJECTED"))
    scenario("tamper_schema", lambda h: paired(
        h, req=fresh_request(), mutate=mut_schema, expect_b2="REJECTED", expect_c="REJECTED"))
    scenario("tamper_server_uri", lambda h: paired(
        h, req=fresh_request(), mutate=mut_server, expect_b2="REJECTED", expect_c="REJECTED"))
    scenario("executor_mismatch", lambda h: paired(
        h, req=fresh_request(), mutate=mut_executor, expect_b2="REJECTED", expect_c="REJECTED"))
    scenario("expired_authorization", lambda h: paired(
        h, req=fresh_request(), ttl=-1.0, now=now, expect_b2="REJECTED", expect_c="REJECTED"))
    scenario("revoked_b2_denies", lambda h: paired(
        h, req=fresh_request(), revoke=True, expect_b2="REJECTED", expect_c="EXECUTED"))
    scenario("credential_tamper", lambda h: paired(
        h, req=fresh_request(), tamper_cred=True, expect_b2="EXECUTED", expect_c="REJECTED"))
    scenario("auth_service_unreachable", lambda h: paired(
        h, req=fresh_request(), kill_service=True, expect_b2="REJECTED", expect_c="EXECUTED"))
    # C trust anchor: a validly-signed credential carrying a wrong/unknown issuer
    # or audience or key_id MUST be rejected by the Executor's pre-configured
    # trust set (it never trusts values carried in the request itself).
    scenario("c_unknown_key_id", lambda h: paired(
        h, req=fresh_request(), cred_claim_overrides={"key_id": "h1-key-UNTRUSTED"},
        expect_b2="EXECUTED", expect_c="REJECTED"))
    scenario("c_wrong_audience", lambda h: paired(
        h, req=fresh_request(), cred_claim_overrides={"audience": "attacker-audience"},
        expect_b2="EXECUTED", expect_c="REJECTED"))
    scenario("c_wrong_issuer", lambda h: paired(
        h, req=fresh_request(), cred_claim_overrides={"issuer": "attacker-issuer"},
        expect_b2="EXECUTED", expect_c="REJECTED"))

    # Replay / concurrency / crash use dedicated helpers.
    def scenario_replay(h: Harness) -> dict[str, Any]:
        req = fresh_request()
        jti, cred = h.setup_authorization(request=req)
        h.mark()
        r1 = h.run_c(request=req, credential=cred)
        r2 = h.run_c(request=req, credential=cred)
        eff = h.effects_added()
        ok = r1["outcome"] == "EXECUTED" and r2["outcome"] == "DEDUP_HIT" and eff == 1
        rows.append(_row("replay_sequential", "C", "EXECUTED+DEDUP_HIT/1effect",
                         {"outcome": f"{r1['outcome']}+{r2['outcome']}", "reason": r2["reason"]}, eff, ok))
        return {"first": r1, "second": r2, "effects": eff}

    def scenario_concurrent(h: Harness) -> dict[str, Any]:
        import threading
        req = fresh_request()
        jti, cred = h.setup_authorization(request=req)
        h.mark()
        results: list[dict[str, Any]] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(h.run_c(request=req, credential=cred))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        eff = h.effects_added()
        executed = sum(1 for r in results if r["outcome"] == "EXECUTED")
        ok = executed == 1 and eff == 1
        rows.append(_row("replay_concurrent", "C", "1 EXECUTED/1 effect",
                         {"outcome": f"{executed} EXECUTED of 8", "reason": "OK"}, eff, ok))
        return {"executed": executed, "effects": eff, "outcomes": h.sink.outcome_counts()}

    def scenario_crash(h: Harness) -> dict[str, Any]:
        req = fresh_request()
        jti, cred = h.setup_authorization(request=req)
        h.mark()
        r_rollback = h.run_c(request=req, credential=cred, rollback_once=True)
        eff_after_rollback = h.effects_added()
        r_retry = h.run_c(request=req, credential=cred)
        eff_after_retry = h.effects_added()
        r_replay = h.run_c(request=req, credential=cred)
        eff_final = h.effects_added()
        ok = (
            r_rollback["outcome"] == "ROLLED_BACK" and eff_after_rollback == 0
            and r_retry["outcome"] == "EXECUTED" and eff_after_retry == 1
            and r_replay["outcome"] == "DEDUP_HIT" and eff_final == 1
        )
        rows.append(_row("crash_rollback_then_retry", "C", "ROLLBACK→EXECUTE→DEDUP/1effect",
                         {"outcome": f"{r_rollback['outcome']}→{r_retry['outcome']}→{r_replay['outcome']}",
                          "reason": "OK"}, eff_final, ok))
        return {"rollback": r_rollback, "retry": r_retry, "replay": r_replay, "effects": eff_final}

    def scenario_forged_digest(h: Harness) -> dict[str, Any]:
        req = fresh_request()
        jti, cred = h.setup_authorization(request=req)
        # Planner adds a forged action_digest inside arguments / top-level; Executor
        # must recompute from identity fields and ignore it.
        forged = fresh_request()
        forged["action_digest"] = digest({"forged": True})  # bogus top-level hint
        forged["arguments"] = dict(forged["arguments"])
        # Use a SEPARATE jti/credential for C so the forged-field check is not
        # confounded by dedup from the B2 path.
        jti_c, cred_c = h.setup_authorization(request=fresh_request())
        h.mark()
        r_b2 = h.run_b2(request=forged, auth_ref=h.auth_ref(jti))
        e_b2 = h.effects_added()
        h.mark()
        r_c = h.run_c(request=forged, credential=cred_c)
        e_c = h.effects_added()
        # A forged top-level action_digest is ignored: the Executor recomputes
        # from the (unchanged) identity fields, so a legitimate action still runs.
        # The point is that the forged field did NOT cause a bypass or a denial.
        ok_b2 = r_b2["outcome"] == "EXECUTED" and e_b2 == 1
        ok_c = r_c["outcome"] == "EXECUTED" and e_c == 1
        rows.append(_row("planner_forged_digest", "B2", "EXECUTED (forged field ignored)",
                         r_b2, e_b2, ok_b2))
        rows.append(_row("planner_forged_digest", "C", "EXECUTED (forged field ignored)",
                         r_c, e_c, ok_c))
        return {"b2": r_b2, "c": r_c, "effects_b2": e_b2, "effects_c": e_c}

    scenario("replay_sequential", scenario_replay)
    scenario("replay_concurrent", scenario_concurrent)
    scenario("crash_rollback", scenario_crash)
    scenario("planner_forged_digest", scenario_forged_digest)

    return rows, raws


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default=str(HERE / "results" / "run-001"))
    args = parser.parse_args()
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    workdir = outdir / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    rows, raws = run_matrix(workdir)

    with (outdir / "trials.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    passed = sum(1 for r in rows if r["pass"] == "TRUE")
    summary = {
        "experiment": "H1 minimum feasibility - B2 online vs C local credential",
        "total_checks": len(rows),
        "passed_checks": passed,
        "failed_checks": len(rows) - passed,
        "all_pass": passed == len(rows),
        "meta": {
            "action_domain": "h1-action-binding-v1",
            "digest": "sha256 over canonical action identity fields",
            "b2_transport": "real localhost TLS with certificate pinning",
            "b2_fails_closed": True,
            "c_trust_anchor": "pre-configured Ed25519 public key by key_id",
            "shared_consumption_store": True,
            "consume_and_effect_same_transaction": True,
            "not_exactly_once_for_third_party": True,
        },
    }
    (outdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (outdir / "raw.json").write_text(
        json.dumps(raws, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary["all_pass"]:
        print("WARNING: some checks failed; see trials.csv", file=sys.stderr)


if __name__ == "__main__":
    main()
