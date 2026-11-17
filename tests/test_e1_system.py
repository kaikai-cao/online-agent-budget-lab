"""E1.6 system-level end-to-end acceptance (no protocol change).

This suite deliberately does NOT re-run the E1.1-E1.5 unit matrices: those
already cover policy/attestation tampering, D11 receipt fields, single-capability
dispatch and transport fakes (see ``test_e1_encoding``, ``test_metering``,
``test_cross_layer_bridge``, ``test_e1_runtime`` and ``test_e1_execution``).

What is added here is SYSTEM behaviour that those unit-level suites cannot show:

* one uninterrupted chain from Issuer registration through D10 admission, real
  Halo2 prove/verify, D11 state commit, E1.5 final gate, deterministic local
  tool dispatch and a v2 Execution Receipt -- with the SQLite state inspected
  directly (D10 operation count and D11 version/nullifier/operation rows);
* a deterministic local tool that FAILS after dispatch: a signed FAILED v2
  receipt is persisted, both budgets stay charged, and a retry cannot cause a
  second dispatch or a rewritten receipt;
* real ``e1_service`` process KILLS before and after the D11 commit, followed by
  the actual Python restart/get_operation recovery and the final gate --
  the previous suites only injected in-process crashes or transport fakes;
* two-process-equivalent concurrency through one real service (two threads,
  same C_old), scope/period isolation and idempotency observed in the DB;
* a compact full-chain credential-mismatch sweep asserting dispatch_count==0.

Honest boundary: this is an executable acceptance record of the frozen design,
not a formal security proof. The deterministic local tool is not evidence about
arbitrary external APIs; ``c`` is a policy-assigned weighted fee, not a physical
resource measurement; D10 and D11 remain separate SQLite databases with Saga
semantics (no cross-database atomic transaction, no refund).
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget import (
    CoordinatorHTTPServer,
    OnlineBudgetClient,
    OnlineBudgetCoordinator,
    OnlineBudgetExecutionAdapter,
    ToolPermission,
    issue_online_lease_grant,
)
from online_budget import e1_runtime
from online_budget.canonical import b64encode, canonical_json_bytes, digest
from online_budget.cross_layer_bridge import BridgeUnavailable, CrossLayerBridge, ServiceError
from online_budget.e1_encoding import canonical_digest, fp_from_hex, fp_to_hex
from online_budget.e1_receipts import RECEIPT_DOMAIN, RECEIPT_SIGN_DOMAIN
from online_budget.e1_runtime import E1FailClosed, PendingExecution, run_tool_call_e1
from online_budget.executor import LocalToolRegistry, ToolExecutionDenied, TrustedToolExecutor
from online_budget.executor_authorization import issue_executor_authorization
from online_budget.metering import (
    ATTESTATION_DOMAIN,
    BudgetScope,
    compute_metering_policy_digest,
    parse_metering_policy,
    sign_metering_policy,
)
from online_budget.receipts import BudgetReceipt
from online_budget.tool_binding import ToolCallBinding

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "experiments" / "d11_3_c_coordinator" / "target" / "debug" / "e1_service.exe"

REG_DOMAIN = b"D11.3-C-REGISTRATION-v1"
SCOPE_DOMAIN = "d11-e1-cross-layer-scope-v1"
BINDING_DOMAIN = "agent-tool-call-binding-v1"

Q_N, P_N, COST = 100, 1, 20
BUDGET_ID_N, PERIOD_ID_N = 101, 7
ARGS = {"invoice_id": "INV-E16-SYSTEM"}
PROVER_STATE = {"u_old": 0, "r_old": 11, "r_new": 13, "nf_secret": 17}

D11_SIGN_SEED = 3
D10_COORD_SEED = 4
GATEWAY_SEED = 5
ISSUER_SEED = 7
EXEC_SEED = 9

_COUNTER = itertools.count(1)


# --------------------------------------------------------------------------- #
# small pure helpers (independent of any test class)
# --------------------------------------------------------------------------- #
def _seed(n: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([n] * 32))


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _resign_d11(receipt: dict, changes: dict, *, key: Ed25519PrivateKey) -> dict:
    """Re-sign a D11 receipt after changing one unsigned business field."""
    names = (
        "operation_id", "binding_digest", "metering_quote_digest", "budget_id",
        "period_id", "state_version", "new_commitment", "nullifier", "coordinator_key_id",
    )
    new = dict(receipt)
    new.update(changes)
    unsigned = {name: new[name] for name in names}
    dt = canonical_digest(RECEIPT_DOMAIN, unsigned)
    sig = b64encode(
        key.sign(canonical_json_bytes({
            "domain": RECEIPT_SIGN_DOMAIN, "transition_digest": dt,
        }))
    )
    new["transition_digest"] = dt
    new["coordinator_signature"] = sig
    return new


def _resign_budget_receipt(receipt: dict, changes: dict, *, key: Ed25519PrivateKey) -> dict:
    payload = dict(receipt["payload"])
    payload.update(changes)
    return {"payload": payload, "signature_b64": b64encode(key.sign(canonical_json_bytes(payload)))}


def _resign_attestation(envelope: dict, changes: dict, *, key: Ed25519PrivateKey) -> dict:
    att = dict(envelope["attestation"])
    att.update(changes)
    sig = b64encode(
        key.sign(canonical_json_bytes({"domain": ATTESTATION_DOMAIN, "payload": att}))
    )
    return {"attestation": att, "signature_b64": sig}


def _budget_digest(pending: PendingExecution) -> str:
    return BudgetReceipt.from_dict(pending.d10_budget_receipt).receipt_digest


def _binding_from_pending(pending: PendingExecution) -> ToolCallBinding:
    return ToolCallBinding.from_dict({
        **pending.binding,
        "binding_digest": digest({"domain": BINDING_DOMAIN, "binding": pending.binding}),
    })


class _CountingRegistry(LocalToolRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.dispatch_count = 0

    def dispatch(self, name, arguments):
        self.dispatch_count += 1
        return super().dispatch(name, arguments)


class _FailingRegistry(LocalToolRegistry):
    """Deterministic local tool that enters dispatch and then throws."""

    def __init__(self) -> None:
        super().__init__()
        self.dispatch_count = 0

    def dispatch(self, name, arguments):
        self.dispatch_count += 1
        raise RuntimeError("deterministic local tool failure")


# --------------------------------------------------------------------------- #
# bridge proxies: only fault-injection points, no verification logic
# --------------------------------------------------------------------------- #
class _BridgeProxy:
    """Transparent proxy; subclasses override exactly one transport method."""

    def __init__(self, real: CrossLayerBridge) -> None:
        self.real = real

    def __getattr__(self, name):
        return getattr(self.real, name)


class _Recorder(_BridgeProxy):
    def __init__(self, real: CrossLayerBridge) -> None:
        super().__init__(real)
        self.prove_witnesses: list[dict] = []
        self.submit_payloads: list[dict] = []

    def prove(self, witness):
        self.prove_witnesses.append(dict(witness))
        return self.real.prove(witness)

    def submit_transition_e1(self, payload):
        self.submit_payloads.append(dict(payload))
        return self.real.submit_transition_e1(payload)


class _KillBeforeSubmit(_BridgeProxy):
    """Kill the REAL e1_service child after D10 admission, before D11 submit."""

    def __init__(self, real: CrossLayerBridge) -> None:
        super().__init__(real)
        self.kills = 0
        self.submit_payloads: list[dict] = []

    def submit_transition_e1(self, payload):
        self.submit_payloads.append(dict(payload))
        if self.kills == 0:
            self.kills += 1
            proc = self.real._proc
            assert proc is not None and proc.poll() is None
            proc.kill()
            proc.wait(timeout=15)
            raise BridgeUnavailable("test: service killed before D11 submit")
        return self.real.submit_transition_e1(payload)


class _KillAfterCommit(_BridgeProxy):
    """Forward the real submit (commit), then kill the child before responding."""

    def __init__(self, real: CrossLayerBridge) -> None:
        super().__init__(real)
        self.kills = 0

    def submit_transition_e1(self, payload):
        receipt = self.real.submit_transition_e1(payload)
        if self.kills == 0:
            self.kills += 1
            proc = self.real._proc
            assert proc is not None and proc.poll() is None
            proc.kill()
            proc.wait(timeout=15)
            raise BridgeUnavailable("test: service killed after D11 commit, response lost")
        return receipt


@dataclass
class _OpContext:
    operation_id: str
    execution: dict
    authorization: object
    scope: BudgetScope
    prover_state: dict
    arguments: dict
    budget_id: int
    period_id: int
    c_old: int | None = None


class _SystemHarness:
    """One real D10 Coordinator + one real Rust service + one fresh D11 DB.

    Every test builds its own harness so that SQLite state is unambiguous. A
    harness starts only one ``e1_service`` process (one keygen); mid-test kills
    are recovered by the production ``CrossLayerBridge.restart()`` path.
    """

    def __init__(self, case: unittest.TestCase, *, registry=None) -> None:
        self.case = case
        self.serial = next(_COUNTER)
        self.now = int(time.time())
        self.root = Path(tempfile.mkdtemp(prefix=f"e16-system-{self.serial}-"))
        case.addCleanup(
            lambda: __import__("shutil").rmtree(self.root, ignore_errors=True)
        )

        self.issuer = _seed(ISSUER_SEED)
        self.d10_coord = _seed(D10_COORD_SEED)
        self.gateway = _seed(GATEWAY_SEED)
        self.executor_key = _seed(EXEC_SEED)
        self.d11_sign = _seed(D11_SIGN_SEED)
        self.coord_key_id = "d11-coordinator-v1"
        self.tool_name = "invoice_review"
        self.registry = registry if registry is not None else LocalToolRegistry()
        self.schema_hash = self.registry.schema_hash(self.tool_name)

        self.global_id = f"global-e16-{self.serial}"
        self.lease_id = f"lease-e16-{self.serial}"
        self.coordinator_id = f"coordinator-e16-{self.serial}"
        self.gateway_id = f"gateway-e16-{self.serial}"
        self.executor_id = f"executor-e16-{self.serial}"
        self.issuer_id = f"issuer-e16-{self.serial}"

        self.lease = issue_online_lease_grant(
            self.issuer, issuer_id=self.issuer_id, grant_id=f"grant-e16-{self.serial}",
            lease_id=self.lease_id, nonce=f"nonce-e16-{self.serial}",
            global_budget_id=self.global_id, quota_limit=20,
            issued_at=self.now - 30, expires_at=self.now + 3600,
            coordinator_audience=self.coordinator_id,
            allowed_gateway_ids=(self.gateway_id,),
            subject_id="agent-e16", context_digest=digest({"tenant": "e16", "purpose": "system"}),
            allowed_tools=(ToolPermission(self.tool_name, self.schema_hash),),
        )
        self.coordinator = OnlineBudgetCoordinator(
            coordinator_id=self.coordinator_id, global_budget_id=self.global_id,
            global_quota_limit=50, issuer_public_key=self.issuer.public_key(),
            coordinator_private_key=self.d10_coord, coordinator_key_id="coord-e16-key",
            database_path=self.root / "d10.sqlite3",
            gateways={self.gateway_id: self.gateway.public_key()}, clock=lambda: self.now,
        )
        self.server = CoordinatorHTTPServer(("127.0.0.1", 0), self.coordinator)
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.server_thread.start()
        case.addCleanup(self._stop_server)
        client = OnlineBudgetClient(
            base_url=f"http://127.0.0.1:{self.server.server_address[1]}",
            gateway_id=self.gateway_id, gateway_private_key=self.gateway,
            coordinator_public_key=self.d10_coord.public_key(),
            coordinator_id=self.coordinator_id, global_budget_id=self.global_id,
        )
        self.adapter = OnlineBudgetExecutionAdapter(
            client=client, issuer_public_key=self.issuer.public_key(),
            global_budget_id=self.global_id, global_quota_limit=50,
            coordinator_id=self.coordinator_id,
            receipt_cache_path=self.root / "gateway-cache.sqlite3",
        )

        self.policy = sign_metering_policy(
            self.issuer, issuer_id=self.issuer_id, policy_version="v-e16-system",
            P=fp_to_hex(P_N),
            entries=[{
                "tool_name": self.tool_name, "tool_schema_hash": self.schema_hash, "cost": COST,
            }],
        )
        self.cfg_path, self.db_path = self._write_config()
        self.bridge = CrossLayerBridge(
            [str(EXE), str(self.cfg_path)], timeout=90, startup_timeout=90
        )
        self.bridge.start()
        case.addCleanup(self.bridge.close)
        self.d11_keys = {self.coord_key_id: self.d11_sign.public_key()}

        # The Runtime executor is used only for schema/precheck and signing the
        # Attestation; it must never dispatch (run_tool_call_e1 never calls it).
        self.runtime_executor = self.executor()

        self.op1 = self.new_context("op-e16-1", BUDGET_ID_N, PERIOD_ID_N)

    # -------------------------------------------------------------- lifecycle //
    def _stop_server(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join(timeout=3)
        except Exception:
            pass

    def _write_config(self):
        cfg = self.root / "config.json"
        db = self.root / "d11.sqlite3"
        cfg.write_text(json.dumps({
            "db_path": str(db), "issuer_id": self.issuer_id,
            "issuer_public_key_b64": _pub_b64(self.issuer),
            "executor_public_keys": {self.executor_id: _pub_b64(self.executor_key)},
            "coordinator_key_id": self.coord_key_id,
            "coordinator_signing_key_b64": b64encode(bytes([D11_SIGN_SEED] * 32)),
            "coordinator_public_keys": {self.coord_key_id: _pub_b64(self.d11_sign)},
        }), encoding="utf-8")
        return cfg, db

    # ------------------------------------------------------------- construction //
    def _make_execution(self, operation_id: str) -> dict:
        unsigned = {
            "version": 2, "issuer_id": self.lease.issuer_id, "grant_id": self.lease.grant_id,
            "lease_id": self.lease.lease_id, "subject_id": self.lease.subject_id,
            "audience": self.gateway_id, "context_digest": self.lease.context_digest,
            "issued_at": self.lease.issued_at, "expires_at": self.lease.expires_at,
            "quota_limit": self.lease.quota_limit, "nonce": self.lease.nonce,
            "allowed_tools": [p.as_dict() for p in self.lease.allowed_tools],
            "parent_authorization_digest": hashlib.sha256(b"e16").hexdigest(),
            "parent_authorization_nonce": "parent-e16", "operation_id": operation_id,
        }
        return {
            **unsigned,
            "signature_b64": b64encode(self.issuer.sign(canonical_json_bytes(unsigned))),
        }

    def new_context(
        self, operation_id: str, budget_id: int, period_id: int, *, register: bool = True
    ) -> _OpContext:
        execution = self._make_execution(operation_id)
        self.adapter.bind_lease(execution, self.lease)
        authorization = issue_executor_authorization(
            self.issuer, issuer_id=self.issuer_id,
            authorization_id=f"auth-{operation_id}",
            online_lease_grant=self.lease, execution_grant=execution,
            gateway_id=self.gateway_id, coordinator_id=self.coordinator_id,
            executor_id=self.executor_id,
            executor_public_key=self.executor_key.public_key(),
            tool_name=self.tool_name, tool_schema_hash=self.schema_hash,
            issued_at=self.now - 20, expires_at=self.now + 1800, arguments=ARGS,
        )
        scope = BudgetScope(
            global_budget_id=self.global_id, lease_id=self.lease_id,
            budget_id=fp_to_hex(budget_id), period_id=fp_to_hex(period_id),
            Q=Q_N, P=fp_to_hex(P_N),
        )
        ctx = _OpContext(
            operation_id=operation_id, execution=execution, authorization=authorization,
            scope=scope, prover_state=dict(PROVER_STATE), arguments=dict(ARGS),
            budget_id=budget_id, period_id=period_id,
        )
        if register:
            proof = self.bridge.prove(self._witness(ctx))
            ctx.c_old = int(fp_from_hex(proof["instance"][4]))
            self._register_scope(ctx)
        return ctx

    def _witness(self, ctx: _OpContext) -> dict:
        u_old = ctx.prover_state["u_old"]
        return {
            "budget_id": fp_to_hex(ctx.budget_id), "period_id": fp_to_hex(ctx.period_id),
            "quota": Q_N, "cost": COST, "u_old": u_old, "u_new": u_old + COST,
            "slack": Q_N - u_old - COST,
            "r_old": fp_to_hex(ctx.prover_state["r_old"]),
            "r_new": fp_to_hex(ctx.prover_state["r_new"]),
            "nf_secret": fp_to_hex(ctx.prover_state["nf_secret"]),
            "policy": fp_to_hex(P_N),
        }

    def _register_scope(self, ctx: _OpContext) -> None:
        message = (
            REG_DOMAIN + ctx.budget_id.to_bytes(32, "little")
            + ctx.period_id.to_bytes(32, "little") + Q_N.to_bytes(32, "little")
            + P_N.to_bytes(32, "little") + (ctx.c_old or 0).to_bytes(32, "little")
        )
        auth_bytes = message + self.issuer.sign(message)
        unsigned = {
            "version": 1, "issuer_id": self.issuer_id, "global_budget_id": self.global_id,
            "lease_id": self.lease_id, "online_lease_grant_digest": _sha(b"e16-lease"),
            "budget_id": fp_to_hex(ctx.budget_id), "period_id": fp_to_hex(ctx.period_id),
            "Q": Q_N, "P": fp_to_hex(P_N),
            "metering_policy_digest": compute_metering_policy_digest(self.policy),
            "registration_authorization_digest": _sha(auth_bytes),
        }
        signed = {
            **unsigned,
            "signature_b64": b64encode(self.issuer.sign(canonical_json_bytes(
                {"domain": SCOPE_DOMAIN, "payload": unsigned}
            ))),
        }
        self.bridge.register_e1(signed, base64.b64encode(auth_bytes).decode())

    # ------------------------------------------------------------- executors //
    def executor(self, *, registry=None, d11_keys=None, store_dir: str | None = None):
        reg = registry if registry is not None else _CountingRegistry()
        tmp_path = store_dir or tempfile.mkdtemp(prefix=f"e16-exec-{self.serial}-")
        if store_dir is None:
            self.case.addCleanup(lambda: __import__("shutil").rmtree(tmp_path, ignore_errors=True))
        ex = TrustedToolExecutor(
            executor_id=self.executor_id, issuer_public_key=self.issuer.public_key(),
            coordinator_public_key=self.d10_coord.public_key(),
            executor_private_key=self.executor_key,
            database_path=str(Path(tmp_path) / "exec.sqlite3"), registry=reg,
            clock=lambda: self.now, authorization_policy="authorization_required",
            e1_required=True,
            d11_coordinator_public_keys=self.d11_keys if d11_keys is None else d11_keys,
        )
        ex.counter = reg
        return ex

    # ------------------------------------------------------------------- run //
    def run(self, ctx: _OpContext, *, bridge=None, executor=None, policy=None,
            now=None, issued_at=None, expires_at=None) -> PendingExecution:
        return run_tool_call_e1(
            bridge=bridge if bridge is not None else self.bridge,
            gateway_adapter=self.adapter,
            executor=executor if executor is not None else self.runtime_executor,
            online_lease_grant=self.lease, execution_grant=ctx.execution,
            executor_id=self.executor_id, executor_authorization=ctx.authorization,
            metering_policy=policy if policy is not None else self.policy,
            issuer_public_key=self.issuer.public_key(), budget_scope=ctx.scope,
            prover_state=ctx.prover_state, tool_name=self.tool_name,
            arguments=ctx.arguments,
            now=self.now if now is None else now,
            issued_at=self.now - 10 if issued_at is None else issued_at,
            expires_at=self.now + 600 if expires_at is None else expires_at,
        )

    @staticmethod
    def execute(ex, h: "_SystemHarness", pending: PendingExecution, ctx: _OpContext,
                **overrides) -> dict:
        return ex.execute_e1(
            pending_execution=pending, online_lease_grant=h.lease,
            execution_grant=overrides.get("execution", ctx.execution),
            executor_authorization=overrides.get("authorization", ctx.authorization),
            metering_policy=overrides.get("policy", h.policy),
            budget_scope=overrides.get("scope", ctx.scope),
        )

    # ------------------------------------------------------------ DB snapshots //
    def d10_state(self) -> dict:
        with sqlite3.connect(self.root / "d10.sqlite3") as con:
            global_used = con.execute(
                "SELECT global_used_count FROM budget_meta WHERE singleton_id=1"
            ).fetchone()[0]
            operations = con.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
            lease_used = con.execute(
                "SELECT used_count FROM leases WHERE lease_id=?", (self.lease_id,)
            ).fetchone()[0]
        return {"global_used": global_used, "operations": operations, "lease_used": lease_used}

    def d11_state(self, ctx: _OpContext) -> dict:
        bid, pid = fp_to_hex(ctx.budget_id), fp_to_hex(ctx.period_id)
        with sqlite3.connect(self.db_path) as con:
            row = con.execute(
                "SELECT current_version,current_commitment FROM budget_instances "
                "WHERE budget_id=? AND period_id=?", (bid, pid)
            ).fetchone()
            nullifiers = con.execute(
                "SELECT COUNT(*) FROM used_nullifiers WHERE budget_id=? AND period_id=?",
                (bid, pid),
            ).fetchone()[0]
            ops = con.execute(
                "SELECT COUNT(*) FROM budget_operations WHERE budget_id=? AND period_id=?",
                (bid, pid),
            ).fetchone()[0]
            scopes = con.execute(
                "SELECT COUNT(*) FROM cross_layer_scopes WHERE global_budget_id=? "
                "AND lease_id=?", (self.global_id, self.lease_id)
            ).fetchone()[0]
        return {
            "version": None if row is None else row[0],
            "commitment": None if row is None else row[1],
            "nullifiers": nullifiers, "operations": ops, "scopes": scopes,
        }


# --------------------------------------------------------------------------- #
# E1.6 system acceptance
# --------------------------------------------------------------------------- #
@unittest.skipUnless(EXE.exists(), "e1_service binary not built")
class E1SystemAcceptanceTests(unittest.TestCase):
    """A-E of the E1.6 matrix, observed on real processes and SQLite state."""

    # ------------------------------------------------------------------ A //
    def test_s01_full_chain_success_single_dispatch_and_single_charge(self):
        h = _SystemHarness(self)
        recorder = _Recorder(h.bridge)
        ex = h.executor()

        pending = h.run(h.op1, bridge=recorder)
        receipt = h.execute(ex, h, pending, h.op1)

        # Tool / receipt.
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(receipt["payload"]["receipt_version"], 2)
        self.assertTrue(ex.verify_receipt(receipt, binding=_binding_from_pending(pending)))
        self.assertEqual(receipt["payload"]["budget_receipt_digest"], _budget_digest(pending))
        self.assertEqual(
            receipt["payload"]["executor_authorization_digest"],
            h.op1.authorization.authorization_digest,
        )
        # D10 counts operations (1 per call), never weighted consumption.
        self.assertEqual(h.d10_state(), {"global_used": 1, "operations": 1, "lease_used": 1})
        # D11 stores the weighted transition in one version/one nullifier/one row.
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))
        self.assertEqual(state["commitment"], pending.d11_transition_receipt["new_commitment"])
        # c is the policy-assigned weighted fee: u_new-u_old == c in the prove witness.
        witness = recorder.prove_witnesses[-1]
        self.assertEqual(witness["u_new"] - witness["u_old"], COST)
        self.assertEqual(witness["cost"], COST)
        self.assertFalse(pending.recovered)

    # ------------------------------------------------------------------ B //
    def test_s02_tool_failure_persists_failed_v2_receipt_without_replay(self):
        h = _SystemHarness(self, registry=_FailingRegistry())
        ex = h.executor(registry=h.registry)
        pending = h.run(h.op1)
        receipt = h.execute(ex, h, pending, h.op1)

        self.assertEqual(receipt["payload"]["status"], "FAILED")
        self.assertEqual(receipt["payload"]["receipt_version"], 2)
        self.assertEqual(ex.counter.dispatch_count, 1)  # entered dispatch exactly once
        self.assertTrue(ex.verify_receipt(receipt, binding=_binding_from_pending(pending)))
        self.assertEqual(receipt["payload"]["result_digest"], digest({
            "domain": "agent-tool-result-v1", "result": receipt["payload"]["result"],
        }))
        # Tool failure != budget failure: both budgets stay charged, no refund.
        self.assertEqual(h.d10_state()["global_used"], 1)
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"]), (1, 1))

        # Retry returns the SAME stored receipt; no second dispatch, no rewrite.
        again = h.execute(ex, h, pending, h.op1)
        self.assertEqual(again, receipt)
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(h.d10_state()["global_used"], 1)
        self.assertEqual(h.d11_state(h.op1)["version"], 1)

    # ------------------------------------------------------------------ C //
    def test_s03_failure_before_d10_admission_charges_nothing(self):
        h = _SystemHarness(self)
        ex = h.executor()
        bad = h.policy.as_dict()
        bad["signature_b64"] = b64encode(bytes(64))
        with self.assertRaises(E1FailClosed):
            h.run(h.op1, policy=parse_metering_policy(bad))
        self.assertEqual(h.d10_state(), {"global_used": 0, "operations": 0, "lease_used": 0})
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (0, 0, 0))
        self.assertEqual(ex.counter.dispatch_count, 0)

    def test_s04_process_kill_before_d11_commit_recovers_with_original_credentials(self):
        h = _SystemHarness(self)
        killer = _KillBeforeSubmit(h.bridge)
        ex = h.executor()

        pending = h.run(h.op1, bridge=killer)
        self.assertTrue(pending.recovered)
        self.assertEqual(killer.kills, 1)
        # Original attestation/quote/D_E are reused; no re-sign, no new charge.
        self.assertEqual(len(killer.submit_payloads), 2)
        self.assertEqual(
            killer.submit_payloads[0]["metering_attestation"],
            killer.submit_payloads[1]["metering_attestation"],
        )
        self.assertEqual(
            killer.submit_payloads[0]["metering_quote_digest"],
            killer.submit_payloads[1]["metering_quote_digest"],
        )
        self.assertEqual(
            pending.metering_attestation,
            killer.submit_payloads[0]["metering_attestation"],
        )
        self.assertEqual(pending.metering_attestation["attestation"]["c"], COST)
        self.assertEqual(pending.cross_layer_digest, e1_runtime.compute_cross_layer_admission_digest(
            digest({"domain": BINDING_DOMAIN, "binding": pending.binding}),
            h.op1.authorization.authorization_digest,
            pending.metering_quote_digest,
        ))
        self.assertEqual(h.d10_state()["global_used"], 1)
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))

        receipt = h.execute(ex, h, pending, h.op1)
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")

    def test_s05_process_kill_after_d11_commit_restores_exact_stored_receipt(self):
        h = _SystemHarness(self)
        killer = _KillAfterCommit(h.bridge)
        ex = h.executor()

        pending = h.run(h.op1, bridge=killer)
        self.assertTrue(pending.recovered)
        self.assertEqual(killer.kills, 1)
        # The restored receipt is byte-identical to the one the surviving DB holds.
        stored = h.bridge.get_operation(
            operation_id=h.op1.operation_id,
            binding_digest=pending.d11_transition_receipt["binding_digest"],
            metering_quote_digest=pending.d11_transition_receipt["metering_quote_digest"],
        )
        self.assertIsNotNone(stored)
        self.assertEqual(pending.d11_transition_receipt, stored)
        self.assertEqual(h.d10_state()["global_used"], 1)
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))

        receipt = h.execute(ex, h, pending, h.op1)
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["receipt_version"], 2)

    def test_s06_expired_original_attestation_after_kill_fails_closed(self):
        h = _SystemHarness(self)
        killer = _KillBeforeSubmit(h.bridge)
        ex = h.executor()
        original_issue = e1_runtime.issue_metering_attestation
        issue_calls = []

        def counting_issue(**kwargs):
            issue_calls.append(1)
            return original_issue(**kwargs)

        def advanced_clock(*, bridge, artifacts, budget_scope, now):
            # Test-only injection: wall clock advanced while the service was down.
            return original_recover(
                bridge=bridge, artifacts=artifacts, budget_scope=budget_scope,
                now=now + 3600,
            )

        original_recover = e1_runtime._recover_submit
        with mock.patch.object(e1_runtime, "issue_metering_attestation", counting_issue), \
             mock.patch.object(e1_runtime, "_recover_submit", advanced_clock):
            with self.assertRaises(E1FailClosed) as ctx:
                h.run(h.op1, bridge=killer)
        self.assertIn("expired", str(ctx.exception))
        self.assertEqual(len(issue_calls), 1)  # never re-signed a fresh Attestation
        # One-sided Saga state is reported, but no fake receipt and no dispatch.
        self.assertEqual(h.d10_state()["global_used"], 1)
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (0, 0, 0))
        self.assertEqual(ex.counter.dispatch_count, 0)

    def test_s07_final_gate_failure_never_dispatches_or_seals_receipt(self):
        h = _SystemHarness(self)
        ex = h.executor()
        pending = h.run(h.op1)
        bad = dict(pending.d11_transition_receipt)
        bad["coordinator_signature"] = b64encode(bytes(64))
        forged = replace(pending, d11_transition_receipt=bad)

        with self.assertRaises(ToolExecutionDenied):
            h.execute(ex, h, forged, h.op1)
        self.assertEqual(ex.counter.dispatch_count, 0)
        self.assertIsNone(ex.store.get_receipt(h.op1.operation_id))
        # The committed D11 receipt itself is untouched.
        self.assertEqual(h.d11_state(h.op1)["version"], 1)

    # ------------------------------------------------------------------ D //
    def test_s08_two_threads_same_c_old_exactly_one_state_transition(self):
        h = _SystemHarness(self)
        ctx2 = h.new_context("op-e16-race", BUDGET_ID_N, PERIOD_ID_N, register=False)
        results: dict[str, tuple[str, object]] = {}
        barrier = threading.Barrier(2)

        def worker(ctx):
            barrier.wait(timeout=60)
            try:
                results[ctx.operation_id] = ("ok", h.run(ctx))
            except Exception as exc:  # the losing CAS must fail closed
                results[ctx.operation_id] = ("err", exc)

        threads = [threading.Thread(target=worker, args=(ctx,)) for ctx in (h.op1, ctx2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=180)
        self.assertFalse(any(t.is_alive() for t in threads), "race worker hung")
        self.assertEqual(
            sorted(kind for kind, _ in results.values()), ["err", "ok"],
            f"unexpected outcomes: {results}",
        )
        # Check the real DB, not just the two return values.
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))
        # Both D10 operations were admitted before the race; no refund is given.
        self.assertEqual(h.d10_state()["global_used"], 2)
        winner = next(p for _, p in results.values() if isinstance(p, PendingExecution))
        winner_ctx = h.op1 if winner.operation_id == h.op1.operation_id else ctx2
        ex = h.executor()
        self.assertEqual(
            h.execute(ex, h, winner, winner_ctx)["payload"]["status"], "SUCCEEDED"
        )
        self.assertEqual(ex.counter.dispatch_count, 1)

    def test_s09_same_operation_same_digests_returns_identical_receipt(self):
        h = _SystemHarness(self)
        recorder = _Recorder(h.bridge)
        pending = h.run(h.op1, bridge=recorder)
        self.assertEqual(len(recorder.submit_payloads), 1)
        again = h.bridge.submit_transition_e1(recorder.submit_payloads[0])
        self.assertEqual(again, pending.d11_transition_receipt)
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))

    def test_s10_same_operation_different_digest_is_idempotency_conflict(self):
        h = _SystemHarness(self)
        recorder = _Recorder(h.bridge)
        h.run(h.op1, bridge=recorder)
        payload = dict(recorder.submit_payloads[0])

        # Re-sign the Attestation so the request reaches the CAS instead of
        # failing at the binding-digest check (same construction as Rust i02).
        payload["binding_digest"] = "sha256:" + "b" * 64
        att = _resign_attestation(payload["metering_attestation"], {
            "binding_digest": payload["binding_digest"],
        }, key=h.executor_key)
        payload["metering_attestation"] = att
        payload["metering_quote_digest"] = canonical_digest(ATTESTATION_DOMAIN, att["attestation"])

        with self.assertRaises(ServiceError) as ctx:
            h.bridge.submit_transition_e1(payload)
        self.assertEqual(ctx.exception.code, "IDEMPOTENCY_CONFLICT")
        state = h.d11_state(h.op1)
        self.assertEqual((state["version"], state["nullifiers"], state["operations"]), (1, 1, 1))

    def test_s11_same_scope_different_budget_is_scope_conflict_no_partial_write(self):
        h = _SystemHarness(self)
        before = h.d11_state(h.op1)
        try:
            h.new_context("op-e16-conflict", BUDGET_ID_N + 500, PERIOD_ID_N)
        except ServiceError as exc:
            self.assertEqual(exc.code, "SCOPE_CONFLICT")
        else:
            self.fail("registering a different budget_id in the same scope must conflict")
        with sqlite3.connect(h.db_path) as con:
            registered = con.execute(
                "SELECT COUNT(*) FROM budget_instances WHERE budget_id=?",
                (fp_to_hex(BUDGET_ID_N + 500),),
            ).fetchone()[0]
        self.assertEqual(registered, 0)
        self.assertEqual(h.d11_state(h.op1), before)

    def test_s12_different_periods_are_isolated_end_to_end(self):
        h = _SystemHarness(self)
        ctx2 = h.new_context("op-e16-period2", BUDGET_ID_N + 1, PERIOD_ID_N + 1)
        pending1 = h.run(h.op1)
        pending2 = h.run(ctx2)
        ex = h.executor()

        r1 = h.execute(ex, h, pending1, h.op1)
        r2 = h.execute(ex, h, pending2, ctx2)
        self.assertEqual(ex.counter.dispatch_count, 2)
        self.assertEqual(
            [r1["payload"]["status"], r2["payload"]["status"]], ["SUCCEEDED", "SUCCEEDED"]
        )
        s1, s2 = h.d11_state(h.op1), h.d11_state(ctx2)
        self.assertEqual((s1["version"], s1["nullifiers"], s1["operations"]), (1, 1, 1))
        self.assertEqual((s2["version"], s2["nullifiers"], s2["operations"]), (1, 1, 1))
        self.assertNotEqual(s1["commitment"], s2["commitment"])
        self.assertEqual(s1["scopes"], 2)
        self.assertEqual(h.d10_state()["global_used"], 2)

    # ------------------------------------------------------------------ E //
    def test_s13_full_chain_credential_mismatches_never_dispatch(self):
        h = _SystemHarness(self)
        pending = h.run(h.op1)
        variants = {}

        bad_att = dict(pending.metering_attestation)
        bad_att["attestation"] = dict(bad_att["attestation"])
        bad_att["attestation"]["c"] = COST + 1
        variants["attestation_tampered"] = replace(pending, metering_attestation=bad_att)

        variants["d10_request_digest_mismatch"] = replace(pending, d10_budget_receipt=(
            _resign_budget_receipt(pending.d10_budget_receipt, {
                "request_digest": "sha256:" + "a" * 64,
            }, key=h.d10_coord)
        ))
        variants["d11_signature_tampered"] = replace(pending, d11_transition_receipt={
            **pending.d11_transition_receipt,
            "coordinator_signature": b64encode(bytes(64)),
        })
        variants["operation_id_mismatch"] = replace(pending, d11_transition_receipt=(
            _resign_d11(pending.d11_transition_receipt, {"operation_id": "op-forged"},
                        key=h.d11_sign)
        ))
        variants["untrusted_coordinator_key"] = pending

        for name, forged in variants.items():
            with self.subTest(variant=name):
                # e1_required forbids an empty key table; a populated table with
                # the WRONG Coordinator key is the realistic untrusted case.
                keys = (
                    {h.coord_key_id: _seed(99).public_key()}
                    if name == "untrusted_coordinator_key" else h.d11_keys
                )
                ex = h.executor(d11_keys=keys)
                with self.assertRaises(ToolExecutionDenied):
                    h.execute(ex, h, forged, h.op1)
                self.assertEqual(ex.counter.dispatch_count, 0)
                self.assertIsNone(ex.store.get_receipt(h.op1.operation_id))


if __name__ == "__main__":
    unittest.main(verbosity=2)
