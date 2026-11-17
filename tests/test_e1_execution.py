"""E1.5 final execution-gate security tests.

A single real cross-layer PendingExecution is produced once in ``setUpClass``
using the frozen Rust ``e1_service`` (real Halo2 prove/verify, real D10
coordinator, real Ed25519 receipts). Each test then gives an E1-configured
Executor an independent store + a dispatch counter and tampers one credential,
asserting the tool is NEVER dispatched (dispatch count stays 0).

No Python test token, ``verified=True`` or MockVerifier is used: the C11 happy
path performs a real dispatch of the deterministic local demo tool; all
cryptographic verification is real Ed25519 / canonical digest verification.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget import (
    CoordinatorHTTPServer, OnlineBudgetClient, OnlineBudgetCoordinator,
    OnlineBudgetExecutionAdapter, ToolPermission, issue_online_lease_grant,
)
from online_budget.canonical import b64encode, canonical_json_bytes, digest
from online_budget.cross_layer_bridge import CrossLayerBridge
from online_budget.e1_encoding import canonical_digest, fp_from_hex, fp_to_hex
from online_budget.e1_receipts import RECEIPT_DOMAIN, RECEIPT_SIGN_DOMAIN
from online_budget.e1_runtime import PendingExecution, run_tool_call_e1
from online_budget.executor import LocalToolRegistry, ToolExecutionDenied, TrustedToolExecutor
from online_budget.executor_authorization import issue_executor_authorization
from online_budget.receipts import BudgetReceipt
from online_budget.metering import (
    BudgetScope, compute_metering_policy_digest, parse_metering_policy, sign_metering_policy,
)
ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "experiments" / "d11_3_c_coordinator" / "target" / "debug" / "e1_service.exe"
REG_DOMAIN = b"D11.3-C-REGISTRATION-v1"
SCOPE_DOMAIN = "d11-e1-cross-layer-scope-v1"

BUDGET_ID_N, PERIOD_ID_N, Q_N, P_N, COST = 101, 7, 100, 1, 20
PROVER_STATE = {"u_old": 0, "r_old": 11, "r_new": 13, "nf_secret": 17}
GLOBAL, LEASE = "global-e15-test", "lease-e15-test"
COORDINATOR_ID, GATEWAY_ID = "coordinator-e15-test", "gateway-e15-test"
EXECUTOR_ID, ISSUER_ID = "executor-e15-test", "issuer-e15-test"
OPERATION_ID = "op-e15-1"
ARGS = {"invoice_id": "INV-E15-1"}
COORD_KEY_ID = "d11-coordinator-v1"
D11_SIGN_SEED = 3   # Rust config uses seed-3 Coordinator signing/public key
D10_COORD_SEED = 4
EXEC_SEED = 9
ISSUER_SEED = 7


def _seed(n: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([n] * 32))


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    import base64
    return base64.b64encode(raw).decode()


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


_D11_UNSIGNED = (
    "operation_id", "binding_digest", "metering_quote_digest", "budget_id",
    "period_id", "state_version", "new_commitment", "nullifier", "coordinator_key_id",
)


def _resign_d11(receipt: dict, changes: dict, *, seed: int = D11_SIGN_SEED) -> dict:
    """Return a D11 receipt with changed fields, validly re-signed (same key)."""
    new = dict(receipt)
    new.update(changes)
    unsigned = {name: new[name] for name in _D11_UNSIGNED}
    dt = canonical_digest(RECEIPT_DOMAIN, unsigned)
    sig = b64encode(
        _seed(seed).sign(canonical_json_bytes({"domain": RECEIPT_SIGN_DOMAIN, "transition_digest": dt}))
    )
    new["transition_digest"] = dt
    new["coordinator_signature"] = sig
    return new


def _resign_budget_receipt(receipt: dict, changes: dict, *, seed: int = D10_COORD_SEED) -> dict:
    """Return a D10 Budget Receipt with changed payload, validly re-signed."""
    payload = dict(receipt["payload"])
    payload.update(changes)
    sig = b64encode(_seed(seed).sign(canonical_json_bytes(payload)))
    return {"payload": payload, "signature_b64": sig}


class _CountingRegistry(LocalToolRegistry):
    """Registry that counts real dispatches (schema logic unchanged)."""

    def __init__(self) -> None:
        super().__init__()
        self.dispatch_count = 0

    def dispatch(self, name, arguments):
        self.dispatch_count += 1
        return super().dispatch(name, arguments)


@unittest.skipUnless(EXE.exists(), "e1_service binary not built")
class E1ExecutionGateTests(unittest.TestCase):
    """Real cross-layer credentials produced once; each test perturbs one field."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.now = int(time.time())
        cls.tmp = tempfile.TemporaryDirectory(prefix="e15-class-")
        cls.root = Path(cls.tmp.name)
        cls.issuer = _seed(ISSUER_SEED)
        cls.d10_coord = _seed(D10_COORD_SEED)
        cls.gateway = _seed(5)
        cls.executor_key = _seed(EXEC_SEED)

        cls.registry = LocalToolRegistry()
        cls.schema_hash = cls.registry.schema_hash("invoice_review")
        cls.context_digest = digest({"tenant": "e15", "purpose": "final-gate"})
        cls.lease = issue_online_lease_grant(
            cls.issuer, issuer_id=ISSUER_ID, grant_id="grant-e15", lease_id=LEASE,
            nonce="nonce-e15", global_budget_id=GLOBAL, quota_limit=5,
            issued_at=cls.now - 30, expires_at=cls.now + 900,
            coordinator_audience=COORDINATOR_ID, allowed_gateway_ids=(GATEWAY_ID,),
            subject_id="agent-e15", context_digest=cls.context_digest,
            allowed_tools=(ToolPermission("invoice_review", cls.schema_hash),),
        )
        cls.execution = cls._make_execution(OPERATION_ID)
        cls.coordinator = OnlineBudgetCoordinator(
            coordinator_id=COORDINATOR_ID, global_budget_id=GLOBAL, global_quota_limit=20,
            issuer_public_key=cls.issuer.public_key(), coordinator_private_key=cls.d10_coord,
            coordinator_key_id="coord-e15-key",
            database_path=cls.root / "coordinator.sqlite3",
            gateways={GATEWAY_ID: cls.gateway.public_key()}, clock=lambda: cls.now,
        )
        cls.server = CoordinatorHTTPServer(("127.0.0.1", 0), cls.coordinator)
        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        cls.server_thread.start()
        client = OnlineBudgetClient(
            base_url=f"http://127.0.0.1:{cls.server.server_address[1]}",
            gateway_id=GATEWAY_ID, gateway_private_key=cls.gateway,
            coordinator_public_key=cls.d10_coord.public_key(),
            coordinator_id=COORDINATOR_ID, global_budget_id=GLOBAL,
        )
        cls.adapter = OnlineBudgetExecutionAdapter(
            client=client, issuer_public_key=cls.issuer.public_key(),
            global_budget_id=GLOBAL, global_quota_limit=20, coordinator_id=COORDINATOR_ID,
            receipt_cache_path=cls.root / "gateway-cache.sqlite3",
        )
        cls.adapter.bind_lease(cls.execution, cls.lease)

        cls.policy = sign_metering_policy(
            cls.issuer, issuer_id=ISSUER_ID, policy_version="v-e15-1",
            P=fp_to_hex(P_N),
            entries=[{"tool_name": "invoice_review", "tool_schema_hash": cls.schema_hash, "cost": COST}],
        )
        cls.scope = BudgetScope(
            global_budget_id=GLOBAL, lease_id=LEASE, budget_id=fp_to_hex(BUDGET_ID_N),
            period_id=fp_to_hex(PERIOD_ID_N), Q=Q_N, P=fp_to_hex(P_N),
        )
        cls.authorization = issue_executor_authorization(
            cls.issuer, issuer_id=ISSUER_ID, authorization_id="auth-e15-1",
            online_lease_grant=cls.lease, execution_grant=cls.execution,
            gateway_id=GATEWAY_ID, coordinator_id=COORDINATOR_ID, executor_id=EXECUTOR_ID,
            executor_public_key=cls.executor_key.public_key(),
            tool_name="invoice_review", tool_schema_hash=cls.schema_hash,
            issued_at=cls.now - 15, expires_at=cls.now + 600, arguments=ARGS,
        )

        # Rust service config and cross-layer scope registration.
        cls.cfg_path, cls.db_path = cls._write_config(cls.root)
        cls.bridge = CrossLayerBridge([str(EXE), str(cls.cfg_path)], timeout=90, startup_timeout=90)
        cls.bridge.start()
        # Get C_old from one real prove, then register the scope bound to it.
        witness = cls._witness()
        prove = cls.bridge.prove(witness)
        c_old = int(fp_from_hex(prove["instance"][4]))
        cls._register_scope(c_old)

        # The E1.4-style executor that produces the pending execution.
        cls.runtime_executor = TrustedToolExecutor(
            executor_id=EXECUTOR_ID, issuer_public_key=cls.issuer.public_key(),
            coordinator_public_key=cls.d10_coord.public_key(),
            executor_private_key=cls.executor_key,
            database_path=cls.root / "runtime-executor.sqlite3", registry=cls.registry,
            clock=lambda: cls.now, authorization_policy="authorization_required",
        )
        cls.pending = run_tool_call_e1(
            bridge=cls.bridge, gateway_adapter=cls.adapter, executor=cls.runtime_executor,
            online_lease_grant=cls.lease, execution_grant=cls.execution,
            executor_id=EXECUTOR_ID, executor_authorization=cls.authorization,
            metering_policy=cls.policy, issuer_public_key=cls.issuer.public_key(),
            budget_scope=cls.scope, prover_state=PROVER_STATE,
            tool_name="invoice_review", arguments=ARGS,
            now=cls.now, issued_at=cls.now - 10, expires_at=cls.now + 600,
        )
        cls.d11_keys = {COORD_KEY_ID: _seed(D11_SIGN_SEED).public_key()}

        cls.addClassCleanup(cls._class_cleanup)

    @classmethod
    def _class_cleanup(cls) -> None:
        try:
            cls.bridge.close()
        except Exception:
            pass
        try:
            cls.server.shutdown()
            cls.server.server_close()
            cls.server_thread.join(timeout=3)
        except Exception:
            pass
        cls.tmp.cleanup()

    @classmethod
    def _witness(cls) -> dict:
        return {
            "budget_id": fp_to_hex(BUDGET_ID_N), "period_id": fp_to_hex(PERIOD_ID_N),
            "quota": Q_N, "cost": COST, "u_old": PROVER_STATE["u_old"],
            "u_new": PROVER_STATE["u_old"] + COST,
            "slack": Q_N - PROVER_STATE["u_old"] - COST,
            "r_old": fp_to_hex(PROVER_STATE["r_old"]),
            "r_new": fp_to_hex(PROVER_STATE["r_new"]),
            "nf_secret": fp_to_hex(PROVER_STATE["nf_secret"]), "policy": fp_to_hex(P_N),
        }

    @classmethod
    def _write_config(cls, root: Path):
        db = str(root / "d11.sqlite")
        cfg = root / "config.json"
        cfg.write_text(json.dumps({
            "db_path": db, "issuer_id": ISSUER_ID, "issuer_public_key_b64": _pub_b64(cls.issuer),
            "executor_public_keys": {EXECUTOR_ID: _pub_b64(cls.executor_key)},
            "coordinator_key_id": COORD_KEY_ID,
            "coordinator_signing_key_b64": b64encode(bytes([D11_SIGN_SEED] * 32)),
            "coordinator_public_keys": {COORD_KEY_ID: _pub_b64(_seed(D11_SIGN_SEED))},
        }), encoding="utf-8")
        return cfg, db

    @classmethod
    def _make_execution(cls, operation_id: str) -> dict:
        unsigned = {
            "version": 2, "issuer_id": cls.lease.issuer_id, "grant_id": cls.lease.grant_id,
            "lease_id": cls.lease.lease_id, "subject_id": cls.lease.subject_id,
            "audience": GATEWAY_ID, "context_digest": cls.lease.context_digest,
            "issued_at": cls.lease.issued_at, "expires_at": cls.lease.expires_at,
            "quota_limit": cls.lease.quota_limit, "nonce": cls.lease.nonce,
            "allowed_tools": [p.as_dict() for p in cls.lease.allowed_tools],
            "parent_authorization_digest": hashlib.sha256(b"e15").hexdigest(),
            "parent_authorization_nonce": "parent-e15", "operation_id": operation_id,
        }
        return {**unsigned, "signature_b64": b64encode(cls.issuer.sign(canonical_json_bytes(unsigned)))}

    @classmethod
    def _register_scope(cls, c_old: int) -> None:
        message = (
            REG_DOMAIN + BUDGET_ID_N.to_bytes(32, "little") + PERIOD_ID_N.to_bytes(32, "little")
            + Q_N.to_bytes(32, "little") + P_N.to_bytes(32, "little") + c_old.to_bytes(32, "little")
        )
        auth_bytes = message + cls.issuer.sign(message)
        import base64
        unsigned = {
            "version": 1, "issuer_id": ISSUER_ID, "global_budget_id": GLOBAL, "lease_id": LEASE,
            "online_lease_grant_digest": _sha(b"lease-e15"), "budget_id": fp_to_hex(BUDGET_ID_N),
            "period_id": fp_to_hex(PERIOD_ID_N), "Q": Q_N, "P": fp_to_hex(P_N),
            "metering_policy_digest": compute_metering_policy_digest(cls.policy),
            "registration_authorization_digest": _sha(auth_bytes),
        }
        signed = dict(unsigned)
        signed["signature_b64"] = b64encode(
            cls.issuer.sign(canonical_json_bytes({"domain": SCOPE_DOMAIN, "payload": unsigned}))
        )
        cls.bridge.register_e1(signed, base64.b64encode(auth_bytes).decode())

    def _executor(self) -> TrustedToolExecutor:
        """An independent E1-enabled Executor with its own store + counting registry."""
        tmp = tempfile.TemporaryDirectory(prefix="e15-exec-")
        self.addCleanup(tmp.cleanup)
        registry = _CountingRegistry()
        ex = TrustedToolExecutor(
            executor_id=EXECUTOR_ID, issuer_public_key=self.issuer.public_key(),
            coordinator_public_key=self.d10_coord.public_key(),
            executor_private_key=self.executor_key,
            database_path=str(Path(tmp.name) / "exec.sqlite3"), registry=registry,
            clock=lambda: self.now, authorization_policy="authorization_required",
            e1_required=True, d11_coordinator_public_keys=self.d11_keys,
        )
        ex.counter = registry
        return ex

    def _run_e1(self, ex, pending=None, **overrides):
        return ex.execute_e1(
            pending_execution=pending if pending is not None else self.pending,
            online_lease_grant=self.lease, execution_grant=self.execution,
            executor_authorization=overrides.get("authorization", self.authorization),
            metering_policy=overrides.get("policy", self.policy),
            budget_scope=overrides.get("scope", self.scope),
        )

    def _assert_denied_no_dispatch(self, ex, pending=None, **overrides):
        with self.assertRaises(ToolExecutionDenied):
            self._run_e1(ex, pending=pending, **overrides)
        self.assertEqual(ex.counter.dispatch_count, 0)

    # ---------------------------------------------------------------- happy path //
    def test_c11_all_credentials_valid_dispatches_and_seals_v2(self):
        ex = self._executor()
        receipt = self._run_e1(ex)
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(receipt["payload"]["receipt_version"], 2)
        self.assertEqual(receipt["payload"]["result"]["invoice_id"], ARGS["invoice_id"])
        self.assertTrue(ex.verify_receipt(receipt, binding=self._reconstruct_binding()))
        # Fifth relation: Execution Receipt commits the Budget Receipt digest.
        self.assertEqual(receipt["payload"]["budget_receipt_digest"], _budget_digest(self.pending))
        self.assertEqual(
            receipt["payload"]["executor_authorization_digest"],
            self.authorization.authorization_digest,
        )

    def _reconstruct_binding(self):
        from online_budget.tool_binding import ToolCallBinding
        return ToolCallBinding.from_dict({
            **self.pending.binding,
            "binding_digest": digest({"domain": "agent-tool-call-binding-v1", "binding": self.pending.binding}),
        })

    def test_c12_replay_returns_stored_receipt_without_second_dispatch(self):
        ex = self._executor()
        first = self._run_e1(ex)
        second = self._run_e1(ex)
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(first, second)

    # ------------------------------------------------------------ D10 receipt gate //
    def test_c02_tampered_d10_budget_receipt_denied(self):
        ex = self._executor()
        # Tamper the signature only (no re-sign): a forged Budget Receipt must
        # fail the D10 Coordinator signature check.
        bad = dict(self.pending.d10_budget_receipt)
        bad["signature_b64"] = b64encode(bytes(64))
        p = replace(self.pending, d10_budget_receipt=bad)
        self._assert_denied_no_dispatch(ex, p)

    def test_c03_d10_request_digest_not_equal_d_e_denied(self):
        ex = self._executor()
        bad = _resign_budget_receipt(
            self.pending.d10_budget_receipt, {"request_digest": "sha256:" + "a" * 64}
        )
        p = replace(self.pending, d10_budget_receipt=bad)
        self._assert_denied_no_dispatch(ex, p)

    # ------------------------------------------------------------- D11 receipt gate //
    def test_c04_tampered_d11_signature_denied(self):
        ex = self._executor()
        r = dict(self.pending.d11_transition_receipt)
        sig = r["coordinator_signature"]
        r["coordinator_signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c05_tampered_d11_transition_digest_denied(self):
        ex = self._executor()
        r = dict(self.pending.d11_transition_receipt)
        r["transition_digest"] = "sha256:" + "0" * 64
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c06_unregistered_d11_coordinator_key_id_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"coordinator_key_id": "unknown-key"})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c07_d11_operation_id_mismatch_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"operation_id": "op-other"})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c08_d11_binding_digest_mismatch_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"binding_digest": "sha256:" + "b" * 64})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c09_d11_quote_digest_mismatch_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"metering_quote_digest": "sha256:" + "c" * 64})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)

    def test_c10_d11_budget_and_period_id_mismatch_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"budget_id": fp_to_hex(999)})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)
        ex2 = self._executor()
        r2 = _resign_d11(self.pending.d11_transition_receipt, {"period_id": fp_to_hex(999)})
        p2 = replace(self.pending, d11_transition_receipt=r2)
        self._assert_denied_no_dispatch(ex2, p2)

    def test_c13_d11_state_field_format_illegal_denied(self):
        ex = self._executor()
        r = _resign_d11(self.pending.d11_transition_receipt, {"state_version": -1})
        p = replace(self.pending, d11_transition_receipt=r)
        self._assert_denied_no_dispatch(ex, p)
        ex2 = self._executor()
        r2 = dict(self.pending.d11_transition_receipt)
        r2["new_commitment"] = "not-canonical-fp"
        p2 = replace(self.pending, d11_transition_receipt=r2)
        self._assert_denied_no_dispatch(ex2, p2)

    # ----------------------------------------------------------- attestation/policy //
    def test_c14_tampered_attestation_denied(self):
        ex = self._executor()
        att = dict(self.pending.metering_attestation)
        att["attestation"] = dict(att["attestation"])
        att["attestation"]["c"] = att["attestation"]["c"] + 1
        p = replace(self.pending, metering_attestation=att)
        self._assert_denied_no_dispatch(ex, p)

    def test_c15_metering_policy_bad_signature_denied(self):
        ex = self._executor()
        bad = parse_metering_policy(self.policy.as_dict())
        bad_data = bad.as_dict()
        bad_data["signature_b64"] = b64encode(bytes(64))
        p = replace(self.pending)  # unchanged pending; policy is a separate arg
        self._assert_denied_no_dispatch(ex, p, policy=parse_metering_policy(bad_data))

    # ---------------------------------------------------------- binding/arguments //
    def test_c16_arguments_tampered_denied(self):
        ex = self._executor()
        p = replace(self.pending, arguments={"invoice_id": "INV-OTHER"})
        self._assert_denied_no_dispatch(ex, p)

    def test_c17_schema_drift_denied(self):
        ex = self._executor()
        ex.registry._schemas["invoice_review"]["properties"]["invoice_id"]["minLength"] = 2
        self._assert_denied_no_dispatch(ex)

    # ---------------------------------------------------------- mode / missing D11 //
    def test_c18_plain_execute_denied_in_e1_mode(self):
        ex = self._executor()
        with self.assertRaises(ToolExecutionDenied):
            ex.execute(
                binding=self._reconstruct_binding(), arguments=ARGS,
                online_lease_grant=self.lease, execution_grant=self.execution,
                budget_receipt=self.pending.d10_budget_receipt,
                executor_authorization=self.authorization,
            )
        self.assertEqual(ex.counter.dispatch_count, 0)

    def test_c19_missing_d11_receipt_denied(self):
        ex = self._executor()
        p = replace(self.pending, d11_transition_receipt=None)
        self._assert_denied_no_dispatch(ex, p)

    def test_c20_e1_config_requires_authorization_and_trusted_keys(self):
        with self.assertRaises(ValueError):
            TrustedToolExecutor(
                executor_id=EXECUTOR_ID, issuer_public_key=self.issuer.public_key(),
                coordinator_public_key=self.d10_coord.public_key(),
                executor_private_key=self.executor_key, database_path=":memory:",
                authorization_policy="legacy_allowed", e1_required=True,
                d11_coordinator_public_keys=self.d11_keys,
            )
        with self.assertRaises(ValueError):
            TrustedToolExecutor(
                executor_id=EXECUTOR_ID, issuer_public_key=self.issuer.public_key(),
                coordinator_public_key=self.d10_coord.public_key(),
                executor_private_key=self.executor_key, database_path=":memory:",
                authorization_policy="authorization_required", e1_required=True,
                d11_coordinator_public_keys={},
            )

    # ------------------------------------------------- dispatch capability gate //
    def _d10_executor(self) -> TrustedToolExecutor:
        """A legacy D10-only Executor (no E1 gate) with its own counting registry."""
        tmp = tempfile.TemporaryDirectory(prefix="e15-d10-exec-")
        self.addCleanup(tmp.cleanup)
        registry = _CountingRegistry()
        ex = TrustedToolExecutor(
            executor_id=EXECUTOR_ID, issuer_public_key=self.issuer.public_key(),
            coordinator_public_key=self.d10_coord.public_key(),
            executor_private_key=self.executor_key,
            database_path=str(Path(tmp.name) / "exec.sqlite3"), registry=registry,
            clock=lambda: self.now,
        )
        ex.counter = registry
        return ex

    def _direct_dispatch_kwargs(self) -> dict:
        """Well-formed helper arguments a bypass caller would try to pass."""
        return dict(
            binding=self._reconstruct_binding(),
            safe_arguments=dict(ARGS),
            receipt=BudgetReceipt.from_dict(self.pending.d10_budget_receipt),
            authorization_digest=None,
        )

    def test_c21_e1_mode_direct_dispatch_helper_denied(self):
        ex = self._executor()
        with self.assertRaises(ToolExecutionDenied):
            ex._dispatch_and_seal(**self._direct_dispatch_kwargs())
        self.assertEqual(ex.counter.dispatch_count, 0)

    def test_c22_d10_mode_direct_dispatch_helper_denied(self):
        ex = self._d10_executor()
        with self.assertRaises(ToolExecutionDenied):
            ex._dispatch_and_seal(**self._direct_dispatch_kwargs())
        self.assertEqual(ex.counter.dispatch_count, 0)

    def test_c23_d10_normal_execute_still_succeeds(self):
        """Capability gate must not break the legacy D10-only execute() path."""
        from online_budget.tool_binding import build_tool_call_binding
        op = "op-e15-d10-direct"
        execution = self._make_execution(op)
        self.adapter.bind_lease(execution, self.lease)
        binding = build_tool_call_binding(
            operation_id=op, gateway_id=GATEWAY_ID,
            coordinator_id=COORDINATOR_ID, online_lease_grant=self.lease,
            execution_grant=execution, tool_name="invoice_review",
            tool_schema_hash=self.schema_hash, arguments=ARGS, executor_id=EXECUTOR_ID,
        )
        self.adapter.consume_for_grant(
            execution, operation_id=op, request_digest=binding.binding_digest
        )
        budget_receipt = self.adapter.coordinator_receipt_for_operation(op)
        ex = self._d10_executor()
        receipt = ex.execute(
            binding=binding, arguments=ARGS, online_lease_grant=self.lease,
            execution_grant=execution, budget_receipt=budget_receipt,
        )
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(receipt["payload"]["receipt_version"], 1)

    def test_c24_no_capability_issuer_and_real_token_cannot_replay(self):
        """No reusable issuer method exists; the real path's token is single-use.

        The capability used by a real ``execute_e1`` call is captured via a spy
        on ``_dispatch_and_seal`` (no direct construction). It must have been
        consumed by the real path, and cannot drive a second dispatch.
        """
        ex = self._executor()
        # No instance-level method accepts arbitrary binding/receipt to mint a
        # capability -- that was the bypass the review flagged.
        self.assertFalse(hasattr(ex, "_issue_dispatch_capability"))
        captured: list = []
        real = ex._dispatch_and_seal

        def spy(*args, **kwargs):
            captured.append(kwargs.get("_capability"))
            return real(*args, **kwargs)

        ex._dispatch_and_seal = spy
        self._run_e1(ex)  # normal E1 path creates + consumes a real capability
        self.assertEqual(len(captured), 1)
        cap = captured[0]
        self.assertIsNotNone(cap)
        self.assertTrue(cap.consumed)
        self.assertEqual(ex.counter.dispatch_count, 1)
        # The consumed token cannot drive another dispatch.
        with self.assertRaises(ToolExecutionDenied):
            ex._dispatch_and_seal(**self._direct_dispatch_kwargs(), _capability=cap)
        self.assertEqual(ex.counter.dispatch_count, 1)


def _budget_digest(pending: PendingExecution) -> str:
    from online_budget.receipts import BudgetReceipt
    return BudgetReceipt.from_dict(pending.d10_budget_receipt).receipt_digest


if __name__ == "__main__":
    unittest.main(verbosity=2)
