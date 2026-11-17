"""E1.4 Runtime orchestration tests.

D-E digest, c-from-policy, real Halo2 proof through the frozen Rust service,
D10 admission with request_digest == D_E, D11 transition consistency, fail-closed
paths and §B.6.1 crash recovery. No Python test token, verified=True or
MockProver is used for proof verification: the Rust ``e1_service`` does the real
verification. Transport-only fakes are marked as such and never stand in for
cryptographic checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

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
from online_budget.canonical import b64encode, canonical_json_bytes, digest
from online_budget.cross_layer_bridge import BridgeTimeout, CrossLayerBridge, ServiceError
from online_budget.e1_encoding import canonical_digest, fp_from_hex, fp_to_hex
from online_budget.e1_runtime import (
    CROSS_LAYER_ADMISSION_DOMAIN,
    E1FailClosed,
    E1SubmitIndeterminate,
    PendingExecution,
    compute_cross_layer_admission_digest,
    run_tool_call_e1,
)
from online_budget.executor import LocalToolRegistry, TrustedToolExecutor
from online_budget.executor_authorization import issue_executor_authorization
from online_budget.metering import (
    BudgetScope,
    compute_metering_policy_digest,
    sign_metering_policy,
)
from online_budget.tool_binding import arguments_digest

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "experiments" / "d11_3_c_coordinator" / "target" / "debug" / "e1_service.exe"
REG_DOMAIN = b"D11.3-C-REGISTRATION-v1"
SCOPE_DOMAIN = "d11-e1-cross-layer-scope-v1"

BUDGET_ID_N = 101
PERIOD_ID_N = 7
Q = 100
P_N = 1
COST = 20
PROVER_STATE = {"u_old": 0, "r_old": 11, "r_new": 13, "nf_secret": 17}
GLOBAL = "global-e14-test"
LEASE = "lease-e14-test"
COORDINATOR_ID = "coordinator-e14-test"
GATEWAY_ID = "gateway-e14-test"
EXECUTOR_ID = "executor-e14-test"
ISSUER_ID = "issuer-e14-test"
OPERATION_ID = "op-e14-1"
ARGS = {"invoice_id": "INV-E14-1"}


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _seed(n: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([n] * 32))


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    import base64

    return base64.b64encode(raw).decode()


@unittest.skipUnless(EXE.exists(), "e1_service binary not built")
class E1RuntimeIntegrationTests(unittest.TestCase):
    """Full D10 + D11 + real Halo2 integration. Fixed keys match the service config."""

    _shared: dict[str, object] = {}

    @classmethod
    def setUpClass(cls) -> None:
        # One real proof, computed once, supplies C_old for all registrations.
        issuer = _seed(7)
        with tempfile.TemporaryDirectory(prefix="e14-proof-") as d:
            cfg_path, _ = cls._write_config(Path(d), issuer)
            bridge = CrossLayerBridge([str(EXE), str(cfg_path)], timeout=90, startup_timeout=90)
            with bridge:
                witness = cls._witness()
                result = bridge.prove(witness)
                instance = result["instance"]
                cls._shared["instance"] = instance
                cls._shared["c_old"] = fp_from_hex(instance[4])
                cls._shared["proof_b64"] = result["proof_b64"]

    @staticmethod
    def _witness() -> dict[str, object]:
        return {
            "budget_id": fp_to_hex(BUDGET_ID_N),
            "period_id": fp_to_hex(PERIOD_ID_N),
            "quota": Q,
            "cost": COST,
            "u_old": PROVER_STATE["u_old"],
            "u_new": PROVER_STATE["u_old"] + COST,
            "slack": Q - PROVER_STATE["u_old"] - COST,
            "r_old": fp_to_hex(PROVER_STATE["r_old"]),
            "r_new": fp_to_hex(PROVER_STATE["r_new"]),
            "nf_secret": fp_to_hex(PROVER_STATE["nf_secret"]),
            "policy": fp_to_hex(P_N),
        }

    @staticmethod
    def _write_config(root: Path, issuer: Ed25519PrivateKey):
        db = str(root / "d11.sqlite")
        cfg = root / "config.json"
        cfg.write_text(
            json.dumps(
                {
                    "db_path": db,
                    "issuer_id": ISSUER_ID,
                    "issuer_public_key_b64": _pub_b64(issuer),
                    "executor_public_keys": {EXECUTOR_ID: _pub_b64(_seed(9))},
                    "coordinator_key_id": "d11-coordinator-v1",
                    "coordinator_signing_key_b64": b64encode(bytes([3] * 32)),
                    "coordinator_public_keys": {
                        "d11-coordinator-v1": _pub_b64(_seed(3))
                    },
                }
            ),
            encoding="utf-8",
        )
        return cfg, db

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="e14-runtime-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = int(time.time())
        self.issuer = _seed(7)
        self.gateway_key = _seed(5)
        self.coordinator_key = _seed(4)
        self.executor_key = _seed(9)
        self.registry = LocalToolRegistry()
        self.schema_hash = self.registry.schema_hash("invoice_review")
        self.context_digest = digest({"tenant": "e14", "purpose": "cross-layer"})

        # ---- D10 stack ----
        self.lease = issue_online_lease_grant(
            self.issuer,
            issuer_id=ISSUER_ID,
            grant_id="grant-e14",
            lease_id=LEASE,
            nonce="nonce-e14",
            global_budget_id=GLOBAL,
            quota_limit=5,
            issued_at=self.now - 30,
            expires_at=self.now + 900,
            coordinator_audience=COORDINATOR_ID,
            allowed_gateway_ids=(GATEWAY_ID,),
            subject_id="agent-e14",
            context_digest=self.context_digest,
            allowed_tools=(ToolPermission("invoice_review", self.schema_hash),),
        )
        self.execution = self._make_execution()
        self.coordinator = OnlineBudgetCoordinator(
            coordinator_id=COORDINATOR_ID,
            global_budget_id=GLOBAL,
            global_quota_limit=20,
            issuer_public_key=self.issuer.public_key(),
            coordinator_private_key=self.coordinator_key,
            coordinator_key_id="coord-e14-key",
            database_path=self.root / "coordinator.sqlite3",
            gateways={GATEWAY_ID: self.gateway_key.public_key()},
            clock=lambda: self.now,
        )
        self.server = CoordinatorHTTPServer(("127.0.0.1", 0), self.coordinator)
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self.thread.start()
        self.addCleanup(self._stop_server)
        client = OnlineBudgetClient(
            base_url=f"http://127.0.0.1:{self.server.server_address[1]}",
            gateway_id=GATEWAY_ID,
            gateway_private_key=self.gateway_key,
            coordinator_public_key=self.coordinator_key.public_key(),
            coordinator_id=COORDINATOR_ID,
            global_budget_id=GLOBAL,
        )
        self.adapter = OnlineBudgetExecutionAdapter(
            client=client,
            issuer_public_key=self.issuer.public_key(),
            global_budget_id=GLOBAL,
            global_quota_limit=20,
            coordinator_id=COORDINATOR_ID,
            receipt_cache_path=self.root / "gateway-cache.sqlite3",
        )
        self.adapter.bind_lease(self.execution, self.lease)
        self.executor = TrustedToolExecutor(
            executor_id=EXECUTOR_ID,
            issuer_public_key=self.issuer.public_key(),
            coordinator_public_key=self.coordinator_key.public_key(),
            executor_private_key=self.executor_key,
            database_path=self.root / "executor.sqlite3",
            registry=self.registry,
            clock=lambda: self.now,
            authorization_policy="authorization_required",
        )

        # ---- policy, scope, auth ----
        self.policy = sign_metering_policy(
            self.issuer,
            issuer_id=ISSUER_ID,
            policy_version="v-e14-1",
            P=fp_to_hex(P_N),
            entries=[
                {
                    "tool_name": "invoice_review",
                    "tool_schema_hash": self.schema_hash,
                    "cost": COST,
                }
            ],
        )
        self.budget_scope = BudgetScope(
            global_budget_id=GLOBAL,
            lease_id=LEASE,
            budget_id=fp_to_hex(BUDGET_ID_N),
            period_id=fp_to_hex(PERIOD_ID_N),
            Q=Q,
            P=fp_to_hex(P_N),
        )
        self.authorization = issue_executor_authorization(
            self.issuer,
            issuer_id=ISSUER_ID,
            authorization_id="auth-e14-1",
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            gateway_id=GATEWAY_ID,
            coordinator_id=COORDINATOR_ID,
            executor_id=EXECUTOR_ID,
            executor_public_key=self.executor_key.public_key(),
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            issued_at=self.now - 15,
            expires_at=self.now + 600,
            arguments=ARGS,
        )

        # ---- D11 service with a registered cross-layer scope ----
        self.cfg_path, self.db_path = self._write_config(self.root, self.issuer)
        self.bridge = CrossLayerBridge(
            [str(EXE), str(self.cfg_path)], timeout=90, startup_timeout=90
        )
        self.bridge.start()
        self.addCleanup(self.bridge.close)
        self._register_scope()

    def _stop_server(self) -> None:
        if getattr(self, "server", None) is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None

    def _make_execution(self) -> dict:
        unsigned = {
            "version": 2,
            "issuer_id": self.lease.issuer_id,
            "grant_id": self.lease.grant_id,
            "lease_id": self.lease.lease_id,
            "subject_id": self.lease.subject_id,
            "audience": GATEWAY_ID,
            "context_digest": self.lease.context_digest,
            "issued_at": self.lease.issued_at,
            "expires_at": self.lease.expires_at,
            "quota_limit": self.lease.quota_limit,
            "nonce": self.lease.nonce,
            "allowed_tools": [p.as_dict() for p in self.lease.allowed_tools],
            "parent_authorization_digest": hashlib.sha256(b"e14").hexdigest(),
            "parent_authorization_nonce": "parent-e14",
            "operation_id": OPERATION_ID,
        }
        return {**unsigned, "signature_b64": b64encode(self.issuer.sign(canonical_json_bytes(unsigned)))}

    def _register_scope(self) -> None:
        c_old = int(self._shared["c_old"])
        message = (
            REG_DOMAIN
            + BUDGET_ID_N.to_bytes(32, "little")
            + PERIOD_ID_N.to_bytes(32, "little")
            + Q.to_bytes(32, "little")
            + P_N.to_bytes(32, "little")
            + c_old.to_bytes(32, "little")
        )
        auth_bytes = message + self.issuer.sign(message)
        unsigned = {
            "version": 1,
            "issuer_id": ISSUER_ID,
            "global_budget_id": GLOBAL,
            "lease_id": LEASE,
            "online_lease_grant_digest": _sha(b"online-lease-grant-e14"),
            "budget_id": fp_to_hex(BUDGET_ID_N),
            "period_id": fp_to_hex(PERIOD_ID_N),
            "Q": Q,
            "P": fp_to_hex(P_N),
            "metering_policy_digest": compute_metering_policy_digest(self.policy),
            "registration_authorization_digest": _sha(auth_bytes),
        }
        signed = dict(unsigned)
        signed["signature_b64"] = b64encode(
            self.issuer.sign(
                canonical_json_bytes({"domain": SCOPE_DOMAIN, "payload": unsigned})
            )
        )
        import base64

        self.bridge.register_e1(signed, base64.b64encode(auth_bytes).decode())

    def _run(self, bridge=None, *, now=None, issued_at=None, expires_at=None):
        return run_tool_call_e1(
            bridge=bridge or self.bridge,
            gateway_adapter=self.adapter,
            executor=self.executor,
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            executor_id=EXECUTOR_ID,
            executor_authorization=self.authorization,
            metering_policy=self.policy,
            issuer_public_key=self.issuer.public_key(),
            budget_scope=self.budget_scope,
            prover_state=PROVER_STATE,
            tool_name="invoice_review",
            arguments=ARGS,
            now=self.now if now is None else now,
            issued_at=self.now - 10 if issued_at is None else issued_at,
            expires_at=self.now + 600 if expires_at is None else expires_at,
        )

    # ------------------------------------------------------------------ tests //
    def test_d01_digest_formula_and_domain_separation(self):
        d_e = compute_cross_layer_admission_digest(
            "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64
        )
        expected = canonical_json_bytes(
            {
                "domain": CROSS_LAYER_ADMISSION_DOMAIN,
                "binding_digest": "sha256:" + "1" * 64,
                "executor_authorization_digest": "sha256:" + "2" * 64,
                "metering_quote_digest": "sha256:" + "3" * 64,
            }
        )
        self.assertEqual(d_e, "sha256:" + hashlib.sha256(expected).hexdigest())
        # NOT the nested canonical_digest(domain, payload) form.
        nested = canonical_digest(
            CROSS_LAYER_ADMISSION_DOMAIN,
            {
                "binding_digest": "sha256:" + "1" * 64,
                "executor_authorization_digest": "sha256:" + "2" * 64,
                "metering_quote_digest": "sha256:" + "3" * 64,
            },
        )
        self.assertNotEqual(d_e, nested)
        with self.assertRaises(E1FailClosed):
            compute_cross_layer_admission_digest("bad", "sha256:" + "2" * 64, "sha256:" + "3" * 64)

    def test_d02_c_cannot_be_caller_supplied(self):
        import inspect

        params = inspect.signature(run_tool_call_e1).parameters
        self.assertNotIn("c", params)
        self.assertNotIn("cost", params)
        pending = self._run()
        self.assertEqual(pending.metering_attestation["attestation"]["c"], COST)

    def test_d03_end_to_end_two_budgets_committed_without_dispatch(self):
        dispatched = []

        def forbidden(**kwargs):
            dispatched.append(kwargs)
            raise AssertionError("E1.4 must not dispatch a tool")

        self.executor.execute = forbidden  # type: ignore[assignment]
        pending = self._run()
        self.assertEqual(dispatched, [])
        self.assertIsInstance(pending, PendingExecution)
        self.assertEqual(pending.d10_budget_receipt["payload"]["request_digest"], pending.cross_layer_digest)
        self.assertEqual(pending.d11_transition_receipt["operation_id"], OPERATION_ID)
        self.assertEqual(
            pending.d11_transition_receipt["binding_digest"],
            pending.metering_attestation["attestation"]["binding_digest"],
        )
        self.assertEqual(
            pending.d11_transition_receipt["metering_quote_digest"], pending.metering_quote_digest
        )
        self.assertEqual(pending.operation_id, OPERATION_ID)
        self.assertEqual(pending.tool_name, "invoice_review")

    def test_d04_tampered_policy_fails_closed_without_d10_charge(self):
        from online_budget.metering import parse_metering_policy

        tampered = parse_metering_policy(self.policy.as_dict() if hasattr(self.policy, "as_dict") else self.policy)
        # Corrupt the signature while keeping a parseable policy.
        bad = tampered.as_dict()
        bad["signature_b64"] = b64encode(bytes(64))
        with self.assertRaises(E1FailClosed):
            run_tool_call_e1(
                bridge=self.bridge,
                gateway_adapter=self.adapter,
                executor=self.executor,
                online_lease_grant=self.lease,
                execution_grant=self.execution,
                executor_id=EXECUTOR_ID,
                executor_authorization=self.authorization,
                metering_policy=parse_metering_policy(bad),
                issuer_public_key=self.issuer.public_key(),
                budget_scope=self.budget_scope,
                prover_state=PROVER_STATE,
                tool_name="invoice_review",
                arguments=ARGS,
                now=self.now,
                issued_at=self.now - 10,
                expires_at=self.now + 600,
            )
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_d05_recovery_when_d11_not_committed(self):
        """Transport fake drops the first submit; recovery re-proves and commits for real."""

        class DropFirstSubmit:
            def __init__(self, real):
                self.real = real
                self.dropped = False

            def health(self):
                return self.real.health()

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                return self.real.get_operation(**kwargs)

            def submit_transition_e1(self, payload):
                if not self.dropped:
                    self.dropped = True
                    raise BridgeTimeout("simulated lost submit response")  # transport only
                return self.real.submit_transition_e1(payload)

        pending = self._run(bridge=DropFirstSubmit(self.bridge))
        self.assertTrue(pending.recovered)
        self.assertEqual(pending.d11_transition_receipt["operation_id"], OPERATION_ID)
        # One D10 operation charge, one D11 state transition.
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d06_recovery_when_receipt_lost_after_commit(self):
        """Real submit commits, response is 'lost'; get_operation restores the exact receipt."""

        class CommitThenDropResponse:
            def __init__(self, real):
                self.real = real
                self.first = True

            def health(self):
                return self.real.health()

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                return self.real.get_operation(**kwargs)

            def submit_transition_e1(self, payload):
                receipt = self.real.submit_transition_e1(payload)
                if self.first:
                    self.first = False
                    raise BridgeTimeout("simulated lost response after real commit")
                return receipt

        pending = self._run(bridge=CommitThenDropResponse(self.bridge))
        self.assertTrue(pending.recovered)
        self.assertEqual(pending.d11_transition_receipt["operation_id"], OPERATION_ID)
        # Re-submit is absorbed by D11 idempotency; no second D10 charge.
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d06b_explicit_service_rejection_fails_closed_without_restart(self):
        """A well-formed ok:false refusal is definitive; no blind re-submit."""

        class ExplicitReject:
            def __init__(self, real):
                self.real = real
                self.restart_calls = 0

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.restart_calls += 1

            def submit_transition_e1(self, payload):
                raise ServiceError("PROOF_INVALID", "verifier rejected proof")

        fake = ExplicitReject(self.bridge)
        with self.assertRaises(E1FailClosed) as ctx:
            self._run(bridge=fake)
        self.assertIn("PROOF_INVALID", str(ctx.exception))
        self.assertEqual(fake.restart_calls, 0)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d08_store_error_after_commit_restores_receipt_via_get_operation(self):
        """§B.5: STORE_ERROR is not a refusal; query and restore the stored receipt."""

        class StoreErrorAfterCommit:
            def __init__(self, real):
                self.real = real
                self.lookups = 0

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                self.lookups += 1
                return self.real.get_operation(**kwargs)

            def submit_transition_e1(self, payload):
                self.real.submit_transition_e1(payload)  # really commits
                raise ServiceError("STORE_ERROR", "store acknowledged late")

        fake = StoreErrorAfterCommit(self.bridge)
        dispatched = []
        self.executor.execute = lambda **kw: dispatched.append(kw)
        pending = self._run(bridge=fake)
        self.assertEqual(dispatched, [])
        self.assertEqual(fake.lookups, 1)
        self.assertTrue(pending.recovered)
        self.assertEqual(pending.d11_transition_receipt["operation_id"], OPERATION_ID)
        self.assertEqual(
            pending.d11_transition_receipt["binding_digest"],
            pending.metering_attestation["attestation"]["binding_digest"],
        )
        # One D10 charge; the stored D11 receipt was restored, not re-submitted.
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d09_state_conflict_hit_restores_and_miss_fails_closed(self):
        """§B.5: STATE_CONFLICT queries by original id; hit restores, miss fails closed."""

        class StateConflictHit:
            def __init__(self, real):
                self.real = real
                self.lookups = 0

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                self.lookups += 1
                return self.real.get_operation(**kwargs)

            def submit_transition_e1(self, payload):
                self.real.submit_transition_e1(payload)  # commit, then report conflict
                raise ServiceError("STATE_CONFLICT", "state already advanced")

        hit = StateConflictHit(self.bridge)
        restored = self._run(bridge=hit)
        self.assertTrue(restored.recovered)
        self.assertEqual(hit.lookups, 1)
        self.assertEqual(restored.d11_transition_receipt["operation_id"], OPERATION_ID)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

        # Miss case: exercise the shared recovery helper directly. This is the
        # exact code both the first-submit and re-submit ServiceError paths use.
        from online_budget.e1_runtime import (
            _AdmissionArtifacts,
            _restore_from_idempotent_lookup,
        )
        from online_budget.metering import issue_metering_attestation, verify_metering_policy
        from online_budget.tool_binding import build_tool_call_binding, snapshot_arguments

        verified = verify_metering_policy(self.policy, self.issuer.public_key())
        binding = build_tool_call_binding(
            operation_id=OPERATION_ID,
            gateway_id=GATEWAY_ID,
            coordinator_id=COORDINATOR_ID,
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            arguments=snapshot_arguments(ARGS),
            executor_id=EXECUTOR_ID,
        )
        att = issue_metering_attestation(
            executor_private_key=self.executor_key,
            executor_id=EXECUTOR_ID,
            operation_id=OPERATION_ID,
            binding=binding,
            authorization=self.authorization,
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            budget_scope=self.budget_scope,
            verified_policy=verified,
            issued_at=self.now - 10,
            expires_at=self.now + 600,
        )
        artifacts = _AdmissionArtifacts(
            operation_id=OPERATION_ID,
            binding_digest=binding.binding_digest,
            metering_attestation=att,
            metering_quote_digest="sha256:" + "0" * 64,
            cross_layer_digest="sha256:" + "0" * 64,
            d10_budget_receipt={"payload": {"request_digest": "sha256:" + "0" * 64}},
            prove_witness={},
            instance=[],
        )

        class MissingLookup:
            def __init__(self):
                self.lookups = 0

            def get_operation(self, **kwargs):
                self.lookups += 1
                return None

        miss = MissingLookup()
        with self.assertRaises(E1FailClosed) as ctx:
            _restore_from_idempotent_lookup(
                bridge=miss, artifacts=artifacts, budget_scope=self.budget_scope, code="STATE_CONFLICT"
            )
        self.assertIn("no committed receipt", str(ctx.exception))
        self.assertEqual(miss.lookups, 1)

    def test_d10_ambiguous_error_uncertain_lookup_is_indeterminate(self):
        """If the idempotent query itself is uncertain, state is unknown -> no dispatch."""

        class UncertainLookup:
            def __init__(self, real):
                self.real = real

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                raise BridgeTimeout("lookup response lost")

            def submit_transition_e1(self, payload):
                raise ServiceError("STORE_ERROR", "maybe committed")

        with self.assertRaises(E1SubmitIndeterminate) as ctx:
            self._run(bridge=UncertainLookup(self.bridge))
        self.assertIn("STORE_ERROR", str(ctx.exception))
        self.assertEqual(ctx.exception.operation_id, OPERATION_ID)

    def test_d11_resubmit_store_error_also_resolves_by_lookup(self):
        """The _recover_submit re-submit path must also query on STORE_ERROR."""

        class UncertainThenStoreError:
            def __init__(self, real):
                self.real = real
                self.submit_n = 0
                self.lookups = 0

            def prove(self, witness):
                return self.real.prove(witness)

            def restart(self):
                self.real.restart()

            def get_operation(self, **kwargs):
                self.lookups += 1
                return self.real.get_operation(**kwargs)

            def submit_transition_e1(self, payload):
                self.submit_n += 1
                if self.submit_n == 1:
                    raise BridgeTimeout("lost first submit response")
                self.real.submit_transition_e1(payload)  # second submit commits
                raise ServiceError("STORE_ERROR", "commit ack lost")

        fake = UncertainThenStoreError(self.bridge)
        pending = self._run(bridge=fake)
        self.assertEqual(fake.submit_n, 2)
        self.assertEqual(fake.lookups, 2)  # one after restart, one for STORE_ERROR
        self.assertTrue(pending.recovered)
        self.assertEqual(pending.d11_transition_receipt["operation_id"], OPERATION_ID)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d07_expired_attestation_after_uncertain_submit_fails_closed(self):
        """Rule 5: expired original attestation must never be re-issued."""
        from online_budget.e1_runtime import _AdmissionArtifacts, _recover_submit
        from online_budget.metering import issue_metering_attestation, verify_metering_policy

        verified = verify_metering_policy(self.policy, self.issuer.public_key())
        from online_budget.tool_binding import build_tool_call_binding, snapshot_arguments

        binding = build_tool_call_binding(
            operation_id=OPERATION_ID,
            gateway_id=GATEWAY_ID,
            coordinator_id=COORDINATOR_ID,
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            arguments=snapshot_arguments(ARGS),
            executor_id=EXECUTOR_ID,
        )
        att = issue_metering_attestation(
            executor_private_key=self.executor_key,
            executor_id=EXECUTOR_ID,
            operation_id=OPERATION_ID,
            binding=binding,
            authorization=self.authorization,
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            budget_scope=self.budget_scope,
            verified_policy=verified,
            issued_at=self.now - 1000,
            expires_at=self.now + 1,
        )

        class AlwaysMissing:
            def restart(self):
                pass

            def get_operation(self, **kwargs):
                return None

            def prove(self, witness):
                self.excuse = "must not re-prove for expired attestation"
                return {}

        fake = AlwaysMissing()
        artifacts = _AdmissionArtifacts(
            operation_id=OPERATION_ID,
            binding_digest=binding.binding_digest,
            metering_attestation=att,
            metering_quote_digest="sha256:" + "0" * 64,
            cross_layer_digest="sha256:" + "0" * 64,
            d10_budget_receipt={"payload": {"request_digest": "sha256:" + "0" * 64}},
            prove_witness={},
            instance=[],
        )
        with self.assertRaises(E1FailClosed) as ctx:
            _recover_submit(
                bridge=fake,
                artifacts=artifacts,
                budget_scope=self.budget_scope,
                now=self.now + 2,
            )
        self.assertIn("expired", str(ctx.exception))
        self.assertFalse(hasattr(fake, "excuse"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
