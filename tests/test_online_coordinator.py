from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget import (
    CoordinatorHTTPServer, CoordinatorUnavailable, GlobalBudgetExceeded,
    GatewayNotAuthorized, LeaseInactive, OnlineBudgetClient,
    OnlineBudgetCoordinator, OnlineLeaseGrant, OperationBindingConflict,
    ToolPermission, issue_online_lease_grant, issue_revocation, verify_budget_receipt,
    OnlineBudgetExecutionAdapter, GrantRejected, verify_online_receipt_chain, LeaseInactive,
)
from online_budget.auth import sign_gateway_envelope
from online_budget.canonical import b64encode, canonical_json_bytes, digest, private_key_bytes, public_key_bytes
from online_budget.errors import AuthenticationError


class OnlineCoordinatorTests(unittest.TestCase):
    NOW = 1_800_000_000
    COORDINATOR_ID = "coordinator-test-1"
    BUDGET_ID = "online-epoch-test"
    TOOL_NAME = "invoice_review"
    SCHEMA_HASH = digest({"type": "object", "required": ["invoice_id"]})
    CONTEXT_DIGEST = digest({"tenant": "tenant-1", "purpose": "review"})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="d91-online-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.issuer_private = Ed25519PrivateKey.generate()
        self.coordinator_private = Ed25519PrivateKey.generate()
        self.gateway_a_private = Ed25519PrivateKey.generate()
        self.gateway_b_private = Ed25519PrivateKey.generate()
        self.now = [self.NOW]
        self.coordinator = self.make_coordinator(global_limit=10)
        self.server = CoordinatorHTTPServer(("127.0.0.1", 0), self.coordinator)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop_server(self):
        if getattr(self, "server", None) is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None

    def make_coordinator(self, *, global_limit: int):
        db_name = "coordinator.sqlite3"
        if global_limit == 1:
            db_name = "coordinator-final-unit.sqlite3"
        return OnlineBudgetCoordinator(
            coordinator_id=self.COORDINATOR_ID,
            global_budget_id=self.BUDGET_ID,
            global_quota_limit=global_limit,
            issuer_public_key=self.issuer_private.public_key(),
            coordinator_private_key=self.coordinator_private,
            coordinator_key_id="coord-key-1",
            database_path=self.root / db_name,
            gateways={
                "gateway-A": self.gateway_a_private.public_key(),
                "gateway-B": self.gateway_b_private.public_key(),
            },
            clock=lambda: self.now[0],
        )

    def client(self, gateway_id="gateway-A"):
        key = self.gateway_a_private if gateway_id == "gateway-A" else self.gateway_b_private
        return OnlineBudgetClient(
            base_url=self.base_url, gateway_id=gateway_id,
            gateway_private_key=key,
            coordinator_public_key=self.coordinator_private.public_key(),
            coordinator_id=self.COORDINATOR_ID,
        )

    def make_lease(self, lease_id: str, *, quota: int = 4, allowed=("gateway-A", "gateway-B"), expires_delta=3600):
        return issue_online_lease_grant(
            self.issuer_private,
            issuer_id="issuer-test", grant_id=f"grant-{lease_id}", lease_id=lease_id,
            nonce=f"nonce-{lease_id}", global_budget_id=self.BUDGET_ID,
            quota_limit=quota, issued_at=self.NOW - 10, expires_at=self.NOW + expires_delta,
            coordinator_audience=self.COORDINATOR_ID, allowed_gateway_ids=allowed,
            subject_id=f"agent-{lease_id}", context_digest=self.CONTEXT_DIGEST,
            allowed_tools=(ToolPermission(self.TOOL_NAME, self.SCHEMA_HASH),),
        )

    def make_execution(self, lease: OnlineLeaseGrant, operation_id: str, gateway_id="gateway-A"):
        unsigned = {
            "version": 2,
            "issuer_id": lease.issuer_id,
            "grant_id": lease.grant_id,
            "lease_id": lease.lease_id,
            "subject_id": lease.subject_id,
            "audience": gateway_id,
            "context_digest": lease.context_digest,
            "issued_at": lease.issued_at,
            "expires_at": lease.expires_at,
            "quota_limit": lease.quota_limit,
            "nonce": lease.nonce,
            "allowed_tools": [x.as_dict() for x in sorted(lease.allowed_tools, key=lambda p: p.tool_name)],
            "parent_authorization_digest": hashlib.sha256(f"parent:{operation_id}".encode()).hexdigest(),
            "parent_authorization_nonce": f"parent-nonce-{operation_id}",
            "operation_id": operation_id,
        }
        signature = self.issuer_private.sign(canonical_json_bytes(unsigned))
        return {**unsigned, "signature_b64": b64encode(signature)}

    def register(self, lease: OnlineLeaseGrant, gateway_id="gateway-A"):
        return self.client(gateway_id).register_lease(lease)

    def consume(self, lease, operation_id, *, gateway_id="gateway-A", request_digest=None):
        execution = self.make_execution(lease, operation_id, gateway_id)
        return self.client(gateway_id).consume(
            lease, execution, operation_id=operation_id,
            request_digest=request_digest or digest({"operation_id": operation_id, "args": {"invoice_id": operation_id}}),
        )

    def test_overlapping_lease_caps_are_allowed_without_reservations(self):
        lease_a = self.make_lease("lease-A", quota=8)
        lease_b = self.make_lease("lease-B", quota=8)
        self.register(lease_a)
        self.register(lease_b)
        info = self.coordinator.inspect()
        self.assertEqual(info["global_quota_limit"], 10)
        self.assertEqual(sum(x["quota_limit"] for x in info["leases"]), 16)
        self.assertEqual(info["global_used_count"], 0)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_two_gateways_racing_for_final_global_unit_only_one_commits(self):
        self.coordinator = self.make_coordinator(global_limit=1)
        self.server.coordinator = self.coordinator
        lease_a = self.make_lease("lease-A", quota=5)
        lease_b = self.make_lease("lease-B", quota=5)
        self.register(lease_a, "gateway-A")
        self.register(lease_b, "gateway-B")
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.consume, lease_a, "final-A", gateway_id="gateway-A")
            b = pool.submit(self.consume, lease_b, "final-B", gateway_id="gateway-B")
            results = []
            for f in (a, b):
                try:
                    results.append(("ok", f.result(timeout=10)))
                except GlobalBudgetExceeded:
                    results.append(("exhausted", None))
        self.assertEqual(sorted(x[0] for x in results), ["exhausted", "ok"])
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 1)
        self.assertEqual(state["receipt_count"], 1)

    def test_independent_gateway_processes_share_one_authoritative_final_unit(self):
        self.coordinator = self.make_coordinator(global_limit=1)
        self.server.coordinator = self.coordinator
        grants = [
            (self.make_lease("lease-process-A", quota=3), "gateway-A", self.gateway_a_private),
            (self.make_lease("lease-process-B", quota=3), "gateway-B", self.gateway_b_private),
        ]
        configs = []
        worker = Path(__file__).with_name("process_consume_worker.py")
        gate = self.root / "start-workers"
        for index, (lease, gateway_id, private_key) in enumerate(grants):
            self.register(lease, gateway_id)
            operation_id = f"process-op-{index}"
            cfg = {
                "base_url": self.base_url,
                "coordinator_id": self.COORDINATOR_ID,
                "gateway_id": gateway_id,
                "gateway_private_key_b64": b64encode(private_key_bytes(private_key)),
                "coordinator_public_key_b64": b64encode(public_key_bytes(self.coordinator_private.public_key())),
                "online_lease_grant": lease.as_dict(),
                "execution_grant": self.make_execution(lease, operation_id, gateway_id),
                "operation_id": operation_id,
                "request_digest": digest({"process": operation_id}),
            }
            cfg_path = self.root / f"worker-{index}.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            configs.append(cfg_path)
        env = dict(__import__("os").environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        workers = [
            subprocess.Popen(
                [sys.executable, str(worker), str(cfg), str(gate)],
                cwd=str(Path(__file__).resolve().parents[1]),
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for cfg in configs
        ]
        gate.write_text("go", encoding="utf-8")
        outputs = []
        for proc in workers:
            stdout, stderr = proc.communicate(timeout=20)
            self.assertEqual(proc.returncode, 0, msg=f"worker failed: {stdout} {stderr}")
            outputs.append(json.loads(stdout.strip().splitlines()[-1]))
        self.assertEqual(sorted(item["status"] for item in outputs), ["committed", "global_exhausted"])
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 1)
        self.assertEqual(state["operation_count"], 1)

    def test_exact_duplicate_http_requests_return_same_signed_receipt(self):
        lease = self.make_lease("lease-A", quota=4)
        self.register(lease)
        execution = self.make_execution(lease, "same-op", "gateway-A")
        req_digest = digest({"same": "payload"})
        client = self.client()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(client.consume, lease, execution, operation_id="same-op", request_digest=req_digest) for _ in range(2)]
            receipts = [f.result(timeout=10) for f in futures]
        self.assertEqual(receipts[0].as_dict(), receipts[1].as_dict())
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 1)
        self.assertEqual(state["operation_count"], 1)

    def test_operation_id_cannot_be_rebound_across_gateway_or_lease(self):
        lease_a = self.make_lease("lease-A")
        lease_b = self.make_lease("lease-B")
        self.register(lease_a, "gateway-A")
        self.register(lease_b, "gateway-B")
        self.consume(lease_a, "collision-op", gateway_id="gateway-A")
        with self.assertRaises(OperationBindingConflict):
            self.consume(lease_b, "collision-op", gateway_id="gateway-B")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_revoke_commit_order_allows_exact_replay_but_blocks_new_operation(self):
        lease = self.make_lease("lease-A")
        self.register(lease)
        first = self.consume(lease, "before-revoke")
        revocation = issue_revocation(
            self.issuer_private, issuer_id=lease.issuer_id, global_budget_id=self.BUDGET_ID,
            revocation_id="revocation-1", lease_id=lease.lease_id,
            grant_digest=lease.grant_digest, revoked_at=self.now[0],
        )
        self.client().revoke_lease(revocation)
        replay = self.consume(lease, "before-revoke")
        self.assertEqual(first.as_dict(), replay.as_dict())
        with self.assertRaises(LeaseInactive):
            self.consume(lease, "after-revoke")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_new_consume_is_rejected_after_expiry_but_committed_replay_is_stable(self):
        lease = self.make_lease("lease-A", expires_delta=20)
        self.register(lease)
        first = self.consume(lease, "before-expiry")
        self.now[0] += 21
        replay = self.consume(lease, "before-expiry")
        self.assertEqual(first.as_dict(), replay.as_dict())
        with self.assertRaises(LeaseInactive):
            self.consume(lease, "after-expiry")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_gateway_not_listed_in_signed_lease_is_rejected(self):
        lease = self.make_lease("lease-A", allowed=("gateway-A",))
        self.register(lease, "gateway-A")
        with self.assertRaises(GatewayNotAuthorized):
            self.consume(lease, "unauthorized-op", gateway_id="gateway-B")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_tampered_gateway_signature_is_rejected_before_mutation(self):
        from online_budget.auth import sign_gateway_envelope
        from online_budget.canonical import canonical_json_bytes
        from urllib.request import Request, urlopen
        lease = self.make_lease("lease-A")
        envelope = sign_gateway_envelope(
            "gateway-A", "POST", "/v1/leases/register", {"grant": lease.as_dict()}, self.gateway_a_private
        )
        envelope["path"] = "/v1/budget/consume"
        data = canonical_json_bytes(envelope)
        req = Request(self.base_url + "/v1/budget/consume", data=data,
                      headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 401)
        self.assertEqual(self.coordinator.inspect()["global_used_count"], 0)

    def test_receipt_signature_tampering_is_detected(self):
        lease = self.make_lease("lease-A")
        self.register(lease)
        receipt = self.consume(lease, "tamper-op")
        tampered = {"payload": dict(receipt.payload), "signature_b64": receipt.signature_b64}
        tampered["payload"]["global_sequence"] += 1
        self.assertFalse(verify_budget_receipt(tampered, self.coordinator_private.public_key()))

    def test_coordinator_restart_preserves_operation_and_exact_receipt(self):
        lease = self.make_lease("lease-A")
        self.register(lease)
        first = self.consume(lease, "restart-op")
        self.stop_server()
        self.coordinator = self.make_coordinator(global_limit=10)
        self.server = CoordinatorHTTPServer(("127.0.0.1", 0), self.coordinator)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        replay = self.consume(lease, "restart-op")
        self.assertEqual(first.as_dict(), replay.as_dict())
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_service_unavailable_is_unknown_outcome_not_a_local_fallback(self):
        client = OnlineBudgetClient(
            base_url="http://127.0.0.1:1", gateway_id="gateway-A",
            gateway_private_key=self.gateway_a_private,
            coordinator_public_key=self.coordinator_private.public_key(),
            coordinator_id=self.COORDINATOR_ID, timeout_seconds=0.2,
        )
        with self.assertRaises(CoordinatorUnavailable):
            client.lookup_operation("no-op")

    def test_online_adapter_exposes_verified_global_budget_receipt(self):
        lease = self.make_lease("lease-A")
        execution = self.make_execution(lease, "adapter-op", "gateway-A")
        adapter = OnlineBudgetExecutionAdapter(
            client=self.client("gateway-A"), issuer_public_key=self.issuer_private.public_key(),
            global_budget_id=self.BUDGET_ID, global_quota_limit=10,
            coordinator_id=self.COORDINATOR_ID,
            receipt_cache_path=self.root / "gateway-A-cache.sqlite3",
        )
        # This calls the authenticated register API and pins the exact Execution Grant digest.
        binding = adapter.bind_lease(execution, lease)
        self.assertEqual(binding["global_budget_id"], self.BUDGET_ID)
        result = adapter.consume_for_grant(
            execution, operation_id="adapter-op", request_digest=digest({"adapter": "request"}),
        )
        self.assertEqual(result.global_sequence, 1)
        self.assertEqual(result.counter_value, 1)
        self.assertTrue(result.coordinator_receipt_digest.startswith("sha256:"))
        self.assertTrue(verify_budget_receipt(result.coordinator_receipt, self.coordinator_private.public_key()))
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)
        cached = adapter.coordinator_receipt_for_operation("adapter-op")
        self.assertEqual(cached, result.coordinator_receipt)
        gateway_payload = {
            "version": 1, "status": "SUCCEEDED", "gateway_id": "gateway-A",
            "global_budget_id": self.BUDGET_ID, "lease_id": lease.lease_id,
            "global_lease_grant_digest": lease.grant_digest,
            "operation_id": "adapter-op", "request_digest": digest({"adapter": "request"}),
            "global_sequence": 1, "budget_counter_value": 1, "lease_used_count": 1,
        }
        from online_budget.canonical import b64encode, canonical_json_bytes
        gateway_receipt = {
            "payload": gateway_payload,
            "signature_b64": b64encode(self.gateway_a_private.sign(canonical_json_bytes(gateway_payload))),
        }
        link = adapter.build_receipt_chain("adapter-op", gateway_receipt)
        self.assertTrue(verify_online_receipt_chain(
            link, gateway_receipt, result.coordinator_receipt,
            self.gateway_a_private.public_key(), self.coordinator_private.public_key(),
        ))
        # A committed receipt may be replayed locally during a Coordinator outage.
        execution_new = self.make_execution(lease, "offline-new-op", "gateway-A")
        adapter.bind_lease(execution_new, lease)
        self.stop_server()
        restarted_adapter = OnlineBudgetExecutionAdapter(
            client=self.client("gateway-A"), issuer_public_key=self.issuer_private.public_key(),
            global_budget_id=self.BUDGET_ID, global_quota_limit=10,
            coordinator_id=self.COORDINATOR_ID,
            receipt_cache_path=self.root / "gateway-A-cache.sqlite3",
        )
        replay = restarted_adapter.consume_for_grant(
            execution, operation_id="adapter-op", request_digest=digest({"adapter": "request"}),
        )
        self.assertEqual(replay.coordinator_receipt, result.coordinator_receipt)
        with self.assertRaises(CoordinatorUnavailable):
            restarted_adapter.consume_for_grant(
                execution_new, operation_id="offline-new-op", request_digest=digest({"new": "request"}),
            )

    def test_execution_grant_expiry_blocks_new_operation(self):
        lease = self.make_lease("lease-A")
        self.register(lease)
        execution = self.make_execution(lease, "expired-exec")
        self.now[0] = self.NOW + 3601
        with self.assertRaises(LeaseInactive):
            self.client().consume(lease, execution, operation_id="expired-exec", request_digest=digest({"x": 1}))
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_execution_grant_mismatch_is_rejected(self):
        lease = self.make_lease("lease-A")
        self.register(lease)
        execution = self.make_execution(lease, "wrong-op")
        execution["operation_id"] = "changed-op"
        # Signature is now invalid; no request may reach budget mutation.
        with self.assertRaises(Exception):
            self.client().consume(lease, execution, operation_id="changed-op", request_digest=digest({"x": 1}))
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
