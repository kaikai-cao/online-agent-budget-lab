from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from http.server import ThreadingHTTPServer
import socket
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
    ConfigurationMismatch, CoordinatorHTTPServer, CoordinatorIndeterminate,
    CoordinatorUnavailable, GlobalBudgetExceeded, LeaseCapExceeded, LeaseInactive,
    OnlineBudgetClient, OnlineBudgetCoordinator, OnlineLeaseGrant,
    ToolPermission, issue_online_lease_grant, issue_revocation,
)
from online_budget.canonical import (
    b64encode, canonical_json_bytes, digest, private_key_bytes, public_key_bytes,
)
from online_budget.http_api import CoordinatorRequestHandler, MAX_BODY_BYTES


class FaultHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, coordinator):
        self.coordinator = coordinator
        self.drop_operation_id = None
        self.drop_done = False
        self.drop_event = threading.Event()
        self.delay_operation_id = None
        self.delay_entered = threading.Event()
        self.delay_release = threading.Event()
        self.tamper_operation_id = None
        self.fault_lock = threading.Lock()
        super().__init__(address, FaultRequestHandler)


class FaultRequestHandler(CoordinatorRequestHandler):
    server: FaultHTTPServer

    def _send_json(self, status, payload):
        result = payload.get("result") if isinstance(payload, dict) else None
        receipt_payload = result.get("payload") if isinstance(result, dict) else None
        operation_id = receipt_payload.get("operation_id") if isinstance(receipt_payload, dict) else None

        if status == 200 and operation_id == self.server.drop_operation_id:
            with self.server.fault_lock:
                should_drop = not self.server.drop_done
                if should_drop:
                    self.server.drop_done = True
            if should_drop:
                self.server.drop_event.set()
                self.close_connection = True
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.connection.close()
                except OSError:
                    pass
                return

        if status == 200 and operation_id == self.server.delay_operation_id:
            self.server.delay_entered.set()
            if not self.server.delay_release.wait(timeout=15):
                self.close_connection = True
                return

        if status == 200 and operation_id == self.server.tamper_operation_id:
            # Corrupt only the wire response after the Coordinator has committed and signed it.
            payload = dict(payload)
            result = dict(result)
            receipt_payload = dict(receipt_payload)
            receipt_payload["global_sequence"] = int(receipt_payload["global_sequence"]) + 1
            result["payload"] = receipt_payload
            payload["result"] = result

        super()._send_json(status, payload)


class OnlineCoordinatorAdversarialTests(unittest.TestCase):
    NOW = 1_800_000_000
    COORDINATOR_ID = "coordinator-d92-test"
    BUDGET_ID = "online-d92-epoch"
    TOOL_NAME = "invoice_review"
    SCHEMA_HASH = digest({"type": "object", "required": ["invoice_id"]})
    CONTEXT_DIGEST = digest({"tenant": "tenant-d92", "purpose": "recovery-validation"})

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="d92-online-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.issuer_private = Ed25519PrivateKey.generate()
        self.coordinator_private = Ed25519PrivateKey.generate()
        self.gateway_a_private = Ed25519PrivateKey.generate()
        self.gateway_b_private = Ed25519PrivateKey.generate()
        self.now = [self.NOW]
        self.coordinator = self.make_coordinator()
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

    def make_coordinator(self):
        return OnlineBudgetCoordinator(
            coordinator_id=self.COORDINATOR_ID,
            global_budget_id=self.BUDGET_ID,
            global_quota_limit=10,
            issuer_public_key=self.issuer_private.public_key(),
            coordinator_private_key=self.coordinator_private,
            coordinator_key_id="coordinator-key-d92",
            database_path=self.root / "coordinator.sqlite3",
            gateways={
                "gateway-A": self.gateway_a_private.public_key(),
                "gateway-B": self.gateway_b_private.public_key(),
            },
            clock=lambda: self.now[0],
        )

    def client(self, gateway_id="gateway-A", *, base_url=None, timeout=5.0):
        private_key = self.gateway_a_private if gateway_id == "gateway-A" else self.gateway_b_private
        return OnlineBudgetClient(
            base_url=base_url or self.base_url,
            gateway_id=gateway_id,
            gateway_private_key=private_key,
            coordinator_public_key=self.coordinator_private.public_key(),
            coordinator_id=self.COORDINATOR_ID,
            timeout_seconds=timeout,
        )

    def make_lease(self, lease_id, *, quota=4, allowed=("gateway-A", "gateway-B"), expires_delta=3600):
        return issue_online_lease_grant(
            self.issuer_private,
            issuer_id="issuer-d92", grant_id=f"grant-{lease_id}", lease_id=lease_id,
            nonce=f"nonce-{lease_id}", global_budget_id=self.BUDGET_ID,
            quota_limit=quota, issued_at=self.NOW - 10, expires_at=self.NOW + expires_delta,
            coordinator_audience=self.COORDINATOR_ID, allowed_gateway_ids=allowed,
            subject_id=f"subject-{lease_id}", context_digest=self.CONTEXT_DIGEST,
            allowed_tools=(ToolPermission(self.TOOL_NAME, self.SCHEMA_HASH),),
        )

    def make_execution(self, lease, operation_id, gateway_id="gateway-A"):
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

    def register(self, lease, gateway_id="gateway-A"):
        return self.client(gateway_id).register_lease(lease)

    def consume(self, lease, operation_id, *, gateway_id="gateway-A", request_digest=None, client=None):
        execution = self.make_execution(lease, operation_id, gateway_id)
        selected = client or self.client(gateway_id)
        return selected.consume(
            lease, execution, operation_id=operation_id,
            request_digest=request_digest or digest({"operation_id": operation_id, "args": {"invoice_id": operation_id}}),
        )

    def start_fault_server(self):
        server = FaultHTTPServer(("127.0.0.1", 0), self.coordinator)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(lambda: self._stop_fault_server(server, thread))
        return server, f"http://127.0.0.1:{server.server_address[1]}"

    @staticmethod
    def _stop_fault_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    def _process_environment(self):
        env = dict(__import__("os").environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        return env

    def test_per_lease_cap_is_enforced_without_extra_global_charge(self):
        lease = self.make_lease("lease-cap", quota=1)
        self.register(lease)
        first = self.consume(lease, "lease-cap-first")
        self.assertEqual(first.payload["lease_used_count"], 1)
        with self.assertRaises(LeaseCapExceeded):
            self.consume(lease, "lease-cap-second")
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 1)
        self.assertEqual(state["operation_count"], 1)

    def test_same_operation_id_from_two_os_processes_returns_one_exact_receipt(self):
        lease = self.make_lease("lease-process-duplicate")
        self.register(lease)
        operation_id = "same-operation-two-processes"
        config = {
            "base_url": self.base_url,
            "coordinator_id": self.COORDINATOR_ID,
            "gateway_id": "gateway-A",
            "gateway_private_key_b64": b64encode(private_key_bytes(self.gateway_a_private)),
            "coordinator_public_key_b64": b64encode(public_key_bytes(self.coordinator_private.public_key())),
            "online_lease_grant": lease.as_dict(),
            "execution_grant": self.make_execution(lease, operation_id),
            "operation_id": operation_id,
            "request_digest": digest({"shared-process-request": operation_id}),
        }
        config_path = self.root / "duplicate-worker.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        gate = self.root / "release-workers"
        worker = Path(__file__).with_name("process_consume_worker.py")
        procs = [
            subprocess.Popen(
                [sys.executable, str(worker), str(config_path), str(gate)],
                cwd=str(Path(__file__).resolve().parents[1]), env=self._process_environment(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for _ in range(2)
        ]
        gate.write_text("go", encoding="utf-8")
        outputs = []
        for proc in procs:
            stdout, stderr = proc.communicate(timeout=20)
            self.assertEqual(proc.returncode, 0, msg=f"worker failed: {stdout} {stderr}")
            outputs.append(json.loads(stdout.strip().splitlines()[-1]))
        self.assertEqual([item["status"] for item in outputs], ["committed", "committed"])
        self.assertEqual(outputs[0]["receipt"], outputs[1]["receipt"])
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 1)
        self.assertEqual(state["operation_count"], 1)
        self.assertEqual(state["receipt_count"], 1)

    def test_lost_http_response_after_commit_retries_exact_stored_receipt(self):
        lease = self.make_lease("lease-lost-response")
        self.register(lease)
        operation_id = "committed-but-response-dropped"
        execution = self.make_execution(lease, operation_id)
        request_digest = digest({"lost-response": True})
        server, url = self.start_fault_server()
        server.drop_operation_id = operation_id
        fault_client = self.client(base_url=url, timeout=1.0)
        with self.assertRaises(CoordinatorUnavailable):
            fault_client.consume(lease, execution, operation_id=operation_id, request_digest=request_digest)
        self.assertTrue(server.drop_event.wait(2), "fault server did not drop the post-commit response")
        before_retry = self.coordinator.assert_invariants()
        self.assertEqual(before_retry["global_used_count"], 1)
        retried = fault_client.consume(lease, execution, operation_id=operation_id, request_digest=request_digest)
        self.assertEqual(retried.payload["global_sequence"], 1)
        self.assertEqual(retried.payload["operation_id"], operation_id)
        after_retry = self.coordinator.assert_invariants()
        self.assertEqual(after_retry["global_used_count"], 1)
        self.assertEqual(after_retry["operation_count"], 1)

    def test_delayed_first_response_can_arrive_after_later_sequence(self):
        lease = self.make_lease("lease-reordered-response", quota=4)
        self.register(lease)
        server, url = self.start_fault_server()
        server.delay_operation_id = "slow-response-op"
        fault_client = self.client(base_url=url)
        pool = ThreadPoolExecutor(max_workers=2)
        slow_future = pool.submit(self.consume, lease, "slow-response-op", client=fault_client)
        try:
            self.assertTrue(server.delay_entered.wait(5), "first response was not delayed")
            fast_receipt = self.consume(lease, "fast-response-op", client=fault_client)
            self.assertEqual(fast_receipt.payload["global_sequence"], 2)
            server.delay_release.set()
            slow_receipt = slow_future.result(timeout=10)
        finally:
            server.delay_release.set()
            pool.shutdown(wait=True, cancel_futures=True)
        self.assertEqual(slow_receipt.payload["global_sequence"], 1)
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 2)
        self.assertEqual(state["operation_count"], 2)
        self.assertEqual(state["receipt_count"], 2)

    def test_coordinator_process_termination_inside_transaction_rolls_back_then_retry_commits_once(self):
        lease = self.make_lease("lease-process-crash")
        self.register(lease)
        operation_id = "kill-during-uncommitted-write"
        execution = self.make_execution(lease, operation_id)
        marker = self.root / "transaction-paused.marker"
        release = self.root / "transaction-release.marker"
        config = {
            "coordinator_id": self.COORDINATOR_ID,
            "global_budget_id": self.BUDGET_ID,
            "global_quota_limit": 10,
            "coordinator_key_id": "coordinator-key-d92",
            "database_path": str(self.root / "coordinator.sqlite3"),
            "issuer_public_key_b64": b64encode(public_key_bytes(self.issuer_private.public_key())),
            "coordinator_private_key_b64": b64encode(private_key_bytes(self.coordinator_private)),
            "gateways": {
                "gateway-A": b64encode(public_key_bytes(self.gateway_a_private.public_key())),
                "gateway-B": b64encode(public_key_bytes(self.gateway_b_private.public_key())),
            },
            "now": self.NOW,
            "marker_path": str(marker),
            "release_path": str(release),
            "gateway_id": "gateway-A",
            "online_lease_grant": lease.as_dict(),
            "execution_grant": execution,
            "operation_id": operation_id,
            "request_digest": digest({"crash-test": operation_id}),
        }
        config_path = self.root / "crash-worker.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        worker = Path(__file__).with_name("process_crash_consume_worker.py")
        proc = subprocess.Popen(
            [sys.executable, str(worker), str(config_path)],
            cwd=str(Path(__file__).resolve().parents[1]), env=self._process_environment(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        deadline = time.monotonic() + 20
        while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if not marker.exists():
            stdout, stderr = proc.communicate(timeout=5)
            self.fail(f"worker did not reach the uncommitted receipt insert; rc={proc.returncode}; stdout={stdout}; stderr={stderr}")
        proc.terminate()
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=5)

        # Reopen the same database as a fresh Coordinator process would.
        self.coordinator = self.make_coordinator()
        self.server.coordinator = self.coordinator
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 0)
        self.assertEqual(state["operation_count"], 0)
        self.assertEqual(state["receipt_count"], 0)
        self.assertEqual(self.coordinator.inspect()["next_global_sequence"], 1)
        self.assertEqual(self.coordinator.get_lease(lease.lease_id)["used_count"], 0)

        retried = self.consume(lease, operation_id, request_digest=digest({"crash-test": operation_id}))
        self.assertEqual(retried.payload["global_sequence"], 1)
        final = self.coordinator.assert_invariants()
        self.assertEqual(final["global_used_count"], 1)
        self.assertEqual(final["operation_count"], 1)
        self.assertEqual(final["receipt_count"], 1)

    def test_consume_and_revoke_race_respects_database_commit_order(self):
        lease = self.make_lease("lease-revoke-race")
        self.register(lease)
        operation_id = "consume-revoke-race-op"
        execution = self.make_execution(lease, operation_id)
        request_digest = digest({"race": operation_id})
        revocation = issue_revocation(
            self.issuer_private, issuer_id=lease.issuer_id, global_budget_id=self.BUDGET_ID,
            revocation_id="revocation-race-d92", lease_id=lease.lease_id,
            grant_digest=lease.grant_digest, revoked_at=self.now[0],
        )
        barrier = threading.Barrier(2)

        def consume_call():
            barrier.wait(timeout=5)
            try:
                return ("committed", self.client().consume(
                    lease, execution, operation_id=operation_id, request_digest=request_digest,
                ))
            except LeaseInactive:
                return ("revoked_first", None)

        def revoke_call():
            barrier.wait(timeout=5)
            self.client().revoke_lease(revocation)
            return "revocation_committed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            consume_future = pool.submit(consume_call)
            revoke_future = pool.submit(revoke_call)
            outcome, receipt = consume_future.result(timeout=15)
            self.assertEqual(revoke_future.result(timeout=15), "revocation_committed")

        self.assertEqual(self.coordinator.get_lease(lease.lease_id)["state"], "REVOKED")
        state = self.coordinator.assert_invariants()
        expected_usage = 1 if outcome == "committed" else 0
        self.assertEqual(state["global_used_count"], expected_usage)
        self.assertEqual(state["operation_count"], expected_usage)
        if outcome == "committed":
            replay = self.client().consume(lease, execution, operation_id=operation_id, request_digest=request_digest)
            self.assertEqual(replay.as_dict(), receipt.as_dict())
        else:
            self.assertIsNone(self.coordinator.lookup_operation("gateway-A", operation_id))
        with self.assertRaises(LeaseInactive):
            self.consume(lease, "new-operation-after-revoke")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], expected_usage)

    def test_expiry_is_rechecked_at_admission_boundary_inside_transaction(self):
        lease = self.make_lease("lease-expiry-race", expires_delta=20)
        self.register(lease)
        operation_id = "expires-while-admission-paused"
        execution = self.make_execution(lease, operation_id)
        entered = threading.Event()
        release = threading.Event()
        observed_time = [lease.expires_at - 1]

        def controlled_clock():
            entered.set()
            if not release.wait(timeout=10):
                raise TimeoutError("test clock gate timed out")
            return observed_time[0]

        self.coordinator.clock = controlled_clock
        pool = ThreadPoolExecutor(max_workers=1)
        future = pool.submit(self.client().consume, lease, execution, operation_id=operation_id,
                             request_digest=digest({"expiry-race": operation_id}))
        try:
            self.assertTrue(entered.wait(5), "consume did not reach the in-transaction clock check")
            observed_time[0] = lease.expires_at
            release.set()
            with self.assertRaises(LeaseInactive):
                future.result(timeout=10)
        finally:
            release.set()
            pool.shutdown(wait=True, cancel_futures=True)
        self.assertEqual(self.coordinator.get_lease(lease.lease_id)["state"], "EXPIRED")
        state = self.coordinator.assert_invariants()
        self.assertEqual(state["global_used_count"], 0)
        self.assertEqual(state["operation_count"], 0)

    def test_coordinator_issuer_and_gateway_key_or_budget_configuration_drift_fail_closed(self):
        db_path = self.coordinator.database_path
        common = {
            "coordinator_id": self.COORDINATOR_ID,
            "global_budget_id": self.BUDGET_ID,
            "global_quota_limit": 10,
            "issuer_public_key": self.issuer_private.public_key(),
            "coordinator_private_key": self.coordinator_private,
            "coordinator_key_id": "coordinator-key-d92",
            "database_path": db_path,
            "gateways": {
                "gateway-A": self.gateway_a_private.public_key(),
                "gateway-B": self.gateway_b_private.public_key(),
            },
            "clock": lambda: self.now[0],
        }
        variants = [
            {**common, "global_quota_limit": 11},
            {**common, "issuer_public_key": Ed25519PrivateKey.generate().public_key()},
            {**common, "coordinator_private_key": Ed25519PrivateKey.generate()},
        ]
        for index, values in enumerate(variants):
            with self.subTest(configuration_variant=index), self.assertRaises(ConfigurationMismatch):
                OnlineBudgetCoordinator(**values)
        with self.assertRaises(ConfigurationMismatch):
            self.coordinator.enroll_gateway("gateway-A", Ed25519PrivateKey.generate().public_key())
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_tampered_coordinator_http_receipt_is_not_returned_to_caller(self):
        lease = self.make_lease("lease-wire-tamper")
        self.register(lease)
        operation_id = "wire-receipt-tamper-op"
        execution = self.make_execution(lease, operation_id)
        request_digest = digest({"wire-tamper": operation_id})
        server, url = self.start_fault_server()
        server.tamper_operation_id = operation_id
        fault_client = self.client(base_url=url)
        dispatch_log = []
        with self.assertRaises(CoordinatorIndeterminate):
            receipt = fault_client.consume(lease, execution, operation_id=operation_id, request_digest=request_digest)
            dispatch_log.append(receipt)
        self.assertEqual(dispatch_log, [], "tool dispatch must not proceed without a verified receipt")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)
        # The underlying committed receipt remains intact and can be retrieved by exact retry.
        valid = self.client().consume(lease, execution, operation_id=operation_id, request_digest=request_digest)
        self.assertEqual(valid.payload["global_sequence"], 1)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def _raw_http_request(self, request_bytes):
        sock = socket.create_connection(self.server.server_address, timeout=3)
        sock.settimeout(3)
        chunks = []
        try:
            sock.sendall(request_bytes)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            chunks.append(data)
        finally:
            sock.close()
        return b"".join(chunks)

    def test_http_framing_size_auth_health_and_bind_boundaries(self):
        with urlopen(self.base_url + "/health", timeout=3) as response:
            health = json.loads(response.read().decode("utf-8"))
        self.assertEqual(set(health), {"ok", "coordinator_id", "global_budget_id", "health"})
        self.assertTrue(health["ok"])

        unauth = Request(self.base_url + "/v1/budget/consume", data=b"{}",
                         headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(HTTPError) as unauth_error:
            urlopen(unauth, timeout=3)
        self.assertEqual(unauth_error.exception.code, 401)
        unauth_error.exception.close()

        wrong_media = Request(self.base_url + "/v1/budget/consume", data=b"{}",
                              headers={"Content-Type": "text/plain"}, method="POST")
        with self.assertRaises(HTTPError) as media_error:
            urlopen(wrong_media, timeout=3)
        self.assertEqual(media_error.exception.code, 415)
        media_error.exception.close()

        # Send only headers for an oversized body: the Coordinator must reject before reading it.
        oversized_response = self._raw_http_request(
            b"POST /v1/budget/consume HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {MAX_BODY_BYTES + 1}\r\n\r\n".encode("ascii")
        )
        self.assertIn(b" 413 ", oversized_response.split(b"\r\n", 1)[0])
        self.assertIn(b"Connection: close", oversized_response)

        # Ambiguous duplicate Content-Length is rejected and the HTTP/1.1 connection is closed.
        duplicate_length_response = self._raw_http_request(
            b"POST /v1/budget/consume HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        )
        self.assertIn(b" 400 ", duplicate_length_response.split(b"\r\n", 1)[0])
        self.assertIn(b"Connection: close", duplicate_length_response)

        with self.assertRaises(ValueError):
            CoordinatorHTTPServer(("0.0.0.0", 0), self.coordinator)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
