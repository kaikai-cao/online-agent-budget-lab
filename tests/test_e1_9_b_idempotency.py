"""E1.9-B / B.5 -- concurrency & idempotency index tests (unit).

Verifies that concurrent requests for the same key are serialised by the
server-side SQLite BEGIN IMMEDIATE authoritative transaction: exactly ONE Entry
is appended, all other callers get the original (idempotent=True).
"""

from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_idempotency import IdempotencyStore
from online_budget.journal_service import JournalService, ServiceRequest

from _e1b_helpers import make_config, simulated_caller


class ConcurrentCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        self.config, _ = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey
        )
        self.caller = simulated_caller("TESTHOST\\exec_acct")
        self.svc = JournalService(self.config, require_os_backed=False).start()

    def tearDown(self) -> None:
        self.svc.stop()
        self.tmp.cleanup()

    def test_C01_concurrent_same_key_one_entry(self):
        n = 12
        results: list[dict] = []
        errors: list[str] = []
        barrier = threading.Barrier(n)

        def worker():
            req = ServiceRequest(
                method="append_intent",
                params={
                    "operation_id": "op-conc",
                    "executor_id": "exec-A",
                    "envelope": {
                        "operation_id": "op-conc",
                        "binding_digest": "sha256:" + "a" * 64,
                        "executor_id": "exec-A",
                    },
                },
            )
            try:
                barrier.wait()
                results.append(self.svc.handle(req, self.caller))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], errors)
        self.assertEqual(len(results), n)
        seqs = {r["entry"]["seq"] for r in results}
        self.assertEqual(seqs, {1}, f"expected single seq, got {seqs}")
        # exactly one non-idempotent append
        fresh_count = sum(1 for r in results if not r["idempotent"])
        self.assertEqual(fresh_count, 1)
        vi = self.svc.handle(ServiceRequest("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_C02_index_persists_and_is_queryable(self):
        self.svc.handle(
            ServiceRequest("append_intent", {
                "operation_id": "op-idx", "executor_id": "exec-A",
                "envelope": {"operation_id": "op-idx", "binding_digest": "sha256:" + "a" * 64,
                             "executor_id": "exec-A"},
            }),
            self.caller,
        )
        store = IdempotencyStore(self.config.idempotency_db_path)
        with store._db() as con:
            row = store.get(con, "op-idx", "INTENT")
        self.assertIsNotNone(row)
        self.assertEqual(row["seq"], 1)
        self.assertTrue(row["payload_digest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
