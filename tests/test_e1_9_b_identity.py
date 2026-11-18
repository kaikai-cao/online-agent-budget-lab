"""E1.9-B / B.3 -- identity binding tests (unit, simulated identities).

These are UNIT tests with injected (simulated) identities.  They verify the
service-layer authorisation logic.  They are NOT a substitute for the real
Windows OS-identity/ACL acceptance test (test_e1_9_b_ipc.py, marked env-gated).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_identity import CallerIdentityError, IdentityAuthorizer
from online_budget.journal_service import JournalService
from online_budget.journal_service_config import ServiceConfig, ServiceConfigError

from _e1b_helpers import make_config, simulated_caller


class IdentityCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey
        )
        self.account = "TESTHOST\\exec_acct"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_I01_authorizer_accepts_mapped_executor(self):
        auth = IdentityAuthorizer(self.config, require_os_backed=False)
        result = auth.authorize(simulated_caller(self.account), "exec-A")
        self.assertEqual(result, "exec-A")

    def test_I02_unknown_os_identity_rejected(self):
        auth = IdentityAuthorizer(self.config, require_os_backed=False)
        with self.assertRaises(CallerIdentityError):
            auth.authorize(simulated_caller("TESTHOST\\intruder"), "exec-A")

    def test_I03_executor_outside_mapping_rejected(self):
        auth = IdentityAuthorizer(self.config, require_os_backed=False)
        with self.assertRaises(CallerIdentityError):
            auth.authorize(simulated_caller(self.account), "exec-B")

    def test_I04_no_public_key_mapping_rejected_at_config_time(self):
        # A config whose identity map references an unregistered executor is invalid.
        self.raw["os_identity_to_executor_ids"][self.account] = ["ghost"]
        with self.assertRaises(ServiceConfigError):
            ServiceConfig.from_dict(self.raw, base_dir=self.dir)

    def test_I05_os_backed_required_by_default(self):
        auth = IdentityAuthorizer(self.config, require_os_backed=True)
        with self.assertRaises(CallerIdentityError):
            auth.authorize(simulated_caller(self.account), "exec-A")

    def test_I06_service_rejects_claimed_executor_mismatch(self):
        svc = JournalService(self.config, require_os_backed=False).start()
        try:
            # Claim a different executor than the OS identity mapping allows.
            with self.assertRaises(Exception) as ctx:
                svc._append_intent(
                    {
                        "operation_id": "op-x",
                        "executor_id": "exec-B",
                        "envelope": {
                            "operation_id": "op-x",
                            "binding_digest": "sha256:" + "a" * 64,
                            "executor_id": "exec-B",
                        },
                    },
                    simulated_caller(self.account),
                )
            self.assertIn("executor", str(ctx.exception).lower())
        finally:
            svc.stop()


if __name__ == "__main__":
    unittest.main()
