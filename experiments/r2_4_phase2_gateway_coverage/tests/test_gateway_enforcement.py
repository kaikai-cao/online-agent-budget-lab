"""P1 must be a REAL mandatory gateway, not a convention that requests pass it.

The service entrance authenticates gateway-signed receipts with the gateway
public key. A caller without the gateway private key cannot produce a valid
receipt; a direct call is rejected and never executes.
"""
import _base  # noqa: F401
import tempfile
import unittest
from pathlib import Path

from r24p2.gateway import Gateway
from r24p2.models import derive_key
from r24p2.service import RejectedByGateway, ToolService


class TestGatewayEnforcement(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="r24p2-gw-")
        root = Path(self._tmp.name)
        gk = derive_key(1, "gateway")
        sk = derive_key(1, "service")
        self.gw = Gateway(root / "g.sqlite3", gk, "gw-01")
        self.svc = ToolService(root / "s.sqlite3", sk, gk.public_key(),
                               "gw-01", "svc-A", enforce_gateway=True)
        self.svc_nogw = ToolService(root / "s0.sqlite3", sk, gk.public_key(),
                                    "gw-01", "svc-A", enforce_gateway=False)

    def tearDown(self):
        self._tmp.cleanup()

    def test_direct_call_without_receipt_is_rejected_and_not_executed(self):
        with self.assertRaises(RejectedByGateway):
            self.svc.receive(None, "r", "call", "att")
        self.assertEqual(self.svc.count(), 0, "no submission on rejection")

    def test_forged_receipt_with_wrong_key_is_rejected(self):
        from r24p2.models import ForwardReceipt
        attacker_key = derive_key(999, "attacker")  # not the gateway key
        fake = ForwardReceipt("r", "call", "att", "svc-A", "gw-01").sign(attacker_key)
        with self.assertRaises(RejectedByGateway):
            self.svc.receive(fake, "r", "call", "att")

    def test_valid_gateway_receipt_is_accepted(self):
        receipt = self.gw.forward("r", "call", "att", "svc-A")
        accepted, sub = self.svc.receive(receipt, "r", "call", "att")
        self.assertTrue(accepted)
        self.assertIsNotNone(sub)
        self.assertEqual(self.svc.count(), 1)

    def test_wrong_service_id_receipt_rejected(self):
        receipt = self.gw.forward("r", "call", "att", "svc-B")
        with self.assertRaises(RejectedByGateway):
            self.svc.receive(receipt, "r", "call", "att")

    def test_p0_without_enforcement_accepts_direct_call(self):
        # P0 honestly has no gateway; a direct call executes (and self-reports).
        accepted, sub = self.svc_nogw.receive(None, "r", "call", "att")
        self.assertTrue(accepted)
        self.assertIsNotNone(sub)


if __name__ == "__main__":
    unittest.main(verbosity=2)
