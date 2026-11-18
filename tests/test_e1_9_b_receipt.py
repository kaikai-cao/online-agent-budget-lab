"""E1.9-B / B.4 -- Receipt v2 server-side validation tests (unit).

Verifies the B2.2 binding corrections: forced v2 (v1 rejected), exact field set,
signature with registry key, and executor_id/operation_id/binding_digest/result
four-way binding.  A forged-but-self-consistent Receipt is EXPECTED to pass the
structural checks -- the honest boundary is asserted in the report, not hidden.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_receipt_validator import ReceiptValidationError, validate_result_receipt

from _e1b_helpers import receipt_v2, result_envelope, sha


class ReceiptCase(unittest.TestCase):
    def setUp(self) -> None:
        self.ekey = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        self.exec = "exec-A"
        self.op = "op-r1"
        self.binding = sha("a")
        self.result = {"value": 42}

    def _receipt(self, **overrides):
        params = dict(
            executor_id=self.exec, operation_id=self.op,
            binding_digest=self.binding, result=self.result, key=self.ekey,
            version=overrides.pop("version", 2),
        )
        params.update(overrides)  # executor_id/operation_id/binding_digest overrides land here
        return receipt_v2(**params)

    def _envelope(self, receipt=None, **overrides):
        return result_envelope(
            operation_id=self.op, binding_digest=self.binding,
            result=self.result, receipt=receipt or self._receipt(), **overrides
        )

    def _validate(self, *, receipt=None, envelope=None, intent_exec=None, intent_binding=None, key=None):
        validate_result_receipt(
            receipt=receipt if receipt is not None else self._receipt(),
            envelope=envelope if envelope is not None else self._envelope(receipt=receipt),
            intent_executor_id=intent_exec or self.exec,
            intent_binding_digest=intent_binding or self.binding,
            executor_public_key=key or self.ekey.public_key(),
        )

    def test_V01_valid_v2_passes(self):
        self._validate()

    def test_V02_v1_rejected(self):
        from online_budget.execution_receipts import RECEIPT_FIELDS_V1, sign_execution_receipt
        payload = {
            "receipt_version": 1, "executor_id": self.exec, "coordinator_id": "c",
            "global_budget_id": "g", "gateway_id": "gw", "lease_id": "l",
            "operation_id": self.op, "binding_digest": self.binding,
            "budget_receipt_digest": sha("b"), "tool_name": "t",
            "tool_schema_hash": sha("s"), "arguments_digest": sha("g"),
            "status": "SUCCEEDED",
            "result_digest": __import__("online_budget.canonical", fromlist=["digest"]).digest(
                {"domain": "agent-tool-result-v1", "result": self.result}),
            "result": self.result, "completed_at": 1,
        }
        self.assertEqual(set(payload), RECEIPT_FIELDS_V1)
        v1 = sign_execution_receipt(payload, self.ekey).as_dict()
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=v1, envelope=self._envelope(receipt=v1))
        self.assertEqual(ctx.exception.code, "RECEIPT_VERSION_UNSUPPORTED")

    def test_V03_version_missing_rejected(self):
        r = self._receipt()
        del r["payload"]["receipt_version"]
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertEqual(ctx.exception.code, "RECEIPT_VERSION_MISSING")

    def test_V04_wrong_signature_key_rejected(self):
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(key=self.other.public_key())
        self.assertEqual(ctx.exception.code, "RECEIPT_SIGNATURE")

    def test_V05_executor_id_mismatch_rejected(self):
        r = self._receipt(executor_id="exec-B")
        # re-sign is done by helper; envelope needs matching receipt object
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertEqual(ctx.exception.code, "EXECUTOR_ID_MISMATCH")

    def test_V06_operation_id_mismatch_rejected(self):
        r = self._receipt(operation_id="op-other")
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertEqual(ctx.exception.code, "OPERATION_ID_MISMATCH")

    def test_V07_binding_digest_mismatch_rejected(self):
        r = self._receipt(binding_digest=sha("z"))
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertEqual(ctx.exception.code, "BINDING_DIGEST_MISMATCH")

    def test_V08_result_digest_recompute_rejected(self):
        r = self._receipt(result_digest=sha("wrong"))
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertEqual(ctx.exception.code, "RESULT_DIGEST_MISMATCH")

    def test_V09_intent_binding_mismatch_rejected(self):
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(intent_binding=sha("different"))
        self.assertEqual(ctx.exception.code, "INTENT_BINDING_MISMATCH")

    def test_V10_tampered_payload_rejected(self):
        r = self._receipt()
        r["payload"]["result"] = {"value": 999}  # break signature
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=r, envelope=self._envelope(receipt=r))
        self.assertIn(ctx.exception.code, {"RECEIPT_SIGNATURE", "RESULT_DIGEST_MISMATCH"})

    def test_V11_receipt_result_vs_envelope_result_binding(self):
        """B-F1: a valid Receipt over result X must not pair with an envelope carrying result Y.

        The Receipt itself is fully valid: correct v2 fields, self-consistent
        result_digest, and a correct signature by the registry key.  Only the
        envelope's ``result`` differs.  Before B-F1 this combination was
        accepted, letting the Journal record a result the Executor never signed.
        """
        receipt = self._receipt(result=self.result)  # signed over {"value": 42}
        rogue_envelope = result_envelope(
            operation_id=self.op,
            binding_digest=self.binding,
            result={"value": 9999},  # envelope claims a DIFFERENT result
            receipt=receipt,
        )
        with self.assertRaises(ReceiptValidationError) as ctx:
            self._validate(receipt=receipt, envelope=rogue_envelope)
        self.assertEqual(ctx.exception.code, "RESULT_ENVELOPE_MISMATCH")

    def test_V12_matching_receipt_and_envelope_result_passes(self):
        """B-F1 control: identical (non-trivial) results on both sides still pass."""
        rich = {"value": 42, " echoed": ["a", "b"], "nested": {"k": 1}}
        receipt = self._receipt(result=rich)
        envelope = result_envelope(
            operation_id=self.op, binding_digest=self.binding, result=rich, receipt=receipt
        )
        self._validate(receipt=receipt, envelope=envelope)


if __name__ == "__main__":
    unittest.main()
