"""E1.2 tests: signed Metering Policy, fee computation, Metering Attestation.

Run:
    PYTHONPATH=src python -m unittest tests.test_metering -v
"""

from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget import e1_encoding as enc
from online_budget import metering as m
from online_budget.canonical import b64encode, canonical_json_bytes, digest
from online_budget.executor_authorization import ExecutorAuthorization, issue_executor_authorization
from online_budget.grants import ToolPermission, issue_online_lease_grant
from online_budget.tool_binding import build_tool_call_binding


class MeteringTests(unittest.TestCase):
    NOW = 1_800_000_000
    ISSUER_ID = "issuer-metering-test"
    GATEWAY_ID = "gateway-metering-test"
    COORDINATOR_ID = "coordinator-metering-test"
    EXECUTOR_ID = "executor-metering-test"
    OPERATION_ID = "operation-metering-test"
    TOOL_NAME = "invoice_review"
    COST = 3
    Q = 100

    def setUp(self):
        self.issuer_key = Ed25519PrivateKey.generate()
        self.executor_key = Ed25519PrivateKey.generate()
        self.schema_hash = digest({"tool": self.TOOL_NAME, "schema_version": 1})
        self.context_digest = digest({"tenant": "tenant-metering-test"})
        self.arguments = {"invoice_id": "inv-1", "amount": 100}

        # --- trusted D10 upstream objects (reuse frozen issuance paths) -------
        self.lease = issue_online_lease_grant(
            self.issuer_key,
            issuer_id=self.ISSUER_ID,
            grant_id="grant-metering-test",
            lease_id="lease-metering-test",
            nonce="nonce-metering-test",
            global_budget_id="budget-metering-test",
            quota_limit=5,
            issued_at=self.NOW - 100,
            expires_at=self.NOW + 1000,
            coordinator_audience=self.COORDINATOR_ID,
            allowed_gateway_ids=(self.GATEWAY_ID,),
            subject_id="agent-metering-test",
            context_digest=self.context_digest,
            allowed_tools=(ToolPermission(self.TOOL_NAME, self.schema_hash),),
        )
        self.execution = self._make_execution(self.OPERATION_ID)
        self.binding = build_tool_call_binding(
            operation_id=self.OPERATION_ID,
            gateway_id=self.GATEWAY_ID,
            coordinator_id=self.COORDINATOR_ID,
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            tool_name=self.TOOL_NAME,
            tool_schema_hash=self.schema_hash,
            arguments=self.arguments,
            executor_id=self.EXECUTOR_ID,
        )
        self.authorization = issue_executor_authorization(
            self.issuer_key,
            issuer_id=self.ISSUER_ID,
            authorization_id="authorization-metering-test",
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            gateway_id=self.GATEWAY_ID,
            coordinator_id=self.COORDINATOR_ID,
            executor_id=self.EXECUTOR_ID,
            executor_public_key=self.executor_key.public_key(),
            tool_name=self.TOOL_NAME,
            tool_schema_hash=self.schema_hash,
            issued_at=self.NOW - 10,
            expires_at=self.NOW + 100,
            arguments=self.arguments,
        )

        # --- E1.2 policy / scope / attestation --------------------------------
        self.P = enc.fp_to_hex(7)
        self.policy = m.sign_metering_policy(
            self.issuer_key,
            issuer_id=self.ISSUER_ID,
            policy_version="policy-v1",
            P=self.P,
            entries=[
                {"tool_name": self.TOOL_NAME, "tool_schema_hash": self.schema_hash, "cost": self.COST},
            ],
        )
        self.assertTrue(m.verify_metering_policy(self.policy, self.issuer_key.public_key()))
        self.scope = m.BudgetScope(
            global_budget_id=self.lease.global_budget_id,
            lease_id=self.lease.lease_id,
            budget_id=enc.fp_to_hex(11),
            period_id=enc.fp_to_hex(22),
            Q=self.Q,
            P=self.P,
        )
        self.attestation = self._issue_attestation()

    # ------------------------------------------------------------------ helpers
    def _make_execution(self, operation_id):
        unsigned = {
            "version": 2,
            "issuer_id": self.lease.issuer_id,
            "grant_id": self.lease.grant_id,
            "lease_id": self.lease.lease_id,
            "subject_id": self.lease.subject_id,
            "audience": self.GATEWAY_ID,
            "context_digest": self.lease.context_digest,
            "issued_at": self.lease.issued_at,
            "expires_at": self.lease.expires_at,
            "quota_limit": self.lease.quota_limit,
            "nonce": self.lease.nonce,
            "allowed_tools": [p.as_dict() for p in self.lease.allowed_tools],
            "parent_authorization_digest": hashlib.sha256(operation_id.encode()).hexdigest(),
            "parent_authorization_nonce": "parent-" + operation_id,
            "operation_id": operation_id,
        }
        return {
            **unsigned,
            "signature_b64": b64encode(self.issuer_key.sign(canonical_json_bytes(unsigned))),
        }

    def _issue_attestation(self, **overrides):
        args = dict(
            executor_private_key=self.executor_key,
            executor_id=self.EXECUTOR_ID,
            operation_id=self.OPERATION_ID,
            binding=self.binding,
            authorization=self.authorization,
            tool_name=self.TOOL_NAME,
            tool_schema_hash=self.schema_hash,
            budget_scope=self.scope,
            verified_policy=self.policy,
            issued_at=self.NOW - 10,
            expires_at=self.NOW + 100,
        )
        args.update(overrides)
        return m.issue_metering_attestation(**args)

    def _verify(self, attestation=None, *, policy=None, key=None, scope=None,
                auth_digest=None, now=None):
        return m.verify_metering_attestation(
            attestation or self.attestation,
            key or self.executor_key.public_key(),
            expected_binding=self.binding,
            expected_authorization_digest=auth_digest or self.authorization.authorization_digest,
            expected_budget_scope=scope or self.scope,
            expected_policy=policy or self.policy,
            now=self.NOW if now is None else now,
        )

    def _resign(self, payload, domain=m.ATTESTATION_DOMAIN, key=None):
        sig = m._sign_domain_payload(payload, key or self.executor_key, domain=domain)
        return m.MeteringAttestation(dict(payload), sig)

    @staticmethod
    def _alt_sha(field):
        return digest({"tampered": field})

    # ------------------------------------------------------------- M01–M12 policy
    def test_M01_parse_signed_policy(self):
        parsed = m.parse_metering_policy(self.policy.as_dict())
        self.assertEqual(parsed.unsigned_payload(), self.policy.unsigned_payload())
        self.assertFalse(parsed.is_verified())

    def test_M02_issuer_signature_verifies(self):
        policy = m.parse_metering_policy(self.policy.as_dict())
        self.assertTrue(m.verify_metering_policy(policy, self.issuer_key.public_key()))
        self.assertTrue(policy.is_verified())

    def test_M03_tampered_cost_rejected(self):
        raw = self.policy.as_dict()
        raw["entries"][0]["cost"] = 99
        policy = m.parse_metering_policy(raw)
        self.assertFalse(m.verify_metering_policy(policy, self.issuer_key.public_key()))

    def test_M04_tampered_P_rejected(self):
        raw = self.policy.as_dict()
        raw["P"] = enc.fp_to_hex(999)
        policy = m.parse_metering_policy(raw)
        self.assertFalse(m.verify_metering_policy(policy, self.issuer_key.public_key()))

    def test_M05_tampered_policy_version_rejected(self):
        raw = self.policy.as_dict()
        raw["policy_version"] = "policy-v2"
        policy = m.parse_metering_policy(raw)
        self.assertFalse(m.verify_metering_policy(policy, self.issuer_key.public_key()))

    def test_M06_wrong_issuer_key_rejected(self):
        policy = m.parse_metering_policy(self.policy.as_dict())
        self.assertFalse(m.verify_metering_policy(policy, Ed25519PrivateKey.generate().public_key()))

    def test_M07_duplicate_rule_rejected(self):
        raw = self.policy.as_dict()
        raw["entries"].append(copy.deepcopy(raw["entries"][0]))
        with self.assertRaises(m.MeteringError):
            m.parse_metering_policy(raw)

    def test_M08_unregistered_tool_rejected(self):
        with self.assertRaises(m.MeteringError):
            m.compute_cost("unknown_tool", self.schema_hash, self.policy)

    def test_M09_schema_hash_mismatch_rejected(self):
        with self.assertRaises(m.MeteringError):
            m.compute_cost(self.TOOL_NAME, self._alt_sha("schema"), self.policy)

    def test_M10_zero_cost_rejected(self):
        raw = self.policy.as_dict()
        raw["entries"][0]["cost"] = 0
        with self.assertRaises(m.MeteringError):
            m.parse_metering_policy(raw)

    def test_M11_cost_above_uint32_rejected(self):
        raw = self.policy.as_dict()
        raw["entries"][0]["cost"] = 2**32
        with self.assertRaises(m.MeteringError):
            m.parse_metering_policy(raw)

    def test_M12_compute_cost_returns_signed_value(self):
        self.assertEqual(m.compute_cost(self.TOOL_NAME, self.schema_hash, self.policy), self.COST)

    # ------------------------------------------------------- M13–M19 issue/verify
    def test_M13_issue_attestation(self):
        self.assertIsInstance(self.attestation, m.MeteringAttestation)
        payload = self.attestation.attestation
        self.assertEqual(set(payload), m.ATTESTATION_FIELDS)
        self.assertEqual(payload["c"], self.COST)
        self.assertEqual(payload["Q"], self.Q)
        self.assertEqual(payload["metering_policy_digest"], m.compute_metering_policy_digest(self.policy))

    def test_M14_verify_attestation(self):
        self.assertTrue(self._verify())

    def test_M15_tamper_any_field_rejected(self):
        for field in m.ATTESTATION_FIELDS:
            with self.subTest(field=field):
                payload = dict(self.attestation.attestation)
                if field in ("binding_digest", "executor_authorization_digest", "arguments_digest",
                             "tool_schema_hash", "metering_policy_digest"):
                    payload[field] = self._alt_sha(field)
                elif field in ("budget_id", "period_id", "P"):
                    payload[field] = enc.fp_to_hex(12345)
                elif field in ("Q", "c"):
                    payload[field] = 999
                elif field == "version":
                    payload[field] = 2
                else:
                    payload[field] = "tampered-" + field
                # keep original signature; any field change breaks signature/binding
                tampered = m.MeteringAttestation(payload, self.attestation.signature_b64)
                self.assertFalse(self._verify(tampered))

    def test_M16_tampered_signature_rejected(self):
        tampered = m.MeteringAttestation(
            dict(self.attestation.attestation), b64encode(b"x" * 64)
        )
        self.assertFalse(self._verify(tampered))

    def test_M17_wrong_executor_key_rejected(self):
        self.assertFalse(self._verify(key=Ed25519PrivateKey.generate().public_key()))

    def test_M18_expired_attestation_rejected(self):
        self.assertFalse(self._verify(now=self.attestation.attestation["expires_at"]))

    def test_M19_invalid_validity_interval_rejected(self):
        with self.assertRaises(m.MeteringError):
            self._issue_attestation(issued_at=self.NOW + 100, expires_at=self.NOW)

    # ------------------------------------------------- M20–M26 binding/domain
    def test_M20_other_operation_id_rejected(self):
        payload = dict(self.attestation.attestation)
        payload["operation_id"] = "operation-other"
        self.assertFalse(self._verify(self._resign(payload)))

    def test_M21_other_arguments_digest_rejected(self):
        payload = dict(self.attestation.attestation)
        payload["arguments_digest"] = self._alt_sha("arguments")
        self.assertFalse(self._verify(self._resign(payload)))

    def test_M22_other_authorization_digest_rejected(self):
        payload = dict(self.attestation.attestation)
        payload["executor_authorization_digest"] = self._alt_sha("authorization")
        self.assertFalse(self._verify(self._resign(payload)))

    def test_M23_other_budget_scope_rejected(self):
        for field, value in (
            ("budget_id", enc.fp_to_hex(123)),
            ("period_id", enc.fp_to_hex(456)),
            ("Q", self.Q + 1),
            ("P", enc.fp_to_hex(789)),
        ):
            with self.subTest(field=field):
                payload = dict(self.attestation.attestation)
                payload[field] = value
                self.assertFalse(self._verify(self._resign(payload)))

    def test_M24_wrong_metering_policy_digest_rejected(self):
        payload = dict(self.attestation.attestation)
        payload["metering_policy_digest"] = self._alt_sha("policy")
        self.assertFalse(self._verify(self._resign(payload)))

    def test_M25_forged_cost_rejected(self):
        # (a) attacker changes c but keeps the old signature and policy digest.
        payload = dict(self.attestation.attestation)
        payload["c"] = 999
        self.assertFalse(self._verify(m.MeteringAttestation(payload, self.attestation.signature_b64)))
        # (b) even if c is re-signed, recomputation from the verified policy must disagree.
        self.assertFalse(self._verify(self._resign(payload)))

    def test_M26_wrong_domain_signature_rejected(self):
        payload = dict(self.attestation.attestation)
        wrong = self._resign(payload, domain="d11-e1-metering-attestation-v2")
        self.assertFalse(self._verify(wrong))

    # ------------------------------------------------- M27–M28 shape/type strict
    def test_M27_wrong_field_set_rejected(self):
        # extra field inside the business payload
        payload = dict(self.attestation.attestation)
        payload["extra"] = "x"
        self.assertFalse(self._verify(m.MeteringAttestation(payload, self.attestation.signature_b64)))
        # missing field
        payload = dict(self.attestation.attestation)
        del payload["operation_id"]
        self.assertFalse(self._verify(m.MeteringAttestation(payload, self.attestation.signature_b64)))
        # extra/missing field in the outer envelope
        envelope = self.attestation.as_dict()
        envelope["unexpected"] = 1
        self.assertFalse(m.verify_metering_attestation(
            envelope, self.executor_key.public_key(),
            expected_binding=self.binding,
            expected_authorization_digest=self.authorization.authorization_digest,
            expected_budget_scope=self.scope,
            expected_policy=self.policy,
            now=self.NOW,
        ))

    def test_M28_bool_disguised_as_integer_rejected(self):
        # bool in attestation integer fields
        for field in ("version", "Q", "c", "issued_at", "expires_at"):
            with self.subTest(field=field):
                payload = dict(self.attestation.attestation)
                payload[field] = True
                self.assertFalse(self._verify(m.MeteringAttestation(payload, self.attestation.signature_b64)))
        # bool cost in a policy must be rejected at parse time
        raw = self.policy.as_dict()
        raw["entries"][0]["cost"] = True
        with self.assertRaises(m.MeteringError):
            m.parse_metering_policy(raw)

    # ------------------------------------------------------------- extra invariants
    def test_unverified_policy_cannot_compute_cost(self):
        policy = m.parse_metering_policy(self.policy.as_dict())
        with self.assertRaises(m.MeteringError):
            m.compute_cost(self.TOOL_NAME, self.schema_hash, policy)

    def test_no_cost_parameter_in_issue_api(self):
        import inspect
        params = inspect.signature(m.issue_metering_attestation).parameters
        self.assertNotIn("c", params)
        self.assertNotIn("cost", params)

    def test_policy_digest_excludes_signature(self):
        a = m.compute_metering_policy_digest(self.policy)
        other = replace(self.policy, signature_b64=b64encode(b"y" * 64))
        self.assertEqual(a, m.compute_metering_policy_digest(other))

    def test_quote_digest_is_canonical_digest(self):
        self.assertEqual(
            m.compute_metering_quote_digest(self.attestation),
            enc.canonical_digest(m.ATTESTATION_DOMAIN, self.attestation.attestation),
        )

    def test_domain_separation(self):
        self.assertNotEqual(m.POLICY_DOMAIN, m.ATTESTATION_DOMAIN)
        self.assertEqual(m.POLICY_DOMAIN, "d11-e1-metering-policy-v1")
        self.assertEqual(m.ATTESTATION_DOMAIN, "d11-e1-metering-attestation-v1")


if __name__ == "__main__":
    unittest.main()
