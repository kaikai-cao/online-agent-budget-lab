from __future__ import annotations

import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.canonical import b64encode, canonical_json_bytes, digest, public_key_bytes
from online_budget.grants import ToolPermission, issue_online_lease_grant
from online_budget.executor_authorization import (
    ExecutorAuthorization,
    ExecutorAuthorizationError,
    issue_executor_authorization,
    verify_executor_authorization,
)


class ExecutorAuthorizationTests(unittest.TestCase):
    NOW = 1_800_000_000
    ISSUER_ID = "issuer-auth-test"
    GATEWAY_ID = "gateway-auth-test"
    COORDINATOR_ID = "coordinator-auth-test"
    EXECUTOR_ID = "executor-auth-test"

    def setUp(self):
        self.issuer_key = Ed25519PrivateKey.generate()
        self.executor_key = Ed25519PrivateKey.generate()
        self.schema_hash = digest({"tool": "invoice_review", "schema_version": 1})
        self.context_digest = digest({"tenant": "tenant-auth-test"})

        self.lease = issue_online_lease_grant(
            self.issuer_key,
            issuer_id=self.ISSUER_ID,
            grant_id="grant-auth-test",
            lease_id="lease-auth-test",
            nonce="nonce-auth-test",
            global_budget_id="budget-auth-test",
            quota_limit=5,
            issued_at=self.NOW - 100,
            expires_at=self.NOW + 1000,
            coordinator_audience=self.COORDINATOR_ID,
            allowed_gateway_ids=(self.GATEWAY_ID,),
            subject_id="agent-auth-test",
            context_digest=self.context_digest,
            allowed_tools=(ToolPermission("invoice_review", self.schema_hash),),
        )
        self.execution = self._make_execution("operation-auth-test")
        self.authorization = self._issue()

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
            "parent_authorization_digest": hashlib.sha256(
                operation_id.encode()
            ).hexdigest(),
            "parent_authorization_nonce": "parent-" + operation_id,
            "operation_id": operation_id,
        }
        return {
            **unsigned,
            "signature_b64": b64encode(
                self.issuer_key.sign(canonical_json_bytes(unsigned))
            ),
        }

    def _issue(self, execution=None):
        return issue_executor_authorization(
            self.issuer_key,
            issuer_id=self.ISSUER_ID,
            authorization_id="authorization-auth-test",
            online_lease_grant=self.lease,
            execution_grant=execution or self.execution,
            gateway_id=self.GATEWAY_ID,
            coordinator_id=self.COORDINATOR_ID,
            executor_id=self.EXECUTOR_ID,
            executor_public_key=self.executor_key.public_key(),
            tool_name="invoice_review",
            tool_schema_hash=self.schema_hash,
            issued_at=self.NOW - 10,
            expires_at=self.NOW + 100,
        )

    def _verify(self, authorization=None, execution=None, **overrides):
        args = {
            "online_lease_grant": self.lease,
            "execution_grant": execution or self.execution,
            "gateway_id": self.GATEWAY_ID,
            "coordinator_id": self.COORDINATOR_ID,
            "executor_id": self.EXECUTOR_ID,
            "tool_name": "invoice_review",
            "tool_schema_hash": self.schema_hash,
            "now": self.NOW,
        }
        args.update(overrides)
        return verify_executor_authorization(
            authorization or self.authorization,
            self.issuer_key.public_key(),
            **args,
        )

    def test_valid_authorization_verifies_executor_public_key(self):
        actual = self._verify()
        self.assertEqual(public_key_bytes(actual), public_key_bytes(self.executor_key.public_key()))

    def test_authorization_round_trip(self):
        parsed = ExecutorAuthorization.from_dict(self.authorization.as_dict())
        self.assertEqual(parsed.authorization_digest, self.authorization.authorization_digest)
        self.assertEqual(public_key_bytes(self._verify(parsed)), public_key_bytes(self.executor_key.public_key()))

    def test_tampered_signature_is_rejected(self):
        tampered = ExecutorAuthorization(
            self.authorization.payload,
            b64encode(b"x" * 64),
        )
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(tampered)

    def test_tampered_payload_is_rejected(self):
        payload = dict(self.authorization.payload)
        payload["executor_id"] = "executor-attacker"
        tampered = ExecutorAuthorization(payload, self.authorization.signature_b64)
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(tampered)

    def test_wrong_operation_grant_is_rejected(self):
        other_execution = self._make_execution("operation-other")
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(execution=other_execution)

    def test_wrong_executor_identity_is_rejected(self):
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(executor_id="executor-other")

    def test_wrong_tool_or_schema_is_rejected(self):
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(tool_name="other_tool")
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(tool_schema_hash=digest({"schema": "different"}))

    def test_expired_authorization_is_rejected(self):
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(now=self.authorization.payload["expires_at"])

    def test_not_yet_valid_authorization_is_rejected(self):
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(now=self.authorization.payload["issued_at"] - 1)

    def test_boolean_version_is_rejected(self):
        payload = dict(self.authorization.payload)
        payload["version"] = True
        malformed = ExecutorAuthorization(payload, self.authorization.signature_b64)
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(malformed)

    def test_malformed_hash_is_rejected(self):
        payload = dict(self.authorization.payload)
        payload["tool_schema_hash"] = "not-a-digest"
        malformed = ExecutorAuthorization(payload, self.authorization.signature_b64)
        with self.assertRaises(ExecutorAuthorizationError):
            self._verify(malformed)


if __name__ == "__main__":
    unittest.main()
