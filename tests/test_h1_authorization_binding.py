"""H1专项测试：B2 在线授权验证 vs C 本地 Ed25519 凭证验证。

每项测试直接调用实验模块并断言 B2/C 的实际结果；不读取 runner 的 CSV 预期
值来伪造成功。运行：
  PYTHONPATH="src;tests;experiments/h1_authorization_binding" \
    .venv/Scripts/python -m unittest tests.test_h1_authorization_binding -v
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "src"), str(REPO / "experiments" / "h1_authorization_binding")):
    if p not in sys.path:
        sys.path.insert(0, p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

from online_budget.canonical import digest  # noqa: E402

from h1_authorization_service import (  # noqa: E402
    AuthorizationService,
    AuthServiceTLSServer,
    B2OnlineVerifier,
    CredentialIssuanceError,
)
from h1_executor import Executor, VerificationError  # noqa: E402
from h1_protocol import H1ProtocolError, compute_action_digest  # noqa: E402
from h1_sink import ControlledSink  # noqa: E402

BASE_REQUEST: dict[str, Any] = {
    "executor_id": "executor-main",
    "server_uri": "https://mcp.example.test/mcp",
    "tool_name": "send_email",
    "schema_hash": digest({"template": "send_email-v1"}),
    "arguments": {"to": "alice@example.test", "subject": "hi", "body": "hello"},
}


def fresh_request(**overrides: Any) -> dict[str, Any]:
    req = dict(BASE_REQUEST)
    req["arguments"] = dict(BASE_REQUEST["arguments"])
    req.update(overrides)
    return req


class H1Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="h1-test-")
        self.workdir = Path(self._tmp.name)
        self.auth = AuthorizationService()
        self.tls = AuthServiceTLSServer(self.auth)
        host, port, fp = self.tls.start()
        self.b2 = B2OnlineVerifier(host=host, port=port, pinned_fingerprint=fp)
        self.sink = ControlledSink(self.workdir / f"sink-{uuid.uuid4().hex}.sqlite3")
        pub = Ed25519PublicKey.from_public_bytes(self.auth.public_key_bytes())
        self.executor = Executor(
            executor_id="executor-main",
            sink=self.sink,
            b2_verifier=self.b2,
            trusted_keys={"h1-key-1": pub},
        )

    def tearDown(self) -> None:
        self.tls.shutdown()
        self._tmp.cleanup()

    def authorize(self, *, request: dict[str, Any], ttl: float = 300.0, now: float | None = None):
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=request, jti=jti, ttl_seconds=ttl, now=now)
        return jti, self.auth.issue_credential(jti)

    def auth_ref(self, jti: str) -> dict[str, Any]:
        return {"jti": jti, "action_digest": compute_action_digest(BASE_REQUEST)}

    def b2_exec(self, *, request: dict[str, Any], jti: str, rollback_once: bool = False):
        return self.executor.execute_b2(
            request=request, auth_ref=self.auth_ref(jti), rollback_once=rollback_once
        )

    def c_exec(self, *, request: dict[str, Any], credential: dict[str, Any], rollback_once: bool = False):
        return self.executor.execute_c(
            request=request, credential=credential, rollback_once=rollback_once
        )

    def assert_denied(self, fn, reason_fragment: str) -> None:
        with self.assertRaises(VerificationError) as ctx:
            fn()
        self.assertIn(reason_fragment, str(ctx.exception))


class TestH1Protocol(H1Fixture):
    def test_action_digest_domain_and_nonfinite_rejection(self):
        d1 = compute_action_digest(BASE_REQUEST)
        self.assertTrue(d1.startswith("sha256:"))
        # domain separation: digest differs from a no-domain raw digest
        self.assertNotEqual(d1, digest(BASE_REQUEST))
        bad = fresh_request()
        bad["arguments"]["score"] = float("inf")
        with self.assertRaises(H1ProtocolError):
            compute_action_digest(bad)

    def test_planner_forged_digest_field_is_ignored(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        forged = fresh_request()
        forged["action_digest"] = digest({"forged": True})
        # B2: forged top-level digest hint ignored, real identity unchanged.
        out_b2 = self.b2_exec(request=forged, jti=jti_b2)
        self.assertEqual(out_b2["outcome"], "EXECUTED")
        # C: same, recomputed from identity fields, credential still valid.
        out_c = self.c_exec(request=forged, credential=cred_c)
        self.assertEqual(out_c["outcome"], "EXECUTED")


class TestH1LegalAndTamper(H1Fixture):
    def test_01_legal_authorization_both_paths(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        self.assertEqual(self.b2_exec(request=req, jti=jti_b2)["outcome"], "EXECUTED")
        self.assertEqual(self.c_exec(request=req, credential=cred_c)["outcome"], "EXECUTED")

    def test_02_tamper_arguments_rejected_both(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        bad = fresh_request(arguments={"to": "attacker@test", "subject": "hi", "body": "hello"})
        self.assert_denied(lambda: self.b2_exec(request=bad, jti=jti_b2), "ACTION_DIGEST_MISMATCH")
        self.assert_denied(lambda: self.c_exec(request=bad, credential=cred_c), "ACTION_DIGEST_MISMATCH")

    def test_03_tamper_schema_rejected_both(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        bad = fresh_request(schema_hash=digest({"template": "evil-v2"}))
        for fn in (lambda: self.b2_exec(request=bad, jti=jti_b2),
                   lambda: self.c_exec(request=bad, credential=cred_c)):
            self.assert_denied(fn, "ACTION_DIGEST_MISMATCH")

    def test_04_tamper_server_uri_rejected_both(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        bad = fresh_request(server_uri="https://evil.test/mcp")
        for fn in (lambda: self.b2_exec(request=bad, jti=jti_b2),
                   lambda: self.c_exec(request=bad, credential=cred_c)):
            self.assert_denied(fn, "ACTION_DIGEST_MISMATCH")

    def test_05_executor_mismatch_rejected_both(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        bad = fresh_request(executor_id="executor-attacker")
        for fn in (lambda: self.b2_exec(request=bad, jti=jti_b2),
                   lambda: self.c_exec(request=bad, credential=cred_c)):
            self.assert_denied(fn, "EXECUTOR_TARGET_MISMATCH")

    def test_06_expired_authorization_issuance_refused(self):
        # 新语义：授权在签发前已过期 -> issue_credential 拒绝（签发入口约束）。
        # B2 在线查询仍按服务端当前状态返回 EXPIRED（与签发路径无关）。
        req = fresh_request()
        now = time.time()
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=req, jti=jti, ttl_seconds=-1.0, now=now)
        with self.assertRaises(CredentialIssuanceError) as ctx:
            self.auth.issue_credential(jti)
        self.assertEqual(ctx.exception.reason, "EXPIRED")
        self.assert_denied(lambda: self.b2_exec(request=req, jti=jti), "EXPIRED")

    def test_08_c_credential_signature_tamper_rejected(self):
        req = fresh_request()
        jti, cred = self.authorize(request=req)
        cred = dict(cred)
        cred["payload"] = dict(cred["payload"])
        cred["payload"]["arguments"] = {"to": "attacker@test"}
        self.assert_denied(lambda: self.c_exec(request=req, credential=cred), "C_SIGNATURE_INVALID")

    def test_09_c_unknown_key_id_wrong_audience_issuer(self):
        req = fresh_request()
        for override, fragment in [
            ({"key_id": "h1-key-UNTRUSTED"}, "C_UNKNOWN_KEY_ID"),
            ({"audience": "attacker-audience"}, "C_BAD_AUDIENCE"),
            ({"issuer": "attacker-issuer"}, "C_BAD_ISSUER"),
        ]:
            _, cred = self.authorize(request=req)
            cred = dict(cred)
            cred["payload"] = dict(cred["payload"])
            cred["payload"].update(override)
            self.assert_denied(lambda c=cred: self.c_exec(request=req, credential=c), fragment)


class TestH1AvailabilityAndRevocation(H1Fixture):
    def test_07_revoked_b2_denies_c_offline_cannot_know(self):
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        self.auth.revoke(jti_b2)
        self.auth.revoke(jti_c)
        self.assert_denied(lambda: self.b2_exec(request=req, jti=jti_b2), "REVOKED")
        # C signed before revocation; without an online channel it cannot learn it.
        out = self.c_exec(request=req, credential=cred_c)
        self.assertEqual(out["outcome"], "EXECUTED")

    def test_10_b2_fail_closed_when_service_unreachable(self):
        req = fresh_request()
        jti, _ = self.authorize(request=req)
        self.tls.shutdown()
        self.assert_denied(lambda: self.b2_exec(request=req, jti=jti), "AUTH_SERVICE_UNREACHABLE")

    def test_11_c_valid_credential_works_offline(self):
        req = fresh_request()
        _, cred = self.authorize(request=req)
        self.tls.shutdown()
        out = self.c_exec(request=req, credential=cred)
        self.assertEqual(out["outcome"], "EXECUTED")

    def test_11b_b2_wrong_pin_denied(self):
        req = fresh_request()
        jti, _ = self.authorize(request=req)
        bad_b2 = B2OnlineVerifier(host=self.b2.host, port=self.b2.port, pinned_fingerprint="00" * 32)
        self.executor.b2_verifier = bad_b2
        self.assert_denied(lambda: self.b2_exec(request=req, jti=jti), "AUTH_SERVICE_UNREACHABLE")


class TestH1Consumption(H1Fixture):
    def test_12_sequential_replay_single_effect(self):
        req = fresh_request()
        _, cred = self.authorize(request=req)
        self.assertEqual(self.c_exec(request=req, credential=cred)["outcome"], "EXECUTED")
        self.assertEqual(self.c_exec(request=req, credential=cred)["outcome"], "DEDUP_HIT")
        self.assertEqual(self.sink.effect_count(), 1)

    def test_13_concurrent_replay_single_effect(self):
        req = fresh_request()
        _, cred = self.authorize(request=req)
        results: list[dict[str, Any]] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            results.append(self.c_exec(request=req, credential=cred))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        executed = sum(1 for r in results if r["outcome"] == "EXECUTED")
        dedup = sum(1 for r in results if r["outcome"] == "DEDUP_HIT")
        self.assertEqual(executed, 1)
        self.assertEqual(dedup, 7)
        self.assertEqual(self.sink.effect_count(), 1)

    def test_14_crash_before_commit_then_retry(self):
        req = fresh_request()
        _, cred = self.authorize(request=req)
        out = self.c_exec(request=req, credential=cred, rollback_once=True)
        self.assertEqual(out["outcome"], "ROLLED_BACK")
        self.assertEqual(self.sink.effect_count(), 0)
        self.assertEqual(self.sink.consumption_count(), 0)
        self.assertEqual(self.c_exec(request=req, credential=cred)["outcome"], "EXECUTED")
        self.assertEqual(self.sink.effect_count(), 1)

    def test_15_post_commit_replay_no_second_effect(self):
        req = fresh_request()
        _, cred = self.authorize(request=req)
        self.c_exec(request=req, credential=cred)
        self.c_exec(request=req, credential=cred)
        self.c_exec(request=req, credential=cred)
        self.assertEqual(self.sink.effect_count(), 1)

    def test_shared_store_b2_then_c_same_jti_dedup(self):
        # Fairness evidence: B2 and C share one consumption store, so the same
        # jti consumed by B2 is deduped when C tries it (and vice versa).
        req = fresh_request()
        jti, cred = self.authorize(request=req)
        self.assertEqual(self.b2_exec(request=req, jti=jti)["outcome"], "EXECUTED")
        self.assertEqual(self.c_exec(request=req, credential=cred)["outcome"], "DEDUP_HIT")
        self.assertEqual(self.sink.effect_count(), 1)


class TestH1IssuanceGuard(H1Fixture):
    """签发入口约束（H1 验收修复）：签发前撤销/过期拒签；签发后撤销语义不变。"""

    def test_20_active_issuance_then_c_executes(self):
        # 正常 ACTIVE 授权仍能签发，并可由 C 预置公钥验签执行。
        req = fresh_request()
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=req, jti=jti, ttl_seconds=300.0)
        cred = self.auth.issue_credential(jti)  # 不得抛异常
        self.assertEqual(self.c_exec(request=req, credential=cred)["outcome"], "EXECUTED")
        self.assertEqual(self.sink.effect_count(), 1)

    def test_21_revoke_before_issuance_refused(self):
        # 撤销发生在签发之前：issue_credential 必须拒绝，无凭证可签。
        req = fresh_request()
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=req, jti=jti, ttl_seconds=300.0)
        self.auth.revoke(jti)
        with self.assertRaises(CredentialIssuanceError) as ctx:
            self.auth.issue_credential(jti)
        self.assertEqual(ctx.exception.reason, "REVOKED")

    def test_22_expired_before_issuance_refused(self):
        # 授权在签发时点已过期：issue_credential 必须拒绝。
        req = fresh_request()
        now = time.time()
        jti = f"jti-{uuid.uuid4().hex}"
        self.auth.confirm(request=req, jti=jti, ttl_seconds=-1.0, now=now)
        with self.assertRaises(CredentialIssuanceError) as ctx:
            self.auth.issue_credential(jti, now=now)
        self.assertEqual(ctx.exception.reason, "EXPIRED")

    def test_23_revoke_after_issuance_keeps_h1_tradeoff(self):
        # 已签发凭证之后再撤销：保持 H1 原有架构权衡——B2 在线拒、C 离线仍执行。
        # 该测试锁定"签发后撤销"语义，不得因修复签发入口而改变。
        req = fresh_request()
        jti_b2, _ = self.authorize(request=req)
        jti_c, cred_c = self.authorize(request=req)
        self.auth.revoke(jti_b2)
        self.auth.revoke(jti_c)
        self.assert_denied(lambda: self.b2_exec(request=req, jti=jti_b2), "REVOKED")
        out = self.c_exec(request=req, credential=cred_c)
        self.assertEqual(out["outcome"], "EXECUTED")
        self.assertEqual(self.sink.effect_count(), 1)


if __name__ == "__main__":
    unittest.main()
