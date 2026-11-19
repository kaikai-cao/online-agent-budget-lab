"""H2 正确性测试：H2-a~g（机制正确性断言，任一失败即阻断 H2.1）。

每项测试直接调用实验模块并断言实际结果；不读取 runner 的 CSV 预期值来伪造成功。

  PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
    .venv/Scripts/python -m unittest tests.test_h2_revocation_management -v

覆盖：
  H2-a 四组公平性（同一 ActionRequest/digest/Sink/时钟/信任锚）
  H2-b 快照抗回滚/抗伪造（含重启重放）
  H2-c 过期 fail closed、无错误放行
  H2-d1 C2 已知撤销不放行；H2-d2 四组原子消费最多一次副作用
  H2-e  B2 查询—消费竞态被如实测量（已知边界，非缺陷）
  H2-f  首次信任建立（S0/S1/S2、BOOT_ONLINE、不可信注入拒绝）
  H2-g  刷新成本如实计量（attempt/success/failure、失败不重置计时、实测请求率）
"""

from __future__ import annotations

import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from typing import Any

REPO = Path(__file__).resolve().parents[1]
for p in (
    str(REPO / "src"),
    str(REPO / "tests"),
    str(REPO / "experiments" / "h1_authorization_binding"),
    str(REPO / "experiments" / "h2_revocation_management"),
):
    if p not in sys.path:
        sys.path.insert(0, p)
# Both h1 and h2 dirs contain a run_experiment.py. Force the h2 copy to the
# FRONT so `from run_experiment import compute_refresh_metrics` resolves to the
# H2 runner, regardless of the order given in PYTHONPATH.
_H2_DIR = str(REPO / "experiments" / "h2_revocation_management")
if _H2_DIR in sys.path:
    sys.path.remove(_H2_DIR)
sys.path.insert(0, _H2_DIR)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from h1_protocol import compute_action_digest  # noqa: E402
from h2_executor import (  # noqa: E402
    H2Harness,
    LogicalClock,
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    OUTCOME_REJECTED,
    TrialResult,
    fresh_request,
)
from h2_snapshot import (  # noqa: E402
    SNAPSHOT_DOMAIN,
    SnapshotValidationError,
    build_snapshot,
    snapshot_payload_bytes,
    validate_snapshot,
)
from h2_snapshot_state import (  # noqa: E402
    BOOT_OFFLINE,
    BOOT_ONLINE,
    STATE_S0_BOOTSTRAP,
    STATE_S1_RESTORE,
    STATE_S2_CORRUPT,
    SnapshotStateStore,
    StateAlreadyInitialized,
    StateUnavailable,
)
from run_experiment import (  # noqa: E402
    NA_NO_APPLICABLE,
    NA_NO_CONTINUOUS_CLOCK,
    NA_NO_SUCCESS,
    NA_NO_WALL,
    compute_refresh_metrics,
)


class H2Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="h2-test-")
        self.workdir = Path(self._tmp.name)

    def harness(self, *, validity: float = 120.0, refresh: float = 30.0) -> H2Harness:
        return H2Harness(
            workdir=self.workdir / f"h-{uuid.uuid4().hex}",
            validity_seconds=validity,
            refresh_interval=refresh,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()


# ---------------------------------------------------------------------------
# H2-a 四组公平性
# ---------------------------------------------------------------------------
class TestH2Fairness(H2Fixture):
    def test_h2a_four_groups_share_request_digest_and_sink_semantics(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            # Identical ActionRequest + digest across all four groups.
            req = fresh_request()
            d = compute_action_digest(req)
            h.service.confirm(request=req, jti="fair-b2", ttl_seconds=300.0, now=0.0)
            for j in ("fair-c0", "fair-c1", "fair-c2"):
                h.service.confirm(request=req, jti=j, ttl_seconds=300.0, now=0.0)
            cred0 = h.service.issue_credential("fair-c0", now=0.0)
            cred1 = h.service.issue_credential("fair-c1", now=0.0)
            cred2 = h.service.issue_credential("fair-c2", now=0.0)
            for c in (cred0, cred1, cred2):
                self.assertEqual(c["payload"]["action_digest"], d)

            r_b2 = h.executor.execute_b2(request=req, jti="fair-b2")
            r_c0 = h.executor.execute_c_offline(group="C0", request=req, credential=cred0)
            r_c1 = h.executor.execute_c_offline(group="C1", request=req, credential=cred1)
            r_c2 = h.executor.execute_c2(request=req, credential=cred2)
            for r in (r_b2, r_c0, r_c1, r_c2):
                self.assertEqual(r.outcome, OUTCOME_EXECUTED)
                self.assertEqual(r.reason, "OK")
            # Shared Sink: 4 distinct jtis -> 4 effects; all use the same store.
            self.assertEqual(h.sink.effect_count(), 4)
            # Same trust anchor + same clock across groups.
            self.assertIs(h.executor.clock, h.clock)
            self.assertEqual(h.executor.trusted_keys, h.trusted_keys)
        finally:
            h.close()

    def test_h2a_same_jti_shared_store_dedups_across_groups(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            req = fresh_request()
            h.service.confirm(request=req, jti="shared-jti", ttl_seconds=300.0, now=0.0)
            cred = h.service.issue_credential("shared-jti", now=0.0)
            r1 = h.executor.execute_b2(request=req, jti="shared-jti")
            r2 = h.executor.execute_c2(request=req, credential=cred)
            self.assertEqual(r1.outcome, OUTCOME_EXECUTED)
            self.assertEqual(r2.outcome, OUTCOME_DEDUP_HIT)
            self.assertEqual(h.sink.effect_count(), 1)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-b 快照抗伪造/抗回滚（含重启）
# ---------------------------------------------------------------------------
class TestH2SnapshotSecurity(H2Fixture):
    def _boot(self, h: H2Harness):
        h.clock.set(0.0)
        return h.executor.bootstrap_online()

    def test_h2b_bad_signature_rejected_cache_unchanged(self):
        h = self.harness()
        try:
            before = self._boot(h)
            evil = Ed25519PrivateKey.generate()
            forged = build_snapshot(
                version=before.high_water_version + 1,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=["x"], signing_key=evil,
            )
            with self.assertRaises(SnapshotValidationError) as ctx:
                h.snapshot_state.accept_candidate(
                    forged, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0)
            self.assertEqual(ctx.exception.code, "SNAPSHOT_SIGNATURE_INVALID")
            after = h.snapshot_state.restore()
            self.assertEqual(after.cached_digest, before.cached_digest)
            self.assertEqual(after.high_water_version, before.high_water_version)
        finally:
            h.close()

    def test_h2b_untrusted_key_issuer_domain_rejected(self):
        h = self.harness()
        try:
            before = self._boot(h)
            variants = [
                dict(key_id="unknown-key"),
                dict(issuer="evil-issuer"),
            ]
            for i, override in enumerate(variants):
                snap = build_snapshot(
                    version=before.high_water_version + 1 + i,
                    issuer=h.service.issuer, key_id=h.service.key_id,
                    generated_at=0.0, valid_from=0.0, valid_until=120.0,
                    revoked_jtis=[], signing_key=h.service.signing_key,
                )
                snap.update(override)
                with self.assertRaises(SnapshotValidationError) as ctx:
                    h.snapshot_state.accept_candidate(
                        snap, trusted_keys=h.trusted_keys,
                        trusted_issuer=h.service.issuer, now=0.0)
                self.assertEqual(ctx.exception.code, "SNAPSHOT_UNTRUSTED")
            # domain tampered after signing
            snap = build_snapshot(
                version=99, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            snap = dict(snap); snap["domain"] = "evil-domain"
            with self.assertRaises(SnapshotValidationError) as ctx:
                h.snapshot_state.accept_candidate(
                    snap, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0)
            self.assertEqual(ctx.exception.code, "SNAPSHOT_UNTRUSTED")
        finally:
            h.close()

    def test_h2b_expired_notyet_malformed_rejected(self):
        h = self.harness()
        try:
            before = self._boot(h)
            cases = []
            exp = dict(generated_at=0.0, valid_from=0.0, valid_until=1.0)
            exp_snap = build_snapshot(
                version=before.high_water_version + 1,
                issuer=h.service.issuer, key_id=h.service.key_id,
                signing_key=h.service.signing_key, revoked_jtis=[], **exp)
            cases.append((exp_snap, 5.0, "SNAPSHOT_EXPIRED"))
            nyv = build_snapshot(
                version=before.high_water_version + 2,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=10.0, valid_from=10.0, valid_until=20.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            cases.append((nyv, 5.0, "SNAPSHOT_NOT_YET_VALID"))
            unsorted = build_snapshot(
                version=before.high_water_version + 3,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            unsorted = dict(unsorted); unsorted["revoked_jtis"] = ["z", "a"]
            cases.append((unsorted, 0.0, "SNAPSHOT_MALFORMED"))
            nonfinite = build_snapshot(
                version=before.high_water_version + 4,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            nonfinite = dict(nonfinite); nonfinite["generated_at"] = float("inf")
            cases.append((nonfinite, 0.0, "SNAPSHOT_MALFORMED"))
            for snap, now, code in cases:
                with self.assertRaises(SnapshotValidationError) as ctx:
                    h.snapshot_state.accept_candidate(
                        snap, trusted_keys=h.trusted_keys,
                        trusted_issuer=h.service.issuer, now=now)
                self.assertEqual(ctx.exception.code, code)
            self.assertEqual(h.snapshot_state.restore().cached_digest, before.cached_digest)
        finally:
            h.close()

    def test_h2b_stale_version_rejected_inprocess(self):
        h = self.harness()
        try:
            before = self._boot(h)
            stale = build_snapshot(
                version=before.high_water_version,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            with self.assertRaises(SnapshotValidationError) as ctx:
                h.snapshot_state.accept_candidate(
                    stale, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0)
            self.assertEqual(ctx.exception.code, "SNAPSHOT_VERSION_STALE")
            self.assertEqual(h.snapshot_state.restore().cached_digest, before.cached_digest)
        finally:
            h.close()

    def test_h2b_restart_restores_hwm_and_rejects_replay(self):
        h = self.harness()
        try:
            self._boot(h)
            jti_b = f"jti-b-{uuid.uuid4().hex}"
            h.service.confirm(request=fresh_request(), jti=jti_b, ttl_seconds=300.0, now=0.0)
            cred_b = h.service.issue_credential(jti_b, now=0.0)
            v11 = build_snapshot(
                version=11, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[jti_b], signing_key=h.service.signing_key)
            h.snapshot_state.accept_candidate(
                v11, trusted_keys=h.trusted_keys, trusted_issuer=h.service.issuer, now=0.0)
            # restart: new store over same db
            same = h.snapshot_state.db_path
            h.snapshot_state = SnapshotStateStore(same)
            h.executor.snapshot_state = h.snapshot_state
            restored = h.snapshot_state.restore()
            self.assertEqual(restored.high_water_version, 11)
            v10 = build_snapshot(
                version=10, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            with self.assertRaises(SnapshotValidationError) as ctx:
                h.snapshot_state.accept_candidate(
                    v10, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0)
            self.assertEqual(ctx.exception.code, "SNAPSHOT_VERSION_STALE")
            # jti-B revocation preserved -> execute rejected
            r = h.executor.execute_c2(request=fresh_request(), credential=cred_b)
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertEqual(r.reason, "REVOKED_BY_SNAPSHOT")
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-c 过期 fail closed、无错误放行
# ---------------------------------------------------------------------------
class TestH2FailClosed(H2Fixture):
    def test_h2c_expired_snapshot_offline_fail_closed(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()  # valid_until=120
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_fetcher.available = False
            h.clock.set(200.0)  # expired
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertEqual(r.reason, "SNAPSHOT_UNAVAILABLE")
            self.assertEqual(r.effects_added, 0)
            self.assertEqual(r.refresh_outcome, "REFRESH_FAILED_FAIL_CLOSED")
        finally:
            h.close()

    def test_h2c_known_revocation_on_stale_cache_never_allowed(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            # Inject a snapshot that lists jti (still valid), accept it.
            jti, cred = h.authorize(ttl=300.0)
            snap = build_snapshot(
                version=2, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[jti], signing_key=h.service.signing_key)
            h.snapshot_state.accept_candidate(
                snap, trusted_keys=h.trusted_keys, trusted_issuer=h.service.issuer, now=0.0)
            # Now simulate failed refresh with stale cache: revocation still listed.
            h.snapshot_fetcher.available = False
            h.clock.set(40.0)  # age>=R -> refresh fails, cache unexpired
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.refresh_outcome, "REFRESH_FAILED_STALE_CONTINUE")
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertEqual(r.reason, "REVOKED_BY_SNAPSHOT")
            self.assertEqual(r.effects_added, 0)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-d1 C2 已知撤销不放行；H2-d2 四组原子消费
# ---------------------------------------------------------------------------
class TestH2RevocationAndConsumption(H2Fixture):
    def test_h2d1_c2_known_revocation_concurrent_rejected(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(2.0)
            h.revoke(jti)
            h.clock.set(40.0)  # trigger refresh to pull revocation
            results: list[TrialResult] = []
            barrier = threading.Barrier(8)

            def worker():
                barrier.wait()
                results.append(h.executor.execute_c2(
                    request=fresh_request(), credential=cred))

            ts = [threading.Thread(target=worker) for _ in range(8)]
            for t in ts: t.start()
            for t in ts: t.join()
            self.assertTrue(all(r.outcome == OUTCOME_REJECTED for r in results))
            self.assertTrue(all(r.reason == "REVOKED_BY_SNAPSHOT" for r in results))
            self.assertEqual(h.sink.effect_count(), 0)
        finally:
            h.close()

    def test_h2d2_four_groups_concurrent_single_effect(self):
        for group in ("B2", "C0", "C1", "C2"):
            with self.subTest(group=group):
                h = self.harness()
                try:
                    h.clock.set(0.0)
                    if group == "C2":
                        h.executor.bootstrap_online()
                    jti, cred = h.authorize(ttl=300.0)
                    results: list[TrialResult] = []
                    barrier = threading.Barrier(8)

                    def worker():
                        barrier.wait()
                        if group == "B2":
                            results.append(h.executor.execute_b2(
                                request=fresh_request(), jti=jti))
                        elif group == "C2":
                            results.append(h.executor.execute_c2(
                                request=fresh_request(), credential=cred))
                        else:
                            results.append(h.executor.execute_c_offline(
                                group=group, request=fresh_request(), credential=cred))

                    ts = [threading.Thread(target=worker) for _ in range(8)]
                    for t in ts: t.start()
                    for t in ts: t.join()
                    executed = sum(1 for r in results if r.outcome == OUTCOME_EXECUTED)
                    dedup = sum(1 for r in results if r.outcome == OUTCOME_DEDUP_HIT)
                    self.assertEqual(executed, 1)
                    self.assertEqual(dedup, 7)
                    self.assertEqual(h.sink.effect_count(), 1)
                finally:
                    h.close()

    def test_h2d2_sequential_replay_single_effect(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            r1 = h.executor.execute_c2(request=fresh_request(), credential=cred)
            r2 = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r1.outcome, OUTCOME_EXECUTED)
            self.assertEqual(r2.outcome, OUTCOME_DEDUP_HIT)
            self.assertEqual(h.sink.effect_count(), 1)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-e B2 查询—消费竞态
# ---------------------------------------------------------------------------
class TestH2B2Race(H2Fixture):
    def test_h2e_b2_query_then_revoke_still_effects_and_records_window(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=300.0)
            seen = {}

            def barrier():
                seen["t_revoke"] = h.revoke(jti)
                h.clock.advance(5)  # model query->consume gap

            r = h.executor.execute_b2(
                request=fresh_request(), jti=jti, barrier_after_query=barrier)
            # ALLOW was returned before revoke -> execution still completes.
            self.assertEqual(r.outcome, OUTCOME_EXECUTED)
            self.assertEqual(r.effects_added, 1)
            self.assertIsNotNone(r.t_query)
            self.assertIsNotNone(r.t_consume)
            window = r.t_consume - r.t_query
            self.assertAlmostEqual(window, 5.0)
            r.b2_race_effect_count = r.effects_added
            self.assertEqual(r.b2_race_effect_count, 1)
            # The service now shows REVOKED (revocation happened at barrier).
            self.assertEqual(h.service.record_state(jti), "REVOKED")
        finally:
            h.close()

    def test_h2e_b2_fail_closed_when_service_unreachable(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=300.0)
            h.b2_tls.shutdown()
            r = h.executor.execute_b2(request=fresh_request(), jti=jti)
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertIn("AUTH_SERVICE_UNREACHABLE", r.reason)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-f 首次信任建立
# ---------------------------------------------------------------------------
class TestH2Bootstrap(H2Fixture):
    def test_h2f_s0_boot_online_establishes_initialized_hwm(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            self.assertEqual(h.snapshot_state.state(), STATE_S0_BOOTSTRAP)
            self.assertFalse(h.snapshot_state.is_initialized())
            restored = h.executor.bootstrap_online()
            self.assertEqual(restored.bootstrap_mode, BOOT_ONLINE)
            self.assertGreaterEqual(restored.high_water_version, 1)
            self.assertTrue(h.snapshot_state.is_initialized())
            self.assertEqual(h.snapshot_state.state(), STATE_S1_RESTORE)
        finally:
            h.close()

    def test_h2f_s0_untrusted_stale_snapshot_rejected(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            stale = build_snapshot(
                version=99, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            with self.assertRaises(SnapshotValidationError) as ctx:
                h.executor.bootstrap_from_untrusted(stale)
            self.assertEqual(ctx.exception.code, "SNAPSHOT_UNTRUSTED")
            self.assertEqual(h.snapshot_state.state(), STATE_S0_BOOTSTRAP)
            self.assertFalse(h.snapshot_state.is_initialized())
        finally:
            h.close()

    def test_h2f_s1_restart_restores_not_rebootstrap(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            first = h.executor.bootstrap_online()
            same = h.snapshot_state.db_path
            h.snapshot_state = SnapshotStateStore(same)
            h.executor.snapshot_state = h.snapshot_state
            self.assertEqual(h.snapshot_state.state(), STATE_S1_RESTORE)
            restored = h.snapshot_state.restore()
            self.assertEqual(restored.high_water_version, first.high_water_version)
            # Cannot re-bootstrap once initialized.
            with self.assertRaises(StateAlreadyInitialized):
                h.executor.bootstrap_online()
        finally:
            h.close()

    def test_h2f_s2_corrupt_fails_closed_no_rebootstrap(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_state.corrupt_digest_for_test()
            h.snapshot_state = SnapshotStateStore(h.snapshot_state.db_path)
            h.executor.snapshot_state = h.snapshot_state
            self.assertEqual(h.snapshot_state.state(), STATE_S2_CORRUPT)
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertEqual(r.reason, "SNAPSHOT_STATE_UNAVAILABLE")
            self.assertEqual(r.effects_added, 0)
            # S2 never auto re-bootstrap; initialized stays true.
            self.assertTrue(h.snapshot_state.is_initialized())
            with self.assertRaises(StateUnavailable):
                h.executor.bootstrap_online()
        finally:
            h.close()

    def test_h2f_boot_offline_records_assumption(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            snap = build_snapshot(
                version=7, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            restored = h.executor.bootstrap_offline(snap)
            self.assertEqual(restored.bootstrap_mode, BOOT_OFFLINE)
            self.assertEqual(restored.high_water_version, 7)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2-g 刷新成本如实计量
# ---------------------------------------------------------------------------
class TestH2RefreshCost(H2Fixture):
    def test_h2g_refresh_success_counted_and_timer_updated(self):
        h = self.harness(refresh=30.0)
        try:
            h.clock.set(0.0)
            boot = h.executor.bootstrap_online()
            self.assertEqual(boot.last_refresh_local, 0.0)
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(40.0)  # age>=R -> refresh
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.refresh_attempts, 1)
            self.assertEqual(r.refresh_outcome, "REFRESH_SUCCESS")
            self.assertTrue(r.snapshot_accepted)
            self.assertEqual(r.t_last_refresh_local, 40.0)
            self.assertIsNotNone(r.refresh_latency_ms)
        finally:
            h.close()

    def test_h2g_refresh_failure_does_not_reset_timer_and_retries(self):
        h = self.harness(refresh=5.0)
        try:
            h.clock.set(0.0)
            boot = h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_fetcher.available = False
            # Two consecutive execs while offline, age>=R both times.
            h.clock.set(10.0)
            r1 = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r1.refresh_outcome, "REFRESH_FAILED_STALE_CONTINUE")
            self.assertEqual(r1.refresh_attempts, 1)
            # timer NOT reset: still 0.0 from bootstrap
            self.assertEqual(r1.t_last_refresh_local, boot.last_refresh_local)
            h.clock.set(11.0)
            r2 = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r2.refresh_outcome, "REFRESH_FAILED_STALE_CONTINUE")
            self.assertEqual(r2.refresh_attempts, 1)  # retried on next exec
            self.assertEqual(r2.t_last_refresh_local, boot.last_refresh_local)
            # actual attempt count = 2 (not 1/R)
            attempts = r1.refresh_attempts + r2.refresh_attempts
            self.assertEqual(attempts, 2)
        finally:
            h.close()

    def test_h2g_actual_request_rate_from_counters_not_one_over_r(self):
        h = self.harness(refresh=5.0)
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_fetcher.available = False
            attempts = 0
            for i in range(10):
                h.clock.set(10.0 + i)  # every exec age>=R, offline -> each attempts
                r = h.executor.execute_c2(request=fresh_request(), credential=cred)
                attempts += r.refresh_attempts
            # 1/R would be at most ~1 over 10 logical seconds; actual is 10.
            self.assertEqual(attempts, 10)
            self.assertGreater(attempts, 1.0 / 5.0)
        finally:
            h.close()

    def test_h2g_payload_size_grows_with_revocation_set(self):
        h = self.harness()
        try:
            h.clock.set(0.0)
            sizes = []
            for K in (1, 10, 100):
                snap = build_snapshot(
                    version=K, issuer=h.service.issuer, key_id=h.service.key_id,
                    generated_at=0.0, valid_from=0.0, valid_until=120.0,
                    revoked_jtis=[f"jti-{i:05d}" for i in range(K)],
                    signing_key=h.service.signing_key)
                sizes.append(snapshot_payload_bytes(snap))
            self.assertTrue(sizes[0] < sizes[1] < sizes[2])
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2.1-R1 HWM 与缓存快照版本一致性（用户独立核查阻断项）
# ---------------------------------------------------------------------------
class TestH2R1HwmCacheConsistency(H2Fixture):
    def test_r1_hwm_only_corruption_is_s2_and_c2_fails_closed(self):
        """只篡改 HWM、保持 cached_snapshot 与 digest 不变；重开必须为 S2，
        C2 拒绝执行、无副作用、不自动重 bootstrap。"""
        h = self.harness()
        try:
            h.clock.set(0.0)
            boot = h.executor.bootstrap_online()  # v1, hwm=1
            jti, cred = h.authorize(ttl=300.0)
            # Damage ONLY the persisted HWM (1 -> 5), leaving cache v1 + digest
            # byte-for-byte intact. A digest-only check cannot detect this.
            h.snapshot_state.corrupt_hwm_only_for_test(5)
            h.snapshot_state = SnapshotStateStore(h.snapshot_state.db_path)
            h.executor.snapshot_state = h.snapshot_state
            self.assertEqual(h.snapshot_state.state(), STATE_S2_CORRUPT)
            with self.assertRaises(StateUnavailable):
                h.snapshot_state.restore()
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.outcome, OUTCOME_REJECTED)
            self.assertEqual(r.reason, "SNAPSHOT_STATE_UNAVAILABLE")
            self.assertEqual(r.effects_added, 0)
            # S2 never auto re-bootstrap; initialized stays true.
            self.assertTrue(h.snapshot_state.is_initialized())
            with self.assertRaises(StateUnavailable):
                h.executor.bootstrap_online()
        finally:
            h.close()

    def test_r1_corrupt_hwm_cannot_be_bypassed_by_mid_version_snapshot(self):
        """损坏的 HWM 若被当作可信，版本 3~4 快照可越过 v1 缓存并重放旧撤销集；
        一致性检查后 S2 直接 fail closed，任何候选都不得进入 accept_candidate。"""
        h = self.harness()
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()  # cache v1, hwm=1
            h.snapshot_state.corrupt_hwm_only_for_test(5)
            h.snapshot_state = SnapshotStateStore(h.snapshot_state.db_path)
            h.executor.snapshot_state = h.snapshot_state
            # A validly-signed v4 (> corrupt hwm 5? no: 4<5, but > original 1)
            # would previously find cache v1 with hwm read as 5 -> version 4
            # <= 5 rejected; use v6 to show accept path is blocked by state(),
            # independent of version arithmetic.
            v6 = build_snapshot(
                version=6, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key)
            with self.assertRaises(StateUnavailable):
                h.snapshot_state.accept_candidate(
                    v6, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0)
            self.assertEqual(h.snapshot_state.state(), STATE_S2_CORRUPT)
        finally:
            h.close()

    def test_r1_hwm_cache_version_consistent_after_normal_refresh(self):
        """正常 bootstrap 与成功刷新后 hwm==cached.version，S1 可恢复（不误报 S2）。"""
        h = self.harness()
        try:
            h.clock.set(0.0)
            boot = h.executor.bootstrap_online()
            self.assertEqual(boot.high_water_version, boot.cached_snapshot["version"])
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(40.0)  # age>=R -> refresh success
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.refresh_outcome, "REFRESH_SUCCESS")
            st = h.snapshot_state.restore()
            self.assertEqual(st.high_water_version, st.cached_snapshot["version"])
            self.assertEqual(h.snapshot_state.state(), STATE_S1_RESTORE)
        finally:
            h.close()


# ---------------------------------------------------------------------------
# H2.1-R2 关键字段与刷新聚合指标（用户独立核查阻断项）
# ---------------------------------------------------------------------------
class TestH2R2FieldsAndAggregates(H2Fixture):
    def test_r2_c2_trial_records_generated_age_and_bootstrap_version(self):
        """C2 适用 trial 必须获得真实数值，而非 NA/NULL。"""
        h = self.harness(refresh=30.0)
        try:
            h.clock.set(0.0)
            boot = h.executor.bootstrap_online()  # generated_at=0, hwm=1
            jti, cred = h.authorize(ttl=300.0)
            # age<R -> NO_REFRESH_NEEDED, uses bootstrap snapshot (generated_at=0)
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            self.assertEqual(r.refresh_outcome, "NO_REFRESH_NEEDED")
            self.assertEqual(r.t_snapshot_generated, 0.0)
            self.assertEqual(r.age_at_exec, 0.0 - 0.0)
            self.assertEqual(r.bootstrap_snapshot_version, boot.cached_snapshot["version"])
            self.assertEqual(r.bootstrap_snapshot_version, 1)

            # age>=R -> refresh success; generated_at comes from actual new
            # snapshot, age recomputed with updated t_last_refresh_local.
            h.clock.set(40.0)
            jti2, cred2 = h.authorize(ttl=300.0)
            r2 = h.executor.execute_c2(request=fresh_request(), credential=cred2)
            self.assertEqual(r2.refresh_outcome, "REFRESH_SUCCESS")
            self.assertIsNotNone(r2.t_snapshot_generated)
            self.assertEqual(r2.t_snapshot_generated, 40.0)  # actual snapshot field
            self.assertEqual(r2.age_at_exec, r2.t_exec_attempt - r2.t_last_refresh_local)
            self.assertEqual(r2.bootstrap_snapshot_version, 1)  # never rewritten
        finally:
            h.close()

    def test_r2_non_c2_and_unborn_events_stay_na(self):
        """非适用组 / 未发生事件保持 NA，不得伪造数值。"""
        h = self.harness()
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=300.0)
            r = h.executor.execute_c_offline(
                group="C0", request=fresh_request(), credential=cred)
            self.assertEqual(r.group, "C0")
            self.assertIsNone(r.age_at_exec)
            self.assertIsNone(r.bootstrap_snapshot_version)
            self.assertIsNone(r.t_snapshot_generated)
        finally:
            h.close()

    @staticmethod
    def _metric_row(scenario, group, arm, outcome, attempts,
                    t_last=None, instance=None):
        """Synthetic §5-style row for the pure metric function."""
        row = {
            "scenario_id": scenario, "group": group, "arm": arm,
            "refresh_outcome": outcome, "refresh_attempts": attempts,
            "actual_outcome": "EXECUTED",
        }
        if t_last is not None:
            row["t_last_refresh_local"] = t_last
        if instance is not None:
            row["_instance_id"] = instance
        return row

    def test_r2_refresh_metrics_per_unit_not_merged(self):
        """R2.1-A：不同 scenario/group/arm 的计数与请求率不得混合。"""
        rows = [
            self._metric_row("M01", "C2", "base", "NO_REFRESH_NEEDED", 0),
            self._metric_row("M04", "C2", "base", "REFRESH_SUCCESS", 1, 40.0, "i1"),
            self._metric_row("M05", "C2", "base",
                             "REFRESH_FAILED_STALE_CONTINUE", 2, None, "i2"),
            # candidate-only row and a non-C2 row are out of scope
            self._metric_row("M09", "C2", "expired", "NA", 0),
            self._metric_row("M01", "C0", "base", "NA", 0),
        ]
        windows = {
            ("M01", "C2", "base"): (0.0, 0.5),
            ("M04", "C2", "base"): (0.0, 2.0),
            ("M05", "C2", "base"): (0.0, 4.0),
        }
        m = compute_refresh_metrics(rows, windows)
        self.assertEqual(m["unit_count"], 3)
        self.assertEqual(m["applicable_trial_count"], 3)
        by_key = {(u["scenario_id"], u["group"], u["arm"]): u for u in m["units"]}
        self.assertEqual(by_key[("M01", "C2", "base")]["refresh_attempt_count"], 0)
        self.assertEqual(by_key[("M04", "C2", "base")]["refresh_attempt_count"], 1)
        self.assertEqual(by_key[("M04", "C2", "base")]["refresh_success_count"], 1)
        self.assertEqual(by_key[("M05", "C2", "base")]["refresh_attempt_count"], 2)
        self.assertEqual(by_key[("M05", "C2", "base")]["refresh_failure_count"], 1)
        # Each rate uses its OWN first->last span: 1/2 and 2/4, not (1+2)/(2+4).
        self.assertEqual(
            by_key[("M04", "C2", "base")]["actual_refresh_request_rate"], 0.5)
        self.assertEqual(
            by_key[("M05", "C2", "base")]["actual_refresh_request_rate"], 0.5)
        # A real observation of zero attempts with a valid wall is 0.0, not NA.
        self.assertEqual(
            by_key[("M01", "C2", "base")]["actual_refresh_request_rate"], 0.0)
        # No merged cross-unit rate is emitted at the top level.
        self.assertNotIn("actual_refresh_request_rate", m)

    def test_r22_first_last_span_is_the_denominator(self):
        """R2.2：请求率 = 单元实际尝试数 / 该单元首末 trial 墙钟跨度。"""
        rows = [self._metric_row(
            "M14", "C2", "intermittent_pathA", "REFRESH_SUCCESS", 1, 40.0, "c2i")]
        key = ("M14", "C2", "intermittent_pathA")
        unit = compute_refresh_metrics(rows, {key: (2.0, 4.0)})["units"][0]
        self.assertEqual(unit["observation_wall_seconds"], 2.0)
        self.assertEqual(unit["actual_refresh_request_rate"], 0.5)  # 1/(4-2)
        # No unit-scoped endpoints -> NA, never a whole-run duration or 0.
        missing = compute_refresh_metrics(rows, {})["units"][0]
        self.assertEqual(missing["observation_wall_seconds"], NA_NO_WALL)
        self.assertEqual(missing["actual_refresh_request_rate"], NA_NO_WALL)

    def test_r2_cross_harness_times_never_form_interval(self):
        """R2.1-B：不同 Harness（逻辑时钟重启）的时间不得算成刷新间隔。"""
        key = ("M14", "C2", "intermittent_pathA")
        rows = [
            self._metric_row("M14", "C2", "intermittent_pathA",
                             "REFRESH_SUCCESS", 1, 40.0, "harness-A"),
            self._metric_row("M14", "C2", "intermittent_pathA",
                             "REFRESH_SUCCESS", 1, 10.0, "harness-B"),
        ]
        unit = compute_refresh_metrics(rows, {key: (0.0, 3.0)})["units"][0]
        self.assertEqual(unit["refresh_success_count"], 2)
        # 40 and 10 are not on one timeline; a 30s (or 40s) diff would be invented.
        self.assertEqual(unit["successful_refresh_interval"], NA_NO_CONTINUOUS_CLOCK)
        self.assertNotIsInstance(unit["successful_refresh_interval"], dict)

    def test_r2_same_instance_interval_is_computed(self):
        """同一执行实例内的相邻成功刷新仍须能算出真实间隔（机制未退化为常量 NA）。"""
        key = ("M14", "C2", "intermittent_pathA")
        rows = [
            self._metric_row("M14", "C2", "intermittent_pathA",
                             "REFRESH_SUCCESS", 1, 10.0, "harness-A"),
            self._metric_row("M14", "C2", "intermittent_pathA",
                             "REFRESH_SUCCESS", 1, 30.0, "harness-A"),
        ]
        unit = compute_refresh_metrics(rows, {key: (0.0, 2.0)})["units"][0]
        self.assertEqual(
            unit["successful_refresh_interval"]["adjacent_diffs_s"], [20.0])

    def test_r2_missing_metrics_stay_na_never_zero(self):
        """不可计算必须显式 NA，不得记 0。"""
        empty = compute_refresh_metrics([], {})
        self.assertEqual(empty["refresh_attempt_count"], NA_NO_APPLICABLE)
        self.assertEqual(empty["actual_refresh_request_rate"], NA_NO_APPLICABLE)
        self.assertEqual(empty["units"], [])

        rows = [self._metric_row("M01", "C2", "base", "NO_REFRESH_NEEDED", 0)]
        no_wall = compute_refresh_metrics(rows, None)["units"][0]
        self.assertEqual(no_wall["observation_wall_seconds"], NA_NO_WALL)
        self.assertEqual(no_wall["actual_refresh_request_rate"], NA_NO_WALL)
        self.assertNotEqual(no_wall["actual_refresh_request_rate"], 0)

        key = ("M04", "C2", "base")
        one = compute_refresh_metrics(
            [self._metric_row("M04", "C2", "base", "REFRESH_SUCCESS", 1, 0.0, "i")],
            {key: (0.0, 1.0)})["units"][0]
        self.assertEqual(one["successful_refresh_interval"], NA_NO_SUCCESS)

    def test_r22_runner_records_first_start_last_end(self):
        """Runner 必须记录单元首末 trial 的 perf_counter 时刻，而非累计活跃时间。"""
        from run_experiment import Runner
        r = Runner(workdir=self.workdir / "runner-unit-span", n=1)
        r.m01(0)  # four groups, one unit each
        self.assertGreaterEqual(len(r.unit_observation), 4)
        for key, (first, last) in r.unit_observation.items():
            self.assertGreater(last, first, key)
        self.assertIn(("M01_legal_exec", "C2", "base"), r.unit_observation)
        self.assertIn(("M01_legal_exec", "B2", "base"), r.unit_observation)
        # The whole-run diagnostic is a separate value, not used per unit.
        self.assertIsNone(r.run_wall_seconds)

    def test_r22_interleaved_unit_time_is_in_span(self):
        """A 的首末 trial 之间有 B 执行 8s：A 的跨度是 last-first（含该间隔）。"""
        from run_experiment import Runner
        r = Runner(workdir=self.workdir / "runner-interleave", n=1)
        a = ("S_A", "C2", "base")
        b = ("S_B", "C2", "base")
        rows = [
            self._metric_row("S_A", "C2", "base", "NO_REFRESH_NEEDED", 1),
            self._metric_row("S_A", "C2", "base", "NO_REFRESH_NEEDED", 1),
        ]
        b_row = self._metric_row("S_B", "C2", "base", "NO_REFRESH_NEEDED", 0)
        # Each emit consumes one perf_counter value; _trial_t0 is set manually
        # to emulate the trial start after harness setup.
        with patch("run_experiment.time.perf_counter", side_effect=[1.0, 3.0, 10.0]):
            r._instance_id = "i"
            r._trial_t0 = 0.0
            r.emit(rows[0], "EXECUTED")            # A first trial: (0, 1)
            r._trial_t0 = 2.0
            r.emit(b_row, "EXECUTED")              # B trial:      (2, 3)
            r._trial_t0 = 9.0
            r.emit(rows[1], "EXECUTED")            # A last trial: (0, 10)

        self.assertEqual(r.unit_observation[a], (0.0, 10.0))
        self.assertEqual(r.unit_observation[b], (2.0, 3.0))
        by = {u["scenario_id"]: u for u in
              compute_refresh_metrics(r.rows, r.unit_observation)["units"]}
        # A: 2 attempts / 10s span, NOT 2/2s summed active time.
        self.assertEqual(by["S_A"]["observation_wall_seconds"], 10.0)
        self.assertEqual(by["S_A"]["refresh_attempt_count"], 2)
        self.assertEqual(by["S_A"]["actual_refresh_request_rate"], 0.2)
        # B has its own independent window: 0 attempts / 1s = 0.0.
        self.assertEqual(by["S_B"]["observation_wall_seconds"], 1.0)
        self.assertEqual(by["S_B"]["actual_refresh_request_rate"], 0.0)

    def test_r22_unit_spans_are_independent(self):
        """不同单元的 first/last 互不影响，请求率各按自身跨度计算。"""
        rows = [
            self._metric_row("A", "C2", "x", "REFRESH_SUCCESS", 1, 1.0, "i1"),
            self._metric_row("B", "C2", "y", "REFRESH_SUCCESS", 3, 2.0, "i2"),
        ]
        obs = {("A", "C2", "x"): (0.0, 10.0), ("B", "C2", "y"): (2.0, 5.0)}
        by = {(u["scenario_id"], u["arm"]): u for u in
              compute_refresh_metrics(rows, obs)["units"]}
        self.assertEqual(by[("A", "x")]["observation_wall_seconds"], 10.0)
        self.assertEqual(by[("A", "x")]["actual_refresh_request_rate"], 0.1)
        self.assertEqual(by[("B", "y")]["observation_wall_seconds"], 3.0)
        self.assertEqual(by[("B", "y")]["actual_refresh_request_rate"], 1.0)

    def test_r22_invalid_window_is_na_not_zero(self):
        """缺失/非有限/非正的端点一律 NA，不返回 0。"""
        rows = [self._metric_row("M01", "C2", "base", "NO_REFRESH_NEEDED", 1)]
        key = ("M01", "C2", "base")
        for window in (None, (5.0, 5.0), (8.0, 3.0),
                       (float("nan"), 1.0), (0.0, float("inf"))):
            obs = {} if window is None else {key: window}
            u = compute_refresh_metrics(rows, obs)["units"][0]
            self.assertEqual(u["observation_wall_seconds"], NA_NO_WALL)
            self.assertEqual(u["actual_refresh_request_rate"], NA_NO_WALL)


if __name__ == "__main__":
    unittest.main()
