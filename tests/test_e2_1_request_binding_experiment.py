"""E2.1 — Request-Binding security-effectiveness experiment tests.

These tests validate that the experiment harness itself is logically sound:
they do NOT assert the "expected" security outcome as a substitute for running
the experiment.  They verify each mechanism behaves as designed so the raw CSV
data produced by run_experiment.py is trustworthy.
"""

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in (str(REPO / "src"), str(REPO / "tests"),
          str(REPO / "experiments" / "e2_1_request_binding")):
    if p not in sys.path:
        sys.path.insert(0, p)

from test_e1_system import (  # noqa: E402
    _SystemHarness, ARGS, BUDGET_ID_N, PERIOD_ID_N,
)
from online_budget.e1_runtime import E1FailClosed  # noqa: E402
from online_budget.executor import ToolExecutionDenied  # noqa: E402
from online_budget.executor_authorization import ExecutorAuthorizationError  # noqa: E402
from online_budget.executor_authorization import (  # noqa: E402
    issue_executor_authorization, verify_executor_authorization,
)
from online_budget.tool_binding import arguments_digest  # noqa: E402
from online_budget.e1_runtime import PendingExecution  # noqa: E402

import run_experiment as exp  # noqa: E402


class _Case(unittest.TestCase):
    """Minimal TestCase providing addCleanup for the harness."""

    def runTest(self) -> None:  # pragma: no cover - container only
        pass


class E21ExperimentLogicTests(unittest.TestCase):
    """Group-isolation checks for G1 / G2 (no real E1 service needed)."""

    def setUp(self) -> None:
        self.case = _Case()
        self.h = _SystemHarness(self.case)

    def tearDown(self) -> None:
        # Trigger all registered cleanups from the shim case.
        for fn, a, kw in reversed(self.case._cleanups):  # noqa: SLF001
            try:
                fn(*a, **kw)
            except Exception:  # noqa: BLE001
                pass

    def _reg(self) -> exp.StatefulEffectRegistry:
        return exp.StatefulEffectRegistry()

    # -- G1 -----------------------------------------------------------------
    def test_01_g1_schema_valid_substitution_not_rejected_by_schema(self):
        reg = self._reg()
        rec = exp.run_g1(self.h, reg, scenario=exp.SCENARIO_SUBSTITUTE,
                         trial=0, operation_id="op-e21-t01")
        # Schema-valid value substitution passes static ACL + schema and
        # actually reaches the tool -> unauthorized effect is observable.
        self.assertTrue(rec["accepted"], rec)
        self.assertEqual(rec["rejection_stage"], "")
        self.assertEqual(rec["dispatch_count"], 1)
        self.assertEqual(rec["unauthorized_effects"], 1)
        self.assertIn(exp.ATTACK_INVOICE, rec["effects"])

    def test_02_g1_benign_accepted(self):
        reg = self._reg()
        rec = exp.run_g1(self.h, reg, scenario=exp.SCENARIO_BENIGN,
                         trial=0, operation_id="op-e21-t02")
        self.assertTrue(rec["accepted"], rec)
        self.assertEqual(rec["unauthorized_effects"], 0)

    # -- G2 -----------------------------------------------------------------
    def test_03_g2_v1_has_no_argument_digest_and_cannot_stop_substitution(self):
        reg = self._reg()
        rec = exp.run_g2(self.h, reg, self.h.issuer,
                         scenario=exp.SCENARIO_SUBSTITUTE, trial=0,
                         operation_id="op-e21-t03")
        self.assertEqual(rec["authorization_version"], "1", rec)
        self.assertTrue(rec["accepted"], rec)
        self.assertEqual(rec["dispatch_count"], 1)
        self.assertEqual(rec["unauthorized_effects"], 1)
        self.assertIn(exp.ATTACK_INVOICE, rec["effects"])

    def test_04_g2_v1_authorization_payload_lacks_arguments_digest(self):
        ctx = self.h.new_context("op-e21-t04", BUDGET_ID_N, PERIOD_ID_N, register=False)
        auth = issue_executor_authorization(
            self.h.issuer, issuer_id=self.h.issuer_id,
            authorization_id="auth-t04", online_lease_grant=self.h.lease,
            execution_grant=ctx.execution, gateway_id=self.h.gateway_id,
            coordinator_id=self.h.coordinator_id, executor_id=self.h.executor_id,
            executor_public_key=self.h.executor_key.public_key(),
            tool_name="invoice_review", tool_schema_hash=self.h.schema_hash,
            issued_at=self.h.now - 20, expires_at=self.h.now + 1800,
        )
        self.assertEqual(auth.payload["version"], 1)
        self.assertNotIn("arguments_digest", auth.payload)

    def test_05_v2_authorization_stops_substitution_at_verify(self):
        # A v2 authorization signed for BENIGN must reject a v1-style verify
        # against the substituted arguments digest.
        ctx = self.h.new_context("op-e21-t05", BUDGET_ID_N, PERIOD_ID_N, register=False)
        auth_v2 = issue_executor_authorization(
            self.h.issuer, issuer_id=self.h.issuer_id,
            authorization_id="auth-t05", online_lease_grant=self.h.lease,
            execution_grant=ctx.execution, gateway_id=self.h.gateway_id,
            coordinator_id=self.h.coordinator_id, executor_id=self.h.executor_id,
            executor_public_key=self.h.executor_key.public_key(),
            tool_name="invoice_review", tool_schema_hash=self.h.schema_hash,
            issued_at=self.h.now - 20, expires_at=self.h.now + 1800,
            arguments=exp.BENIGN_ARGUMENTS,
        )
        self.assertEqual(auth_v2.payload["version"], 2)
        with self.assertRaises(ExecutorAuthorizationError):
            verify_executor_authorization(
                auth_v2, self.h.issuer.public_key(),
                online_lease_grant=self.h.lease, execution_grant=ctx.execution,
                gateway_id=self.h.gateway_id, coordinator_id=self.h.coordinator_id,
                executor_id=self.h.executor_id, tool_name="invoice_review",
                tool_schema_hash=self.h.schema_hash, now=self.h.now,
                expected_arguments_digest=arguments_digest(exp.ATTACK_ARGUMENTS),
                canonicalization_version=auth_v2.payload["canonicalization_version"],
                require_argument_binding=True,
            )


class E21FullE1AttackTests(unittest.TestCase):
    """G3 checks against the real four-gate chain and Rust e1_service."""

    def setUp(self) -> None:
        self.case = _Case()
        self.h = _SystemHarness(self.case)
        self.reg = exp.StatefulEffectRegistry()
        self.ex = self.h.executor(registry=self.reg)

    def tearDown(self) -> None:
        for fn, a, kw in reversed(self.case._cleanups):  # noqa: SLF001
            try:
                fn(*a, **kw)
            except Exception:  # noqa: BLE001
                pass

    def _ctx(self, tag: str, register: bool = False, budget: int = BUDGET_ID_N):
        # Reuse the scope registered by the harness at init (BUDGET_ID_N,
        # PERIOD_ID_N); only operation_id is unique. register=True with a
        # different budget_id would trigger D11 SCOPE_CONFLICT.
        return self.h.new_context(f"op-e21-{tag}", budget, PERIOD_ID_N, register=register)

    # -- C1 -----------------------------------------------------------------
    def test_06_c1_before_admission_no_effect_no_admission(self):
        ctx = self._ctx("c1", register=False)
        ctx.arguments = dict(exp.ATTACK_ARGUMENTS)
        d10_before = self.h.d10_state()
        with self.assertRaises((E1FailClosed, ExecutorAuthorizationError, ValueError)):
            self.h.run(ctx)
        self.assertEqual(self.h.d10_state(), d10_before)
        self.assertEqual(self.reg.dispatch_count, 0)
        self.assertEqual(self.reg.unauthorized_effects(), 0)

    # -- C2 -----------------------------------------------------------------
    def test_07_c2_after_admission_denied_but_admission_committed(self):
        ctx = self._ctx("c2")
        pending = self.h.run(ctx)
        self.assertEqual(self.h.d11_state(ctx)["version"], 1)  # admission committed
        forged = dataclasses.replace(pending, arguments=dict(exp.ATTACK_ARGUMENTS))
        with self.assertRaises(ToolExecutionDenied):
            self.h.execute(self.ex, self.h, forged, ctx)
        # No tool side effect despite committed admission; honest Saga window.
        self.assertEqual(self.reg.dispatch_count, 0)
        self.assertEqual(self.reg.unauthorized_effects(), 0)
        self.assertIsNone(self.ex.store.get_receipt(ctx.operation_id))
        self.assertEqual(self.h.d11_state(ctx)["version"], 1)  # stays committed

    # -- G3 benign ----------------------------------------------------------
    def test_08_g3_benign_executes_with_single_dispatch(self):
        ctx = self._ctx("benign")
        pending = self.h.run(ctx)
        receipt = self.h.execute(self.ex, self.h, pending, ctx)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(self.reg.dispatch_count, 1)
        self.assertEqual(self.reg.unauthorized_effects(), 0)

    # -- exact replay -------------------------------------------------------
    def test_09_exact_replay_returns_original_receipt_no_second_dispatch(self):
        ctx = self._ctx("replay")
        pending = self.h.run(ctx)
        r1 = self.h.execute(self.ex, self.h, pending, ctx)
        first = self.reg.dispatch_count
        r2 = self.h.execute(self.ex, self.h, pending, ctx)
        self.assertEqual(r1, r2)
        self.assertEqual(self.reg.dispatch_count, first)
        self.assertEqual(first, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
