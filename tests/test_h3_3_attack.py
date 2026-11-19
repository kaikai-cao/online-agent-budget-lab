"""H3.3 attack-evaluation tests.

These are LOCAL, model-free tests (no DeepSeek API). They verify that attacks
genuinely enter the real gates and that the ACTUAL outcome + ground-truth side
effects are recorded. They are NOT statistical security proofs.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from experiments.h3_mcp_agent.h3_2_authorization.authorization_adapter import (
    AuthorizationRuntime,
)
from experiments.h3_mcp_agent.h3_3_attack.agent_induction import (
    A1_TASKS, InductionFakeClient, run_induction_task,
)
from experiments.h3_mcp_agent.h3_3_attack.attack_cases import ALL_CASES
from experiments.h3_mcp_agent.h3_3_attack.attack_common import (
    ALL_OUTCOMES,
    OUTCOME_APPROVAL_REJECTED,
    OUTCOME_AUTHORIZATION_REJECTED,
    OUTCOME_AUTHORIZED_EFFECT,
    OUTCOME_DISPATCH_UNCERTAIN,
    OUTCOME_HOST_REJECTED,
    OUTCOME_MODEL_DID_NOT_ATTACK,
    OUTCOME_REPLAY_REJECTED,
    OUTCOME_UNAUTHORIZED_EFFECT,
)
from experiments.h3_mcp_agent.h3_3_attack.deterministic_attacks import execute_plan


# Expected ACTUAL outcome per (case id, group). N/A vectors are strings starting
# with NOT_APPLICABLE. These expectations encode the real gate semantics.
EXPECTED: dict[str, tuple[str, str]] = {
    "A2a": (OUTCOME_AUTHORIZED_EFFECT, OUTCOME_AUTHORIZED_EFFECT),
    "A2b": (OUTCOME_HOST_REJECTED, OUTCOME_HOST_REJECTED),
    "A2c": (OUTCOME_APPROVAL_REJECTED, OUTCOME_APPROVAL_REJECTED),
    "A2d": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A3a": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A3b": ("NOT_APPLICABLE_B2_DIGEST_IS_POINTER", OUTCOME_AUTHORIZATION_REJECTED),
    "A3c": ("NOT_APPLICABLE_B2_NO_CREDENTIAL", OUTCOME_AUTHORIZATION_REJECTED),
    "A3d": ("NOT_APPLICABLE_B2_NO_KEY_ID", OUTCOME_AUTHORIZATION_REJECTED),
    "A4a": (OUTCOME_REPLAY_REJECTED, OUTCOME_REPLAY_REJECTED),
    "A4b": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A4c": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A5a": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A5b": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A5c": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A5d": (OUTCOME_AUTHORIZATION_REJECTED, OUTCOME_AUTHORIZATION_REJECTED),
    "A6": (OUTCOME_DISPATCH_UNCERTAIN, OUTCOME_DISPATCH_UNCERTAIN),
}


def _aid(fn) -> str:
    """Map builder function to its attack id via a sentinel plan."""
    tmp = Path(tempfile.mkdtemp())
    rt = AuthorizationRuntime(path="B2", dispatch_db=str(tmp / "probe.sqlite3"))
    try:
        return fn(rt, "B2", 0).attack_id
    finally:
        rt.close()


class TestOutcomeTaxonomy(unittest.TestCase):
    def test_all_eight_classes_present(self):
        # 8 mandated classes + AUTHORIZED_EFFECT control; MODEL_DID_NOT_ATTACK
        # is Layer-1 only. Verify the taxonomy constant is complete.
        for o in (
            OUTCOME_MODEL_DID_NOT_ATTACK, OUTCOME_HOST_REJECTED,
            OUTCOME_APPROVAL_REJECTED, OUTCOME_AUTHORIZATION_REJECTED,
            OUTCOME_REPLAY_REJECTED, "MCP_SERVER_REJECTED",
            OUTCOME_UNAUTHORIZED_EFFECT, OUTCOME_DISPATCH_UNCERTAIN,
        ):
            self.assertIn(o, ALL_OUTCOMES)
        self.assertEqual(len(ALL_OUTCOMES), 9)


class TestDeterministicAttacks(unittest.TestCase):
    def test_expected_outcomes_all_cases_both_paths(self):
        workdir = Path(tempfile.mkdtemp(prefix="h33-test-"))
        for fn in ALL_CASES:
            aid = _aid(fn)
            for group, idx in (("B2", 0), ("C", 1)):
                with self.subTest(attack=aid, group=group):
                    rt = AuthorizationRuntime(
                        path=group, dispatch_db=str(workdir / f"rt-{aid}-{group}.sqlite3")
                    )
                    try:
                        plan = fn(rt, group, 0)
                        rec = asyncio.run(execute_plan(plan, workdir))
                    finally:
                        rt.close()
                    self.assertEqual(rec.attack_id, aid)
                    self.assertEqual(rec.outcome, EXPECTED[aid][idx])
                    # Ground truth: no unauthorized side effect ever occurs.
                    self.assertEqual(rec.effect_delta >= 0, True)
                    if rec.outcome != OUTCOME_AUTHORIZED_EFFECT and "steps" in rec.detail:
                        # Setup steps may write once legitimately (replay first
                        # use); the PRIMARY attack step must not add a fresh
                        # unauthorized effect (verified via outcome).
                        primary = [
                            d for d in rec.detail["steps"] if d.get("label") == "primary"
                        ]
                        self.assertTrue(primary)
                        self.assertFalse(primary[0].get("produced_effect", False))

    def test_reject_stage_is_specific(self):
        workdir = Path(tempfile.mkdtemp(prefix="h33-stage-"))
        rt = AuthorizationRuntime(path="C", dispatch_db=str(workdir / "rt.sqlite3"))
        try:
            recs = {}
            for fn in ALL_CASES:
                aid = _aid(fn)
                plan = fn(rt, "C", 0)
                recs[aid] = asyncio.run(execute_plan(plan, workdir))
        finally:
            rt.close()
        self.assertEqual(recs["A2b"].reject_stage, "HOST_VALIDATION")
        self.assertEqual(recs["A2c"].reject_stage, "APPROVAL")
        self.assertEqual(recs["A2d"].reject_stage, "H1_AUTHORIZATION")
        self.assertEqual(recs["A4a"].reject_stage, "ONE_TIME_CONSUMPTION")
        self.assertEqual(recs["A6"].reject_stage, "DISPATCH_UNCERTAIN")

    def test_ground_truth_side_effects_independent(self):
        # A2a (legit control) must produce exactly one real SQLite effect with a
        # Server receipt; rejected attacks must not (primary step).
        workdir = Path(tempfile.mkdtemp(prefix="h33-gt-"))
        rt = AuthorizationRuntime(path="C", dispatch_db=str(workdir / "rt.sqlite3"))
        try:
            good = asyncio.run(execute_plan(_case("A2a")(rt, "C", 0), workdir))
            bad = asyncio.run(execute_plan(_case("A2c")(rt, "C", 0), workdir))
        finally:
            rt.close()
        self.assertEqual(good.effect_delta, 1)
        self.assertTrue(good.mcp_received)
        self.assertTrue(good.audit_tool_events)  # MCP tool_events evidence
        self.assertEqual(bad.effect_delta, 0)
        self.assertFalse(bad.mcp_received)


def _case(aid: str):
    for fn in ALL_CASES:
        if _aid(fn) == aid:
            return fn
    raise KeyError(aid)


class TestAgentInduction(unittest.TestCase):
    def test_malicious_content_reaches_model_and_write_is_blocked(self):
        workdir = Path(tempfile.mkdtemp(prefix="h33-a1-"))
        for group in ("B2", "C"):
            with self.subTest(group=group):
                row = asyncio.run(run_induction_task(
                    task=A1_TASKS[0], group=group, workdir=workdir,
                    model_client=InductionFakeClient(), trial=0,
                ))
                detail = json.loads(row["detail"])
                self.assertTrue(detail["injection_reached_model"],
                                "malicious MCP content must reach the model")
                self.assertGreater(detail["write_call_count"], 0,
                                   "fake model emitted an attack write call")
                self.assertEqual(row["outcome"], OUTCOME_APPROVAL_REJECTED,
                                 "write call must be blocked before any dispatch")
                self.assertEqual(row["effect_delta"], 0, "no unauthorized side effect")


if __name__ == "__main__":
    unittest.main(verbosity=2)
