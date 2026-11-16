"""Unit tests for the D11.1 minimal budget-quota relation.

T01-T15 are the fixed cases from the task package. T16-T23 add boundary and
type coverage (floats, strings, None, empty containers, huge ints, and direct
checks of is_valid_uint32).
"""

import unittest

from quota_relation import (
    MAX_BUDGET,
    check_quota_relation,
    is_valid_uint32,
)


class CheckQuotaRelationTests(unittest.TestCase):
    """Fixed acceptance table T01-T15 plus extra edge cases."""

    # ---- fixed acceptance cases -------------------------------------------
    def test_t01_normal_within_quota(self):
        # 60 + 20 = 80 <= 100
        self.assertTrue(check_quota_relation(100, 20, 60))

    def test_t02_exactly_at_cap(self):
        # 60 + 40 = 100 == quota
        self.assertTrue(check_quota_relation(100, 40, 60))

    def test_t03_over_cap(self):
        # 60 + 41 = 101 > 100
        self.assertFalse(check_quota_relation(100, 41, 60))

    def test_t04_last_unit(self):
        # 99 + 1 = 100 == quota
        self.assertTrue(check_quota_relation(100, 1, 99))

    def test_t05_one_over_after_full(self):
        # 100 + 1 = 101 > 100
        self.assertFalse(check_quota_relation(100, 1, 100))

    def test_t06_zero_cost_rejected(self):
        self.assertFalse(check_quota_relation(100, 0, 60))

    def test_t07_zero_quota_rejected(self):
        self.assertFalse(check_quota_relation(0, 1, 0))

    def test_t08_negative_cost_rejected(self):
        self.assertFalse(check_quota_relation(100, -1, 0))

    def test_t09_negative_spent_rejected(self):
        self.assertFalse(check_quota_relation(100, 1, -1))

    def test_t10_spent_above_uint32_rejected(self):
        # u = 2**32 is out of uint32 range (MAX is 2**32 - 1).
        self.assertFalse(check_quota_relation(100, 1, 2**32))

    def test_t11_max_quota_exact_fit(self):
        # (2**32-2) + 1 = 2**32-1 == MAX_BUDGET == quota
        self.assertTrue(check_quota_relation(MAX_BUDGET, 1, MAX_BUDGET - 1))

    def test_t12_max_quota_wraparound_must_not_pass(self):
        # (2**32-2) + 2 = 2**32 which, if wrapped mod 2**32, would be 0 and
        # wrongly appear <= quota. Integer semantics must reject it.
        self.assertFalse(check_quota_relation(MAX_BUDGET, 2, MAX_BUDGET - 1))

    def test_t13_bool_quota_rejected(self):
        self.assertFalse(check_quota_relation(True, 1, 0))

    def test_t14_bool_cost_rejected(self):
        self.assertFalse(check_quota_relation(100, False, 0))

    def test_t15_bool_spent_rejected(self):
        self.assertFalse(check_quota_relation(100, 1, True))

    # ---- extra boundary / type cases --------------------------------------
    def test_t16_float_cost_rejected(self):
        self.assertFalse(check_quota_relation(100, 1.5, 60))

    def test_t17_string_quota_rejected(self):
        self.assertFalse(check_quota_relation("100", 1, 0))

    def test_t18_none_inputs_rejected(self):
        self.assertFalse(check_quota_relation(None, 1, 0))
        self.assertFalse(check_quota_relation(100, None, 0))
        self.assertFalse(check_quota_relation(100, 1, None))

    def test_t19_empty_container_inputs_rejected(self):
        self.assertFalse(check_quota_relation([], 1, 0))
        self.assertFalse(check_quota_relation(100, (), 0))
        self.assertFalse(check_quota_relation(100, 1, {}))

    def test_t20_very_large_integer_rejected(self):
        huge = 2**200
        self.assertFalse(check_quota_relation(huge, 1, 0))
        self.assertFalse(check_quota_relation(100, huge, 0))
        self.assertFalse(check_quota_relation(100, 1, huge))

    def test_t21_negative_quota_rejected(self):
        self.assertFalse(check_quota_relation(-1, 1, 0))

    def test_t22_cost_above_uint32_rejected(self):
        self.assertFalse(check_quota_relation(MAX_BUDGET, 2**32, 0))

    def test_t23_is_valid_uint32_boundaries(self):
        self.assertTrue(is_valid_uint32(0))
        self.assertTrue(is_valid_uint32(MAX_BUDGET))
        self.assertFalse(is_valid_uint32(-1))
        self.assertFalse(is_valid_uint32(MAX_BUDGET + 1))
        self.assertFalse(is_valid_uint32(True))
        self.assertFalse(is_valid_uint32(False))
        self.assertFalse(is_valid_uint32(1.0))

    def test_t24_max_budget_constant(self):
        self.assertEqual(MAX_BUDGET, 2**32 - 1)


if __name__ == "__main__":
    unittest.main()
