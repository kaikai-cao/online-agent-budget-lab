"""D11.1 minimal budget-quota relation.

This is a PLAIN Python reference model of the integer relation

    0 <= u,  1 <= c,  u + c <= Q

with all values fixed to 32-bit unsigned integers. It is NOT a zero-knowledge
proof and NOT a verifier: it takes u as an ordinary argument and simply checks
the arithmetic. Privacy / Halo2 are deliberately out of scope for D11.1.
"""

MAX_BUDGET = 2**32 - 1


def is_valid_uint32(value: int) -> bool:
    """Check whether value is a valid uint32, rejecting bool."""
    # bool is a subclass of int in Python; reject it explicitly.
    if isinstance(value, bool):
        return False
    if not isinstance(value, int):
        return False
    return 0 <= value <= MAX_BUDGET


def check_quota_relation(
    quota: int,
    cost: int,
    spent_before: int,
) -> bool:
    """Check the D11.1 budget state-transition relation.

    Requires:
        1 <= quota      <= MAX_BUDGET
        1 <= cost       <= MAX_BUDGET
        0 <= spent_before <= MAX_BUDGET
        spent_before + cost <= quota

    All three inputs must be genuine ints (bool rejected), within uint32
    range. Returns True only when every constraint holds.

    NOTE: This is a deterministic reference check over Python integers, not a
    zero-knowledge verifier. spent_before (u) is passed in the clear here.
    """
    if not is_valid_uint32(quota) or not is_valid_uint32(cost) or not is_valid_uint32(spent_before):
        return False

    # quota >= 1 and cost >= 1 (is_valid_uint32 already allows 0, which we reject here).
    if quota < 1 or cost < 1:
        return False

    # Explicit integer addition; no modular wraparound. Both operands are
    # uint32, sum may exceed MAX_BUDGET and is compared directly against quota.
    return spent_before + cost <= quota
