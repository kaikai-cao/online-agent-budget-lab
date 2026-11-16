"""Protocol data structures and field/integer semantics for D11.3-D.

Field encoding mirrors the Rust D11.3-C crate exactly: Pallas base field
`Fp`, canonical 32-byte little-endian representation. Validity is checked
against the real Pallas modulus, not merely "is a positive Python int".

Commitments (`C_old`, `C_new`) and nullifiers (`N`) are treated as OPAQUE field
elements here. This module deliberately does NOT compute them with SHA-256 or
any other substitute: the Poseidon opening relations belong to the frozen
D11.3-B.0/B.1 Rust circuit, and a Python stand-in must not be presented as
compatible with it. The reference model validates state-machine semantics and
the two budget equations; commitment opening is out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Pallas base field modulus (halo2_proofs 0.4 / pasta_curves 0.6, Fp).
PALLAS_FP_MODULUS = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
FIELD_BYTES = 32
MAX_UINT32 = 2**32 - 1

# Same domain prefix as d11_3_c_coordinator::registration::REGISTRATION_DOMAIN.
REGISTRATION_DOMAIN = b"D11.3-C-REGISTRATION-v1"

# Public instance rows of the frozen B.1 circuit.
INSTANCE_ROWS = 8


class FieldEncodingError(ValueError):
    """Raised for a non-canonical or out-of-range field representation."""


def is_field_element(value: Any) -> bool:
    """True only for a genuine int in [0, PallasModulus). `bool` is rejected."""
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 <= value < PALLAS_FP_MODULUS


def require_field_element(value: Any, name: str) -> int:
    if not is_field_element(value):
        raise FieldEncodingError(
            f"{name} must be an int in [0, PallasModulus); got {value!r}"
        )
    return value


def is_valid_uint32(value: Any) -> bool:
    """Same integer semantics as D11.1: genuine int, bool rejected, 0..2^32-1."""
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 <= value <= MAX_UINT32


def require_uint32(value: Any, name: str) -> int:
    if not is_valid_uint32(value):
        raise ValueError(f"{name} must be a uint32 int; got {value!r}")
    return value


def fp_to_bytes(value: int) -> bytes:
    """Canonical 32-byte little-endian encoding (Fp::to_repr() equivalent)."""
    require_field_element(value, "field element")
    return value.to_bytes(FIELD_BYTES, "little")


def fp_from_bytes(data: bytes) -> int:
    """Decode a canonical 32-byte little-endian representation.

    Rejects wrong lengths and encodings >= modulus, matching Rust
    `Fp::from_repr(...).into()` in d11_3_c_coordinator.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) != FIELD_BYTES:
        raise FieldEncodingError(
            f"field encoding must be exactly {FIELD_BYTES} bytes"
        )
    value = int.from_bytes(data, "little")
    if value >= PALLAS_FP_MODULUS:
        raise FieldEncodingError("non-canonical field encoding: value >= modulus")
    return value


@dataclass(frozen=True)
class StateWitness:
    """Private witness of one state transition; mirrors B.1 `StateWitness`.

    All five budget numbers are enforced as uint32 with Q >= 1 and c >= 1.
    The two relations are checked with plain Python integer addition: no
    modular reduction, so a 2^32 wraparound cannot be mistaken for success.
    """

    budget_id: int
    period_id: int
    quota: int
    cost: int
    u_old: int
    u_new: int
    slack: int
    r_old: int
    r_new: int
    nf_secret: int
    policy: int

    def __post_init__(self) -> None:
        for name in ("budget_id", "period_id", "r_old", "r_new", "nf_secret", "policy"):
            require_field_element(getattr(self, name), name)
        for name in ("quota", "cost", "u_old", "u_new", "slack"):
            require_uint32(getattr(self, name), name)
        if self.quota < 1:
            raise ValueError("quota must be >= 1")
        if self.cost < 1:
            raise ValueError("cost must be >= 1")

    def check_relations(self) -> None:
        """Enforce u_old + c = u_new and u_new + s = Q over the integers."""
        if self.u_old + self.cost != self.u_new:
            raise ValueError("u_old + c != u_new")
        if self.u_new + self.slack != self.quota:
            raise ValueError("u_new + s != Q")


@dataclass(frozen=True)
class Transition:
    """A transition witness plus its opaque commitment/nullifier values."""

    witness: StateWitness
    c_old: int
    c_new: int
    nullifier: int

    def __post_init__(self) -> None:
        for name in ("c_old", "c_new", "nullifier"):
            require_field_element(getattr(self, name), name)

    def public_inputs(self) -> tuple[int, ...]:
        """Eight public rows: [budget_id, period_id, Q, c, C_old, C_new, N, P]."""
        w = self.witness
        return (
            w.budget_id,
            w.period_id,
            w.quota,
            w.cost,
            self.c_old,
            self.c_new,
            self.nullifier,
            w.policy,
        )


@dataclass
class BudgetState:
    """Per-instance persisted state of the reference Coordinator."""

    budget_id: int
    period_id: int
    quota: int
    policy: int
    current_commitment: int
    version: int
    authorization: bytes
    used_nullifiers: set[int] = field(default_factory=set)
