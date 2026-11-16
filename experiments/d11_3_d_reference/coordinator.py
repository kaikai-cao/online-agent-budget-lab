"""Python reference Coordinator: registration, replay protection, atomic CAS.

The flow mirrors D11.3-C but with a single process lock instead of SQLite:
check instance/registration/Q/P, check state and nullifier, verify the proof,
then RECHECK state and nullifier under the same lock and commit atomically.
The double check is intentional: proof verification may take time, and another
request may commit while it runs.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model import (
    INSTANCE_ROWS,
    BudgetState,
    is_field_element,
    is_valid_uint32,
)
from .proof_verifier import ProofRejected, ProofVerifier
from .registration import RegistrationAuthorization, RegistrationError


class CoordinatorError(Exception):
    """Base class for rejected transitions/registrations."""


class InvalidPublicInput(CoordinatorError):
    pass


class InvalidRegistration(CoordinatorError):
    pass


class DuplicateRegistration(CoordinatorError):
    pass


class UnregisteredInstance(CoordinatorError):
    pass


class QuotaMismatch(CoordinatorError):
    pass


class PolicyMismatch(CoordinatorError):
    pass


class StaleCommitment(CoordinatorError):
    pass


class NullifierReused(CoordinatorError):
    pass


class ProofVerificationFailed(CoordinatorError):
    pass


@dataclass(frozen=True)
class TransitionReceipt:
    budget_id: int
    period_id: int
    version: int
    new_commitment: int
    nullifier: int


class Coordinator:
    """In-memory reference Coordinator; safe for concurrent threads."""

    def __init__(
        self,
        issuer: Ed25519PublicKey,
        verifier: ProofVerifier,
        *,
        fault_hook: Callable[[], None] | None = None,
    ) -> None:
        self._issuer = issuer
        self._verifier = verifier
        self._states: dict[tuple[int, int], BudgetState] = {}
        self._lock = threading.RLock()
        # Test-only failure injection. Called after all rechecks but BEFORE any
        # mutation; it cannot bypass proof verification.
        self._fault_hook = fault_hook

    def register(self, authorization: RegistrationAuthorization) -> None:
        try:
            authorization.verify(self._issuer)
        except RegistrationError as exc:
            raise InvalidRegistration(str(exc)) from exc
        fields = authorization.fields
        key = (fields.budget_id, fields.period_id)
        with self._lock:
            if key in self._states:
                raise DuplicateRegistration("instance already registered")
            self._states[key] = BudgetState(
                budget_id=fields.budget_id,
                period_id=fields.period_id,
                quota=fields.quota,
                policy=fields.policy,
                current_commitment=fields.initial_commitment,
                version=0,
                authorization=authorization.encode(),
            )

    def get_state(self, budget_id: int, period_id: int) -> BudgetState | None:
        """Return an isolated copy for assertions; never a live state object."""
        with self._lock:
            state = self._states.get((budget_id, period_id))
            if state is None:
                return None
            return BudgetState(
                budget_id=state.budget_id,
                period_id=state.period_id,
                quota=state.quota,
                policy=state.policy,
                current_commitment=state.current_commitment,
                version=state.version,
                authorization=state.authorization,
                used_nullifiers=set(state.used_nullifiers),
            )

    def seed_used_nullifier(self, budget_id: int, period_id: int, nullifier: int) -> None:
        """TEST-ONLY: mark N used while C_old is still current.

        This isolates the nullifier check just as the Rust C replay test seeds
        `used_nullifiers` directly. It is not part of the transition path.
        """
        with self._lock:
            state = self._states.get((budget_id, period_id))
            if state is None:
                raise UnregisteredInstance("cannot seed an unregistered instance")
            state.used_nullifiers.add(nullifier)

    def submit_transition(
        self, proof: object, instance: Sequence[int]
    ) -> TransitionReceipt:
        # 1. Public-input format and uint32 domain for Q and c.
        row = tuple(instance)
        if len(row) != INSTANCE_ROWS or not all(is_field_element(v) for v in row):
            raise InvalidPublicInput("public instance must contain 8 field elements")
        quota, cost = row[2], row[3]
        if not is_valid_uint32(quota) or quota < 1:
            raise InvalidPublicInput("Q must be a uint32 with Q >= 1")
        if not is_valid_uint32(cost) or cost < 1:
            raise InvalidPublicInput("c must be a uint32 with c >= 1")
        budget_id, period_id = row[0], row[1]
        c_old, c_new, nullifier, policy = row[4], row[5], row[6], row[7]

        # 2. Instance must be registered; take a snapshot so the rest of the
        # pre-checks do not hold the lock while proof verification runs.
        with self._lock:
            state = self._states.get((budget_id, period_id))
            if state is None:
                raise UnregisteredInstance("budget instance is not registered")
            snapshot = (
                state.quota,
                state.policy,
                state.current_commitment,
                set(state.used_nullifiers),
                state.authorization,
            )
        registered_quota, registered_policy, current, used, authorization_bytes = snapshot

        # 3. Re-verify the stored issuer authorization.
        try:
            stored = RegistrationAuthorization.decode(authorization_bytes)
            stored.verify(self._issuer)
        except RegistrationError as exc:
            raise InvalidRegistration(str(exc)) from exc
        if (
            stored.fields.budget_id != budget_id
            or stored.fields.period_id != period_id
            or stored.fields.quota != registered_quota
            or stored.fields.policy != registered_policy
        ):
            raise InvalidRegistration("stored authorization does not match the instance")

        # 4. Q and P must equal the registered values (D11.3-A scheme B).
        if quota != registered_quota:
            raise QuotaMismatch("public Q differs from registered Q")
        if policy != registered_policy:
            raise PolicyMismatch("public P differs from registered P")

        # 5-6. Pre-checks. They are repeated under the lock after verification.
        if c_old != current:
            raise StaleCommitment("C_old is not the current commitment")
        if nullifier in used:
            raise NullifierReused("nullifier already used")

        # 7. Proof verification (test stand-in in this package).
        try:
            self._verifier.verify(proof, row)
        except ProofRejected as exc:
            raise ProofVerificationFailed(str(exc)) from exc

        # 8-9. Recheck and commit under one lock.
        with self._lock:
            state = self._states.get((budget_id, period_id))
            if state is None:
                raise UnregisteredInstance("instance disappeared during verification")
            if state.current_commitment != c_old:
                raise StaleCommitment("C_old became stale during proof verification")
            if nullifier in state.used_nullifiers:
                raise NullifierReused("nullifier was used during proof verification")
            if self._fault_hook is not None:
                self._fault_hook()
            # All mutations happen only after every check and the fault hook.
            state.used_nullifiers.add(nullifier)
            state.current_commitment = c_new
            state.version += 1
            version = state.version

        return TransitionReceipt(
            budget_id=budget_id,
            period_id=period_id,
            version=version,
            new_commitment=c_new,
            nullifier=nullifier,
        )
