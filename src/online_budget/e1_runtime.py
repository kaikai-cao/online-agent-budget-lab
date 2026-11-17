"""E1.4 additive cross-layer Runtime: D10 admission + D11 state transition.

This module is the Python-side orchestrator frozen in
``docs/D11.3_E1_IMPLEMENTATION_PLAN.md`` §E.1 steps 1-5. It deliberately stops
after both budgets have committed and returns a *pending execution context* for
E1.5. It never calls ``executor.execute()`` and never dispatches a tool: the
frozen D10 executor still verifies the ordinary admission digest, so executing
here would bypass the final cross-layer binding gate that E1.5 owns.

Trust boundary:

* ``c`` is computed by :mod:`metering` from an Issuer-signed policy. The caller
  cannot supply it and this module never overrides it.
* ``D_E`` is the flat frozen object digest (E1.0 §6.1 / E1.1 §C.5), computed with
  :func:`e1_encoding.digest_object` -- NOT the nested ``canonical_digest`` form.
* Real Halo2 proof generation and verification happen only in the Rust service;
  Python checks field consistency but is never a proof verifier.
* If D11 submission is indeterminate, recovery follows E1.0 §B.6.1: restart the
  service, query ``get_operation`` with the original keys, and either restore
  the committed receipt or re-submit with the ORIGINAL attestation and ``D_E``
  (regenerating the proof only because the new process has new proving keys).
  An expired attestation fails closed with the charged-but-uncommitted state
  reported explicitly. No tool dispatch occurs on any failure path.
* The explicit ``STATE_CONFLICT`` / ``STORE_ERROR`` codes (E1.0 §B.5) are NOT
  treated as definitive refusals: on both the first submit and the re-submit
  path they trigger an idempotent ``get_operation`` lookup. A consistent hit
  is restored, a miss or uncertain lookup fails closed. All other explicit
  rejections (e.g. ``PROOF_INVALID``) fail closed without any re-submit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import e1_encoding as enc
from .canonical import public_key_bytes
from .cross_layer_bridge import BridgeUnavailable, ServiceError
from .executor_authorization import (
    ExecutorAuthorization,
    verify_executor_authorization,
)
from .metering import (
    BudgetScope,
    MeteringAttestation,
    MeteringPolicy,
    VerifiedMeteringPolicy,
    compute_metering_quote_digest,
    issue_metering_attestation,
    verify_metering_attestation,
    verify_metering_policy,
)
from .tool_binding import (
    ToolCallBinding,
    build_tool_call_binding,
    snapshot_arguments,
)

# Frozen domain prefix (E1.0 §6.1 / E1.1 §C.5). Distinct from every other domain.
CROSS_LAYER_ADMISSION_DOMAIN = "agent-e0-cross-layer-admission-v1"

# E1.0 §B.5: these two codes do NOT prove the transition failed. The store may
# already hold a committed receipt, so the original operation must be queried
# by idempotent lookup (§B.6) before any fail-closed conclusion. Every other
# explicit service rejection (PROOF_INVALID, ATTESTATION_INVALID,
# IDEMPOTENCY_CONFLICT, ...) remains a definitive refusal -> fail closed.
IDEMPOTENT_QUERY_CODES = frozenset({"STATE_CONFLICT", "STORE_ERROR"})


class E1RuntimeError(RuntimeError):
    """Base failure: the pending operation is NOT safe to dispatch."""


class E1FailClosed(E1RuntimeError):
    """A trust/binding/expiry failure; no fake receipt, no dispatch."""


class E1SubmitIndeterminate(E1RuntimeError):
    """D11 submission outcome stayed unknown after one recovery attempt."""

    def __init__(self, message: str, *, operation_id: str) -> None:
        self.operation_id = operation_id
        super().__init__(message)


@dataclass(frozen=True)
class PendingExecution:
    """Both budgets committed; ready for the E1.5 final binding gate.

    No field here authorizes dispatch by itself. E1.5 must recompute ``D_E``
    from the same attestation, verify the Coordinator signature on the D11
    receipt, and check all five equivalence relations before tool execution.
    """

    operation_id: str
    tool_name: str
    arguments: dict[str, Any]
    binding: dict[str, Any]
    metering_attestation: dict[str, Any]
    metering_quote_digest: str
    cross_layer_digest: str
    d10_budget_receipt: dict[str, Any]
    d11_transition_receipt: dict[str, Any]
    recovered: bool = False
    d10_charged: bool = True
    d11_committed: bool = True


@dataclass(frozen=True)
class _AdmissionArtifacts:
    """Pre-D11 artifacts that MUST be reused unchanged during Saga recovery."""

    operation_id: str
    binding_digest: str
    metering_attestation: MeteringAttestation
    metering_quote_digest: str
    cross_layer_digest: str
    d10_budget_receipt: dict[str, Any]
    prove_witness: dict[str, Any]
    instance: list[str]


# --------------------------------------------------------------------------- #
# D_E
# --------------------------------------------------------------------------- #
def compute_cross_layer_admission_digest(
    binding_digest: str,
    executor_authorization_digest: str,
    metering_quote_digest: str,
) -> str:
    """``D_E = digest({domain, binding, authorization, metering quote})``.

    Flat object digest (E1.1 ``digest_object``), never the nested
    ``canonical_digest(domain, payload)`` form. All three inputs must be
    ``sha256:`` digests; anything else fails closed.
    """
    for value, name in (
        (binding_digest, "binding_digest"),
        (executor_authorization_digest, "executor_authorization_digest"),
        (metering_quote_digest, "metering_quote_digest"),
    ):
        if not enc.is_sha256(value):
            raise E1FailClosed(f"{name} must be a sha256 digest")
    return enc.digest_object(
        {
            "domain": CROSS_LAYER_ADMISSION_DOMAIN,
            "binding_digest": binding_digest,
            "executor_authorization_digest": executor_authorization_digest,
            "metering_quote_digest": metering_quote_digest,
        }
    )


# --------------------------------------------------------------------------- #
# Witness assembly (trusted prover state + attestation c)
# --------------------------------------------------------------------------- #
def _build_prove_witness(
    *, budget_scope: BudgetScope, cost: int, prover_state: Mapping[str, int]
) -> dict[str, Any]:
    """Build the B.1 prove payload; ``cost`` comes only from the attestation."""
    budget_scope.validate()
    Q = budget_scope.Q
    enc.u32_to_fp_hex(Q)  # strict uint32 (bool/in-range), fail closed
    if isinstance(cost, bool) or not isinstance(cost, int) or not (1 <= cost <= enc.MAX_UINT32):
        raise E1FailClosed("attestation c is not a nonzero uint32")
    u_old = prover_state["u_old"]
    for name in ("u_old", "r_old", "r_new", "nf_secret"):
        value = prover_state[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise E1FailClosed(f"prover_state.{name} must be a non-bool non-negative int")
    if any(prover_state[n] >= enc.PALLAS_FP_MODULUS for n in ("r_old", "r_new", "nf_secret")):
        raise E1FailClosed("prover_state scalar out of Pallas Fp range")
    u_new = u_old + cost
    slack = Q - u_new
    if u_new > enc.MAX_UINT32 or slack < 0 or slack > enc.MAX_UINT32:
        raise E1FailClosed("weighted consumption exceeds registered quota Q")
    return {
        "budget_id": budget_scope.budget_id,
        "period_id": budget_scope.period_id,
        "quota": Q,
        "cost": cost,
        "u_old": u_old,
        "u_new": u_new,
        "slack": slack,
        "r_old": enc.fp_to_hex(prover_state["r_old"]),
        "r_new": enc.fp_to_hex(prover_state["r_new"]),
        "nf_secret": enc.fp_to_hex(prover_state["nf_secret"]),
        "policy": budget_scope.P,
    }


def _check_prove_result(
    result: Mapping[str, Any], *, witness: Mapping[str, Any], cost: int
) -> tuple[str, list[str]]:
    """Field-level sanity of the prove response; never proof verification."""
    proof_b64 = result.get("proof_b64")
    instance = result.get("instance")
    if not isinstance(proof_b64, str) or not proof_b64:
        raise E1FailClosed("prove response missing proof_b64")
    try:
        enc.proof_b64_decode(proof_b64)
    except enc.E1EncodingError as exc:
        raise E1FailClosed(f"prove response proof_b64 is not canonical base64: {exc}") from exc
    if not isinstance(instance, list) or len(instance) != 8 or not all(
        isinstance(row, str) for row in instance
    ):
        raise E1FailClosed("prove response instance must be 8 Fp hex rows")
    try:
        if instance[0] != witness["budget_id"] or instance[1] != witness["period_id"]:
            raise E1FailClosed("prove instance budget_id/period_id mismatch")
        if enc.fp_hex_to_u32(instance[2]) != witness["quota"]:
            raise E1FailClosed("prove instance Q mismatch")
        if enc.fp_hex_to_u32(instance[3]) != cost:
            raise E1FailClosed("prove instance c mismatch")
        if instance[7] != witness["policy"]:
            raise E1FailClosed("prove instance P mismatch")
    except enc.E1EncodingError as exc:
        raise E1FailClosed(f"prove instance is not a canonical uint32 Fp: {exc}") from exc
    return proof_b64, list(instance)


# --------------------------------------------------------------------------- #
# Receipt consistency (source authentication belongs to E1.5)
# --------------------------------------------------------------------------- #
def _check_transition_receipt(
    receipt: Mapping[str, Any], artifacts: _AdmissionArtifacts, *, budget_scope: BudgetScope
) -> None:
    expected = {
        "operation_id": artifacts.operation_id,
        "binding_digest": artifacts.binding_digest,
        "metering_quote_digest": artifacts.metering_quote_digest,
        "budget_id": budget_scope.budget_id,
        "period_id": budget_scope.period_id,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise E1FailClosed(f"D11 receipt {key} does not match the submitted operation")
    if not enc.is_sha256(receipt.get("transition_digest")):
        raise E1FailClosed("D11 receipt transition_digest is not a sha256 digest")
    if not isinstance(receipt.get("coordinator_signature"), str) or not receipt[
        "coordinator_signature"
    ]:
        raise E1FailClosed("D11 receipt is not signed")


# --------------------------------------------------------------------------- #
# Recovery: E1.0 §B.5 / §B.6 idempotent lookup on ambiguous service errors
# --------------------------------------------------------------------------- #
def _restore_from_idempotent_lookup(
    *,
    bridge: Any,
    artifacts: _AdmissionArtifacts,
    budget_scope: BudgetScope,
    code: str,
) -> dict[str, Any]:
    """Resolve ``STATE_CONFLICT`` / ``STORE_ERROR`` via ``get_operation`` (§B.5).

    These codes do not prove the transition failed: the store may already hold
    a committed receipt. Query with the ORIGINAL operation keys. A consistent
    hit is returned as the authoritative stored receipt; a miss fails closed
    (no fake receipt); an uncertain query leaves the state unknown and is
    reported as :class:`E1SubmitIndeterminate`. This function never re-signs,
    never re-charges D10 and never dispatches.
    """
    try:
        stored = bridge.get_operation(
            operation_id=artifacts.operation_id,
            binding_digest=artifacts.binding_digest,
            metering_quote_digest=artifacts.metering_quote_digest,
        )
    except Exception as exc:  # the query itself is uncertain -> state unknown
        raise E1SubmitIndeterminate(
            f"D11 {code}: idempotent lookup outcome unknown: {type(exc).__name__}",
            operation_id=artifacts.operation_id,
        ) from exc
    if stored is None:
        raise E1FailClosed(
            f"D11 {code}: get_operation found no committed receipt; "
            "fail closed, no fake receipt, no dispatch"
        )
    # A hit must still match the original operation fields. A mismatch is an
    # IDEMPOTENCY_CONFLICT (§B.6), fail closed rather than trusting the store.
    _check_transition_receipt(stored, artifacts, budget_scope=budget_scope)
    return dict(stored)


def _pending_from_stored_receipt(
    *,
    artifacts: _AdmissionArtifacts,
    receipt: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    binding_payload: dict[str, Any],
) -> PendingExecution:
    """Wrap an idempotently-restored receipt as a pending (never dispatched) op."""
    return PendingExecution(
        operation_id=artifacts.operation_id,
        tool_name=tool_name,
        arguments=arguments,
        binding=binding_payload,
        metering_attestation=artifacts.metering_attestation.as_dict(),
        metering_quote_digest=artifacts.metering_quote_digest,
        cross_layer_digest=artifacts.cross_layer_digest,
        d10_budget_receipt=artifacts.d10_budget_receipt,
        d11_transition_receipt=receipt,
        recovered=True,
    )


# --------------------------------------------------------------------------- #
# Recovery: §B.6.1 rules 2-5
# --------------------------------------------------------------------------- #
def _recover_submit(
    *,
    bridge: Any,
    artifacts: _AdmissionArtifacts,
    budget_scope: BudgetScope,
    now: int,
) -> PendingExecution:
    """Handle an indeterminate D11 submit after D10 already charged c=1 op.

    Never re-signs the attestation, never re-runs D10 admission, never forges a
    receipt, and never dispatches a tool.
    """
    bridge.restart()
    stored = bridge.get_operation(
        operation_id=artifacts.operation_id,
        binding_digest=artifacts.binding_digest,
        metering_quote_digest=artifacts.metering_quote_digest,
    )
    if stored is not None:
        _check_transition_receipt(stored, artifacts, budget_scope=budget_scope)
        return PendingExecution(
            operation_id=artifacts.operation_id,
            tool_name="",  # filled by caller-level wrapper below
            arguments={},
            binding={},
            metering_attestation=artifacts.metering_attestation.as_dict(),
            metering_quote_digest=artifacts.metering_quote_digest,
            cross_layer_digest=artifacts.cross_layer_digest,
            d10_budget_receipt=artifacts.d10_budget_receipt,
            d11_transition_receipt=dict(stored),
            recovered=True,
        )
    # D11 did not commit. The original attestation is frozen; if it has expired
    # we must fail closed and report the one-sided (D10-charged) state.
    att = artifacts.metering_attestation.attestation
    if now >= att["expires_at"]:
        raise E1FailClosed(
            "D10 already charged + D11 not committed + original Attestation expired: "
            "fail closed, no re-issue, no dispatch"
        )
    # New process regenerated proving/verifying keys; do NOT present the old
    # proof to the new process. Regenerate with the ORIGINAL attestation's c.
    new_result = bridge.prove(artifacts.prove_witness)
    proof_b64, instance = _check_prove_result(
        new_result, witness=artifacts.prove_witness, cost=att["c"]
    )
    if instance != artifacts.instance:
        # Public inputs must stay identical (same K/C_old, same c, same scope).
        raise E1FailClosed("regenerated proof has different public inputs")
    try:
        receipt = bridge.submit_transition_e1(
            {
                "proof_b64": proof_b64,
                "instance": instance,
                "metering_attestation": artifacts.metering_attestation.as_dict(),
                "metering_quote_digest": artifacts.metering_quote_digest,
                "operation_id": artifacts.operation_id,
                "binding_digest": artifacts.binding_digest,
            }
        )
    except ServiceError as exc:
        if exc.code in IDEMPOTENT_QUERY_CODES:
            # Same §B.5 rule on the re-submit path: a store-level conflict or
            # error may hide an already-committed operation. Query before
            # concluding; never re-sign or re-charge D10.
            stored = _restore_from_idempotent_lookup(
                bridge=bridge,
                artifacts=artifacts,
                budget_scope=budget_scope,
                code=exc.code,
            )
            return _pending_from_stored_receipt(
                artifacts=artifacts,
                receipt=stored,
                tool_name="",  # filled by caller-level wrapper below
                arguments={},
                binding_payload={},
            )
        # Other explicit refusals are definitive; report and stop.
        raise E1FailClosed(
            f"D11 re-submit rejected ({exc.code}): {exc.message}; "
            "D10 charged, D11 not committed"
        ) from exc
    except Exception as exc:  # transport uncertainty again -> do not guess
        raise E1SubmitIndeterminate(
            f"D11 re-submit outcome unknown after restart: {type(exc).__name__}",
            operation_id=artifacts.operation_id,
        ) from exc
    _check_transition_receipt(receipt, artifacts, budget_scope=budget_scope)
    return PendingExecution(
        operation_id=artifacts.operation_id,
        tool_name="",
        arguments={},
        binding={},
        metering_attestation=artifacts.metering_attestation.as_dict(),
        metering_quote_digest=artifacts.metering_quote_digest,
        cross_layer_digest=artifacts.cross_layer_digest,
        d10_budget_receipt=artifacts.d10_budget_receipt,
        d11_transition_receipt=dict(receipt),
        recovered=True,
    )


# --------------------------------------------------------------------------- #
# Main entry point
# --------------------------------------------------------------------------- #
def run_tool_call_e1(
    *,
    bridge: Any,
    gateway_adapter: Any,
    executor: Any,
    online_lease_grant: Any,
    execution_grant: Mapping[str, Any],
    executor_id: str,
    executor_authorization: ExecutorAuthorization | Mapping[str, Any],
    metering_policy: MeteringPolicy,
    issuer_public_key: Ed25519PublicKey,
    budget_scope: BudgetScope,
    prover_state: Mapping[str, int],
    tool_name: str,
    arguments: Mapping[str, Any],
    now: int,
    issued_at: int,
    expires_at: int,
) -> PendingExecution:
    """Run frozen steps 1-5 and return a pending (not executed) operation.

    ``now`` and the attestation validity window come from trusted runtime
    configuration, never from planner-supplied data. ``executor`` is used only
    for its registry/schema and ``prepare_tool_call`` precheck; ``execute`` is
    never called.
    """
    if isinstance(executor_authorization, Mapping):
        authorization = ExecutorAuthorization.from_dict(executor_authorization)
    else:
        authorization = executor_authorization

    # -- 1. precheck: snapshot, binding, Executor Authorization v2, schema ----
    safe_arguments = snapshot_arguments(arguments)
    schema_hash = executor.registry.schema_hash(tool_name)
    operation_id = execution_grant["operation_id"]
    binding = build_tool_call_binding(
        operation_id=operation_id,
        gateway_id=gateway_adapter.client.gateway_id,
        coordinator_id=gateway_adapter.coordinator_id,
        online_lease_grant=online_lease_grant,
        execution_grant=execution_grant,
        tool_name=tool_name,
        tool_schema_hash=schema_hash,
        arguments=safe_arguments,
        executor_id=executor_id,
    )
    authorized_key = verify_executor_authorization(
        authorization,
        issuer_public_key,
        online_lease_grant=online_lease_grant,
        execution_grant=execution_grant,
        gateway_id=gateway_adapter.client.gateway_id,
        coordinator_id=gateway_adapter.coordinator_id,
        executor_id=executor_id,
        tool_name=tool_name,
        tool_schema_hash=schema_hash,
        now=now,
        expected_arguments_digest=binding.arguments_digest,
        canonicalization_version=binding.canonicalization_version,
        require_argument_binding=True,
    )
    if public_key_bytes(authorized_key) != public_key_bytes(executor.executor_private_key.public_key()):
        raise E1FailClosed("Executor Authorization names a different Executor key")
    safe_arguments = executor.prepare_tool_call(
        binding=binding,
        arguments=safe_arguments,
        online_lease_grant=online_lease_grant,
        execution_grant=execution_grant,
        executor_authorization=authorization.as_dict(),
    )
    if budget_scope.global_budget_id != binding.global_budget_id or (
        budget_scope.lease_id != binding.lease_id
    ):
        raise E1FailClosed("budget_scope D10 identifiers do not match the binding")

    # -- 2. Metering Attestation: c from verified Issuer policy only ----------
    verified_policy: VerifiedMeteringPolicy | None = verify_metering_policy(
        metering_policy, issuer_public_key
    )
    if verified_policy is None:
        raise E1FailClosed("Metering Policy signature is not trusted")
    attestation = issue_metering_attestation(
        executor_private_key=executor.executor_private_key,
        executor_id=executor_id,
        operation_id=operation_id,
        binding=binding,
        authorization=authorization,
        tool_name=tool_name,
        tool_schema_hash=schema_hash,
        budget_scope=budget_scope,
        verified_policy=verified_policy,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    quote_digest = compute_metering_quote_digest(attestation)
    if not verify_metering_attestation(
        attestation,
        executor.executor_private_key.public_key(),
        expected_binding=binding,
        expected_authorization_digest=authorization.authorization_digest,
        expected_budget_scope=budget_scope,
        expected_policy=verified_policy,
        now=now,
    ):
        raise E1FailClosed("self-issued Metering Attestation failed verification")

    # -- 3. D_E: flat frozen object digest ----------------------------------
    d_e = compute_cross_layer_admission_digest(
        binding.binding_digest, authorization.authorization_digest, quote_digest
    )

    # -- 4. real Halo2 proof through the Rust service -----------------------
    prove_witness = _build_prove_witness(
        budget_scope=budget_scope, cost=attestation.attestation["c"], prover_state=prover_state
    )
    try:
        prove_result = bridge.prove(prove_witness)
    except Exception as exc:
        raise E1FailClosed(f"real Halo2 proof generation failed: {type(exc).__name__}") from exc
    proof_b64, instance = _check_prove_result(
        prove_result, witness=prove_witness, cost=attestation.attestation["c"]
    )

    artifacts = _AdmissionArtifacts(
        operation_id=operation_id,
        binding_digest=binding.binding_digest,
        metering_attestation=attestation,
        metering_quote_digest=quote_digest,
        cross_layer_digest=d_e,
        d10_budget_receipt={},
        prove_witness=prove_witness,
        instance=instance,
    )

    # -- 5. D10 admission with request_digest == D_E ------------------------
    try:
        gateway_adapter.consume_for_grant(
            execution_grant, operation_id=operation_id, request_digest=d_e
        )
    except Exception as exc:
        # D10 did not admit; no budget was consumed, so re-issue is allowed.
        raise E1FailClosed(f"D10 admission failed: {type(exc).__name__}") from exc
    d10_receipt = gateway_adapter.coordinator_receipt_for_operation(operation_id)
    if d10_receipt is None:
        raise E1FailClosed("D10 Budget Receipt is unavailable")
    if d10_receipt.get("payload", {}).get("request_digest") != d_e:
        raise E1FailClosed("D10 Budget Receipt request_digest != D_E")
    artifacts = _AdmissionArtifacts(
        operation_id=operation_id,
        binding_digest=binding.binding_digest,
        metering_attestation=attestation,
        metering_quote_digest=quote_digest,
        cross_layer_digest=d_e,
        d10_budget_receipt=d10_receipt,
        prove_witness=prove_witness,
        instance=instance,
    )

    # -- 6. D11 state transition with the SAME attestation/quote/operation --
    try:
        receipt = bridge.submit_transition_e1(
            {
                "proof_b64": proof_b64,
                "instance": instance,
                "metering_attestation": attestation.as_dict(),
                "metering_quote_digest": quote_digest,
                "operation_id": operation_id,
                "binding_digest": binding.binding_digest,
            }
        )
        recovered = False
    except ServiceError as exc:
        if exc.code in IDEMPOTENT_QUERY_CODES:
            # §B.5: STATE_CONFLICT / STORE_ERROR do not prove the transition
            # failed. The store may already hold a committed receipt. Query by
            # the original operation keys and restore on a consistent hit;
            # a miss or uncertain lookup fails closed (no fake receipt).
            stored = _restore_from_idempotent_lookup(
                bridge=bridge,
                artifacts=artifacts,
                budget_scope=budget_scope,
                code=exc.code,
            )
            return _pending_from_stored_receipt(
                artifacts=artifacts,
                receipt=stored,
                tool_name=tool_name,
                arguments=dict(safe_arguments),
                binding_payload=binding.payload(),
            )
        # Every other well-formed ok:false rejection (PROOF_INVALID,
        # ATTESTATION_INVALID, IDEMPOTENCY_CONFLICT, ...) is definitive: fail
        # closed, do not restart or blindly re-submit.
        raise E1FailClosed(f"D11 rejected the transition ({exc.code}): {exc.message}") from exc
    except BridgeUnavailable:
        # Only uncertain transport faults justify restart + get_operation
        # recovery. Never guess that an unconfirmed submit succeeded.
        recovered_pending = _recover_submit(
            bridge=bridge, artifacts=artifacts, budget_scope=budget_scope, now=now
        )
        return PendingExecution(
            operation_id=recovered_pending.operation_id,
            tool_name=tool_name,
            arguments=dict(safe_arguments),
            binding=binding.payload(),
            metering_attestation=recovered_pending.metering_attestation,
            metering_quote_digest=recovered_pending.metering_quote_digest,
            cross_layer_digest=recovered_pending.cross_layer_digest,
            d10_budget_receipt=recovered_pending.d10_budget_receipt,
            d11_transition_receipt=recovered_pending.d11_transition_receipt,
            recovered=True,
        )
    _check_transition_receipt(receipt, artifacts, budget_scope=budget_scope)
    return PendingExecution(
        operation_id=operation_id,
        tool_name=tool_name,
        arguments=dict(safe_arguments),
        binding=binding.payload(),
        metering_attestation=attestation.as_dict(),
        metering_quote_digest=quote_digest,
        cross_layer_digest=d_e,
        d10_budget_receipt=d10_receipt,
        d11_transition_receipt=dict(receipt),
        recovered=recovered,
    )


__all__ = [
    "CROSS_LAYER_ADMISSION_DOMAIN",
    "E1RuntimeError",
    "E1FailClosed",
    "E1SubmitIndeterminate",
    "PendingExecution",
    "compute_cross_layer_admission_digest",
    "run_tool_call_e1",
]
