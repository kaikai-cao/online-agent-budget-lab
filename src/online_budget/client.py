from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .auth import sign_gateway_envelope
from .canonical import canonical_json_bytes
from .errors import (
    AuthenticationError, CoordinatorError, CoordinatorIndeterminate, GlobalBudgetExceeded,
    GatewayNotAuthorized, GrantRejected, LeaseCapExceeded, LeaseInactive,
    LeaseNotRegistered, OperationBindingConflict,
)
from .grants import LeaseRevocation, OnlineLeaseGrant, execution_grant_dict, execution_grant_digest
from .receipts import BudgetReceipt, verify_budget_receipt


HTTP_ERRORS = {
    "GATEWAY_UNAUTHENTICATED": AuthenticationError,
    "GRANT_INVALID": GrantRejected,
    "GATEWAY_NOT_AUTHORIZED": GatewayNotAuthorized,
    "LEASE_NOT_REGISTERED": LeaseNotRegistered,
    "LEASE_INACTIVE": LeaseInactive,
    "LEASE_CAP_EXHAUSTED": LeaseCapExceeded,
    "GLOBAL_BUDGET_EXHAUSTED": GlobalBudgetExceeded,
    "OPERATION_BINDING_CONFLICT": OperationBindingConflict,
    "COORDINATOR_INDETERMINATE": CoordinatorIndeterminate,
}


class CoordinatorUnavailable(RuntimeError):
    """Transport failure with unknown outcome. Caller must retry the same operation ID."""


class OnlineBudgetClient:
    def __init__(
        self, *, base_url: str, gateway_id: str, gateway_private_key: Ed25519PrivateKey,
        coordinator_public_key: Ed25519PublicKey, coordinator_id: str, global_budget_id: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.gateway_id = gateway_id
        if not coordinator_id or not coordinator_id.strip():
            raise ValueError("coordinator_id must be non-empty")
        # D9.3.1: pin the budget epoch as part of the client's trust configuration.
        if not isinstance(global_budget_id, str) or not global_budget_id.strip():
            raise ValueError("global_budget_id must be non-empty")
        self.coordinator_id = coordinator_id
        self.global_budget_id = global_budget_id
        self.gateway_private_key = gateway_private_key
        self.coordinator_public_key = coordinator_public_key
        self.timeout_seconds = timeout_seconds

    def _post(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        envelope = sign_gateway_envelope(self.gateway_id, "POST", path, payload, self.gateway_private_key)
        data = canonical_json_bytes(envelope)
        req = Request(self.base_url + path, data=data, headers={
            "Content-Type": "application/json", "Accept": "application/json",
        }, method="POST")
        try:
            with urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read(1_048_577)
        except HTTPError as exc:
            # HTTPError is also a file-like response. Close it explicitly to
            # release the underlying socket on every denial/unknown-outcome path.
            with exc:
                if exc.code >= 500:
                    raise CoordinatorUnavailable(
                        f"Coordinator returned HTTP {exc.code}; commit outcome may be unknown"
                    ) from exc
                try:
                    result = json.loads(exc.read().decode("utf-8"))
                    err = result.get("error", {})
                    cls = HTTP_ERRORS.get(err.get("code"), CoordinatorError)
                    raise cls(err.get("message", "Coordinator rejected request")) from exc
                except (ValueError, KeyError, TypeError):
                    raise CoordinatorUnavailable(
                        f"Coordinator HTTP error {exc.code}; outcome may be unknown"
                    ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise CoordinatorUnavailable(f"Coordinator transport outcome is unknown: {exc}") from exc
        if len(raw) > 1_048_576:
            raise CoordinatorUnavailable("Coordinator response exceeded configured limit")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CoordinatorUnavailable("Coordinator returned an invalid response; outcome may be unknown") from exc
        if not body.get("ok"):
            err = body.get("error", {})
            cls = HTTP_ERRORS.get(err.get("code"), CoordinatorError)
            raise cls(err.get("message", "Coordinator rejected request"))
        result = body.get("result")
        if not isinstance(result, dict):
            raise CoordinatorUnavailable("Coordinator response has an invalid result shape")
        return result

    def register_lease(self, grant: OnlineLeaseGrant) -> dict[str, Any]:
        return self._post("/v1/leases/register", {"grant": grant.as_dict()})

    def revoke_lease(self, revocation: LeaseRevocation) -> dict[str, Any]:
        return self._post("/v1/leases/revoke", {"revocation": revocation.as_dict()})

    def lookup_lease(self, lease_id: str) -> dict[str, Any]:
        return self._post("/v1/leases/lookup", {"lease_id": lease_id})

    def consume(
        self, online_grant: OnlineLeaseGrant, execution_grant: Any, *,
        operation_id: str, request_digest: str,
    ) -> BudgetReceipt:
        result = self._post("/v1/budget/consume", {
            "online_lease_grant": online_grant.as_dict(),
            "execution_grant": execution_grant_dict(execution_grant),
            "operation_id": operation_id,
            "request_digest": request_digest,
        })
        receipt = BudgetReceipt.from_dict(result)
        expected = {
            "coordinator_id": self.coordinator_id,
            "global_budget_id": online_grant.global_budget_id,
            "gateway_id": self.gateway_id,
            "lease_id": online_grant.lease_id,
            "global_lease_grant_digest": online_grant.grant_digest,
            "operation_id": operation_id,
            "request_digest": request_digest,
            "execution_grant_digest": execution_grant_digest(execution_grant_dict(execution_grant)),
        }
        if not verify_budget_receipt(receipt, self.coordinator_public_key, expected=expected):
            raise CoordinatorIndeterminate("Coordinator Budget Receipt signature or binding is invalid")
        return receipt

    def lookup_operation(self, operation_id: str) -> BudgetReceipt | None:
        result = self._post("/v1/budget/lookup", {"operation_id": operation_id})
        if not result.get("found"):
            return None
        receipt = BudgetReceipt.from_dict(result["receipt"])
        expected = {
            "coordinator_id": self.coordinator_id,
            "global_budget_id": self.global_budget_id,
            "gateway_id": self.gateway_id,
            "operation_id": operation_id,
        }
        if not verify_budget_receipt(receipt, self.coordinator_public_key, expected=expected):
            raise CoordinatorIndeterminate("stored Coordinator receipt failed identity or binding verification")
        return receipt
