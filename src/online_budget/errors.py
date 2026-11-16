from __future__ import annotations


class CoordinatorError(RuntimeError):
    code = "COORDINATOR_ERROR"
    http_status = 400


class AuthenticationError(CoordinatorError):
    code = "GATEWAY_UNAUTHENTICATED"
    http_status = 401


class GrantRejected(CoordinatorError):
    code = "GRANT_INVALID"
    http_status = 403


class GatewayNotAuthorized(CoordinatorError):
    code = "GATEWAY_NOT_AUTHORIZED"
    http_status = 403


class LeaseNotRegistered(CoordinatorError):
    code = "LEASE_NOT_REGISTERED"
    http_status = 404


class LeaseInactive(CoordinatorError):
    code = "LEASE_INACTIVE"
    http_status = 403


class LeaseCapExceeded(CoordinatorError):
    code = "LEASE_CAP_EXHAUSTED"
    http_status = 409


class GlobalBudgetExceeded(CoordinatorError):
    code = "GLOBAL_BUDGET_EXHAUSTED"
    http_status = 409


class OperationBindingConflict(CoordinatorError):
    code = "OPERATION_BINDING_CONFLICT"
    http_status = 409


class CoordinatorIndeterminate(CoordinatorError):
    code = "COORDINATOR_INDETERMINATE"
    http_status = 503


class ConfigurationMismatch(CoordinatorError):
    code = "COORDINATOR_CONFIGURATION_MISMATCH"
    http_status = 503
