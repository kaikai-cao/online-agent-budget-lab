"""Read-only bridge to the FROZEN H1 implementation.

H3.2 MUST reuse H1's real protocol / authorization service / executor rather
than re-implementing a look-alike. H1 modules use top-level imports (e.g.
``from h1_protocol import ...``), so this module puts that directory (and the
repo ``src``) on sys.path and re-exports the exact symbols. Nothing in H1 is
modified by H3.2.
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[2]
_H1_DIR = _REPO / "experiments" / "h1_authorization_binding"
_SRC = _REPO / "src"

for _p in (str(_SRC), str(_H1_DIR), str(_REPO)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from h1_protocol import (  # noqa: E402
    ACTION_FIELDS,
    CREDENTIAL_DOMAIN,
    ActionRequest,
    AuthorizationObject,
    H1ProtocolError,
    action_identity,
    build_authorization_object,
    compute_action_digest,
)
from h1_authorization_service import (  # noqa: E402
    DEFAULT_AUDIENCE,
    DEFAULT_ISSUER,
    DEFAULT_KEY_ID,
    AuthorizationService,
    AuthServiceTLSServer,
    B2OnlineVerifier,
    CredentialIssuanceError,
)
from h1_executor import Executor, VerificationError  # noqa: E402
from h1_sink import (  # noqa: E402
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    OUTCOME_ROLLED_BACK,
)
from online_budget.canonical import digest, is_sha256  # noqa: E402

__all__ = [
    "ACTION_FIELDS",
    "CREDENTIAL_DOMAIN",
    "ActionRequest",
    "AuthorizationObject",
    "H1ProtocolError",
    "action_identity",
    "build_authorization_object",
    "compute_action_digest",
    "DEFAULT_AUDIENCE",
    "DEFAULT_ISSUER",
    "DEFAULT_KEY_ID",
    "AuthorizationService",
    "AuthServiceTLSServer",
    "B2OnlineVerifier",
    "CredentialIssuanceError",
    "Executor",
    "VerificationError",
    "OUTCOME_DEDUP_HIT",
    "OUTCOME_EXECUTED",
    "OUTCOME_ROLLED_BACK",
    "digest",
    "is_sha256",
]
