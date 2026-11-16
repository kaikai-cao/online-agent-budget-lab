from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from online_budget import OnlineBudgetClient, ToolPermission, issue_online_lease_grant
from online_budget.canonical import b64encode, canonical_json_bytes, digest, private_key_from_b64, public_key_from_b64


def main() -> int:
    config = json.loads((ROOT / "coordinator-config.json").read_text(encoding="utf-8"))
    keys = json.loads((ROOT / "dev-client-keys.json").read_text(encoding="utf-8"))
    issuer_private = private_key_from_b64(keys["issuer_private_key_b64"])
    gateway_id = "gateway-A"
    gateway_private = private_key_from_b64(keys["gateway_private_keys_b64"][gateway_id])
    coordinator_private = private_key_from_b64(config["coordinator_private_key_b64"])
    client = OnlineBudgetClient(
        base_url="http://127.0.0.1:8765", gateway_id=gateway_id,
        gateway_private_key=gateway_private,
        coordinator_public_key=coordinator_private.public_key(),
        coordinator_id=config["coordinator_id"],
    )
    now = int(time.time())
    context_digest = digest({"tenant_id": "tenant-demo", "purpose": "invoice-review"})
    schema = {"type": "object", "required": ["invoice_id"], "properties": {"invoice_id": {"type": "string"}}}
    permission = ToolPermission("invoice_review", digest(schema))
    online_grant = issue_online_lease_grant(
        issuer_private,
        issuer_id="issuer-dev",
        grant_id=f"grant-demo-{now}",
        lease_id=f"lease-demo-{now}",
        nonce=f"nonce-demo-{now}",
        global_budget_id=config["global_budget_id"],
        quota_limit=5,
        issued_at=now - 1,
        expires_at=now + 600,
        coordinator_audience=config["coordinator_id"],
        allowed_gateway_ids=(gateway_id,),
        subject_id="agent-demo",
        context_digest=context_digest,
        allowed_tools=(permission,),
    )
    operation_id = f"demo-operation-{now}"
    execution_unsigned = {
        "version": 2,
        "issuer_id": online_grant.issuer_id,
        "grant_id": online_grant.grant_id,
        "lease_id": online_grant.lease_id,
        "subject_id": online_grant.subject_id,
        "audience": gateway_id,
        "context_digest": online_grant.context_digest,
        "issued_at": online_grant.issued_at,
        "expires_at": online_grant.expires_at,
        "quota_limit": online_grant.quota_limit,
        "nonce": online_grant.nonce,
        "allowed_tools": [permission.as_dict()],
        "parent_authorization_digest": hashlib.sha256(f"parent:{operation_id}".encode()).hexdigest(),
        "parent_authorization_nonce": f"parent-nonce-{operation_id}",
        "operation_id": operation_id,
    }
    execution_grant = {
        **execution_unsigned,
        "signature_b64": b64encode(issuer_private.sign(canonical_json_bytes(execution_unsigned))),
    }
    client.register_lease(online_grant)
    receipt = client.consume(
        online_grant,
        execution_grant,
        operation_id=operation_id,
        request_digest=digest({"tool": "invoice_review", "arguments": {"invoice_id": "INV-DEMO-1"}}),
    )
    print(json.dumps(receipt.as_dict(), indent=2, sort_keys=True))
    print("Coordinator Budget Receipt signature verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
