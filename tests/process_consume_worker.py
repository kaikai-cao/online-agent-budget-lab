from __future__ import annotations

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from online_budget import GlobalBudgetExceeded, OnlineBudgetClient, OnlineLeaseGrant
from online_budget.canonical import private_key_from_b64, public_key_from_b64


def main() -> int:
    config_path = Path(sys.argv[1])
    gate_path = Path(sys.argv[2])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 15
    while not gate_path.exists():
        if time.monotonic() >= deadline:
            print(json.dumps({"status": "worker_timeout"}))
            return 2
        time.sleep(0.01)
    client = OnlineBudgetClient(
        base_url=config["base_url"], gateway_id=config["gateway_id"],
        gateway_private_key=private_key_from_b64(config["gateway_private_key_b64"]),
        coordinator_public_key=public_key_from_b64(config["coordinator_public_key_b64"]),
        coordinator_id=config["coordinator_id"],
        global_budget_id=config["global_budget_id"],
    )
    grant = OnlineLeaseGrant.from_dict(config["online_lease_grant"])
    try:
        receipt = client.consume(
            grant, config["execution_grant"], operation_id=config["operation_id"],
            request_digest=config["request_digest"],
        )
        print(json.dumps({"status": "committed", "receipt": receipt.as_dict()}, sort_keys=True))
        return 0
    except GlobalBudgetExceeded:
        print(json.dumps({"status": "global_exhausted"}, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "error", "error_type": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
