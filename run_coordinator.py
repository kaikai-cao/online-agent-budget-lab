from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from online_budget import OnlineBudgetCoordinator
from online_budget.canonical import private_key_from_b64, public_key_from_b64
from online_budget.http_api import serve


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the single-node Online Budget Coordinator")
    parser.add_argument("--config", default="coordinator-config.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    path = Path(args.config).resolve()
    config = json.loads(path.read_text(encoding="utf-8"))
    issuer = public_key_from_b64(config["issuer_public_key_b64"])
    coordinator_private = private_key_from_b64(config["coordinator_private_key_b64"])
    gateways = {
        row["gateway_id"]: public_key_from_b64(row["public_key_b64"])
        for row in config["gateways"]
    }
    db_path = Path(config["database_path"])
    if not db_path.is_absolute():
        db_path = path.parent / db_path
    coordinator = OnlineBudgetCoordinator(
        coordinator_id=config["coordinator_id"],
        global_budget_id=config["global_budget_id"],
        global_quota_limit=config["global_quota_limit"],
        issuer_public_key=issuer,
        coordinator_private_key=coordinator_private,
        coordinator_key_id=config["coordinator_key_id"],
        database_path=db_path,
        gateways=gateways,
    )
    print(f"Coordinator: {coordinator.coordinator_id}")
    print(f"Budget epoch: {coordinator.global_budget_id}")
    print(f"Database: {coordinator.database_path}")
    print(f"Listening: http://{args.host}:{args.port}")
    print("Development HTTP only: use TLS termination for any non-loopback deployment.")
    serve(coordinator, args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
