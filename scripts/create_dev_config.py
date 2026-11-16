from __future__ import annotations

import json
from pathlib import Path
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from online_budget.canonical import b64encode, private_key_bytes, public_key_bytes


def main() -> int:
    issuer = Ed25519PrivateKey.generate()
    coordinator = Ed25519PrivateKey.generate()
    gateway_a = Ed25519PrivateKey.generate()
    gateway_b = Ed25519PrivateKey.generate()
    config = {
        "coordinator_id": "coordinator-dev-1",
        "coordinator_key_id": "coordinator-key-dev-1",
        "global_budget_id": "online-budget-epoch-dev-1",
        "global_quota_limit": 100,
        "database_path": "state/coordinator.sqlite3",
        "issuer_public_key_b64": b64encode(public_key_bytes(issuer.public_key())),
        "coordinator_private_key_b64": b64encode(private_key_bytes(coordinator)),
        "gateways": [
            {"gateway_id": "gateway-A", "public_key_b64": b64encode(public_key_bytes(gateway_a.public_key()))},
            {"gateway_id": "gateway-B", "public_key_b64": b64encode(public_key_bytes(gateway_b.public_key()))},
        ],
    }
    out = ROOT / "coordinator-config.json"
    out.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    out.chmod(0o600)
    key_material = {
        "issuer_private_key_b64": b64encode(private_key_bytes(issuer)),
        "gateway_private_keys_b64": {
            "gateway-A": b64encode(private_key_bytes(gateway_a)),
            "gateway-B": b64encode(private_key_bytes(gateway_b)),
        },
        "coordinator_public_key_b64": b64encode(public_key_bytes(coordinator.public_key())),
    }
    key_file = ROOT / "dev-client-keys.json"
    key_file.write_text(json.dumps(key_material, indent=2) + "\n", encoding="utf-8")
    key_file.chmod(0o600)
    print(f"Wrote {out}")
    print(f"Wrote {key_file}")
    print("WARNING: development keys only. These files are git-ignored and must never be committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
