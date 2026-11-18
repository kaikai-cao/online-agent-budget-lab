"""Generate a deployment config for the E1.9-B Journal Service.

Run on the target Windows host::

    python scripts/create_journal_service_config.py --out journal-service.json \
        --journal-key <base64-32bytes> --executor-id exec-A \
        --executor-pubkey <base64-ed25519-pubkey> \
        --os-identity 'DESKTOP-X\\exec_acct'

If --journal-key is omitted, a fresh Ed25519 signing key is generated and its
base64 seed is printed (KEEP IT SECRET -- store in a protected ACL directory).
The script prints the current process SID so ADMIN can build the pipe DACL.
It does NOT create OS accounts or set ACLs -- that is an ADMIN step (see the
implementation report's administrator command section).
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create E1.9-B Journal Service config")
    parser.add_argument("--out", required=True, help="output JSON path")
    parser.add_argument("--pipe-name", default="online_budget_journal")
    parser.add_argument("--journal-db", default="state/journal.sqlite3")
    parser.add_argument("--idem-db", default="state/journal_idem.sqlite3")
    parser.add_argument("--journal-key", help="base64 32-byte Ed25519 seed (generated if omitted)")
    parser.add_argument("--executor-id", required=True)
    parser.add_argument("--executor-pubkey", required=True, help="base64 Ed25519 public key")
    parser.add_argument("--os-identity", required=True, help="OS account (DOMAIN\\user) allowed to use executor-id")
    parser.add_argument("--allowed-sid", action="append", default=[], help="SID allowed on the pipe ACL (repeatable)")
    args = parser.parse_args(argv)

    if args.journal_key:
        seed = base64.b64decode(args.journal_key, validate=True)
        if len(seed) != 32:
            print("--journal-key must be a base64 32-byte seed", file=sys.stderr)
            return 2
        signing = Ed25519PrivateKey.from_private_bytes(seed)
        generated = False
    else:
        signing = Ed25519PrivateKey.generate()
        generated = True

    key_bytes = signing.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = signing.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    try:
        from online_budget.journal_identity import current_process_identity
        ident = current_process_identity()
        sids = args.allowed_sid or [ident.sid]
    except Exception:  # non-Windows config generation still possible with explicit SIDs
        if not args.allowed_sid:
            print("on non-Windows you must pass --allowed-sid", file=sys.stderr)
            return 2
        sids = args.allowed_sid
        ident = None

    config = {
        "pipe_name": args.pipe_name,
        "journal_db_path": args.journal_db,
        "idempotency_db_path": args.idem_db,
        "journal_signing_key_b64": _b64(key_bytes),
        "journal_verify_key_b64": _b64(pub_bytes),
        "allowed_client_sids": list(sids),
        "os_identity_to_executor_ids": {args.os_identity: [args.executor_id]},
        "executor_public_keys": {args.executor_id: args.executor_pubkey},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote config: {out}")
    if generated:
        print(f"GENERATED journal signing key seed (KEEP SECRET): {_b64(key_bytes)}")
    if ident is not None:
        print(f"current process SID: {ident.sid}  account: {ident.account}")


if __name__ == "__main__":
    raise SystemExit(main())
