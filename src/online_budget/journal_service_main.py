"""E1.9-B -- Journal Service standalone process entry point (B.1).

Usage::

    python -m online_budget.journal_service_main --config journal-service.json
    python -m online_budget.journal_service_main --print-sid

Startup:
  * loads the fixed deployment config (registries, keys, ACL SIDs);
  * constructs JournalService, which runs a FULL verify_integrity() and refuses
    to serve on any integrity failure (fail closed);
  * starts the Windows Named Pipe server (OS identity + ACL enforced);
  * Ctrl+C / SIGTERM sets the stop flag and the process exits cleanly.

Diagnostics go to stderr; no credentials are ever accepted over the pipe.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

from .journal_identity import current_process_identity
from .journal_ipc import NamedPipeServer
from .journal_fileacl import FileACLError, verify_private_file
from .journal_service import JournalService, ServiceStartupError
from .journal_service_config import ServiceConfig, ServiceConfigError


def _load_config(path: str) -> ServiceConfig:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    return ServiceConfig.from_dict(data, base_dir=Path(path).resolve().parent)


def _verify_private_file_acl(config: ServiceConfig, config_path: str) -> bool:
    """B-F2 fail-closed startup gate on the key/config/DB file ACLs.

    Returns True if the boundary was actively checked, False if it is not
    configured (caller prints a loud warning).  A configured check that fails
    raises FileACLError and the service refuses to start.
    """
    if not config.journal_service_sid:
        return False
    allowed = (config.journal_service_sid,)
    forbidden_read = config.executor_account_sids
    forbidden_write = config.executor_account_sids
    # The config file itself carries the signing key seed (base64).
    verify_private_file(
        config_path, allowed_sids=allowed, forbidden_read_sids=forbidden_read
    )
    # Both databases: the Executor must not be able to mutate them.  On first
    # start the file may not exist yet -- check its parent directory (the DB
    # inherits that DACL) so the boundary is still enforced before creation.
    for db_path in (config.journal_db_path, config.idempotency_db_path):
        target = db_path if db_path.exists() else db_path.parent
        verify_private_file(target, allowed_sids=allowed, forbidden_write_sids=forbidden_write)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="E1.9-B independent Journal Service")
    parser.add_argument("--config", help="path to the deployment JSON config")
    parser.add_argument("--print-sid", action="store_true", help="print current process SID/account (ACL helper) and exit")
    args = parser.parse_args(argv)

    if args.print_sid:
        ident = current_process_identity()
        print(json.dumps({"sid": ident.sid, "account": ident.account}, ensure_ascii=False))
        return 0

    if not args.config:
        parser.error("--config is required (or use --print-sid)")

    try:
        config = _load_config(args.config)
    except (ServiceConfigError, OSError, json.JSONDecodeError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    # B-F2: refuse to serve if a forbidden SID can read the key/config or write
    # a database.  Missing journal_service_sid -> loud warning, not silent OK.
    if config.journal_service_sid:
        try:
            _verify_private_file_acl(config, args.config)
        except FileACLError as exc:
            print(f"refusing to start: private-file ACL check failed: {exc}", file=sys.stderr)
            return 3
    else:
        print(
            "WARNING: journal_service_sid not configured; private-file ACL boundary "
            "(B-F2) is NOT enforced. Run scripts/setup_journal_service_acl.ps1 and "
            "set journal_service_sid/executor_account_sids before production use.",
            file=sys.stderr,
        )

    try:
        service = JournalService(config, require_os_backed=True).start()
    except ServiceStartupError as exc:
        print(f"refusing to start: {exc}", file=sys.stderr)
        return 3

    server = NamedPipeServer(
        pipe_name=config.pipe_name,
        allowed_sids=config.allowed_client_sids,
        service=service,
        require_os_backed=True,
    )

    def _handle_signal(_signum, _frame):
        server.stop()
        service.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
    except (AttributeError, ValueError):
        pass  # SIGTERM unavailable on some Windows Python builds

    print(f"journal service listening on {server.path}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
    print("journal service stopped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
