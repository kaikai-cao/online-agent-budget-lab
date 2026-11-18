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
from .journal_service import JournalService, ServiceStartupError
from .journal_service_config import ServiceConfig, ServiceConfigError


def _load_config(path: str) -> ServiceConfig:
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    return ServiceConfig.from_dict(data, base_dir=Path(path).resolve().parent)


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
