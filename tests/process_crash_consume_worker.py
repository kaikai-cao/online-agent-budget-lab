from __future__ import annotations

import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from online_budget import OnlineBudgetCoordinator, OnlineLeaseGrant
from online_budget.canonical import private_key_from_b64, public_key_from_b64


class BlockingCoordinator(OnlineBudgetCoordinator):
    """Test-only crash hook: pause after accounting writes but before receipt insert/commit."""

    def __init__(self, *args, marker_path: Path, release_path: Path, **kwargs):
        self._marker_path = marker_path
        self._release_path = release_path
        self._pause_once = False
        super().__init__(*args, **kwargs)

    def _connect(self):
        con = super()._connect()
        con.set_trace_callback(self._trace_sql)
        return con

    def _trace_sql(self, statement: str) -> None:
        normalized = " ".join(statement.strip().upper().split())
        if not self._pause_once and normalized.startswith("INSERT INTO RECEIPTS("):
            self._pause_once = True
            self._marker_path.write_text("inside_uncommitted_transaction", encoding="utf-8")
            deadline = time.monotonic() + 60
            while not self._release_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)


def main() -> int:
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    coordinator = BlockingCoordinator(
        coordinator_id=config["coordinator_id"],
        global_budget_id=config["global_budget_id"],
        global_quota_limit=config["global_quota_limit"],
        issuer_public_key=public_key_from_b64(config["issuer_public_key_b64"]),
        coordinator_private_key=private_key_from_b64(config["coordinator_private_key_b64"]),
        coordinator_key_id=config["coordinator_key_id"],
        database_path=config["database_path"],
        gateways={name: public_key_from_b64(value) for name, value in config["gateways"].items()},
        clock=lambda: config["now"],
        marker_path=Path(config["marker_path"]),
        release_path=Path(config["release_path"]),
    )
    grant = OnlineLeaseGrant.from_dict(config["online_lease_grant"])
    receipt = coordinator.consume(
        config["gateway_id"], grant, config["execution_grant"],
        operation_id=config["operation_id"], request_digest=config["request_digest"],
    )
    print(json.dumps({"status": "unexpected_commit", "receipt": receipt.as_dict()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
