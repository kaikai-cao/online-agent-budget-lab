"""Tool service with a gateway-authenticated entrance (P1 enforcement point).

The service entrance verifies the gateway's signature on a ForwardReceipt using
the GATEWAY PUBLIC KEY. There is no code path that executes a call without a
valid gateway receipt: a direct/bypass request is REJECTED at the entrance and
never touches the service logic.

The service self-reports a signed ServiceSubmission after executing (P0 evidence).
Enforcement (who may enter) and self-reporting (what I claim I did) are separate.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .models import ForwardReceipt, ServiceSubmission, verify


class RejectedByGateway(Exception):
    """Raised when a request lacks a valid gateway-authenticated receipt."""


class ToolService:
    def __init__(
        self, db_path: str | Path, key: Ed25519PrivateKey,
        gateway_pubkey: Ed25519PublicKey, gateway_id: str, service_id: str,
        enforce_gateway: bool = True, track_attempt: bool = True,
    ):
        self.db_path = str(db_path)
        self.key = key
        self.gateway_pubkey = gateway_pubkey
        self.gateway_id = gateway_id
        self.service_id = service_id
        # Deployment property: P0 has no mandatory gateway (enforce=False) and
        # no independent attempt tracking (track_attempt=False). P1-P3 enforce.
        self.enforce_gateway = enforce_gateway
        self.track_attempt = track_attempt
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS submissions (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT, logical_call_id TEXT, attempt_id TEXT,
                   service_id TEXT, executed INTEGER, signature TEXT)"""
            )
            con.commit()

    def authenticate(self, receipt: ForwardReceipt | None) -> bool:
        """The enforcement check. Only a valid, gateway-signed receipt for THIS
        service passes. Returns False for None / wrong service / bad signature."""
        if receipt is None:
            return False
        if receipt.service_id != self.service_id:
            return False
        if receipt.gateway_id != self.gateway_id:
            return False
        return verify(self.gateway_pubkey, receipt.signature, receipt.signed_payload())

    def receive(self, receipt: ForwardReceipt | None, run_id: str,
                logical_call_id: str, attempt_id: str, suppress_report: bool = False
                ) -> tuple[bool, ServiceSubmission | None]:
        """Service entrance. Returns (accepted, submission).

        Raises RejectedByGateway (no execution, no submission) if authentication
        fails. Only on success does the service execute and (optionally) report.
        """
        if self.enforce_gateway and not self.authenticate(receipt):
            raise RejectedByGateway("no valid gateway-authenticated receipt")

        # P0: no gateway exists, no independent attempt tracking. The recorded
        # attempt_id is blank so retries cannot be distinguished from duplicates.
        effective_attempt = attempt_id if self.track_attempt else ""

        # --- execution happens here (ground truth recorded by controller outside) ---
        if suppress_report:
            return True, None  # T3: executed but did not submit a report

        sub = ServiceSubmission(
            run_id=run_id, logical_call_id=logical_call_id, attempt_id=effective_attempt,
            service_id=self.service_id, service_executed_claim=True,
        ).sign(self.key)
        self._append(sub)
        return True, sub

    def _append(self, sub: ServiceSubmission) -> None:
        with closing(self._connect()) as con:
            con.execute(
                "INSERT INTO submissions (run_id, logical_call_id, attempt_id, "
                "service_id, executed, signature) VALUES (?,?,?,?,?,?)",
                (sub.run_id, sub.logical_call_id, sub.attempt_id, sub.service_id,
                 1 if sub.service_executed_claim else 0, sub.signature),
            )
            con.commit()

    def resubmit(self, sub: ServiceSubmission) -> None:
        """Simulate a duplicate TRANSMISSION of an already-made report (T4)."""
        self._append(sub)

    def submissions(self) -> list[ServiceSubmission]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT run_id, logical_call_id, attempt_id, service_id, executed, signature "
                "FROM submissions ORDER BY id"
            ).fetchall()
        return [
            ServiceSubmission(
                run_id=r["run_id"], logical_call_id=r["logical_call_id"],
                attempt_id=r["attempt_id"], service_id=r["service_id"],
                service_executed_claim=bool(r["executed"]), signature=r["signature"],
            )
            for r in rows
        ]

    def count(self) -> int:
        with closing(self._connect()) as con:
            return int(con.execute("SELECT COUNT(*) FROM submissions").fetchone()[0])
