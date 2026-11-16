from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def replace_exact(text: str, old: str, new: str, *, path: str, expected: int = 1) -> str:
    if new in text:
        return text
    count = text.count(old)
    if count != expected:
        raise RuntimeError(
            f"Patch anchor mismatch in {path}: expected {expected} occurrence(s), found {count}; "
            "no files have been written."
        )
    return text.replace(old, new, expected)


def transform(path: str, edits: list[tuple[str, str, int]]) -> str:
    file_path = ROOT / path
    if not file_path.is_file():
        raise FileNotFoundError(f"Required repository file is missing: {path}")
    content = file_path.read_text(encoding="utf-8")
    for old, new, expected in edits:
        content = replace_exact(content, old, new, path=path, expected=expected)
    return content


changes: dict[str, str] = {}

# Coordinator: preserve Gateway disable state, serialize identity checks with
# state-changing operations, and validate database state before serving.
changes["src/online_budget/coordinator.py"] = transform(
    "src/online_budget/coordinator.py",
    [
        (
            "        for gateway_id, public_key in gateways.items():\n"
            "            self.enroll_gateway(gateway_id, public_key)\n",
            "        for gateway_id, public_key in gateways.items():\n"
            "            self.enroll_gateway(gateway_id, public_key)\n"
            "        # D9.3.1: never serve from a database that fails physical or ledger checks.\n"
            "        self._startup_integrity_check()\n",
            1,
        ),
        (
            "    def _connect(self) -> sqlite3.Connection:\n",
            "    def _startup_integrity_check(self) -> None:\n"
            "        \"\"\"Fail startup closed on SQLite or Online budget-ledger inconsistency.\"\"\"\n"
            "        try:\n"
            "            with self._db() as con:\n"
            "                integrity_rows = con.execute(\"PRAGMA integrity_check\").fetchall()\n"
            "                integrity = [str(row[0]) for row in integrity_rows]\n"
            "                if integrity != [\"ok\"]:\n"
            "                    raise CoordinatorIndeterminate(\"SQLite integrity_check failed: \" + \"; \".join(integrity))\n"
            "                foreign_key_errors = con.execute(\"PRAGMA foreign_key_check\").fetchall()\n"
            "                if foreign_key_errors:\n"
            "                    raise CoordinatorIndeterminate(\"SQLite foreign_key_check reported violations\")\n"
            "            self.assert_invariants()\n"
            "        except CoordinatorIndeterminate:\n"
            "            raise\n"
            "        except sqlite3.DatabaseError as exc:\n"
            "            raise CoordinatorIndeterminate(\"Coordinator database integrity validation failed\") from exc\n"
            "\n"
            "    def _connect(self) -> sqlite3.Connection:\n",
            1,
        ),
        (
            "            row = con.execute(\"SELECT key_digest FROM gateways WHERE gateway_id=?\", (gateway_id,)).fetchone()\n"
            "            if row is not None and row[\"key_digest\"] != key_digest:\n"
            "                con.rollback()\n"
            "                raise ConfigurationMismatch(\"Gateway key rotation requires an explicit enrollment procedure\")\n"
            "            con.execute(\n"
            "                \"INSERT INTO gateways(gateway_id,public_key_b64,key_digest,enabled) VALUES(?,?,?,1) \"\n"
            "                \"ON CONFLICT(gateway_id) DO UPDATE SET enabled=1\",\n"
            "                (gateway_id, b64encode(raw), key_digest),\n"
            "            )\n"
            "            con.commit()\n",
            "            row = con.execute(\"SELECT key_digest FROM gateways WHERE gateway_id=?\", (gateway_id,)).fetchone()\n"
            "            if row is not None and row[\"key_digest\"] != key_digest:\n"
            "                con.rollback()\n"
            "                raise ConfigurationMismatch(\"Gateway key rotation requires an explicit enrollment procedure\")\n"
            "            # D9.3.1: startup enrollment inserts new identities but never re-enables an existing disabled one.\n"
            "            if row is None:\n"
            "                con.execute(\n"
            "                    \"INSERT INTO gateways(gateway_id,public_key_b64,key_digest,enabled) VALUES(?,?,?,1)\",\n"
            "                    (gateway_id, b64encode(raw), key_digest),\n"
            "                )\n"
            "            con.commit()\n",
            1,
        ),
        (
            "    def _assert_gateway_allowed(self, gateway_id: str, grant: OnlineLeaseGrant) -> None:\n"
            "        if gateway_id not in grant.allowed_gateway_ids:\n"
            "            raise GatewayNotAuthorized(\"Gateway ID is not listed in the signed Online Lease Grant\")\n"
            "        if self.gateway_public_key(gateway_id) is None:\n"
            "            raise GatewayNotAuthorized(\"Gateway is not enrolled or has been disabled\")\n",
            "    @staticmethod\n"
            "    def _require_gateway_enabled(con: sqlite3.Connection, gateway_id: str) -> None:\n"
            "        row = con.execute(\"SELECT enabled FROM gateways WHERE gateway_id=?\", (gateway_id,)).fetchone()\n"
            "        if row is None or int(row[\"enabled\"]) != 1:\n"
            "            raise GatewayNotAuthorized(\"Gateway is not enrolled or has been disabled\")\n"
            "\n"
            "    def _assert_gateway_allowed(\n"
            "        self, con: sqlite3.Connection, gateway_id: str, grant: OnlineLeaseGrant,\n"
            "    ) -> None:\n"
            "        if gateway_id not in grant.allowed_gateway_ids:\n"
            "            raise GatewayNotAuthorized(\"Gateway ID is not listed in the signed Online Lease Grant\")\n"
            "        self._require_gateway_enabled(con, gateway_id)\n",
            1,
        ),
        (
            "        self._assert_gateway_allowed(gateway_id, grant)\n"
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                self._assert_ready(con)\n",
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                self._assert_ready(con)\n"
            "                self._assert_gateway_allowed(con, gateway_id, grant)\n",
            1,
        ),
        (
            "    def get_lease(self, lease_id: str) -> dict[str, Any] | None:\n"
            "        with self._db() as con:\n"
            "            row = con.execute(\"SELECT * FROM leases WHERE lease_id=?\", (lease_id,)).fetchone()\n"
            "        return None if row is None else self._lease_row(row)\n",
            "    def get_lease(self, lease_id: str) -> dict[str, Any] | None:\n"
            "        with self._db() as con:\n"
            "            row = con.execute(\"SELECT * FROM leases WHERE lease_id=?\", (lease_id,)).fetchone()\n"
            "        return None if row is None else self._lease_row(row)\n"
            "\n"
            "    def get_lease_for_gateway(self, gateway_id: str, lease_id: str) -> dict[str, Any] | None:\n"
            "        \"\"\"Read Lease metadata only while the caller remains an enabled Gateway.\"\"\"\n"
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN\")\n"
            "            self._require_gateway_enabled(con, gateway_id)\n"
            "            row = con.execute(\"SELECT * FROM leases WHERE lease_id=?\", (lease_id,)).fetchone()\n"
            "            if row is None:\n"
            "                con.commit()\n"
            "                return None\n"
            "            allowed = json.loads(row[\"allowed_gateway_ids_json\"])\n"
            "            if gateway_id not in allowed:\n"
            "                raise GatewayNotAuthorized(\"Gateway is not authorized to inspect this Lease\")\n"
            "            result = self._lease_row(row)\n"
            "            con.commit()\n"
            "            return result\n",
            1,
        ),
        (
            "        if self.gateway_public_key(gateway_id) is None:\n"
            "            raise GatewayNotAuthorized(\"Gateway is not enrolled or has been disabled\")\n"
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                self._assert_ready(con)\n"
            "                old = con.execute(\"SELECT * FROM revocations WHERE revocation_id=?\", (record.revocation_id,)).fetchone()\n",
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                self._assert_ready(con)\n"
            "                self._require_gateway_enabled(con, gateway_id)\n"
            "                old = con.execute(\"SELECT * FROM revocations WHERE revocation_id=?\", (record.revocation_id,)).fetchone()\n",
            1,
        ),
        (
            "        self._assert_gateway_allowed(gateway_id, online_grant)\n"
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                meta = self._assert_ready(con)\n",
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN IMMEDIATE\")\n"
            "            try:\n"
            "                meta = self._assert_ready(con)\n"
            "                self._assert_gateway_allowed(con, gateway_id, online_grant)\n",
            1,
        ),
        (
            "    def lookup_operation(self, gateway_id: str, operation_id: str) -> BudgetReceipt | None:\n"
            "        if self.gateway_public_key(gateway_id) is None:\n"
            "            raise GatewayNotAuthorized(\"Gateway is not enrolled or has been disabled\")\n"
            "        with self._db() as con:\n"
            "            row = con.execute(\n"
            "                \"SELECT o.gateway_id,r.receipt_json,r.signature_b64 FROM operations o \"\n"
            "                \"LEFT JOIN receipts r ON r.operation_id=o.operation_id WHERE o.operation_id=?\",\n"
            "                (operation_id,),\n"
            "            ).fetchone()\n"
            "        if row is None:\n"
            "            return None\n"
            "        if row[\"gateway_id\"] != gateway_id:\n"
            "            raise OperationBindingConflict(\"operation_id belongs to another Gateway\")\n"
            "        if row[\"receipt_json\"] is None:\n"
            "            raise CoordinatorIndeterminate(\"operation receipt is missing\")\n"
            "        return BudgetReceipt(json.loads(row[\"receipt_json\"]), row[\"signature_b64\"])\n",
            "    def lookup_operation(self, gateway_id: str, operation_id: str) -> BudgetReceipt | None:\n"
            "        with self._db() as con:\n"
            "            con.execute(\"BEGIN\")\n"
            "            self._require_gateway_enabled(con, gateway_id)\n"
            "            row = con.execute(\n"
            "                \"SELECT o.gateway_id,r.receipt_json,r.signature_b64 FROM operations o \"\n"
            "                \"LEFT JOIN receipts r ON r.operation_id=o.operation_id WHERE o.operation_id=?\",\n"
            "                (operation_id,),\n"
            "            ).fetchone()\n"
            "            if row is None:\n"
            "                con.commit()\n"
            "                return None\n"
            "            if row[\"gateway_id\"] != gateway_id:\n"
            "                raise OperationBindingConflict(\"operation_id belongs to another Gateway\")\n"
            "            if row[\"receipt_json\"] is None:\n"
            "                raise CoordinatorIndeterminate(\"operation receipt is missing\")\n"
            "            receipt = BudgetReceipt(json.loads(row[\"receipt_json\"]), row[\"signature_b64\"])\n"
            "            con.commit()\n"
            "            return receipt\n",
            1,
        ),
    ],
)

# The client now requires the expected global epoch and checks both authority IDs
# when it recovers a stored receipt.
changes["src/online_budget/client.py"] = transform(
    "src/online_budget/client.py",
    [
        (
            "        coordinator_public_key: Ed25519PublicKey, coordinator_id: str,\n"
            "        timeout_seconds: float = 5.0,\n",
            "        coordinator_public_key: Ed25519PublicKey, coordinator_id: str, global_budget_id: str,\n"
            "        timeout_seconds: float = 5.0,\n",
            1,
        ),
        (
            "        if not coordinator_id or not coordinator_id.strip():\n"
            "            raise ValueError(\"coordinator_id must be non-empty\")\n"
            "        self.coordinator_id = coordinator_id\n",
            "        if not coordinator_id or not coordinator_id.strip():\n"
            "            raise ValueError(\"coordinator_id must be non-empty\")\n"
            "        # D9.3.1: pin the budget epoch as part of the client's trust configuration.\n"
            "        if not isinstance(global_budget_id, str) or not global_budget_id.strip():\n"
            "            raise ValueError(\"global_budget_id must be non-empty\")\n"
            "        self.coordinator_id = coordinator_id\n"
            "        self.global_budget_id = global_budget_id\n",
            1,
        ),
        (
            "        if not verify_budget_receipt(receipt, self.coordinator_public_key, expected={\"gateway_id\": self.gateway_id, \"operation_id\": operation_id}):\n"
            "            raise CoordinatorIndeterminate(\"stored Coordinator receipt failed verification\")\n",
            "        expected = {\n"
            "            \"coordinator_id\": self.coordinator_id,\n"
            "            \"global_budget_id\": self.global_budget_id,\n"
            "            \"gateway_id\": self.gateway_id,\n"
            "            \"operation_id\": operation_id,\n"
            "        }\n"
            "        if not verify_budget_receipt(receipt, self.coordinator_public_key, expected=expected):\n"
            "            raise CoordinatorIndeterminate(\"stored Coordinator receipt failed identity or binding verification\")\n",
            1,
        ),
    ],
)

# The Adapter pins the same Coordinator and budget epoch as the Client.
changes["src/online_budget/adapter.py"] = transform(
    "src/online_budget/adapter.py",
    [
        (
            "        if client.coordinator_id != coordinator_id:\n"
            "            raise ValueError(\"client and adapter Coordinator identities differ\")\n",
            "        if client.coordinator_id != coordinator_id:\n"
            "            raise ValueError(\"client and adapter Coordinator identities differ\")\n"
            "        # D9.3.1: a Client pinned to another budget epoch cannot back this Adapter.\n"
            "        if client.global_budget_id != global_budget_id:\n"
            "            raise ValueError(\"client and adapter budget epoch identities differ\")\n",
            1,
        ),
    ],
)

# The built-in server accepts only explicit loopback IP literals, not hostnames
# whose resolution may be changed independently of this check.
changes["src/online_budget/http_api.py"] = transform(
    "src/online_budget/http_api.py",
    [
        (
            "            lease_id = payload[\"lease_id\"]\n"
            "            lease = c.get_lease(lease_id)\n"
            "            if lease is None:\n"
            "                return {\"found\": False}\n"
            "            if gateway_id not in lease[\"allowed_gateway_ids\"]:\n"
            "                from .errors import GatewayNotAuthorized\n"
            "                raise GatewayNotAuthorized(\"Gateway is not authorized to inspect this Lease\")\n"
            "            return {\"found\": True, **lease}\n",
            "            lease_id = payload[\"lease_id\"]\n"
            "            lease = c.get_lease_for_gateway(gateway_id, lease_id)\n"
            "            if lease is None:\n"
            "                return {\"found\": False}\n"
            "            return {\"found\": True, **lease}\n",
            1,
        ),
        (
            "        host = server_address[0]\n"
            "        try:\n"
            "            loopback = ipaddress.ip_address(host).is_loopback\n"
            "        except ValueError:\n"
            "            loopback = isinstance(host, str) and host.lower() == \"localhost\"\n"
            "        if not loopback:\n"
            "            raise ValueError(\n"
            "                \"built-in Coordinator HTTP server is loopback-only; use a TLS reverse proxy \"\n"
            "                \"and forward to 127.0.0.1\"\n"
            "            )\n",
            "        host = server_address[0]\n"
            "        # D9.3.1: do not accept hostnames; validate the exact IP literal passed to bind().\n"
            "        try:\n"
            "            loopback = ipaddress.ip_address(host).is_loopback\n"
            "        except (ValueError, TypeError):\n"
            "            loopback = False\n"
            "        if not loopback:\n"
            "            raise ValueError(\n"
            "                \"built-in Coordinator HTTP server requires an explicit loopback IP literal; \"\n"
            "                \"use a TLS reverse proxy for remote Gateways\"\n"
            "            )\n",
            1,
        ),
    ],
)

# Update all in-repository Client constructions to supply the required budget epoch.
changes["examples/demo_online_flow.py"] = transform(
    "examples/demo_online_flow.py",
    [(
        "        coordinator_id=config[\"coordinator_id\"],\n",
        "        coordinator_id=config[\"coordinator_id\"],\n"
        "        global_budget_id=config[\"global_budget_id\"],\n",
        1,
    )],
)

changes["tests/process_consume_worker.py"] = transform(
    "tests/process_consume_worker.py",
    [(
        "        coordinator_id=config[\"coordinator_id\"],\n",
        "        coordinator_id=config[\"coordinator_id\"],\n"
        "        global_budget_id=config[\"global_budget_id\"],\n",
        1,
    )],
)

changes["tests/test_online_coordinator.py"] = transform(
    "tests/test_online_coordinator.py",
    [
        (
            "            coordinator_id=self.COORDINATOR_ID,\n",
            "            coordinator_id=self.COORDINATOR_ID,\n"
            "            global_budget_id=self.BUDGET_ID,\n",
            2,
        ),
        (
            "                \"coordinator_id\": self.COORDINATOR_ID,\n",
            "                \"coordinator_id\": self.COORDINATOR_ID,\n"
            "                \"global_budget_id\": self.BUDGET_ID,\n",
            1,
        ),
    ],
)

changes["tests/test_online_coordinator_adversarial.py"] = transform(
    "tests/test_online_coordinator_adversarial.py",
    [
        (
            "import socket\n",
            "import socket\n"
            "import sqlite3\n",
            1,
        ),
        (
            "    ConfigurationMismatch, CoordinatorHTTPServer, CoordinatorIndeterminate,\n"
            "    CoordinatorUnavailable, GlobalBudgetExceeded, LeaseCapExceeded, LeaseInactive,\n",
            "    AuthenticationError, ConfigurationMismatch, CoordinatorHTTPServer, CoordinatorIndeterminate,\n"
            "    CoordinatorUnavailable, GatewayNotAuthorized, GlobalBudgetExceeded, LeaseCapExceeded, LeaseInactive,\n",
            1,
        ),
        (
            "            coordinator_id=self.COORDINATOR_ID,\n"
            "            timeout_seconds=timeout,\n",
            "            coordinator_id=self.COORDINATOR_ID,\n"
            "            global_budget_id=self.BUDGET_ID,\n"
            "            timeout_seconds=timeout,\n",
            1,
        ),
        (
            "            \"coordinator_id\": self.COORDINATOR_ID,\n"
            "            \"gateway_id\": \"gateway-A\",\n",
            "            \"coordinator_id\": self.COORDINATOR_ID,\n"
            "            \"global_budget_id\": self.BUDGET_ID,\n"
            "            \"gateway_id\": \"gateway-A\",\n",
            1,
        ),
        (
            "\n\nif __name__ == \"__main__\":\n",
            "\n\n    def test_disabled_gateway_stays_disabled_after_restart_and_denies_mutations(self):\n"
            "        lease = self.make_lease(\"lease-disabled-persist\")\n"
            "        self.register(lease)\n"
            "        self.coordinator.disable_gateway(\"gateway-A\")\n"
            "\n"
            "        # Reconstructing the Coordinator must not turn the persisted disabled flag back on.\n"
            "        self.coordinator = self.make_coordinator()\n"
            "        self.server.coordinator = self.coordinator\n"
            "        self.assertIsNone(self.coordinator.gateway_public_key(\"gateway-A\"))\n"
            "\n"
            "        execution = self.make_execution(lease, \"disabled-consume-op\")\n"
            "        with self.assertRaises(GatewayNotAuthorized):\n"
            "            self.coordinator.consume(\"gateway-A\", lease, execution, operation_id=\"disabled-consume-op\",\n"
            "                                    request_digest=digest({\"disabled\": \"consume\"}))\n"
            "        new_lease = self.make_lease(\"lease-disabled-register\")\n"
            "        with self.assertRaises(GatewayNotAuthorized):\n"
            "            self.coordinator.register_lease(\"gateway-A\", new_lease)\n"
            "        revocation = issue_revocation(\n"
            "            self.issuer_private, issuer_id=lease.issuer_id, global_budget_id=self.BUDGET_ID,\n"
            "            revocation_id=\"revocation-disabled-gateway\", lease_id=lease.lease_id,\n"
            "            grant_digest=lease.grant_digest, revoked_at=self.now[0],\n"
            "        )\n"
            "        with self.assertRaises(GatewayNotAuthorized):\n"
            "            self.coordinator.revoke_lease(\"gateway-A\", revocation)\n"
            "        with self.assertRaises(AuthenticationError):\n"
            "            self.client().lookup_operation(\"disabled-consume-op\")\n"
            "        self.assertEqual(self.coordinator.assert_invariants()[\"global_used_count\"], 0)\n"
            "\n"
            "    def test_gateway_disable_serializes_after_an_admitted_consume(self):\n"
            "        lease = self.make_lease(\"lease-disable-consume-order\")\n"
            "        self.register(lease)\n"
            "        operation_id = \"disable-after-admission-op\"\n"
            "        execution = self.make_execution(lease, operation_id)\n"
            "        request_digest = digest({\"disable-order\": operation_id})\n"
            "        entered = threading.Event()\n"
            "        release = threading.Event()\n"
            "        disable_started = threading.Event()\n"
            "        original_check = self.coordinator._assert_gateway_allowed\n"
            "\n"
            "        def paused_check(con, gateway_id, grant):\n"
            "            original_check(con, gateway_id, grant)\n"
            "            entered.set()\n"
            "            if not release.wait(timeout=10):\n"
            "                raise TimeoutError(\"test gate timed out\")\n"
            "\n"
            "        self.coordinator._assert_gateway_allowed = paused_check\n"
            "        def disable():\n"
            "            disable_started.set()\n"
            "            self.coordinator.disable_gateway(\"gateway-A\")\n"
            "\n"
            "        pool = ThreadPoolExecutor(max_workers=2)\n"
            "        consume_future = pool.submit(\n"
            "            self.coordinator.consume, \"gateway-A\", lease, execution,\n"
            "            operation_id=operation_id, request_digest=request_digest,\n"
            "        )\n"
            "        disable_future = None\n"
            "        try:\n"
            "            self.assertTrue(entered.wait(5), \"consume did not reach in-transaction Gateway check\")\n"
            "            disable_future = pool.submit(disable)\n"
            "            self.assertTrue(disable_started.wait(3))\n"
            "            time.sleep(0.1)\n"
            "            self.assertFalse(disable_future.done(), \"disable should wait behind the active consume transaction\")\n"
            "            release.set()\n"
            "            receipt = consume_future.result(timeout=10)\n"
            "            disable_future.result(timeout=10)\n"
            "        finally:\n"
            "            release.set()\n"
            "            self.coordinator._assert_gateway_allowed = original_check\n"
            "            pool.shutdown(wait=True, cancel_futures=True)\n"
            "        self.assertEqual(receipt.payload[\"global_sequence\"], 1)\n"
            "        self.assertIsNone(self.coordinator.gateway_public_key(\"gateway-A\"))\n"
            "        self.assertEqual(self.coordinator.assert_invariants()[\"global_used_count\"], 1)\n"
            "\n"
            "    def test_startup_fails_closed_on_ledger_invariant_corruption(self):\n"
            "        lease = self.make_lease(\"lease-startup-corrupt\")\n"
            "        self.register(lease)\n"
            "        self.consume(lease, \"startup-corrupt-op\")\n"
            "        corrupt = sqlite3.connect(self.root / \"coordinator.sqlite3\")\n"
            "        try:\n"
            "            corrupt.execute(\"UPDATE budget_meta SET global_used_count=0 WHERE singleton_id=1\")\n"
            "            corrupt.commit()\n"
            "        finally:\n"
            "            corrupt.close()\n"
            "\n"
            "        with self.assertRaises(CoordinatorIndeterminate):\n"
            "            self.make_coordinator()\n"
            "\n"
            "    def test_operation_lookup_rejects_wrong_coordinator_or_budget_epoch(self):\n"
            "        lease = self.make_lease(\"lease-lookup-pinning\")\n"
            "        self.register(lease)\n"
            "        self.consume(lease, \"lookup-pinning-op\")\n"
            "        common = {\n"
            "            \"base_url\": self.base_url, \"gateway_id\": \"gateway-A\",\n"
            "            \"gateway_private_key\": self.gateway_a_private,\n"
            "            \"coordinator_public_key\": self.coordinator_private.public_key(),\n"
            "        }\n"
            "        wrong_coordinator = OnlineBudgetClient(\n"
            "            **common, coordinator_id=\"coordinator-impostor\", global_budget_id=self.BUDGET_ID,\n"
            "        )\n"
            "        with self.assertRaises(CoordinatorIndeterminate):\n"
            "            wrong_coordinator.lookup_operation(\"lookup-pinning-op\")\n"
            "        wrong_epoch = OnlineBudgetClient(\n"
            "            **common, coordinator_id=self.COORDINATOR_ID, global_budget_id=\"other-budget-epoch\",\n"
            "        )\n"
            "        with self.assertRaises(CoordinatorIndeterminate):\n"
            "            wrong_epoch.lookup_operation(\"lookup-pinning-op\")\n"
            "\n"
            "    def test_adapter_rejects_client_pinned_to_another_budget_epoch(self):\n"
            "        wrong_epoch_client = OnlineBudgetClient(\n"
            "            base_url=self.base_url, gateway_id=\"gateway-A\",\n"
            "            gateway_private_key=self.gateway_a_private,\n"
            "            coordinator_public_key=self.coordinator_private.public_key(),\n"
            "            coordinator_id=self.COORDINATOR_ID, global_budget_id=\"wrong-epoch\",\n"
            "        )\n"
            "        from online_budget import OnlineBudgetExecutionAdapter\n"
            "        with self.assertRaises(ValueError):\n"
            "            OnlineBudgetExecutionAdapter(\n"
            "                client=wrong_epoch_client, issuer_public_key=self.issuer_private.public_key(),\n"
            "                global_budget_id=self.BUDGET_ID, global_quota_limit=10,\n"
            "                coordinator_id=self.COORDINATOR_ID, receipt_cache_path=self.root / \"wrong-epoch-cache.sqlite3\",\n"
            "            )\n"
            "\n"
            "    def test_http_server_rejects_hostname_bind_and_chunked_transfer_encoding(self):\n"
            "        with self.assertRaises(ValueError):\n"
            "            CoordinatorHTTPServer((\"localhost\", 0), self.coordinator)\n"
            "        response = self._raw_http_request(\n"
            "            b\"POST /v1/budget/consume HTTP/1.1\\r\\n\"\n"
            "            b\"Host: 127.0.0.1\\r\\n\"\n"
            "            b\"Content-Type: application/json\\r\\n\"\n"
            "            b\"Transfer-Encoding: chunked\\r\\n\\r\\n\"\n"
            "            b\"2\\r\\n{}\\r\\n0\\r\\n\\r\\n\"\n"
            "        )\n"
            "        self.assertIn(b\" 400 \", response.split(b\"\\r\\n\", 1)[0])\n"
            "        self.assertIn(b\"Connection: close\", response)\n"
            "        self.assertEqual(self.coordinator.assert_invariants()[\"global_used_count\"], 0)\n"
            "\n"
            "\nif __name__ == \"__main__\":\n",
            1,
        ),
    ],
)

# Prepare every changed file before writing anything. This makes anchor mismatch
# a clean preflight failure rather than a half-applied source patch.
backup_root = Path(tempfile.mkdtemp(prefix="d93_1_hardening_backup_"))
for relative in changes:
    original = ROOT / relative
    backup = backup_root / relative
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, backup)

for relative, content in changes.items():
    target = ROOT / relative
    temporary = target.with_suffix(target.suffix + ".d93_1.tmp")
    temporary.write_text(content, encoding="utf-8", newline="")
    temporary.replace(target)

print("D9.3.1 source patch applied.")
print(f"Updated {len(changes)} existing files.")
print(f"Original-file backups: {backup_root}")
print("Next: run .\\run-tests.ps1 with PYTHONWARNINGS=error::ResourceWarning.")
