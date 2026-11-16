# Online Agent Budget Lab

A standalone research repository for the Online Global Budget Coordination work (D9).

## Current status

- **D9.0:** design decisions accepted as the D9.1 reference-model baseline.
- **D9.1:** single-node HTTP Coordinator, SQLite WAL ledger, Online Lease Grant v4, Gateway request authentication, signed Budget Receipts, HTTP client and E4.8.3-compatible Online adapter implemented as a reference model.
- **D9.1 local validation:** 15 tests pass, including independent Gateway OS processes racing for the final global budget unit.
- **Offline baseline:** maintained separately in [`kaikai-cao/offline-agent-budget-lab`](https://github.com/kaikai-cao/offline-agent-budget-lab), frozen at commit `10577ab5d53181aef522b7c8f920e4dc7251a124`.

D9.1 is not a replicated or production-ready service. The Coordinator must be the sole authority for new consumption; the client has no local spending fallback.

## Repository layout

```text
online-agent-budget-lab/
├── README.md
├── requirements.txt
├── pyproject.toml
├── run_coordinator.py
├── run-tests.ps1
├── scripts/
│   └── create_dev_config.py
├── examples/
│   └── demo_online_flow.py
├── src/
│   └── online_budget/
│       ├── adapter.py
│       ├── auth.py
│       ├── canonical.py
│       ├── client.py
│       ├── coordinator.py
│       ├── errors.py
│       ├── grants.py
│       ├── http_api.py
│       ├── receipt_chain.py
│       └── receipts.py
├── tests/
│   ├── process_consume_worker.py
│   └── test_online_coordinator.py
└── docs/
    ├── D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md
    └── D9.1_SINGLE_NODE_COORDINATOR_IMPLEMENTATION.md
```

## Quick start (local development only)

Python 3.10+ is required.

```powershell
python -m pip install -r requirements.txt
python scripts/create_dev_config.py
python run_coordinator.py --config coordinator-config.json --host 127.0.0.1 --port 8765
```

In a second PowerShell window:

```powershell
python examples/demo_online_flow.py
```

The demonstration registers an Issuer-signed v4 Lease Grant, sends an authenticated consume request, and verifies the Coordinator-signed Budget Receipt.

The development configuration writes `coordinator-config.json` and `dev-client-keys.json`. They contain private keys and are excluded by `.gitignore`. They are test-only keys and must never be committed or reused.

## Run tests

Preferred PowerShell entry point (sets the `src` import path automatically):

```powershell
.\run-tests.ps1
```

Equivalent direct command from the repository root:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m unittest discover -s tests -v
```

Expected D9.1 reference-model result: **15 tests pass**.

## Security and deployment boundary

- One logical Coordinator process owns the authoritative SQLite WAL database. Gateways communicate over HTTP and never open the database file.
- SQLite WAL is local to the Coordinator host; do not put the database on a network share or have remote Gateways access it directly.
- The built-in HTTP server is for local development. Any non-loopback deployment must use TLS termination and a hardened network boundary.
- Gateway authentication uses Ed25519 signatures over the HTTP method, exact path and canonical request payload. Exact replays are safe only because state-changing operations are idempotent and operation IDs are bound to immutable request tuples.
- The Coordinator verifies Issuer signatures on Online Lease Grant v4 and Execution Grant v2. It signs Budget Receipts; the adapter verifies them before returning a budget-confirmed result.
- The Online adapter persists verified Coordinator receipts in a Gateway-local SQLite cache. An exact, already-committed operation can be resumed from that cache during a Coordinator outage; an operation without a cached signed receipt cannot spend while the Coordinator is unavailable.
- `build_receipt_chain()` creates an additional Gateway signature linking the Coordinator Budget Receipt to the E4.8.3 execution receipt without modifying the frozen Offline repository.
- `quota_limit` in Online v1 is a per-Lease cap, not a global reservation. `SUM(quota_limit)` may exceed `G`; only committed usage is charged against the global cap.
- This prototype does not implement Coordinator replication, HA, consensus, key rotation, rate limiting, TLS itself, TPM/TEE, multi-region writes, fair scheduling, variable-cost operations or arbitrary external-tool exactly-once effects.

See [`docs/D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md`](docs/D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md) and [`docs/D9.1_SINGLE_NODE_COORDINATOR_IMPLEMENTATION.md`](docs/D9.1_SINGLE_NODE_COORDINATOR_IMPLEMENTATION.md) for protocol and implementation details.
