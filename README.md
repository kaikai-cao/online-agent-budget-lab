
# Online Agent Budget Lab

A standalone research prototype for single-node Online Global Budget Coordination (D9).

## Project status

The repository implements and validates a single-node Online Budget Coordinator and an E4.8.3-compatible Gateway adapter.

| Stage | Result |
|---|---|
| D9.0 — Design baseline | Completed |
| D9.1 — Single-node Coordinator implementation | Completed |
| D9.2 — Adversarial and recovery tests | Completed |
| D9.3 — Security boundary review | Completed |
| D9.3.1 — Bounded hardening | Completed |
| D9.4 — Online v1 integration acceptance | Acceptance recorded; see the D9.4 report |

Current validated baseline: `69dac31` (`fix: harden single-node online budget coordinator`).

The D9.4 validation run on the Windows development environment reported **31 tests passing**. It also completed a separate HTTP smoke test using an isolated worktree, generated development keys, and a temporary SQLite database.

This is a research reference implementation, not a production-ready distributed service.

## Architecture

- One logical Coordinator process owns the authoritative SQLite WAL ledger.
- Gateways communicate with the Coordinator over the HTTP API. Gateways do not access the authoritative database directly.
- Online Lease Grant v4 and Execution Grant v2 are Issuer-signed.
- Gateway requests are authenticated using Ed25519.
- The Coordinator atomically admits new budget consumption and issues signed Budget Receipts.
- The Gateway-side Online adapter verifies and caches Coordinator receipts and can construct a receipt chain linking a Gateway execution receipt to a Coordinator budget receipt.

The Coordinator is the authority for **new** budget consumption. If it is unavailable, a new operation cannot obtain a budget authorization. An exact replay of an already committed operation may be served from a locally cached, verified receipt.

## Core accounting invariants

For each Lease \(i\):

- `0 <= U_i <= Q_i`
- `S = SUM(U_i)`
- `0 <= S <= G`

Where:

- `U_i` is the committed usage of Lease `i`.
- `Q_i` is the Lease quota.
- `S` is the global committed usage.
- `G` is the global budget limit.

Each committed operation consumes one unit. The operation record count and receipt count must match committed global usage, and global sequence numbers must be unique and contiguous.

Lease quotas are per-Lease hard caps, not global reservations. The sum of Lease quota limits may exceed the global budget limit.

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
├── tests/
└── docs/
```

## Local development

Python 3.10+ is required.

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Generate development configuration and keys:

```powershell
python scripts/create_dev_config.py
```

Start the Coordinator:

```powershell
python run_coordinator.py --config coordinator-config.json --host 127.0.0.1 --port 8765
```

In a second PowerShell window, run the HTTP demonstration:

```powershell
python examples/demo_online_flow.py
```

The demonstration exercises the HTTP Coordinator and Client path: Lease Grant registration, authenticated budget consumption, receipt retrieval, and Coordinator receipt signature verification. It does **not** invoke an external tool or demonstrate a complete Agent tool-execution workflow.

The generated `coordinator-config.json` and `dev-client-keys.json` contain private development keys. They are test-only, git-ignored, and must never be committed or reused.

## Run tests

Preferred PowerShell entry point:

```powershell
.\run-tests.ps1
```

Equivalent direct command:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m unittest discover -s tests -v
```

The D9.4 Windows acceptance run completed with:

```text
Ran 31 tests
OK
```

The run was performed with:

```powershell
$env:PYTHONWARNINGS = "error::ResourceWarning"
```

No ResourceWarning interrupted the test run. See `docs/D9.4_ONLINE_V1_ACCEPTANCE.md` for the acceptance scope and evidence.

## Security and deployment boundaries

- **Single node only:** this implementation does not provide Coordinator replication, consensus, leader election, or high availability.
- **Coordinator availability:** new budget consumption fails closed when the Coordinator cannot be reached. There is no local spending fallback.
- **Database scope:** SQLite WAL is local to the Coordinator host. Do not place the authoritative database on a network share or let remote Gateways open it directly.
- **HTTP deployment:** the built-in HTTP server is intended for local development and loopback binding. A remote deployment requires a separately hardened network boundary and TLS termination.
- **Gateway and adapter trust:** the Coordinator authenticates the Gateway and binds an opaque request digest into its operation record and receipt. It does not independently prove that the digest corresponds to a particular tool name, schema, and canonical argument tuple. That semantic validation remains the responsibility of the trusted Gateway/Tool Adapter.
- **Receipt meaning:** a signed Coordinator receipt attests to the Coordinator's budget admission and recorded request binding. It is not, by itself, proof that an external tool actually executed or produced a particular result.
- **Rollback boundary:** internal invariant checks can detect many inconsistent database states, but cannot detect restoration of an older, internally consistent database snapshot without an external monotonic anchor.
- **Key lifecycle:** production-grade key rotation, a complete authenticated administration plane, KMS/HSM integration, and hardware-backed anti-rollback are not implemented.
- **Other exclusions:** multi-region writes, fair scheduling, variable-cost accounting, refunds, and arbitrary external-tool exactly-once effects are outside the current scope.

The Offline baseline is maintained separately in [`kaikai-cao/offline-agent-budget-lab`](https://github.com/kaikai-cao/offline-agent-budget-lab). This repository does not modify that frozen project.

## Design and acceptance records

- `docs/D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md` — protocol and design baseline.
- `docs/D9.1_SINGLE_NODE_COORDINATOR_IMPLEMENTATION.md` — initial implementation record.
- `docs/D9.3_ONLINE_V1_SECURITY_BOUNDARY_REVIEW.md` — security boundary review and findings.
- `docs/D9.4_ONLINE_V1_ACCEPTANCE.md` — integration acceptance evidence and freeze assessment.
