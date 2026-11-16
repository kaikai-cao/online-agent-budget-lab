# Online Agent Budget Lab

A standalone research repository for the Online Global Budget Coordination work (D9).

## Current status

- **D9.0:** protocol design proposal prepared; pending review and acceptance.
- **D9.1:** coordinator and client implementation not started.
- **Offline baseline:** maintained separately in [`kaikai-cao/offline-agent-budget-lab`](https://github.com/kaikai-cao/offline-agent-budget-lab), frozen at commit `10577ab5d53181aef522b7c8f920e4dc7251a124`.

## Repository layout

```text
online-agent-budget-lab/
├── README.md
└── docs/
    └── D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md
```

## Design document

Read [`docs/D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md`](docs/D9.0_ONLINE_GLOBAL_BUDGET_DESIGN.md) first.

The document is a proposal, not an implementation or security proof. The initial Online version is scoped as one logical Coordinator with one authoritative transactional database. Replication, high availability, consensus, multi-region operation, and production deployment are out of scope for D9.1 unless explicitly added in a later design decision.
