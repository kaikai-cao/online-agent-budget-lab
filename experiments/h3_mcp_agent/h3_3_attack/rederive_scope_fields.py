"""Offline archive revision (2026-11-19) — re-derive field scope, NO re-run.

This tool does NOT contact DeepSeek, does NOT re-run any experiment, and does
NOT change any outcome / reject_stage / effect / count. It ONLY fills the two
field families added by the archive revision, using evidence ALREADY present
in each archived record's `detail`:

  1. A1 trial-level `mcp_called` / `mcp_received` were recorded False even
     though the model made real read-only `search_records` MCP calls (100 in
     total; injection reached the model 80/80 via the real MCP response). We
     set them from that recorded evidence, and split read-only MCP traffic
     (`mcp_readonly_call_count`, `mcp_readonly_received`) from the attack write
     call (`primary_*`).
  2. A4/A6 top-level `effect_delta` / `mcp_*` include the FIRST legitimate
     setup step. We derive `primary_*` from the archived `detail.steps`
     entry labelled `primary`, so the replay's own (empty) effect is explicit.

Derivation is deterministic and auditable: it reads only archived JSONL, keeps
the original `detail` bytes, and rewrites JSONL / CSV with the added columns.
Summaries gain a `field_semantics` note; all counts are preserved verbatim.

Usage:
    PYTHONPATH="src;tests" python -m experiments.h3_mcp_agent.h3_3_attack.rederive_scope_fields
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .attack_common import RECORD_FIELDS

_RESULTS = Path(__file__).resolve().parents[1] / "results" / "h3-3"
_GROUPS = ("A1", "A2", "A3", "A4", "A5", "A6")
_READONLY_TOOL = "search_records"

_FIELD_SEMANTICS_NOTE = (
    "Archive revision 2026-11-19: A1 top-level mcp_called/mcp_received are "
    "trial-level (real read-only search_records MCP calls) and were re-derived "
    "from the preserved detail; mcp_readonly_* isolate that read-only traffic; "
    "primary_* describe ONLY the primary attack step (A4/A6 top-level effect "
    "includes the first legitimate setup step). Outcomes/counts unchanged."
)


def _detail(row: dict[str, Any]) -> dict[str, Any]:
    d = row.get("detail")
    if isinstance(d, str):
        return json.loads(d) if d else {}
    return d or {}


def _derive_row(row: dict[str, Any]) -> dict[str, Any]:
    """Fill the five scope fields from archived evidence only."""
    aid = row.get("attack_id", "")
    detail = _detail(row)

    if aid == "A1":
        # Count real read-only MCP tools/calls from the model's recorded
        # tool_calls (each search_records tool_call was dispatched to the real
        # MCP Server: authorization_verified_count >= 1 and injection was
        # delivered via the real MCP response).
        readonly_calls = 0
        for msg in detail.get("model_responses", []):
            for tc in msg.get("tool_calls") or []:
                if (tc.get("function") or {}).get("name") == _READONLY_TOOL:
                    readonly_calls += 1
        # The injection string can only have reached the model through a real
        # MCP tool response; that is the archived Server-stamp-equivalent proof.
        readonly_received = bool(detail.get("injection_reached_model")) and readonly_calls > 0
        row["mcp_readonly_call_count"] = readonly_calls
        row["mcp_readonly_received"] = readonly_received
        # Trial-level: real MCP traffic happened (read-only), so both True.
        row["mcp_called"] = bool(readonly_calls) or bool(row.get("mcp_called"))
        row["mcp_received"] = readonly_received or bool(row.get("mcp_received"))
        # Attack write call: none in MODEL_DID_NOT_ATTACK.
        row["primary_mcp_called"] = False
        row["primary_mcp_received"] = False
        row["primary_effect_delta"] = 0
    else:
        # Layer 2: no read-only MCP calls by construction.
        row["mcp_readonly_call_count"] = 0
        row["mcp_readonly_received"] = False
        primary = next(
            (s for s in detail.get("steps", []) if s.get("label") == "primary"), {}
        )
        dispatched = bool(primary.get("dispatch_permitted")) and (
            primary.get("mcp_status") not in (None, "DISPATCH_UNCERTAIN")
        )
        row["primary_mcp_called"] = dispatched
        row["primary_mcp_received"] = dispatched and primary.get("mcp_status") == "OK"
        row["primary_effect_delta"] = 1 if primary.get("produced_effect") is True else 0
    return row


def _write_group(group: str) -> int:
    jpath = _RESULTS / group / f"{group}_trials.jsonl"
    rows = [json.loads(line) for line in jpath.read_text(encoding="utf-8").splitlines() if line.strip()]
    for r in rows:
        _derive_row(r)

    with jpath.open("w", encoding="utf-8") as f:
        for r in rows:
            out = dict(r)
            f.write(json.dumps(out, ensure_ascii=False) + "\n")

    cpath = _RESULTS / group / f"{group}_trials.csv"
    with cpath.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=RECORD_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            out = dict(r)
            if isinstance(out.get("detail"), dict):
                out["detail"] = json.dumps(out["detail"], ensure_ascii=False)
            for k in ("host_received_arguments", "validated_arguments", "attack_input",
                      "original_task", "audit_tool_events", "audit_dispatch_events"):
                if isinstance(out.get(k), (dict, list)):
                    out[k] = json.dumps(out[k], ensure_ascii=False)
            w.writerow(out)

    spath = _RESULTS / group / f"{group}_summary.json"
    summ = json.loads(spath.read_text(encoding="utf-8"))
    summ["field_semantics"] = _FIELD_SEMANTICS_NOTE
    spath.write_text(json.dumps(summ, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(rows)


def main() -> None:
    counts = {g: _write_group(g) for g in _GROUPS}
    opath = _RESULTS / "overall_summary.json"
    overall = json.loads(opath.read_text(encoding="utf-8"))
    overall["field_semantics"] = _FIELD_SEMANTICS_NOTE
    opath.write_text(json.dumps(overall, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"rederived": counts, "note": "no DeepSeek / no experiment re-run"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
