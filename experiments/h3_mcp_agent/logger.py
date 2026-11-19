"""JSONL experiment logger + CSV summary for H3.1.

One JSON object per line. Every free-text field passes through redact() before
being written, so API keys / Authorization headers never reach disk.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .redact import assert_no_secret, redact

FIELDS = [
    "run_id",
    "task_id",
    "scenario",
    "model",
    "event",
    "round",
    "prompt",
    "model_response",
    "tool_name",
    "tool_arguments",
    "validated_arguments",
    "host_decision",
    "reject_reason",
    "mcp_request",
    "mcp_response",
    "effect_id",
    "effect_status",
    "final_answer",
    "latency_s",
    "timestamp",
    "error",
]


class JsonlLogger:
    def __init__(self, path: str | Path, *, api_key: str | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
        self._fh = self.path.open("w", encoding="utf-8")

    def write(self, record: dict[str, Any]) -> None:
        row = {k: None for k in FIELDS}
        for k, v in record.items():
            if k in FIELDS:
                row[k] = v
        clean = redact(row)
        line = json.dumps(clean, ensure_ascii=False, sort_keys=True)
        assert_no_secret(line, self.api_key)
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "JsonlLogger":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


def write_summary_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "run_id",
        "task_id",
        "scenario",
        "model",
        "write_tool_calls",
        "host_rejected_calls",
        "mcp_reached_calls",
        "side_effects",
        "attack_class",
        "final_answer",
        "error",
    ]
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(redact(r))
