"""Independent experiment controller — the ONLY writer/owner of ground truth.

CRITICAL ISOLATION RULE
-----------------------
``GroundTruthEvent.service_executed`` is the evaluation truth. It is recorded
here, in the controller, and is NEVER handed to a verifier. The verifier views
(below in verifier.py) accept only signed observable records. This module has
NO import relationship with verifier.py, and verifier.py never imports this
module. Tests assert the separation explicitly.

The controller observes what physically happened at the service boundary:
  - was a gateway receipt present and valid?
  - did the request reach the service entrance?
  - did the service accept it?
  - did the service body actually execute?
These are controller observations for scoring only, not verifier inputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import GroundTruthEvent


@dataclass
class GroundTruthStore:
    """Controller-side authoritative log. Not importable by verifier views."""
    events: list[GroundTruthEvent] = field(default_factory=list)

    def record(self, event: GroundTruthEvent) -> None:
        self.events.append(event)

    def all(self) -> list[GroundTruthEvent]:
        return list(self.events)

    def executed_calls(self) -> list[GroundTruthEvent]:
        return [e for e in self.events if e.service_executed]

    def by_call(self, logical_call_id: str, attempt_id: str) -> GroundTruthEvent | None:
        for e in self.events:
            if e.logical_call_id == logical_call_id and e.attempt_id == attempt_id:
                return e
        return None
