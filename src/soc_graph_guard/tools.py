"""Tool backends: read tools return provenance-tagged results; action tools return receipts.

`ReplayBackend` serves a labelled scenario file, so every run is repeatable and needs no SIEM tenant.
A live backend (for example, MCP clients for your SIEM, threat-intel and SOAR) implements the same methods.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from soc_graph_guard.models import ActionRecord, Source, ToolResult


class ToolBackend(Protocol):
    def get_alert(self) -> ToolResult: ...
    def threat_intel(self, indicator: str) -> ToolResult: ...
    def siem_search(self, indicator: str) -> ToolResult: ...
    def mail_scope(self) -> ToolResult: ...
    def execute(self, action: str, target: str, approved_by: str) -> ActionRecord: ...


class ReplayBackend:
    """Replays one scenario. Unknown lookups return an explicit empty result, never an invented one."""

    source = Source.REPLAY

    def __init__(self, scenario: dict[str, Any]):
        self.scenario = scenario
        self.executed: list[ActionRecord] = []

    @classmethod
    def from_file(cls, path: str | Path) -> ReplayBackend:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def get_alert(self) -> ToolResult:
        return ToolResult(tool="get_alert", data=self.scenario["alert"], source=self.source)

    def threat_intel(self, indicator: str) -> ToolResult:
        ti = self.scenario.get("threat_intel", {})
        data = ti.get(indicator, {"indicator": indicator, "score": None, "found": False})
        return ToolResult(tool="threat_intel", data=data, source=self.source)

    def siem_search(self, indicator: str) -> ToolResult:
        events = [e for e in self.scenario.get("siem_events", []) if indicator in json.dumps(e)]
        return ToolResult(tool="siem_search", data={"indicator": indicator, "events": events}, source=self.source)

    def mail_scope(self) -> ToolResult:
        return ToolResult(tool="mail_scope", data=self.scenario.get("mail_scope", {}), source=self.source)

    def execute(self, action: str, target: str, approved_by: str) -> ActionRecord:
        record = ToolResult(tool=action, data={"target": target, "status": "ok"}, source=self.source)
        rec = ActionRecord(name=action, target=target, receipt=record.receipt, approved_by=approved_by)
        self.executed.append(rec)
        return rec
