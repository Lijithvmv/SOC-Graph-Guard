"""Screen attacker-influenced fields (log fields, email bodies, notes) with GuardLayer before anything reads them.

Detection is one layer, not the defence: GuardLayer catches blatant injections, and a subtle one can get through.
That's why the assessment never reads free text at all (see `assess.py`). Screening decides *taint*, and a
tainted session needs a human for every action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from guardlayer import GuardLayer, Verdict


@dataclass
class ScreenResult:
    field: str
    verdict: str
    rules: list[str] = field(default_factory=list)


class InputScreen:
    def __init__(self, guard: GuardLayer | None = None, threshold: Verdict = Verdict.FLAG):
        self.guard = guard or GuardLayer()
        self.threshold = threshold

    def screen(self, untrusted: dict[str, Any]) -> tuple[bool, list[ScreenResult]]:
        """Return (tainted, per-field results). Tainted if any field reaches the threshold verdict."""
        results: list[ScreenResult] = []
        tainted = False
        for name, value in untrusted.items():
            if not value:
                continue
            r = self.guard.scan_context(str(value), source=name)
            rules = sorted({d.rule for d in r.detections if d.rule != "ip_address"})
            results.append(ScreenResult(field=name, verdict=r.verdict.value, rules=rules))
            if r.verdict >= self.threshold:
                tainted = True
        return tainted, results
