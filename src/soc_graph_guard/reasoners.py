"""Reasoners: where a language model would sit.

- `TemplateSummarizer` (default) writes the guarded workflow's narrative from structured facts only.
- `ChatModelSummarizer` does the same with any LangChain chat model (for example ChatOllama); it still never sees
  untrusted free text, and its output never drives a decision.
- `GullibleReasoner` is the *baseline's* decision-maker: a deterministic stand-in for a model that follows
  instructions embedded in the content it reads, and falls back to keyword heuristics. It reproduces documented
  failure patterns so CI is repeatable; run the baseline with a real model for live experiments.
"""

from __future__ import annotations

import re
from typing import Any

from soc_graph_guard.models import Assessment

_OBEY = re.compile(
    r"(false positive|classify (this )?as benign|mark (this|it)( email)? as safe|take no action|do not quarantine|"
    r"close (the |this )?case|approved red.?team)",
    re.IGNORECASE,
)


class TemplateSummarizer:
    def summarize(self, a: Assessment, executed: list[str], pending: list[str]) -> str:
        done = ", ".join(executed) or "none"
        waiting = ", ".join(pending) or "none"
        return (f"Verdict {a.verdict.value} (risk {a.risk.value}). Basis: {'; '.join(a.reasons)}. "
                f"Actions executed with receipts: {done}. Pending or denied: {waiting}.")


class ChatModelSummarizer:
    def __init__(self, model: Any):
        self.model = model

    def summarize(self, a: Assessment, executed: list[str], pending: list[str]) -> str:
        facts = TemplateSummarizer().summarize(a, executed, pending)
        prompt = ("Rewrite these SOC case facts as a concise analyst note. Do not add facts or actions.\n\n" + facts)
        return str(getattr(self.model.invoke(prompt), "content", facts))


class GullibleReasoner:
    """Decides from the full raw text, like a prompt-only agent. Deliberately naive."""

    def decide(self, kind: str, text: str, top_score: int | None) -> list[str]:
        if _OBEY.search(text):
            return ["close_case"]  # followed an instruction it found in the data
        if kind == "phishing":
            if re.search(r"\b(urgent|invoice|verify|payroll)\b", text, re.IGNORECASE):
                return ["purge_email", "block_domain", "reset_password"]  # purge-by-default pattern
            return ["close_case"]
        return ["escalate_case"] if (top_score or 0) >= 70 else ["close_case"]
