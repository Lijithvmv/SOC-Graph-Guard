"""Core data contracts: every tool result carries provenance, every action carries a receipt.

The rule these types enforce: a report may only say something happened if a tool receipt proves it.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Source(str, Enum):
    """Where a tool result came from. Reports must show this, so simulated data never passes as real."""

    LIVE = "live"  # a real system
    REPLAY = "replay"  # recorded / scenario data replayed through a backend
    MOCK = "mock"  # synthetic stand-in


class ToolResult(BaseModel):
    """The output of one tool call, with provenance and a receipt id that reports can cite."""

    tool: str
    data: Any
    source: Source
    receipt: str = Field(default_factory=lambda: f"rcpt-{uuid.uuid4().hex[:12]}")


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"  # the graph could not reach a safe conclusion on its own


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Assessment(BaseModel):
    """A deterministic assessment computed only from structured evidence, never from free text."""

    verdict: Verdict
    risk: RiskLevel
    reasons: list[str]
    evidence_receipts: list[str]


class ActionRequest(BaseModel):
    """An action the workflow wants to take, before autonomy grading."""

    name: str
    target: str
    reason: str
    evidence_receipts: list[str] = Field(default_factory=list)


class ActionRecord(BaseModel):
    """An action that was executed, with the receipt of the executing tool call."""

    name: str
    target: str
    receipt: str
    approved_by: str  # "auto" or the approver's id


class Report(BaseModel):
    """What the workflow tells the analyst. `actions_taken` only ever lists receipted actions."""

    scenario_id: str
    verdict: Verdict
    risk: RiskLevel
    summary: str
    reasons: list[str]
    actions_taken: list[ActionRecord]
    actions_pending_or_denied: list[str]
    injection_detected: bool
    evidence_sources: dict[str, str]  # receipt -> source (live / replay / mock)
