"""Deterministic assessment and action planning from structured evidence only.

The attacker can write log fields and email bodies. They can't change a threat-intel score, a SIEM event count
or the asset inventory. So verdicts are computed from those, and free text is never an input here. That's
what makes an *undetected* injection harmless to the decision.
"""

from __future__ import annotations

from typing import Any

from soc_graph_guard.models import ActionRequest, Assessment, RiskLevel, ToolResult, Verdict


def _max_score(ti: list[ToolResult]) -> int | None:
    scores = [r.data.get("score") for r in ti if r.data.get("score") is not None]
    return max(scores) if scores else None


def assess(kind: str, alert: dict[str, Any], ti: list[ToolResult], siem: list[ToolResult],
           mail: ToolResult | None) -> Assessment:
    receipts = [r.receipt for r in ti + siem + ([mail] if mail else [])]
    top = _max_score(ti)
    hits = sum(len(r.data.get("events", [])) for r in siem)
    reasons = [f"max threat-intel score: {top if top is not None else 'no data'}", f"SIEM events: {hits}"]

    if kind == "triage":
        # `baseline` comes from the asset inventory (a trusted, structured source), never from the alert text.
        if alert.get("baseline") == "approved_scanner" and (top is None or top < 40):
            reasons.append("asset inventory: approved internal scanner")
            return Assessment(verdict=Verdict.BENIGN, risk=RiskLevel.LOW, reasons=reasons, evidence_receipts=receipts)
        if (top or 0) >= 70 or ((top or 0) >= 40 and hits >= 5):
            return Assessment(verdict=Verdict.TRUE_POSITIVE, risk=RiskLevel.HIGH, reasons=reasons, evidence_receipts=receipts)
        if (top or 0) >= 40 or hits >= 5:
            return Assessment(verdict=Verdict.NEEDS_REVIEW, risk=RiskLevel.MEDIUM, reasons=reasons, evidence_receipts=receipts)
        return Assessment(verdict=Verdict.BENIGN, risk=RiskLevel.LOW, reasons=reasons, evidence_receipts=receipts)

    if kind == "phishing":
        scope = mail.data if mail else {}
        clicked = len(scope.get("clicked_users", []))
        harvesting = bool(scope.get("credential_harvesting"))
        reasons += [f"recipients: {scope.get('recipients', 0)}", f"users who clicked: {clicked}",
                    f"credential harvesting observed: {harvesting}"]
        if harvesting or (clicked > 0 and (top or 0) >= 70):
            return Assessment(verdict=Verdict.TRUE_POSITIVE, risk=RiskLevel.HIGH, reasons=reasons, evidence_receipts=receipts)
        if (top is None or top < 20) and clicked == 0:
            return Assessment(verdict=Verdict.BENIGN, risk=RiskLevel.LOW, reasons=reasons, evidence_receipts=receipts)
        return Assessment(verdict=Verdict.NEEDS_REVIEW, risk=RiskLevel.MEDIUM, reasons=reasons, evidence_receipts=receipts)

    return Assessment(verdict=Verdict.NEEDS_REVIEW, risk=RiskLevel.MEDIUM,
                      reasons=reasons + [f"unknown workflow kind {kind!r}"], evidence_receipts=receipts)


def plan(kind: str, a: Assessment, alert: dict[str, Any], mail: ToolResult | None) -> list[ActionRequest]:
    """Map a verdict to requested actions. Anything not explicitly mapped escalates to a human (safe default)."""
    ev = a.evidence_receipts
    case = alert.get("alert_id", "unknown-case")
    if kind == "phishing" and a.verdict is Verdict.TRUE_POSITIVE and mail:
        scope = mail.data
        actions = [
            ActionRequest(name="purge_email", target=scope.get("subject", "?"), reason="credential phishing in mailboxes", evidence_receipts=ev),
            ActionRequest(name="block_domain", target=scope.get("sender_domain", "?"), reason="phishing sender infrastructure", evidence_receipts=ev),
        ]
        actions += [ActionRequest(name="reset_password", target=u, reason="user clicked the phishing link", evidence_receipts=ev)
                    for u in scope.get("clicked_users", [])]
        return actions + [ActionRequest(name="escalate_case", target=case, reason="confirmed phishing incident", evidence_receipts=ev)]
    if a.verdict is Verdict.TRUE_POSITIVE:
        return [ActionRequest(name="escalate_case", target=case, reason="evidence supports a true positive", evidence_receipts=ev)]
    if a.verdict is Verdict.BENIGN:
        return [ActionRequest(name="close_case", target=case, reason="evidence supports benign", evidence_receipts=ev)]
    return [ActionRequest(name="escalate_case", target=case, reason="inconclusive: human review", evidence_receipts=ev)]
