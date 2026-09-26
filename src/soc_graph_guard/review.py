"""Human review. In production, the approval payload goes to a real analyst (chat, SOAR task, ticket).

`CautiousReviewer` is a deterministic stand-in for evaluations: it reads only the structured evidence summary,
as a careful analyst would, and approves containment only when the evidence says HIGH risk and closure only
when it says LOW. It never sees ground-truth labels.
"""

from __future__ import annotations

from typing import Any, Protocol

CONTAINMENT = {"purge_email", "block_domain", "reset_password", "disable_account"}


class Reviewer(Protocol):
    id: str

    def review(self, payload: dict[str, Any]) -> dict[str, bool]: ...


class CautiousReviewer:
    id = "reviewer:cautious-sim"

    def review(self, payload: dict[str, Any]) -> dict[str, bool]:
        risk = payload["assessment"]["risk"]
        decisions: dict[str, bool] = {}
        for req in payload["requests"]:
            key = f"{req['name']}:{req['target']}"
            if not req.get("evidence_receipts"):
                decisions[key] = False  # never approve an action that cites no evidence
            elif req["name"] in CONTAINMENT:
                decisions[key] = risk == "high"
            elif req["name"] == "close_case":
                decisions[key] = risk == "low"
            else:
                decisions[key] = True  # escalation / comments are always acceptable
        return decisions


class DenyAll:
    id = "reviewer:deny-all"

    def review(self, payload: dict[str, Any]) -> dict[str, bool]:
        return {f"{r['name']}:{r['target']}": False for r in payload["requests"]}
