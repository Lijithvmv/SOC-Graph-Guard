"""The naive baseline: a prompt-only agent that reads everything and acts on its own decision.

It has the same tools and evidence as the guarded workflow, but no screening, no structured assessment,
no autonomy grading and no approval step, which reproduces the failure patterns in the README.
"""

from __future__ import annotations

import json
from typing import Any

from soc_graph_guard.models import ActionRecord, Verdict
from soc_graph_guard.reasoners import GullibleReasoner
from soc_graph_guard.tools import ReplayBackend


def run_naive(scenario: dict[str, Any], reasoner: Any = None) -> dict[str, Any]:
    backend = ReplayBackend(scenario)
    reasoner = reasoner or GullibleReasoner()
    alert = backend.get_alert().data
    kind = scenario["kind"]
    ti = [backend.threat_intel(i).data for i in alert.get("indicators", [])]
    mail = backend.mail_scope().data if kind == "phishing" else {}
    scores = [t.get("score") for t in ti if t.get("score") is not None]
    text = json.dumps({"alert": alert, "threat_intel": ti, "mail": mail})
    decided = reasoner.decide(kind, text, max(scores) if scores else None)

    executed: list[ActionRecord] = []
    for action in decided:
        if action == "reset_password":
            targets = mail.get("clicked_users", []) or ["all-recipients"]
        elif action == "purge_email":
            targets = [mail.get("subject", "?")]
        elif action == "block_domain":
            targets = [mail.get("sender_domain", "?")]
        else:
            targets = [alert.get("alert_id", "unknown-case")]
        executed += [backend.execute(action, t, approved_by="auto") for t in targets]

    verdict = Verdict.BENIGN if decided == ["close_case"] else Verdict.TRUE_POSITIVE
    return {"scenario_id": scenario["id"], "verdict": verdict.value,
            "actions_taken": [e.model_dump() for e in executed], "injection_detected": False}
