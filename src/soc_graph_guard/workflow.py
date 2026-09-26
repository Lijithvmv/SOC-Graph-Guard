"""The guarded SOC workflow as a LangGraph graph.

load → enrich → screen → assess → plan_and_grade ─┬─> approval_gate (interrupt) ─┐
                                                   └─> execute <─────────────────┘ → report

Controls, and where they live:
1. provenance on every tool result ............ tools.py (ToolResult.source, receipt)
2. decisions from structured evidence only .... assess.py (free text never read)
3. injection screening → taint ................ guard.py (GuardLayer)
4. graded autonomy per action ................. autonomy.py
5. human approval before high-potency actions . approval_gate (LangGraph interrupt)
6. unmapped verdicts escalate, never act ...... assess.plan()
7. hash-chained decision log .................. audit.py
8. reports list only receipted actions ........ report node
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from soc_graph_guard.assess import assess, plan
from soc_graph_guard.audit import DecisionLog
from soc_graph_guard.autonomy import Autonomy, grade
from soc_graph_guard.guard import InputScreen
from soc_graph_guard.models import Assessment, Report, ToolResult
from soc_graph_guard.reasoners import TemplateSummarizer
from soc_graph_guard.tools import ToolBackend

ALLOWED: dict[str, frozenset[str]] = {
    "triage": frozenset({"add_case_comment", "escalate_case", "close_case"}),
    "phishing": frozenset({"add_case_comment", "escalate_case", "close_case", "purge_email", "block_domain", "reset_password"}),
}


class SocState(TypedDict, total=False):
    scenario_id: str
    kind: str
    alert: dict[str, Any]
    ti: list[dict[str, Any]]
    siem: list[dict[str, Any]]
    mail: dict[str, Any] | None
    tainted: bool
    screen: list[dict[str, Any]]
    assessment: dict[str, Any]
    auto: list[dict[str, Any]]
    needs_approval: list[dict[str, Any]]
    denied: list[str]
    approved: list[dict[str, Any]]
    approver: str
    executed: list[dict[str, Any]]
    report: dict[str, Any]


def _key(req: dict[str, Any]) -> str:
    return f"{req['name']}:{req['target']}"


def build_workflow(backend: ToolBackend, *, screen: InputScreen | None = None, log: DecisionLog | None = None,
                   summarizer: Any = None, checkpointer: Any = None):
    """Build the compiled graph. Dependencies are injected, so the same graph runs on replay or live backends."""
    screen = screen or InputScreen()
    log = log if log is not None else DecisionLog()
    summarizer = summarizer or TemplateSummarizer()

    def load(state: SocState) -> SocState:
        alert = backend.get_alert()
        log.append("alert_loaded", receipt=alert.receipt, source=alert.source.value)
        return {"alert": alert.model_dump(mode="json")}

    def enrich(state: SocState) -> SocState:
        indicators = state["alert"]["data"].get("indicators", [])
        ti = [backend.threat_intel(i) for i in indicators]
        siem = [backend.siem_search(i) for i in indicators]
        mail = backend.mail_scope() if state["kind"] == "phishing" else None
        for r in ti + siem + ([mail] if mail else []):
            log.append("tool_result", tool=r.tool, receipt=r.receipt, source=r.source.value)
        return {"ti": [r.model_dump(mode="json") for r in ti], "siem": [r.model_dump(mode="json") for r in siem],
                "mail": mail.model_dump(mode="json") if mail else None}

    def screen_inputs(state: SocState) -> SocState:
        untrusted = dict(state["alert"]["data"].get("untrusted_fields", {}))
        if state.get("mail"):
            untrusted["email_subject"] = state["mail"]["data"].get("subject", "")
            untrusted["email_body"] = state["mail"]["data"].get("body", "")
        tainted, results = screen.screen(untrusted)
        log.append("inputs_screened", tainted=tainted, flagged=[r.field for r in results if r.verdict != "allow"])
        return {"tainted": tainted, "screen": [r.__dict__ for r in results]}

    def assess_node(state: SocState) -> SocState:
        a = assess(state["kind"], state["alert"]["data"],
                   [ToolResult.model_validate(r) for r in state["ti"]],
                   [ToolResult.model_validate(r) for r in state["siem"]],
                   ToolResult.model_validate(state["mail"]) if state.get("mail") else None)
        log.append("assessed", verdict=a.verdict.value, risk=a.risk.value, evidence=a.evidence_receipts)
        return {"assessment": a.model_dump(mode="json")}

    def plan_and_grade(state: SocState) -> SocState:
        a = Assessment.model_validate(state["assessment"])
        mail = ToolResult.model_validate(state["mail"]) if state.get("mail") else None
        requests = plan(state["kind"], a, state["alert"]["data"], mail)
        auto, approval, denied = [], [], []
        for req in requests:
            level = grade(req.name, tainted=state.get("tainted", False), allowed=ALLOWED.get(state["kind"], frozenset()))
            log.append("action_graded", action=req.name, target=req.target, autonomy=level.value)
            (auto if level is Autonomy.AUTO else approval if level is Autonomy.APPROVAL else denied).append(req)
        return {"auto": [r.model_dump() for r in auto], "needs_approval": [r.model_dump() for r in approval],
                "denied": [f"{r.name}:{r.target} (denied: not permitted for this workflow)" for r in denied]}

    def route_after_grading(state: SocState) -> str:
        return "approval_gate" if state.get("needs_approval") else "execute"

    def approval_gate(state: SocState) -> SocState:
        reply = interrupt({"scenario_id": state["scenario_id"], "assessment": state["assessment"],
                           "tainted": state.get("tainted", False), "requests": state["needs_approval"]})
        decisions: dict[str, bool] = reply.get("decisions", {})
        approved = [r for r in state["needs_approval"] if decisions.get(_key(r), False)]
        rejected = [f"{_key(r)} (not approved)" for r in state["needs_approval"] if not decisions.get(_key(r), False)]
        log.append("approval_decision", reviewer=reply.get("reviewer", "unknown"),
                   approved=[_key(r) for r in approved], rejected=rejected)
        return {"approved": approved, "approver": reply.get("reviewer", "unknown"),
                "denied": state.get("denied", []) + rejected}

    def execute(state: SocState) -> SocState:
        executed = []
        for req in state.get("auto", []):
            executed.append(backend.execute(req["name"], req["target"], approved_by="auto"))
        for req in state.get("approved", []):
            executed.append(backend.execute(req["name"], req["target"], approved_by=state.get("approver", "unknown")))
        for rec in executed:
            log.append("action_executed", action=rec.name, target=rec.target, receipt=rec.receipt, approved_by=rec.approved_by)
        return {"executed": [r.model_dump() for r in executed]}

    def report(state: SocState) -> SocState:
        a = Assessment.model_validate(state["assessment"])
        executed = state.get("executed", [])
        sources = {r["receipt"]: r["source"] for r in state["ti"] + state["siem"] + ([state["mail"]] if state.get("mail") else [])}
        summary = summarizer.summarize(a, [_key(e) for e in executed], state.get("denied", []))
        rep = Report(scenario_id=state["scenario_id"], verdict=a.verdict, risk=a.risk, summary=summary, reasons=a.reasons,
                     actions_taken=executed, actions_pending_or_denied=state.get("denied", []),
                     injection_detected=state.get("tainted", False), evidence_sources=sources)
        log.append("report", verdict=a.verdict.value, actions=[_key(e) for e in executed])
        return {"report": rep.model_dump(mode="json")}

    g = StateGraph(SocState)
    for name, fn in [("load", load), ("enrich", enrich), ("screen", screen_inputs), ("assess", assess_node),
                     ("plan_and_grade", plan_and_grade), ("approval_gate", approval_gate), ("execute", execute),
                     ("report", report)]:
        g.add_node(name, fn)
    g.add_edge(START, "load")
    g.add_edge("load", "enrich")
    g.add_edge("enrich", "screen")
    g.add_edge("screen", "assess")
    g.add_edge("assess", "plan_and_grade")
    g.add_conditional_edges("plan_and_grade", route_after_grading, {"approval_gate": "approval_gate", "execute": "execute"})
    g.add_edge("approval_gate", "execute")
    g.add_edge("execute", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer or InMemorySaver()), log

