"""The live backend over MCP: strict parsing, the same decisions as replay, and a hostile server."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from test_security_properties import ADVERSARIAL

from soc_graph_guard.mcp_backend import MCPBackend, clean_alert, clean_mail, clean_siem, clean_threat_intel
from soc_graph_guard.review import CautiousReviewer
from soc_graph_guard.runner import load_scenarios, run_guarded, score

SERVER = str(Path(__file__).resolve().parents[1] / "examples" / "mcp_soc_server.py")
SCENARIOS = load_scenarios()


def _actions(report):
    return sorted((a["name"], a["target"]) for a in report["actions_taken"])


# ------------------------------------------------------------------ parsing what a server returns
@pytest.mark.parametrize(("raw", "expected"), [(88, 88), (0, 0), (100, 100), (101, None), (-1, None), (True, None), ("90", None), (None, None), (72.6, 72)])
def test_threat_intel_scores_outside_0_to_100_or_not_numbers_become_no_data(raw, expected):
    assert clean_threat_intel("x", {"score": raw})["score"] == expected


def test_malformed_results_become_safe_defaults():
    assert clean_alert("not a dict") == {"alert_id": "unknown-case", "rule": "", "host": "", "asset_criticality": "",
                                         "indicators": [], "untrusted_fields": {}}  # fmt: skip
    assert clean_siem("x", {"events": "lots"}) == {"indicator": "x", "events": []}
    mail = clean_mail({"recipients": "900", "clicked_users": ["a", 3, None], "credential_harvesting": "yes"})
    assert mail["recipients"] == 0 and mail["clicked_users"] == ["a"] and mail["credential_harvesting"] is False


def test_unknown_fields_are_dropped():
    assert "exec" not in clean_threat_intel("x", {"score": 10, "exec": "rm -rf /"})
    assert set(clean_alert({"alert_id": "A", "admin_override": True})) == {"alert_id", "rule", "host", "asset_criticality",
                                                                          "indicators", "untrusted_fields"}


# ------------------------------------------------------------------ over a real MCP connection
def _live(scenario, tmp_path):
    path = tmp_path / f"{scenario['id']}.json"
    path.write_text(json.dumps(scenario), encoding="utf-8")
    with MCPBackend(sys.executable, [SERVER, str(path)], timeout=60) as backend:
        return run_guarded({"id": scenario["id"], "kind": scenario["kind"]}, CautiousReviewer(), backend)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["id"])
def test_live_backend_reaches_the_same_decisions_as_replay(scenario, tmp_path):
    replay, _, _ = run_guarded(scenario, CautiousReviewer())
    live, log, _ = _live(scenario, tmp_path)
    assert live["verdict"] == replay["verdict"]
    assert _actions(live) == _actions(replay)
    assert set(live["evidence_sources"].values()) <= {"live"}
    assert log.verify()


def test_hostile_server_bogus_score_is_ignored_and_its_text_taints_the_session(tmp_path):
    base = next(s for s in SCENARIOS if s["id"] == "01_triage_c2_beacon")
    hostile = copy.deepcopy(base)
    ind = hostile["alert"]["indicators"][0]
    hostile["threat_intel"][ind] = {"indicator": ind, "score": 999, "found": True, "category": ADVERSARIAL[0]}
    report, _, approvals = _live(hostile, tmp_path)
    s = score(hostile, report)
    assert report["injection_detected"]          # the threat-intel text was screened and flagged
    assert "max threat-intel score: no data" in report["reasons"]  # 999 is not a reputation score
    assert not s["forbidden_executed"] and not s["high_potency_without_approval"]
    assert approvals >= 1                         # a tainted session asks a human
