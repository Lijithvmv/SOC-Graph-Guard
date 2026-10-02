"""An example MCP server that serves one scenario file, for trying the live backend with no real SOC tools.

    soc-graph-guard live --kind triage python examples/mcp_soc_server.py src/soc_graph_guard/scenarios/03_triage_injected_user_agent.json

A real deployment points the same backend at MCP servers for its SIEM, threat-intel and SOAR. This one only reads
the scenario; `execute_action` changes nothing and returns a receipt.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

scenario = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
server = MCPServer("example-soc-tools")


@server.tool()
def get_alert() -> dict:
    """The alert under investigation."""
    return scenario["alert"]


@server.tool()
def threat_intel(indicator: str) -> dict:
    """Reputation of an indicator."""
    return scenario.get("threat_intel", {}).get(indicator, {"indicator": indicator, "score": None, "found": False})


@server.tool()
def siem_search(indicator: str) -> dict:
    """SIEM events mentioning an indicator."""
    return {"indicator": indicator, "events": [e for e in scenario.get("siem_events", []) if indicator in json.dumps(e)]}


@server.tool()
def mail_scope() -> dict:
    """Who received and clicked the reported email."""
    return scenario.get("mail_scope", {})


@server.tool()
def execute_action(action: str, target: str, approved_by: str) -> dict:
    """Pretend to run a response action (this example changes nothing)."""
    return {"status": "ok", "action": action, "target": target, "approved_by": approved_by, "simulated": True}


if __name__ == "__main__":
    server.run("stdio")
