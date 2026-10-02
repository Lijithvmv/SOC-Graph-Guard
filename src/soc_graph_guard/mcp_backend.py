"""A live backend over MCP: the same five operations, served by an MCP server you choose (the `mcp` extra).

`MCPBackend` starts the server over stdio and maps the workflow's operations to its tools (by default `get_alert`,
`threat_intel`, `siem_search`, `mail_scope`, `execute_action`; pass `tools=` to rename them). Every result is
tagged `live`.

The server is someone else's software, so nothing it returns is taken on trust:

- **Structure is checked, not assumed.** Only known fields of the right type are kept: a threat-intel score that isn't
  a number from 0 to 100 becomes "no data", and so does anything malformed. Missing evidence never becomes "benign"
  (`assess.py`): a human decides.
- **All free text is screened.** The workflow sends every string a live server returns through GuardLayer, not only the
  alert's marked fields; an injection there taints the session, so every action needs approval.
- **What it can't fix:** a server that lies with well-formed numbers (a false reputation score) can mislead the
  verdict. Choosing which servers to run is the control for that; this backend makes the source of every number
  visible in the report and the audit log.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
from collections.abc import Sequence
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING, Any

from soc_graph_guard.models import ActionRecord, Source, ToolResult

if TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import Self

DEFAULT_TOOLS = {"get_alert": "get_alert", "threat_intel": "threat_intel", "siem_search": "siem_search",
                 "mail_scope": "mail_scope", "execute": "execute_action"}  # fmt: skip
MAX_ITEMS = 1000
MAX_TEXT = 8000


class MCPToolError(RuntimeError):
    """The server reported an error, or returned something that isn't a result."""


def _text(value: Any) -> str:
    return value[:MAX_TEXT] if isinstance(value, str) else ""


def _strings(value: Any, limit: int = MAX_ITEMS) -> list[str]:
    return [v[:MAX_TEXT] for v in value[:limit] if isinstance(v, str)] if isinstance(value, list) else []


def _score(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value) if 0 <= value <= 100 else None


def _flat(value: Any, depth: int = 0) -> Any:
    """JSON-like data only, bounded; anything else is dropped."""
    if depth > 6:
        return None
    if isinstance(value, dict):
        return {str(k)[:200]: _flat(v, depth + 1) for k, v in list(value.items())[:200]}
    if isinstance(value, list):
        return [_flat(v, depth + 1) for v in value[:MAX_ITEMS]]
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def clean_alert(data: Any) -> dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    untrusted = d.get("untrusted_fields") if isinstance(d.get("untrusted_fields"), dict) else {}
    out = {"alert_id": _text(d.get("alert_id")) or "unknown-case", "rule": _text(d.get("rule")), "host": _text(d.get("host")),
           "asset_criticality": _text(d.get("asset_criticality")), "indicators": _strings(d.get("indicators"), 50),
           "untrusted_fields": {str(k)[:100]: _text(v) for k, v in list(untrusted.items())[:50]}}  # fmt: skip
    if isinstance(d.get("baseline"), str):  # the asset-inventory label; a stated trust assumption about this server
        out["baseline"] = d["baseline"][:100]
    return out


def clean_threat_intel(indicator: str, data: Any) -> dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    return {"indicator": indicator, "score": _score(d.get("score")), "found": d.get("found") is True,
            "category": _text(d.get("category"))}  # fmt: skip


def clean_siem(indicator: str, data: Any) -> dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    events = d.get("events") if isinstance(d.get("events"), list) else []
    return {"indicator": indicator, "events": [_flat(e) for e in events[:MAX_ITEMS] if isinstance(e, dict)]}


def clean_mail(data: Any) -> dict[str, Any]:
    d = data if isinstance(data, dict) else {}
    recipients = d.get("recipients")
    return {"subject": _text(d.get("subject")), "sender_domain": _text(d.get("sender_domain")),
            "recipients": recipients if isinstance(recipients, int) and not isinstance(recipients, bool) and recipients >= 0 else 0,
            "clicked_users": _strings(d.get("clicked_users")), "credential_harvesting": d.get("credential_harvesting") is True,
            "body": _text(d.get("body"))}  # fmt: skip


class MCPBackend:
    """The `ToolBackend` protocol over one MCP server, started over stdio. Use as a context manager, or call `close()`."""

    source = Source.LIVE

    def __init__(self, command: str, args: Sequence[str] = (), *, tools: dict[str, str] | None = None,
                 env: dict[str, str] | None = None, timeout: float = 30.0):  # fmt: skip
        try:
            from mcp import ClientSession
            from mcp.client.stdio import StdioServerParameters, stdio_client
        except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency
            raise ModuleNotFoundError("MCPBackend needs: pip install 'soc-graph-guard[mcp]'") from exc
        self.tools = {**DEFAULT_TOOLS, **(tools or {})}
        self.timeout = timeout
        self.executed: list[ActionRecord] = []
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._stack = AsyncExitStack()

        async def connect() -> Any:
            read, write = await self._stack.enter_async_context(
                stdio_client(StdioServerParameters(command=command, args=list(args), env=env)))
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            return session

        try:
            self._session = self._run(connect())
        except Exception:
            self.close()
            raise

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(self.timeout)

    def _call(self, operation: str, arguments: dict[str, Any] | None = None) -> Any:
        result = self._run(self._session.call_tool(self.tools[operation], arguments or {}))
        if getattr(result, "is_error", False):
            raise MCPToolError(f"{self.tools[operation]} failed: {self._first_text(result)[:300]}")
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict):
            return structured.get("result", structured) if set(structured) == {"result"} else structured
        text = self._first_text(result)
        try:
            return json.loads(text)
        except ValueError:
            return {"text": text}

    @staticmethod
    def _first_text(result: Any) -> str:
        for block in getattr(result, "content", None) or []:
            if getattr(block, "type", None) == "text":
                return str(block.text)
        return ""

    def get_alert(self) -> ToolResult:
        return ToolResult(tool="get_alert", data=clean_alert(self._call("get_alert")), source=self.source)

    def threat_intel(self, indicator: str) -> ToolResult:
        data = clean_threat_intel(indicator, self._call("threat_intel", {"indicator": indicator}))
        return ToolResult(tool="threat_intel", data=data, source=self.source)

    def siem_search(self, indicator: str) -> ToolResult:
        data = clean_siem(indicator, self._call("siem_search", {"indicator": indicator}))
        return ToolResult(tool="siem_search", data=data, source=self.source)

    def mail_scope(self) -> ToolResult:
        return ToolResult(tool="mail_scope", data=clean_mail(self._call("mail_scope")), source=self.source)

    def execute(self, action: str, target: str, approved_by: str) -> ActionRecord:
        reply = self._call("execute", {"action": action, "target": target, "approved_by": approved_by})
        record = ToolResult(tool=action, data=_flat(reply), source=self.source)
        rec = ActionRecord(name=action, target=target, receipt=record.receipt, approved_by=approved_by)
        self.executed.append(rec)
        return rec

    def close(self) -> None:
        if self._loop.is_running():
            with contextlib.suppress(Exception):  # shutting down; nothing more to do
                asyncio.run_coroutine_threadsafe(self._stack.aclose(), self._loop).result(self.timeout)
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
