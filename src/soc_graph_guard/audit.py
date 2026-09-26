"""A hash-chained decision log: editing, deleting or reordering an entry breaks `verify()`."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class DecisionLog:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        prev = self.entries[-1]["hash"] if self.entries else ""
        body = {"seq": len(self.entries), "event": event, **fields, "prev": prev}
        body["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
        self.entries.append(body)
        return body

    def verify(self) -> bool:
        prev = ""
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            if entry["seq"] != i or entry["prev"] != prev or entry["hash"] != digest:
                return False
            prev = entry["hash"]
        return True
