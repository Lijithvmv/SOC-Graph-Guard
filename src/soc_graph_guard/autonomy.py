"""Graded autonomy: decide per action whether it may run automatically, needs a human, or is refused.

Scores follow the spirit of the UK NCSC's scale for automated defensive actions (0 = safest, 4 = riskiest):
potency (can it change things?), scope (how much estate?) and recoverability (how cleanly can it be undone?).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Autonomy(str, Enum):
    AUTO = "auto"
    APPROVAL = "approval"
    DENY = "deny"


@dataclass(frozen=True)
class ActionProfile:
    potency: int
    scope: int
    recoverability: int


# Unknown actions are not listed, so they are denied.
ACTION_PROFILES: dict[str, ActionProfile] = {
    "add_case_comment": ActionProfile(potency=1, scope=0, recoverability=0),
    "escalate_case": ActionProfile(potency=1, scope=0, recoverability=1),
    "close_case": ActionProfile(potency=2, scope=0, recoverability=1),
    "block_domain": ActionProfile(potency=3, scope=3, recoverability=1),
    "reset_password": ActionProfile(potency=3, scope=1, recoverability=2),
    "purge_email": ActionProfile(potency=4, scope=3, recoverability=3),
    "disable_account": ActionProfile(potency=4, scope=1, recoverability=2),
}


def grade(action: str, *, tainted: bool, allowed: frozenset[str]) -> Autonomy:
    """Grade one action.

    - Not in the workflow's allow-list, or unknown: DENY.
    - Low potency and easily undone, in a session with no detected injection: AUTO.
    - Everything else: APPROVAL. A detected injection upgrades every action to APPROVAL.
    """
    profile = ACTION_PROFILES.get(action)
    if profile is None or action not in allowed:
        return Autonomy.DENY
    if tainted:
        return Autonomy.APPROVAL
    if profile.potency <= 2 and profile.recoverability <= 1:
        return Autonomy.AUTO
    return Autonomy.APPROVAL
