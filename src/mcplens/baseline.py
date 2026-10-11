"""Baseline snapshots and rug-pull diffing.

A baseline pins the SHA-256 of every tool's canonical definition
(name + description + inputSchema). Re-scanning and diffing against the
baseline exposes silent definition changes — the 'rug pull' pattern where
a server behaves during review and mutates afterwards.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .models import ToolInfo

SNAPSHOT_VERSION = 1


def tool_hash(tool: ToolInfo) -> str:
    return hashlib.sha256(tool.canonical_json().encode("utf-8")).hexdigest()


def set_hash(tools: list[ToolInfo]) -> str:
    joined = "\n".join(f"{t.name}:{tool_hash(t)}" for t in sorted(tools, key=lambda x: x.name))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def make_snapshot(tools: list[ToolInfo], label: str = "") -> dict[str, Any]:
    return {
        "mcplens_snapshot": SNAPSHOT_VERSION,
        "created": datetime.now(timezone.utc).isoformat(),
        "target": label,
        "set_sha256": set_hash(tools),
        "tools": {
            t.name: {"sha256": tool_hash(t), "definition": t.canonical()}
            for t in tools
        },
    }


def save_snapshot(snapshot: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_snapshot(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if data.get("mcplens_snapshot") != SNAPSHOT_VERSION:
        raise ValueError(f"{path} is not an mcplens snapshot (version mismatch)")
    return data


@dataclass
class ToolChange:
    name: str
    kind: str  # "added" | "removed" | "changed"
    fields: list[str] = field(default_factory=list)  # for "changed": which fields differ


@dataclass
class DiffResult:
    changes: list[ToolChange] = field(default_factory=list)
    old_set_hash: str = ""
    new_set_hash: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)


def _field_diffs(old_def: dict[str, Any], new_def: dict[str, Any]) -> list[str]:
    fields = []
    if old_def.get("description") != new_def.get("description"):
        fields.append("description")
    if json.dumps(old_def.get("inputSchema") or {}, sort_keys=True) != \
            json.dumps(new_def.get("inputSchema") or {}, sort_keys=True):
        fields.append("inputSchema")
    return fields


def diff_snapshot(snapshot: dict[str, Any], current: list[ToolInfo]) -> DiffResult:
    old_tools: dict[str, Any] = snapshot.get("tools") or {}
    result = DiffResult(old_set_hash=snapshot.get("set_sha256", ""),
                        new_set_hash=set_hash(current))
    current_by_name = {t.name: t for t in current}

    for name in sorted(set(old_tools) - set(current_by_name)):
        result.changes.append(ToolChange(name=name, kind="removed"))
    for name in sorted(set(current_by_name) - set(old_tools)):
        result.changes.append(ToolChange(name=name, kind="added"))
    for name in sorted(set(old_tools) & set(current_by_name)):
        tool = current_by_name[name]
        if old_tools[name].get("sha256") != tool_hash(tool):
            old_def = old_tools[name].get("definition") or {}
            fields = _field_diffs(old_def, tool.canonical())
            result.changes.append(ToolChange(name=name, kind="changed",
                                             fields=fields or ["definition"]))
    return result
