"""OpenCode-style episode trace parsing."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolCall:
    tool: str
    input: dict[str, Any]
    raw: dict[str, Any]


@dataclass(frozen=True)
class EpisodeTrace:
    calls: tuple[ToolCall, ...]

    @property
    def has_task_end(self) -> bool:
        return any(normalize_tool_name(call.tool) == "task-end" for call in self.calls)

    @property
    def attempted_oracle_access(self) -> bool:
        for call in self.calls:
            text = json.dumps(call.raw, sort_keys=True)
            if "/oracle" in text or "\\oracle" in text or '"oracle/' in text:
                return True
        return False

    @classmethod
    def from_jsonl(cls, path: Path) -> EpisodeTrace:
        calls: list[ToolCall] = []
        with path.open(encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                call = extract_tool_call(event)
                if call:
                    calls.append(call)
        return cls(tuple(calls))

    @classmethod
    def empty(cls) -> EpisodeTrace:
        return cls(())


def extract_tool_call(event: dict[str, Any]) -> ToolCall | None:
    """Parse common OpenCode-like and generic JSONL tool-call shapes."""

    if "tool" in event:
        return ToolCall(
            tool=str(event["tool"]),
            input=_as_dict(event.get("input") or event.get("args") or {}),
            raw=event,
        )

    if "name" in event and str(event.get("type", "")).lower() in {"tool_call", "tool"}:
        return ToolCall(
            tool=str(event["name"]),
            input=_as_dict(event.get("input") or {}),
            raw=event,
        )

    for key in ("part", "message", "data"):
        value = event.get(key)
        if isinstance(value, dict):
            nested = extract_tool_call(value)
            if nested:
                return ToolCall(tool=nested.tool, input=nested.input, raw=event)

    if event.get("type") in {"tool_call", "tool-call"} and "function" in event:
        function = event["function"]
        if isinstance(function, dict):
            return ToolCall(
                tool=str(function.get("name", "")),
                input=_as_dict(function.get("arguments") or {}),
                raw=event,
            )
    return None


def normalize_tool_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {"value": value}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    return {}
