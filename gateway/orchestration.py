from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class OrchestrationDecision:
    action: str
    final: str | None = None
    target_agent: str | None = None
    input: str | None = None
    session_id: str | None = None
    reason: str | None = None


def orchestrator_prompt(agents: dict[str, Any]) -> str:
    agent_lines = []
    for agent_id, agent in sorted(agents.items()):
        if getattr(agent, "orchestrates", False):
            continue
        description = getattr(agent, "description", None) or getattr(agent, "role", "worker")
        agent_lines.append(f"- {agent_id}: {description}")

    available_agents = "\n".join(agent_lines) or "- none"
    return (
        "You are the center Codex orchestrator behind an OpenAI-compatible gateway.\n"
        "Decide whether to answer directly or route the task to exactly one child agent.\n"
        "Return exactly one JSON object. Do not include markdown, code fences, or prose outside JSON.\n"
        "\n"
        "Available child agents:\n"
        f"{available_agents}\n"
        "\n"
        "JSON schema:\n"
        "{\n"
        '  "action": "final" | "call_agent",\n'
        '  "final": "required when action is final",\n'
        '  "target_agent": "required when action is call_agent",\n'
        '  "input": "required when action is call_agent",\n'
        '  "session_id": "optional stable child-agent session id",\n'
        '  "reason": "short private routing reason"\n'
        "}\n"
        "\n"
        "Routing guidance:\n"
        "- Use planner for breaking down tasks and deciding implementation steps.\n"
        "- Use coder for making or explaining concrete code changes.\n"
        "- Use reviewer for reviewing changes and surfacing defects.\n"
        "- After receiving an agent result, either call another useful agent or return final.\n"
        "- If no child agent is needed, return action=final.\n"
    )


def agent_result_prompt(agent_id: str, result: str) -> str:
    return (
        "Child agent result received.\n"
        f"agent_id: {agent_id}\n"
        "result:\n"
        f"{result}\n"
        "\n"
        "Return the next orchestration JSON object only."
    )


def parse_decision(text: str) -> OrchestrationDecision | None:
    payload = _extract_json(text)
    if not isinstance(payload, dict):
        return None

    action = str(payload.get("action", "")).strip().lower()
    if action in {"respond", "answer", "done"}:
        action = "final"
    if action in {"route", "handoff", "delegate"}:
        action = "call_agent"
    if action not in {"final", "call_agent"}:
        return None

    final = payload.get("final")
    target_agent = payload.get("target_agent")
    agent_input = payload.get("input")
    session_id = payload.get("session_id")
    reason = payload.get("reason")

    return OrchestrationDecision(
        action=action,
        final=str(final) if final is not None else None,
        target_agent=str(target_agent) if target_agent is not None else None,
        input=str(agent_input) if agent_input is not None else None,
        session_id=str(session_id) if session_id is not None else None,
        reason=str(reason) if reason is not None else None,
    )


def strip_for_orchestration(body: dict[str, Any]) -> dict[str, Any]:
    stripped = dict(body)
    for key in (
        "stream",
        "tools",
        "tool_choice",
        "response_format",
        "text",
        "parallel_tool_calls",
    ):
        stripped.pop(key, None)
    return stripped


def _extract_json(text: str) -> Any:
    stripped = _strip_code_fence(text.strip())
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        return value
    return None


def _strip_code_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if len(lines) >= 2 and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return text
