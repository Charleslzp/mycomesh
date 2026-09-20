"""Strict content-free facts and advisory output shared by local jury agents.

An optional local Codex adapter uses the user's existing login, with no tools.
This module has no credential-file, wallet or transaction access.
Model suggestions do not establish evidence or authorize a vote or penalty.
"""
from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
import tempfile
from typing import Any

from .codex_app_backend import CodexAppServerBackend
from .codex_backend import CodexProcessLimiter


FACT_NAMES = (
    "commitment", "signatures", "classification", "protocol", "chain_binding",
    "report_binding", "actor_eligibility", "vote_window",
)
_VALUES = (
    {"verified", "unverified"}, {"verified", "unverified"},
    {"protocol_contradiction", "contextual_allegation", "inconclusive", "unverifiable"},
    {"v9", "other", "unverified"},
    {"matched", "mismatched", "unavailable", "not_checked"},
    {"matched", "absent", "mismatched", "not_checked"},
    {"eligible", "ineligible", "not_checked"}, {"open", "closed", "not_checked"},
)


class AdvisorError(ValueError):
    """A sanitized error that does not echo untrusted input."""


def validate_facts(facts: Any) -> list[dict[str, str]]:
    """Allow only eight ordered enum facts; never accept original evidence text."""
    if type(facts) is not list or len(facts) != len(FACT_NAMES):
        raise AdvisorError("invalid advisor facts")
    copied = []
    for index, (fact, name, allowed) in enumerate(zip(facts, FACT_NAMES, _VALUES), 1):
        if (type(fact) is not dict or set(fact) != {"id", "name", "value"}
                or type(fact["id"]) is not str or fact["id"] != f"F{index:02}"
                or type(fact["name"]) is not str or fact["name"] != name
                or type(fact["value"]) is not str or fact["value"] not in allowed):
            raise AdvisorError("invalid advisor facts")
        copied.append(dict(fact))
    return copied


def validate_advice(value: Any, facts: Any) -> dict[str, Any]:
    """Validate advisory structure only; callers retain all policy decisions.

    In particular, ``review_violation`` does not upgrade the supplied facts or
    confer signing authority. Returned prose remains untrusted display text.
    """
    ids_allowed = {fact["id"] for fact in validate_facts(facts)}
    if type(value) is not dict or set(value) != {"recommendation", "summary", "fact_ids", "uncertainties"}:
        raise AdvisorError("invalid advisor output")
    recommendation, summary = value["recommendation"], value["summary"]
    ids, uncertainties = value["fact_ids"], value["uncertainties"]
    if (type(recommendation) is not str
            or recommendation not in {"review_violation", "request_more_evidence", "abstain"}
            or type(summary) is not str or not 20 <= len(summary) <= 1200 or len(summary.strip()) < 20
            or type(ids) is not list or not 1 <= len(ids) <= 8
            or any(type(item) is not str or item not in ids_allowed for item in ids)
            or len(set(ids)) != len(ids) or type(uncertainties) is not list or len(uncertainties) > 6
            or any(type(item) is not str or not 1 <= len(item) <= 400 or not item.strip() for item in uncertainties)):
        raise AdvisorError("invalid advisor output")
    return {"recommendation": recommendation, "summary": summary,
            "fact_ids": list(ids), "uncertainties": list(uncertainties)}


_INSTRUCTIONS = (
    "Assist the local user with independent review of MycoMesh verification facts. "
    "Use only the eight supplied enum facts; do not read files, invoke tools, browse, "
    "or request additional data. Unverified or unchecked facts are limitations, "
    "not proof of guilt or innocence. Explain the facts and uncertainty in Chinese. "
    "You cannot authorize votes, refunds, slashing or transactions. The user must "
    "independently review and separately sign any decision. Return only the supplied "
    "JSON output schema, cite existing fact IDs, and do not invent model identity."
)


def _advice_schema() -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "required": ["recommendation", "summary", "fact_ids", "uncertainties"],
        "properties": {
            "recommendation": {"type": "string", "enum": [
                "review_violation", "request_more_evidence", "abstain"]},
            "summary": {"type": "string", "minLength": 20, "maxLength": 1200},
            "fact_ids": {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": True,
                         "items": {"type": "string", "enum": [f"F{i:02}" for i in range(1, 9)]}},
            "uncertainties": {"type": "array", "maxItems": 6,
                              "items": {"type": "string", "minLength": 1, "maxLength": 400}},
        },
    }


def _strict_advice_json(raw: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise ValueError("nonfinite JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class LocalCodexAdvisor:
    """Optional personal-Codex advice, never signing or executing a verdict.

    ``codex_home`` must already exist. No login files are inspected or created by
    this adapter. Codex itself uses that explicit existing user login. Read-only
    execution, disabled tools and an empty work directory contain the model's
    task; the separate wallet signing process must never be mounted here.
    """

    def __init__(self, command: str, codex_home: str | Path, model: str,
                 timeout_seconds: float = 60) -> None:
        try:
            if (type(command) is not str or not command.strip() or len(command) > 4096
                    or any(ord(char) < 32 for char in command)
                    or type(model) is not str or not model.strip() or len(model) > 200
                    or any(char.isspace() or ord(char) < 32 for char in model)
                    or not isinstance(codex_home, (str, Path)) or not str(codex_home)
                    or not Path(codex_home).is_dir()
                    or type(timeout_seconds) not in (int, float)
                    or not math.isfinite(timeout_seconds) or not 1 <= timeout_seconds <= 60):
                raise ValueError("invalid local Codex configuration")
            self.command = command
            self.codex_home = str(Path(codex_home).absolute())
            self.model = model
            self.timeout_seconds = float(timeout_seconds)
        except (ValueError, TypeError, OSError):
            raise AdvisorError("invalid local Codex configuration") from None

    def advise(self, facts: Any) -> dict[str, Any]:
        safe_facts = validate_facts(facts)
        try:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(self._advise(safe_facts))
            raise AdvisorError("local Codex advisor unavailable")
        except Exception:
            # Codex stderr/model content may be private. Never echo it.
            raise AdvisorError("local Codex advisor unavailable") from None

    async def _advise(self, facts: list[dict[str, str]]) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="mycomesh-jury-") as workdir:
            backend = CodexAppServerBackend(
                command=self.command, codex_home=self.codex_home, workdir=workdir,
                sandbox="read-only", timeout_seconds=self.timeout_seconds,
                process_limiter=CodexProcessLimiter(maximum=1),
                production_strict=True, testnet_metering=True,
                testnet_max_output_token_cap=2000,
            )
            # Override ambient web-search opt-in for this dedicated task.
            backend.testnet_web_search = False
            backend.stdout_max_bytes = 1024 * 1024
            backend.stderr_retain_bytes = 4096
            backend.max_messages = 1000
            result = None
            try:
                result = await asyncio.wait_for(backend._run_turn(
                    prompt=json.dumps({"facts": facts}, separators=(",", ":")),
                    model=self.model, output_schema=_advice_schema(), tools=[],
                    instructions=_INSTRUCTIONS,
                ), timeout=self.timeout_seconds)
                if result.pending_tool_call is not None:
                    raise AdvisorError("local Codex advisor unavailable")
                backend._validate_testnet_metering_result({"max_output_tokens": 2000}, result)
                if type(result.text) is not str or len(result.text.encode("utf-8")) > 65536:
                    raise AdvisorError("local Codex advisor unavailable")
                return validate_advice(_strict_advice_json(result.text), facts)
            finally:
                try:
                    if result is not None and result.client is not None:
                        await result.client.close()
                finally:
                    await backend.close()
