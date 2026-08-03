from __future__ import annotations

import copy
import json
import time
import uuid
from collections.abc import AsyncIterator, Iterator, Mapping
from typing import Any


_TERMINAL_EVENTS = {
    "completed": "response.completed",
    "failed": "response.failed",
    "incomplete": "response.incomplete",
    "cancelled": "response.incomplete",
}


def openai_error(
    message: str,
    *,
    error_type: str = "server_error",
    code: str | None = None,
    param: str | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "message": str(message),
            "type": error_type,
            "param": param,
            "code": code or error_type,
        }
    }


def normalize_openai_error(value: Any, *, fallback_type: str = "server_error") -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return openai_error(str(value or fallback_type), error_type=fallback_type)
    root = dict(value)
    raw = root.get("error")
    if not isinstance(raw, Mapping):
        return openai_error(str(root.get("detail") or root.get("message") or fallback_type), error_type=fallback_type)
    error = dict(raw)
    message = str(error.get("message") or root.get("detail") or fallback_type)
    error_type = str(error.get("type") or fallback_type)
    return {
        **{key: item for key, item in root.items() if key != "error"},
        "error": {
            **error,
            "message": message,
            "type": error_type,
            "param": error.get("param"),
            "code": error.get("code") or error_type,
        },
    }


def encode_sse_event(event: Mapping[str, Any]) -> bytes:
    event_type = str(event.get("type") or "error")
    data = json.dumps(dict(event), ensure_ascii=False, separators=(",", ":"))
    return f"event: {event_type}\ndata: {data}\n\n".encode("utf-8")


async def responses_sse(
    payload: Mapping[str, Any],
    *,
    compact: bool = False,
) -> AsyncIterator[bytes]:
    for event in response_stream_events(payload, compact=compact):
        yield encode_sse_event(event)


def response_stream_events(
    payload: Mapping[str, Any],
    *,
    compact: bool = False,
) -> Iterator[dict[str, Any]]:
    final = _normalize_response(payload)
    sequence_number = 0

    def event(event_type: str, **fields: Any) -> dict[str, Any]:
        nonlocal sequence_number
        value = {"type": event_type, "sequence_number": sequence_number, **fields}
        sequence_number += 1
        return value

    if compact:
        for output_index, item in enumerate(final["output"]):
            yield event(
                "response.output_item.done",
                output_index=output_index,
                item=item,
            )
        yield event(_terminal_event(final), response=final)
        return

    created = copy.deepcopy(final)
    created.update(
        {
            "status": "in_progress",
            "output": [],
            "output_text": "",
            "error": None,
            "incomplete_details": None,
            "usage": None,
        }
    )
    yield event("response.created", response=created)
    yield event("response.in_progress", response=created)

    for output_index, item in enumerate(final["output"]):
        item_type = str(item.get("type") or "")
        item_id = str(item.get("id") or "")
        added = _incremental_item(item)
        yield event(
            "response.output_item.added",
            output_index=output_index,
            item=added,
        )

        if item_type == "message":
            yield from _message_events(event, item, item_id, output_index)
        elif item_type == "reasoning":
            yield from _reasoning_events(event, item, item_id, output_index)
        elif item_type == "function_call":
            arguments = str(item.get("arguments") or "")
            if arguments:
                yield event(
                    "response.function_call_arguments.delta",
                    item_id=item_id,
                    output_index=output_index,
                    delta=arguments,
                )
            yield event(
                "response.function_call_arguments.done",
                item_id=item_id,
                output_index=output_index,
                call_id=str(item.get("call_id") or ""),
                name=str(item.get("name") or ""),
                arguments=arguments,
            )
        elif item_type == "custom_tool_call":
            tool_input = str(item.get("input") or "")
            if tool_input:
                yield event(
                    "response.custom_tool_call_input.delta",
                    item_id=item_id,
                    output_index=output_index,
                    delta=tool_input,
                )
            yield event(
                "response.custom_tool_call_input.done",
                item_id=item_id,
                output_index=output_index,
                call_id=str(item.get("call_id") or ""),
                name=str(item.get("name") or ""),
                input=tool_input,
            )
        elif item_type in {"mcp_call", "mcp_tool_call"}:
            arguments = str(item.get("arguments") or "")
            yield event(
                "response.mcp_call.in_progress",
                item_id=item_id,
                output_index=output_index,
            )
            if arguments:
                yield event(
                    "response.mcp_call_arguments.delta",
                    item_id=item_id,
                    output_index=output_index,
                    delta=arguments,
                )
            yield event(
                "response.mcp_call_arguments.done",
                item_id=item_id,
                output_index=output_index,
                arguments=arguments,
            )
            yield event(
                "response.mcp_call.failed" if item.get("error") else "response.mcp_call.completed",
                item_id=item_id,
                output_index=output_index,
            )
        elif item_type == "web_search_call":
            yield event(
                "response.web_search_call.in_progress",
                item_id=item_id,
                output_index=output_index,
            )
            yield event(
                "response.web_search_call.searching",
                item_id=item_id,
                output_index=output_index,
            )
            yield event(
                "response.web_search_call.completed",
                item_id=item_id,
                output_index=output_index,
            )
        elif item_type == "file_search_call":
            yield event(
                "response.file_search_call.in_progress",
                item_id=item_id,
                output_index=output_index,
            )
            yield event(
                "response.file_search_call.searching",
                item_id=item_id,
                output_index=output_index,
            )
            yield event(
                "response.file_search_call.completed",
                item_id=item_id,
                output_index=output_index,
            )
        elif item_type == "code_interpreter_call":
            code = str(item.get("code") or "")
            yield event(
                "response.code_interpreter_call.in_progress",
                item_id=item_id,
                output_index=output_index,
            )
            if code:
                yield event(
                    "response.code_interpreter_call_code.delta",
                    item_id=item_id,
                    output_index=output_index,
                    delta=code,
                )
            yield event(
                "response.code_interpreter_call_code.done",
                item_id=item_id,
                output_index=output_index,
                code=code,
            )
            yield event(
                "response.code_interpreter_call.completed",
                item_id=item_id,
                output_index=output_index,
            )

        yield event(
            "response.output_item.done",
            output_index=output_index,
            item=item,
        )

    yield event(_terminal_event(final), response=final)


async def chat_completion_sse(
    payload: Mapping[str, Any],
    *,
    include_usage: bool = False,
) -> AsyncIterator[bytes]:
    response_id = str(payload.get("id") or f"chatcmpl_{uuid.uuid4().hex}")
    model = str(payload.get("model") or "")
    created = int(payload.get("created") or time.time())
    choices = payload.get("choices") if isinstance(payload.get("choices"), list) else []
    for fallback_index, raw_choice in enumerate(choices):
        if not isinstance(raw_choice, Mapping):
            continue
        choice = dict(raw_choice)
        index = int(choice.get("index") if isinstance(choice.get("index"), int) else fallback_index)
        message = choice.get("message") if isinstance(choice.get("message"), Mapping) else {}
        yield _chat_sse_chunk(
            response_id,
            model,
            created,
            index,
            {"role": str(message.get("role") or "assistant")},
            None,
        )
        content = message.get("content")
        if isinstance(content, str) and content:
            yield _chat_sse_chunk(response_id, model, created, index, {"content": content}, None)
        tool_calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else []
        for tool_index, raw_tool in enumerate(tool_calls):
            if not isinstance(raw_tool, Mapping):
                continue
            tool = dict(raw_tool)
            function = tool.get("function") if isinstance(tool.get("function"), Mapping) else {}
            delta = {
                "tool_calls": [
                    {
                        "index": tool_index,
                        "id": str(tool.get("id") or f"call_{uuid.uuid4().hex[:24]}"),
                        "type": str(tool.get("type") or "function"),
                        "function": {
                            "name": str(function.get("name") or ""),
                            "arguments": str(function.get("arguments") or ""),
                        },
                    }
                ]
            }
            yield _chat_sse_chunk(response_id, model, created, index, delta, None)
        yield _chat_sse_chunk(
            response_id,
            model,
            created,
            index,
            {},
            str(choice.get("finish_reason") or ("tool_calls" if tool_calls else "stop")),
        )
    if include_usage and isinstance(payload.get("usage"), Mapping):
        chunk = {
            "id": response_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [],
            "usage": dict(payload["usage"]),
        }
        yield f"data: {json.dumps(chunk, ensure_ascii=False, separators=(',', ':'))}\n\n".encode("utf-8")
    yield b"data: [DONE]\n\n"


def _normalize_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    response = copy.deepcopy(dict(payload))
    response["id"] = str(response.get("id") or response.get("request_id") or f"resp_{uuid.uuid4().hex}")
    response.setdefault("object", "response")
    response.setdefault("created_at", int(time.time()))
    status = str(response.get("status") or "completed")
    response["status"] = status if status in _TERMINAL_EVENTS else "completed"
    output = response.get("output")
    response["output"] = [
        _normalize_item(item)
        for item in output
        if isinstance(item, Mapping)
    ] if isinstance(output, list) else []
    response.setdefault("error", None)
    response.setdefault("incomplete_details", None)
    if not isinstance(response.get("output_text"), str):
        response["output_text"] = "".join(
            str(part.get("text") or "")
            for item in response["output"]
            if item.get("type") == "message"
            for part in item.get("content", [])
            if isinstance(part, Mapping) and part.get("type") == "output_text"
        )
    return response


def _normalize_item(raw: Mapping[str, Any]) -> dict[str, Any]:
    item = copy.deepcopy(dict(raw))
    item_type = str(item.get("type") or "unknown")
    item["type"] = item_type
    prefixes = {
        "message": "msg",
        "reasoning": "rs",
        "function_call": "fc",
        "custom_tool_call": "ct",
        "tool_search_call": "ts",
        "web_search_call": "ws",
        "file_search_call": "fs",
        "code_interpreter_call": "ci",
        "mcp_call": "mcp",
        "mcp_tool_call": "mcp",
        "compaction": "cmp",
        "compaction_summary": "cmp",
    }
    item["id"] = str(item.get("id") or f"{prefixes.get(item_type, 'item')}_{uuid.uuid4().hex}")
    if item_type == "message":
        item["role"] = str(item.get("role") or "assistant")
        content = item.get("content")
        item["content"] = [
            _normalize_content(part)
            for part in content
            if isinstance(part, Mapping)
        ] if isinstance(content, list) else []
        item.setdefault("status", "completed")
    elif item_type == "reasoning":
        summary = item.get("summary")
        item["summary"] = [
            {
                **dict(part),
                "type": str(part.get("type") or "summary_text"),
                "text": str(part.get("text") or ""),
            }
            for part in summary
            if isinstance(part, Mapping)
        ] if isinstance(summary, list) else []
        content = item.get("content")
        if isinstance(content, list):
            item["content"] = [
                {
                    **dict(part),
                    "type": str(part.get("type") or "reasoning_text"),
                    "text": str(part.get("text") or ""),
                }
                for part in content
                if isinstance(part, Mapping)
            ]
        item.setdefault("status", "completed")
    elif item_type == "function_call":
        item["call_id"] = str(item.get("call_id") or "")
        item["name"] = str(item.get("name") or "")
        item["arguments"] = str(item.get("arguments") or "")
        item.setdefault("status", "completed")
    elif item_type == "custom_tool_call":
        item["call_id"] = str(item.get("call_id") or "")
        item["name"] = str(item.get("name") or "")
        item["input"] = str(item.get("input") or "")
        item.setdefault("status", "completed")
    elif item_type == "tool_search_call":
        item.setdefault("call_id", None)
        item["execution"] = str(item.get("execution") or "client")
        item.setdefault("arguments", {})
        item.setdefault("status", "completed")
    return item


def _normalize_content(raw: Mapping[str, Any]) -> dict[str, Any]:
    part = copy.deepcopy(dict(raw))
    part_type = str(part.get("type") or "output_text")
    part["type"] = part_type
    if part_type == "output_text":
        part["text"] = str(part.get("text") or "")
        part["annotations"] = list(part.get("annotations") or [])
        part["logprobs"] = list(part.get("logprobs") or [])
    elif part_type == "refusal":
        part["refusal"] = str(part.get("refusal") or "")
    return part


def _incremental_item(item: Mapping[str, Any]) -> dict[str, Any]:
    added = copy.deepcopy(dict(item))
    if "status" in added or added.get("type") in {
        "message",
        "reasoning",
        "function_call",
        "custom_tool_call",
        "tool_search_call",
    }:
        added["status"] = "in_progress"
    if added.get("type") == "message":
        added["content"] = []
    elif added.get("type") == "reasoning":
        added["summary"] = []
        if "content" in added:
            added["content"] = []
    elif added.get("type") == "function_call":
        added["arguments"] = ""
    elif added.get("type") == "custom_tool_call":
        added["input"] = ""
    elif added.get("type") in {"mcp_call", "mcp_tool_call"}:
        added["arguments"] = ""
    return added


def _message_events(event: Any, item: Mapping[str, Any], item_id: str, output_index: int) -> Iterator[dict[str, Any]]:
    content = item.get("content") if isinstance(item.get("content"), list) else []
    for content_index, part in enumerate(content):
        if not isinstance(part, Mapping):
            continue
        part_type = str(part.get("type") or "")
        added_part = copy.deepcopy(dict(part))
        if part_type == "output_text":
            added_part["text"] = ""
        elif part_type == "refusal":
            added_part["refusal"] = ""
        yield event(
            "response.content_part.added",
            item_id=item_id,
            output_index=output_index,
            content_index=content_index,
            part=added_part,
        )
        if part_type == "output_text":
            text = str(part.get("text") or "")
            logprobs = list(part.get("logprobs") or [])
            if text:
                yield event(
                    "response.output_text.delta",
                    item_id=item_id,
                    output_index=output_index,
                    content_index=content_index,
                    delta=text,
                    logprobs=logprobs,
                )
            for annotation_index, annotation in enumerate(part.get("annotations") or []):
                yield event(
                    "response.output_text.annotation.added",
                    item_id=item_id,
                    output_index=output_index,
                    content_index=content_index,
                    annotation_index=annotation_index,
                    annotation=annotation,
                )
            yield event(
                "response.output_text.done",
                item_id=item_id,
                output_index=output_index,
                content_index=content_index,
                text=text,
                logprobs=logprobs,
            )
        elif part_type == "refusal":
            refusal = str(part.get("refusal") or "")
            if refusal:
                yield event(
                    "response.refusal.delta",
                    item_id=item_id,
                    output_index=output_index,
                    content_index=content_index,
                    delta=refusal,
                )
            yield event(
                "response.refusal.done",
                item_id=item_id,
                output_index=output_index,
                content_index=content_index,
                refusal=refusal,
            )
        yield event(
            "response.content_part.done",
            item_id=item_id,
            output_index=output_index,
            content_index=content_index,
            part=part,
        )


def _reasoning_events(event: Any, item: Mapping[str, Any], item_id: str, output_index: int) -> Iterator[dict[str, Any]]:
    summary = item.get("summary") if isinstance(item.get("summary"), list) else []
    for summary_index, part in enumerate(summary):
        if not isinstance(part, Mapping):
            continue
        text = str(part.get("text") or "")
        yield event(
            "response.reasoning_summary_part.added",
            item_id=item_id,
            output_index=output_index,
            summary_index=summary_index,
            part={**dict(part), "type": "summary_text", "text": ""},
        )
        if text:
            yield event(
                "response.reasoning_summary_text.delta",
                item_id=item_id,
                output_index=output_index,
                summary_index=summary_index,
                delta=text,
            )
        yield event(
            "response.reasoning_summary_text.done",
            item_id=item_id,
            output_index=output_index,
            summary_index=summary_index,
            text=text,
        )
        yield event(
            "response.reasoning_summary_part.done",
            item_id=item_id,
            output_index=output_index,
            summary_index=summary_index,
            part=part,
        )
    content = item.get("content") if isinstance(item.get("content"), list) else []
    for content_index, part in enumerate(content):
        if not isinstance(part, Mapping):
            continue
        text = str(part.get("text") or "")
        yield event(
            "response.content_part.added",
            item_id=item_id,
            output_index=output_index,
            content_index=content_index,
            part={**dict(part), "type": "reasoning_text", "text": ""},
        )
        if text:
            yield event(
                "response.reasoning_text.delta",
                item_id=item_id,
                output_index=output_index,
                content_index=content_index,
                delta=text,
            )
        yield event(
            "response.reasoning_text.done",
            item_id=item_id,
            output_index=output_index,
            content_index=content_index,
            text=text,
        )
        yield event(
            "response.content_part.done",
            item_id=item_id,
            output_index=output_index,
            content_index=content_index,
            part=part,
        )


def _terminal_event(response: Mapping[str, Any]) -> str:
    return _TERMINAL_EVENTS.get(str(response.get("status") or "completed"), "response.completed")


def _chat_sse_chunk(
    response_id: str,
    model: str,
    created: int,
    index: int,
    delta: Mapping[str, Any],
    finish_reason: str | None,
) -> bytes:
    chunk = {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": index,
                "delta": dict(delta),
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(chunk, ensure_ascii=False, separators=(',', ':'))}\n\n".encode("utf-8")
