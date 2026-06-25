from __future__ import annotations

import json
from typing import Any


MISSING = object()


def json_schema_content(content: str, schema: dict[str, Any]) -> str:
    """Return JSON content coerced to the common JSON Schema subset used by APIs."""
    candidate = _parse_json_object(content)
    value = coerce_to_schema(candidate if candidate is not MISSING else content.strip(), schema, content.strip())
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def coerce_to_schema(value: Any, schema: dict[str, Any], fallback: str = "") -> Any:
    if not isinstance(schema, dict):
        return value

    if "const" in schema:
        return schema["const"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        if value in schema["enum"]:
            return value
        return schema["enum"][0]

    schema_type = _schema_type(schema)
    if schema_type == "object" or "properties" in schema:
        return _coerce_object(value, schema, fallback)
    if schema_type == "array":
        return _coerce_array(value, schema, fallback)
    if schema_type == "integer":
        return _coerce_integer(value)
    if schema_type == "number":
        return _coerce_number(value)
    if schema_type == "boolean":
        return _coerce_boolean(value)
    if schema_type == "null":
        return None
    return _coerce_string(value, fallback)


def _parse_json_object(content: str) -> Any:
    stripped = content.strip()
    if not stripped:
        return MISSING
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return MISSING


def _schema_type(schema: dict[str, Any]) -> str:
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        return next((item for item in schema_type if item != "null"), "string")
    if isinstance(schema_type, str):
        return schema_type
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return "string"


def _coerce_object(value: Any, schema: dict[str, Any], fallback: str) -> dict[str, Any]:
    source = value if isinstance(value, dict) else {}
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict):
        properties = {}
    keys = list(properties.keys())
    if isinstance(required, list):
        keys = list(dict.fromkeys([str(key) for key in required] + keys))

    result = {
        key: coerce_to_schema(source.get(key, MISSING), properties.get(key, {"type": "string"}), fallback)
        for key in keys
    }
    if schema.get("additionalProperties") is not False:
        for key, item in source.items():
            if key not in result:
                result[key] = item
    return result


def _coerce_array(value: Any, schema: dict[str, Any], fallback: str) -> list[Any]:
    item_schema = schema.get("items", {"type": "string"})
    if not isinstance(item_schema, dict):
        item_schema = {"type": "string"}
    if isinstance(value, list):
        return [coerce_to_schema(item, item_schema, fallback) for item in value]
    if value is MISSING:
        return []
    return [coerce_to_schema(value, item_schema, fallback)]


def _coerce_integer(value: Any) -> int:
    if isinstance(value, bool) or value is MISSING:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _coerce_number(value: Any) -> int | float:
    if isinstance(value, bool) or value is MISSING:
        return 0
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            return 0
        return int(number) if number.is_integer() else number
    return 0


def _coerce_boolean(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"false", "0", "no", "off"}:
            return False
        if lowered in {"true", "1", "yes", "on"}:
            return True
    return True


def _coerce_string(value: Any, fallback: str) -> str:
    if value is MISSING or value is None:
        return fallback
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
