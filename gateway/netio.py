from __future__ import annotations

import math
import string
import time
from typing import Any, BinaryIO


class NetworkIOError(ValueError):
    pass


def is_legacy_ipv4_hostname(value: str) -> bool:
    """Return whether libc may interpret a non-canonical hostname as IPv4."""
    labels = str(value).lower().split(".")
    if not 1 <= len(labels) <= 4 or any(not label for label in labels):
        return False
    numbers: list[int] = []
    for label in labels:
        if label.startswith("0x"):
            digits = label[2:]
            base = 16
            alphabet = string.hexdigits
        elif len(label) > 1 and label.startswith("0"):
            digits = label[1:]
            base = 8
            alphabet = "01234567"
        else:
            digits = label
            base = 10
            alphabet = string.digits
        if not digits or any(character not in alphabet for character in digits):
            return False
        numbers.append(int(digits, base))

    if len(numbers) == 1:
        return numbers[0] <= 0xFFFFFFFF
    if any(number > 0xFF for number in numbers[:-1]):
        return False
    final_limits = {2: 0xFFFFFF, 3: 0xFFFF, 4: 0xFF}
    return numbers[-1] <= final_limits[len(numbers)]


def bounded_timeout(value: Any, *, maximum: float, label: str = "timeout") -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise NetworkIOError(f"{label} must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise NetworkIOError(f"{label} must be finite and positive")
    if timeout > maximum:
        raise NetworkIOError(f"{label} must not exceed {maximum:g} seconds")
    return timeout


def read_bounded(
    response: BinaryIO,
    *,
    maximum: int,
    label: str = "response",
    deadline: float | None = None,
) -> bytes:
    if maximum <= 0:
        raise ValueError("maximum must be positive")
    if deadline is not None and not math.isfinite(float(deadline)):
        raise ValueError("deadline must be finite")
    declared_length = _content_length(response)
    if declared_length is not None and declared_length > maximum:
        raise NetworkIOError(f"{label} exceeds {maximum} bytes")

    read_once = getattr(response, "read1", None)
    if not callable(read_once):
        nested = getattr(response, "fp", None)
        read_once = getattr(nested, "read1", None)
    if not callable(read_once):
        _apply_remaining_timeout(response, deadline, label)
        try:
            payload = response.read(maximum + 1)
        except TimeoutError as exc:
            raise NetworkIOError(f"{label} deadline exceeded") from exc
        _check_deadline(deadline, label)
    else:
        chunks: list[bytes] = []
        remaining_bytes = maximum + 1
        while remaining_bytes > 0:
            _apply_remaining_timeout(response, deadline, label)
            try:
                chunk = read_once(min(64 * 1024, remaining_bytes))
            except TimeoutError as exc:
                raise NetworkIOError(f"{label} deadline exceeded") from exc
            _check_deadline(deadline, label)
            if not chunk:
                break
            chunks.append(chunk)
            remaining_bytes -= len(chunk)
        payload = b"".join(chunks)
    if len(payload) > maximum:
        raise NetworkIOError(f"{label} exceeds {maximum} bytes")
    return payload


def text_preview(value: str, maximum: int = 1024) -> str:
    return value if len(value) <= maximum else value[:maximum] + "..."


def _content_length(response: BinaryIO) -> int | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all("Content-Length") or []
    else:
        value = headers.get("Content-Length") if hasattr(headers, "get") else None
        values = [] if value is None else [value]
    parts = [part.strip() for value in values for part in str(value).split(",")]
    if not parts:
        return None
    if len(parts) != 1 or not parts[0].isdigit():
        raise NetworkIOError("response has an invalid Content-Length")
    return int(parts[0])


def _check_deadline(deadline: float | None, label: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise NetworkIOError(f"{label} deadline exceeded")


def _apply_remaining_timeout(response: BinaryIO, deadline: float | None, label: str) -> None:
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetworkIOError(f"{label} deadline exceeded")

    candidates = [response, getattr(response, "fp", None)]
    for parent in tuple(candidates):
        candidates.extend(
            [
                getattr(parent, "raw", None),
                getattr(parent, "_sock", None),
            ]
            if parent is not None
            else []
        )
    for candidate in tuple(candidates):
        if candidate is not None:
            candidates.append(getattr(candidate, "_sock", None))
    for candidate in candidates:
        setter = getattr(candidate, "settimeout", None)
        if callable(setter):
            try:
                setter(max(remaining, 0.001))
            except (OSError, ValueError):
                continue
            return
