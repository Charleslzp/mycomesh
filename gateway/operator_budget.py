"""Small durable usage budget used by operator-configured Providers."""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from pathlib import Path


class OperatorBudgetError(ValueError):
    pass


MAX_USAGE_LIMIT_UNITS = 10**30


class OperatorBudget:
    """Track a rolling, fixed-length usage window in a role data volume.

    Values are settlement units (USDC's six-decimal integer scale).  The
    budget is advisory for requests without a payment reservation; V4/V5
    requests reserve their signed maximum before the upstream call.
    """

    def __init__(self, *, limit_units: int, period_seconds: int, state_path: str | Path):
        if type(limit_units) is not int or limit_units < 0 or limit_units > MAX_USAGE_LIMIT_UNITS:
            raise OperatorBudgetError(
                f"usage limit must be between 0 and {MAX_USAGE_LIMIT_UNITS}"
            )
        if type(period_seconds) is not int or period_seconds < 60 or period_seconds > 366 * 24 * 60 * 60:
            raise OperatorBudgetError("usage period must be between 60 seconds and one year")
        self.limit_units = limit_units
        self.period_seconds = period_seconds
        self.state_path = Path(state_path)
        self._lock = threading.RLock()
        self._window_started = int(time.time())
        self._spent_units = 0
        self._reserved_units = 0
        self._load()

    @property
    def enabled(self) -> bool:
        return self.limit_units > 0

    def reserve(self, maximum_units: int) -> bool:
        maximum = max(0, int(maximum_units))
        if not self.enabled:
            return True
        with self._lock:
            self._refresh()
            if self._spent_units + self._reserved_units + maximum > self.limit_units:
                return False
            self._reserved_units += maximum
            self._save()
            return True

    def settle(self, reservation_units: int, actual_units: int) -> bool:
        actual = max(0, int(actual_units))
        reservation = max(0, int(reservation_units))
        if not self.enabled:
            return True
        with self._lock:
            self._refresh()
            self._reserved_units = max(0, self._reserved_units - reservation)
            if self._spent_units + actual > self.limit_units:
                self._save()
                return False
            self._spent_units += actual
            self._save()
            return True

    def release(self, reservation_units: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._refresh()
            self._reserved_units = max(0, self._reserved_units - max(0, int(reservation_units)))
            self._save()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            self._refresh()
            return {
                "limit_units": self.limit_units,
                "period_seconds": self.period_seconds,
                "window_started": self._window_started,
                "spent_units": self._spent_units,
                "reserved_units": self._reserved_units,
            }

    def _refresh(self) -> None:
        now = int(time.time())
        if now - self._window_started < self.period_seconds:
            return
        self._window_started = now
        self._spent_units = 0
        self._reserved_units = 0

    def _load(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if not isinstance(raw, dict):
            return
        try:
            if int(raw.get("limit_units") or 0) != self.limit_units:
                return
            if int(raw.get("period_seconds") or 0) != self.period_seconds:
                return
            now = int(time.time())
            started = int(raw.get("window_started") or now)
            if now - started >= self.period_seconds:
                return
            self._window_started = started
            self._spent_units = max(0, int(raw.get("spent_units") or 0))
        except (TypeError, ValueError, OverflowError):
            return
        # Reservations cannot survive a process restart safely; successful
        # requests are committed as spent and in-flight claims are retried.
        self._reserved_units = 0

    def _save(self) -> None:
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(self.snapshot(), sort_keys=True, separators=(",", ":")) + "\n"
        temporary = self.state_path.with_name(
            f".{self.state_path.name}.{secrets.token_hex(8)}.tmp"
        )
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.state_path)
        os.chmod(self.state_path, 0o600)
