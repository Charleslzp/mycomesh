from __future__ import annotations

import copy
import json
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any

from .relay_discovery import (
    DiscoveryError,
    RelayDirectory,
    build_announcement,
    fetch_directories,
    normalize_bridge_urls,
    request_json,
    verify_admission,
    verify_announcement,
)


DIRECTORY_SCHEMA = "mycomesh.relay-directory.v1"
_LOGGER = logging.getLogger(__name__)
_PUBLICATION_SLOTS = threading.BoundedSemaphore(8)


class BridgeDiscoveryRuntime:
    def __init__(self, config: dict[str, Any], cache_path: str) -> None:
        self.config = copy.deepcopy(config)
        self.directory = RelayDirectory(
            cache_path, policy=config["policy"], context=config["context"]
        )
        self.bridge_urls = list(config["bridge_urls"])
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False

    def merge(self, announcement: dict[str, Any]) -> bool:
        return self.directory.merge(announcement)

    def live(self) -> list[dict[str, Any]]:
        return self.directory.live()

    def payload(self) -> dict[str, Any]:
        return {"schema": DIRECTORY_SCHEMA, "relays": self.live()}

    def sync_once(self) -> int:
        records = fetch_directories(
            self.bridge_urls, timeout=self.config["policy"]["timeout_seconds"],
            network_profile=self.config["context"]["network_profile"],
        )
        accepted = 0
        for record in records:
            try:
                accepted += bool(self.merge(record))
            except (DiscoveryError, ValueError, TypeError):
                continue
        return accepted

    def start(self, bridge_urls: list[str] | None = None) -> None:
        if self._thread is not None:
            return
        if bridge_urls is not None:
            self.bridge_urls = normalize_bridge_urls(
                bridge_urls, network_profile=self.config["context"]["network_profile"]
            )
        self._thread = threading.Thread(
            target=self._run, name="mycomesh-bridge-relay-sync", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sync_once()
            except Exception as exc:
                _LOGGER.warning("Relay directory sync failed (%s)", type(exc).__name__)
            self._stop.wait(self.config["policy"]["refresh_seconds"])

    def close(self) -> None:
        if self._closed:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.config["policy"]["timeout_seconds"] + 2)
            if self._thread.is_alive():
                _LOGGER.warning("Relay directory sync is still draining during shutdown")
                return
        self.directory.close()
        self._closed = True


class RelayDiscoveryPublisher:
    def __init__(
        self,
        config: dict[str, Any],
        admission: dict[str, Any],
        *,
        private_key: str,
        sequence_path: str,
        expected_bindings: dict[str, Any],
    ) -> None:
        self.config = copy.deepcopy(config)
        self.admission = verify_admission(
            admission, policy=config["policy"], context=config["context"]
        )
        for name, expected in expected_bindings.items():
            if self.admission.get(name) != expected:
                raise DiscoveryError(f"Relay admission does not match configured {name}")
        self._private_key = private_key
        self.directory = RelayDirectory(
            sequence_path, policy=config["policy"], context=config["context"]
        )
        self._lock = threading.RLock()
        self._record: dict[str, Any] | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        try:
            self.refresh_record()
        except BaseException:
            self.directory.close()
            raise

    @classmethod
    def from_file(cls, config: dict[str, Any], admission_path: str, **kwargs: Any) -> RelayDiscoveryPublisher:
        with Path(admission_path).open("rb") as source:
            raw = source.read(16 * 1024 + 1)
        if len(raw) > 16 * 1024:
            raise DiscoveryError("Relay admission file exceeds maximum size")
        try:
            admission = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise DiscoveryError("Relay admission file must contain valid JSON") from exc
        return cls(config, admission, **kwargs)

    def refresh_record(self) -> dict[str, Any]:
        with self._lock:
            verify_admission(
                self.admission, policy=self.config["policy"], context=self.config["context"]
            )
            sequence = self.directory.next_sequence(self.admission["attestation_address"])
            record = build_announcement(self.admission, self._private_key, sequence)
            verified = verify_announcement(
                record, policy=self.config["policy"], context=self.config["context"]
            )
            self.directory.merge(verified)
            self._record = verified
            return copy.deepcopy(self._record)

    def current(self) -> dict[str, Any] | None:
        with self._lock:
            if self._record is None or self._record["expires_at"] <= time.time():
                return None
            return copy.deepcopy(self._record)

    def publish_once(self) -> int:
        record = self.current()
        if record is None or record["expires_at"] - time.time() <= 60:
            record = self.refresh_record()
        urls = self.config["bridge_urls"]
        if not urls:
            return 0

        results: queue.Queue[bool] = queue.Queue()

        def register(url: str) -> None:
            try:
                result = request_json(
                    url + "/relays/register", body={"announcement": record},
                    timeout=self.config["policy"]["timeout_seconds"], maximum=16 * 1024,
                )
                results.put(isinstance(result, dict) and result.get("ok") is True)
            except Exception:
                results.put(False)
            finally:
                _PUBLICATION_SLOTS.release()

        pending = 0
        for url in urls:
            if _PUBLICATION_SLOTS.acquire(blocking=False):
                threading.Thread(target=register, args=(url,), name="relay-publish", daemon=True).start()
                pending += 1
        deadline = time.monotonic() + self.config["policy"]["timeout_seconds"] + 0.1
        accepted = 0
        for _ in range(pending):
            try:
                accepted += results.get(timeout=max(0.001, deadline - time.monotonic()))
            except queue.Empty:
                break
        return accepted

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="mycomesh-relay-announcement", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.publish_once()
            except Exception as exc:
                _LOGGER.warning("Relay announcement publication failed (%s)", type(exc).__name__)
            self._stop.wait(min(30, self.config["policy"]["refresh_seconds"]))

    def close(self) -> None:
        if self._closed:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.config["policy"]["timeout_seconds"] + 2)
            if self._thread.is_alive():
                _LOGGER.warning("Relay announcement publisher is still draining during shutdown")
                return
        self.directory.close()
        self._closed = True
