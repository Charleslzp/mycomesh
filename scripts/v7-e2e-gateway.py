#!/usr/bin/env python3
"""Deterministic OpenAI-compatible upstream used by the local V7 smoke test."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "MycoMeshV7E2E/1"

    def _write(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/health", "/ready"}:
            self._write(
                200,
                {
                    "ok": True,
                    "network_profile": "testnet",
                    "production_strict": True,
                    "settlement_ready": True,
                    "public_model_id": "mycomesh-codex-standard-v1",
                    "inference_capabilities": {
                        "schema": "mycomesh.inference.capabilities.v1",
                        "backend": "codex_app_server",
                        "native_output_token_cap": False,
                        "native_usage_events": True,
                        "trusted_native_usage": True,
                        "runtime_metering_proof": False,
                        "post_execution_output_cap_validation": True,
                        "metering_mode": "codex-app-server-postvalidated-v1",
                        "supports_streaming": False,
                        "production_ready": True,
                        "maximum_output_token_cap": 2000,
                    },
                },
            )
            return
        self._write(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/v1/responses", "/v1/chat/completions", "/mycomesh/p2p-infer"}:
            self._write(404, {"error": "not found"})
            return
        if self.headers.get("authorization") != f"Bearer {self.server.gateway_key}":
            self._write(401, {"error": "invalid gateway key"})
            return
        length = int(self.headers.get("content-length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            self._write(400, {"error": "invalid json"})
            return
        endpoint = "chat" if self.path.endswith("/chat/completions") else "responses"
        if self.path == "/mycomesh/p2p-infer":
            if (
                request.get("schema") != "mycomesh.gateway.p2p-native.v1"
                or request.get("endpoint") not in {"chat", "responses"}
                or not isinstance(request.get("request"), dict)
            ):
                self._write(422, {"error": "invalid P2P native inference wrapper"})
                return
            endpoint = request["endpoint"]
            request = request["request"]
        model = str(request.get("model") or "mycomesh-codex-standard-v1")
        if endpoint == "chat":
            usage = {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}
            payload = {
                "id": "e2e-chat-1",
                "object": "chat.completion",
                "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "v7-e2e-ok"}, "finish_reason": "stop"}],
                "usage": usage,
            }
        else:
            usage = {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8}
            payload = {
                "id": "e2e-response-1",
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": model,
                "output": [],
                "output_text": "v7-e2e-ok",
                "usage": usage,
            }
        self._write(200, payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--key", default="e2e-gateway-key")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.gateway_key = args.key
    server.serve_forever()


if __name__ == "__main__":
    main()
