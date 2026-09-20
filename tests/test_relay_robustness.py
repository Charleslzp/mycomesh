from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email.message import Message
import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock, patch

from gateway.chain import keccak256, parse_private_key, private_key_to_address, sign_evm_digest
from gateway.identity import create_identity
from gateway.p2p import ProviderConfig
from gateway.relay import (
    RELAY_PROTOCOL_VERSION, RelayControlHTTPServer, RelayError, RelayNotDispatchedError, RelayOutcomeUnknownError, RelayProviderTCPServer,
    RelaySchedulingError, RelayState, _relay_client_timeout, _relay_settlement_health,
    _normalize_relay_fallbacks, _verify_receipt_status_request, relay_infer, relay_receipt_status, run_relay_provider,
    v7_relay_capabilities,
)
from tests.test_relay_scheduler import CONTRACT, SIGNERS, make_state


def read_line(reader):
    return json.loads(reader.readline())


def write_line(writer, payload):
    writer.write(json.dumps(payload).encode() + b"\n")
    writer.flush()


@contextmanager
def live_provider_socket():
    state = RelayState(require_signed_providers=False, reconnect_grace_seconds=0)
    server = RelayProviderTCPServer(("127.0.0.1", 0), state, "test-relay", 9900, 9901)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    connection = socket.create_connection(server.server_address, timeout=2)
    reader, writer = connection.makefile("rb"), connection.makefile("wb")
    try:
        read_line(reader)
        write_line(writer, {"type": "provider_register", "peer": {"peer_id": "peer-a"}})
        if read_line(reader).get("ok") is not True:
            raise AssertionError("Provider registration failed")
        yield state, connection, reader, writer
    finally:
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        reader.close()
        writer.close()
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def reply(writer, job):
    write_line(writer, {"type": "relay_job_result", "job_id": job["job_id"], "response": {"ok": True}})


class RelayQueueIsolationTest(unittest.TestCase):
    def test_queued_timeout_does_not_interrupt_active_or_following_job(self):
        with live_provider_socket() as (state, connection, reader, writer), ThreadPoolExecutor(max_workers=3) as pool:
            active = pool.submit(relay_infer, state, "peer-a", {"n": 1}, 2)
            active_job = read_line(reader)
            queued = pool.submit(relay_infer, state, "peer-a", {"n": 2}, 0.03)
            with self.assertRaises(RelayNotDispatchedError):
                queued.result(timeout=1)
            self.assertIn("peer-a", state.providers)
            self.assertTrue(state.providers["peer-a"].jobs.empty())
            following = pool.submit(relay_infer, state, "peer-a", {"n": 3}, 2)
            reply(writer, active_job)
            following_job = read_line(reader)
            self.assertEqual(following_job["message"]["n"], 3)
            reply(writer, following_job)
            self.assertTrue(active.result(timeout=1)["ok"])
            self.assertTrue(following.result(timeout=1)["ok"])
            session = state.providers["peer-a"]
            self.assertEqual(session.queued_jobs + session.active_jobs + session.received_jobs, 0)

    def test_active_timeout_marks_only_active_unknown_and_queue_not_dispatched(self):
        with live_provider_socket() as (state, connection, reader, writer), ThreadPoolExecutor(max_workers=3) as pool:
            active = pool.submit(relay_infer, state, "peer-a", {"n": 1}, 0.1)
            read_line(reader)
            queued = [pool.submit(relay_infer, state, "peer-a", {"n": n}, 2) for n in (2, 3)]
            with self.assertRaises(RelayOutcomeUnknownError):
                active.result(timeout=1)
            for pending in queued:
                with self.assertRaises(RelayNotDispatchedError):
                    pending.result(timeout=1)
            self.assertNotIn("peer-a", state.providers)
            self.assertEqual(reader.readline(), b"")

    def test_wrong_job_response_is_unknown_and_never_used_as_next_result(self):
        with live_provider_socket() as (state, connection, reader, writer), ThreadPoolExecutor(max_workers=2) as pool:
            active = pool.submit(relay_infer, state, "peer-a", {"n": 1}, 1)
            read_line(reader)
            write_line(writer, {"type": "relay_job_result", "job_id": "wrong-job", "response": {"ok": True}})
            with self.assertRaises(RelayOutcomeUnknownError):
                active.result(timeout=1)


def status_request(state, *, key="0x" + "11" * 32, now=1789458000):
    address = private_key_to_address(parse_private_key(key))
    body = {"chain_id": state.settlement_chain_id, "settlement_contract": state.settlement_contract,
            "key": address, "request_id": "0x" + "77" * 32, "issued_at": now}
    message = (f"MycoMesh receipt status v1\nchain_id:{body['chain_id']}\nsettlement_contract:{body['settlement_contract']}"
               f"\nkey:{address}\nrequest_id:{body['request_id']}\nissued_at:{now}").encode("ascii")
    digest = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode() + message)
    signed = sign_evm_digest(key, digest)
    body["signature"] = "0x" + signed.r[2:] + signed.s[2:] + bytes([signed.v]).hex()
    return body


class RelayReceiptStatusTest(unittest.TestCase):
    def state(self):
        state = make_state()
        state.settlement_chain_id = 11155111
        state.settlement_contract = CONTRACT
        return state

    def test_personal_sign_vector_and_time_boundary(self):
        state = self.state()
        body = status_request(state)
        for difference in (-300, 0, 300):
            self.assertEqual(_verify_receipt_status_request(state, body, now=body["issued_at"] + difference),
                             (body["request_id"], body["key"]))
        for difference in (-301, 301):
            with self.assertRaises(RelaySchedulingError) as error:
                _verify_receipt_status_request(state, body, now=body["issued_at"] + difference)
            self.assertEqual(error.exception.status_code, 401)

    def test_signature_is_bound_to_key_deployment_request_and_time(self):
        state = self.state()
        body = status_request(state)
        for field, value in (("key", "0x" + "ab" * 20), ("request_id", "0x" + "aa" * 32),
                             ("issued_at", body["issued_at"] + 1), ("chain_id", 1),
                             ("settlement_contract", "0x" + "bb" * 20)):
            with self.subTest(field=field), self.assertRaises(RelaySchedulingError):
                _verify_receipt_status_request(state, {**body, field: value}, now=body["issued_at"])

    def test_status_rejects_noncanonical_or_malformed_inputs(self):
        state = self.state()
        body = status_request(state)
        for field, value in (("chain_id", True), ("issued_at", "1789458000"),
                             ("request_id", body["request_id"] + "\n"),
                             ("key", "0x" + "AB" * 20), ("signature", "0x" + "00" * 65)):
            with self.subTest(field=field), self.assertRaises(RelaySchedulingError):
                _verify_receipt_status_request(state, {**body, field: value}, now=body["issued_at"])
        with self.assertRaises(RelaySchedulingError):
            _verify_receipt_status_request(state, {**body, "payload": {}}, now=body["issued_at"])

    def test_status_filters_by_authenticated_key_and_returns_only_public_fields(self):
        state = self.state()
        body = status_request(state, now=int(time.time()))
        state._settlement_submitter = Mock()
        state._settlement_submitter.public_status.return_value = {
            "request_id": body["request_id"], "status": "failed", "error_code": "authorization_expired",
            "tx_hash": None, "updated_at": 123, "authorization_deadline": 456,
            "payload_json": "secret", "provider_signature": "private response material",
        }
        result = relay_receipt_status(state, body)
        self.assertEqual(set(result), {"request_id", "status", "error_code", "tx_hash", "updated_at", "authorization_deadline"})
        state._settlement_submitter.public_status.assert_called_once_with(body["request_id"], key_address=body["key"])
        state._settlement_submitter.public_status.return_value = None
        with self.assertRaises(RelaySchedulingError) as error:
            relay_receipt_status(state, body)
        self.assertEqual(error.exception.status_code, 404)

    def test_health_separates_provider_availability_from_settlement_readiness(self):
        state = make_state()
        state._settlement_submitter = Mock()
        state._settlement_submitter.snapshot.return_value = {"enabled": True, "settlement_ready": False, "error_code": "insufficient_gas"}
        health = v7_relay_capabilities(state)
        self.assertEqual(health["provider_signers"], sorted(SIGNERS.values()))
        self.assertTrue(health["inference_ready"])
        self.assertFalse(health["settlement_ready"])
        state._settlement_submitter.snapshot.side_effect = RuntimeError("RPC secret")
        self.assertEqual(_relay_settlement_health(state)["error_code"], "health_unavailable")

    def test_client_timeout_can_only_shorten_budget(self):
        for value, expected in (("1", 0.001), ("3000", 3), ("999999", 300)):
            headers = Message()
            headers["X-MycoMesh-Request-Timeout-Ms"] = value
            self.assertEqual(_relay_client_timeout(headers), expected)
        for value in ("0", "-1", "1.5", " 1", "NaN", "∞", "1" * 13):
            headers = Message()
            headers["X-MycoMesh-Request-Timeout-Ms"] = value
            with self.subTest(value=value), self.assertRaises(RelayNotDispatchedError):
                _relay_client_timeout(headers)

    def test_status_http_endpoint_authenticates_and_never_exposes_other_key_records(self):
        state = self.state()
        body = status_request(state, now=int(time.time()))
        state._settlement_submitter = Mock()
        state._settlement_submitter.public_status.return_value = None
        server = RelayControlHTTPServer(("127.0.0.1", 0), state)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/v1/mycomesh/receipts/status"
            request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
            body["key"] = "0x" + "ab" * 20
            request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=2)
            self.assertEqual(error.exception.code, 401)
            error.exception.close()
            self.assertEqual(state._settlement_submitter.public_status.call_count, 1)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


class RelayProviderFallbackTest(unittest.TestCase):
    def endpoint(self, host="backup.example"):
        return {"host": host, "provider_port": 9901, "provider_tls": False,
                "public_url": f"http://{host}", "payment_address": "0x" + "55" * 20,
                "attestation_address": "0x" + "66" * 20}

    def test_nonlocal_fallback_requires_pinned_tls_origin_and_valid_addresses(self):
        endpoint = {**self.endpoint(), "provider_tls": True, "public_url": "https://backup.example"}
        self.assertEqual(_normalize_relay_fallbacks([endpoint], network_profile="testnet"), [endpoint])
        for field, value in (("provider_tls", False), ("provider_port", True),
                             ("public_url", "https://user@backup.example"), ("public_url", "https://other.example"),
                             ("host", "bad;host"), ("host", "bad..host"),
                             ("payment_address", "0x" + "00" * 20),
                             ("attestation_address", endpoint["attestation_address"] + "\n")):
            with self.subTest(field=field, value=value), self.assertRaises(RelayError):
                _normalize_relay_fallbacks([{**endpoint, field: value}], network_profile="testnet")
        with self.assertRaises(RelayError):
            _normalize_relay_fallbacks([endpoint, endpoint], network_profile="testnet")

    def run_fallback(self, *, cleanup_failure=False):
        identity = create_identity()
        config = ProviderConfig(peer_id=identity.peer_id, channel="c", agent_id="test", agent_key="test",
                                gateway_url="http://127.0.0.1:8000/v1", model="m", advertise_host="relay", advertise_port=0,
                                identity=identity, network_profile="local", relay_payment_address="0x" + "33" * 20,
                                relay_attestation_address="0x" + "44" * 20)
        stop, primary_registered, backup_registered = threading.Event(), threading.Event(), threading.Event()
        primary_client, primary_server = socket.socketpair()
        backup_client, backup_server = socket.socketpair()
        errors, calls, callbacks, cleanup_pins = [], [], [], []
        peers = []

        def peer_server(connection, host, payout, signer, registered_event, disconnect):
            reader, writer = connection.makefile("rb"), connection.makefile("wb")
            try:
                challenge = "ab" * 32
                write_line(writer, {"type": "provider_challenge", "protocol": RELAY_PROTOCOL_VERSION,
                                    "challenge": challenge, "audience": host + ":9901",
                                    "relay_payment_address": payout, "relay_attestation_address": signer})
                registration = read_line(reader)
                peers.append(registration["peer"])
                write_line(writer, {"ok": True, "type": "provider_registered", "protocol": RELAY_PROTOCOL_VERSION,
                                    "peer_id": config.peer_id, "challenge": challenge, "relay": "http://untrusted.example",
                                    "relay_payment_address": payout, "relay_attestation_address": signer})
                registered_event.wait(timeout=2)
                if not disconnect:
                    stop.wait(timeout=2)
            except Exception as exc:
                errors.append(exc)
            finally:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                reader.close()
                writer.close()
                connection.close()

        threads = [threading.Thread(target=peer_server, args=(primary_server, "primary.example", config.relay_payment_address,
                   config.relay_attestation_address, primary_registered, True), daemon=True)]
        if not cleanup_failure:
            threads.append(threading.Thread(target=peer_server, args=(backup_server, "backup.example", "0x" + "55" * 20,
                           "0x" + "66" * 20, backup_registered, False), daemon=True))
        for thread in threads:
            thread.start()

        def connect(host, port, timeout):
            calls.append(host)
            if host == "primary.example":
                return primary_client
            self.assertEqual(cleanup_pins, ["0x" + "33" * 20])
            return backup_client

        def on_registered(registration):
            callbacks.append(registration)
            if registration["relay_host"] == "primary.example":
                primary_registered.set()
            else:
                backup_registered.set()
                stop.set()

        def on_disconnected():
            cleanup_pins.append(config.relay_payment_address)
            if cleanup_failure:
                raise RelayError("old heartbeat did not stop")

        try:
            with patch("gateway.relay._connect_relay_provider_socket", side_effect=connect), patch("gateway.relay.time.sleep"):
                if cleanup_failure:
                    with self.assertRaisesRegex(RelayError, "old heartbeat"):
                        run_relay_provider("primary.example", 9901, config, on_registered=on_registered, stop_event=stop,
                                           relay_public_url="http://primary.example", relay_fallbacks=[self.endpoint()],
                                           on_disconnected=on_disconnected)
                else:
                    run_relay_provider("primary.example", 9901, config, on_registered=on_registered, stop_event=stop,
                                       relay_public_url="http://primary.example", relay_fallbacks=[self.endpoint()],
                                       on_disconnected=on_disconnected)
            self.assertFalse(errors)
            self.assertEqual(calls, ["primary.example"] if cleanup_failure else ["primary.example", "backup.example"])
            self.assertIs(config.identity, identity)
            if not cleanup_failure:
                self.assertEqual({peer["peer_id"] for peer in peers}, {identity.peer_id})
                self.assertEqual(callbacks[-1]["relay_public_url"], "http://backup.example")
                self.assertEqual(callbacks[-1]["relay"], "http://backup.example")
                self.assertEqual(config.relay_payment_address, "0x" + "55" * 20)
        finally:
            stop.set()
            for connection in (primary_client, primary_server, backup_client, backup_server):
                connection.close()
            for thread in threads:
                thread.join(timeout=2)

    def test_fallback_keeps_provider_identity_and_waits_for_heartbeat_cleanup(self):
        self.run_fallback()

    def test_failed_heartbeat_cleanup_prevents_reconnecting_or_changing_pins(self):
        self.run_fallback(cleanup_failure=True)


if __name__ == "__main__":
    unittest.main()
