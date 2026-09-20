from __future__ import annotations

import copy
import io
import json
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from gateway.chain import parse_private_key, private_key_to_address
from gateway.relay_discovery import (
    ADMISSION_SCHEMA, ANNOUNCEMENT_SCHEMA, DIRECTORY_SCHEMA, DiscoveryError, RelayDirectory,
    RelayDiscoveryClient, build_admission, build_announcement, canonical_json, fetch_directories,
    load_discovery_config, normalize_policy, probe_announcement, request_json, sign_record,
    validate_origin, verify_admission, verify_announcement,
)
from gateway.relay_discovery_admin import endorse_admission, main as admission_main

ROOT = Path(__file__).resolve().parents[1]
KEYS = ["0x" + f"{number:064x}" for number in (1, 2, 3, 4, 5)]
ADDRESSES = [private_key_to_address(parse_private_key(key)) for key in KEYS]


def fixture(*, now: int | None = None, url: str = "http://127.0.0.1:9902", sequence: int = 1):
    now = int(time.time()) if now is None else now
    policy = normalize_policy({"authorities": ADDRESSES[:3], "threshold": 2})
    context = {"network_id": "mycomesh-test", "channel_id": "codex", "chain_id": 11155111,
               "settlement_contract": "0x" + "ab" * 20, "protocol_version": 8, "network_profile": "local"}
    binding = {key: value for key, value in context.items() if key != "network_profile"}
    binding.update(host="127.0.0.1", provider_port=9901, public_url=url, provider_tls=False,
                   payment_address=ADDRESSES[4], attestation_address=ADDRESSES[3])
    admission = build_admission(binding, expires_at=now + 86400, private_keys=KEYS[:2])
    return policy, context, admission, build_announcement(admission, KEYS[3], sequence, now=now)


class DiscoveryProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.now = 1800000000
        cls.policy, cls.context, cls.admission, cls.record = fixture(now=cls.now)

    def verify(self, record):
        return verify_announcement(record, policy=self.policy, context=self.context, now=self.now)

    def test_signed_roundtrip_and_copy(self):
        verified = self.verify(self.record)
        verified["admission"]["signatures"].clear()
        self.assertEqual(len(self.record["admission"]["signatures"]), 2)

    def test_tamper_rejects_every_binding(self):
        for field, value in {"network_id": "evil", "channel_id": "other", "chain_id": 1,
                             "settlement_contract": ADDRESSES[0], "protocol_version": 9,
                             "host": "127.0.0.2", "provider_port": 1,
                             "public_url": "http://127.0.0.2:9902", "provider_tls": True,
                             "payment_address": ADDRESSES[0], "attestation_address": ADDRESSES[0]}.items():
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record[field] = value
                with self.assertRaises(DiscoveryError):
                    self.verify(record)

    def test_quorum_duplicate_untrusted_and_self_signed_rejected(self):
        for keys in ([KEYS[0]], [KEYS[0], KEYS[0]], [KEYS[0], KEYS[4]], [KEYS[3]]):
            admission = build_admission({key: self.record[key] for key in self.admission if key not in {"schema", "expires_at", "signatures"}},
                                        expires_at=self.now + 86400, private_keys=list(keys))
            with self.assertRaises(DiscoveryError):
                verify_admission(admission, policy=self.policy, context=self.context, now=self.now)

    def test_malformed_or_expired_records(self):
        mutations = [{"sequence": 0}, {"sequence": True}, {"issued_at": self.now + 31},
                     {"expires_at": self.now}, {"expires_at": self.now + 301}, {"extra": 1},
                     {"signature": self.record["signature"][:-2] + "00"},
                     {"signature": "0x" + "00" * 65}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(DiscoveryError):
                    self.verify({**self.record, **mutation})

    def test_network_policy_rejects_weak_or_ambiguous_values(self):
        for policy in ({"authorities": ADDRESSES[:3], "threshold": 1},
                       {"authorities": [ADDRESSES[0], ADDRESSES[0]], "threshold": 2},
                       {"authorities": ADDRESSES[:3], "threshold": True},
                       {"authorities": ADDRESSES[:3], "threshold": 2, "timeout_seconds": float("inf")}):
            with self.assertRaises(DiscoveryError):
                normalize_policy(policy)

    def test_endpoint_ssrf_redirect_dns_and_ambiguous_url_boundary(self):
        for url in ("https://10.0.0.1", "https://169.254.169.254", "https://127.0.0.1", "https://[::1]",
                    "https://[::ffff:8.8.8.8]", "https://example.com", "https://8.8.8.8/",
                    "https://8.8.8.8/a", "https://user@8.8.8.8", "https://8.8.8.8?q=x", "http://8.8.8.8",
                    "https://[2002:0808:0808::1]", "https://[3fff::1]", "https://192.88.99.1", "https://8.8.8.8:443"):
            with self.subTest(url=url), self.assertRaises(DiscoveryError):
                validate_origin(url, network_profile="testnet", literal=True)
        self.assertEqual(validate_origin("https://8.8.8.8", network_profile="testnet", literal=True), "https://8.8.8.8")
        self.assertEqual(validate_origin("https://[2606:4700:4700::1111]", network_profile="testnet", literal=True), "https://[2606:4700:4700::1111]")

    def test_persisted_watermark_rejects_rollback_and_equivocation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relays.sqlite3"
            cache = RelayDirectory(path, policy=self.policy, context=self.context)
            second = build_announcement(self.admission, KEYS[3], 2, now=self.now)
            self.assertTrue(cache.merge(second, now=self.now))
            self.assertFalse(cache.merge(second, now=self.now))
            cache.close()
            cache = RelayDirectory(path, policy=self.policy, context=self.context)
            with self.assertRaises(DiscoveryError):
                cache.merge(self.record, now=self.now)
            changed = build_announcement(self.admission, KEYS[3], 2, now=self.now + 1)
            with self.assertRaises(DiscoveryError):
                cache.merge(changed, now=self.now)
            self.assertEqual(len(cache.live(now=self.now)), 1)
            self.assertEqual(cache.live(now=self.now + 121), [])
            newer_time_old_sequence = build_announcement(self.admission, KEYS[3], 1, now=self.now + 121)
            with self.assertRaises(DiscoveryError):
                cache.merge(newer_time_old_sequence, now=self.now + 121)
            self.assertEqual(cache.next_sequence(ADDRESSES[3]), 3)
            cache.close()

    def test_directory_flood_does_not_evict_remembered_identity(self):
        cache = RelayDirectory(policy=self.policy, context=self.context, max_entries=1)
        cache.merge(self.record, now=self.now)
        binding = {key: self.record[key] for key in self.admission if key not in {"schema", "expires_at", "signatures"}}
        binding["attestation_address"] = ADDRESSES[4]
        admission = build_admission(binding, expires_at=self.now + 86400, private_keys=KEYS[:2])
        with self.assertRaises(DiscoveryError):
            cache.merge(build_announcement(admission, KEYS[4], 1, now=self.now + 121), now=self.now + 121)
        self.assertEqual(cache.next_sequence(ADDRESSES[3]), 2)
        cache.close()

    def test_node_python_signature_interoperability(self):
        script = r'''
import { parseDiscoveryConfig, verifyRelayAnnouncement, discoveryDigest, RELAY_ANNOUNCEMENT_SCHEMA } from "./src/consumer-discovery.mjs";
import { secp256k1 } from "@noble/curves/secp256k1";
let input = ""; for await (const chunk of process.stdin) input += chunk;
const data = JSON.parse(input);
const config = parseDiscoveryConfig({...data.context, relay_discovery:data.policy, bridge_urls:["http://127.0.0.1:1"]},data.context);
verifyRelayAnnouncement(data.record, config, {now:data.now});
const {signature, ...unsigned} = data.record;
unsigned.sequence += 1;
const sig = secp256k1.sign(discoveryDigest(RELAY_ANNOUNCEMENT_SCHEMA,unsigned), data.key.slice(2));
process.stdout.write(JSON.stringify({...unsigned,signature:"0x"+sig.toCompactHex()+(27+sig.recovery).toString(16)}));
'''
        result = subprocess.run(["node", "--input-type=module", "-e", script], cwd=ROOT / "packages/mycomesh-cli",
                                input=json.dumps({"policy": self.policy, "context": self.context, "record": self.record,
                                                  "now": self.now, "key": KEYS[3]}), text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.verify(json.loads(result.stdout))["sequence"], 2)

    def test_independent_authority_endorsement_and_quorum_verification(self):
        policy, context, admission, _ = fixture()
        admission["signatures"] = []
        config = {"policy": policy, "context": context}
        first = endorse_admission(admission, config, private_key=KEYS[0], address=ADDRESSES[0])
        with self.assertRaises(DiscoveryError):
            verify_admission(first, policy=policy, context=context)
        second = endorse_admission(first, config, private_key=KEYS[1], address=ADDRESSES[1])
        self.assertEqual(verify_admission(second, policy=policy, context=context), second)
        with self.assertRaises(DiscoveryError):
            endorse_admission(second, config, private_key=KEYS[0], address=ADDRESSES[0])
        with self.assertRaises(DiscoveryError):
            endorse_admission(admission, config, private_key=KEYS[4], address=ADDRESSES[4])
        forged = copy.deepcopy(first)
        forged["payment_address"] = ADDRESSES[1]
        with self.assertRaises(DiscoveryError):
            endorse_admission(forged, config, private_key=KEYS[1], address=ADDRESSES[1])

    def test_refresh_setting_change_does_not_reset_watermark(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cache.db"
            first = RelayDirectory(path, policy=self.policy, context=self.context)
            first.merge(build_announcement(self.admission, KEYS[3], 2, now=self.now), now=self.now)
            first.close()
            second = RelayDirectory(path, policy={**self.policy, "refresh_seconds": 10}, context=self.context)
            with self.assertRaises(DiscoveryError):
                second.merge(self.record, now=self.now)
            second.close()

    def test_offline_admission_cli_checks_quorum_and_never_overwrites(self):
        policy, context, admission, _ = fixture()
        admission["signatures"] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "network.json"
            manifest.write_text(json.dumps({
                "deployment": "deployment.json", "network_id": context["network_id"],
                "channel_id": context["channel_id"], "network_profile": "local",
                "bridge_urls": ["http://127.0.0.1:9001"], "relay_discovery": policy,
            }))
            (root / "deployment.json").write_text(json.dumps({**context, "settlement": context["settlement_contract"]}))
            source = root / "draft.json"
            source.write_text(json.dumps(admission))
            identities = []
            for index in range(2):
                identity = root / f"authority-{index}.json"
                identity.write_text(json.dumps({"schema_version": 1, "address": ADDRESSES[index], "private_key": KEYS[index]}))
                identity.chmod(0o600)
                identities.append(identity)
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output), \
                 patch("gateway.relay_discovery.request_json", side_effect=AssertionError("offline command used network")):
                for index, identity in enumerate(identities):
                    target = root / f"endorsed-{index}.json"
                    arguments = ["endorse", "--network-config", str(manifest), "--admission", str(source),
                                 "--identity-file", str(identity), "--output", str(target)]
                    self.assertEqual(admission_main(arguments), 0)
                    original = target.read_bytes()
                    self.assertEqual(admission_main(arguments), 2)
                    self.assertEqual(target.read_bytes(), original)
                    status = admission_main(["verify", "--network-config", str(manifest), "--admission", str(target)])
                    self.assertEqual(status, 2 if index == 0 else 0)
                    source = target
            for key in KEYS:
                self.assertNotIn(key, output.getvalue())

    def test_manifest_requires_explicit_matching_trust_and_preserves_opt_out(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.json"
            path.write_text(json.dumps({"deployment": "deployment.json"}))
            self.assertIsNone(load_discovery_config(path))
            deployment = {**self.context, "settlement": self.context["settlement_contract"]}
            (Path(directory) / "deployment.json").write_text(json.dumps(deployment))
            manifest = {"deployment": "deployment.json", "network_id": self.context["network_id"],
                        "channel_id": self.context["channel_id"], "network_profile": "local",
                        "bridge_urls": ["http://127.0.0.1:9001"], "relay_discovery": self.policy}
            path.write_text(json.dumps(manifest))
            self.assertEqual(load_discovery_config(path)["policy"], self.policy)
            manifest["network_id"] = "other"
            path.write_text(json.dumps(manifest))
            with self.assertRaises(DiscoveryError):
                load_discovery_config(path)


class DiscoveryTransportTests(unittest.TestCase):
    def setUp(self):
        self.routes = {}
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                value = owner.routes.get(self.path, {})
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/relays")
                    self.end_headers()
                    return
                body = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.policy, self.context, self.admission, self.record = fixture(url=self.url)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_real_endpoint_probe_and_mismatched_payment(self):
        self.routes["/relay-announcement"] = self.record
        self.routes["/health"] = {"ok": True, "settlement_ready": True,
                                 "relay_payment_address": self.record["payment_address"],
                                 "relay_attestation_address": self.record["attestation_address"]}
        self.assertEqual(probe_announcement(self.record, policy=self.policy, context=self.context), self.record)
        self.routes["/health"]["relay_payment_address"] = ADDRESSES[0]
        with self.assertRaises(DiscoveryError):
            probe_announcement(self.record, policy=self.policy, context=self.context)

    def test_multiple_bridges_one_offline_and_bad_entries_preserve_good_cache(self):
        self.routes["/relays"] = {"schema": DIRECTORY_SCHEMA, "relays": [{"invalid": 1}, self.record]}
        with tempfile.TemporaryDirectory() as directory:
            client = RelayDiscoveryClient(policy=self.policy, context=self.context,
                                          bridge_urls=["http://127.0.0.1:1", self.url], cache_path=Path(directory) / "cache.db")
            self.assertEqual(client.refresh()[0], self.record)
            with patch("gateway.relay_discovery.fetch_directories", return_value=[]):
                self.assertEqual(client.refresh(force=True), [self.record])
            client.close()

    def test_no_redirect_and_bounded_response(self):
        with self.assertRaises(DiscoveryError):
            request_json(self.url + "/redirect")
        self.routes["/large"] = {"payload": "x" * 1024}
        with self.assertRaises(DiscoveryError):
            request_json(self.url + "/large", maximum=32)

    def test_startup_refresh_is_nonblocking_coalesced_and_drains_before_close(self):
        entered, release = threading.Event(), threading.Event()
        def stalled(*_args, **_kwargs):
            entered.set()
            release.wait(2)
            return [self.record]
        with tempfile.TemporaryDirectory() as directory:
            client = RelayDiscoveryClient(policy=self.policy, context=self.context, bridge_urls=[self.url],
                                          cache_path=Path(directory) / "cache.db")
            try:
                with patch("gateway.relay_discovery.fetch_directories", side_effect=stalled) as fetch:
                    beginning = time.monotonic()
                    client.start_refresh()
                    self.assertLess(time.monotonic() - beginning, 0.2)
                    self.assertTrue(entered.wait(1))
                    client.start_refresh()
                    self.assertEqual(fetch.call_count, 1)
                    release.set()
                    client.close()
                self.assertIsNone(client._background)
                self.assertTrue(client.directory._closed)
            finally:
                release.set()
                client.close()

    def test_stalled_dns_is_bounded_for_caller_and_global_workers(self):
        release = threading.Event()
        started = []
        class StalledOpener:
            def open(self, *_args, **_kwargs):
                started.append(1)
                release.wait(5)
                raise OSError("released test resolver")
        try:
            with patch("gateway.relay_discovery.urllib.request.build_opener", return_value=StalledOpener()):
                beginning = time.monotonic()
                for _ in range(10):
                    with self.assertRaises(DiscoveryError):
                        request_json("https://example.com/relays", timeout=0.02)
                self.assertLess(time.monotonic() - beginning, 1)
                self.assertLessEqual(len(started), 8)
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()
