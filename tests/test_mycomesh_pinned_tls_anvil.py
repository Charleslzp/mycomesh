"""Relays without domains or CAs: a self-signed certificate pinned in the on-chain directory."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mycomesh.directory import encode_announce
from mycomesh.evm import address_of
from mycomesh.identity import create_identity
from mycomesh.network import load_network
from mycomesh.protocol import Prices
from mycomesh.provider.link import RelayEndpoint, run_provider
from mycomesh.provider.worker import ProviderWorker
from mycomesh.relay.core import RelayCore
from mycomesh.relay.server import RelayServer
from mycomesh.tlspin import PIN_PREFIX, PinError, generate_certificate, request_json, server_context
from tests.mycomesh_anvil import DISPUTE_WINDOW, PROVIDER_SIGNER, RELAY_SIGNER, AnvilV11, available

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "packages/mycomesh-cli/bin/mycomesh-consumer.mjs"


def echo(document: dict):
    return {"output_text": "pinned and private"}, 10, 5


@unittest.skipUnless(available(), "anvil and forge artifacts are required")
class PinnedTlsAnvilTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.chain = chain = AnvilV11()
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.pin = generate_certificate(tmp / "relay.crt", tmp / "relay.key", "127.0.0.1")
        tls = server_context(tmp / "relay.crt", tmp / "relay.key")
        core = RelayCore(chain.deployment, RELAY_SIGNER, chain.reader, tmp / "relay")
        cls.relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), chain.relay, chain.rpc, DISPUTE_WINDOW,
                                settle_interval=0.0, settle_count=1, http_tls=tls, link_tls=tls)
        cls.relay.start()
        pin = f"{PIN_PREFIX}{cls.pin}"
        cls.url = f"https://127.0.0.1:{cls.relay.http_address[1]}"
        chain.send(chain.relay, chain.directory, encode_announce(
            address_of(RELAY_SIGNER), cls.url + pin, f"127.0.0.1:{cls.relay.link_address[1]}{pin}"))
        cls.manifest = tmp / "network.json"
        cls.manifest.write_text(json.dumps(chain.manifest([])))  # no Relays, no CA: only the chain
        cls.stop = threading.Event()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.stop.set()
        cls.relay.stop()
        cls.chain.close()
        cls.tmp.cleanup()

    def test_provider_and_consumers_trust_the_pin_not_a_ca(self) -> None:
        network = load_network(self.manifest)
        [relay] = network.all_relays()
        self.assertEqual(relay.pin, self.pin)
        status, health = request_json(f"{relay.url}/health{PIN_PREFIX}{relay.pin}")
        self.assertEqual((status, health["relay_signer"]), (200, address_of(RELAY_SIGNER)))
        with self.assertRaises(PinError):
            request_json(f"{relay.url}/health{PIN_PREFIX}{'0' * 64}")

        worker = ProviderWorker(identity=create_identity(), provider_private=PROVIDER_SIGNER, deployment=self.chain.deployment,
                                backend=echo, prices=Prices(1_000, 1_000, 100), models=("gpt-5.5",),
                                data_dir=Path(self.tmp.name) / "provider")
        [link] = run_provider(worker, [RelayEndpoint(relay.link_host, relay.link_port, tls=True, signer=relay.signer,
                                                     pin=relay.pin)], self.stop)
        self.assertTrue(link.connected.wait(20), link.last_error)
        [impostor] = run_provider(worker, [RelayEndpoint(relay.link_host, relay.link_port, tls=True, pin="0" * 64)], self.stop)
        time.sleep(1.5)
        self.assertFalse(impostor.connected.is_set())

        if not shutil.which("node"):
            self.skipTest("node is required for the Consumer half")
        data = Path(self.tmp.name) / "consumer"
        owner = Path(self.tmp.name) / "owner.key"
        owner.write_text(self.chain.consumer + "\n")
        env = {**os.environ, "MYCOMESH_WALLET_PASSWORD": "pinned wallet password"}

        def cli(*args: str) -> str:
            result = subprocess.run(["node", str(CLI), *args, "--network", str(self.manifest), "--data-dir", str(data)],
                                    capture_output=True, text=True, timeout=180, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        cli("init", "--owner-key-file", str(owner))
        cli("setup", "--owner-key-file", str(owner), "--deposit", "5000000", "--max-per-request", "1000000")
        reply = json.loads(cli("request", "--max-fee", "1000000", "hello"))
        self.assertEqual(reply["output_text"], "pinned and private")


    def test_node_pins_ca_issued_certificates_too(self) -> None:
        """Official Relays hold CA-issued certificates; the pin alone must decide, not the chain."""
        if not shutil.which("node"):
            self.skipTest("node is required")
        import datetime
        import ssl

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        tmp = Path(self.tmp.name)
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
        leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay")]))
                .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), False)
                .sign(ca_key, hashes.SHA256()))
        (tmp / "leaf.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (tmp / "leaf.key").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                              serialization.NoEncryption()))
        from mycomesh.tlspin import fingerprint

        pin = fingerprint(leaf.public_bytes(serialization.Encoding.DER))
        core = RelayCore(self.chain.deployment, RELAY_SIGNER, self.chain.reader, tmp / "relay-ca")
        relay = RelayServer(core, ("127.0.0.1", 0), ("127.0.0.1", 0), self.chain.relay, self.chain.rpc, DISPUTE_WINDOW,
                            http_tls=server_context(tmp / "leaf.crt", tmp / "leaf.key"))
        relay.start()
        self.addCleanup(relay.stop)
        url = f"https://127.0.0.1:{relay.http_address[1]}/health"
        script = ("import('" + str(ROOT / "packages/mycomesh-cli/src/consumer.mjs") + "').then(async ({ httpJson }) => {"
                  "const good = await httpJson(process.argv[1], { pin: process.argv[2] });"
                  "const bad = await httpJson(process.argv[1], { pin: '0'.repeat(64) }).then(() => 'accepted', (e) => 'refused');"
                  "console.log(JSON.stringify({ status: good.status, signer: good.body.relay_signer, bad })); });")
        result = subprocess.run(["node", "-e", script, url, pin], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"status": 200, "signer": address_of(RELAY_SIGNER), "bad": "refused"})



if __name__ == "__main__":
    unittest.main()
