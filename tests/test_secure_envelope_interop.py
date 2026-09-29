from __future__ import annotations

import base64
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from gateway.identity import create_identity
from gateway.secure_transport import (
    SecureEnvelopeError,
    TransportKeyPair,
    generate_transport_key,
    open_frame,
    seal_json_frame,
    verify_transport_key_binding,
)


CLI_ROOT = Path(__file__).resolve().parents[1] / "packages/mycomesh-cli"
PURPOSE = "mycomesh.test.interop.v1"


class MemoryReplayStore:
    def __init__(self) -> None:
        self.keys: set[tuple[str, str]] = set()

    def remember(self, scope, replay_key, ttl_seconds, now=None) -> None:
        if (scope, replay_key) in self.keys:
            from gateway.secure_transport import SecureEnvelopeReplayError
            raise SecureEnvelopeReplayError("replayed")
        self.keys.add((scope, replay_key))


def run_node(script: str, payload: dict) -> dict:
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        input=json.dumps(payload), capture_output=True, text=True, cwd=CLI_ROOT, timeout=60, check=False,
    )
    if result.returncode:
        raise AssertionError(f"node failed: {result.stderr}")
    return json.loads(result.stdout)


@unittest.skipUnless(
    shutil.which("node") and (CLI_ROOT / "node_modules/@noble/curves").exists(),
    "Node.js Consumer dependencies are not installed",
)
class SecureEnvelopeInteropTest(unittest.TestCase):
    def test_consumer_seals_and_python_provider_opens(self) -> None:
        provider = create_identity()
        provider_key = generate_transport_key(provider)
        document = {"messages": [{"role": "user", "content": "héllo 世界 \n\"quoted\""}], "max_output_tokens": 64}
        output = run_node(
            """
            import { generateIdentity, sealJsonFrame } from "./src/secure-envelope.mjs";
            let input = ""; for await (const chunk of process.stdin) input += chunk;
            const { binding, peer_id, document, purpose } = JSON.parse(input);
            const sender = generateIdentity();
            const frame = sealJsonFrame(document, { sender, recipientBinding: binding, expectedRecipientPeerId: peer_id, purpose });
            console.log(JSON.stringify({ frame: frame.toString("base64"), sender_peer_id: sender.peerId }));
            """,
            {"binding": provider_key.binding, "peer_id": provider.peer_id, "document": document, "purpose": PURPOSE},
        )
        frame = base64.b64decode(output["frame"])
        opened = open_frame(frame, recipient_key=provider_key, expected_purpose=PURPOSE, replay_store=MemoryReplayStore())
        self.assertEqual(json.loads(opened.payload), document)
        self.assertEqual(opened.sender_peer_id, output["sender_peer_id"])

        tampered = bytearray(frame)
        tampered[-40] ^= 0x01
        with self.assertRaises(SecureEnvelopeError):
            open_frame(bytes(tampered), recipient_key=provider_key, expected_purpose=PURPOSE,
                       replay_store=MemoryReplayStore())

    def test_python_provider_seals_and_consumer_opens(self) -> None:
        keys = run_node(
            """
            import { generateIdentity, generateTransportKey } from "./src/secure-envelope.mjs";
            const identity = generateIdentity();
            const key = generateTransportKey(identity, { lifetimeSeconds: 600 });
            console.log(JSON.stringify({ identity, key }));
            """,
            {},
        )
        # The Consumer's binding must verify under the Python rules.
        verified = verify_transport_key_binding(keys["key"]["binding"])
        self.assertEqual(verified.peer_id, keys["identity"]["peerId"])
        provider = create_identity()
        response = {"id": "resp_1", "output_text": "réponse ✓", "usage": {"output_tokens": 3}}
        frame = seal_json_frame(
            response, sender=provider, recipient_binding=keys["key"]["binding"],
            expected_recipient_peer_id=keys["identity"]["peerId"], purpose=PURPOSE,
        )
        opened = run_node(
            """
            import { openFrame } from "./src/secure-envelope.mjs";
            let input = ""; for await (const chunk of process.stdin) input += chunk;
            const { key, frame, purpose, sender } = JSON.parse(input);
            const replaySet = new Set();
            const bytes = Buffer.from(frame, "base64");
            const result = openFrame(bytes, { recipientKey: key, expectedPurpose: purpose, replaySet, expectedSenderPeerId: sender });
            let replayRejected = false;
            try { openFrame(bytes, { recipientKey: key, expectedPurpose: purpose, replaySet }); } catch { replayRejected = true; }
            console.log(JSON.stringify({ payload: JSON.parse(result.payload.toString("utf8")), replayRejected }));
            """,
            {"key": keys["key"], "frame": base64.b64encode(frame).decode(), "purpose": PURPOSE, "sender": provider.peer_id},
        )
        self.assertEqual(opened["payload"], response)
        self.assertTrue(opened["replayRejected"])

    def test_consumer_rejects_a_substituted_transport_key(self) -> None:
        provider = create_identity()
        other = create_identity()
        binding = generate_transport_key(other).binding
        output = run_node(
            """
            import { generateIdentity, sealJsonFrame } from "./src/secure-envelope.mjs";
            let input = ""; for await (const chunk of process.stdin) input += chunk;
            const { binding, peer_id } = JSON.parse(input);
            try {
              sealJsonFrame({ a: 1 }, { sender: generateIdentity(), recipientBinding: binding, expectedRecipientPeerId: peer_id, purpose: "x.y" });
              console.log(JSON.stringify({ rejected: false }));
            } catch (error) { console.log(JSON.stringify({ rejected: true, message: error.message })); }
            """,
            {"binding": binding, "peer_id": provider.peer_id},
        )
        self.assertTrue(output["rejected"], output)
        self.assertIn("peer_id mismatch", output["message"])


if __name__ == "__main__":
    unittest.main()
