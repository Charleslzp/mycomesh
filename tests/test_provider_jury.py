from __future__ import annotations

import copy
import json
import unittest

from gateway import provider_jury as jury
from gateway.identity import create_identity
from tests.test_chain_v9 import address, digest, key, signer


class ProviderJuryTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_900_000_000
        self.relay = create_identity()
        self.providers = [create_identity(), create_identity(), create_identity()]
        self.system_prompt = "Apply the pinned fraud policy."
        self.capability = {
            "schema": jury.CAPABILITY_SCHEMA,
            "models": ["judge-model"],
            "max_output_tokens": 1024,
            "supports_structured_verdict": True,
            "decision_policy_hash": jury.decision_policy_hash(
                model="judge-model",
                system_prompt=self.system_prompt,
                max_output_tokens=512,
                task_ttl_seconds=300,
            ),
        }
        self.evidence_document = {
            "schema": "fixture.evidence.v1", "finding": "signed response mismatch",
            "artifacts": [digest(13), digest(14)],
        }
        self.inference = {
            "model": "judge-model", "system_prompt": self.system_prompt,
            "evidence_document": self.evidence_document,
            "max_output_tokens": 512,
        }
        self.evidence = {"report_id": digest(11), "evidence_hash": jury.evidence_hash(self.evidence_document),
                         "request_hash": digest(13), "response_hash": digest(14)}

    def selected(self, index: int, *, operator: str | None = None):
        identity = self.providers[index]
        operator_id = operator or f"operator-{index}"
        return {
            "owner": address(100 + index), "vote_signer": signer(20 + index),
            "operator_id": operator_id,
            "operator_id_hash": jury._keccak_text(operator_id),
            "peer_id": identity.peer_id, "peer_id_hash": jury._keccak_text(identity.peer_id),
            "capability": self.capability, "capability_hash": jury.capability_hash(self.capability),
            "reputation": 90 + index,
        }

    def task(self, index: int, **changes):
        args = dict(network_id="fixture", chain_id=31337, settlement_contract=address(50),
                    jury_registry=address(51), settlement_key=digest(1), assignment_hash=digest(2),
                    selected_provider=self.selected(index), evidence=self.evidence,
                    decision_policy_hash=jury.decision_policy_hash(
                        model=self.inference["model"],
                        system_prompt=self.inference["system_prompt"],
                        max_output_tokens=self.inference["max_output_tokens"],
                        task_ttl_seconds=300,
                    ),
                    inference_request=self.inference,
                    relay_identity=self.relay, issued_at=self.now, deadline=self.now + 300,
                    nonce=digest(30 + index))
        args.update(changes)
        return jury.build_jury_task(**args)

    def verdict(self, index: int, task, *, confirmed=True, operator_reason=None):
        return jury.build_provider_verdict(
            task=task,
            model_output={"confirmed": confirmed, "confidence_bps": 9000,
                          "reason_code": "fraud" if confirmed else "not_proven",
                          "reasoning": operator_reason or f"independent reasoning {index}"},
            provider_identity=self.providers[index], evm_private_key=key(20 + index),
            vote_nonce=0, vote_deadline=self.now + 240, now=self.now + 10,
        )

    def test_matching_independent_ai_verdicts_form_atomic_quorum(self):
        tasks = [self.task(0), self.task(1)]
        self.assertEqual(jury.jury_context_hash(tasks[0]), jury.jury_context_hash(tasks[1]))
        verdicts = [self.verdict(0, tasks[0]), self.verdict(1, tasks[1])]
        task_map = {jury.evidence_hash(task): task for task in tasks}
        plan = jury.aggregate_quorum(verdicts, tasks=task_map, threshold=2, now=self.now + 20)
        self.assertTrue(plan["confirmed"])
        self.assertEqual(plan["assignment_hash"], digest(2))
        self.assertEqual(len(plan["vote_permits"]), 2)
        self.assertTrue(plan["calldata"].startswith("0x"))

    def test_juror_specific_reasoning_does_not_change_common_decision(self):
        tasks = [self.task(0), self.task(1)]
        first = self.verdict(0, tasks[0], operator_reason="reason A")
        second = self.verdict(1, tasks[1], operator_reason="reason B")
        self.assertNotEqual(first["model_output_hash"], second["model_output_hash"])
        self.assertEqual(first["decision_hash"], second["decision_hash"])

    def test_negative_quorum_has_zero_report_permits_and_executable_calldata(self):
        tasks = [self.task(0), self.task(1)]
        verdicts = [
            self.verdict(0, tasks[0], confirmed=False),
            self.verdict(1, tasks[1], confirmed=False),
        ]
        self.assertFalse(verdicts[0]["vote_permit"]["confirmed"])
        self.assertEqual(verdicts[0]["vote_permit"]["report_id"], jury.ZERO_BYTES32)
        plan = jury.aggregate_quorum(
            verdicts,
            tasks={jury.evidence_hash(task): task for task in tasks},
            threshold=2,
            now=self.now + 20,
        )
        self.assertFalse(plan["confirmed"])
        self.assertEqual(len(plan["vote_permits"]), 2)
        self.assertTrue(plan["calldata"].startswith("0x"))

    def test_task_and_model_output_tampering_fail_closed(self):
        task = self.task(0)
        changed = copy.deepcopy(task)
        changed["evidence"]["response_hash"] = digest(99)
        with self.assertRaises(jury.ProviderJuryError):
            jury.verify_jury_task(changed, now=self.now + 1)
        verdict = self.verdict(0, task)
        changed = copy.deepcopy(verdict)
        changed["model_output"]["confirmed"] = False
        with self.assertRaises(jury.ProviderJuryError):
            jury.verify_provider_verdict(changed, task=task, now=self.now + 20)

    def test_wrong_provider_identity_or_evm_key_is_rejected(self):
        task = self.task(0)
        with self.assertRaises(jury.ProviderJuryError):
            jury.build_provider_verdict(
                task=task, model_output={"confirmed": True, "confidence_bps": 1,
                                         "reason_code": "x", "reasoning": "x"},
                provider_identity=self.providers[1], evm_private_key=key(20),
                vote_nonce=0, vote_deadline=self.now + 200, now=self.now + 1)
        with self.assertRaises(jury.ProviderJuryError):
            jury.build_provider_verdict(
                task=task, model_output={"confirmed": True, "confidence_bps": 1,
                                         "reason_code": "x", "reasoning": "x"},
                provider_identity=self.providers[0], evm_private_key=key(21),
                vote_nonce=0, vote_deadline=self.now + 200, now=self.now + 1)

    def test_conflicting_outcome_and_duplicate_operator_do_not_form_quorum(self):
        tasks = [self.task(0), self.task(1)]
        verdicts = [self.verdict(0, tasks[0]), self.verdict(1, tasks[1], confirmed=False)]
        with self.assertRaises(jury.ProviderJuryError):
            jury.aggregate_quorum(verdicts, tasks={jury.evidence_hash(x): x for x in tasks},
                                  threshold=2, now=self.now + 20)
        duplicate_task = self.task(1, selected_provider=self.selected(1, operator="operator-0"))
        duplicate = self.verdict(1, duplicate_task)
        with self.assertRaises(jury.ProviderJuryError):
            jury.aggregate_quorum([self.verdict(0, tasks[0]), duplicate],
                                  tasks={jury.evidence_hash(tasks[0]): tasks[0],
                                         jury.evidence_hash(duplicate_task): duplicate_task},
                                  threshold=2, now=self.now + 20)

    def test_model_output_parser_rejects_duplicate_or_unknown_fields(self):
        raw='{"confirmed":true,"confidence_bps":9000,"reason_code":"fraud","reasoning":"bound evidence"}'
        self.assertTrue(jury.parse_model_output(raw)["confirmed"])
        with self.assertRaises(jury.ProviderJuryError):
            jury.parse_model_output(raw[:-1]+',"confirmed":false}')
        with self.assertRaises(jury.ProviderJuryError):
            jury.parse_model_output(raw[:-1]+',"extra":1}')

    def test_both_monetary_outcomes_require_protocol_confidence_floor(self):
        for confirmed in (True, False):
            with self.subTest(confirmed=confirmed):
                raw = json.dumps({
                    "confirmed": confirmed,
                    "confidence_bps": jury.MIN_AUTOMATIC_CONFIDENCE_BPS - 1,
                    "reason_code": "fraud" if confirmed else "not_proven",
                    "reasoning": "insufficient confidence for an automatic monetary action",
                })
                with self.assertRaisesRegex(jury.ProviderJuryError, "confidence floor"):
                    jury.parse_model_output(raw)

    def test_decision_policy_hash_binds_every_executable_input(self):
        base = {
            "model": "judge-model",
            "system_prompt": self.system_prompt,
            "max_output_tokens": 512,
            "task_ttl_seconds": 300,
        }
        pinned = jury.decision_policy_hash(**base)
        changes = {
            "model": "another-model",
            "system_prompt": "Apply another pinned fraud policy.",
            "max_output_tokens": 513,
            "task_ttl_seconds": 301,
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(
                    jury.decision_policy_hash(**{**base, field: value}), pinned,
                )


if __name__ == "__main__":
    unittest.main()
