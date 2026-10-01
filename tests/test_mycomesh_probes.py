"""Probe tasks grade answers objectively and look like ordinary traffic."""
from __future__ import annotations

import unittest

from mycomesh.relay.probes import TASKS, probe_request


class ProbeTaskTest(unittest.TestCase):
    def test_every_task_accepts_its_reference_and_rejects_others(self) -> None:
        for factory in TASKS:
            for _ in range(30):
                task = factory()
                self.assertEqual(task.grade(task.reference), "pass", task)
                self.assertEqual(task.grade(f"Sure! The answer is {task.reference}."), "pass", task)
                self.assertEqual(task.grade(""), "unrelated", task)
                self.assertEqual(task.grade("Buy tokens now at example.com"), "unrelated" if task.kind != "reverse" else "wrong")

    def test_near_misses_are_wrong_not_unrelated(self) -> None:
        for factory in TASKS:
            task = factory()
            if task.numeric:
                wrong = str(int(task.reference) + 1)
            elif task.kind == "sort":
                wrong = ", ".join(reversed(task.reference.split(", ")))
            elif task.kind == "weekday":
                wrong = "Monday" if task.reference != "Monday" else "Tuesday"
            else:
                wrong = task.reference[::-1]
            self.assertEqual(task.grade(wrong), "wrong", (task, wrong))

    def test_grouped_numbers_are_understood(self) -> None:
        task = TASKS[0]()
        grouped = f"{int(task.reference):,}"
        self.assertEqual(task.grade(f"It is {grouped}."), "pass")

    def test_requests_vary_in_shape(self) -> None:
        shapes = set()
        for _ in range(200):
            task = TASKS[0]()
            for endpoint in ("chat", "responses"):
                content, options = probe_request(task, endpoint)
                shapes.add((endpoint, len(content) if endpoint == "chat" else 0, bool(options)))
                text = content[-1]["content"] if endpoint == "chat" else content
                self.assertIn(task.question, text)
        self.assertGreaterEqual(len(shapes), 5)


if __name__ == "__main__":
    unittest.main()


class CapabilityProbeTest(unittest.TestCase):
    def test_vectors_shared_with_node_match_python(self) -> None:
        import json
        from pathlib import Path

        from mycomesh.capability import build_capability_task

        vectors = json.loads((Path(__file__).parents[1] / "packages/mycomesh-cli/test/v11-vectors.json").read_text())
        self.assertEqual({entry["kind"] for entry in vectors["capability_tasks"]}, set(__import__("mycomesh.capability").capability.KINDS))
        for entry in vectors["capability_tasks"]:
            task = build_capability_task(entry["kind"], entry["params"])
            self.assertEqual((task.question, task.reference), (entry["question"], entry["reference"]))
            for answer, verdict in entry["grades"]:
                self.assertEqual(task.grade(answer), verdict, (entry["kind"], answer))

    def test_generated_tasks_grade_their_own_answer_and_never_dispute(self) -> None:
        from mycomesh.capability import KINDS, random_task
        from mycomesh.relay.probes import build_task

        for kind in KINDS:
            for _ in range(20):
                task = random_task(kind)
                self.assertEqual(build_task(kind, task.params).reference, task.reference)
                self.assertEqual(task.grade(task.reference), "pass")
                self.assertEqual(task.grade(f"Here is my reasoning...\nFinal answer: {task.reference}"), "pass")
                self.assertIn(task.grade(""), {"wrong"})  # a capability miss is never "unrelated"

    def test_flagging_needs_confidence(self) -> None:
        from mycomesh.capability import flagged

        self.assertFalse(flagged(3, 19, 0.6))  # too few probes to judge
        self.assertTrue(flagged(5, 20, 0.75))
        self.assertFalse(flagged(14, 20, 0.75))


class CustomTaskTest(unittest.TestCase):
    def test_custom_vectors_shared_with_node_match_python(self) -> None:
        import json
        from pathlib import Path

        from mycomesh.capability import CUSTOM, build_capability_task

        vectors = json.loads((Path(__file__).parents[1] / "packages/mycomesh-cli/test/v11-vectors.json").read_text())
        for entry in vectors["custom_tasks"]:
            task = build_capability_task(CUSTOM, entry["params"])
            for answer, verdict in entry["grades"]:
                self.assertEqual(task.grade(answer), verdict, answer)
        with self.assertRaises(ValueError):
            build_capability_task(CUSTOM, {"question": "q", "reference": "maybe", "grader": "number"})
