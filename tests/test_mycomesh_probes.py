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
