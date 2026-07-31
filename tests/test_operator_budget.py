import tempfile
import unittest
from pathlib import Path

from gateway.operator_budget import OperatorBudget


class OperatorBudgetTest(unittest.TestCase):
    def test_reservation_and_settlement_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.json"
            budget = OperatorBudget(limit_units=100, period_seconds=3600, state_path=path)
            self.assertTrue(budget.reserve(80))
            self.assertFalse(budget.reserve(21))
            self.assertTrue(budget.settle(80, 60))
            reloaded = OperatorBudget(limit_units=100, period_seconds=3600, state_path=path)
            self.assertEqual(reloaded.snapshot()["spent_units"], 60)
            self.assertTrue(reloaded.reserve(40))
            self.assertFalse(reloaded.reserve(1))

    def test_zero_limit_is_unlimited_without_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            budget = OperatorBudget(
                limit_units=0,
                period_seconds=3600,
                state_path=Path(directory) / "usage.json",
            )
            self.assertTrue(budget.reserve(10**12))
            self.assertTrue(budget.settle(10**12, 10**12))
            self.assertFalse((Path(directory) / "usage.json").exists())


if __name__ == "__main__":
    unittest.main()
