"""A Provider serves only models in the network's catalog, in its tier, that its backend offers."""
from __future__ import annotations

import unittest

from mycomesh.__main__ import serving_models

CATALOG = {"gpt-6.1-sol": 1, "gpt-6-sol": 1, "gpt-5.5": 1, "gpt-6-luna": 3, "claude-haiku-4-5": 5}


class Backend:
    def __init__(self, offered):
        self.offered = offered

    def available_models(self):
        return self.offered


class ServingModelsTest(unittest.TestCase):
    def test_every_model_of_the_tier_the_backend_offers(self) -> None:
        # A ChatGPT account through codex-cli 0.162: GPT-6 yes, gpt-5.5 no longer.
        offered = {"gpt-6.1-sol", "gpt-6-sol", "gpt-6-luna", "gpt-5.6-sol"}
        self.assertEqual(serving_models([], 1, CATALOG, Backend(offered)), ["gpt-6.1-sol", "gpt-6-sol"])

    def test_named_models_outside_the_tier_or_not_offered_are_dropped(self) -> None:
        self.assertEqual(serving_models(["gpt-6-sol", "gpt-6-luna", "gpt-5.5"], 1, CATALOG, Backend({"gpt-6-sol", "gpt-6-luna"})), ["gpt-6-sol"])

    def test_dated_ids_count_and_unknown_backends_are_trusted(self) -> None:
        self.assertEqual(serving_models([], 5, CATALOG, Backend({"claude-haiku-4-5-20251001"})), ["claude-haiku-4-5"])
        self.assertEqual(serving_models(["gpt-6-sol"], 1, CATALOG, object()), ["gpt-6-sol"])  # e.g. an exec plugin

    def test_nothing_to_serve_refuses_to_start(self) -> None:
        with self.assertRaises(SystemExit) as refused:
            serving_models([], 1, CATALOG, Backend({"gpt-5.6-sol"}))
        self.assertIn("no model to serve in tier 1", str(refused.exception))


if __name__ == "__main__":
    unittest.main()
