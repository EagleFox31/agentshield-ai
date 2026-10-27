"""Fail-closed and arithmetic sanity checks for the synthetic offline benchmark."""
import asyncio
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from triage_benchmark import evaluate

class BenchmarkTests(unittest.TestCase):
    def test_heldout_counts_and_policy_invariance(self):
        result = asyncio.run(evaluate())
        self.assertEqual(result["cases"], 9)
        self.assertEqual(sum(result["counts"].values()), 9)
        self.assertFalse(result["model_evaluated"])
        self.assertTrue(all(row["model_status"] == "not_configured" for row in result["rows"]))
        self.assertTrue(all(not row["policy_effect"] == "allow" for row in result["rows"] if row["label"] == "attack"))
        self.assertIsNotNone(result["precision"])
        self.assertIsNotNone(result["recall"])

    def test_other_splits(self):
        for split in ("train", "dev"):
            self.assertGreater(asyncio.run(evaluate(split=split))["cases"], 0)

if __name__ == "__main__":
    unittest.main()
