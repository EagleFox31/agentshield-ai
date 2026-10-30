"""Regression gate for reviewed Pyodide Pydantic security patch baseline."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tomllib
import unittest

from scripts.check_worker_provenance import validate

ROOT = Path(__file__).resolve().parents[2]


def read_json(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class WorkerSecurityPatchBaselineTests(unittest.TestCase):
    def setUp(self):
        self.baseline = read_json("docs/WORKER_RUNTIME_BASELINE.json")
        self.wrangler = read_json("wrangler.jsonc")
        self.package = read_json("package.json")
        self.lock = read_json("package-lock.json")
        self.project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.observed = {
            "python_version": "3.14.2",
            "pyodide_version": "314.0.6",
            "packages": {
                "fastapi": "0.139.2", "starlette": "1.3.1",
                "pydantic": "2.14.2", "pydantic_core": "2.50.2",
            },
            "local_only": True,
            "enforcement_ready": False,
            "real_tool_called": False,
        }

    def check(self, observed):
        validate(
            observed, self.baseline, self.wrangler, self.package,
            self.lock, self.project,
        )

    def test_reviewed_security_patch_metadata_matches(self):
        self.assertEqual(self.baseline["packages"], self.observed["packages"])
        self.check(self.observed)

    def test_previous_pydantic_release_fails_closed(self):
        before = copy.deepcopy(self.observed)
        before["packages"]["pydantic"] = "2.14.1"
        before["packages"]["pydantic_core"] = "2.50.1"
        with self.assertRaisesRegex(ValueError, "runtime drift: packages"):
            self.check(before)

    def test_new_unreviewed_patch_fails_closed(self):
        future = copy.deepcopy(self.observed)
        future["packages"]["pydantic"] = "2.14.3"
        with self.assertRaisesRegex(ValueError, "runtime drift: packages"):
            self.check(future)

    def test_no_external_execution_or_production_override(self):
        for key, value in (
            ("local_only", False),
            ("enforcement_ready", True),
            ("real_tool_called", True),
        ):
            forged = copy.deepcopy(self.observed)
            forged[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.check(forged)


if __name__ == "__main__":
    unittest.main()
