"""RAIDER regression for the Cloudflare Python Worker dependency incident."""
import json
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class WorkerPackagingTests(unittest.TestCase):
    def test_fastapi_is_a_required_pyodide_dependency(self):
        with (ROOT / "pyproject.toml").open("rb") as file:
            project = tomllib.load(file)
        # Pywrangler's Pyodide package lock is generated from required project
        # dependencies, not solely uv's optional --extra installation.
        dependencies = project["project"].get("dependencies", [])
        self.assertTrue(any(dep.lower().startswith("fastapi") for dep in dependencies))
        self.assertTrue(any(dep.lower().startswith("pyjwt") for dep in dependencies))
        # Require an explicit reviewed crypto dependency until a vetted native
        # WebCrypto verifier replaces it. The Worker smoke checks *actual*
        # Pyodide compatibility and the dependency CI rejects vulnerable pins;
        # never permanently bake a known-vulnerable version into a test.
        self.assertTrue(any(dep.lower().startswith("cryptography==") for dep in dependencies))

        worker_tools = project.get("dependency-groups", {}).get("worker", [])
        self.assertTrue(any(item.startswith("workers-py") for item in worker_tools))
        self.assertTrue(any(item.startswith("workers-runtime-sdk") for item in worker_tools))

    def test_local_d1_config_cannot_reference_a_real_database(self):
        data = json.loads((ROOT / "wrangler.jsonc").read_text(encoding="utf-8"))
        self.assertIn("python_workers", data["compatibility_flags"])
        self.assertEqual(data["main"], "src/worker.py")
        self.assertEqual(data["d1_databases"][0]["binding"], "DB")
        self.assertEqual(
            data["d1_databases"][0]["database_id"],
            "00000000-0000-0000-0000-000000000000",
        )
        self.assertNotIn("vars", data)

    def test_workflow_has_no_deployment_command_or_cloud_token(self):
        workflow = (ROOT / ".github/workflows/gateway-smoke-ci.yml").read_text(encoding="utf-8")
        self.assertIn("pywrangler dev", workflow)
        self.assertNotIn("pywrangler deploy", workflow)
        self.assertNotIn("wrangler d1 create", workflow)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
