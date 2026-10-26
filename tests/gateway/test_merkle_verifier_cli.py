"""Exercise the public offline verifier as a separate process (no trust in DB state)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from agentshield.audit import AuditEvent, action_digest
from agentshield.merkle import build_manifest, inclusion_path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify_merkle.py"
T = 1_790_000_010_000


def specimen(n):
    return AuditEvent(
        event_id=f"fixture-cli-event-{n:03d}",
        tenant_id="sample_tenant", principal_id="sample_tenant:agent-01",
        action_digest=action_digest("invoices", "read", f"invoice/{n}"),
        effect="deny", reason_codes=("REQUIRED_SCOPE_MISSING",),
        policy_version="fixture-policy-v1", occurred_at_ms=T + n,
        retention_until_ms=T + n + 30 * 86_400_000,
    )


class IndependentVerifierTests(unittest.TestCase):
    def test_cli_verifies_complete_batch_and_inclusion_but_never_claims_onchain(self):
        events = [specimen(i) for i in range(3)]
        manifest = build_manifest(
            events, tenant_id="sample_tenant", batch_id="fixture-batch-001",
            created_at_ms=T + 10,
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            for filename, data in {
                "manifest.json": manifest,
                "events.json": [asdict(e) for e in events],
                "one.json": [asdict(events[1])],
                "proof.json": inclusion_path(manifest, events[1].event_id),
            }.items():
                (temp / filename).write_text(json.dumps(data), encoding="utf-8")
            def run(*args):
                return subprocess.run(
                    [sys.executable, str(SCRIPT), *args],
                    cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                    capture_output=True, text=True, check=False,
                )
            complete = [
                "batch", "--manifest", str(temp / "manifest.json"),
                "--events", str(temp / "events.json"),
                "--trusted-commitment", manifest["commitment"],
            ]
            good = run(*complete)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertFalse(json.loads(good.stdout)["onchain_finality_verified"])
            member = run(
                "inclusion", "--manifest", str(temp / "manifest.json"),
                "--event", str(temp / "one.json"),
                "--proof", str(temp / "proof.json"),
                "--trusted-commitment", manifest["commitment"],
            )
            self.assertEqual(member.returncode, 0, member.stderr)
            wrong = run(*complete[:-1], "f" * 64)
            self.assertEqual(wrong.returncode, 2)
            (temp / "events.json").write_text(
                json.dumps([asdict(e) for e in events[:-1]]), encoding="utf-8",
            )
            missing = run(*complete)
            self.assertEqual(missing.returncode, 2)
            self.assertNotIn("verified on-chain", good.stdout)


if __name__ == "__main__":
    unittest.main()
