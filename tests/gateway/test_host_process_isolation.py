"""Separate CPython *processes*, genuine mTLS and file-backed replay proofs.

No remote D1, external network, actual provider or blockchain transaction.
Signed token is delivered to child sender only over stdin, never argv/env.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import sqlite3
import subprocess
import sys
import threading
import unittest

from cryptography.hazmat.primitives import serialization

import test_host_mtls_handoff as mtls_fixture
from test_host_signed_handoff import NOW

ROOT = Path(__file__).resolve().parents[2]
ROLE_SCRIPT = ROOT / "scripts" / "local_handoff_process.py"


class ProcessIsolationHandoffTests(unittest.TestCase):
    def setUp(self):
        # Reuse the genuine prior signed decision, audited source issuance
        # and ephemeral CA/certificate fixtures; no second policy engine.
        self.fixture = mtls_fixture.LocalMTLSHandoffTests(
            "test_authenticated_loopback_delivery_burns_once_after_source_audit"
        )
        self.fixture.setUp()
        self.temp = self.fixture.folder
        self.replay_path = self.temp / "durable-host-replay.sqlite"
        self.server_ca = self.temp / "server-ca.pem"
        self.client_ca = self.temp / "client-ca.pem"
        self.public_key = self.temp / "trusted-issuer.pem"
        self.server_ca.write_text(self.fixture.server_ca_pem, encoding="ascii")
        self.client_ca.write_text(self.fixture.client_ca_pem, encoding="ascii")
        self.public_key.write_bytes(self.fixture.source.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        self.env = os.environ.copy()
        self.env["AGENTSHIELD_LOCAL_HANDOFF_TEST_ONLY"] = "1"
        self.env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + self.env.get("PYTHONPATH", "")

    def tearDown(self):
        self.fixture.tearDown()

    @staticmethod
    def _read_ready(process):
        ready = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: ready.put(process.stdout.readline()),
                         daemon=True).start()
        try:
            line = ready.get(timeout=6)
        except queue.Empty:
            raise AssertionError("Isolated receiver did not become ready") from None
        response = json.loads(line)
        if response.get("ready") is not True:
            raise AssertionError("Receiver rejected before local binding")
        return response

    def exchange(self, *, token=None, client_cert=None, client_key=None,
                 server_ca=None, client_pin=None, tenant="ci_local",
                 now_ms=NOW + 5, replay_path=None):
        receive = [
            sys.executable, str(ROLE_SCRIPT), "receive",
            "--server-cert", str(self.fixture.server_cert),
            "--server-key", str(self.fixture.server_key),
            "--client-ca", str(self.client_ca),
            "--client-cert-sha256", client_pin or self.fixture.client_pin,
            "--issuer-public-key", str(self.public_key),
            "--replay-db", str(replay_path or self.replay_path),
            "--tenant", tenant, "--command-id", self.fixture.command,
            "--fixture-now-ms", str(now_ms),
        ]
        process = subprocess.Popen(
            receive, cwd=ROOT, env=self.env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            ready = self._read_ready(process)
            self.assertEqual(ready["local_only"], True)
            self.assertEqual(ready["execution_authorized"], False)
            sender = subprocess.run(
                [
                    sys.executable, str(ROLE_SCRIPT), "send",
                    "--port", str(ready["port"]),
                    "--client-cert", str(client_cert or self.fixture.client_cert),
                    "--client-key", str(client_key or self.fixture.client_key),
                    "--server-ca", str(server_ca or self.server_ca),
                ],
                input=self.fixture.token if token is None else token,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, cwd=ROOT, env=self.env, timeout=6,
                check=False,
            )
            after_ready, server_errors = process.communicate(timeout=6)
            # No token should ever appear in the process command line or logs.
            self.assertNotIn(self.fixture.token, repr(receive))
            self.assertNotIn(self.fixture.token, sender.stdout + sender.stderr)
            self.assertNotIn(self.fixture.token, after_ready + server_errors)
            result_line = after_ready.strip()
            result = json.loads(result_line) if result_line else {}
            sender_result = json.loads(sender.stdout.strip())
            return {
                "ready": ready, "sender": sender_result, "receiver": result,
                "client_status": sender.returncode, "server_status": process.returncode,
                "client_pid": sender_result.get("pid"), "server_pid": ready["pid"],
                "client_stderr": sender.stderr, "server_stderr": server_errors,
            }
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def burns(self):
        if not self.replay_path.exists():
            return 0
        with sqlite3.connect(self.replay_path) as db:
            return db.execute("SELECT COUNT(*) FROM used_local_handoffs").fetchone()[0]

    def test_distinct_operating_system_processes_authenticate_and_burn_once(self):
        result = self.exchange()
        self.assertEqual((result["client_status"], result["server_status"]), (0, 0))
        self.assertTrue(result["sender"]["acknowledged"])
        self.assertTrue(result["receiver"]["accepted"])
        self.assertNotEqual(result["client_pid"], result["server_pid"])
        self.assertNotIn(os.getpid(), (result["client_pid"], result["server_pid"]))
        self.assertFalse(result["receiver"]["execution_authorized"])
        self.assertFalse(result["sender"]["external_network_used"])
        self.assertEqual(self.burns(), 1)
        self.assertEqual(self.fixture.source.adapter.calls, ["mock_invoice_read"])
        self.assertEqual(self.fixture.source.db.execute(
            "SELECT count(*) FROM local_handoff_issuances"
        ).fetchone()[0], 1)

    def test_restart_independent_server_preserves_replay_denial(self):
        self.assertEqual(self.exchange()["server_status"], 0)
        refused = self.exchange()
        self.assertEqual(refused["client_status"], 2)
        self.assertEqual(refused["server_status"], 2)
        self.assertTrue(refused["receiver"]["rejected"])
        self.assertTrue(refused["sender"]["no_execution"])
        self.assertEqual(self.burns(), 1)
        self.assertEqual(self.fixture.source.adapter.calls, ["mock_invoice_read"])

    def test_different_ca_trusted_client_is_rejected_by_exact_service_pin(self):
        result = self.exchange(client_cert=self.fixture.other_cert,
                               client_key=self.fixture.other_key)
        self.assertEqual(result["server_status"], 2)
        self.assertEqual(result["client_status"], 2)
        self.assertEqual(self.burns(), 0)

    def test_server_trust_mismatch_or_altered_signed_token_refused(self):
        wrong_ca = self.exchange(server_ca=self.client_ca)
        self.assertEqual((wrong_ca["server_status"], wrong_ca["client_status"]), (2, 2))
        self.assertEqual(self.burns(), 0)
        token = self.fixture.token
        forged = ("A" if token[0] != "A" else "B") + token[1:]
        bad_proof = self.exchange(token=forged)
        self.assertEqual((bad_proof["server_status"], bad_proof["client_status"]), (2, 2))
        self.assertEqual(self.burns(), 0)

    def test_expired_token_and_cross_tenant_never_burn(self):
        expired = self.exchange(now_ms=NOW + 3 + 30_000)
        self.assertEqual((expired["server_status"], expired["client_status"]), (2, 2))
        other = self.exchange(tenant="different_tenant")
        self.assertEqual((other["server_status"], other["client_status"]), (2, 2))
        self.assertEqual(self.burns(), 0)

    def test_no_opt_in_refuses_both_process_roles(self):
        env = self.env.copy()
        env.pop("AGENTSHIELD_LOCAL_HANDOFF_TEST_ONLY", None)
        for role in ("send", "receive"):
            command = [sys.executable, str(ROLE_SCRIPT), role]
            p = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                               text=True, timeout=3, check=False)
            self.assertEqual(p.returncode, 2)
            self.assertTrue(json.loads(p.stdout)["no_execution"])
            self.assertNotIn(self.fixture.token, p.stdout + p.stderr)

    def test_unavailable_host_database_refuses_before_accept(self):
        args = [
            sys.executable, str(ROLE_SCRIPT), "receive",
            "--server-cert", str(self.fixture.server_cert),
            "--server-key", str(self.fixture.server_key),
            "--client-ca", str(self.client_ca),
            "--client-cert-sha256", self.fixture.client_pin,
            "--issuer-public-key", str(self.public_key),
            "--replay-db", str(self.temp / "nonexistent" / "host.sqlite"),
            "--tenant", "ci_local", "--command-id", self.fixture.command,
            "--fixture-now-ms", str(NOW + 5),
        ]
        p = subprocess.run(args, cwd=ROOT, env=self.env,
                           capture_output=True, text=True, timeout=4, check=False)
        self.assertEqual(p.returncode, 2)
        self.assertTrue(json.loads(p.stdout)["no_execution"])
        self.assertNotIn(self.fixture.token, p.stdout + p.stderr)
        self.assertEqual(self.burns(), 0)


if __name__ == "__main__":
    unittest.main()
