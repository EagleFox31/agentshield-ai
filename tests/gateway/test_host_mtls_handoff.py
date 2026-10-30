"""Real local TCP/TLS 1.3 *mutual* service identity and signed handoff tests.

Ephemeral test-only keys/certificates, source D1-compatible SQLite ledger,
independent consumer SQLite replay ledger, 127.0.0.1 only. No provider I/O.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import socket
import sqlite3
import ssl
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import test_host_signed_handoff as signed_fixture
from agentshield.host_mtls_handoff import (
    deliver_local_mtls_handoff, receive_one_local_mtls_handoff,
)
from agentshield.host_signed_handoff import HandoffRejected, init_host_replay_db

HOST = "handoff.agentshield.test"


class LocalMTLSHandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentshield-mtls-")
        self.folder = Path(self.temp.name)
        self.source = signed_fixture.SignedHandoffTests("test_existing_d1_audit_proves_host_signed_one_use_handoff")
        self.source.setUp()
        self.command = self.source.prepare()
        self.token = self.source.issue(self.command)
        self.host_db = sqlite3.connect(":memory:", check_same_thread=False, isolation_level=None)
        init_host_replay_db(self.host_db)
        self.issuer_ca_key, self.issuer_ca_cert = self.make_ca("issuer-client-test-ca")
        self.server_ca_key, self.server_ca_cert = self.make_ca("isolated-server-test-ca")
        self.server_cert, self.server_key, self.server_der = self.make_leaf(
            self.server_ca_key, self.server_ca_cert, HOST, "server", server=True,
        )
        self.client_cert, self.client_key, self.client_der = self.make_leaf(
            self.issuer_ca_key, self.issuer_ca_cert, "test-issuer", "client",
            server=False,
        )
        self.other_cert, self.other_key, self.other_der = self.make_leaf(
            self.issuer_ca_key, self.issuer_ca_cert, "other-test-client", "other",
            server=False,
        )
        self.server_ca_pem = self.server_ca_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii")
        self.client_ca_pem = self.issuer_ca_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode("ascii")
        self.client_pin = hashlib.sha256(self.client_der).hexdigest()

    def tearDown(self):
        self.host_db.close()
        self.source.tearDown()
        self.temp.cleanup()

    @staticmethod
    def make_ca(name):
        now = dt.datetime.now(dt.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    def make_leaf(self, ca_key, ca_cert, name, prefix, *, server):
        now = dt.datetime.now(dt.timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1))
                .not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
                ]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        certificate = self.folder / (prefix + ".pem")
        private_key = self.folder / (prefix + ".key")
        der = cert.public_bytes(serialization.Encoding.DER)
        certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        private_key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        private_key.chmod(0o600)
        return certificate, private_key, der

    def listen(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        return listener

    def exchange(self, *, token=None, cert=None, key=None, server_ca=None,
                 client_pin=None, expected_tenant="ci_local", command=None):
        received = []
        failures = []
        with self.listen() as listener:
            port = listener.getsockname()[1]

            def serve():
                try:
                    received.append(receive_one_local_mtls_handoff(
                        listener, server_cert=self.server_cert,
                        server_key=self.server_key,
                        trusted_client_ca_pem=self.client_ca_pem,
                        pinned_client_cert_sha256=client_pin or self.client_pin,
                        replay_db=self.host_db,
                        trusted_issuer_public_key=self.source.key.public_key(),
                        now_ms=signed_fixture.NOW + 5,
                        expected_tenant=expected_tenant,
                        expected_command_id=command or self.command,
                    ))
                except HandoffRejected as exc:
                    failures.append(exc)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                delivery = deliver_local_mtls_handoff(
                    token if token is not None else self.token, test_port=port,
                    trusted_server_ca_pem=server_ca or self.server_ca_pem,
                    client_cert=cert or self.client_cert,
                    client_key=key or self.client_key,
                )
            except HandoffRejected as exc:
                delivery = exc
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive(), "Local TLS server did not terminate")
        return delivery, received, failures

    def count_burns(self):
        return self.host_db.execute("SELECT COUNT(*) FROM used_local_handoffs").fetchone()[0]

    def test_authenticated_loopback_delivery_burns_once_after_source_audit(self):
        delivery, received, failures = self.exchange()
        self.assertFalse(failures)
        self.assertTrue(delivery.acknowledged)
        self.assertTrue(delivery.network_used)
        self.assertFalse(delivery.external_network_used)
        self.assertFalse(delivery.execution_authorized)
        self.assertFalse(delivery.production_ready)
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].command_id, self.command)
        self.assertFalse(received[0].execution_authorized)
        self.assertEqual(self.count_burns(), 1)
        self.assertEqual(self.source.db.execute(
            "SELECT count(*) FROM local_handoff_issuances"
        ).fetchone()[0], 1)
        self.assertEqual(self.source.adapter.calls, ["mock_invoice_read"])

    def test_second_transport_attempt_is_rejected_by_durable_host_ledger(self):
        self.assertTrue(self.exchange()[0].acknowledged)
        delivery, received, failures = self.exchange()
        self.assertIsInstance(delivery, HandoffRejected)
        self.assertEqual(received, [])
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.count_burns(), 1)
        self.assertEqual(self.source.adapter.calls, ["mock_invoice_read"])

    def test_other_trusted_ca_client_is_rejected_by_separate_certificate_pin(self):
        delivery, received, failures = self.exchange(cert=self.other_cert, key=self.other_key)
        self.assertIsInstance(delivery, HandoffRejected)
        self.assertEqual(received, [])
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.count_burns(), 0)

    def test_missing_client_certificate_pin_refuses_before_token_burn(self):
        delivery, received, failures = self.exchange(client_pin="0" * 64)
        self.assertIsInstance(delivery, HandoffRejected)
        self.assertEqual(received, [])
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.count_burns(), 0)

    def test_wrong_server_root_refused(self):
        delivery, received, failures = self.exchange(server_ca=self.client_ca_pem)
        self.assertIsInstance(delivery, HandoffRejected)
        self.assertEqual(received, [])
        self.assertEqual(self.count_burns(), 0)

    def test_signed_token_tamper_and_cross_tenant_refused(self):
        changed = self.token[:-1] + ("A" if self.token[-1] != "A" else "B")
        for opts in ({"token": changed}, {"expected_tenant": "other_tenant"}):
            with self.subTest(opts=opts):
                delivery, received, failures = self.exchange(**opts)
                self.assertIsInstance(delivery, HandoffRejected)
                self.assertEqual(received, [])
                self.assertEqual(len(failures), 1)
                self.assertEqual(self.count_burns(), 0)

    def test_nonloopback_listener_cannot_be_served(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("0.0.0.0", 0))
            listener.listen(1)
            with self.assertRaises(HandoffRejected):
                receive_one_local_mtls_handoff(
                    listener, server_cert=self.server_cert, server_key=self.server_key,
                    trusted_client_ca_pem=self.client_ca_pem,
                    pinned_client_cert_sha256=self.client_pin,
                    replay_db=self.host_db,
                    trusted_issuer_public_key=self.source.key.public_key(),
                    now_ms=signed_fixture.NOW + 5,
                    expected_tenant="ci_local", expected_command_id=self.command,
                )
        finally:
            listener.close()

    def test_invalid_port_rejected_before_connect(self):
        for port in (0, True, -1, 65536):
            with self.subTest(port=port), self.assertRaises(HandoffRejected):
                deliver_local_mtls_handoff(
                    self.token, test_port=port,
                    trusted_server_ca_pem=self.server_ca_pem,
                    client_cert=self.client_cert, client_key=self.client_key,
                )

    def test_oversize_frame_refused_before_burn(self):
        failures = []
        with self.listen() as listener:
            port = listener.getsockname()[1]

            def serve():
                try:
                    receive_one_local_mtls_handoff(
                        listener, server_cert=self.server_cert, server_key=self.server_key,
                        trusted_client_ca_pem=self.client_ca_pem,
                        pinned_client_cert_sha256=self.client_pin, replay_db=self.host_db,
                        trusted_issuer_public_key=self.source.key.public_key(),
                        now_ms=signed_fixture.NOW + 5,
                        expected_tenant="ci_local", expected_command_id=self.command,
                    )
                except HandoffRejected as exc:
                    failures.append(exc)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(cadata=self.server_ca_pem)
            ctx.load_cert_chain(str(self.client_cert), str(self.client_key))
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
                with ctx.wrap_socket(raw, server_hostname=HOST) as tls:
                    tls.sendall(struct.pack("!I", 9999))
            thread.join(timeout=4)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.count_burns(), 0)


if __name__ == "__main__":
    unittest.main()
