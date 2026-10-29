"""REAL loopback-only TCP/TLS tests for the host proxy candidate.

The server listens solely on 127.0.0.1:ephemeral; no outside network, DNS,
Worker binding or provider API is accessed. All CA/leaf keys are generated
ephemerally at test runtime and are never committed or distributed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from agentshield.demo_invoice import INVOICE, demo_rule_records
from agentshield.egress_policy import EgressRejected
from agentshield.host_loopback_tls import probe_local_tls_fixture
from agentshield.policy import PolicyEngine, Principal, ToolAction

HOST = "api.invoices.example"
BODY = b'{"invoice":"fixture-42"}'


def _response(
    body: bytes = BODY, *, status: str = "200 OK",
    headers: bytes = b"", length: int | None = None,
) -> bytes:
    if length is None:
        length = len(body)
    return (
        f"HTTP/1.1 {status}\r\nContent-Length: {length}\r\n".encode("ascii")
        + headers + b"Connection: close\r\n\r\n" + body
    )


class _LocalTLSServer:
    def __init__(self, cert: Path, key: Path, response: bytes,
                 *, delay: float = 0.0):
        self.response = response
        self.delay = delay
        self.seen_request = b""
        self.sni = ""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(4)
        self.port = self.server.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(str(cert), str(key))
        self.context.set_servername_callback(
            lambda _sock, name, _ctx: setattr(self, "sni", name or "")
        )
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        try:
            with self.server:
                conn, _ = self.server.accept()
                with conn:
                    with self.context.wrap_socket(conn, server_side=True) as tls:
                        tls.settimeout(3)
                        while b"\r\n\r\n" not in self.seen_request:
                            part = tls.recv(4096)
                            if not part:
                                return
                            self.seen_request += part
                            if len(self.seen_request) > 8192:
                                return
                        if self.delay:
                            time.sleep(self.delay)
                        tls.sendall(self.response)
        except (OSError, ssl.SSLError):
            # Deliberate failed client authentication/timeout should not
            # produce an unhandled background-thread exception.
            pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.close()
        self.thread.join(timeout=5)


class LoopbackTLSProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="agentshield-tls-test-")
        now = dt.datetime.now(dt.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AgentShield ephemeral test CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        cls.ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        alien_key = ec.generate_private_key(ec.SECP256R1())
        alien_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted test CA")])
        alien_cert = (
            x509.CertificateBuilder()
            .subject_name(alien_name).issuer_name(alien_name)
            .public_key(alien_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(alien_key, hashes.SHA256())
        )
        cls.other_ca_pem = alien_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        cls.good = cls._leaf(ca_name, ca_key, now, HOST, "good")
        cls.wrong = cls._leaf(ca_name, ca_key, now, "other.invoices.example", "wrong")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def _leaf(cls, issuer, issuer_key, now, hostname, name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(issuer_key, hashes.SHA256())
        )
        folder = Path(cls.temp.name)
        cert_path, key_path = folder / (name + ".crt"), folder / (name + ".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        return cert_path, key_path

    def setUp(self):
        self.actor = Principal("ci_local:local-demo-agent", frozenset({"invoice:read"}))
        self.engine = PolicyEngine(demo_rule_records(self.actor))

    def probe(self, port, *, actor=None, action=None, ca=None, ip="127.0.0.1"):
        return probe_local_tls_fixture(
            actor or self.actor, action or INVOICE, self.engine,
            selected_ip=ip, test_port=port,
            trusted_test_ca_pem=ca if ca is not None else self.ca_pem,
        )

    def test_real_tls_pins_tcp_peer_and_authenticates_original_hostname(self):
        with _LocalTLSServer(*self.good, _response()) as server:
            receipt = self.probe(server.port)
        self.assertEqual(receipt.peer_ip, "127.0.0.1")
        self.assertEqual(receipt.tls_version, "TLSv1.3")
        self.assertEqual(receipt.status, 200)
        self.assertEqual(receipt.body_bytes, len(BODY))
        self.assertEqual(receipt.body_sha256, hashlib.sha256(BODY).hexdigest())
        self.assertTrue(receipt.network_used)
        self.assertFalse(receipt.external_network_used)
        self.assertFalse(receipt.execution_authorized)
        self.assertFalse(receipt.production_ready)
        self.assertEqual(server.sni, HOST)
        self.assertTrue(server.seen_request.startswith(b"GET /v1/invoices/42 HTTP/1.1\r\n"))
        self.assertIn(b"Host: api.invoices.example\r\n", server.seen_request)
        self.assertNotIn(b"Authorization:", server.seen_request)

    def test_wrong_server_certificate_hostname_rejected(self):
        with _LocalTLSServer(*self.wrong, _response()) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)
        self.assertEqual(server.sni, HOST)

    def test_untrusted_ca_rejected_even_with_matching_hostname(self):
        with _LocalTLSServer(*self.good, _response()) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port, ca=self.other_ca_pem)

    def test_missing_invoice_scope_and_changed_action_refused_before_connection(self):
        actor = Principal(self.actor.id, frozenset())
        with self.assertRaises(EgressRejected):
            self.probe(1234, actor=actor)
        with self.assertRaises(EgressRejected):
            self.probe(1234, action=ToolAction("suppliers", "update_bank_account", "supplier/482"))

    def test_any_non_loopback_destination_refused_without_connect(self):
        for ip in ("8.8.8.8", "169.254.169.254", "127.0.0.2", "::1", "localhost", ""):
            with self.subTest(ip=ip), self.assertRaises(EgressRejected):
                self.probe(443, ip=ip)

    def test_redirect_cannot_be_followed(self):
        response = _response(b"", status="302 Found", headers=b"Location: http://169.254.169.254/\r\n")
        with _LocalTLSServer(*self.good, response) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)
        self.assertEqual(server.seen_request.count(b"GET "), 1)

    def test_oversized_body_refused_before_download(self):
        with _LocalTLSServer(*self.good, _response(b"", length=16_385)) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_transfer_encoding_chunked_not_allowed(self):
        with _LocalTLSServer(*self.good, _response(b"chunk", headers=b"Transfer-Encoding: chunked\r\n")) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_duplicate_content_length_is_denied(self):
        with _LocalTLSServer(*self.good, _response(BODY, headers=b"Content-Length: 24\r\n")) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_truncated_response_fails_closed(self):
        with _LocalTLSServer(*self.good, _response(b"hi", length=20)) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_excessive_headers_rejected(self):
        with _LocalTLSServer(*self.good, _response(b"", headers=b"X-Pad: " + b"A" * 9000 + b"\r\n")) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_deadline_is_end_to_end_not_each_recv(self):
        with _LocalTLSServer(*self.good, _response(), delay=2.1) as server:
            with self.assertRaises(EgressRejected):
                self.probe(server.port)

    def test_test_ca_and_port_boundaries(self):
        for port in (0, -1, 65536, True):
            with self.subTest(port=port), self.assertRaises(EgressRejected):
                self.probe(port)


if __name__ == "__main__":
    unittest.main()
