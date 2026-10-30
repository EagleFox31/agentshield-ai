"""ONE-SHOT host-only mTLS test roles in independent OS processes.

EXPERIMENTAL LOCAL TEST HARNESS, not a production service. No public route,
external provider, Cloudflare/D1 connection, arbitrary URL or EVM side effect.
The caller must opt in with AGENTSHIELD_LOCAL_HANDOFF_TEST_ONLY=1. Signed
tokens arrive on STDIN only, never as argv, environment or file content.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentshield.host_mtls_handoff import (
    deliver_local_mtls_handoff, receive_one_local_mtls_handoff,
)
from agentshield.host_signed_handoff import init_host_replay_db

_LOOPBACK = "127.0.0.1"
_OPT_IN = "AGENTSHIELD_LOCAL_HANDOFF_TEST_ONLY"


def _paths(parser: argparse.ArgumentParser, *names: str) -> None:
    for name in names:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local-only test mTLS handoff")
    roles = parser.add_subparsers(dest="role", required=True)
    receive = roles.add_parser("receive", help="One loopback connection, then exit")
    _paths(receive, "server_cert", "server_key", "client_ca",
           "issuer_public_key", "replay_db")
    receive.add_argument("--client-cert-sha256", required=True)
    receive.add_argument("--tenant", required=True)
    receive.add_argument("--command-id", required=True)
    # Synthetic signed fixture timestamps MUST NOT be mistaken for live clock.
    receive.add_argument("--fixture-now-ms", type=int, required=True)
    send = roles.add_parser("send", help="Read token from stdin; never from argv")
    _paths(send, "client_cert", "client_key", "server_ca")
    send.add_argument("--port", type=int, required=True)
    return parser.parse_args()


def _emit(**details: object) -> None:
    print(json.dumps(details, sort_keys=True, separators=(",", ":")), flush=True)


def _receive(args: argparse.Namespace) -> None:
    pubkey = serialization.load_pem_public_key(args.issuer_public_key.read_bytes())
    if not isinstance(pubkey, ec.EllipticCurvePublicKey):
        raise ValueError("Unexpected public key family")
    with sqlite3.connect(str(args.replay_db), timeout=1.0, isolation_level=None) as db:
        # SQLite's full sync is required for the local crash/restart regression.
        db.execute("PRAGMA synchronous=FULL")
        init_host_replay_db(db)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((_LOOPBACK, 0))
            listener.listen(1)
            _emit(ready=True, port=listener.getsockname()[1], pid=os.getpid(),
                  local_only=True, execution_authorized=False)
            receipt = receive_one_local_mtls_handoff(
                listener, server_cert=args.server_cert, server_key=args.server_key,
                trusted_client_ca_pem=args.client_ca.read_text(encoding="ascii"),
                pinned_client_cert_sha256=args.client_cert_sha256,
                replay_db=db, trusted_issuer_public_key=pubkey,
                now_ms=args.fixture_now_ms, expected_tenant=args.tenant,
                expected_command_id=args.command_id,
            )
            _emit(accepted=receipt.token_used, pid=os.getpid(),
                  command_id=receipt.command_id, external_network_used=False,
                  execution_authorized=False, production_ready=False)


def _send(args: argparse.Namespace) -> None:
    raw = sys.stdin.buffer.read(2501)
    # No whitespace normalization: any altered signed proof must be rejected.
    token = raw.decode("ascii")
    receipt = deliver_local_mtls_handoff(
        token, test_port=args.port,
        trusted_server_ca_pem=args.server_ca.read_text(encoding="ascii"),
        client_cert=args.client_cert, client_key=args.client_key,
    )
    _emit(acknowledged=receipt.acknowledged, pid=os.getpid(),
          external_network_used=False, execution_authorized=False,
          production_ready=False)


def main() -> int:
    # Gate BOTH roles, so this module cannot be casually launched as a
    # production-facing service. It never exposes a non-loopback socket.
    if os.environ.get(_OPT_IN) != "1":
        _emit(rejected=True, local_only=True, no_execution=True)
        return 2
    args = _arguments()
    try:
        if args.role == "receive":
            _receive(args)
        else:
            _send(args)
    except Exception:
        # Deliberately redact errors: no raw token, certs or filesystem paths
        # leak into CI logs; fail closed and leave reconciliation to operator.
        _emit(rejected=True, local_only=True, no_execution=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
