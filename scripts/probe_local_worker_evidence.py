"""Read-only local host -> Pywrangler/D1 evidence probe. NOT authority.

Only literal 127.0.0.1, fixed local path, service JWT from stdin, no proxies,
redirects, token logging, persistence, issuance, provider call or dispatch.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import http.client
import json
import re
import sys
import time
import secrets
from pathlib import Path

from agentshield.host_worker_attestation import verify_local_worker_attestation, AttestationRejected

_COMMAND = re.compile(r"local-command-[0-9a-f]{32}\Z")
_TENANT = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
_MAX_RESPONSE = 2048


def local_probe(*, port: int, tenant: str, command: str, bearer: str) -> dict:
    if (type(port) is not int or not 1 <= port <= 65535
        or not isinstance(tenant, str) or not _TENANT.fullmatch(tenant)
        or not isinstance(command, str) or not _COMMAND.fullmatch(command)
        or not isinstance(bearer, str) or not 40 <= len(bearer) <= 8192
        or not bearer.isascii() or bearer.count(".") != 2):
        raise ValueError("Invalid local service probe input")
    # HTTP is UNATTESTED. Only tests use this loopback diagnostic boundary.
    with closing(http.client.HTTPConnection("127.0.0.1", port=port, timeout=2.0)) as conn:
        conn.request(
            "GET", f"/_local/commands/{command}/service-evidence",
            headers={
                "Authorization": "Bearer " + bearer,
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        if (response.status != 200
            or response.getheader("Cache-Control") != "no-store"
            or "application/json" not in (response.getheader("Content-Type") or "")):
            raise ValueError("Local service evidence unavailable")
        raw = response.read(_MAX_RESPONSE + 1)
        if len(raw) > _MAX_RESPONSE:
            raise ValueError("Oversized evidence reply")
        data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("tenant_id") != tenant
        or data.get("command_id") != command
        or data.get("evidence_verified_locally") is not True
        or data.get("transport_attested") is not False
        or data.get("execution_authorized") is not False
        or data.get("external_network_used") is not False
        or data.get("production_ready") is not False
        or data.get("local_only") is not True
        or type(data.get("dispatch_recorded")) is not bool
        or type(data.get("issuance_recorded")) is not bool):
        raise ValueError("Evidence reply rejected")
    return {
        "source": "local_pywrangler_d1",
        "source_claim_authenticated": False,
        "service_request_authenticated_by_worker": True,
        "dispatch_recorded": data["dispatch_recorded"],
        "issuance_recorded": data["issuance_recorded"],
        "execution_authorized": False,
        "external_network_used": False,
        "production_ready": False,
    }


def attested_local_probe(*, port: int, tenant: str, command: str,
                         bearer: str, pinned_worker_public_pem: bytes,
                         challenge: str | None = None) -> dict:
    """Perform LOCAL-only challenged verification, never trust HTTP JSON alone."""
    # Validate caller inputs before generating or sending a challenge.
    if (type(port) is not int or not 1 <= port <= 65535
        or not isinstance(tenant, str) or not _TENANT.fullmatch(tenant)
        or not isinstance(command, str) or not _COMMAND.fullmatch(command)
        or not isinstance(bearer, str) or not 40 <= len(bearer) <= 8192
        or not bearer.isascii() or bearer.count(".") != 2):
        raise ValueError("Invalid attested probe arguments")
    challenge = secrets.token_hex(32) if challenge is None else challenge
    if not isinstance(challenge, str) or re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
        raise ValueError("Invalid local challenge")
    with closing(http.client.HTTPConnection("127.0.0.1", port=port, timeout=2.0)) as conn:
        conn.request(
            "GET", f"/_local/commands/{command}/attested-evidence",
            headers={
                "Authorization": "Bearer " + bearer,
                "X-AgentShield-Nonce": challenge,
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        if (response.status != 200
            or response.getheader("Cache-Control") != "no-store"
            or "application/json" not in (response.getheader("Content-Type") or "")):
            raise ValueError("Worker attestation unavailable")
        data = response.read(4097)
        if len(data) > 4096:
            raise ValueError("Oversized signed Worker response")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate signed response JSON key")
            result[key] = value
        return result
    response_body = json.loads(data, object_pairs_hook=unique,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")))
    evidence = verify_local_worker_attestation(
        response_body, nonce=challenge, tenant=tenant, command=command,
        trusted_public_key_pem=pinned_worker_public_pem,
        now_ms=int(time.time() * 1000),
    )
    return {
        "source": "local_pywrangler_d1_attested",
        "source_claim_authenticated": True,
        "production_source_trusted": False,
        "service_request_authenticated_by_worker": True,
        "dispatch_recorded": evidence["dispatch_recorded"],
        "issuance_recorded": evidence["issuance_recorded"],
        "execution_authorized": False,
        "external_network_used": False,
        "production_ready": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Local-only Worker/D1 diagnostic")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--command-id", required=True)
    parser.add_argument("--pinned-worker-public-key", type=Path)
    args = parser.parse_args()
    try:
        # Strict bound: do not accept JWT via argv, query params or env.
        bearer = sys.stdin.read(8193)
        if args.pinned_worker_public_key is None:
            result = local_probe(
                port=args.port, tenant=args.tenant,
                command=args.command_id, bearer=bearer,
            )
        else:
            result = attested_local_probe(
                port=args.port, tenant=args.tenant,
                command=args.command_id, bearer=bearer,
                pinned_worker_public_pem=args.pinned_worker_public_key.read_bytes(),
            )
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError, AttestationRejected):
        print('{"rejected":true,"execution_authorized":false}')
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
