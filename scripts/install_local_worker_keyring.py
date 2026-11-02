"""OFFLINE LOCAL operator trust installer: never receives private signing keys.

All input is file-based local operator provisioning; no HTTP, D1, cloud API,
deployment, or execution authority. Emit only redacted generation and status.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentshield.host_trust_ledger import install_local_signed_keyring
from agentshield.host_worker_attestation import AttestationRejected


def main() -> int:
    parser = argparse.ArgumentParser(description="Install signed local host keyring")
    parser.add_argument("--signed-manifest", required=True, type=Path)
    parser.add_argument("--operator-public-key", required=True, type=Path)
    parser.add_argument("--host-trust-ledger", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = install_local_signed_keyring(
            ledger_path=str(args.host_trust_ledger),
            signed_envelope=args.signed_manifest.read_bytes(),
            operator_public_pem=args.operator_public_key.read_bytes(),
        )
    except (AttestationRejected, ValueError, OSError):
        print('{"rejected":true,"execution_authorized":false}')
        return 2
    print(json.dumps({
        "generation": receipt.generation, "changed": receipt.changed,
        "execution_authorized": False, "production_ready": False,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
