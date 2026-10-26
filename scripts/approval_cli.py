"""AgentShield local operator CLI. Never passes tokens via argv or persists them.

Example:
    AGENTSHIELD_OPERATOR_TOKEN=... python scripts/approval_cli.py list
    AGENTSHIELD_OPERATOR_TOKEN=... python scripts/approval_cli.py audit APPROVAL_ID
    AGENTSHIELD_OPERATOR_TOKEN=... python scripts/approval_cli.py approve APPROVAL_ID
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlparse


def api(base: str, token: str, path: str, method: str = "GET") -> dict:
    # This CLI is deliberately limited to loopback local Worker execution.
    parsed = urlparse(base)
    if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in ("", "/")):
        raise ValueError("Local-only CLI: use an HTTP loopback address")
    request = urllib.request.Request(
        base.rstrip("/") + path,
        method=method,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("Redirect blocked: operator token must remain on loopback")

    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=10) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentShield local operator approval CLI")
    parser.add_argument("--base-url", default="http://127.0.0.1:8787")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="Review tenant-bound approval requests")
    for name in ("approve", "reject", "audit"):
        item = sub.add_parser(name)
        item.add_argument("approval_id")
    args = parser.parse_args(argv)
    token = os.environ.get("AGENTSHIELD_OPERATOR_TOKEN", "")
    if not token or len(token) > 8192:
        print("Missing/invalid AGENTSHIELD_OPERATOR_TOKEN in environment", file=sys.stderr)
        return 2
    try:
        if args.command == "list":
            result = api(args.base_url, token, "/_local/approvals")
        else:
            ref = quote(args.approval_id, safe="")
            if args.command == "audit":
                path, method = "/_local/approvals/" + ref + "/audit", "GET"
            else:
                path, method = "/_local/approvals/" + ref + "/" + args.command, "POST"
            result = api(args.base_url, token, path, method)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, TimeoutError) as exc:
        if isinstance(exc, urllib.error.HTTPError):
            print(f"Approval API refused request (HTTP {exc.code})", file=sys.stderr)
        else:
            print("Could not reach safe local approval API", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
