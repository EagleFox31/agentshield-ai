"""Fail-closed local Worker/Pyodide provenance contract; standard library only.

This guard compares actual authenticated local Worker runtime observations to
reviewed baseline data. It does NOT freeze Cloudflare's remote platform.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from typing import Any


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be a JSON object")
    return value


def validate(
    observed: dict[str, Any],
    baseline: dict[str, Any],
    wrangler_config: dict[str, Any],
    npm_package: dict[str, Any],
    npm_lock: dict[str, Any],
    python_project: dict[str, Any],
) -> None:
    """Deny drifting runtime, missing npm integrity, unsafe cloud configuration."""
    expected_keys = {
        "python_version", "pyodide_version", "packages", "local_only",
        "enforcement_ready", "real_tool_called",
    }
    if set(observed) != expected_keys:
        raise ValueError("Unexpected or missing Worker evidence keys")
    if observed["local_only"] is not True or observed["enforcement_ready"] is not False:
        raise ValueError("Worker evidence is not from a disabled local-only gateway")
    if observed["real_tool_called"] is not False:
        raise ValueError("Worker executed a real tool")

    for key in ("python_version", "pyodide_version", "packages"):
        if observed[key] != baseline[key]:
            raise ValueError(f"Cloudflare/Pyodide runtime drift: {key}")
    if not isinstance(observed["pyodide_version"], str) or not observed["pyodide_version"]:
        raise ValueError("Missing actual Pyodide version")

    for key in ("compatibility_date", "compatibility_flags"):
        if wrangler_config.get(key) != baseline[key]:
            raise ValueError(f"Cloudflare compatibility contract drift: {key}")
    if wrangler_config.get("d1_databases") != [{
        "binding": "DB",
        "database_name": "agentshield-local-only",
        "database_id": "00000000-0000-0000-0000-000000000000",
    }]:
        raise ValueError("Unexpected D1 binding; never inspect remote D1")

    pinned = baseline["wrangler_version"]
    if npm_package.get("private") is not True:
        raise ValueError("Node toolchain must be private")
    if npm_package.get("devDependencies", {}).get("wrangler") != pinned:
        raise ValueError("Pinned Wrangler version differs from reviewed baseline")
    root = npm_lock.get("packages", {}).get("", {})
    if root.get("devDependencies", {}).get("wrangler") != pinned:
        raise ValueError("Root npm lock disagrees with package.json")
    wrangler = npm_lock.get("packages", {}).get("node_modules/wrangler", {})
    if wrangler.get("version") != pinned or not wrangler.get("integrity", "").startswith("sha512-"):
        raise ValueError("Wrangler lock version or SHA512 integrity missing")
    all_packages = npm_lock.get("packages", {})
    if len(all_packages) < 25:
        raise ValueError("npm lock missing transitive dependency inventory")
    for name, package in all_packages.items():
        if name and package.get("resolved", "").startswith("https://"):
            if not package.get("integrity", "").startswith(("sha512-", "sha256-", "sha1-")):
                raise ValueError("Unverified remote npm dependency integrity")
    deps = python_project["project"]["dependencies"]
    if set(deps) != {
        f"fastapi=={baseline['packages']['fastapi']}",
        f"starlette=={baseline['packages']['starlette']}",
    }:
        raise ValueError("Worker dependency declarations differ from runtime baseline")
    if any("cryptography" in dep.lower() or "pyjwt" in dep.lower() for dep in deps):
        raise ValueError("Host-only crypto/JWT library is part of Worker runtime")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: check_worker_provenance.py OBSERVED_WORKER_JSON", file=sys.stderr)
        return 2
    root = pathlib.Path(__file__).resolve().parents[1]
    try:
        validate(
            load_json(pathlib.Path(sys.argv[1])),
            load_json(root / "docs/WORKER_RUNTIME_BASELINE.json"),
            load_json(root / "wrangler.jsonc"),
            load_json(root / "package.json"),
            load_json(root / "package-lock.json"),
            tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8")),
        )
    except (KeyError, TypeError, ValueError, OSError) as exc:
        print(f"Local Worker platform provenance rejected: {exc}", file=sys.stderr)
        return 1
    print("Local Worker/Pyodide versions match reviewed baseline; no remote runtime freeze claimed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
