# Reproducible development and dependency review

**Scope:** pre-alpha local development only. This is not a production setup or deployment guide. Follow [RAIDER](https://github.com/EagleFox31/appfactory-project-automation): reuse approved tools and existing tests before creating an alternative subsystem.

## Supported baseline

- Python **3.13** for the developer and CI verification shown here; `pyproject.toml` supports older CPython, but the CI reproducibility claim specifically covers Python 3.13.
- `uv==0.10.0` with the version-controlled root [`uv.lock`](../uv.lock).
- Cloudflare `wrangler.jsonc` compatibility date **2026-10-26**, the `python_workers` flag and a **LOCAL-only** D1 binding with the all-zero placeholder ID. The platform's Pyodide and package repository are chosen by Cloudflare based on the compatibility date; `uv.lock` controls host resolution, **not every separate Pyodide wheel**.
- Native Web Crypto ES256 verifies incoming JWTs in the Python Worker. `PyJWT` and patched `cryptography` are used only by host tests and local synthetic JWT fixture generation.

## Clean checkout on a contributor machine

Use a fresh clone (do not carry over `.venv`, `.dev.vars`, `.local-jwt` or Cloudflare local state). Install `uv 0.10.0` from its official distribution and Python 3.13, then run:

```bash
uv python install 3.13
uv lock --check --python 3.13
uv sync --locked --python 3.13 --group test --group quality
uv run --locked --group test python -m unittest discover -s tests/gateway -v
uv run --locked --group quality ruff check src tests scripts --select E9,F63,F7,F82
uv run --locked --group quality ruff format --check src/agentshield/policy.py
uv run --locked --group quality mypy --strict src/agentshield/policy.py
uv run --locked --group test python scripts/demo_invoice_attack.py --assert-secure
uv run --locked --group test python scripts/demo_merkle_proofs.py --assert-secure
uv run --locked --group test python scripts/evaluate_detection.py --assert-contract
```

The pure policy tests also run with only the standard library:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Local Cloudflare Python Worker & D1

Follow the **existing** [gateway smoke workflow](../.github/workflows/gateway-smoke-ci.yml) as the authoritative end-to-end recipe. It installs `worker` dependencies with `uv run --locked --group worker`, creates short-lived ES256 dummy keys on the local machine, applies SQL migrations with `wrangler d1 execute --local`, and runs `pywrangler dev` **locally**. The real local test proves JWT agent/operator trust-root isolation, approval expiration and replay protection, D1 redacted audit, read-only invoice demo, and a native Pyodide runtime.

**Never run `pywrangler deploy`, `wrangler d1 create` or external Workers AI calls as part of these checks.** Avoid copying local JWT fixture files, tokens or `.dev.vars` into logs or commits. The HTTP API does not expose a public authorization/execution endpoint. `enforcement_ready: false` is intentional.

## When dependencies change

1. Update the **appropriate group**: `[project.dependencies]` is the **Worker required runtime**; `test` and `quality` are host-only, and `worker` adds host tooling for local Pywrangler and synthetic signing. A host-test dependency must not accidentally migrate into the Pyodide runtime.
2. Regenerate with **the reviewed resolver**: `uv lock --python 3.13`. Commit both `pyproject.toml` and `uv.lock`. Review actual version and hash changes in the PR.
3. Run `uv lock --check --python 3.13`, then execute the Python CI and the **real** local Cloudflare Worker/D1 regression. The latter must remain green when a Pyodide package or compatibility date changes.
4. Check the vulnerability scan and CycloneDX SBOM artifact on the exact PR commit. Vulnerability warnings must not be suppressed to force green CI.
5. Keep dependency update proposals reviewed: Dependabot may open PRs, but there is no automatic merge. Document any platform-only exceptions and link the relevant issue.

**Important limit:** `uv.lock` gives reproducible resolutions and package hashes for `uv`-managed host environments. It does not by itself freeze Cloudflare's separately selected Pyodide runtime/wheels, any transitive `npx --yes wrangler` downloads, the OS container, or the remote Cloudflare platform. Therefore a green `uv lock --check` alone is insufficient for the Worker. Full release-grade build provenance and an independently reviewed platform freeze remain follow-up gates.

## Security / contribution checklist

No real customer data, production signing keys, secrets, remote paid services, production deployment or real tool mutations. Report vulnerabilities privately following [SECURITY.md](../SECURITY.md). Link PRs to existing issues and provide an exact CI run and any known limitations. Small, reviewable changes beat unverified release claims.
