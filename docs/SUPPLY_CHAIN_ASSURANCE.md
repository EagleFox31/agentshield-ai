# Supply-chain security gates — dependency licenses and secret exposure

**Status:** CI controls under review in PR #38 (issue #2), local pre-alpha only. No production deployment or external AI provider activation.

## Reuse before building (RAIDER)

- **Secrets:** use [Gitleaks](https://github.com/gitleaks/gitleaks-action) v3, a maintained secret scanner, via its pinned immutable GitHub Action commit. The job runs for **every PR**, on `main`, and on manual dispatch with checkout of full available Git history, rather than duplicating scanning rules with regular expressions.
- **Third-party Python licenses:** use [pip-licenses](https://github.com/raimon49/pip-licenses) `5.5.5` to inspect the actual clean `[project.dependencies]` CPython runtime installation. The scanner is installed into a **separate virtualenv** so the report does not accidentally include itself and its own dependencies. Manifest `dependency-licenses.json` is preserved as a short-lived CI artifact.
- **Existing guards remain mandatory:** `uv.lock`, `pip-audit` (no vulnerability ignores), CycloneDX runtime SBOM, Ruff, strict Mypy policy tests, and the actual local Pyodide/Cloudflare Worker+D1 gate. The new jobs do not replace any of these.

## License policy and limitations

The CI reads **PEP 639 / SPDX license expressions** (`--from=expression`) and only allows the currently reviewed **MIT, BSD-3-Clause and PSF-2.0** third-party runtime dependency licenses. Unknown metadata, GPL/AGPL and all unapproved expressions **fail the gate**; there is no implicit permission for new licenses. A negative test intentionally marks FastAPI's known `MIT` license forbidden and verifies the scanner exits unsuccessfully. This is a *conservative license review gate*, **not a legal determination**. Compound SPDX expressions, dual licensing and missing metadata need explicit review before expanding the allowlist; consult the `python-runtime-licenses` artifact.

The local `agentshield-ai` package is excluded from the *third-party dependency* report. The repository currently does **not** publish a root `LICENSE` file, so the owner must separately choose a project distribution license before describing the code as legally open-source. We do not invent or apply a license.

A successful `pip-licenses` scan is **not** proof that all Pyodide-selected wheels, npm/Wrangler, transitive system libraries or artifacts outside the current CPython runtime have been inventoried. These remain tracked in #2.

## Secret-scanning policy

- Gitleaks checks commits/PR changes via existing Git history on every PR, not merely the current working tree. The full-history job must be green, without a repository-wide allowlist or a blanket suppression.
- On a finding, **do not publish the candidate secret in CI logs or in a GitHub issue**. Rotate/revoke potentially real credentials, investigate the affected commit(s) privately, and verify both working tree and retained history before considering a release.
- Detection is best-effort. A green scanner is **not** evidence that all possible secrets are absent. No actual customer credentials, .dev.vars, .local-jwt fixtures or external paid services belong in this repository or smoke tests.
- The action's automated PR comments and artifact uploads are disabled to minimize the chance of surfacing matched text in publicly visible feedback. The failing job remains the merge gate.

## Review status / remaining gates

Collect final CI links on the PR head before considering merge. Broader secret scanning of deployment configuration, exact Cloudflare Pyodide/Wrangler provenance, complete license review and independent JWT security sign-off remain separate explicit tasks. The deployment-ready flag stays false.

**No independent security sign-off is claimed by the authors of this change.**
