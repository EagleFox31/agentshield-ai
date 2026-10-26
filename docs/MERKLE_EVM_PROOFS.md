# AgentShield AI — Independently verifiable Merkle evidence (v1)

**Implementation:** offline hash-chain/Merkle proofs + independent verifier + unsigned EVM intent. **Not deployed, not anchored, no finality claim.**  
**Backlog:** [AgentShield #5](https://github.com/EagleFox31/agentshield-ai/issues/5) · [ADR-0006](adr/0006-merkle-evm-proof-boundary.md).

## Why and precise trust boundary

SQLite/D1 audit rows contain per-event SHA-256 fingerprints, but an administrator who can edit the database could update both a record and its locally stored hash, or delete records. To detect such changes later, AgentShield needs **an independently preserved commitment to a well-defined event batch**.

A verifier checking only the manifest supplied by the same potentially compromised database must report `consistent_unanchored`. It must **not** claim independently verified integrity. To verify historical consistency, the operator obtains `trusted_commitment` (or a chain head) from an **independent, trusted channel**, such as a previously pinned off-database digest or a future chain receipt verified against a trusted EVM client and allowlisted contract.

This scheme cannot prove the original event was truthful or that an event **never logged** was captured. It cannot detect deletion of an entire unpublished tail without an independent expected chain head. Coverage is strictly limited to events enumerated by the independently committed manifest; completeness of an organization's entire historical log also requires authorized append-only batch issuance/coverage policy.

## Canonical v1 construction

The implementation uses only Python's `hashlib.sha256` and existing `AuditEvent.canonical_payload()`; no invented cryptography or JavaScript-specific hash implementation.

1. Extract valid redacted `AuditEvent` rows for exactly **one tenant**, with strict event ID uniqueness; sort by `(occurred_at_ms,event_id)` and cap at **4096 events per batch**.
2. Preserve `event.fingerprint`, already computed as SHA-256 of the canonical versioned JSON `agentshield.audit.v1`.
3. Merkle leaf at position `i`: `SHA256("AgentShield/Merkle/leaf/v1\\0" || uint32_be(i) || event_fingerprint_bytes)`.
4. Internal node: `SHA256("AgentShield/Merkle/node/v1\\0" || left_32 || right_32)`. Duplicate the last node of an odd-width layer.
5. Compute a versioned off-chain manifest containing tenant, batch identifier, monotonic `sequence`, `previous_commitment`, UTC epoch time, count, ordered event-ID/hash/timestamp references and the Merkle tree root.
6. Manifest SHA-256 is computed over UTF-8 canonical JSON (sorted keys, compact separators) **without** its own hash/commitment.
7. The final EVM-sized commitment is `SHA256("AgentShield/Merkle/commitment/v1\\0" || manifest_hash_bytes)`. **Only this 32-byte commitment** is eligible for chain publishing.
8. The next batch in a tenant chain references the previous *commitment*. A pinned head plus continuity/sequence verification detects gaps, batch replacement, deletion and reorder **inside the declared complete chain**.

Fields like tenants, audit event IDs, policy reasons, prompts, bank details, raw logs, JWTs and batch contents **must not appear in EVM calldata or logs**. Even hashes on a public blockchain reveal existence and timestamps when broadcast, so publishing must be explicitly authorized and should be batched.

## Run the offline integrity demonstration

```bash
PYTHONPATH=src python scripts/demo_merkle_proofs.py --assert-secure
PYTHONPATH=src python -m unittest discover -s tests/gateway -p 'test_merkle*.py' -v
```

The demo writes three **synthetic** audit events to ephemeral in-memory SQLite using the existing migration and adapter, then builds a versioned Merkle manifest. It verifies leaf membership and a complete batch against a locally pinned *fixture root*; it also proves that tampering, removal and reordering are rejected. It deliberately reports `onchain_verified:false` and `consistent_unanchored`.

**Important:** the demo's fixture commitment is pinned only inside the test run; it is **not** an external trust anchor.

### Independent CLI verifier

`scripts/verify_merkle.py` is a separate process, with no DB/network imports, credentials or EVM calls. It has three modes:

```bash
# Manifest and events must be supplied as JSON files, not fetched from the target DB.
PYTHONPATH=src python scripts/verify_merkle.py batch \
  --manifest manifest.json --events events.json \
  --trusted-commitment YOUR_EXTERNALLY_PINNED_64_HEX_DIGEST

PYTHONPATH=src python scripts/verify_merkle.py inclusion \
  --manifest manifest.json --event single-event-list.json \
  --proof inclusion-path.json \
  --trusted-commitment YOUR_EXTERNALLY_PINNED_64_HEX_DIGEST

PYTHONPATH=src python scripts/verify_merkle.py chain \
  --manifests ordered-manifests.json \
  --trusted-head YOUR_EXTERNALLY_PINNED_LATEST_CHAIN_HEAD
```

An exit code of 0 confirms only that the **supplied** audit data matches the **supplied** trust root. It does not authenticate where that root was obtained, prove an EVM transaction, or validate RPC finality. Externally obtained trusted roots are an operator responsibility; use a separate signing/distribution channel.

Negative tests include modified/missing/added/reordered events, invalid per-leaf paths, odd-node duplication, conflicting manifest hashes, cross-tenant/duplicate events, missing/reordered chain batches, a replaced head, and wrong-chain/reorg/insufficient-confirmation **untrusted RPC snapshots**.

## Cloudflare local D1 integration

No new remote database or D1 resources are created. With the existing [local identity and approval setup](APPROVALS_LOCAL.md) and [injection demo](DEMO_PROMPT_INJECTION.md):

```bash
curl -X POST -H "Authorization: Bearer $(cat .local-jwt/valid.txt)" \
  http://127.0.0.1:8787/_local/demo/invoice-injection

curl -H "Authorization: Bearer $(cat .local-jwt/operator_valid.txt)" \
  http://127.0.0.1:8787/_local/demo/merkle-batch
```

The second route is **operator-only** and reads the redacted same-tenant D1 audit records, validates stored per-event hashes and produces a fresh Merkle manifest/inclusion paths. It reports `verification_status:consistent_unanchored`, `evm_status:not_submitted` and `onchain_verified:false`. This is a **snapshot**, not a persisted batch or already anchored proof; the batch should be exported and pinned outside D1 for meaningful future historical checks. The local dashboard labels this explicitly **Merkle snapshot (unanchored)**.

The live system would need a scheduled, durable, race-safe batch issuance service, manifest archival (e.g. protected R2), independently distributed/pinned chain heads, retention/recovery policy and replay-safe anchoring worker. These are **not** built or deployed as part of this issue.

## EVM integration boundary (no chain interaction)

- `prepare_evm_anchor_intent(manifest, chain_id, contract_address)` constructs an **unsigned, non-broadcast** intent with a `bytes32` commitment; it never signs, calls RPC, creates wallets, deploys or spends gas.
- [AuditRootRegistry.sol](../contracts/AuditRootRegistry.sol) is a **reference-only, undeployed** Solidity contract. It restricts anchoring to a publisher, allows owner-controlled publisher rotation, records only `bytes32` commitments and emits `RootAnchored(bytes32)`. The contract is compiled in CI, **not deployed or audited**.
- `summarize_anchor_evidence` classifies offline self-reported receipts: no receipt, commitment mismatch, wrong chain/failed receipt, block mismatch/reorg and insufficient confirmations. Even an apparently matching receipt is marked **`unverified_requires_independent_rpc_and_contract_log_check`**. The trust assumptions must be satisfied independently by checking chain ID, authorized contract/publisher, actual event log, canonical block hash and accepted finality threshold.
- **No testnet network, selected chain, publisher key, contract deployment or gas payment has been approved.** A separate deliberate deployment/security review is required.

Solidity contract events are blockchain logs, with address and event-topic context that a real verifier must inspect. A reported transaction hash by itself is not proof of the correct authorized root or canonical finality. See [Solidity event specification](https://docs.soliditylang.org/en/latest/contracts.html#events) and [ABI events](https://docs.soliditylang.org/en/latest/abi-spec.html#events).

## RAIDER acceptance

**Reusable:** Merkle core consumes existing provider-agnostic `AuditEvent`, not new SQLite or D1-specific event formats.  
**Agnostic:** standard-library SHA-256 and standalone verifier require no Cloudflare, EVM SDK or external service.  
**Idempotent:** canonical ordering, duplicate rejection, explicit sequence/previous head and committed coverage.  
**Durable:** strict versioning, domain separation, golden/security negative fixtures and path-scoped CI.  
**Engineering-grade:** explicit trusted root provenance and conservative finality reporting; independently test inclusion, omission, reorder and reorg cases.  
**Retroactive:** existing SQLite/D1 migrations, invoice demonstration, JWT operator permissions and dashboard are retained, not rebuilt.

**Release claims:** *locally verifiable tamper evidence*, **not** `blockchain-backed`, `tamper-proof`, `immutably audited`, `on-chain verified`, `EVM deployed` or `production secure` at this stage.
