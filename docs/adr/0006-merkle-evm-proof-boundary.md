# ADR-0006 — Off-chain audit integrity + optional Merkle/EVM anchoring

- **Date:** 2026-10-26
- **Status:** Accepted as architecture; testnet anchoring is an optional MVP extension

## Context
Blockchain transactions per event are expensive and can leak metadata. D1 audit rows can be updated by a privileged operator, so D1 persistence alone is not an integrity proof.

## Decision
Record canonical, versioned, redacted security events off-chain. Independently compute their cryptographic fingerprints and periodically form **deterministically ordered Merkle batches**. Store batch manifests and inclusion paths outside the chain (D1 initially, with optional protected R2 exports). Anchor **only batch roots and minimal non-identifying metadata** on a chosen EVM **testnet**, under a dedicated, rotation-ready signing account. Keep blockchain publishing asynchronous and opt-in. Never put raw requests, names, user IDs, financial fields, prompts or secrets on-chain. Use a verified cryptographic library, deterministic encoding, domain separation and an independently executable verifier.

## Limits
The proof establishes consistency with an anchored batch at an accepted chain finality depth; it does not establish original truthfulness, authorized event production or completeness of events that were never recorded. Handle reorgs, dropped transactions, unconfirmed anchors and partial failures explicitly. Gateway authorization never waits on chain fees or a blockchain RPC.

## Exit tests
Reordered/altered/removed events yield verification failure within the declared batch coverage. Anchored proof verification tolerates incomplete network availability by reporting `unverified`, never `verified`. Testnet expenditure and deployment require separate approval and are **not authorized** by this ADR.

## References
- [MVP scope](../MVP_SCOPE.md)
