# Security audit: 0.8–0.9 boundary

Date: 2026-08-13

This is an internal code audit, not an independent security assessment. It covers identity, local registry, scoped HTTP, trace replay, peer cryptography, shared documents, asset transfer, rollback datagrams, and network simulation. The 1.0 external-review gate remains open.

## Findings fixed

### Exact-byte package race

The first signing and publishing path read bytes for hashing, then reopened the package for archive validation or copying. A concurrent replacement could separate the validated archive from the signed or stored bytes.

Signing, verification, and registry publication now load one bounded byte buffer, parse that exact buffer, calculate its identity, verify its signature, and store the same bytes. Existing content-addressed objects are compared byte-for-byte before reuse.

### Registry interruption recovery and index binding

An interrupted index replacement could leave only a temporary backup, and a syntactically valid index was not required to have a one-to-one relationship with its transparency entries.

The registry now uses a stable recovery backup, restores it on open, quarantines an invalid current index before recovery, and fails closed if both copies are invalid. Validation binds every indexed id, semantic version, package digest, and signing key to exactly one hash-chained transparency entry. Full audit re-verifies stored bytes and signatures against the trust store.

### HTTP replay amplification and header ambiguity

Serializing response bodies as JSON byte arrays could amplify trace size. Header names also needed case-insensitive duplicate rejection before conversion to an ordered map.

Trace bodies now use bounded hexadecimal encoding. Live and replayed responses pass the same response limits. Header names are deduplicated case-insensitively, host-controlled and hop-by-hop headers are forbidden, and malformed recorded values fail replay. Raw WASI TCP, UDP, and name lookup remain disabled.

### Unbounded network helper state

The initial simulator accepted an unbounded iterator, rollback replay identities could accumulate forever, fixture reads allocated before enforcing their document limit, and shared-document internals were deserializable without invariant reconstruction.

Simulation now has a packet-count ceiling, rollback replay state is pruned to its tick window and capped, fixture input is streamed through a hard limit, and `SharedDocument` can only be constructed and changed through validating methods.

### Trust-document validation gaps

Loaded recovery ids, rotations, revocations, and attestation metadata were not all revalidated at the trust boundary.

Trust-store loading now verifies every public-key identity, recovery id, rotation signature, and revocation signature. Build attestations revalidate toolchain and argument bounds as well as their detached signature.

## Verification

- 161 workspace tests passed before final hardening; focused identity, network, and runtime tests passed again afterward.
- Workspace Clippy passed for every target with warnings denied.
- `cargo audit` found no known advisories in 262 locked dependencies.
- Every fuzz target compiles, including the new scoped-network target.
- Workspace formatting and patch whitespace checks pass.
- Production code forbids `unsafe`; input-reachable `unwrap` and `expect` calls were not introduced.

## Remaining 1.0 gates

- Independent security review and remediation publication.
- Restricted Windows token/AppContainer, macOS sandbox profile, and Linux namespace/seccomp integration for native helpers.
- Production live HTTP, discovery, relay, and NAT adapters with their own process and DNS-rebinding defenses. The current runtime exposes only the policy boundary and offline fixture transport.
- Hardware-backed key storage where available. Windows developer key files currently rely on the containing directory ACL.
- Cross-platform compatibility corpus, soak tests, release performance baselines, signed/notarized installers, and rollback-tested updates.

Until those gates close, the project should describe 0.8 and 0.9 as implemented reference boundaries and 1.0 as stabilization work, not claim that arbitrary native adapters or downloaded cartridges are vulnerability-free.
