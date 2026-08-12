# Security audit: developer workflow and desktop library

Date: 2026-08-12

Scope: the 0.6 developer workflow, 0.7 desktop library, permission persistence, launch recovery, GPU presenter boundary, new CLI commands, and regression review of the 0.1–0.5 package/runtime/storage/trace/media boundaries.

This is an internal code audit, not an independent security assessment. No reviewed boundary should be described as free of all vulnerabilities. Package signing, OS-native worker sandbox profiles, and the production GPU helper remain later security milestones.

## Findings fixed

### S-01 — package install time-of-check/time-of-use window

The first install path validated a source archive and then copied the source again. A concurrent source change could make the installed bytes differ from the bytes whose manifest supplied the catalog metadata.

The library now copies into an exclusive, bounded staging file while calculating its digest, validates that exact staged file, and hard-links those same bytes into the content-addressed destination. Launch verifies the stored package digest again. Package input growth is capped while streaming.

### S-02 — persistent grants survived a changed permission request

A grant keyed only by cartridge id could apply to a later installed version that requested a different authority set.

Persistent grants now bind to a digest of the complete requested capability set. Any addition or removal invalidates the old approval. A grant outside the current manifest request is rejected. Session approvals remain process-local.

### S-03 — concurrent catalog writers could lose security state

Two shell processes could read the same library index and later replace it with conflicting grant, history, or install changes.

The desktop library now holds an operating-system file lock for each mutation session. Lock acquisition has a fixed two-second budget and fails closed instead of waiting indefinitely.

### S-04 — interrupted index replacement could discard the catalog

A crash between moving the old index to its rollback name and publishing the new index could leave no primary document. Corrupt primary and rollback documents could also prevent the shell from opening.

Startup now validates and restores a rollback document when possible, quarantines invalid primary or rollback files, and falls back to an empty valid catalog. Launch ids and resource samples receive semantic validation. Temporary writes are exclusive and uniquely named.

### S-05 — developer project scans allowed excessive aggregate work

Per-file limits did not bound the total bytes hashed, and recursive directory traversal could consume excessive stack on a deeply nested project.

Project inspection now uses iterative traversal with hard entry, individual-file, and aggregate-byte limits. Symbolic links, non-UTF-8 paths, component traversal, control-containing build arguments, and source files changed beyond their declared size remain rejected.

### S-06 — GPU presenter accepted an untyped byte slice

A backend trait taking arbitrary bytes made it possible for an adapter to accidentally bypass stream validation.

Presenters now accept only `ValidatedGpuStream`, whose byte storage is private. Construction validates the protocol magic/version, total byte size, command count, pass count, and configured policy before a backend can see the stream. Accelerated mode separately requires robust buffer access and helper-process isolation.

### S-07 — an installed semantic version could be replaced silently

Reinstalling the same id/version with a different digest could change which artifact the catalog selected.

Installed versions are now immutable. Identical content is idempotent; different content requires a new semantic version. This is a local invariant and does not replace developer signatures planned for 0.8.

### S-08 — scaffold output was not exercised end to end

The first Rust template used a guest type name that collided with the generated WIT trait. This was a correctness issue rather than an authority bypass, but an unusable template could push developers toward ad-hoc build scripts.

The template now uses a namespaced binding module and was tested from `cartridge new` through release component build, package, supervised run, and output.

## Reviewed controls

- Build commands are argument arrays executed without a shell. They exist only in a local developer project and are never loaded from an installed package. Opening an untrusted source checkout remains equivalent to running its build system and requires developer consent.
- Component imports are matched against the runtime before guest execution. The conformance runner then uses the normal killable worker and deterministic replay.
- Project creation and schema/timeline outputs use exclusive creation and refuse overwrites.
- Library documents, histories, resource samples, package staging, project trees, trace exports, GPU streams, and GPU resource budgets are bounded before expensive work.
- Installed paths derive from validated cartridge ids, semantic versions, and SHA-256 digests. Stored relative paths are validated before use.
- A launch cannot start while requested capabilities are missing. Persistent and session grants can be inspected and revoked.
- Running launches are persisted before execution. Interrupted launches become failures and repeated failures enter per-cartridge safe mode without blocking the rest of the library.
- Corrupt library state is quarantined instead of decoded partially or trusted.
- Canonical media receipts remain CPU-generated and byte-exact. GPU output is not treated as byte-identical across drivers.
- Production code in the new crates contains no `unsafe`, reachable `unwrap`, or reachable `expect` calls.

## Verification

- formatting and workspace Clippy with warnings denied
- 151 workspace tests in debug and release modes
- all example-crate tests
- all fuzz targets compile, including the new GPU stream target
- RustSec audit of the workspace, fuzz workspace, and all four example lockfiles
- new Rust scaffold built and executed from a clean temporary project
- package conformance completed API preflight, execution, and deterministic replay
- installed-library preflight, persistent grant, launch, and history smoke test
- cross-platform CI covers Windows, macOS, and Linux
- scheduled Linux libFuzzer workflow covers archive, manifest, snapshot, trace, transaction, reachability, graphics, audio, and GPU stream inputs

## Remaining security boundaries

The public worker is killable and receives a minimal environment, but it does not yet enter restricted Windows tokens/AppContainer, macOS sandbox profiles, or Linux namespaces/seccomp. The GPU presenter contract is implemented, but no production native GPU helper is enabled yet. Package authenticity and trusted runtime updates wait for 0.8 signing. Until those layers land and receive an external review, arbitrary downloaded cartridges should not be presented as fully trustless.
