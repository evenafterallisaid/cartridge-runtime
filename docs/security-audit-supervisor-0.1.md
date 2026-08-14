# Supervisor and full-workspace security review

Date: 2026-08-14

> Historical boundary note: the hard-parent-failure gap recorded here was closed later the same day and is reviewed in [security-audit-process-containment-0.1.md](security-audit-process-containment-0.1.md). The remaining supervisor findings stay as the record of this earlier slice.

Scope: the complete Rust workspace, native desktop shell, dependency graphs, execution and storage boundaries, engine desired/observed state, the foreground stack supervisor, CI/fuzz integration, and end-to-end stack execution. This is an internal review, not an independent assessment.

## Result

No known exploitable issue remains in the implemented portable-runtime and foreground-supervisor boundary after the fixes below. This conclusion does not certify the missing platform-native worker sandboxes, background daemon/API, live network adapters, service broker, secret broker, GPU helper, installer, or fleet control plane.

## Findings fixed during review

| id | severity | finding | resolution |
| --- | --- | --- | --- |
| SUP-01 | high | stack plans computed denied capabilities, but the worker path would otherwise run the package manifest with its full requested authority | the supervisor passes a compact capability ceiling and `cartridge-runtime` intersects it with requested permissions before constructing WASI and every host capability |
| SUP-02 | high | reusing one replica directory across unsigned package upgrades could let different bytes claiming the same cartridge id inherit old durable state | engine-owned state is partitioned by stack, replica, and exact package SHA-256; cross-version handoff now requires a future authenticated migration |
| SUP-03 | medium | two foreground supervisors could race the same stack generation and duplicate workers | a per-stack operating-system lease permits exactly one active supervisor |
| SUP-04 | medium | per-instance replica limits still allowed an aggregate process fan-out across many instances | manifests and independently deserialized plans both enforce 256 total replicas; the supervisor admits at most 32 workers concurrently |
| SUP-05 | medium | stale exits or status from an earlier desired generation could corrupt replacement state | desired event hashes fence observed generations, run ids fence attempts, all transitions are validated, and stale events fail closed |
| SUP-06 | medium | an `always` or failing workload could restart indefinitely or spin without delay | restart counts are bounded to 64, exponential backoff is capped at 30 seconds, and every attempt consumes a finite budget |
| SUP-07 | medium | catalog contents could change between planning and activation | activation revalidates the complete plan, composition locks, exact catalog bytes, package digest, byte length, and archive manifest before spawning |
| SUP-08 | low | observed state could be oversized, partially replaced, changed on disk, or replayed against another plan | status is limited to 1 MiB, deny-unknown JSON, checksum-bound, private, atomically replaced with crash recovery, and checked against the current desired generation |
| SUP-09 | low | Ctrl+C/SIGTERM could bypass destructor-based child cleanup | the supervisor installs an explicit termination handler, kills and waits for owned children, records their exits, and every child enters kill-on-drop ownership immediately after spawn |

## Verification

- strict formatting and Clippy with warnings denied for the workspace and native desktop shell
- complete workspace tests across package, archive, runtime, storage, identity, registry, networking, media, release, engine, CLI, and trace crates
- engine adversarial tests for fork-bomb plans, restart exhaustion, stale exits, interrupted recovery, duplicate supervisors, status tampering, generation drift, and unsigned state inheritance
- runtime tests proving a host capability ceiling can revoke permissions requested by the manifest
- real install → plan → apply → supervise → observed-status execution of the hello cartridge
- real hostile timeout workload: three attempts reached `exhausted` in 4.5 seconds under a two-restart budget
- engine fuzz target extended to deserialize and validate untrusted observed-runtime documents
- RustSec scan: 0 vulnerabilities across 271 resolved Rust dependencies after the supervisor signal dependency was added
- npm audit: 0 vulnerabilities across 8 production desktop dependencies
- desktop RustSec scan: 0 vulnerability advisories; 16 unmaintained GTK3-era transitive warnings and one `glib` 0.18.5 unsoundness warning remain confined to the already-blocked Linux packaging target
- manual review of process creation, environment inheritance, filesystem paths and replacement, bounded decoders, secrets, command execution, permission transitions, and documentation claims

## Residual security gates

- The Wasmtime capability boundary is active, and helpers are killable and deadline-bound, but they do not yet enter restricted Windows tokens/AppContainer, macOS sandbox profiles, or Linux namespaces/seccomp/cgroups. A Wasmtime or native-host escape therefore reaches the user's process authority.
- Graceful termination kills children. A hard crash or power loss can leave a helper alive until its own runtime deadline; platform job objects and parent-death controls remain required.
- The checksum journals detect corruption and stale generations; they are not authentication against a malicious process already running as the same OS user.
- The supervisor is foreground-only. A per-user daemon needs authenticated local IPC, peer-credential checks, replay protection, authorization, liveness leases, and its own review.
- Service calls, independent command/HTTP probes, surge/unavailable rolling updates, ingress, secrets, and native adapters are not implemented and are not covered by this result. Process health, whole-generation transactional rollback, and guest-signalled application probes were added and reviewed separately after this document.
- Linux desktop production packaging remains blocked on the target-specific Tauri/GTK3 graph's 16 maintenance warnings and `glib` unsoundness advisory. Windows and macOS do not build that GTK dependency path.
- Fuzz coverage is bounded and internal. Independent review and platform sandbox penetration testing remain release gates.

Do not describe Cartridge as a complete Docker replacement or as safe for hostile third-party code until the native sandbox and independent-assurance gates are complete.
