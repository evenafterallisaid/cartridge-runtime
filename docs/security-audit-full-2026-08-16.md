# Full security audit: rolling executor milestone

Date: 2026-08-16

This is an internal review of the complete repository after adding daemon-owned concurrent-generation rolling execution. It is not an independent assessment and does not close the platform-native sandbox or kernel-resource gates.

## Result

No known critical or high-severity issue remains in the implemented and reviewed boundary after this round. The review found and fixed two high-impact rollout/launch flaws, hardened durable writes and developer-key handling, and added regression coverage around the new coordinator.

## Findings fixed

| ID | Severity | Finding and fix |
| --- | --- | --- |
| REX-01 | critical | Surge was enforced per matching instance name. A replacement that removed one 256-replica instance and added a differently named 256-replica instance could authorize 512 active workers. Progress validation now computes one stack-wide limit from the larger old/new topology plus bounded aggregate surge, and candidate starts are truncated to remaining global capacity. |
| REX-02 | high | A supervisor verified an installed package before spawning a worker, but the worker received only its path. Replacing the file between those operations could execute bytes different from the reviewed plan. Every run worker now receives the exact authorized SHA-256 and byte length, reopens the archive once, rejects any mismatch, and passes that verified archive directly into the runtime. |
| REX-03 | high | One stack-keyed supervisor owner could not safely represent old and candidate generations at the same time. Supervisor ownership, retry state, leases, status, probes, targets, and mutable state are generation-keyed; temporary dual authority exists only for the exact activated rollout. |
| REX-04 | high | A whole-generation desired record did not itself enforce per-ordinal rollout intent. Generation supervisors now read the authenticated execution checkpoint: candidates can start only enabled ordinals and previous replicas drain only after durable intent. |
| REX-05 | medium | A batch drain could spend the full timeout once per worker. All workers in a batch now share one absolute wall-clock deadline, preventing an attacker from multiplying shutdown time by replica count. |
| REX-06 | medium | Terminal candidate handling could be delayed behind another instance's ordinary start action. Terminal candidates now force rollback before any other rollout action. |
| REX-07 | medium | Retry bookkeeping for obsolete generations could grow across repeated failed rollouts. Retry entries are generation-keyed and pruned against currently authorized targets. |
| REX-08 | medium | A backwards wall-clock adjustment could invalidate coordinator timestamps and strand an otherwise recoverable rollout. Coordinator time is clamped against its validated durable record while process deadlines remain monotonic. |
| KEY-01 | high | Unix developer-key creation wrote bytes before changing the file to mode `0600`, leaving a brief permission race. The file is now created with mode `0600`; serialized secret buffers, decoded key bytes, and parsed secret strings are zeroized on success and failure. Identity readers also reject symlinks and non-regular files. |
| DUR-01 | medium | Several atomic replacements synced file contents but not the containing directory on Unix. Engine journals, rollout records, rollout progress, identity/registry state, release state, desktop library indexes, and app settings now sync their parent directory after publication or terminal deletion. |

## Rolling-executor invariants

- Old and candidate observations must match the exact stack, revision, generation, topology, and rollout record.
- Candidate starts and previous drains are durable, monotonic, bounded per ordinal, and checksummed before they affect a supervisor.
- Active workers never exceed `max(total previous replicas, total candidate replicas) + aggregate surge`, capped by the engine worker ceiling.
- Availability is not spent until the configured candidate readiness and minimum-ready conditions hold.
- Drains are acknowledged only from generation-specific observed state; late exits and stale run ids cannot advance a rollout.
- A terminal candidate, progress deadline, drain deadline, invalid package, or invalid durable checkpoint fails closed into rollback or an explicit error.
- Commit still passes the existing server-side stable-health gate. Rollback re-verifies every retained package before restoring the exact previous desired generation.

## Verification

- `cargo test --workspace`: passed, including 259 workspace unit/integration tests and all doc tests
- `cargo clippy --workspace --all-targets -- -D warnings`: passed
- `cargo clippy --all-targets -- -D warnings` for the Tauri workspace: passed
- `cargo fmt --all -- --check`: passed
- `cargo audit`: zero vulnerability advisories across the 277-package engine lockfile
- `cargo audit` for the Tauri lockfile: zero vulnerability advisories; 17 already-documented warnings from target-specific desktop dependencies
- `npm audit --audit-level=high`: zero vulnerabilities
- `npm run build`: passed
- `cargo check` for the Tauri application: passed
- source scan: no production Rust `unsafe` blocks, shell-command construction, private-key markers, common access-token patterns, `todo!`, `unimplemented!`, TODO, or FIXME markers
- `git diff --check`: passed

The regression set includes exhaustive small rollout schedules, disjoint-topology global surge enforcement, corrupt/replayed progress rejection, terminal-candidate rollback priority, terminal checkpoint cleanup, generation-fenced state/lease/probe ownership, a real two-replica daemon coordinator walk, authenticated health, process-tree termination, parent-death cascading, worker package identity rejection, and crash recovery across durable replacement boundaries.

## Residual risks and open gates

- Wasmtime, capability linking, resource ceilings, and process-tree containment are implemented. Restricted Windows tokens/AppContainer, macOS sandbox profiles, Linux namespaces/seccomp, and kernel CPU/RSS/I/O quotas are not. Arbitrary hostile native adapters are not in the reviewed trust boundary.
- The loopback control protocol is encrypted, authenticated, replay-protected, and rooted in a private per-user directory, but it does not yet authenticate operating-system peer credentials. The current local threat model trusts the owning OS user.
- Ready-only inbound routing is not implemented. Rolling execution preserves process availability but does not claim zero-downtime HTTP service.
- Stateful cross-generation handoff remains blocked on a required migration/rollback-receipt policy. Generation-keyed state prevents accidental implicit sharing.
- Direct in-process embedders choose to share their process with Wasmtime and host transports. The CLI/daemon worker boundary supplies the independent outer watchdog; embedders must provide an equivalent boundary for hostile workloads.
- Windows has no safe standard-library equivalent of Unix parent-directory `fsync`; file data is flushed and recovery checkpoints remain checksummed, but sudden-power-loss guarantees depend on the filesystem and OS.
- Tauri's cross-platform dependency graph retains the previously documented GTK3/unmaintained warnings, including `RUSTSEC-2024-0429` in a target-specific `glib` path. No vulnerable package is reported for the current Windows build, but desktop dependency migration remains release work.
- Independent review, signed/notarized installers, service-manager integration, and rollback-tested release channels remain external 1.0 gates.

Do not describe Cartridge as vulnerability-free, a complete Docker replacement, or safe for arbitrary hostile third-party workloads until those gates are complete.
