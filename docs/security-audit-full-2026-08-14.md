# Whole-repository security review

Date: 2026-08-14

Scope: every production Rust crate, the CLI and local daemon, the Tauri command boundary and frontend, package and state formats, engine plans and journals, worker process containment, CI configuration, both Rust lockfiles, the npm lockfile, examples, fixtures, and fuzz harnesses. This is an internal engineering review, not an independent penetration test.

## Result

No known critical or high-severity vulnerability remains in the implemented and reviewed boundaries after this round. The review fixed operator-budget propagation and verification defects, added Windows creation-time exploit mitigations, repaired a CI audit step that did not scan the lockfile it claimed to scan, and moved desktop lifecycle control behind the authenticated daemon boundary.

This result does not make Cartridge safe for arbitrary hostile third-party code. Portable capability and resource controls are substantially implemented, but native OS authority sandboxes, kernel resource controllers, peer-authenticated local IPC transports, and an independently reviewed release boundary remain open gates.

## Findings closed in this round

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| FULL-01 | high | stack operators could remove capabilities but could not independently lower package CPU, memory, deadline, storage, graphics, or audio budgets | per-instance ceilings now resolve to exact effective values in plan format 2 and are re-applied at the runtime boundary |
| FULL-02 | high | snapshot construction could receive package storage quotas before the operator ceiling was applied | snapshot branches now receive the effective byte, key, and value limits before any state operation |
| FULL-03 | medium | a holder of the daemon capability could recompute a valid plan digest after raising resource values; launch failed later, but the altered desired state could be journaled | apply and supervisor paths both reopen the exact installed package and reject any planned value that is not a ceiling before mutation or launch |
| FULL-04 | medium | Windows process-tree ownership did not apply a creation-time exploit-mitigation baseline | compatible DEP, SEHOP, ASLR, heap, handle, extension-point, font, and image-loading policies are now part of atomic child creation |
| FULL-05 | medium | putting internal limits into the generated public CLI graph caused default-stack exhaustion on ordinary Windows commands | the bounded strict document now crosses only the cleared private worker environment; ordinary `pack` is covered by the smoke test |
| FULL-06 | medium | CI's second `rustsec/audit-check` invocation used an unsupported `working-directory` input, so it rescanned the root lockfile instead of the Tauri lockfile | CI installs a pinned `cargo-audit`, explicitly scans both lockfiles, audits npm dependencies, and no longer grants the obsolete `checks: write` permission |
| FULL-07 | high | desktop apply, stop, and remove commands wrote the engine store directly, bypassing daemon serialization, shutdown fencing, and supervisor ownership | both CLI and desktop now use one bounded encrypted authenticated daemon client; desktop mutations have no offline direct-store fallback and the webview never receives control keys |

Detailed resource-governance evidence is in [security-audit-resource-governance-0.1.md](security-audit-resource-governance-0.1.md). The later engine-health and transactional-update additions have focused reviews in [security-audit-engine-health-0.1.md](security-audit-engine-health-0.1.md) and [security-audit-rollout-0.1.md](security-audit-rollout-0.1.md).

## Historical exploit regression status

The three working exploits reported against revision `2a30c6c` remain closed:

- WASI blocking waits are clamped to the remaining runtime deadline and the outer process supervisor supplies an independent hard wall-clock bound.
- archive inflation is streamed through actual-byte budgets and declared-size mismatches fail closed before an oversized payload is retained.
- Wasmtime tables, memories, instances, and store resources have independent limits; a small linear-memory allowance cannot hide unbounded `table.grow` host allocation.

The workspace test suite contains direct regressions for each boundary.

## Verification performed

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`: 228 tests passed
- Tauri `cargo test`: 4 tests passed
- Tauri `cargo clippy --all-targets -- -D warnings`
- production frontend TypeScript and Vite build from a clean `npm ci`
- normal reduced-budget stack execution and deterministic fuel exhaustion of the same exact package at a one-unit ceiling
- Windows parent-death, private-liveness, and descendant-tree termination tests with creation-time mitigations enabled
- `cargo audit` against the 277-package engine lockfile: zero vulnerability advisories
- `npm audit --audit-level=low` against the desktop lockfile: zero vulnerabilities
- `cargo audit` against the 453-package Tauri lockfile: zero vulnerability advisories and 17 allowed informational warnings described below
- all 14 fuzz targets compile on the stable toolchain
- source scan found no production `unsafe`, `todo!`, `unimplemented!`, TODO/FIXME markers, embedded private keys, common access-token patterns, or tracked credential files
- process-launch review found guest and daemon children routed through the containment layer; the one direct production `Command` call executes a developer-declared local build command and is not a guest execution path
- Tauri capability configuration exposes no filesystem, shell, opener, network, dialog, or process plugin permission; its content security policy is self-only apart from the required IPC origins

Short coverage-guided fuzz campaigns were attempted on Windows. The harnesses compiled, but the installed MSVC libFuzzer/ASan runtime could not execute (`STATUS_DLL_NOT_FOUND`), and the no-sanitizer fallback failed to link sanitizer-coverage section symbols. This review therefore does not count a live fuzzing campaign as evidence. CI or a dedicated Linux fuzz runner remains required for continuous campaigns.

## Dependency observations

The engine workspace and npm graph are clear in their current advisory databases. The Linux side of the Tauri 2.11.5 graph retains 17 allowed RustSec warnings:

- ten unmaintained GTK3 binding advisories (`RUSTSEC-2024-0411` through `RUSTSEC-2024-0420` where applicable)
- unmaintained `proc-macro-error` (`RUSTSEC-2024-0370`)
- five unmaintained `unic-*` crates (`RUSTSEC-2025-0075`, `0080`, `0081`, `0098`, and `0100`)
- `glib` iterator unsoundness (`RUSTSEC-2024-0429`)

These enter only through Tauri/Wry's Linux GTK3 backend. No supported Tauri update removes the graph in this revision. The warnings remain visible rather than ignored; do not claim the Linux desktop dependency graph is warning-free.

## Boundaries reviewed

### Untrusted formats

Archive, manifest, stack, plan, engine event, daemon frame, trace, snapshot, capsule, migration receipt, registry, release, media, collaboration, and settings inputs have explicit byte/count/work limits. Security-sensitive structures deny unknown fields, paths are normalized, archive and artifact identities are digest-bound, and durable replacement uses create-new or private atomic staging.

### Guest execution

Guests receive the WASI 0.2 Component Model surface selected by Cartridge, not ambient directories, sockets, environment, terminal, subprocess, or native device handles. Permissions are intersected with host and stack policy. Fuel, epochs, memory, tables, host resources, mediated I/O work, storage, trace, graphics, audio, and process wall time are bounded.

### Desired state and local control

Plans bind exact package identities, permissions, limits, replicas, and composition edges. Apply revalidates installed bytes before journal mutation. Transactional updates retain the exact previous generation, re-verify both activation and rollback packages, fence conflicting mutations, require stable process health, and recover journal/checkpoint crash windows. Journals, rollout checkpoints, compact rollout status, observed status, and daemon frames are integrity checked and bounded. Local control frames are confidential, authenticated, freshness checked, replay rejected, and tied to one daemon generation.

### Processes and desktop

Daemon, supervisor, and guest descendants are owned as a tree and carry private parent-liveness channels. Windows adds process-creation mitigations; Unix uses process groups. The desktop stores a reviewed plan and daemon credentials outside the webview, applies only its reviewed digest after another package verification, and fails closed on lifecycle mutations when authenticated control is unavailable. Webview plugin authority is empty.

## Residual risks and release gates

- No AppContainer/restricted token on Windows, sandbox profile on macOS, or namespace/Landlock/seccomp sandbox on Linux yet.
- No cgroup, Job Object memory/CPU-rate, macOS resource-policy, disk-I/O, handle-count, or engine-wide disk quota layer yet.
- An unknown Wasmtime, compiler, webview, native adapter, or operating-system vulnerability can cross the portable boundary.
- The daemon still uses authenticated loopback TCP rather than named pipes/Unix sockets with kernel peer credentials and ACLs.
- Rollouts replace a whole generation and rely on process stability; application probes, canary routing, and surge/unavailable rolling windows remain open scheduler gates.
- Same-user processes with direct filesystem authority remain partly outside the threat boundary.
- State and traces are integrity protected where documented but are not generally encrypted at rest.
- Live HTTP, device, GPU, and service-composition adapters require separate adapter-specific sandbox and confused-deputy reviews.
- Fuzz harnesses exist and compile, but continuous sanitizer-backed fuzzing is not yet a CI gate.
- The project has not received an independent security review.

Until those gates close, run unknown cartridges only inside a disposable, unprivileged operating-system account or VM and keep the repository's pre-alpha warning intact.
