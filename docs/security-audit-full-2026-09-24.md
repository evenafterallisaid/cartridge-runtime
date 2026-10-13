# Full security audit: 2026-09-24

Date: 2026-09-24

Scope: the Rust workspace, runtime/package boundaries, daemon and ingress protocol, engine lifecycle and routing, storage and blob handling, process containment, native desktop shell, desktop frontend, dependency audit tooling, and every repository fuzz target.

This is an internal verification pass, not an independent security assessment. It was performed on Windows with the current worktree. Existing worktree changes were preserved.

## Result

No new exploitable issue was confirmed by the executable checks that completed. The historical archive-inflation, unbounded Wasm table, and blocking-timeout findings have matching regression tests and those tests passed. The principal remaining risks are documented release gates, unavailable standalone PoC sources, and dependency-audit network failures.

## Evidence

Passed:

- `cargo fmt --all -- --check`
- `cargo test --workspace --all-targets --no-fail-fast -- --test-threads=1` progressed through the CLI, core, desktop, developer, and engine security suites; the apparent engine deadline stall was not reproducible in isolation
- `cargo test -p cartridge-engine daemon::tests::shared_client_enforces_the_response_deadline -- --exact --nocapture` passed
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`
- `cargo test --manifest-path apps/cartridge-desktop/src-tauri/Cargo.toml --all-targets`
- `cargo clippy --manifest-path apps/cartridge-desktop/src-tauri/Cargo.toml --all-targets -- -D warnings`
- `npm run build` from `apps/cartridge-desktop`
- `cargo fuzz list`: all 14 targets were discoverable
- `cargo fuzz build --sanitizer none` started successfully and compiled the fuzz dependency graph; completion output was not available before this record was written

The workspace tests directly exercised, among other cases, forged ZIP metadata and inflated-byte limits, package and asset tampering, bounded manifests and receipts, daemon authentication and replay rejection, ingress framing and deadlines, process-tree cleanup, routing identity and recovery, health/probe state, storage quotas and blob reachability, and desktop installed-byte binding.

## Incomplete or blocked checks

| Area | Status | Follow-up |
| --- | --- | --- |
| Historical standalone PoCs | `target/audit-pocs/` is absent in this checkout, so the three original PoCs could not be rerun as standalone artifacts | Restore or archive the PoC sources and run them against the current CLI; retain peak-RSS and wall-time measurements |
| RustSec dependency audit | advisory database loaded, but registry/yanked-package checks timed out | Rerun `cargo audit` with working crates.io access and record the complete result, including yanked packages |
| npm dependency audit | blocked by TLS certificate verification against registry.npmjs.org | Rerun `npm audit --audit-level=high` from a trusted network or CI runner |
| Optimized workspace tests | still compiling when this report was prepared; no final result was captured | Rerun `cargo test --workspace --release --no-fail-fast` and retain the final summary |
| Fuzz execution | targets compiled/listed, but no fuzzing campaign was run on Windows | Run bounded CI fuzz campaigns with corpus/crash artifacts and sanitizer support |

## Follow-up security work

1. Add platform-native worker authority controls: Windows restricted token/AppContainer, macOS sandboxing, and Linux namespaces/seccomp/cgroups.
2. Add kernel-enforced CPU, RSS, I/O, process-count, and disk quotas; portable Wasmtime budgets are not equivalent to OS quotas.
3. Add OS peer credentials and native ACLs to the local daemon transport.
4. Replace guest-signalled readiness as the only truth with isolated command and scoped HTTP probes when those adapters are implemented.
5. Review future ingress for TLS, connection draining, rate limiting, load balancing, service authorization, and connection-cache fencing.
6. Obtain an independent security assessment, signed installer/release evidence, reproducible release artifacts, long-duration soak results, and cross-platform fuzz evidence.
7. Investigate the occasional apparent full-suite pause around `shared_client_enforces_the_response_deadline`; the isolated test passed, but the suite should be rerun serially and under a bounded watchdog before release.

## Residual boundary

The project still does not claim safe execution of hostile cartridges. In-process library embedders must supply their own process boundary, same-user filesystem tampering can deny service, traces may contain sensitive replay data, and the current controls do not replace an operating-system authority sandbox. See the [threat model](threat-model.md), [security policy](../SECURITY.md), and the earlier [full audit](security-audit-full-2026-09-01.md) for the maintained assumptions and historical findings.