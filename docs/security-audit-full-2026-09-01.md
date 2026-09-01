# Whole-repository security review

Date: 2026-09-01

Scope: workspace and desktop dependency graphs, runtime execution boundary, local daemon protocol, desired and observed engine state, rolling updates, new routing membership, filesystem replacement and recovery, process containment, package identity, desktop commands, and frontend supply chain.

## Result

The review found and fixed two newly published Wasmtime vulnerabilities, one yanked cryptographic transitive dependency, and six routing-boundary issues during implementation. No known RustSec vulnerability remains in the core workspace lockfile after upgrading to Wasmtime 47.0.4. No known exploitable issue remains in the implemented routing-membership layer after the focused adversarial review.

The desktop Rust graph has no reported vulnerability, but RustSec continues to flag 17 allowed upstream warnings: the Linux Tauri/WebKit GTK3 chain includes unmaintained bindings and the existing `glib` 0.18 iterator unsoundness advisory. They remain release risk even though the audited Windows build does not exercise that GTK path. This is not an independent assessment and does not claim the project is vulnerability-free.

## Findings fixed in this round

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| FULL-09-01 | high | Wasmtime 47.0.3 was affected by RUSTSEC-2026-0269, a filesystem sandbox escape involving trailing slashes in paths or symlinks | pinned the workspace Wasmtime, WASI, and WASI I/O line to 47.0.4 and regenerated the complete dependency family |
| FULL-09-02 | medium | Wasmtime 47.0.3 was affected by RUSTSEC-2026-0268, allowing guest-controlled host heap allocation through WASIp3 streams | upgraded to 47.0.4; the runtime currently links preview 2, but the vulnerable dependency version is no longer accepted |
| FULL-09-03 | low | both lockfiles retained yanked `chacha20` 0.10.1 | updated the core and Tauri graphs to 0.10.2 and re-ran authenticated-channel tests |
| FULL-09-04 | critical | route removal could lag durable drain intent | route membership is now published before drain intent becomes visible to supervisors |
| FULL-09-05 | high | valid but stale routing state could survive health, run, desired-state, or rollout changes | daemon reads independently derive and compare authoritative membership, failing closed on any mismatch |
| FULL-09-06 | high | routing corruption recovery could reset a sequence into an earlier consumer-visible identity | a random epoch scopes each monotonic sequence and rotates on repair |
| FULL-09-07 | medium | one corrupt stack route could stop global daemon reconciliation | regular-file corruption is safely rebuilt and unrecoverable stack-local errors no longer terminate unrelated reconciliation |
| FULL-09-08 | medium | routing files needed explicit type, byte, cardinality, ordering, identity, and checksum bounds | added strict documents, regular-file enforcement, a 1 MiB read cap, aggregate replica ceiling, sorted uniqueness, generation/run fencing, and checksum verification |
| FULL-09-09 | medium | a backwards wall clock could regress publication time during a membership change | changed publications reject time below the previous valid snapshot; consumer ordering uses epoch and sequence |

The routing-specific reasoning and residual gates are in [the routing boundary review](security-audit-routing-0.1.md).

## Review evidence

- `cargo test --workspace --all-targets -- --test-threads=1`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo audit` with 1,235 RustSec advisories loaded: no core vulnerability or warning after remediation
- Tauri `cargo test --all-targets` and `cargo clippy --all-targets -- -D warnings`
- Tauri `cargo audit`: no vulnerability; 17 allowed upstream maintenance/unsoundness warnings retained below
- desktop `npm run build` and `npm audit --audit-level=high`: production build succeeds and reports zero vulnerabilities
- source scan across production Rust found no `unsafe` block; matches were rejection messages for unsafe paths
- focused tests cover stale health, corrupt and semantically changed route files, epoch rotation, backwards time, target ceilings, stopped-stack revocation, and route-before-drain ordering
- the daemon coordinator test exercises ready candidate admission, old replica removal, and final candidate-only membership through a two-replica rolling update

## Residual dependency warnings

The Tauri Linux graph retains warnings for `atk`, `atk-sys`, `gdk`, `gdk-sys`, `gdkwayland-sys`, `gdkx11`, `gdkx11-sys`, `gtk`, `gtk-sys`, `gtk3-macros`, `proc-macro-error`, `unic-char-property`, `unic-char-range`, `unic-common`, `unic-ucd-ident`, `unic-ucd-version`, and `glib`. The `glib` warning is RUSTSEC-2024-0429; the others are maintenance warnings. Removing them requires a supported Tauri/WebKit Linux dependency path rather than a local patch with equivalent assurance.

## Remaining release gates

- Native restricted-token/AppContainer, macOS sandbox, and Linux namespace/seccomp authority isolation are not complete.
- Portable budgets are not kernel CPU, RSS, I/O, process-count, or disk quotas.
- The loopback daemon capability is encrypted and authenticated but does not yet add OS peer credentials or native pipe/socket ACLs.
- Readiness is guest-signalled; isolated command and scoped HTTP probes remain necessary.
- Routing membership is not an inbound proxy. TLS, connection draining, rate limiting, load balancing, service authorization, and cache fencing must be reviewed when ingress is added.
- Same-user tampering can still deny service to engine state even when it cannot make changed state validate.
- Fuzzing, long-duration soak under the patched runtime, signed installers, reproducible release artifacts, and an independent security assessment remain external evidence gates.
