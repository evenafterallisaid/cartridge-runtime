# 1.0 candidate security review

Date: 2026-08-13

Scope: package construction and parsing, manifest negotiation, Wasmtime configuration, WASI clocks and polling, host capabilities, trace/replay, durable and snapshot storage, identity and registry, signed runtime updates, the CLI worker boundary, media command documents, peer/network primitives, fuzz targets, CI workflows, and dependency advisories.

This is an internal review of the portable runtime boundary. It is not the independent review required before a 1.0 release.

## Result

No known sandbox escape or package-validation bypass remains in the reviewed boundary. Every finding reproduced during this round was patched and given a regression test or an end-to-end check. Platform-native helper sandboxing remains an explicit release gate.

## Findings fixed in this round

| id | severity | finding | resolution |
|---|---|---|---|
| RC-01 | high | a self-declared cartridge id could select another package's durable namespace through the public CLI | durable runs and administration now require an exact package signature verified by a trusted key; the worker verifies the same evidence before opening state |
| RC-02 | high | the stability harness executed guest work in its own process and could hang if a blocking-host regression returned | benchmark and soak commands now use a killable worker and a finite one-hour outer ceiling |
| RC-03 | medium | updater paths accepted some unexpected filesystem object types and inherited ambient directory permissions | updater roots are canonicalized; links, Windows reparse points, and non-regular files are rejected; private Unix modes are applied |
| RC-04 | medium | runtime installation buffered an entire artifact of up to 512 MiB | release creation, installation, and verification now use fixed-memory streaming hash/copy loops |
| RC-05 | medium | syntactically valid local corruption could alter updater activation state without detection | update state now has a canonical SHA-256 envelope, retains an interruption backup, and quarantines corrupt copies |
| RC-06 | low | release digests and versions were valid but not fully canonical or tightly length-bounded | signed digests are lowercase-only and semantic-version strings are ASCII and length-bounded |

Earlier regression coverage was rerun for wall-clock timeout escape through WASI polling, ZIP declared-size forgery/decompression bombs, unbounded Wasm tables, trace amplification, finite storage locks, bounded trace/snapshot parsing, terminal controls, create-new packaging, private files, and runtime-version replay binding.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`
- `cargo test --workspace --no-fail-fast`
- `cargo test --workspace --release --no-fail-fast`
- `cargo audit` against 263 locked dependencies: no vulnerable packages reported
- Windows end-to-end package negotiation, package signing/trust, signed runtime release creation/verification/install/status, supervised benchmark/soak, authenticated durable storage, and timeout-fixture execution
- release, WIT, archive, and manifest fuzz targets compile locally; execution is delegated to the pinned Ubuntu fuzz workflow because the installed Windows LLVM 22 ASan runtime does not match nightly Rust's LLVM 23 instrumentation ABI

## Residual and external gates

- The general worker is a killable process boundary, not yet an AppContainer/restricted-token, macOS sandbox, or Linux namespace/seccomp boundary.
- Direct library embedders must authenticate a package principal before attaching shared durable storage. The CLI enforces this for raw durable runs and storage administration; the desktop library and developer loop are local user-authorized workflows.
- Native GPU presentation, live HTTP, discovery, real audio devices, installers, and OS update handoff need separate adapter- and platform-specific reviews as they are implemented.
- Windows Authenticode, macOS signing/notarization, independent review, and externally collected platform stability baselines require credentials or third parties and are not marked complete.
- A malicious process already running as the same OS user can often tamper with user-owned files or invoke internal binaries directly. Hashes, locks, create-new writes, private modes, and trust checks reduce exposure but do not replace an OS account boundary.

Security reports follow [SECURITY.md](../SECURITY.md). The complete trust assumptions are in [the threat model](threat-model.md).
