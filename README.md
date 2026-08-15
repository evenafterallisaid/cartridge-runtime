<p align="center">
  <img src="apps/cartridge-desktop/app-icon.svg" width="112" height="112" alt="Cartridge logo">
</p>

<h1 align="center">Cartridge Runtime</h1>

<p align="center"><strong>Portable WebAssembly applications with explicit capabilities, reproducible state, and a local-first control plane.</strong></p>

<p align="center">Component Model · Capability security · Deterministic replay · Native desktop</p>

Cartridge Runtime is an experimental, capability-based host for portable WebAssembly applications. An application and its assets are packed into one `.cartridge` file, then run through the same versioned interface on Windows, macOS, and Linux.

The project now covers the path from a Rust component to a validated cartridge, a permission-aware Wasmtime host, deterministic media output, persistent state, and replay-oriented execution traces.

## What works

- WebAssembly Component Model guests built against a versioned WIT contract
- Reproducible `.cartridge` packages with component hashes and Merkle-style asset roots
- Manifest-declared clock, randomness, packaged-asset, scoped-storage, graphics, audio, MIDI, and URL-scoped HTTP capabilities
- Exact-byte Ed25519 package signing, trust rotation/revocation, and immutable content-addressed registry publishing
- Encrypted peer sessions, convergent shared documents, verified asset transfer, rollback datagrams, and deterministic network simulation
- Host API/capability version negotiation and signed rollback-safe runtime updates
- Local-only cold-start benchmarks and deterministic long-running replay soak reports
- Fuel, linear-memory, and wall-time limits set by each cartridge manifest
- Bounded archive inflation, Wasm tables, WASI waits, traces, and storage-lock acquisition
- `pack`, `inspect`, `verify`, `deps`, `resolve`, `run`, `replay`, and `trace` commands
- Deterministic trace recording, replay, and first-divergence detection
- Standalone trace validation, summaries, diffing, and privacy-safe redacted exports
- Namespaced key/value storage with ABA-safe revisions, atomic batches, compare-exchange, and deterministic replay
- Checksummed durable storage with process locking and generation recovery
- Portable storage snapshots with inspection, diffing, dry runs, and transactional restore
- Isolated snapshot branches for speculative runs, migration testing, and debugging
- Manifest-declared state schemas with deterministic planning and isolated migration rehearsals
- Durable migration commits with automatic rollback capture, receipts, and recovery evidence
- Reproducible capsule manifests binding packages, source state, traces, and result state
- State-reproducing capsule replay on disposable snapshot branches
- Streaming content-addressed blobs with verified snapshot/capsule reachability and safe GC dry runs
- Checksummed blob root manifests plus deterministic inventory and full-store integrity audits
- Typed inter-cartridge service declarations, direct dependency resolution, exact locks, and verified installed-catalog resolution
- Deterministic virtual windows, resolution-independent drawing, image/font assets, input queues, and PNG capture
- Fixed-format audio graphs, sample-accurate events, bounded delay/effect nodes, deterministic WAV rendering, and callback telemetry
- Visual, synthesizer, and effect reference cartridges
- Safe project scaffolding, build/watch/run, profiling, API preflight, and conformance replay
- Verified installed-cartridge library with permission preflight, revocation, history, and safe mode
- Canonical CPU graphics plus an isolated, resource-bounded GPU presenter contract
- Generation-fenced stack reconciliation with per-replica state, bounded restarts, deadlines, and observed lifecycle status

## Quick start

Install the WASI 0.2 Rust target once:

```sh
rustup target add wasm32-wasip2
```

Build the host and example component:

```sh
cargo build
cargo build --manifest-path examples/hello-cartridge/Cargo.toml --target wasm32-wasip2 --release
```

Package and run it:

```sh
cargo run -p cartridge-cli -- pack examples/hello-cartridge/Cartridge.toml \
  --component examples/hello-cartridge/target/wasm32-wasip2/release/hello_cartridge.wasm \
  --assets examples/hello-cartridge/assets \
  --output dist/hello.cartridge

cargo run -p cartridge-cli -- inspect dist/hello.cartridge
cargo run -p cartridge-cli -- verify dist/hello.cartridge
cargo run -p cartridge-cli -- platform dist/hello.cartridge
cargo run -p cartridge-cli -- asset verify dist/hello.cartridge message.txt
cargo run -p cartridge-cli -- deps dist/hello.cartridge
cargo run -p cartridge-cli -- resolve dist/hello.cartridge
cargo run -p cartridge-cli -- resolve app.cartridge provider.cartridge --lock app.cartridge-lock.json
cargo run -p cartridge-cli -- resolve app.cartridge provider.cartridge --locked app.cartridge-lock.json
cargo run -p cartridge-cli -- run dist/hello.cartridge --trace dist/hello.trace.json -- Clyde
cargo run -p cartridge-cli -- identity keygen --output developer.key.json
cargo run -p cartridge-cli -- identity sign dist/hello.cartridge --key developer.key.json --output hello.signature.json
cargo run -p cartridge-cli -- identity trust hello.signature.json --store trust.json --label "local developer"
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json run dist/hello.cartridge --state-dir dist/state -- Ada
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json storage status dist/hello.cartridge --state-dir dist/state
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json storage export dist/hello.cartridge --state-dir dist/state --output backup.cartridge-state.json
cargo run -p cartridge-cli -- storage inspect backup.cartridge-state.json
cargo run -p cartridge-cli -- storage migration-plan dist/hello.cartridge --from-schema 0
cargo run -p cartridge-cli -- storage migrate app.cartridge old.cartridge-state.json --output migrated.cartridge-state.json
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json storage migrate-commit dist/hello.cartridge --state-dir dist/state --rollback-output rollback.cartridge-state.json --receipt-output migration-receipt.json
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json storage migration-recover dist/hello.cartridge migration-receipt.json --state-dir dist/state
cargo run -p cartridge-cli -- capsule create dist/hello.cartridge --source before.cartridge-state.json --trace run.trace.json --result after.cartridge-state.json --output run.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule verify run.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule diff run.cartridge-capsule.json other.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule replay run.cartridge-capsule.json
cargo run -p cartridge-cli -- run dist/hello.cartridge --from-snapshot backup.cartridge-state.json --snapshot-output branch.cartridge-state.json -- Test
cargo run -p cartridge-cli -- --storage-signature hello.signature.json --storage-trust trust.json storage restore dist/hello.cartridge backup.cartridge-state.json --state-dir dist/state --dry-run
cargo run -p cartridge-cli -- trace inspect dist/hello.trace.json
cargo run -p cartridge-cli -- trace diff dist/hello.trace.json dist/hello.trace.json
cargo run -p cartridge-cli -- trace redact dist/hello.trace.json --output dist/hello.trace-summary.json
cargo run -p cartridge-cli -- blob put dist/hello.trace.json --store dist/blobs
cargo run -p cartridge-cli -- blob list --store dist/blobs
cargo run -p cartridge-cli -- blob audit --store dist/blobs
cargo run -p cartridge-cli -- blob roots create --snapshot backup.cartridge-state.json --output backup.cartridge-blobs.json
cargo run -p cartridge-cli -- blob roots verify backup.cartridge-blobs.json --store dist/blobs
cargo run -p cartridge-cli -- blob gc --store dist/blobs --snapshot backup.cartridge-state.json
cargo run -p cartridge-cli -- replay dist/hello.cartridge dist/hello.trace.json -- Clyde
cargo run -p cartridge-cli -- conformance dist/hello.cartridge -- Clyde
cargo run -p cartridge-cli -- trace export dist/hello.trace.json --output dist/timeline.json
cargo run -p cartridge-cli -- stability benchmark dist/hello.cartridge --iterations 10 --output dist/benchmark.json -- Clyde
cargo run -p cartridge-cli -- stability soak dist/hello.cartridge --iterations 100 --output dist/soak.json -- Clyde
```

Create a project and use the developer loop:

```sh
cargo run -p cartridge-cli -- new demo --language rust
cargo run -p cartridge-cli -- check demo
cargo run -p cartridge-cli -- dev demo --once
```

Install and launch through permission preflight:

```sh
cargo run -p cartridge-cli -- library install dist/hello.cartridge --root dist/library
cargo run -p cartridge-cli -- library resolve dev.example.app --root dist/library --lock app.cartridge-lock.json
cargo run -p cartridge-cli -- library resolve dev.example.app --root dist/library --locked app.cartridge-lock.json
cargo run -p cartridge-cli -- library preflight dev.cartridge.hello --root dist/library
cargo run -p cartridge-cli -- library grant dev.cartridge.hello clock assets storage --root dist/library
cargo run -p cartridge-cli -- library run dev.cartridge.hello --root dist/library -- Clyde
```

Declare and inspect a local stack:

```sh
cargo run -p cartridge-cli -- stack validate tests/fixtures/Cartridge.stack.toml
cargo run -p cartridge-cli -- stack plan tests/fixtures/Cartridge.stack.toml --library dist/library --output dist/hello.stack-plan.json
cargo run -p cartridge-cli -- stack apply tests/fixtures/Cartridge.stack.toml --library dist/library --root dist/engine
cargo run -p cartridge-cli -- stack status hello-stack --root dist/engine
cargo run -p cartridge-cli -- stack supervise hello-stack --library dist/library --root dist/engine
cargo run -p cartridge-cli -- stack ps hello-stack --root dist/engine
cargo run -p cartridge-cli -- stack events hello-stack --root dist/engine
```

Optional instance budgets are upper bounds, not requests for more authority:

```toml
[instances.limits]
fuel = 5000000
memory_bytes = 33554432
timeout_ms = 5000
storage_bytes = 524288

[instances.health]
startup_timeout_ms = 1000
readiness_timeout_ms = 3000
liveness_timeout_ms = 1000
failure_threshold = 2

[instances.update]
order = "start-first"
max_surge = 1
max_unavailable = 0
min_ready_ms = 2000
progress_deadline_ms = 300000
drain_timeout_ms = 30000
```

Guests emit `started`, `ready`, `heartbeat`, and `unhealthy` through the host API. See [application health](docs/application-health.md) for the component call, timeout semantics, and security boundary. See [rolling updates](docs/rolling-updates.md) for the bounded policy and current scheduler status.

Stack planning resolves installed versions to exact package and composition hashes. Each instance can impose operator ceilings on fuel, linear memory, wall time, storage, graphics work, and audio work; plan format 4 binds those ceilings, optional application-health policy, and rolling-update policy before the runtime intersects authority again. Apply records the desired state in a private, checksum-chained journal and is idempotent. The foreground supervisor re-verifies those bytes, runs a configurable bounded worker set, enforces the reviewed capability and resource ceilings inside the runtime, applies finite restart/backoff policy, isolates state by stack/replica/exact package, and persists checksum-bound observed status. Workers and their descendants are owned as one process tree, with parent-death channels and bounded termination.

Run the persistent rootless engine in a terminal or user service manager, then control it from other processes:

```sh
cargo run -p cartridge-cli -- engine serve --root dist/engine --library dist/library
cargo run -p cartridge-cli -- engine ping --root dist/engine
cargo run -p cartridge-cli -- engine apply tests/fixtures/Cartridge.stack.toml --root dist/engine
cargo run -p cartridge-cli -- engine update tests/fixtures/Cartridge.stack.toml --root dist/engine --timeout-ms 30000
cargo run -p cartridge-cli -- engine rollout status hello-stack --root dist/engine
cargo run -p cartridge-cli -- engine wait hello-stack --root dist/engine --timeout-ms 30000
cargo run -p cartridge-cli -- engine health hello-stack --root dist/engine
cargo run -p cartridge-cli -- engine ps hello-stack --root dist/engine
cargo run -p cartridge-cli -- engine events hello-stack --root dist/engine --tail 50
cargo run -p cartridge-cli -- engine stop hello-stack --root dist/engine
cargo run -p cartridge-cli -- engine shutdown --root dist/engine
```

The daemon owns reconciliation after the invoking terminal is gone. Its loopback protocol is non-HTTP, length-bounded, encrypted and authenticated with a random per-boot capability, bound to one engine instance, freshness checked, and replay rejected. The capability is published only in the private engine root and never printed. Supervisor and worker limits are explicit startup settings with hard safety ceilings. Supervisors publish checksum-bound heartbeats, and the authenticated health API distinguishes starting, running, completed, degraded, failed, stopped, removed, and stale generations. Instances with `[instances.health]` stay unready until the guest reports `ready` through the host API; startup, readiness, liveness, and consecutive-failure limits drive restart policy and rollout rollback. Probe reports are run-bound, sequence-fenced, encrypted and authenticated at rest, bounded to 4 KiB, and cleaned under the supervisor lease. `engine wait` supplies a deadline-bounded application-readiness gate for automation. `engine update` uses a durable prepare, activate, stability-and-health-gate, commit transaction and restores the exact previous desired generation if activation or readiness fails. The stability window begins at application readiness for probed workers. Manual rollout commands expose the same checkpoints for inspection and recovery. A deterministic per-replica scheduler validates start-first/stop-first policy, stack-wide surge and unavailable budgets, topology changes, minimum-ready time, progress deadlines, drain timeouts, and terminal-candidate rollback without allowing inconsistent observations. The daemon executes checksummed per-ordinal actions through concurrently fenced old and candidate supervisors, waits for configured readiness, shares one bounded drain deadline, and resumes or rolls back from the durable checkpoint after restart. Each worker reopens and matches the exact authorized package digest before execution. Ready-only ingress, HTTP/command probes, state migration gates, and canary scheduling remain later layers. Windows children enter kill-on-close Job Objects with DEP, ASLR, heap, extension-point, font, and image-loading mitigations applied at process creation; macOS and Linux children enter dedicated process groups; every daemon-supervisor-worker edge also has a private liveness pipe. Native service installation, kernel CPU/RSS policy, restricted-token/AppContainer and Unix authority sandboxes remain open layers.

Run the native desktop shell:

```sh
cd apps/cartridge-desktop
npm ci
npm run tauri dev
```

The desktop connects to the same encrypted authenticated local daemon as the CLI. It shows daemon capacity plus live or last-recorded replica lifecycle, restart, run, and exit state. It can load a stack manifest, review exact hashes, resource ceilings, and effective permissions, then apply that reviewed digest, stop it, or tombstone it. Mutations fail closed while the daemon is unavailable; offline state remains inspectable. The backend keeps the control key and reviewed plan outside the webview and re-verifies every installed package before apply. Light, dark, density, motion, and new-stack defaults persist in the private app-data directory.

Build and run the visual reference with a replayable screenshot sidecar:

```sh
cargo build --manifest-path examples/visual-cartridge/Cargo.toml --target wasm32-wasip2 --release
cargo run -p cartridge-cli -- pack examples/visual-cartridge/Cartridge.toml \
  --component examples/visual-cartridge/target/wasm32-wasip2/release/visual_cartridge.wasm \
  --output dist/visual.cartridge
cargo run -p cartridge-cli -- run dist/visual.cartridge --trace dist/visual.trace.json --media-dir dist/visual-media --input examples/visual-cartridge/input.json
cargo run -p cartridge-cli -- replay dist/visual.cartridge dist/visual.trace.json --media-dir dist/visual-replay
```

`--input` and `--midi` accept bounded JSON arrays of canonical events. Their values enter the trace, so replay does not consult live devices. Every captured PNG and WAV has a receipt in both its capability event and `media-report.json`; `trace diff` and replay therefore act as screenshot and audio regression runners.

PowerShell accepts the same commands on one line, or with backticks in place of the shell continuations above.

## Why capabilities

A cartridge does not receive ambient access to the host computer. It can only call interfaces exposed by the runtime, and sensitive interfaces must also be granted in `Cartridge.toml`. Denials are normal return values rather than host crashes.

The API is intentionally narrow. Arbitrary filesystem directories, network sockets, and raw GPU/device access remain unavailable rather than forming one unrestricted system interface. Graphics and audio use host-owned command graphs; guests never receive a native window, device, mapped GPU allocation, or callback handle. CPU rendering supplies canonical replay output, while the desktop boundary permits a separately sandboxed GPU presenter for interactive acceleration.

## Repository layout

```text
crates/cartridge-core/      package format, validation, and packing
crates/cartridge-dev/       scaffolding, project checks, reload policy, and editor metadata
crates/cartridge-desktop/   installed library, permission UX, recovery, and presenter policy
crates/cartridge-engine/    declarative stacks, desired state, and replica reconciliation
crates/cartridge-media/     deterministic drawing, input, audio, and realtime buffers
crates/cartridge-identity/  developer keys, signatures, trust, and immutable registry
crates/cartridge-network/   scoped HTTP, encrypted peers, sync, and simulation
crates/cartridge-release/   signed runtime metadata, installation, and rollback
crates/cartridge-runtime/   Wasmtime host, permissions, and execution limits
crates/cartridge-storage/   isolated state backends, snapshots, and content-addressed blobs
crates/cartridge-trace/     versioned trace model, validation, and comparison
crates/cartridge-cli/       pack, inspect, and run commands
apps/cartridge-desktop/     Tauri desktop control-plane shell
examples/hello-cartridge/   minimal Rust component and packaged asset
examples/visual-cartridge/  deterministic 2D and input reference
examples/synth-cartridge/   sample-accurate synth reference
examples/effect-cartridge/  bounded delay-effect reference
wit/                        public guest/host contract
docs/                       format, architecture, and roadmap
```

The [whole-repository security review](docs/security-audit-full-2026-08-16.md) records the current audit result, closed findings, evidence, dependency observations, and remaining release gates. The [resource-governance review](docs/security-audit-resource-governance-0.1.md) provides the focused operator-budget and Windows creation-time hardening analysis. The [application-probe review](docs/security-audit-probes-0.1.md) covers guest-reported readiness, liveness enforcement, and the encrypted worker/supervisor signal channel.

Read [the platform status](docs/platform-status.md) for an exact implemented-versus-missing breakdown, [the architecture](docs/architecture.md) for the trust model, [the threat model](docs/threat-model.md), [the latest full security audit](docs/security-audit-full-2026-08-16.md), [1.0 candidate review](docs/security-audit-1.0-rc.md), [engine review](docs/security-audit-engine-0.1.md), [engine-health review](docs/security-audit-engine-health-0.1.md), [rollout review](docs/security-audit-rollout-0.1.md), [supervisor review](docs/security-audit-supervisor-0.1.md), [daemon review](docs/security-audit-daemon-0.1.md), [process-containment review](docs/security-audit-process-containment-0.1.md), and [desktop review](docs/security-audit-desktop-0.1.md) for security boundaries and current findings, [identity and registry](docs/identity-and-registry.md) for signed distribution, [runtime updates](docs/runtime-updates.md) for signed installation and rollback, [the compatibility policy](docs/compatibility-policy.md) for support guarantees, [networking](docs/networking.md) for HTTP and device-mesh boundaries, [developer workflow](docs/developer-workflow.md), [desktop library](docs/desktop-library.md), [media capabilities](docs/media.md) for graphics/audio contracts and limits, [storage](docs/storage.md) for state isolation and replay rules, [backup and recovery](docs/backup-and-recovery.md), [telemetry and performance](docs/telemetry-and-performance.md), [content-addressed blobs](docs/blob-store.md) and [reachability manifests](docs/blob-reachability-format.md) for larger immutable data, [the durable storage format](docs/storage-format.md) for commit and recovery behavior, [the snapshot format](docs/snapshot-format.md) for portable state transfer, [state migrations](docs/migrations.md) and [migration receipts](docs/migration-receipt-format.md) for upgrade recovery, [execution capsules](docs/capsule-format.md) for reproducible artifact binding, [composition](docs/composition.md) for inter-cartridge services, [the trace format](docs/trace-format.md) for replay rules, and [the roadmap](docs/roadmap.md) for the path toward a complete component platform.

## Status

This is a pre-alpha runtime and its API will change. Do not execute cartridges you do not trust yet: capability checks reduce authority, but the runtime has not been independently audited.

## License

MIT
