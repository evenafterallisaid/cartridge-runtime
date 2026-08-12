# Cartridge Runtime

Cartridge Runtime is an experimental, capability-based host for portable WebAssembly applications. An application and its assets are packed into one `.cartridge` file, then run through the same versioned interface on Windows, macOS, and Linux.

The project now covers the path from a Rust component to a validated cartridge, a permission-aware Wasmtime host, deterministic media output, persistent state, and replay-oriented execution traces.

## What works

- WebAssembly Component Model guests built against a versioned WIT contract
- Reproducible `.cartridge` packages with component hashes and Merkle-style asset roots
- Manifest-declared clock, randomness, packaged-asset, scoped-storage, graphics, audio, and MIDI capabilities
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
- Typed inter-cartridge service declarations and direct dependency resolution
- Deterministic virtual windows, resolution-independent drawing, image/font assets, input queues, and PNG capture
- Fixed-format audio graphs, sample-accurate events, bounded delay/effect nodes, deterministic WAV rendering, and callback telemetry
- Visual, synthesizer, and effect reference cartridges
- Safe project scaffolding, build/watch/run, profiling, API preflight, and conformance replay
- Verified installed-cartridge library with permission preflight, revocation, history, and safe mode
- Canonical CPU graphics plus an isolated, resource-bounded GPU presenter contract

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
cargo run -p cartridge-cli -- asset verify dist/hello.cartridge message.txt
cargo run -p cartridge-cli -- deps dist/hello.cartridge
cargo run -p cartridge-cli -- resolve dist/hello.cartridge
cargo run -p cartridge-cli -- run dist/hello.cartridge --trace dist/hello.trace.json -- Clyde
cargo run -p cartridge-cli -- run dist/hello.cartridge --state-dir dist/state -- Ada
cargo run -p cartridge-cli -- storage status dist/hello.cartridge --state-dir dist/state
cargo run -p cartridge-cli -- storage export dist/hello.cartridge --state-dir dist/state --output backup.cartridge-state.json
cargo run -p cartridge-cli -- storage inspect backup.cartridge-state.json
cargo run -p cartridge-cli -- storage migration-plan dist/hello.cartridge --from-schema 0
cargo run -p cartridge-cli -- storage migrate app.cartridge old.cartridge-state.json --output migrated.cartridge-state.json
cargo run -p cartridge-cli -- storage migrate-commit app.cartridge --state-dir dist/state --rollback-output rollback.cartridge-state.json --receipt-output migration-receipt.json
cargo run -p cartridge-cli -- storage migration-recover app.cartridge migration-receipt.json --state-dir dist/state
cargo run -p cartridge-cli -- capsule create dist/hello.cartridge --source before.cartridge-state.json --trace run.trace.json --result after.cartridge-state.json --output run.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule verify run.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule diff run.cartridge-capsule.json other.cartridge-capsule.json
cargo run -p cartridge-cli -- capsule replay run.cartridge-capsule.json
cargo run -p cartridge-cli -- run dist/hello.cartridge --from-snapshot backup.cartridge-state.json --snapshot-output branch.cartridge-state.json -- Test
cargo run -p cartridge-cli -- storage restore dist/hello.cartridge backup.cartridge-state.json --state-dir dist/state --dry-run
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
cargo run -p cartridge-cli -- library preflight dev.cartridge.hello --root dist/library
cargo run -p cartridge-cli -- library grant dev.cartridge.hello clock assets storage --root dist/library
cargo run -p cartridge-cli -- library run dev.cartridge.hello --root dist/library -- Clyde
```

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
crates/cartridge-media/     deterministic drawing, input, audio, and realtime buffers
crates/cartridge-runtime/   Wasmtime host, permissions, and execution limits
crates/cartridge-storage/   isolated state backends, snapshots, and content-addressed blobs
crates/cartridge-trace/     versioned trace model, validation, and comparison
crates/cartridge-cli/       pack, inspect, and run commands
examples/hello-cartridge/   minimal Rust component and packaged asset
examples/visual-cartridge/  deterministic 2D and input reference
examples/synth-cartridge/   sample-accurate synth reference
examples/effect-cartridge/  bounded delay-effect reference
wit/                        public guest/host contract
docs/                       format, architecture, and roadmap
```

Read [the architecture](docs/architecture.md) for the trust model, [developer workflow](docs/developer-workflow.md), [desktop library](docs/desktop-library.md), [media capabilities](docs/media.md) for graphics/audio contracts and limits, [storage](docs/storage.md) for state isolation and replay rules, [content-addressed blobs](docs/blob-store.md) and [reachability manifests](docs/blob-reachability-format.md) for larger immutable data, [the durable storage format](docs/storage-format.md) for commit and recovery behavior, [the snapshot format](docs/snapshot-format.md) for portable state transfer, [state migrations](docs/migrations.md) and [migration receipts](docs/migration-receipt-format.md) for upgrade recovery, [execution capsules](docs/capsule-format.md) for reproducible artifact binding, [composition](docs/composition.md) for inter-cartridge services, [the trace format](docs/trace-format.md) for replay rules, and [the roadmap](docs/roadmap.md) for the path toward a complete desktop platform.

## Status

This is a pre-alpha runtime and its API will change. Do not execute cartridges you do not trust yet: capability checks reduce authority, but the runtime has not been independently audited.

## License

MIT
