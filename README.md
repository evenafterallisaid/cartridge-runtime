# Cartridge Runtime

Cartridge Runtime is an experimental, capability-based host for portable WebAssembly applications. An application and its assets are packed into one `.cartridge` file, then run through the same versioned interface on Windows, macOS, and Linux.

The project is deliberately small at this stage: it proves the complete path from a Rust component to a validated cartridge, a permission-aware Wasmtime host, and a replay-oriented execution trace.

## What works

- WebAssembly Component Model guests built against a versioned WIT contract
- Reproducible `.cartridge` packages with SHA-256 component verification
- Manifest-declared clock, randomness, packaged-asset, and scoped-storage capabilities
- Fuel, linear-memory, and wall-time limits set by each cartridge manifest
- `pack`, `inspect`, `verify`, `deps`, `resolve`, `run`, `replay`, and `trace` commands
- Deterministic trace recording, replay, and first-divergence detection
- Standalone trace validation, summaries, and trace-to-trace diffing
- Namespaced key/value storage with atomic quota checks and deterministic replay
- Checksummed durable storage with process locking and generation recovery
- Typed inter-cartridge service declarations and direct dependency resolution
- A complete example cartridge

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
cargo run -p cartridge-cli -- deps dist/hello.cartridge
cargo run -p cartridge-cli -- resolve dist/hello.cartridge
cargo run -p cartridge-cli -- run dist/hello.cartridge --trace dist/hello.trace.json -- Clyde
cargo run -p cartridge-cli -- run dist/hello.cartridge --state-dir dist/state -- Ada
cargo run -p cartridge-cli -- storage status dist/hello.cartridge --state-dir dist/state
cargo run -p cartridge-cli -- trace inspect dist/hello.trace.json
cargo run -p cartridge-cli -- trace diff dist/hello.trace.json dist/hello.trace.json
cargo run -p cartridge-cli -- replay dist/hello.cartridge dist/hello.trace.json -- Clyde
```

PowerShell accepts the same commands on one line, or with backticks in place of the shell continuations above.

## Why capabilities

A cartridge does not receive ambient access to the host computer. It can only call interfaces exposed by the runtime, and sensitive interfaces must also be granted in `Cartridge.toml`. Denials are normal return values rather than host crashes.

The initial API is intentionally narrow. Filesystem directories, network sockets, windows, audio, and GPU access will be added as separately versioned capabilities rather than as a single unrestricted system interface.

## Repository layout

```text
crates/cartridge-core/      package format, validation, and packing
crates/cartridge-runtime/   Wasmtime host, permissions, and execution limits
crates/cartridge-storage/   isolated storage contract and in-memory backend
crates/cartridge-trace/     versioned trace model, validation, and comparison
crates/cartridge-cli/       pack, inspect, and run commands
examples/hello-cartridge/   minimal Rust component and packaged asset
wit/                        public guest/host contract
docs/                       format, architecture, and roadmap
```

Read [the architecture](docs/architecture.md) for the trust model, [storage](docs/storage.md) for state isolation and replay rules, [the durable storage format](docs/storage-format.md) for commit and recovery behavior, [composition](docs/composition.md) for inter-cartridge services, [the trace format](docs/trace-format.md) for replay rules, and [the roadmap](docs/roadmap.md) for the path toward a complete desktop platform.

## Status

This is a pre-alpha runtime and its API will change. Do not execute cartridges you do not trust yet: capability checks reduce authority, but the runtime has not been independently audited.

## License

MIT
