# Contributing

Cartridge Runtime is early enough that design discussion is as useful as code. Open an issue before implementing a large capability or changing the WIT contract.

Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Changes to the cartridge format or WIT API must include compatibility notes and tests. Security-sensitive code should prefer explicit bounds, typed paths, and denial by default.
