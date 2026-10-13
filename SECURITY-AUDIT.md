# Security Audit: cartridge runtime

**Date:** 2026-08-09
**Scope:** `crates/cartridge-core`, `crates/cartridge-runtime`, `crates/cartridge-storage`, `crates/cartridge-cli`
**Method:** static review + three working proof-of-concept exploits against the released `cartridge.exe` CLI (commit 2a30c6c). All PoCs are reproducible; artifacts live in `target/audit-pocs/` (gitignored).

## Summary

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| F-01 | High | Wall-clock timeout (`timeout_ms`) is bypassable via WASI blocking calls | Confirmed, PoC |
| F-02 | High | Zip size limits enforced on untrusted declared sizes; decompression bomb loads 260 MiB from a 259 KB file | Confirmed, PoC |
| F-03 | High | Guest can allocate unbounded host memory via `table.grow` (no `table_elements` limit); 778 MiB RSS against a 64 MiB memory cap | Confirmed, PoC |

---

## F-01 — Timeout bypass via blocking WASI calls

**Files:** `crates/cartridge-runtime/src/lib.rs:110,114`, `crates/cartridge-runtime/src/lib.rs:147-166`, `crates/cartridge-runtime/src/host.rs:48-58`

**Mechanism.** The deadline is an *epoch* deadline: a background thread increments an epoch counter every 10 ms (`start_epoch_ticker`), and the store's deadline is set to `timeout_ms / 10` ticks (rounded up). Wasmtime only checks the epoch deadline **while executing guest instructions**. A guest that blocks inside a host call (e.g. `wasi:io/poll` / `poll_oneoff`, i.e. `std::thread::sleep` in a wasip2 guest) is never interrupted: the thread sits in the host sleep for as long as the subscription requests, then resumes, and only *then* the stale deadline fires (trapping the run). Fuel is also only consumed by guest instructions, so a sleep consumes zero fuel.

`host.rs:48-58` freezes the WASI clocks only when the `clock` permission is absent — with `clock = true` (a legitimate permission, granted in `examples/hello-cartridge/Cartridge.toml`) the real monotonic clock is exposed and sleeps are real.

**PoC (confirmed).** A component that calls `std::thread::sleep(20s)` inside `run`, packed with `timeout_ms = 1000`:

```
$ cartridge pack --component poc_guest.wasm --output sleeper.cartridge Cartridge.toml
packed Sleeper 0.1.0 -> sleeper.cartridge

$ cartridge run sleeper.cartridge
[info] sleeping 20s via WASI poll_oneoff (manifest timeout_ms = 1000)
Error: the component trapped while running: ... (epoch interrupt, fired only after the sleep returned)

WALL TIME: 20.3 s   (declared timeout_ms = 1000)
```

**Impact.** Any cartridge granted `clock` can pin a host thread for an arbitrary duration (the subscription timeout is a `u64` nanosecond value — years). A pure CPU spin is correctly cut off at ~`timeout_ms` (unit test `epoch_deadline_interrupts_compute` passes), so only blocking calls are exempt; but a `sleep` → resume → `sleep` loop restarts the budget every cycle. In a server context (one host thread per cartridge) this is a straightforward resource-exhaustion denial of service, and `timeout_ms` gives operators false assurance of a hard bound.

**Suggested fixes (any one suffices):**
- Enforce the deadline with a wrapper: run `call_run` on a dedicated worker thread and `join` with a `timeout_ms` wall-clock bound (drop the epoch machinery).
- Bound WASI wall/monotonic clocks to `timeout_ms` worth of ticks (e.g. a `VirtualMonotonicClock` that errors once the budget is spent).
- Restrict `wasi:clocks` / `poll_oneoff` subscriptions to the remaining deadline.

---

## F-02 — Zip size limits trust attacker-controlled declared sizes (decompression bomb)

**Files:** `crates/cartridge-core/src/archive.rs:73-91`

**Mechanism.** `PackageLimits` (`archive.rs:20-30`: 1 MiB manifest, 64 MiB component, 32 MiB asset, 256 MiB total, 4096 entries) are checked against `entry.size()` — the **declared** uncompressed size stored in the central directory, which is attacker-controlled and never cross-checked against the actual decompressed length. The read then allocates `Vec::with_capacity(entry.size())` and `read_to_end`'s the real bytes (`archive.rs:87-90`). A crafted archive declares a 1000-byte component, sails past every check, and materializes the true payload.

**PoC (confirmed).** `poc-zip` builds a legitimate zip whose `component.wasm` contains 260 MiB of zeros (deflate ratio ≈ 1000:1), then patches the uncompressed-size fields in the local file header (offset 22) and central directory entry (offset 24) down to 1000 bytes. `zip` 8.6.0 reads by actual stream length, so the full payload is inflated regardless:

```
forged archive written: 265451 bytes on disk, declared uncompressed size = 1000
CartridgeArchive::open() SUCCEEDED with component of 272629760 bytes (260 MiB)
-> the per-entry 64 MiB cap and the 256 MiB total cap were both bypassed
```

**Impact.** A 259 KB file on disk becomes 260 MiB of heap per `open()` — and the ratio is unbounded: a 64 GiB payload of zeros would inflate from ~64 MB on disk, turning `cartridge verify`, `run`, or any ingestion path into a memory-exhaustion primitive with no working limit.

**Suggested fixes:**
- Enforce limits *during* inflation: stream-decompress with a write-budget counter and abort once an entry exceeds its cap (reject by actual bytes, not declared bytes).
- Verify declared sizes: after `read_to_end`, compare `entry.size()` (or track real length) and reject mismatches.
- Inflate to a temp file / with bounded buffers instead of `read_to_end` into a `Vec` sized by an attacker-controlled number.

---

## F-03 — Unbounded host memory via `table.grow`

**Files:** `crates/cartridge-runtime/src/host.rs:64-66` (`StoreLimitsBuilder::new().memory_size(...).build()`), `crates/cartridge-runtime/src/lib.rs:108`

**Mechanism.** The `StoreLimits` configured for the guest caps only `memory_size`. The `table_elements` field is left at its default (`None` = unlimited), so `table.grow` is not bounded by any manifest knob. A malicious component can declare a funcref table with **no maximum** (limits flags `0x00`) and grow it until host memory is exhausted; funcref table elements cost 8 bytes of host memory each, so 2³¹ elements ≈ 32 GiB — and nothing in the manifest can stop it. `memory_bytes` only governs linear memory, giving a false sense of a 64 MiB ceiling.

**PoC (confirmed).** A hand-assembled core module (`(table 1 funcref)` + exported `grow`) run in a store configured byte-for-byte like the runtime (`memory_size(64 MiB)`, `consume_fuel(true)`, `epoch_interruption(true)`, `fuel = u64::MAX`):

```
table.grow(100_000_000) succeeded, previous size = 1
table now holds ~100000001 elements; at 8 bytes/element that is ~762 MiB of host memory
the manifest memory_bytes cap of 64 MiB does NOT apply to tables
PEAK WORKING SET: 777.8 MiB
```

The grow is a single host-side allocation and consumes only a handful of instructions, so fuel does not help either.

**Suggested fixes:**
- Set `table_elements` on the limiter, ideally from a manifest knob (or a fixed default such as 1 000 000 ≈ 8 MiB of table).
- Also consider `instances`/`memories`/`tables` StoreLimits fields if instances can be created via the component model, and document the remaining per-store limits.

---

## Notes on areas checked and found sound

- **Asset path validation** (`host.rs:is_safe_asset_path`): rejects absolute paths, `..`, backslashes, drive prefixes; assets are read from an in-memory map keyed by validated names — no traversal possible.
- **Storage backend** (`crates/cartridge-storage`): namespaces are stored under SHA-256-hashed directory names; keys never touch the filesystem; state files are size-capped (2 GiB), SHA-256-enveloped, generation-sorted, and pruned to two generations; cross-cartridge snapshot restore is rejected by identity; quotas enforced on `put` and restore.
- **Permission gating**: `clock`, `random`, `assets`, `storage` are each checked in the host implementation and recorded in the execution trace; denied calls are traced and replay divergences detected.
- **Network**: TCP/UDP/name lookup disabled on the WASI context (`host.rs:48-51`).
- **Integrity**: component and asset digests are verified after inflation (`archive.rs:128-155`) — but note this does not mitigate F-02, since the digest check happens after the bomb is already in memory.

## Reproduction

All three PoCs are standalone crates under `target/audit-pocs/`:

```
target/audit-pocs/poc-zip     cargo run --release   # F-02 (writes bomb.cartridge)
target/audit-pocs/poc-tables  cargo run --release   # F-03 (measures peak RSS)
target/audit-pocs/poc-guest   cargo build --target wasm32-wasip2 --release
                              # then pack + run with the real CLI (F-01)
```

They depend on `cartridge-core` / `wit` by absolute path and were verified against wasmtime 47.0.3 and zip 8.6.0 as pinned in the workspace `Cargo.toml`.
