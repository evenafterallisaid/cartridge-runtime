# 0.5 security review

Date: 2026-08-12

Scope: package parsing, manifest limits, Wasmtime configuration, capability dispatch, trace/replay, durable storage, CLI supervision, and the new graphics/input/audio/MIDI boundary.

The review combined manual data-flow analysis, limit and allocation tracing, hostile unit cases, debug and release test suites, dependency advisories, end-to-end component runs, replay comparisons, and fuzz-target compilation. No known exploitable issue remains in the reviewed 0.5 boundary.

## Findings fixed during this review

### M-01: native drawing work could amplify a cheap guest call

The first rasterizer draft clipped pixels while drawing, but a huge line or image destination could still make the host loop far beyond the visible canvas. Wasm fuel does not meter native host loops.

The renderer now validates logical dimensions, coordinate distance, extents, and line widths; estimates aggregate work before allocation; clips image iteration before entering the loop; and caps commands, pixels, assets, frames, work, and captured bytes. Once capture quota is exhausted, later calls fail before parsing or rasterization.

### M-02: audio buffers needed aggregate rather than per-node limits

Individual delay nodes were bounded, but many legal delay nodes could allocate more host memory than intended. Rejected renders near the capture ceiling could also repeat expensive work without consuming the remaining quota.

Graph validation now caps total delay samples, node × frame work, render count, and retained output bytes before or during the first failing call. The quota seals after an aggregate-output failure, preventing repeated native work. Graph ids are contiguous and topologically ordered, and every event/parameter pair is validated before rendering begins.

### M-03: malformed image dimensions could reach unsafe arithmetic assumptions

A zero-width image could reach a scaling division, and several internal conversions relied on invariants with `unwrap`. The public renderer now rejects zero dimensions and invalid payload lengths before rasterization. Image indexing uses checked conversion and slice access, and production media code contains no input-reachable `unwrap` or `expect`.

### M-04: replayed device events needed semantic revalidation

Trace JSON validation checked structure and budgets, but a manually altered trace could contain a structurally valid input or MIDI event that the live injection path would reject. Replay now runs the same text and MIDI validation before returning the event and reports a divergence on failure.

### M-05: media asset references needed their own narrow boundary

Draw calls initially cloned packaged asset vectors and accepted any lookup string. Media assets are now borrowed from the immutable package map, and names must be normalized relative paths under a 1024-byte limit. Missing, malformed, oversized, or path-like references fail the capability call.

### M-06: media traces needed to bind commands as well as output

A frame or graph receipt bound the final bytes, but two different documents with identical output could compare equal. Graphics and audio events now include the submitted document SHA-256 alongside the output receipt. Binary PNG/WAV content stays outside the trace.

## Regression coverage

The earlier audit findings remain covered:

- WASI waits are clamped to the execution deadline and the CLI has an independent killable worker deadline.
- ZIP entries are bounded while inflating and declared/actual size mismatches fail.
- linear memory, tables, table elements, instances, memories, host resources, fuel, and wall time have hard ceilings.
- trace growth, event count, output, trace input files, snapshots, logs, and transaction batches are bounded.
- storage locks use finite retries; terminal controls are escaped; outputs use exclusive creation and private Unix modes.
- runtime version is part of replay identity.

Media-specific regression cases cover hostile coordinates, zero-size and oversized images, capture exhaustion, invalid graphs, graph cycles, excessive work, aggregate delays, deterministic rendering, queue limits, independent permissions, invalid replay events, callback underruns, and device refresh without state mutation.

## Verification matrix

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo test --workspace --release`
- all four example component builds for `wasm32-wasip2`
- packaged visual, synth, and effect end-to-end runs
- visual and audio replay with byte-identical PNG/WAV output
- injected input and MIDI replay without live event files
- `cargo check --manifest-path fuzz/Cargo.toml --bins`
- RustSec audits for the workspace, fuzz workspace, and every example lockfile
- scheduled Linux fuzzing for archive, manifest, snapshot, trace, transaction, reachability, graphics, and audio boundaries

Local libFuzzer execution on Windows requires the LLVM sanitizer runtime, which was not installed on the review machine. Both new targets compile as normal binaries locally and run under the repository's Linux fuzz workflow.

## Remaining platform boundaries

The public CLI clears the worker environment, removes stdin, applies runtime limits, and can kill a stuck worker. It does not yet apply restricted Windows tokens, macOS sandbox profiles, or Linux namespace/seccomp policy; those belong to the desktop sandbox milestone. Direct library users intentionally run Wasmtime and host calls in their own process.

Package ids are still self-declared until signing and trust policy arrive. Durable state directories therefore remain explicit operator-controlled inputs, not a shared public installation store. Native window presentation and audio device backends are also host adapters, never guest authority.

These constraints are documented rather than treated as completed security guarantees. Public exchange of untrusted cartridges still waits on the OS sandbox and signing milestones.
