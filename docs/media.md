# Media capabilities

WIT 0.3 adds deterministic graphics, input, audio, and MIDI without exposing native OS handles to a cartridge. The guest submits bounded JSON command documents through typed capability calls. JSON is used inside the versioned WIT envelope so the command models can gain optional versions before becoming lower-level resource interfaces.

## Graphics

`window-open`, `window-resize`, and `window-close` manage opaque virtual-window handles. `graphics-present` accepts a frame with logical dimensions, a monotonic simulation tick, and an ordered command list. Coordinates are scaled to the target window using integer arithmetic.

The first command set contains clear, rectangle, line, raw RGBA image, and bitmap text operations. Images name packaged assets and declare their exact dimensions; the byte length must equal width × height × 4. Optional font assets use the compact `CFNT` format: the four-byte header `CFNT`, one byte each for glyph width and height, then packed row-major bits for ASCII 32 through 126. Missing or malformed assets fail the call.

Rendering is deliberately integer-only. Alpha blending, nearest-neighbor image scaling, line stepping, and coordinate scaling have no floating-point or platform-library dependency. PNG encoding uses fixed settings. A frame receipt records the raw RGBA and PNG SHA-256 digests.

The host rejects zero or excessive dimensions, distant coordinates, oversized extents, invalid line widths, excessive text, too many commands, work estimates above 100 million pixel operations, and captured output above 256 frames or 64 MiB. Image iteration is clipped before entering the loop, so a huge off-screen destination cannot turn into a host-side denial of service.

## Input and replay

`input-next` returns canonical keyboard, pointer, controller, text, and close events. The CLI can inject a bounded array with `--input events.json`. Text and queue lengths are checked before execution.

Live input is recorded in the trace. Replay reads the recorded event, validates it again, and never consults the injected or platform queue. Frame receipts are trace events, so a changed pixel produces an ordinary first-divergence report. `--media-dir` writes PNG sidecars and `media-report.json` without overwriting existing files.

## Audio

`audio-render` accepts a fixed 48 kHz, stereo, signed-16-bit graph. Nodes are contiguous and topologically ordered. The current set contains square, saw, triangle, and seeded-noise oscillators; gain; one-pole low-pass; bounded delay; and output. Parameters use integer or Q15 values.

Events are ordered by frame and applied before that exact sample. Offline output therefore has the same PCM and WAV digest on every supported host. Each receipt includes graph size, peak level, and both digests.

The manifest bounds nodes, events, and frames. The host also caps node × frame work, aggregate delay storage, document bytes, render count, and captured bytes before allocating. An invalid or overloaded graph fails one host call and does not affect storage or another render.

`RealtimeBuffer` is the adapter boundary for native output. The single producer writes pre-rendered PCM into a power-of-two atomic ring. The audio callback only reads atomics, copies samples into its caller-provided slice, and updates underrun counters; it allocates nothing and never enters guest code. Current fill, peak fill, estimated latency, underruns, overruns, capacity, and device-catalog generations are available to host telemetry.

Audio device catalogs are host-owned. A provider discovers devices and atomically refreshes the validated catalog outside guest execution; the built-in provider exposes the deterministic headless device, while native providers belong to the desktop adapters. Guests receive the stable format, not device enumeration or a callback. Replacing a catalog increments a generation and does not mutate the graph or cartridge state.

## MIDI

MIDI uses its own `permissions.midi` grant and `midi-next` call. Granting audio does not grant MIDI. Events are validated on injection and again during replay. This first contract carries bounded MIDI 1.0 channel messages; richer timestamped device routing can be added without folding it into audio authority.

## CLI artifacts

```text
cartridge run app.cartridge --trace run.json --media-dir media --input input.json --midi midi.json
cartridge replay app.cartridge run.json --media-dir replayed
```

The media directory contains numbered `.png` and `.wav` files plus a canonical report of filenames and receipts. Trace replay recomputes the artifacts and compares their receipts. CI additionally compares the emitted files byte for byte.
