# Architecture

## Design goals

Cartridge Runtime separates portable application logic from operating-system authority. The same component should run on each supported desktop platform while the host remains responsible for permissions, resource limits, packaging, and future native integrations.

The current execution path is:

```text
.cartridge archive
  -> parse and validate manifest
  -> verify component and asset digests
  -> launch a supervised process tree with no inherited environment or guest stdin
  -> configure permissions, memory, fuel, and epoch deadline
  -> instantiate component with Wasmtime
  -> route WIT imports through HostState
  -> record events or inject and compare replay events
```

## Trust boundaries

The component is untrusted. The host validates all paths, bounds random-data requests, caps fuel, linear memory, table elements, table count, memory count, instance count, trace growth, media work, captured artifacts, and final output, and never extracts archive entries onto disk. Packaged assets are held in memory and addressed by normalized relative paths.

Graphics and audio calls execute native host code, so Wasm fuel alone cannot bound them. The renderer validates logical coordinates and dimensions, estimates pixel work before rasterization, clips image loops to the target, limits commands, assets, windows, frames, pixels, and captured bytes, and uses checked size arithmetic. The audio engine validates an ordered acyclic graph, node/event/frame work, aggregate delay storage, output capture, and sample ranges before allocation. These budgets are independent from guest linear memory.

The canonical window host is deterministic and headless. Window handles are opaque lifecycle tokens, not native OS objects. The desktop library defines a presenter boundary for accelerated output: a GPU adapter receives only a validated command stream, requires robust buffer access and helper-process isolation, and is constrained by buffer, texture, shader, command, and render-pass budgets. Canonical receipts still come from the CPU renderer because cross-driver pixels are not assumed to be byte-identical. The first audio backend is a fixed 48 kHz stereo offline renderer. Native audio-device adapters remain outside guest memory and connect to the same command contracts. The realtime PCM queue is preallocated and atomic; its consumer callback performs no allocation and never invokes guest code.

WASI is linked for language-runtime compatibility, but it is not the cartridge permission model. The context has no terminal, environment, arguments, or preopened directories, and its network interfaces are disabled. When clock or randomness permission is absent, the corresponding WASI services use inert deterministic providers instead of host state. Cartridges should use `cartridge:api/host` when they need observable, traceable capability results.

The `.cartridge` archive is also untrusted. Duplicate entries, malformed manifests, unexpected component names, oversized files, declared-size mismatches, and digest mismatches are rejected before execution. Entry and total limits are enforced while data is decompressed rather than trusting ZIP metadata.

Storage backends receive the validated cartridge id as an opaque namespace. Guests never choose a namespace or receive a host path. Per-value, key-count, and total-byte limits are checked before a write changes state. The in-memory backend is deterministic and useful for tests. The directory backend hashes namespace names, serializes writers with an operating-system file lock, and commits immutable checksummed generations while retaining one rollback point.

Portable snapshots sit above the backend contract. They contain sorted key/value state and cartridge identity, but no host path, lock, journal generation, timestamp, or platform metadata. Restore validates identity, integrity, and quotas before replacing a namespace in one locked generation. Dry runs use the same plan without committing it.

Migration rehearsal is separated from durable restore. The runtime derives the ordered steps from the package manifest, creates a new snapshot-backed store for every edge, and lets the guest advance only to that edge's declared destination schema. Intermediate snapshots must pass identity, integrity, and quota checks. No durable backend is opened, and a failed or trapped step discards its partial branch instead of publishing it.

Fuel provides a deterministic instruction budget. A separate runtime epoch ticker enforces the manifest wall-time deadline during guest execution. WASI monotonic subscriptions are clamped to the same remaining deadline, so a guest cannot escape the budget by sleeping inside a host poll call. Storage lock acquisition also has a fixed upper bound. Epoch timing is deliberately coarse and is not part of deterministic replay.

The public CLI treats component compilation and execution as untrusted work. It validates the bounded archive, launches a helper with a cleared environment and no guest-visible stdin, and kills the complete helper process tree if startup plus the manifest deadline is exceeded. Windows children receive a private kill-on-close Job Object through the `CreateProcessW` attribute list, so containment exists at process creation; a transaction terminates any partially created child if setup cannot commit. Unix children lead dedicated process groups. A private stdin pipe is reserved solely for parent liveness: EOF or unexpected input makes the child exit, so a hard parent crash does not strand the worker. Termination waits are bounded. This contains compiler crashes and gives the CLI a deadline independent of guest and WASI control flow. It is process containment, not yet a platform-native authority sandbox: kernel memory and CPU quotas, restricted Windows tokens, macOS sandbox profiles, and Linux namespace/seccomp policies remain future work. Direct users of the runtime library stay in process by design.

Applied stacks add a second control-plane layer. A checksum-bound desired generation expands into stable replica identities, and one supervisor owns that stack through an operating-system lock. It reopens every exact catalog package, creates state beneath stack/replica/package-digest roots, clears each worker environment, enforces a configured concurrency ceiling and 256 declared replicas, and persists bounded observed state after each transition. Run ids fence late exits from replacement attempts; finite exponential backoff and restart budgets prevent crash loops; Ctrl+C and termination signals kill owned process trees. Daemon-supervisor and supervisor-worker liveness pipes cascade hard parent failure without relying on cleanup handlers. The capability set reviewed in the stack plan is passed as a ceiling and intersected again inside `cartridge-runtime`, so process-launch code cannot widen manifest authority.

The rootless engine daemon owns those supervisors across client lifetimes. One per-root lease identifies the current daemon generation. A supervisor launched by the daemon checks both the private endpoint identity and the still-held daemon lease every 250 milliseconds, then terminates its workers if ownership disappears or changes. The control channel binds only to IPv4 loopback and does not speak HTTP. Each request and response is carried in a bounded length-prefixed frame protected by XChaCha20-Poly1305, direction-specific associated data, the boot instance id, random nonces, random request ids, a 30-second freshness window, and a finite replay cache. The random control key is stored in an atomically replaced private endpoint file, zeroized in memory on drop, and omitted from logs. Mutations are serialized, shutdown rejects later mutations, accepted clients drain before supervisor teardown, and finite client, frame, stack, supervisor, worker, event, and retry limits bound the control plane.

Durable state also requires authenticated or exact-byte identity. CLI runs and storage administration using `--state-dir` require `--storage-signature` and `--storage-trust`; the signature binds the exact package bytes, id, version, component, and asset root to a trusted developer key before the id can select a durable namespace. The stack supervisor instead isolates its engine-owned namespace beneath the exact package digest, so different unsigned bytes cannot inherit an earlier package's state. Cross-version stack state handoff will require an authenticated migration rather than an implicit directory reuse. Embedders that construct a shared persistent backend directly must enforce an equivalent policy.

The first release is not a complete sandbox. Wasmtime provides the component isolation boundary, the host controls which imports are linked, and the CLI adds crash-resistant process-tree containment. Signed packages, cache isolation, kernel resource limits, operating-system authority sandbox profiles, and independent review are required before cartridges should be treated as safe to exchange publicly.

## Portability boundary

The WIT package is the portable ABI. A component imports `cartridge:api/host`, not Win32, Cocoa, or a Linux desktop API. Platform adapters can later implement richer capabilities behind stable interfaces:

```text
cartridge component
        |
        v
versioned WIT capabilities
        |
   +----+----+
   |    |    |
Windows macOS Linux
```

Applications that only use common capabilities remain byte-for-byte portable. Target-specific capabilities will live in explicit packages so portability loss is visible in component metadata.

## Cartridge relationships

Isolation is the default, not a ban on cooperation. A cartridge may declare a dependency on a specific version range and a precise list of WIT interfaces. The resolver selects a technically compatible provider, while a separate grant policy decides whether the connection is allowed.

Calls will pass through a runtime broker. The caller receives the declared service interface, not the provider's memory, storage, or other capabilities. Any delegated resource is restricted to the intersection of provider authority, interface contract, caller grant, and resource scope.

The manifest, direct resolver, exact-byte lock, and installed-library catalog resolution are implemented. Live multi-instance wiring and persistent relationship grants are not yet implemented. The full design is in [composition.md](composition.md).

## Tracing and replay

Every call through the cartridge capability API receives a monotonically increasing sequence number. Trace format v2 binds the recording to a runtime version, component digest, and argument list. During replay, nondeterministic clock, random, input, and MIDI results come from the trace; deterministic graphics and audio receipts are recomputed and compared. Output, fuel usage, missing events, extra events, media digests, and trace growth limits are checked after execution.

Trace types live in `cartridge-trace`, which does not depend on Wasmtime or the package reader. This lets the CLI and future debugger validate, summarize, and compare recordings without loading executable code.

Replay currently works at capability boundaries. The next debugger layer will add linear-memory checkpoints and state hashes, which are needed for reverse stepping inside longer executions.

The trace format is versioned independently from the cartridge format so either can evolve without silently changing the other.
