# Roadmap

Cartridge is meant to become a small application platform, not just a command that launches WebAssembly. The long-term target is a runtime where a developer can build a cartridge once, run the same file on every supported desktop, understand every permission it requests, reproduce any failure, and move its state between devices.

This document is intentionally larger than a release checklist. It describes the systems the project needs, the order they should arrive in, and the point where each part is useful on its own.

## North star

A cartridge should be:

- portable across Windows, macOS, and Linux
- isolated from ambient operating-system authority
- inspectable before it runs
- deterministic when its capability inputs are recorded
- easy to build in more than one language
- capable of real graphics, audio, input, storage, and networking
- distributable as one signed file
- debuggable without requiring the original development machine

The runtime should be useful for small tools and plugins first, then grow toward games, music software, visual experiments, automations, and local-first applications.

## Product shape

The mature project will contain several related products that share the same formats and APIs:

```text
cartridge cli
  pack, inspect, run, replay, test, sign, publish

cartridge desktop
  library, permission prompts, windows, settings, debugger

cartridge sdk
  wit packages, generated bindings, templates, test host

cartridge registry
  signed packages, transparency data, dependency metadata

cartridge protocol
  package format, trace format, capability contracts, identity
```

These should remain separate crates or applications. The CLI must not depend on the desktop UI, the package format must not depend on Wasmtime, and guest SDKs must not need runtime internals.

## Engineering principles

1. Capabilities are narrow and deny by default.
2. Portable APIs come before platform-specific convenience APIs.
3. Every nondeterministic capability must have a record and replay story.
4. Formats are versioned independently from the runtime.
5. A cartridge never receives a raw home-directory path by accident.
6. The command-line workflow stays complete even after the desktop app exists.
7. Security claims require tests and a written boundary.
8. Compatibility breaks are acceptable before 1.0, but silent breaks are not.
9. New subsystems need one small reference cartridge before being considered usable.
10. The project should produce useful tools during development, not only at the end.

## Release line

Current development state: milestones 0.1 through 0.9 and the portable 1.0 candidate boundary are implemented at the library and reference-host level. The runtime now includes package identity, immutable signed distribution, scoped replayable HTTP, transport-independent encrypted device-mesh primitives, capability negotiation, authenticated durable-storage principals, signed runtime updates, rollback, and supervised stability tooling. External 1.0 release gates remain, while implementation has started on the 1.1 composition graph. Release labels here describe compatibility milestones, not published versions.

### 0.1 — package and execute

Purpose: prove that the file format, component boundary, and host can work together.

Included:

- `.cartridge` archive format
- normalized manifest and component digest
- WIT host contract
- Wasmtime component execution
- clock, randomness, logging, and packaged assets
- fuel and memory limits
- package path and size validation
- `pack`, `inspect`, and `run`
- initial host-call traces
- cross-platform CI

Exit criteria:

- the example builds and runs on all CI operating systems
- two builds from the same inputs produce identical package bytes
- malformed archives and undeclared capabilities fail predictably

### 0.2 — deterministic replay

Purpose: turn traces into executable bug reports.

Implemented:

- versioned trace headers with component identity and invocation arguments
- replay clock and random results without contacting the host
- compare deterministic calls such as logs and asset reads
- report the first divergent sequence, operation, and value
- reject traces from another component version or argument list
- compare final output and fuel use
- add `cartridge replay`
- document trace compatibility rules

Exit criteria:

- a recorded example replays without using the live wall clock
- changing an argument produces a useful first-divergence report
- truncating or extending a trace is detected
- malformed trace values cannot panic the host

### 0.3 — scoped persistent state

Purpose: let useful applications remember data without exposing arbitrary files.

Work:

- key/value interface for settings and small state
- opaque per-cartridge namespaces selected by the runtime
- total-byte, key-count, and per-value quotas
- ephemeral storage for tests
- storage events in replay traces
- replay reads from the trace without mutating live state
- deterministic key listing
- content-addressed blob interface for larger data
- per-cartridge storage directories owned by the runtime
- crash-safe atomic writes and recovery
- versioned migrations with dry runs and rollback points
- portable snapshot, inspect, diff, and restore commands
- optional snapshot encryption and redaction rules

Delivery slices:

1. In-memory key/value contract, namespace isolation, quotas, guest bindings, and replay semantics.
2. Durable directory backend with locking, immutable generation commits, corruption detection, and recovery tests on every CI platform.
3. Canonical snapshot format with content digests, CLI export/inspect/diff, dry runs, and transactional restore.
4. Isolated snapshot branches for speculative execution and migration rehearsals.
5. Manifest state schemas and deterministic migration-plan validation.
6. Migration execution against a snapshot branch before committing changes.
7. Automatic rollback capture, race-safe durable migration commit, and failure-preserving CLI supervision.
8. Pre-commit migration receipts and evidence-based recovery after supervisor or host interruption.
9. Content-addressed blobs, garbage collection, and references from key/value records:
   - [implemented] bounded streaming ingestion, verification, deduplication, and materialization
   - [implemented] finite-wait cross-process exclusion for reads, writes, and collection
   - [implemented] safe-by-default explicit-retain garbage collection
   - [implemented] canonical references and verified reachability from snapshots and capsules
   - [implemented] checksummed, path-free multi-artifact reachability manifests for backup sets
   - sign reachability manifests after package signing and trust-store policy exist
   - add guest-visible streaming blob resources after store quota and authorization semantics are fixed
10. [implemented] ABA-safe namespace revisions, compare-exchange, and bounded atomic guest batches across memory, snapshot, and durable backends.

The first eight slices, the storage-management plane of slice nine, and slice ten are implemented. Slice nine now has canonical references, artifact-derived reachability, reusable root manifests, verified inventory, integrity auditing, and fail-closed collection. Its remaining boundary is guest authority and streaming: per-cartridge store quotas, lifecycle ownership, and an async resource API must be fixed before cartridges can create or read blobs themselves. Durable state is opt-in through `--state-dir`, which keeps host-directory policy explicit until the desktop runtime owns a standard application-data location. Snapshots are independently versioned and exclude internal journal metadata while preserving the monotonic revision clock. State schemas now follow data through memory, durable generations, and portable snapshots. Manifests declare unambiguous monotonic migration edges, and the CLI can either rehearse those plans or capture a rollback snapshot and commit a successful result as one generation. Conditional commit compares the locked namespace with its source so a concurrent writer cannot be lost. A flushed pre-commit receipt binds that source and isolated migration revision to the only generation and digest the migration can create, making the supervisor's final crash window recoverable without trusting console output.

Migration design constraints:

- the manifest declares a monotonically increasing state schema version
- every migration names one source and destination schema version
- the runtime captures an automatic rollback snapshot before migration
- migration code runs against an isolated overlay, never the live namespace
- dry runs report key and byte changes without exposing stored values
- the transformed snapshot must pass integrity and quota validation
- committing a migration writes exactly one durable generation
- failed or trapped migrations leave the previous generation active
- interrupted commits are classified from immutable generation evidence rather than guessed
- downgrade support is explicit rather than inferred
- migration compatibility is tested on snapshots from every released schema

Later snapshot work includes selective exports, encrypted envelopes, signed backups, blob references, streaming import for large state, and redaction policies for support bundles. None of those should change the guest key/value ABI.

### Scouted platform opportunities

These directions fit the existing architecture, but their order follows the maturity of the standards they build on:

- **Atomic state transactions.** [implemented] Namespace-wide revision tokens, compare-exchange, bounded batches, portable revision snapshots, trace replay, and one-generation durable commits now form the synchronous foundation. Future work can map these semantics onto the WASI key/value atomic and batch interfaces without weakening the current ABA guarantees.
- **Reactive state watch streams.** Allow a cartridge to subscribe to changes it has authority to observe, with coalescing, bounded queues, and trace events. This belongs after async host calls and composition supervision so a slow consumer cannot stall storage commits.
- **Streaming content-addressed blobs.** Store large values as deduplicated chunks addressed by digest, keep small references in key/value state, and trace digests rather than payloads. The guest API should use component-model streams instead of buffering complete objects into linear memory.
- **State-and-trace capsules.** Bind a source snapshot, execution trace, package digest, and result snapshot into one inspectable crash or test artifact. Snapshot branches make the first version possible without memory checkpointing.
- **Determinism certificates.** Run the same capsule repeatedly across runtime versions or operating systems and emit a compact attestation over matching output, trace, fuel class, and result-state digest. This turns portability claims into reproducible evidence without pretending the certificate is a developer signature.
- **Crash-consistent activation journals.** Generalize migration receipts into prepare/commit evidence for package upgrades and composition-graph changes. New providers and state should become visible together, while restart recovery proves which graph was activated.
- **Capability leases.** Let a supervisor grant a bounded capability token with an expiry, call budget, and trace identity instead of permanently expanding a cartridge's authority. This is useful for one-shot file imports, user-mediated secrets, and temporary network access.
- **Parallel scenario matrices.** Fan out many runs from one immutable snapshot, then compare outputs, traces, fuel, and state diffs. This can become `cartridge test --matrix` once branch execution and a test manifest exist.
- **Portable interpreter fallback.** Investigate a Pulley backend for architectures where native code generation is unavailable or undesirable. It should complement, not replace, Wasmtime's compiled path and needs independent performance and sandbox measurements.
- **Async component services.** Adopt Component Model Preview 3 futures, streams, cancellation, and backpressure when the toolchain stabilizes. This unlocks long-lived cartridge services, blob streaming, watches, networking, and composition without inventing a private async ABI.

Standards tracked for this work include the official [WASI key/value proposal](https://github.com/WebAssembly/wasi-keyvalue), [WASI blobstore proposal](https://github.com/WebAssembly/wasi-blobstore), [Component Model repository](https://github.com/WebAssembly/component-model), and [Pulley RFC](https://github.com/bytecodealliance/rfcs/blob/main/accepted/pulley.md).

Exit criteria:

- cartridges cannot address another cartridge's data
- interrupted writes preserve the previous valid state
- a state snapshot can move between Windows and macOS
- migrations are testable before data is modified
- an interrupted migration can be classified without retrying guest code

### 0.4 — windows, drawing, and input

Purpose: make cartridges visible and interactive.

Implemented:

- window lifecycle capability
- keyboard, pointer, controller, and text input events
- resolution-independent 2D drawing API
- image and font assets
- frame scheduling and monotonic simulation time
- headless renderer for tests
- screenshot-based regression runner
- graphics limits and validation
- first visual reference cartridges

Delivery slices:

1. WIT 0.3 virtual-window lifecycle with opaque bounded handles.
2. Integer-scaled 2D command documents for clears, rectangles, lines, packaged RGBA images, and bitmap fonts.
3. Canonical keyboard, pointer, controller, text, and close events with bounded injection.
4. Cross-platform headless rasterizer with fixed PNG settings and raw/presentation digests.
5. Monotonic simulation ticks, trace-bound frame receipts, deterministic replay, and CLI media sidecars.
6. Pre-raster geometry, command, pixel, asset, work, frame-count, and captured-byte validation.
7. Visual reference cartridge and byte-for-byte replay regression in all-platform CI.

The first renderer should be deliberately constrained. A stable 2D command stream is more valuable than immediately exposing a complete native GUI toolkit. A later GPU interface can coexist with it.

The portable 0.4 boundary is complete. Native presentation is intentionally owned by the 0.7 desktop shell; adding an OS window adapter must not change the guest command stream or headless output.

Exit criteria:

- the same cartridge produces equivalent frames on all supported systems
- recorded input can be replayed headlessly
- invalid draw commands cannot crash the desktop host
- screenshots can be attached to trace reports

### 0.5 — real-time audio

Purpose: support instruments, effects, games, and visualizers.

Implemented:

- audio device discovery outside the guest
- fixed-format audio graph contract
- sample-accurate parameter events
- lock-free communication between runtime and audio callback
- offline rendering for deterministic tests
- underrun and latency telemetry
- WASM DSP node limits
- MIDI input as a separate permission
- example synthesizer and effect cartridges

Delivery slices:

1. Fixed 48 kHz stereo signed-16-bit graph with contiguous topological node ids.
2. Deterministic integer oscillator, gain, low-pass, delay, and output nodes.
3. Ordered sample-accurate parameter events with Q15 validation.
4. Reproducible PCM/WAV offline renderer and trace-bound render receipts.
5. Preallocated atomic single-producer/single-consumer callback buffer with underrun, overrun, and peak-fill telemetry.
6. Host-owned device catalog generations that cannot mutate guest state.
7. Separate validated and replayable MIDI permission and event queue.
8. Node, event, frame, work, aggregate delay-storage, render-count, and captured-byte limits.
9. Synthesizer and delay-effect reference cartridges with byte-for-byte replay regression in all-platform CI.

The portable 0.5 boundary is complete. Native device enumeration and callback hookup stay in host adapters delivered with the desktop shell. Guests cannot enumerate devices or execute inside the real-time callback; that separation is part of the stable contract rather than missing guest functionality.

Exit criteria:

- the audio callback performs no guest-triggered allocation
- offline renders are reproducible
- device changes do not corrupt cartridge state
- an overloaded node is isolated without taking down the host

### 0.6 — developer workflow

Purpose: make building cartridges pleasant enough for daily use.

Work:

- `cartridge new` templates
- `cartridge dev` build/watch/run loop
- hot reload with optional state handoff
- local capability inspector
- manifest schema and editor integration
- generated Rust, TinyGo, and JavaScript bindings
- guest-side testing library
- runtime conformance suite
- package-size and fuel profiling
- trace viewer export format

Exit criteria:

- a new developer can create and run a cartridge in under five minutes
- API mismatches are reported before execution
- hot reload never overwrites persistent state without a migration
- SDK examples are tested against the current runtime in CI

Implemented delivery slices:

1. Exclusive Rust, TinyGo, and JavaScript project scaffolds with a checked-in WIT contract.
2. Bounded project validation, stable source fingerprints, package sizing, and declared fuel/memory/time profiles.
3. Argument-array build commands and a supervised build/watch/run loop with a one-shot CI mode.
4. State handoff that permits identical schemas, identifies declared migrations, and refuses unsafe schema changes.
5. Runtime import preflight before guest execution and a run-plus-replay conformance command.
6. JSON Schema output for editor integrations and a bounded full-fidelity trace timeline format.

The 0.6 workflow boundary is complete. Language toolchains remain external developer dependencies; installed packages can never supply or execute a build command.

### 0.7 — desktop library and permission UX

Purpose: provide a real home for installed cartridges.

Work:

- native desktop shell for the three supported systems
- cartridge library with search, versions, and profiles
- preflight permission screen
- session-only and persistent grants
- permission revocation
- launch history and resource monitor
- integrated trace timeline
- crash recovery and safe mode
- file associations for `.cartridge`
- automatic runtime updates independent of cartridge updates

Exit criteria:

- no cartridge executes before its requested authority is visible
- grants can be inspected and revoked later
- a broken cartridge cannot prevent the library from opening
- the shell passes keyboard and screen-reader navigation checks

Implemented delivery slices:

1. Cross-platform native library core and CLI shell with verified content-addressed installs, search, versions, and profiles.
2. Stable preflight prompt models with readable capability descriptions and named keyboard/screen-reader actions.
3. Session-only and persistent grants, granular revocation, and automatic reapproval when the requested capability set changes.
4. Bounded launch history and monotonic resource samples for fuel, memory, and audio underruns.
5. Interrupted-launch recovery, per-cartridge crash-loop safe mode, and corrupt-index quarantine.
6. `.cartridge` association recognition, separate runtime release channels, and trace timeline integration.
7. A graphics presenter boundary with canonical CPU and policy-gated GPU modes. Accelerated mode requires robust buffer access, process isolation, and explicit resource limits.

The 0.7 library boundary is complete. The CLI is the first accessible shell; richer graphical frontends remain consumers of this library rather than new security boundaries. GPU-backed 2D and future 3D adapters must preserve the validation contract described below.

### 0.8 — identity, signing, and distribution

Purpose: make packages exchangeable without pretending a checksum is authenticity.

Work:

- developer key generation and storage
- Ed25519 package signatures
- signed manifest and asset tree
- content-addressed package identity
- reproducible-build attestations
- local trust store
- revocation and key-rotation format
- registry client and protocol
- immutable version publishing
- transparency metadata
- dependency and capability index

Exit criteria:

- modifying any signed package byte invalidates verification
- a lost key has a documented recovery or rotation path
- registry compromise cannot silently replace an existing signed version
- unsigned local development remains possible and clearly labelled

Status: implemented. The local registry is the protocol reference; production remote federation and third-party operational hardening remain post-reference deployment work.

### 0.9 — networking and device mesh

Purpose: support multiplayer, collaboration, and local-first sync without granting raw sockets by default.

Work:

- URL-scoped HTTP capability
- declarative domain allowlists
- request and response size limits
- replayable HTTP fixtures
- encrypted peer identity
- peer discovery and NAT traversal in the host
- message channels exposed to guests
- content-addressed asset transfer
- CRDT-backed shared documents
- rollback-friendly datagram channel for games
- network simulator for latency, jitter, loss, and reordering

Exit criteria:

- a cartridge cannot contact an undeclared destination
- recorded network sessions replay offline
- peer identity is independent from an IP address
- sync converges after devices reconnect
- network simulation can reproduce a reported multiplayer failure

Status: implemented at the portable boundary. Live discovery/NAT adapters remain host-owned integrations so cartridges never receive raw socket authority.

### 1.0 — stable platform boundary

Purpose: make the formats and core APIs dependable enough for outside projects.

Work:

- [external gate] independent security review
- [implemented] fuzzing for package, manifest, release, trace, and WIT boundaries
- [implemented] deterministic, deadline-supervised release-build soak harness
- [implemented] stable package and trace compatibility policy
- [implemented] capability version negotiation before component compilation
- [implemented] signed runtime release metadata and artifact verification
- [external gate] certificate-backed macOS notarization and Windows signing
- [implemented] rollback-capable, crash-recoverable local updater
- [implemented] complete threat model for the portable runtime boundary
- [implemented] backup and recovery documentation
- [implemented] telemetry kept local unless explicitly exported
- [implemented] release-build startup, execution, headless graphics/audio render, fuel, and trace baselines

Exit criteria:

- no known sandbox escape or package validation bypass
- stable interfaces have conformance tests and support windows
- every supported platform passes the same cartridge corpus
- runtime upgrades can be rolled back without losing cartridge state
- the project can reproduce a crash from a self-contained report

Current stabilization gates:

- freeze WIT `0.4` only after a compatibility corpus passes on Windows, macOS, and Linux
- commission an independent security review and publish its remediation record
- add platform-native helper sandboxes, signing/notarization, and rollback-tested installers
- collect and publish platform baselines from the release-build stability workflow
- add native worker RSS and real-device audio-latency sampling once platform adapters exist
- grow the compatibility corpus with artifacts produced by every public SDK release

Status: the portable 1.0 candidate boundary is implemented and under stabilization. Capability negotiation, signed release metadata, verified installation, crash recovery, rollback, local-only measurements, compatibility guarantees, and recovery guidance now have executable paths. A 1.0 release remains blocked on the explicitly external gates above; the project does not describe those gates as complete until their platform credentials, independent review record, and native sandbox evidence exist.

## Beyond 1.0

The 1.0 boundary establishes a safe local platform. Later releases can build larger systems on top without weakening it.

### The Docker-sized target

Cartridge should grow from a runtime into a complete component engine: one tool that can build, package, sign, publish, install, compose, run, inspect, update, and recover portable applications. The credible comparison is not "Docker, but every container is Wasm." It is a different platform for workloads that benefit from capability security, typed interfaces, deterministic replay, fast startup, and host-independent packaging.

The product loop should eventually feel this small:

```sh
cartridge build
cartridge push registry.example/dev/photo-stack:1.4.0
cartridge stack plan Cartridge.stack.toml
cartridge stack apply Cartridge.stack.toml
cartridge ps
cartridge logs photo-stack
cartridge trace replay photo-stack/last-failure
```

The engine has five planes:

1. **Artifact plane** — reproducible components, immutable package identities, signatures, provenance, SBOMs, registries, and content-addressed caches.
2. **Composition plane** — typed dependency graphs, exact locks, relationship grants, service routing, secrets, state, blobs, and declared ingress.
3. **Execution plane** — rootless supervised workers, OS sandboxes, quotas, health checks, restart policy, upgrades, and rollback.
4. **Operations plane** — desired-state reconciliation, logs, metrics, traces, snapshots, events, policy, garbage collection, and support capsules.
5. **Fleet plane** — signed workload plans, authenticated agents, placement, rollout, device policy, encrypted transport, and failure recovery.

This target deliberately excludes compatibility traps that would erase Cartridge's advantages. There is no ambient shell, bind-mount-anything flag, inherited environment, host networking mode, privileged cartridge, or raw device escape hatch. Typed services replace private virtual networks; named state and blob resources replace arbitrary host volumes; secret handles replace plaintext environment variables; explicit host adapters replace device passthrough.

Success would mean Cartridge is a serious alternative for component applications, automation workers, extension systems, local-first services, creative pipelines, CI jobs, and managed edge workloads. General Linux distributions, kernel-dependent software, and existing OCI images remain better served by container engines.

### 1.1 — cartridge composition

Purpose: let independently developed cartridges form applications and workflows through typed contracts.

Work:

- [implemented for direct graphs] installed-cartridge catalog with immutable package identities
- transitive semantic-version resolver
- [implemented] bounded exact-byte direct launch-plan lockfiles and verification
- service discovery separated from permission
- persistent and session-only relationship grants
- multi-instance supervisor
- provider activation and idle suspension
- synchronous and asynchronous WIT service calls
- cancellation, deadlines, and backpressure
- opaque resource delegation with provenance
- cycle detection and activation diagnostics
- provider crash isolation and restart budgets
- side-by-side major versions
- graph view in the desktop permission UI
- composition events in deterministic traces

Build order:

1. [implemented] persist the direct resolver result as a create-new lock that binds package bytes, component/assets, versions, aliases, and interfaces
2. [implemented for direct graphs] resolve from the installed catalog and verify that every selected package still matches its library record
3. expand the lock into a transitive graph with side-by-side major versions and minimal unsatisfied-constraint diagnostics
4. separate graph compatibility, user approval, and activation into independently inspectable documents
5. supervise provider instances with deadlines, restart budgets, cancellation, and bounded queues before exposing calls
6. add typed synchronous calls, then async calls and resource delegation with provenance
7. record activation, calls, cancellation, backpressure, crashes, and revocation in deterministic traces
8. add desktop graph inspection and per-edge persistent/session grants

Exit criteria:

- a caller can use only the interfaces listed in its approved graph edge
- provider authority is never inherited by the caller
- revoking an edge closes live resources predictably
- required, optional, cyclic, missing, and incompatible relationships have useful diagnostics
- the same locked composition plan launches on each supported operating system

### 1.2 — local engine and declarative stacks

Purpose: turn the individual runtime subsystems into one rootless, inspectable application engine.

Work:

- a versioned `Cartridge.stack.toml` format for applications, providers, exact locks, state, blobs, secrets, ingress, schedules, budgets, and update policy
- `stack validate`, `plan`, `apply`, `status`, `stop`, `remove`, `export`, and `import`
- [implemented first slice] a per-user engine daemon over an encrypted authenticated local transport with replay rejection
- [implemented first slice] one desired-state reconciler and append-only event journal
- atomic plan application with preflight, staged activation, health gates, and rollback
- instance identities separated from package identities
- restart policies, exponential backoff, circuit breaking, graceful shutdown, and kill deadlines
- named state and blob resources with ownership, retention, snapshot, restore, and clone policies
- secret slots exposed as opaque operation handles rather than files or environment variables
- typed service routing and declared HTTP ingress without ambient private networks
- bounded structured logs, metrics, traces, and engine events with redaction policies
- resource accounting and quotas per instance, stack, publisher, and user
- orphan detection, content/store garbage collection, and disk-pressure behavior
- development mode that can replace one component while preserving the rest of the graph
- offline application bundles containing packages, signatures, lock, policy, and optional state

Security order:

1. specify the stack document, canonical digest, limits, and trust semantics
2. implement an in-process planner with no mutation
3. add a crash-recoverable journal and atomic local apply
4. [implemented first slice] move lifecycle ownership into a per-user daemon with authenticated clients
5. add platform-native worker sandboxes before remote or unattended workloads
6. add secrets and ingress only after audit events, revocation, and redaction exist

Exit criteria:

- applying the same locked stack on Windows, macOS, and Linux selects identical portable artifacts
- a failed or interrupted apply converges to either the previous healthy plan or the new healthy plan
- every live process, grant, resource, route, and byte of durable state has an inspectable owner
- stack removal cannot delete retained state, shared blobs, or another stack's resources
- the engine daemon and its workers run without administrator privileges
- no stack option grants ambient host filesystem, environment, process, network, or device authority

### 1.3 — reproducible build graph and registry federation

Purpose: make source-to-running-stack reproducible, cacheable, attestable, and usable by teams.

Work:

- a bounded build graph with explicit source, toolchain, dependency, component, asset, package, signature, and test nodes
- hermetic builders with no network by default and declared fetch inputs
- local and remote content-addressed caches keyed by canonical build inputs
- multi-language SDK/toolchain lockfiles and compatibility matrices
- reproducible package comparison with explanations for differing bytes
- source, builder, dependency, and test provenance attestations
- CycloneDX/SPDX SBOM export and vulnerability-policy gates
- registry namespace policy, retention, mirrors, replication, and transparency proofs
- resumable chunked push/pull with verified deltas
- channels, immutable releases, staged promotion, deprecation, and emergency revocation
- CI identities that can sign only approved namespaces and channels
- public conformance records and benchmark artifacts tied to exact package identities
- air-gapped cache and registry bundles

Exit criteria:

- a clean build can reproduce the same package identity from a complete source declaration
- cache hits never bypass signature, provenance, policy, or compatibility verification
- registries cannot silently replace an existing identity or version
- a release can be traced from source revision through builder and tests to every deployed stack
- offline builds and installs fail with an exact list of missing immutable inputs

### 1.4 — time-travel workbench

Purpose: make replay a complete debugger rather than only a host-call verifier.

Work:

- periodic linear-memory checkpoints
- table and resource checkpoint metadata
- copy-on-write snapshot pages
- compressed checkpoint storage
- state hashes between capability events
- reverse continue to the previous host call
- data watchpoints implemented through replay search
- branch execution with edited events
- compare two branches at memory, output, frame, and audio levels
- automatic first-bad-checkpoint search
- trace and snapshot minimization
- debugger protocol usable by the CLI and desktop app
- self-contained crash capsules

Exit criteria:

- a failure can be reproduced without the original host state
- reverse navigation reaches any recorded capability boundary
- edited branches cannot mutate the source recording
- checkpoint storage remains bounded for long sessions
- debugger results are stable across supported platforms

### 1.5 — programmable workspaces

Purpose: let cartridges become building blocks for serious personal tools rather than isolated launchable apps.

Work:

- workspace files listing cartridges, versions, grants, and layout
- typed event bus with schema identities
- user-built pipelines between compatible service ports
- transactional multi-cartridge operations
- runtime-owned shared documents
- command palette and discoverable actions
- intents such as open, convert, preview, export, and share
- file-type handlers selected by the user
- background jobs with explicit schedules and budgets
- secrets vault with per-operation consent
- workflow history and rollback
- headless workspace execution in CI
- import and export of complete workspace state

Examples could include a media pipeline assembled from decoder, metadata, thumbnail, and publishing cartridges; or a music workspace assembled from sequencer, synthesizer, visualizer, and export cartridges.

Exit criteria:

- every pipeline edge is typed and permissioned
- failed multi-step workflows leave recoverable state
- background jobs cannot outlive their grants or budgets
- secrets are never serialized into manifests or traces by default
- a workspace can be inspected and validated without running it

### 1.6 — trusted device mesh

Purpose: let a user's cartridges and data move between their own devices without requiring a central service.

Work:

- device identity and pairing
- encrypted peer channels
- content-addressed package and asset transfer
- state snapshot synchronization
- runtime-owned CRDT documents
- capability grants scoped to a device
- remote service routing with visible consent
- offline queues and conflict handling
- selective sync policies
- encrypted backup targets
- network replay fixtures
- device-loss revocation

Exit criteria:

- pairing requires an authenticated out-of-band step
- a removed device cannot request new state
- sync converges after long offline periods
- remote execution is always distinguishable from local execution
- no registry account is required for direct device-to-device use

### 1.7 — portable GPU and 3D

Purpose: support modern interactive graphics without handing native device authority to a cartridge or pretending that every driver produces identical pixels.

Work:

- versioned WebGPU-style buffer, texture, sampler, bind-group, pipeline, and render-pass resources
- host-validated WGSL subset with compilation limits and diagnostic normalization
- isolated GPU helper with a restart budget and device-loss recovery
- Metal, Vulkan, Direct3D 12, and software adapters behind one presenter contract
- explicit video-memory, upload, command, pass, shader, and pipeline-cache quotas
- generation-checked opaque handles and deterministic resource destruction
- indirect-draw, query, readback, and timestamp restrictions that prevent bounds and fingerprinting leaks
- structural replay of resource creation and command submission
- selectable canonical CPU, accelerated, and validation-layer execution modes
- tolerance-based screenshot comparison alongside byte-exact command-stream receipts
- frame pacing, pipeline compilation, upload, and GPU-time telemetry
- glTF reference viewer and a moderately complex 3D game scene in the shared platform corpus

Exit criteria:

- guests never receive a native API handle, mapped host pointer, or driver object
- malformed shaders and command streams cannot reach a backend before validation
- GPU-process failure cannot take down the library or corrupt cartridge state
- every resource is charged before native allocation and released after a bounded lifetime
- the same cartridge runs through all supported backends with equivalent observable behavior
- replay distinguishes command divergence from permitted driver-level pixel variation

### 2.0 — fleet engine and multiple execution environments

Purpose: keep the cartridge contract useful beyond one desktop process without pretending every host has identical capabilities.

Possible hosts:

- desktop interactive runtime
- headless automation runner
- CI conformance runner
- dedicated home server
- browser-based restricted host
- mobile companion for compatible cartridges
- embedded or kiosk profile

Each host advertises a capability profile. A cartridge can state hard requirements and optional enhancements. Portability means the component and contracts remain reusable; it does not mean a GPU editor must run unchanged on a headless sensor.

Work:

- host capability profiles
- portable feature negotiation
- remote build and conformance service
- ahead-of-time component caches per architecture
- deterministic headless rendering and audio
- restricted browser adapter
- power, thermal, and foreground limits for mobile profiles
- fleet policy for managed installations
- signed workload plans for servers
- consistent trace exchange between host types
- mutually authenticated per-host agents with short-lived enrollment credentials
- signed desired-state plans and monotonic rollout generations
- placement constraints, resource-fit scoring, affinities, anti-affinities, and maintenance drains
- replicated stateless services and explicitly constrained stateful placement
- rolling, canary, blue/green, and pause-on-regression deployment strategies
- lease-based ownership so a network partition cannot create duplicate singleton jobs
- encrypted service routing with local/remote identity visible in policy and traces
- fleet-wide inventory, audit events, policy evaluation, and revocation
- backup-aware rescheduling and disaster-recovery rehearsals

Exit criteria:

- a compromised worker cannot forge scheduler plans, publisher signatures, or another workload's identity
- loss of the control plane does not grant new authority or erase healthy local workloads
- partitions have documented fail-open or fail-closed behavior for every workload class
- rollouts stop automatically when health, resource, replay, or policy gates regress
- stateful workloads move only through an explicit snapshot/restore or replicated-state protocol
- one command can explain why every instance is on its current host and artifact version

## Ambitious platform services

These are candidates for versioned system cartridges or tightly controlled host capabilities. They should not all become privileged code inside the core runtime.

### Secrets and identity

- hardware-backed developer and user keys where available
- named secret slots rather than environment variables
- one-shot signing operations without revealing private keys
- OAuth and passkey brokers with origin restrictions
- per-service pseudonymous identities
- audit trail for secret use
- recovery and device-rotation workflows

### Data and databases

- transactional key/value service
- portable embedded relational database service
- schema migration planner
- change streams for reactive cartridges
- content-addressed object storage
- runtime-owned shared collections
- query budgets and cancellation
- encrypted exports and backups

### Scheduling and automation

- cron-like schedules with local-time semantics
- event-triggered jobs
- battery, network, and idle constraints
- maximum runtime and retry budgets
- human approval gates inside workflows
- durable job history
- deterministic job replay
- webhook ingress through scoped public endpoints

### Media and creative computation

- color-managed image surfaces
- video frame and timeline resources
- low-latency audio and MIDI graphs
- font shaping and accessibility semantics
- GPU compute with validated resource limits
- offline deterministic render farms
- plugin latency compensation
- project-wide asset dependency tracking

### Collaboration

- shared CRDT documents
- presence and cursor channels separated from durable data
- end-to-end encrypted rooms
- role-based document capabilities
- offline edits and conflict visualization
- replayable collaboration sessions
- signed project history
- export without service lock-in

### Policy and administration

- declarative organization policies
- capability allow and deny rules
- trusted publisher lists
- pinned runtime and cartridge versions
- resource budgets by user or workspace
- offline installation bundles
- local audit logs
- reproducible policy evaluation

### Developer ecosystem

- interface registry independent from package hosting
- WIT compatibility checker
- API review tooling
- component benchmark exchange
- public conformance badges backed by reproducible runs
- fuzz corpus sharing
- package provenance explorer
- compatibility dashboards across runtime versions
- generated SDK documentation and examples

## Cross-cutting workstreams

The release line gives an order, but several systems continue through every milestone.

### Runtime core

- compiled-component cache keyed by engine and component version
- instance pooling for short-lived tools
- epoch interruption in addition to fuel
- table, instance, and resource limits
- cancellation and graceful shutdown
- async host calls once the API needs them
- capability-specific worker isolation
- crash containment for native platform adapters
- benchmark corpus and flamegraph workflow

### Capability model

- machine-readable capability descriptors
- semantic versions per WIT package
- required versus optional capabilities
- grant scope and expiry
- user-readable explanations kept separate from identifiers
- delegation between cartridges without authority amplification
- platform-specific capability namespaces
- capability discovery without probing private host state

### Composition and supervision

- direct and transitive dependency resolution
- exact selected-version plans
- typed service endpoints
- persistent grant graph
- provider lifecycle and activation
- resource delegation without authority amplification
- cancellation and call deadlines
- backpressure and queue limits
- graph cycle diagnostics
- provider health and circuit breaking
- upgrade coordination with active clients
- local and remote routing kept visibly distinct
- replay representation for service calls

### Determinism and debugger

- canonical JSON trace representation followed by a compact binary form
- event checksums and chunked streaming
- trace redaction rules
- host-call replay
- input and network replay
- linear-memory checkpoints
- incremental and compressed snapshots
- state hashes between checkpoints
- reverse stepping to the previous capability call
- execution branches with one changed input
- side-by-side divergence viewer
- automatic trace minimization
- portable crash bundles containing package, trace, state, and screenshots

### Package system

- canonical archive ordering and timestamps
- full asset-tree hashes
- optional compression policies per asset type
- delta updates between versions
- dependency components and composition
- package metadata without executing code
- icons, screenshots, and localization
- maximum expansion ratios and decompression budgets
- format corpus for backward-compatibility tests

### SDK and language support

- Rust SDK first
- TinyGo SDK after the capability surface settles
- JavaScript components through the standard component toolchain
- C and C++ bindings for DSP and game code
- generated documentation from WIT
- language-neutral examples
- ABI compatibility fixtures built by old SDK versions
- no SDK-only capability that another language cannot implement

### Security

- archive and manifest fuzz targets
- component import allowlist checks before compilation
- explicit limits on every guest-controlled allocation
- deterministic denial behavior
- separate development and installed-package trust levels
- native sandbox profiles around the runtime process
- least-privilege platform adapters
- signature verification before compiled-cache lookup
- dependency advisories and SBOM generation
- incident response and private reporting process

### Quality and compatibility

- Windows x64, macOS Intel, macOS Apple Silicon, and Linux x64 release coverage
- additional Linux display-server testing once the desktop shell exists
- golden package and trace fixtures
- property tests for normalized paths and manifests
- differential tests between record and replay
- compatibility runs against previous stable runtime releases
- fault injection for disk-full, clock changes, device loss, and process termination
- performance regression thresholds in CI

## Reference cartridges

Each major subsystem should be proven by a cartridge that remains small enough to understand:

1. `hello` — logging, assets, clock, and CLI arguments
2. `state-lab` — migrations, snapshots, and quota behavior
3. `canvas-lab` — drawing, input recording, and screenshot tests
4. `synth-lab` — real-time and offline audio paths
5. `latency-lab` — rollback simulation and network impairment
6. `mesh-notes` — encrypted local-first synchronization
7. `debug-lab` — deliberate divergence and reverse-debugger fixtures

These are test fixtures and documentation at the same time. They should avoid becoming polished end-user applications inside the main repository.

## Repository growth

The current workspace should evolve roughly toward:

```text
crates/
  cartridge-core          package and manifest types
  cartridge-runtime       execution and capability host
  cartridge-replay        trace validation, replay, checkpoints
  cartridge-storage       scoped persistent state
  cartridge-render        drawing and input
  cartridge-audio         real-time audio host
  cartridge-registry      identities and distribution client
  cartridge-cli           command-line frontend

apps/
  cartridge-desktop       native library and debugger

sdk/
  rust
  tinygo
  javascript

spec/
  package
  trace
  capabilities

tests/
  corpus
  conformance
  fuzz
```

New crates should only be split out when they establish an actual dependency boundary. Empty architecture folders make the repository look larger without making the system better.

## Definition of done for a capability

A capability is not complete when its host function works once. It is complete when it has:

- a versioned WIT contract
- a manifest declaration
- deny-by-default host behavior
- resource limits
- a record and replay representation
- malformed-input tests
- a reference cartridge
- user-facing permission wording
- platform notes
- compatibility expectations

## Near-term build order

The next concrete sequence is:

1. Finish the 1.1 graph model:
   - [implemented] exact-byte direct locks from explicit package paths
   - [implemented] integrity-checked direct resolution from the installed catalog
   - recursively expand manifests into a bounded graph without activating code
   - support side-by-side incompatible major versions through instance-qualified nodes
   - return a minimal unsatisfied constraint/interface explanation
   - detect dependency and constructor-time activation cycles separately
2. Specify relationship authority:
   - define a canonical approved-graph document separate from the compatibility lock
   - bind every grant to caller, provider identity, interface set, scope, expiry, and approval generation
   - model session, persistent, policy-provided, and revoked edges
   - prove that provider host authority never becomes caller authority
3. [partially implemented] Build the local composition supervisor:
   - [implemented] expand exact plans into stable replicas under a single-owner foreground supervisor
   - [implemented] enforce finite restart budgets, deterministic capped backoff, crash recovery, worker deadlines, and a 32-worker admission ceiling
   - [implemented] persist checksum-bound, generation-fenced observed state and reject stale run exits
   - [implemented] enforce reviewed capability ceilings inside the runtime and isolate state by exact package digest
   - activate providers before wiring edges
   - enforce per-call deadlines, cancellation trees, queue limits, and backpressure
   - add restart budgets, circuit breaking, idle suspension, and crash isolation
   - record activation, calls, failures, and revocation in deterministic traces
4. [partially implemented] Extend `Cartridge.stack.toml` beyond its first control-plane slice:
   - [implemented] bounded instances, version requirements, exact package and composition locks
   - [implemented] named state/blob resources, retention intent, quotas, and declared secret slots
   - [implemented] strict/balanced/permissive capability policy with explicit grants and blocks
   - add service edges, budgets, health checks, jobs, ingress, and rollout policy
   - add a semantic plan diff alongside the implemented canonical plan digest
5. [partially implemented] Turn the local desired-state engine into a reconciler:
   - [implemented] globally locked, checksum-chained, idempotent apply/stop/remove journal
   - [implemented] generation-fenced replica expansion, durable observed status, restart recovery, process reconciliation, and one-supervisor leases
   - [implemented] rootless daemon ownership, encrypted local requests, bounded replay defense, per-boot liveness fencing, serialized mutations, and graceful client/supervisor drain
   - add explicit prepare/activate/commit rollout phases and recovery checkpoints
   - add health-gated rollback and rolling/canary replacement
   - compact long journals through signed checkpoints without losing auditability
6. Complete the external 1.0 security gates in parallel:
   - platform-native worker sandboxes and kernel resource limits
   - independent review and remediation record
   - signed/notarized installers and rollback-tested release channels
7. [implemented first slice] Move lifecycle ownership into a per-user engine daemon after standalone stack apply is stable. The next daemon slices are native service installation, OS peer credentials, process-tree containment, health-gated rollout, and structured observability.
8. [partially implemented] Build the desktop shell over the same control-plane types:
   - [implemented] native Tauri shell with library, stack, security posture, and event views
   - [implemented] exact plan and permission review with server-retained digest and package re-verification before apply
   - [implemented] private native-backed appearance and new-stack preferences with light/dark/system themes, density, and reduced-motion control
   - add process/resource views, semantic plan diff, package import, and secret prompts
   - add live logs, health, resource charts, trace inspection, and rollback controls
   - no privileged background service by default; explicit elevation only for optional adapters
9. Grow from one machine toward an authority-minimal fleet:
   - signed node enrollment, short-lived leases, placement constraints, and drain
   - deterministic rollout plans and health-gated canaries
   - content-addressed package distribution and verified state transfer
   - preserve the same cartridge capability boundary on every node

Completed foundations:

- trace replay and first-divergence reporting
- standalone trace types, validation, summaries, and comparison
- epoch deadlines alongside deterministic fuel limits
- isolated in-memory storage with quotas and side-effect-free replay
- checksummed durable generations, process locking, status, and recovery
- portable snapshot export, inspection, diffing, dry runs, and transactional restore
- isolated snapshot branch execution with optional result export
- state schemas persisted across memory, durable generations, and portable snapshots
- validated manifest migration graphs and identity-bound ordered plans
- isolated multi-step migration rehearsals with intermediate schema and quota validation
- checksummed pre-commit migration receipts with committed, not-committed, changed, and indeterminate recovery states
- portable execution capsule manifests with path confinement, raw artifact digests, and semantic cross-file verification
- state-reproducing capsule replay on disposable snapshot branches
- privacy-safe non-replayable trace summary and metadata exports
- content-addressed blob storage with bounded streaming I/O, checksummed reachability manifests, deterministic inventory, full-store audits, and safe-by-default garbage collection
- ABA-safe compare-exchange and bounded atomic state batches across all storage backends
- Merkle-style package asset roots and selective payload verification
- seeded archive, package-manifest, composition-lock, snapshot, trace, transaction, blob-reachability, media, network, release, GPU-stream, and WIT fuzz targets with scheduled bounded runs
- bounded archive inflation, WASI waits, storage locks, tables, traces, and diagnostic inputs
- supervised CLI workers for killable component compilation and execution
- minimized Wasmtime features and explicit rejection of unused Wasm proposals
- bounded package construction, snapshot decoding, durable-state decoding, and host resource tables
- pinned CI actions, automated dependency updates, and RustSec advisory checks

Security work immediately ahead:

1. [implemented] Bind package identity to a trusted developer signature before the public CLI treats a cartridge id as a durable-storage principal.
2. Add platform-native sandbox profiles and kernel memory/CPU limits around the existing execution workers, then move high-risk native adapters into separate capability-specific workers.
3. [partially implemented] Trace redaction profiles are available; encrypted support bundles remain.
4. [partially implemented] Keep expanding the seeded parser and protocol fuzz suite; capsule and receipt parsers still need library boundaries before they can join it cleanly.

The local registry reference is useful protocol evidence, but public hosting or a marketplace must wait for independent review, operational abuse controls, provenance policy, and incident response. Distribution magnifies every earlier design mistake.
