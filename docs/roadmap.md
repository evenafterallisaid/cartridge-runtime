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

Current development state: the 0.1 vertical slice and 0.2 replay milestone are implemented. Runtime work is moving into 0.3 storage. Release labels here describe compatibility milestones, not published versions.

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

Work:

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
7. Content-addressed blobs, garbage collection, and references from key/value records.

The first five slices are implemented. Durable state is opt-in through `--state-dir`, which keeps host-directory policy explicit until the desktop runtime owns a standard application-data location. Snapshots are independently versioned and exclude internal journal metadata. State schemas now follow data through memory, durable generations, and portable snapshots. Manifests declare unambiguous monotonic migration edges, and the CLI can build an identity-bound ordered plan without executing the component. The next slice executes those plans against isolated branches.

Migration design constraints:

- the manifest declares a monotonically increasing state schema version
- every migration names one source and destination schema version
- the runtime captures an automatic rollback snapshot before migration
- migration code runs against an isolated overlay, never the live namespace
- dry runs report key and byte changes without exposing stored values
- the transformed snapshot must pass integrity and quota validation
- committing a migration writes exactly one durable generation
- failed or trapped migrations leave the previous generation active
- downgrade support is explicit rather than inferred
- migration compatibility is tested on snapshots from every released schema

Later snapshot work includes selective exports, encrypted envelopes, signed backups, blob references, streaming import for large state, and redaction policies for support bundles. None of those should change the guest key/value ABI.

### Scouted platform opportunities

These directions fit the existing architecture, but their order follows the maturity of the standards they build on:

- **Atomic state transactions.** Add compare-and-swap and bounded batch operations before exposing multi-key migrations to guests. The WASI key/value proposal already separates single-key, atomic, batch, and watch interfaces, which gives Cartridge a useful compatibility target without forcing one backend model.
- **Reactive state watch streams.** Allow a cartridge to subscribe to changes it has authority to observe, with coalescing, bounded queues, and trace events. This belongs after async host calls and composition supervision so a slow consumer cannot stall storage commits.
- **Streaming content-addressed blobs.** Store large values as deduplicated chunks addressed by digest, keep small references in key/value state, and trace digests rather than payloads. The guest API should use component-model streams instead of buffering complete objects into linear memory.
- **State-and-trace capsules.** Bind a source snapshot, execution trace, package digest, and result snapshot into one inspectable crash or test artifact. Snapshot branches make the first version possible without memory checkpointing.
- **Parallel scenario matrices.** Fan out many runs from one immutable snapshot, then compare outputs, traces, fuel, and state diffs. This can become `cartridge test --matrix` once branch execution and a test manifest exist.
- **Portable interpreter fallback.** Investigate a Pulley backend for architectures where native code generation is unavailable or undesirable. It should complement, not replace, Wasmtime's compiled path and needs independent performance and sandbox measurements.
- **Async component services.** Adopt Component Model Preview 3 futures, streams, cancellation, and backpressure when the toolchain stabilizes. This unlocks long-lived cartridge services, blob streaming, watches, networking, and composition without inventing a private async ABI.

Standards tracked for this work include the official [WASI key/value proposal](https://github.com/WebAssembly/wasi-keyvalue), [WASI blobstore proposal](https://github.com/WebAssembly/wasi-blobstore), [Component Model repository](https://github.com/WebAssembly/component-model), and [Pulley RFC](https://github.com/bytecodealliance/rfcs/blob/main/accepted/pulley.md).

Exit criteria:

- cartridges cannot address another cartridge's data
- interrupted writes preserve the previous valid state
- a state snapshot can move between Windows and macOS
- migrations are testable before data is modified

### 0.4 — windows, drawing, and input

Purpose: make cartridges visible and interactive.

Work:

- window lifecycle capability
- keyboard, pointer, controller, and text input events
- resolution-independent 2D drawing API
- image and font assets
- frame scheduling and monotonic simulation time
- headless renderer for tests
- screenshot-based regression runner
- graphics limits and validation
- first visual reference cartridges

The first renderer should be deliberately constrained. A stable 2D command stream is more valuable than immediately exposing a complete native GUI toolkit. A later GPU interface can coexist with it.

Exit criteria:

- the same cartridge produces equivalent frames on all supported systems
- recorded input can be replayed headlessly
- invalid draw commands cannot crash the desktop host
- screenshots can be attached to trace reports

### 0.5 — real-time audio

Purpose: support instruments, effects, games, and visualizers.

Work:

- audio device discovery outside the guest
- fixed-format audio graph contract
- sample-accurate parameter events
- lock-free communication between runtime and audio callback
- offline rendering for deterministic tests
- underrun and latency telemetry
- WASM DSP node limits
- MIDI input as a separate permission
- example synthesizer and effect cartridges

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

### 1.0 — stable platform boundary

Purpose: make the formats and core APIs dependable enough for outside projects.

Work:

- external security review
- fuzzing for package, manifest, trace, and WIT boundaries
- long-running resource leak tests
- stable package and trace compatibility policy
- capability version negotiation
- signed runtime releases
- macOS notarization and Windows signing
- rollback-capable updater
- complete threat model
- backup and recovery documentation
- telemetry kept local unless explicitly exported
- performance baselines for startup, memory, frame time, and audio latency

Exit criteria:

- no known sandbox escape or package validation bypass
- stable interfaces have conformance tests and support windows
- every supported platform passes the same cartridge corpus
- runtime upgrades can be rolled back without losing cartridge state
- the project can reproduce a crash from a self-contained report

## Beyond 1.0

The 1.0 boundary establishes a safe local platform. Later releases can build larger systems on top without weakening it.

### 1.1 — cartridge composition

Purpose: let independently developed cartridges form applications and workflows through typed contracts.

Work:

- installed-cartridge catalog
- transitive semantic-version resolver
- exact launch-plan lockfiles
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

Exit criteria:

- a caller can use only the interfaces listed in its approved graph edge
- provider authority is never inherited by the caller
- revoking an edge closes live resources predictably
- required, optional, cyclic, missing, and incompatible relationships have useful diagnostics
- the same locked composition plan launches on each supported operating system

### 1.2 — time-travel workbench

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

### 1.3 — programmable workspaces

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

### 1.4 — trusted device mesh

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

### 2.0 — multiple execution environments

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

1. Define the migration execution WIT contract and run validated steps against isolated snapshot branches.
2. Validate every intermediate schema, quota, and state digest before a single durable commit.
3. Add automatic rollback snapshots and explicit migration commit/recovery commands.
4. Bind branch runs to trace and state digests for reproducible test capsules.
5. Add compare-and-swap and bounded atomic batch operations.
6. Add content-addressed blobs, streaming access, and snapshot references for larger state.
7. Add package-wide Merkle-style asset integrity.
8. Create a minimal 2D window and input prototype behind new WIT packages.
9. Build a small trace viewer after there is enough real trace data to design around.

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

The project should not start a registry or marketplace before signing, capability UX, and the security model exist. Distribution magnifies every earlier design mistake.
