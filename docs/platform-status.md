# Platform status

Cartridge is a substantial portable runtime prototype, not yet a Docker replacement. The core differentiator already works: a `.cartridge` is a bounded, integrity-checked WebAssembly component application whose host authority is expressed through versioned capabilities rather than inherited from the operating system.

## What works now

| Surface | Working implementation |
| --- | --- |
| Package | Reproducible `.cartridge` archives, strict manifests, exact component hashes, asset-tree integrity, selective verification, and inflation limits |
| Execute | Wasmtime Component Model host, WASI 0.2 compatibility, fuel/memory/table/instance/wall-time limits, crash-resistant process-tree containment, capability negotiation, host-enforced capability ceilings, and operator resource ceilings bound into immutable plans |
| Authority | Deny-by-default clock, randomness, assets, storage, graphics, audio, MIDI, URL-scoped outbound HTTP, and engine-brokered local service contracts |
| Identity | Ed25519 exact-byte signatures, trust rotation and revocation, authenticated durable-state principals, and immutable registry versions |
| State | Namespaced memory/durable backends, checksummed generations, snapshots, atomic batches, compare-exchange, migrations, rollback, and recovery receipts |
| Data | Streaming content-addressed blobs, verified reachability, root manifests, inventory, audits, and safe garbage collection |
| Replay | Deterministic traces, record/replay, first-divergence reports, media receipts, redacted exports, and state-reproducing execution capsules |
| Media | Deterministic 2D CPU renderer, input recording, fixed-format audio graphs, offline WAV output, MIDI, and an isolated bounded GPU presenter contract |
| Develop | Project scaffolds, checks, build/watch/run, state handoff rules, profiling, schema output, API preflight, and conformance replay |
| Install | Integrity-checked per-user library, immutable versions, permission preflight/grants/revocation, launch history, crash-loop safe mode, and runtime channels |
| Distribute | Local signed registry reference, content identities, publishing/resolution/audit, and signed runtime update/install/rollback |
| Network | Replayable scoped HTTP, encrypted peer-session primitives, verified asset transfer, CRDT document primitives, and deterministic simulation |
| Compose | Typed dependency/provider declarations, direct semantic-version resolution, exact-byte lockfiles, and verified resolution from the installed library catalog |
| Control plane | Strict `Cartridge.stack.toml` parsing, exact installed-package plans, operator ceilings for fuel/memory/time/storage/media, bounded resources and secret declarations, explicit security profiles, guest-signalled startup/readiness/liveness policy, plan-bound rolling policy with a deterministic availability-safe scheduler core, crash-recoverable per-ordinal rollout intent, generation-scoped old/candidate leases and state, epoch- and sequence-fenced ready-only routing membership with route-before-drain ordering, permission-gated deadline-bound local invocation of exact ready runs, idempotent apply/stop/remove, checksum-chained desired state, generation-fenced observed state, durable prepare/activate/commit/rollback transactions, application-health-gated automatic update rollback, single-owner supervision, per-replica state, bounded concurrency/restarts/backoff/deadlines, supervisor heartbeats, authenticated aggregate health, deadline-bounded readiness waits, and a rootless persistent daemon with encrypted authenticated local control, replay rejection, liveness fencing, process-tree ownership, crash recovery, and Docker-style `engine` lifecycle commands |
| Desktop | Native Tauri shell with overview, library, stack, journal, and settings views; native verified `.cartridge` import and exact package inspection; authenticated daemon health; live and last-recorded replica status; exact plan, limits, and permission review; package re-verification; daemon-only apply/stop/remove controls; persistent light/dark themes, density, motion, and safe new-stack defaults |
| Quality | Cross-platform CI, parser fuzz targets, deterministic soak/benchmark tooling, compatibility policy, threat model, and RustSec dependency audit |

## What does not exist yet

| Missing layer | Why it matters |
| --- | --- |
| Native OS sandbox adapters | The helper is killable, authority-poor, and creation-hardened on Windows, but restricted Windows tokens/AppContainer, macOS sandbox profiles, and Linux namespaces/seccomp/cgroups are still external 1.0 gates |
| Typed composition broker | The engine can invoke an opted-in ready guest through the bounded local service ABI, but one cartridge cannot yet call another through an approved typed graph edge |
| Transitive graph solver | Resolution currently handles one root's direct dependencies; it does not yet solve a whole graph, cycles, side-by-side majors, or minimal conflicts |
| Relationship authorization | Capability grants exist for individual cartridges, but per-service-edge persistent/session grants and revocation are not wired into activation |
| Service-aware supervisor | Standalone replica lifecycle, restart reconciliation, guest-signalled application health, stale-supervisor detection, readiness waits, whole-generation rollback, deterministic rolling decisions, durable rollout intent, daemon-driven concurrent generation execution, graceful bounded draining, isolated old/candidate ownership, and ready-only local routing membership work; provider-first activation, typed service wiring, HTTP/command probes, inbound routing, idle suspension, cancellation trees, circuit breaking, and backpressure remain |
| OS service integration | The daemon is a working foreground service suitable for a user service manager, but installers, login startup, upgrade handoff, and native service-manager definitions are not wired yet |
| Complete stack schema | Instances, exact packages, resources, secret slots, restart intent, security policy, guest-signalled health policy, and rolling-update policy work; services, ingress, jobs, external probe kinds, and runtime secret delivery remain |
| Network ingress | Authenticated foreground loopback HTTP gateway and command invocation work without guest sockets; daemon-owned declared listeners, browser sessions, TLS, remote clients, rate limits, and streaming remain |
| Secret broker | There are developer keys and trust stores, but no runtime secret slots, operation-scoped use, audit trail, or hardware-backed provider |
| Hermetic build engine | Developer builds work, but source/toolchain lockfiles, sandboxed build graphs, remote cache, provenance, and SBOM gates do not |
| Hosted/federated registry | The local registry proves protocol behavior; production storage, federation, transparency operations, mirrors, and account policy do not exist |
| Fleet scheduler | Peer primitives are not a cluster: there is no control plane, agent enrollment, placement, leases, rollout, drain, or stateful failover |
| Complete desktop workflow | The daemon-backed native control-plane shell and verified package import work; permission grant/revoke controls, version lifecycle actions, daemon lifecycle installation, logs, traces, resource charts, semantic plan diff, secret prompts, updates, accessibility polish, signed installers, and native adapters remain |
| Independent assurance | The project has internal audits and regression PoCs, but not an independent security assessment or stable release support record |

## The honest Docker comparison

Docker and OCI excel at packaging existing native/Linux software with its filesystem, processes, sockets, and ecosystem intact. Cartridge intentionally does not provide those ambient interfaces. It packages a component and assets, then brokers typed host capabilities.

That makes Cartridge a poor target for an arbitrary database image or Linux distribution, but a potentially stronger target for:

- cross-platform application components and plugin ecosystems
- local-first desktop services and creative pipelines
- deterministic automation and CI workers
- signed extensions that should not inherit host authority
- fast-starting managed edge jobs
- replayable test, simulation, and support workloads

The rootless local engine owns desired-state reconciliation through an authenticated API, retains its complete supervisor/worker process tree across supported operating systems, gates opted-in workloads on application readiness and liveness, executes crash-recoverable availability-bounded per-replica rolling actions across separately authorized generations, publishes ready-only routing membership before drain begins, and invokes exact ready service runs through a bounded permission-gated broker. A foreground authenticated loopback HTTP gateway now exposes one service to local API clients. The next engine gates are daemon-owned declared HTTP ingress, typed composition edges, state migration policy, native authority sandboxes, kernel resource policy, and OS peer credentials.
