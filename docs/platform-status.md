# Platform status

Cartridge is a substantial portable runtime prototype, not yet a Docker replacement. The core differentiator already works: a `.cartridge` is a bounded, integrity-checked WebAssembly component application whose host authority is expressed through versioned capabilities rather than inherited from the operating system.

## What works now

| Surface | Working implementation |
| --- | --- |
| Package | Reproducible `.cartridge` archives, strict manifests, exact component hashes, asset-tree integrity, selective verification, and inflation limits |
| Execute | Wasmtime Component Model host, WASI 0.2 compatibility, fuel/memory/table/instance/wall-time limits, crash-resistant process-tree containment, capability negotiation, host-enforced capability ceilings, and operator resource ceilings bound into immutable plans |
| Authority | Deny-by-default clock, randomness, assets, storage, graphics, audio, MIDI, and URL-scoped HTTP contracts |
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
| Control plane | Strict `Cartridge.stack.toml` parsing, exact installed-package plans, operator ceilings for fuel/memory/time/storage/media, bounded resources and secret declarations, explicit security profiles, idempotent apply/stop/remove, checksum-chained desired state, generation-fenced observed state, durable prepare/activate/commit/rollback transactions, health-gated automatic update rollback, single-owner supervision, per-replica state, bounded concurrency/restarts/backoff/deadlines, supervisor heartbeats, authenticated aggregate health, deadline-bounded readiness waits, and a rootless persistent daemon with encrypted authenticated local control, replay rejection, liveness fencing, process-tree ownership, crash recovery, and Docker-style `engine` lifecycle commands |
| Desktop | Native Tauri shell with overview, library, stack, journal, and settings views; authenticated daemon health; live and last-recorded replica status; exact plan, limits, and permission review; package re-verification; daemon-only apply/stop/remove controls; persistent light/dark themes, density, motion, and safe new-stack defaults |
| Quality | Cross-platform CI, parser fuzz targets, deterministic soak/benchmark tooling, compatibility policy, threat model, and RustSec dependency audit |

## What does not exist yet

| Missing layer | Why it matters |
| --- | --- |
| Native OS sandbox adapters | The helper is killable, authority-poor, and creation-hardened on Windows, but restricted Windows tokens/AppContainer, macOS sandbox profiles, and Linux namespaces/seccomp/cgroups are still external 1.0 gates |
| Live service broker | Manifests and locks describe service edges, but one cartridge cannot yet invoke another through those typed interfaces |
| Transitive graph solver | Resolution currently handles one root's direct dependencies; it does not yet solve a whole graph, cycles, side-by-side majors, or minimal conflicts |
| Relationship authorization | Capability grants exist for individual cartridges, but per-service-edge persistent/session grants and revocation are not wired into activation |
| Service-aware supervisor | Standalone replica lifecycle, restart reconciliation, process-level health, stale-supervisor detection, readiness waits, and whole-generation rollback work; provider-first activation, typed service wiring, application probes, surge/unavailable rolling replacement, idle suspension, cancellation trees, circuit breaking, and backpressure remain |
| OS service integration | The daemon is a working foreground service suitable for a user service manager, but installers, login startup, upgrade handoff, and native service-manager definitions are not wired yet |
| Complete stack schema | Instances, exact packages, resources, secret slots, restart intent, and security policy work; services, ingress, jobs, health checks, rollout policy, and runtime secret delivery remain |
| Service ingress | HTTP is outbound and fixtureable; inbound routes, TLS identity, rate limits, and typed ingress policy are not implemented |
| Secret broker | There are developer keys and trust stores, but no runtime secret slots, operation-scoped use, audit trail, or hardware-backed provider |
| Hermetic build engine | Developer builds work, but source/toolchain lockfiles, sandboxed build graphs, remote cache, provenance, and SBOM gates do not |
| Hosted/federated registry | The local registry proves protocol behavior; production storage, federation, transparency operations, mirrors, and account policy do not exist |
| Fleet scheduler | Peer primitives are not a cluster: there is no control plane, agent enrollment, placement, leases, rollout, drain, or stateful failover |
| Complete desktop workflow | The daemon-backed native control-plane shell works; package import, daemon lifecycle installation, logs, traces, resource charts, semantic plan diff, secret prompts, updates, accessibility polish, signed installers, and native adapters remain |
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

The rootless local engine now owns desired-state reconciliation through an authenticated API and retains its complete supervisor/worker process tree across supported operating systems. The next milestone is to make it explain and control every service edge, health decision, rollout, grant, resource, and state transition while adding native authority sandboxes and kernel resource policy.
