# Platform status

Cartridge is a substantial portable runtime prototype, not yet a Docker replacement. The core differentiator already works: a `.cartridge` is a bounded, integrity-checked WebAssembly component application whose host authority is expressed through versioned capabilities rather than inherited from the operating system.

## What works now

| Surface | Working implementation |
| --- | --- |
| Package | Reproducible `.cartridge` archives, strict manifests, exact component hashes, asset-tree integrity, selective verification, and inflation limits |
| Execute | Wasmtime Component Model host, WASI 0.2 compatibility, fuel/memory/table/instance/wall-time limits, killable helper process, and capability negotiation |
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
| Control plane | Strict `Cartridge.stack.toml` parsing, exact installed-package plans, bounded resources and secret declarations, explicit security profiles, idempotent apply/stop/remove, and a checksum-chained desired-state journal |
| Quality | Cross-platform CI, parser fuzz targets, deterministic soak/benchmark tooling, compatibility policy, threat model, and RustSec dependency audit |

## What does not exist yet

| Missing layer | Why it matters |
| --- | --- |
| Native OS sandbox adapters | The helper is killable and authority-poor, but restricted Windows tokens/AppContainer, macOS sandbox profiles, and Linux namespaces/seccomp/cgroups are still external 1.0 gates |
| Live service broker | Manifests and locks describe service edges, but one cartridge cannot yet invoke another through those typed interfaces |
| Transitive graph solver | Resolution currently handles one root's direct dependencies; it does not yet solve a whole graph, cycles, side-by-side majors, or minimal conflicts |
| Relationship authorization | Capability grants exist for individual cartridges, but per-service-edge persistent/session grants and revocation are not wired into activation |
| Multi-instance supervisor | The engine records multi-instance desired state but does not yet activate providers, enforce restart budgets, suspend idle instances, or apply cancellation and backpressure |
| Engine daemon | Commands are standalone; no per-user control plane owns desired state, reconciles crashes, or exposes one authenticated local API |
| Complete stack schema | Instances, exact packages, resources, secret slots, restart intent, and security policy work; services, ingress, jobs, health checks, rollout policy, and runtime secret delivery remain |
| Service ingress | HTTP is outbound and fixtureable; inbound routes, TLS identity, rate limits, and typed ingress policy are not implemented |
| Secret broker | There are developer keys and trust stores, but no runtime secret slots, operation-scoped use, audit trail, or hardware-backed provider |
| Hermetic build engine | Developer builds work, but source/toolchain lockfiles, sandboxed build graphs, remote cache, provenance, and SBOM gates do not |
| Hosted/federated registry | The local registry proves protocol behavior; production storage, federation, transparency operations, mirrors, and account policy do not exist |
| Fleet scheduler | Peer primitives are not a cluster: there is no control plane, agent enrollment, placement, leases, rollout, drain, or stateful failover |
| Native desktop shell | Library and presenter policy are implemented as reference libraries/CLI flows; a polished permission UI and native adapters remain |
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

The next product milestone is therefore not OCI compatibility. It is a rootless local engine that can apply a signed, locked stack of cartridges and explain every process, service edge, grant, resource, and state transition.
