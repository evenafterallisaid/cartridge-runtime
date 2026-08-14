# Threat model

## Security goals

Cartridge aims to run portable components with less authority than the user, make every granted authority visible, bound host resource use, authenticate exchanged packages and runtime updates, and make state-changing failures recoverable. A malicious cartridge should not gain ambient filesystem, socket, device, process, environment, or terminal access.

## Protected assets

- host files, credentials, devices, network identity, and local services
- cartridge-private durable state and backups
- developer and runtime signing keys
- package, registry, release, trace, snapshot, and capsule integrity
- availability of the desktop library and other cartridges
- privacy of capability outcomes and local telemetry

## Adversaries

- a malicious or malformed `.cartridge`, trace, snapshot, capsule, fixture, registry index, or release document
- a compromised registry or update mirror without the trusted signing key
- a cartridge attempting CPU, memory, storage, graphics, audio, trace, IPC, or parser exhaustion
- a peer sending forged, replayed, reordered, oversized, or corrupt collaboration data
- an interrupted process or concurrent cooperating process racing state and index updates
- a local process able to modify files in a user-writable Cartridge directory

The last adversary is partially outside the portable boundary. Content hashes detect changes, process locks coordinate cooperating instances, and private directories reduce exposure, but a process running as the same OS user can often replace files or inject input. Platform sandboxing and OS account boundaries remain necessary.

## Trust boundaries

1. Archive reader: compressed attacker bytes become a validated manifest, component, and asset map.
2. Wasmtime component: guest memory and code call only linked WIT imports.
3. Host capabilities: permissions, version negotiation, quotas, normalized paths/URLs, and tracing mediate authority.
4. Worker process tree: compiler and guest failure are killable independently from the UI; OS process groups/jobs and parent-liveness pipes prevent descendants surviving owner failure.
5. Native adapters: graphics, audio, HTTP, discovery, and future devices receive validated host-owned documents, never guest pointers or raw handles.
6. Persistent storage: the public CLI authenticates a cartridge id with a trusted package signature before opening its hashed namespace; stack replicas additionally partition engine-owned state by exact package digest. Commits use locks, revisions, checksums, and rollback generations.
7. Distribution: Ed25519 trust authenticates packages and runtime releases; content addresses and transparency chains detect replacement.
8. Peer mesh: X25519 identities derive authenticated session keys; sequence numbers and AEAD reject forgery and replay.
9. Local engine control: a private random per-boot capability authenticates bounded encrypted loopback frames; instance ids, request ids, freshness checks, replay state, mutation serialization, and daemon leases prevent cross-generation or replayed control.

## Main defenses

- ZIP entry, inflation, count, path, and total-byte limits
- Component Model type boundary with raw WASI networking, directories, environment, terminal, and arguments disabled
- package and operator fuel, epoch deadline, memory/table/instance/resource, media-work, storage, trace, HTTP, peer, CRDT, and simulation limits; operator ceilings can only reduce package budgets
- deterministic record/replay with strict event consumption and input revalidation
- exact-byte package/release signatures and immutable version publishing
- create-new outputs, staged commits, finite locks, compare-exchange revisions, backups, and quarantine
- helper process-tree deadline, minimal environment, parent-death liveness, bounded termination, and a creation-time Windows exploit-mitigation baseline
- opt-in guest health reports sealed with a random per-run key, bound to the exact run id, strictly sequenced, size capped, receipt-time scheduled, and lease-cleaned before another supervisor starts
- no production `unsafe` code in the workspace

## Residual risks and non-goals

- Wasmtime or an enabled native adapter may contain an unknown vulnerability.
- The general CLI worker is killable and Windows workers receive exploit mitigations, but it does not yet enter AppContainer/restricted tokens, macOS sandbox profiles, or Linux namespace/seccomp profiles.
- Job Objects and process groups own complete child trees, while private parent-liveness pipes cover hard daemon and supervisor failure. Kernel-uninterruptible processes can still outlive the two-second reap window, and process containment does not reduce the worker's operating-system authority.
- Portable operator budgets constrain guest-visible and host-mediated work, but they are not kernel CPU-share, resident-memory, file-I/O, or process-count quotas. A native-host escape still has the worker's user-level resource authority until the platform resource layer exists.
- The daemon protocol is confidential and authenticated, but it does not yet use Unix peer credentials or Windows named-pipe ACLs. A local process without the endpoint capability cannot issue a valid command, though it can still consume the small bounded unauthenticated connection pool until its short authentication deadline.
- A guest is authoritative about its own semantic readiness and can lie; probes prevent accidental or failed applications from being promoted, not a malicious workload from claiming health. Another process already running as the same user may deny service to the ephemeral probe path, but cannot forge an accepted signal without the per-run key. Native per-worker authority isolation remains the stronger boundary.
- Rollout checkpoints are mutable recovery state, not the source of desired-state truth. Activation and rollback must be adjacent immutable journal events, active transactions fence other mutations, and any checkpoint/journal divergence outside the two recognized crash windows fails closed.
- The reference HTTP transport is offline fixtures. A production live adapter must defend DNS rebinding, proxy confusion, redirect scope changes, TLS policy, and connection pooling separately.
- Canonical CPU rendering is deterministic; native GPU presentation is not claimed byte-identical across drivers.
- Local state and trace files are integrity-protected where documented but not generally encrypted at rest.
- Traffic analysis, compromised peers after pairing, malicious same-user processes, kernel compromise, firmware compromise, and physical access are not solved by the portable runtime.

Security reports should follow [SECURITY.md](../SECURITY.md). Internal audit documents state reviewed boundaries and remaining gates; they are not substitutes for an independent assessment.
