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
4. Worker process: compiler and guest failure are killable independently from the UI.
5. Native adapters: graphics, audio, HTTP, discovery, and future devices receive validated host-owned documents, never guest pointers or raw handles.
6. Persistent storage: the public CLI authenticates a cartridge id with a trusted package signature before opening its hashed namespace; stack replicas additionally partition engine-owned state by exact package digest. Commits use locks, revisions, checksums, and rollback generations.
7. Distribution: Ed25519 trust authenticates packages and runtime releases; content addresses and transparency chains detect replacement.
8. Peer mesh: X25519 identities derive authenticated session keys; sequence numbers and AEAD reject forgery and replay.

## Main defenses

- ZIP entry, inflation, count, path, and total-byte limits
- Component Model type boundary with raw WASI networking, directories, environment, terminal, and arguments disabled
- fuel, epoch deadline, memory/table/instance/resource, media-work, storage, trace, HTTP, peer, CRDT, and simulation limits
- deterministic record/replay with strict event consumption and input revalidation
- exact-byte package/release signatures and immutable version publishing
- create-new outputs, staged commits, finite locks, compare-exchange revisions, backups, and quarantine
- helper process deadline and minimal environment
- no production `unsafe` code in the workspace

## Residual risks and non-goals

- Wasmtime or an enabled native adapter may contain an unknown vulnerability.
- The general CLI worker is killable but does not yet enter AppContainer/restricted tokens, macOS sandbox profiles, or Linux namespace/seccomp profiles.
- A graceful supervisor signal kills owned children, and every worker retains a Wasmtime deadline. A hard supervisor crash can still leave a child alive until that deadline because platform job objects and parent-death controls are not implemented yet.
- The reference HTTP transport is offline fixtures. A production live adapter must defend DNS rebinding, proxy confusion, redirect scope changes, TLS policy, and connection pooling separately.
- Canonical CPU rendering is deterministic; native GPU presentation is not claimed byte-identical across drivers.
- Local state and trace files are integrity-protected where documented but not generally encrypted at rest.
- Traffic analysis, compromised peers after pairing, malicious same-user processes, kernel compromise, firmware compromise, and physical access are not solved by the portable runtime.

Security reports should follow [SECURITY.md](../SECURITY.md). Internal audit documents state reviewed boundaries and remaining gates; they are not substitutes for an independent assessment.
