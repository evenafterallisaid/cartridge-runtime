# Engine daemon and full-workspace security review

Date: 2026-08-14

Scope: the complete Rust workspace, native desktop shell, dependency graphs, package/runtime/storage boundaries, desired and observed engine state, foreground supervision, and the first rootless persistent engine daemon. This is an internal review, not an independent security assessment.

## Result

No known exploitable issue remains in the implemented daemon protocol and lifecycle boundary after the fixes below. This result does not certify the missing platform-native worker sandboxes, OS process-tree containment, peer-credential transports, service broker, secret broker, ingress, health-gated rollout, signed installers, or fleet control plane.

## Findings fixed during review

| id | severity | finding | resolution |
| --- | --- | --- | --- |
| DAE-01 | critical | JSON startup output initially serialized the endpoint object and would have exposed the daemon control key to logs | startup output now constructs an explicit public-only document; the endpoint debug implementation redacts the key and an end-to-end regression test rejects `key_hex` in output |
| DAE-02 | high | a predictable loopback or browser-compatible API would let unrelated local or web content attempt control-plane commands | the listener binds exact IPv4 loopback, uses a non-HTTP length-prefixed protocol, and accepts commands only after XChaCha20-Poly1305 authentication with a random 256-bit per-boot capability |
| DAE-03 | high | captured requests could otherwise be replayed or reflected across directions and daemon restarts | request and response AEAD use distinct associated data, every frame is bound to the random daemon instance, requests have random ids and timestamps, and a finite cache rejects duplicates and requests outside the 30-second freshness window |
| DAE-04 | high | a daemon crash could leave an earlier supervisor continuing after a replacement daemon starts | every daemon-launched supervisor is fenced by both the exact boot instance and the still-held daemon lease; it checks ownership every 250 milliseconds and stops its workers when either changes |
| DAE-05 | medium | unauthenticated loopback clients could request large allocations or unbounded threads before authentication | frames are capped at 4 MiB, authentication reads have a short deadline, only eight clients may be active, replay state is capped at 4096 ids, responses are bounded, and malformed frames receive no authenticated error oracle |
| DAE-06 | medium | concurrent apply/stop/remove and shutdown calls could reorder desired state or let a mutation land after shutdown began | mutations are serialized, shutdown takes the mutation fence before changing state, later mutations fail closed, the endpoint is withdrawn, and accepted clients drain before supervisors are stopped |
| DAE-07 | medium | endpoint replacement, symlinks, permissive Unix roots, partial writes, or stale files could expose or redirect the control capability | endpoint and lock paths must be regular non-symlink files, Unix daemon roots reject group/other access, endpoint files request mode `0600`, publication is flushed and atomically replaced, and removal is instance-bound |
| DAE-08 | medium | unconstrained stacks, supervisors, workers, events, frames, or retries could turn valid control commands into process or memory exhaustion | the engine caps known stacks at 1024, daemon supervisors at 64, total replicas and per-stack workers at 256, event tails at 256, frames at 4 MiB, and active clients at eight; supervisor-process failures use exponential retry delay capped at 30 seconds and reset only after a stable run |
| DAE-09 | medium | a reviewed plan could be applied after the installed catalog bytes changed | daemon apply reopens the configured library and re-verifies exact package bytes, lengths, hashes, manifests, and composition locks before the journal mutation |
| DAE-10 | low | stale observed state from the previous desired generation could prevent normal reconciliation | status from another revision or generation is treated as absent, while checksum-validating the matching generation still fails closed on tampering |
| DAE-11 | low | key material copied into endpoint and codec values could remain in ordinary memory after use | the codec key array and serialized endpoint key string are zeroized on drop, and custom debug output never includes the capability |
| DAE-12 | low | desktop settings checked file size before using an unbounded convenience read, leaving a growth race between metadata and read | settings are now read through a `MAX_SETTINGS_BYTES + 1` limited handle and rejected if the post-read bound is crossed |
| DAE-13 | high | the engine bounded each journal event and the event count but not aggregate decoded history, allowing a valid worst-case journal to demand tens of gigabytes | each stack history now has a 64 MiB aggregate budget enforced during append and during sequential reads from actual bytes, in addition to the per-event and count limits |

## Verification

- strict formatting and Clippy with warnings denied for the engine and CLI during implementation
- engine and CLI unit suites, including cryptographic direction separation, tamper rejection, endpoint privacy, replay rejection, bounded framing, and terminal-safe errors
- a real daemon integration test covering startup, private discovery, malformed unauthenticated traffic, authenticated ping/info, clean shutdown, endpoint removal, and key-free output
- cross-platform CI workflow extended to run install → daemon start → authenticated apply → automatic supervision → observed success → event query → stop → remove → shutdown
- manual live Windows run of daemon startup, authenticated ping/info, shutdown response, zero exit, and stale-endpoint removal
- engine fuzz target extended across endpoint, frame, request, and response decoders and validators
- production-source scan found no Rust `unsafe` blocks and no committed private-key markers
- RustSec scan: 0 vulnerabilities across 271 resolved root-workspace dependencies
- npm audit: 0 vulnerabilities in the desktop graph
- desktop RustSec scan: 0 vulnerability advisories; 16 unmaintained target-specific transitive warnings and one `glib` unsoundness warning remain on the already-blocked Linux desktop packaging graph
- full workspace formatting, strict Clippy, tests, desktop native tests, and frontend production build recorded at the reviewed commit before publication

## Residual security gates

- Wasmtime capability isolation and helper deadlines are active, but a runtime or native-host escape still reaches the user's process authority until restricted Windows tokens/AppContainer, macOS sandbox profiles, and Linux namespaces/seccomp/cgroups exist.
- Graceful daemon and supervisor shutdown stops workers, and daemon ownership loss is detected quickly. A hard supervisor crash can still leave a bounded worker alive until its Wasmtime deadline because Windows Job Objects and Unix parent-death/process-group containment are not implemented yet.
- The random endpoint capability authenticates control commands, but the first transport does not inspect Unix peer credentials or use Windows named-pipe ACLs. Unauthenticated local traffic is memory/time bounded but can still cause availability pressure.
- The endpoint key is protected by private creation and the user's directory ACLs; it is not encrypted at rest. A malicious process already running as the same OS user remains partly outside this boundary.
- The daemon is invoked as a foreground user service. Login startup, service-manager manifests, upgrade handoff, and crash-loop policy for the daemon itself are not implemented.
- Health checks, staged/rolling rollback, typed service calls, ingress, runtime secrets, and structured log streaming are not implemented and are outside this result.
- The desktop still uses its narrow native commands directly; switching it to the daemon must preserve the rule that the webview never receives endpoint key material or raw process authority.
- Linux desktop production packaging remains blocked on the target-specific Tauri/GTK3 maintenance and unsoundness advisories already documented by the desktop review.
- Fuzz coverage is bounded and internal. Independent review and platform sandbox penetration testing remain release gates.

Do not describe Cartridge as a complete Docker replacement or as safe for arbitrary hostile third-party code until the native sandbox, process containment, and independent-assurance gates are complete.
