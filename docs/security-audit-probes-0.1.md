# Application health probe boundary review

Date: 2026-08-14

Scope: stack health policy parsing and planning, guest host calls, worker-to-supervisor reporting, startup/readiness/liveness scheduling, observed status, aggregate health, restart behavior, rollout commit and rollback gates, crash cleanup, and cross-platform end-to-end fixtures.

## Result

No known exploitable issue remains in the implemented guest-signal probe boundary after this review. This result covers opt-in application readiness and liveness reported by the running cartridge. It does not claim that a malicious cartridge tells the truth, and it does not cover future HTTP or command probe runners.

## Findings closed

| ID | Severity | Finding and remediation |
| --- | --- | --- |
| PROBE-01 | high | plaintext or checksum-only reports could disclose application detail and permit local forgery; every envelope is now sealed with XChaCha20-Poly1305 under a random per-run key and 24-byte random nonce |
| PROBE-02 | high | a valid report could otherwise be replayed across attempts or reordered; associated data, plaintext, file location, and supervisor state bind the exact run id, while a strictly increasing sequence rejects repeats and reordering |
| PROBE-03 | high | trusting a worker timestamp would let a guest extend or skip health deadlines; the supervisor schedules every transition from host receipt time and retains guest time only inside the authenticated ephemeral envelope |
| PROBE-04 | medium | guest-provided failure text could leak credentials through status, logs, or daemon responses; detail is validated, capped at 512 bytes, encrypted in transit-at-rest, never copied into durable observed state, and replaced by fixed host messages |
| PROBE-05 | medium | crash-left probe and temporary files could grow without a lifecycle bound; an exclusive supervisor lease now performs canonical, symlink-rejecting cleanup before workers start, with a 4,096-file scan ceiling and no deletion after an unexpected entry is found |
| PROBE-06 | medium | a fast successful job could publish readiness and exit between supervisor polls, consuming a false restart; an exited process now receives one final authenticated report read before readiness classification, and the real fixture must succeed on attempt one |
| PROBE-07 | high | rollout stability measured only from process creation could commit immediately after late readiness; probed running replicas now begin the server-enforced stability window at the most recent ready transition |
| PROBE-08 | medium | enabling application gating implicitly for older components would make existing workloads permanently unready; the policy is explicit in the stack plan, unprobed workloads retain process readiness, and a probed worker cannot use the process-running transition |
| PROBE-09 | medium | oversized, special, symlinked, incomplete, relative, or cross-run channel artifacts could confuse the supervisor or filesystem boundary; paths are engine-derived beneath validated stack/replica identities and canonicalized before crossing into the worker, envelopes are regular files capped at 4 KiB, incomplete worker environments fail closed, and unsafe cleanup entries abort before deletion |
| PROBE-10 | high | an untrusted guest could call the health API in a tight loop and amplify cheap WASM work into repeated host filesystem flushes; reports are now capped at 4,096 calls per worker run, the ephemeral replacement no longer performs durability syncs, and the runtime deadline and fuel budget remain independent outer bounds |
| PROBE-11 | high | accepting only new plan format 3 would make existing format-2 desired-state journals unreadable after an engine upgrade; the reader now accepts format 2 only when probe policy is absent, preserves its original canonical hash by omitting the optional field, and emits format 3 for new plans |
| PROBE-12 | medium | extending the pre-1.0 host interface could silently strand components built against the earlier 0.4 function set; a checked-in legacy WIT/component fixture is built and executed against the current runtime on all three CI platforms |
| PROBE-13 | high | the new probe fields and runtime-status format could prevent a supervisor from reading its pre-upgrade `runtime.json`; format 1 now remains checksum-verifiable only without probe state, absent fields retain their legacy canonical encoding, and all new observations use format 2 |

## Invariants reviewed

- A configured replica remains `starting` until an authenticated `ready` signal for its current run is accepted.
- `started` and `heartbeat` prove channel liveness but do not grant readiness.
- `unhealthy` and missed liveness deadlines make aggregate health degraded; the configured consecutive-failure threshold terminates the process and enters ordinary restart policy.
- Startup and initial-readiness deadlines cannot be extended by guest reports or guest time.
- A later `ready` transition clears probe failures and restarts rollout stability observation.
- Completed one-shot jobs are successful only if they reached readiness first.
- Probe keys and guest details do not appear in debug output, runtime status, health reports, daemon frames, or CLI text.
- Probe state is checksum-bound into generation-fenced runtime status and independently validated against whether the exact plan requested health gating.

## Evidence

- encrypted-envelope tamper, wrong-run, key-redaction, size, and detail-bound tests
- supervisor state-machine tests for ready gating, replay rejection, unhealthy transitions, timeout thresholds, and recovery
- aggregate health tests for waiting, ready, and degraded probe counts
- runtime host test proving bounded out-of-band forwarding without trace mutation
- runtime host test proving the per-run report ceiling drops later calls
- CLI file-replacement round trip proving authenticated sequence advancement
- a real relative-root supervisor run proving the worker receives a canonical absolute channel path and reaches readiness on its first attempt
- engine cleanup test proving bounded canonical removal and fail-before-delete behavior for unexpected files
- legacy plan-format validation and a pre-health 0.4 component compatibility corpus
- real WASM supervisor runs proving ready one-shot success on attempt one, startup timeout for a silent guest, and liveness termination after the configured failure threshold
- cross-platform CI fixtures for the same positive, startup-timeout, and liveness-timeout paths

## Residual risks

- The guest can deliberately claim readiness while semantically broken. Independent command, HTTP, service-edge, metric, or operator gates are still needed for adversarial correctness checks.
- A same-user process that can interfere with private engine files may deny service, inspect worker process memory, or steal the per-run key. Restricted tokens/AppContainer and Unix authority sandboxes remain required to narrow that boundary.
- Reports use a private filesystem channel because the current contained-process abstraction exposes only the parent-liveness pipe. A future authenticated inherited IPC channel can remove the ephemeral file race surface.
- Signal probes do not provide zero-downtime replacement. Concurrent generations, ready-only routing, draining, surge/unavailable windows, and canaries remain scheduler work.
