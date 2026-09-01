# Engine routing boundary review

Date: 2026-09-01

Scope: ready-only replica selection, rollout candidate admission, previous-generation removal, stop/remove behavior, snapshot integrity, crash recovery, daemon publication, authenticated query exposure, and bounded resource use.

## Result

No known exploitable issue remains in the implemented local routing-membership plane after this review. The implementation deliberately does not claim inbound ingress, connection draining, TLS, load balancing, or service authorization.

## Findings fixed during implementation

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| ROUTE-01 | critical | a supervisor could observe old-generation drain intent before a router learned that the replica was no longer eligible, creating a window for new work to enter a draining process | the coordinator publishes removal from its in-memory next progress state before persisting drain intent; authoritative reads fail closed during the narrow crash window |
| ROUTE-02 | high | a syntactically valid snapshot could remain routable after health, desired state, run identity, or rollout progress changed | every daemon query re-derives the complete expected target set from authoritative current state and rejects any mismatch |
| ROUTE-03 | high | rebuilding a corrupted snapshot at sequence one could create an ABA ambiguity for consumers that remembered only a sequence | snapshots include a random epoch; repair starts a new epoch and consumers compare epoch plus sequence |
| ROUTE-04 | medium | a corrupt routing file for one stack could terminate the daemon reconcile loop and interrupt unrelated stacks | bounded regular-file corruption is rebuilt; unrecoverable per-stack publication errors are reported without stopping global reconciliation |
| ROUTE-05 | medium | attacker-controlled routing documents could use links, special files, oversized JSON, duplicate endpoints, or unordered data to widen access or exhaust parsing | paths reject symlinks and non-regular files, reads are capped at 1 MiB, target counts use the aggregate replica ceiling, fields are strict, targets are sorted and unique, and the document is checksummed |
| ROUTE-06 | medium | wall-clock regression could make a newer membership document appear older while advancing its sequence | changed publications reject a timestamp lower than the previous valid snapshot; ordering remains epoch and sequence based |

## Security properties

- Routing state is derived availability data and never grants package, capability, filesystem, or network authority.
- Only exact authorized generation and run identities can appear.
- Opted-in health probes gate publication; unhealthy and stale runtime state is removed on the next reconciliation and rejected immediately by authoritative reads.
- Candidate replicas are excluded until both rollout intent and runtime readiness agree.
- Previous replicas are excluded before their drain deadline begins.
- Stop and remove produce an empty target set.
- The authenticated daemon protocol version is bumped for the new response shape.

## Verification

- focused tests cover unready-to-ready transitions, health regression, stale authoritative state, route-before-drain ordering, stop revocation, semantic tampering, corrupt-file recovery with epoch rotation, and backwards publication time
- the daemon rollout coordinator test covers candidate admission, old-replica removal, and committed-generation membership across a two-replica rolling update
- workspace tests, lints, dependency audits, and desktop checks passed locally; cross-platform CI remains the final release evidence for the complete change

## Remaining gates

- There is no inbound proxy or typed service router yet. Future ingress must consume only authenticated daemon snapshots and must fence cached connections by epoch, generation, and run id.
- Readiness is guest-signalled. Independent bounded HTTP and command probes are still required for stronger application correctness.
- Same-user processes can deny service to mutable engine files. Native OS authority sandboxes and peer credentials remain required release layers.
- Kernel CPU, resident-memory, I/O, process-count, and engine-wide disk quotas remain separate work.
