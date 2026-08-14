# Engine rollout boundary review

Date: 2026-08-14

Scope: candidate preparation, installed-package verification, desired-state activation, health-gated commit, cancellation, previous-generation rollback, checkpoint replacement and recovery, terminal history, authenticated protocol exposure, and automatic update orchestration.

## Result

No known exploitable issue remains in the implemented whole-generation rollout transaction after this review. This result covers crash-consistent process-health-gated replacement and rollback. It does not certify zero-downtime scheduling or application correctness.

## Findings fixed during implementation

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| ROLL-01 | critical | an ordinary apply, stop, or remove during a prepared or activated rollout could detach the checkpoint from desired state and make rollback target the wrong generation | every direct mutation now recovers and checks the current rollout first, then refuses while a transaction is active |
| ROLL-02 | high | a crash after appending activation or rollback but before replacing the checkpoint could leave the transaction one phase behind its immutable journal | recovery accepts only the exact adjacent candidate or previous-plan event, derives the missing phase, and rewrites the checksum-bound checkpoint; any other divergence fails closed |
| ROLL-03 | high | rollback could reactivate package identities that had changed or disappeared after preparation | the daemon reopens the library and re-verifies every exact package in the retained previous plan before appending rollback |
| ROLL-04 | medium | unbounded checkpoint history could turn repeated authenticated updates into disk and directory-scan exhaustion | one current document is bounded to two maximum plans plus fixed metadata; terminal history is capped at 256 canonical regular files and 256 MiB per stack, and new updates stop before either limit |
| ROLL-05 | medium | a stale or cross-stack rollout identifier could otherwise control a newer transaction | every request carries a digest identifier recomputed from stack, time, previous generation, and candidate plan; it must equal the current checkpoint before mutation |
| ROLL-06 | high | a candidate could briefly reach `running`, commit, and then crash immediately afterward | commit requires generation-fenced ready health; every running replica must also survive a server-enforced two-second stability window, while successfully completed jobs may commit immediately; the final health checksum is bound into the checkpoint |
| ROLL-07 | medium | losing the prepare or rollback response could strand a successful mutation as an apparent client failure | automatic update queries the authenticated current checkpoint after either ambiguous response and resumes only when stack, candidate or rollout identity, and the expected phase all match |
| ROLL-08 | medium | returning the full checkpoint duplicated both plans into control responses, creating frame-size pressure and disclosing unnecessary arguments and policy detail | daemon responses now use a compact independently checksummed status that carries only identities, phases, generations, and health evidence; complete plans remain private in the engine checkpoint |

## Security properties

- Preparation changes no desired state and can be cancelled without creating a journal event.
- Candidate and rollback package bytes are re-verified at the last daemon boundary before activation.
- Activation and rollback are immutable desired-state journal entries; the mutable checkpoint cannot rewrite that history.
- The previous revision, generation, state, and complete plan are retained and checksum-bound.
- Active transactions serialize with all other daemon mutations and also fence direct `EngineStore` mutation calls.
- Rollback after an activated or committed candidate restores the previous plan, stopped plan, or tombstone exactly.
- Automatic `engine update` keeps readiness and the stability observation inside its deadline, rolls back when activation, readiness, stability, or commit fails, and reports a second error if rollback itself cannot be proven.
- Protocol version 2 prevents an older daemon/client pair from silently misinterpreting rollout messages.
- Complete checkpoints contain package identities, policy, arguments, and secret names, but never secret values or daemon credentials. Authenticated clients receive only compact rollout status documents.

## Verification

- unit coverage for prepare, cancel, activate, health and stability rejection, health-bound commit, stopped candidates, post-commit rollback, tamper rejection, history ceilings, compact plan-free status, and both journal/checkpoint crash windows
- integration coverage for authenticated missing-checkpoint queries and bounded CLI command construction
- live Windows daemon runs covering initial update, stability-gated commit, compact status identity, post-commit rollback, a second update, terminal checkpoint archival, and automatic rollback of a worker that exhausts fuel after briefly reaching `running`
- cross-platform CI runs `engine update`, checks a committed checkpoint and its health digest, and continues through normal health, process, event, stop, remove, and shutdown operations

## Remaining gates

- The current scheduler replaces one complete generation. It does not preserve old and new workers concurrently, enforce `max_surge` or `max_unavailable`, or route canary traffic.
- Commit uses process readiness. Manifest-defined startup, readiness, and liveness probes are still required before claiming application-health-gated rollout.
- Rollback restores desired state and exact package identity, but state-schema compatibility still depends on explicit migration planning and receipts.
- Per-stack checkpoint history is bounded, but a lower engine-wide disk quota and authenticated pruning policy are still required for large multi-stack installations.
- Native authority sandboxes and kernel CPU, RSS, I/O, and disk enforcement remain independent release gates.
