# Rolling policy and scheduler review

Date: 2026-08-16

Scope: rolling-policy parsing, plan identity and legacy readers, per-instance and aggregate bounds, generation-separated ordinal observations, deterministic action selection, availability and surge arithmetic, minimum-ready and progress gates, drain deadlines, and terminal candidate handling.

## Result

No known exploitable issue remains in the implemented rolling policy and decision boundary after this review. This result covers policy validation and the pure scheduler. It does not cover live concurrent-generation execution, routing, or drain IPC because those layers are not implemented yet.

## Findings closed

| ID | Severity | Finding and remediation |
| --- | --- | --- |
| RLP-01 | high | an operator policy could otherwise create unbounded replacement workers; surge is capped by the declared replica count, each instance remains bounded to 32 replicas, and aggregate stack surge is capped at 64 above the 256-replica desired-state ceiling |
| RLP-02 | medium | zero surge combined with zero unavailable capacity would create a permanent scheduler deadlock; that combination is rejected during manifest and plan validation |
| RLP-03 | high | forged or corrupted readiness observations could authorize an unsafe drain; previous readiness must be a subset of previous active replicas, while candidate availability must be backed by readiness and an active candidate process |
| RLP-04 | high | mixing ordinals or terminal state across generations could stop the wrong worker; previous and candidate sets are separate, every ordinal is range checked, and a terminal candidate cannot simultaneously be active |
| RLP-05 | high | arithmetic or selection errors could exceed surge or reduce ready capacity below policy; all counts use bounded checked or saturating arithmetic, actions select canonical ascending ordinals, and an exhaustive small-state test covers every legal policy and valid observation through three replicas |
| RLP-06 | medium | a candidate could wait forever without reaching readiness; progress deadlines are mandatory, bounded from one second through one hour, must exceed minimum-ready and drain windows, and return an explicit rollback action |
| RLP-07 | high | an exhausted candidate could be ignored while old capacity slowly drained; any terminal candidate returns rollback before another start or drain action |
| RLP-08 | medium | a drain could remain graceful forever and pin both generations; the drain timeout is plan-bound, capped at five minutes, and may explicitly be zero for immediate termination |
| RLP-09 | high | policy changes after operator review could widen availability or resource use; non-default policy is checksum-bound in plan format 4, and mutations invalidate the plan digest |
| RLP-10 | high | upgrading the plan reader could make existing desired-state journals unreadable; format 2 remains accepted only without health or rolling policy, format 3 remains accepted only without rolling policy, default rolling fields retain their omitted legacy encoding, and new plans emit format 4 |
| RLP-11 | medium | the desktop could present an exact digest without showing the new policy that affects capacity and availability; plan review now displays order, surge, unavailable, minimum-ready, progress-deadline, and drain values, with the canonical defaults supplied for legacy plans whose field is intentionally omitted |

## Invariants reviewed

- A start action never makes active old plus candidate replicas exceed `replicas + max_surge`.
- A drain action never reduces ready old plus minimum-ready candidates below `replicas - max_unavailable` when the observation began at or above that threshold.
- Candidate readiness cannot count until an active candidate exists, and candidate availability cannot count until readiness exists.
- Completion requires no active previous replica and every desired candidate ordinal to be minimum-ready.
- Candidate terminal state and an expired progress deadline produce rollback rather than another mutating action.
- Every action is deterministic for the same policy and observation.
- Policy and observations contain counts and ordinals only; they contain no package arguments, secret values, health details, paths, or daemon credentials.

## Evidence

- focused start-first and stop-first progression tests
- readiness, minimum-ready, terminal-candidate, progress-deadline, completion, and surge rejection tests
- exhaustive valid-state enumeration for one through three replicas across both orderings and every legal surge/unavailable pair
- format-2 and format-3 compatibility tests plus format-4 policy digest tamper rejection
- cross-platform manifest validation and exact plan-output checks in CI
- production frontend build covering backward-compatible policy rendering in the exact-plan inspector

## Residual risks

- The live executor still activates a whole desired generation. Scheduler progress must be persisted and recovered before actions can safely control real workers.
- Ready-only service routing and connection draining require a service broker and ingress layer. Process readiness alone cannot preserve in-flight requests.
- Stateful updates need schema compatibility or a verified migration rollback receipt before old and candidate writers can overlap.
- The scheduler currently treats an exhausted candidate as terminal. Canary metrics, manual pause/resume, and retryable deployment-level failures remain later policy layers.
