# Engine health boundary review

Date: 2026-08-14

Scope: supervisor heartbeat persistence, health derivation, authenticated health responses, readiness waiting, deadline propagation, CLI command construction, and aggregate resource bounds.

## Result

No known exploitable issue remains in the implemented process-health boundary after this review. The feature reports convergence and supervisor freshness; it does not claim that a running process is application-healthy.

## Findings fixed during implementation

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| HEALTH-01 | high | adding more engine subcommands exhausted the default Windows main-thread stack during Clap command construction, denying every CLI operation | command parsing and execution now run on a named thread with a fixed 8 MiB stack; the worker liveness and daemon integration regressions cover startup afterward |
| HEALTH-02 | medium | a readiness timeout could be exceeded by the shared client's fixed 15-second socket timeout | the shared client accepts a nonzero caller deadline, clamps it to the global maximum, and `engine wait` passes only its remaining budget on every request |
| HEALTH-03 | medium | an unbounded aggregate health request could amplify one authenticated request across the full 1,024-stack inventory while holding the engine lock | aggregate reports are capped at 64 sorted entries and larger installations must select a stack; replica counts and the daemon frame remain independently bounded |
| HEALTH-04 | medium | a structurally valid runtime status from another desired generation could otherwise influence a derived report | health derivation binds stack, revision, and the exact checksum-chained event generation before counting any phase |

## Boundary decisions

- Health reports are canonical, checksum-bound documents with strict unknown-field rejection and count consistency checks.
- Only the authenticated encrypted daemon protocol exposes aggregate or selected health.
- A supervisor heartbeat changes only observation time and document identity; it cannot alter replica phase, restart policy, or run identity.
- A live phase becomes stale after 20 seconds without a valid heartbeat. Terminal completed and failed results remain terminal rather than aging into stale.
- Ready means all desired running replicas are either running or completed successfully. Degraded and failed states make the wait command fail early.
- Application-specific probes are intentionally absent. Process health is not mislabeled as HTTP, service, or semantic health.

## Verification

- readiness transition tests cover starting, healthy, completed, stale, stopped, and removed state
- changed counts, report identities, generation mismatches, and oversized aggregates fail closed
- heartbeat tests prove monotonic observation without replica mutation
- zero client deadlines are rejected before endpoint access
- authenticated daemon integration covers empty aggregate health and missing-stack wait failure
- cross-platform CI exercises `engine wait` and validates the resulting health document against a real supervised cartridge

## Remaining gates

- Manifest-defined startup, readiness, and liveness probes need bounded schedules, output limits, and explicit capability rules.
- Safe updates still require prepare, activate, commit, rollback evidence, surge/unavailable ceilings, and crash recovery.
- Heartbeats prove supervisor observation, not kernel-enforced CPU/RSS health or application correctness.
