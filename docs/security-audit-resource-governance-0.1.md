# Resource governance security review

Date: 2026-08-14

Scope: stack resource declarations, immutable plan encoding, supervisor-to-worker transfer, runtime enforcement, snapshot branches, Windows process-creation mitigations, and regression behavior. This is an internal review, not an independent security assessment.

## Result

No known exploitable issue remains in the implemented portable operator-budget boundary after the fixes and tests below. The boundary lets an operator reduce a package's fuel, linear-memory, wall-time, storage, graphics, and audio allowances. It does not provide kernel CPU-share, resident-memory, file-I/O, disk, or process-count quotas, and it is not an operating-system authority sandbox.

## Findings fixed

| ID | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| RGC-01 | high | stack policy could remove capabilities but could not reduce resource budgets requested by a package | every instance can declare bounded optional ceilings; planning resolves the minimum and binds all exact values into plan format 2 |
| RGC-02 | high | a launch-path bug could have omitted a planned ceiling after review | the worker receives a bounded strict document through its cleared private control environment and `cartridge-runtime` intersects it again at the enforcement boundary |
| RGC-03 | high | snapshot branches were constructed with package storage limits before a runtime ceiling could apply | branch construction now uses the effective storage byte, key, and value limits before any state operation |
| RGC-04 | medium | a client with the daemon capability could recompute a valid plan digest after raising a resource ceiling; the supervisor rejected launch, but the altered desired plan could be journaled first | apply-time installed-package verification and the supervisor both reopen the exact package and reject any plan value that is not a ceiling before mutation or launch |
| RGC-05 | medium | contained Windows helpers used process-tree ownership without creation-time exploit mitigations | a JIT-compatible DEP, SEHOP, ASLR, heap, extension-point, font, and image-loading policy is applied in the same atomic creation transaction |
| RGC-06 | medium | adding the internal limit document to the generated public CLI command enum exhausted the default Windows main-thread stack during ordinary commands | the field was removed from the public parser; the bounded document now travels only in the already-cleared private worker environment, and normal `pack` execution is covered again |

## Evidence

- manifest limits share one validator and `constrained_by` operation, including the storage total/value invariant
- plan validation recomputes its digest and rejects invalid exact limits
- hidden worker input rejects unknown fields, zero or out-of-range values, and documents larger than 4096 bytes before package access
- a live Windows smoke run proves a normal component succeeds under reduced fuel, memory, deadline, and storage ceilings
- the same exact package deterministically traps with `all fuel consumed by WebAssembly` when its stack ceiling is one fuel unit
- Windows parent-death, descendant-tree termination, and liveness tests pass with the mitigation policy active
- cross-platform CI validates the reduced plan and exercises both the successful and deliberately exhausted stack

## Invariants

- a ceiling can only reduce a validated package limit
- the effective limits, not operator input with omitted fields, are committed to desired state
- changing any effective limit changes the plan digest and desired generation
- workers do not inherit ambient environment; only exact control variables are supplied
- storage limits apply when a snapshot branch is constructed, not only after guest execution begins
- disabling a stack sandbox policy can omit optional Windows exploit mitigations for that guest worker, but never disables process-tree ownership, parent liveness, archive validation, Wasmtime limits, or operator ceilings

## Residual risk

- Portable limits bound Wasm and mediated host work. They do not cap native compiler/JIT RSS, CPU share, open handles, filesystem throughput, or total engine disk use at the kernel.
- Windows mitigations make exploitation harder but do not remove filesystem, registry, token, socket, or same-user authority. Restricted tokens or AppContainer remain required.
- macOS and Linux have process ownership but no equivalent authority sandbox in this slice. Seatbelt-style profiles, namespaces, Landlock, seccomp, and cgroups remain future work where supported.
- The private worker environment is an integrity channel from the trusted parent in the normal launch path, not an authentication boundary against another process already running as the same user. Parent liveness and exact package verification remain separate defenses.
- A lower operator deadline is also enforced by the outer supervisor, but scheduling jitter means it is not a deterministic replay input.
- Plan format 2 is a pre-release compatibility break. Old desired plans fail closed rather than silently gaining default budgets.

Do not describe this slice as kernel resource isolation, a complete native sandbox, or proof that arbitrary hostile third-party code is safe. Those claims remain gated on platform authority adapters, kernel quotas, and independent review.
