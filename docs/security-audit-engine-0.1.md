# Engine control-plane security review

Date: 2026-08-14

Scope: the complete workspace plus the first `cartridge-engine` stack planner, desired-state journal, CLI lifecycle, parser fuzz boundary, and CI integration. This is an internal review, not an independent assessment.

## Result

No known exploitable issue remains in the reviewed control-plane boundary. The engine does not execute or reconcile stack instances yet, so this result does not certify a future supervisor, daemon, local API, desktop shell, or native sandbox adapter.

## Findings fixed during review

| id | severity | finding | resolution |
| --- | --- | --- | --- |
| ENG-01 | medium | a checksum-valid plan did not independently bind effective permissions to the selected security profile and explicit grant/block inputs | plans now retain the explicit inputs and recompute the only valid allowed/denied partition during validation |
| ENG-02 | medium | a plan could carry package identity fields that disagreed with its validated composition root | plan validation now binds cartridge id, version, package digest, and byte length to the exact root lock |
| ENG-03 | medium | repeated large dependency locks could grow an in-memory plan substantially before the event-size check | plan construction and canonical serialization now share an 8 MiB aggregate ceiling |
| ENG-04 | low | resource owners, secret references, collection ordering, and argument aggregate size were not all revalidated when reading a persisted plan | every persisted field is now bounded and cross-checked independently of manifest parsing |
| ENG-05 | low | journal enumeration ignored directory read failures and unrelated entries | event directories now fail closed on enumeration errors, non-canonical chains, and unexpected entries while allowing only crash-leftover temporary names |
| ENG-06 | low | newly created engine directories relied on the process umask on Unix | engine directories request mode `0700`; event and lock files request mode `0600` |
| ENG-07 | low | an event tagged as `stop` could contain a valid plan with running instances | stop events now require every instance to have stopped desired state |

Regression tests cover recomputed permission widening, detached package identity, changed event bytes, unexpected journal entries, sandbox-disabled confirmation, exact version selection, and idempotent apply/stop/remove chains.

## Verification

- formatting and strict Clippy across the workspace
- strict Clippy and compilation for every fuzz target
- complete debug and release workspace test suites
- a real CLI stack lifecycle from package creation and library installation through validate, exact plan, idempotent apply, list, stop, remove, and status
- RustSec audit of the workspace, fuzz workspace, four examples, and two hostile/runtime fixture lockfiles
- nightly libFuzzer build of the engine manifest/plan/event target

The Windows host could not start the libFuzzer executable because its matching sanitizer DLL is unavailable (`STATUS_DLL_NOT_FOUND`). The target is included in the pinned Ubuntu fuzz workflow, where it runs with the existing parser targets.

## Residual and future gates

- `sandbox = "required"` is desired-state policy only until a reconciler launches workers through verified platform-native sandbox adapters. Apply never claims that a process is running.
- Before activation, the supervisor must reopen the exact package, recheck its digest and composition lock, require trusted signature evidence, and refuse catalog drift.
- The checksum chain detects accidental changes and partial rewrites; it is not an authentication boundary against a malicious process already running as the same OS user.
- Secret declarations contain names and required/optional policy only. Values must be delivered through a future operation-scoped secret broker and must never enter plans, arguments, events, logs, or traces.
- Journal compaction needs authenticated checkpoints, rollback protection, and recovery tests before the current 4096-event ceiling can be lifted.
- The local daemon/API must authenticate its peer, authorize every mutation, bind requests to the interactive OS user, resist replay and confused-deputy paths, and keep privileged adapters outside the main process.
- Native sandbox adapters, the live service broker, ingress, GPU/audio/network helpers, installers, and the desktop shell each require their own focused review.

The broader portable-runtime conclusions and original timeout, archive-inflation, and table-growth regressions remain covered by [the 1.0 candidate review](security-audit-1.0-rc.md) and [threat model](threat-model.md).
