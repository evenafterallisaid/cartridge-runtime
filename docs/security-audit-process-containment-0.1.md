# Native process-containment security review

Date: 2026-08-14

Scope: one-shot CLI workers, stack replica workers, daemon-owned stack supervisors, their descendant processes, hard parent failure, explicit termination, process cleanup, and the new Unix `command-group` and Windows `windows-spawn` dependencies. This is an internal review, not an independent security assessment.

## Result

No known exploitable issue remains in the implemented native process-ownership boundary after the fixes and adversarial tests below. Process containment prevents orphaned work and bounds shutdown; it does not replace restricted tokens, AppContainer, macOS sandbox profiles, Linux namespaces/seccomp/cgroups, or an independent assessment.

## Findings fixed during review

| id | severity | finding | resolution |
| --- | --- | --- | --- |
| PCT-01 | high | killing only the direct worker PID could leave a native descendant running outside the supervisor deadline | every managed child now leads one contained process tree; termination targets the complete Job Object or process group |
| PCT-02 | high | a hard supervisor crash on Unix could leave a bounded Wasm worker alive until its own wall-clock deadline | every daemon-supervisor and supervisor-worker edge owns a private pipe; EOF makes the child exit immediately and the failure cascades down the tree |
| PCT-03 | high | assigning an already-running Windows child to a Job Object would leave an escape race; the first candidate library could also leak a suspended process and raw handles when assignment failed | the candidate was replaced; the final backend supplies the private kill-on-close Job through the `CreateProcessW` attribute list and transactionally terminates any partially created child on setup failure |
| PCT-04 | medium | `kill` followed by an unbounded blocking `wait` could hang the control plane on an uninterruptible process | termination polls for at most two seconds; Windows then closes its kill-on-close Job and Unix repeats group termination when the wrapper is dropped |
| PCT-05 | medium | panic or early-return paths could drop a still-running child handle without terminating its tree | the local child wrapper kills a still-armed process tree on drop; normal paths record exit before disarming it |
| PCT-06 | medium | the hidden worker context previously relied only on a forgeable environment marker | workers now also require the parent-liveness channel before opening a package or runtime; a regression test rejects the old environment-only invocation |
| PCT-07 | low | repurposing stdin for liveness could accidentally grant a guest a host input channel | the pipe is consumed only by a host watchdog thread; WASI stdin remains unavailable and any byte on the liveness channel terminates the worker |

## Verification

- a Windows adversarial test launches a contained leader which launches a delayed descendant, kills the leader tree, and proves the descendant cannot write its escape sentinel
- a parent-death test launches a worker fixture, closes only its liveness writer, and observes a non-success exit within a fixed deadline
- a cascade test severs the daemon-side liveness channel only after a nested supervisor and worker are live, then proves neither the supervisor nor its delayed worker survives
- an integration test proves `CARTRIDGE_WORKER=1` without the private liveness channel fails before package access
- a live Windows smoke run packs and installs the reference cartridge, starts the daemon, applies a stack, observes its contained worker succeed, authenticates shutdown, and observes a clean daemon exit
- all one-shot workers, stack workers, and daemon supervisors use the same containment constructor; the remaining process spawn is the developer-authored build command and is not a runtime worker
- strict workspace Clippy with warnings denied and the complete workspace test suite pass locally
- root RustSec scan: 0 vulnerabilities across 277 resolved dependencies, including exact-pinned Unix `command-group` 5.0.1 and Windows `windows-spawn` 0.1.0
- npm audit: 0 vulnerabilities
- desktop RustSec scan: 0 vulnerability advisories; 16 unmaintained transitive warnings and one `glib` unsoundness warning remain in the blocked GTK3 Linux desktop graph
- production workspace source remains subject to `unsafe_code = "forbid"`; platform-specific unsafe system calls are isolated inside the reviewed third-party process libraries

## Residual security gates

- Process ownership is not authority reduction. A Wasmtime or native-host escape still reaches the worker's user-level OS authority until platform sandbox adapters are enabled.
- Process groups and liveness pipes do not provide kernel CPU, resident-memory, I/O, or disk quotas. Windows Job limits and Linux cgroups remain part of the resource-control layer.
- A kernel-uninterruptible process can exceed the two-second reap window. The engine stops waiting so one broken child cannot indefinitely hang shutdown, but the operating system remains responsible for final reclamation.
- A same-user malicious process can simulate environment variables and a pipe. The hidden worker command is defense in depth, not an authentication boundary; package validation, Wasmtime isolation, and capability ceilings remain mandatory.
- Job Object assignment can be denied by an incompatible outer Windows job. Startup fails closed rather than running the worker without containment.
- A native process that can deliberately create a new Unix session or process group can escape group signaling. Cartridges have no process-spawn interface; native-code compromise remains in the platform-sandbox threat model.
- Cross-platform CI provides regression evidence on current hosted runners, not proof across every supported kernel or service-manager configuration.

Do not describe Cartridge as a complete Docker replacement or as safe for arbitrary hostile third-party code until native authority sandboxes, kernel resource controls, and independent assurance are complete.
