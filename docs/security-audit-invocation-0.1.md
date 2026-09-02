# Security audit: local invocation 0.1

Date: 2026-09-03

Scope: the `serve` permission, guest host ABI, authenticated daemon request, ready-replica selection, cross-process mailbox, response correlation, limits, route loss, timeout behavior, and worker-exit cleanup. This is an internal implementation review, not the independent assessment required for a stable release.

## Result

The reviewed path remains deny-by-default and does not grant guest networking. Requests are accepted only through the authenticated local daemon, validated before publication and again before guest delivery, pinned to an exact ready run, bounded in count/bytes/time, and correlated to a single active response. No known exploitable issue remains in this implemented boundary after the fixes below.

## Findings fixed

| Finding | Severity | Fix |
| --- | --- | --- |
| INV-01 unrelated readiness changes could make a fresh routing snapshot fail validation between selection and mailbox creation | medium availability | invocation checks now derive whether the exact pinned target is still ready; unrelated membership changes neither widen authority nor cancel valid work |
| INV-02 crashed or restarted workers could leave request mailboxes and temporary envelopes behind indefinitely | medium availability/storage | supervisors retain each run directory and remove only bounded, recognized regular files after worker exit or termination |
| INV-03 the public request validator accepted uppercase hexadecimal ids while the worker scanner accepted lowercase ids only | low availability | request identities now use one canonical lowercase format at every boundary |
| INV-04 relative engine roots produced a valid daemon but unusable service-worker channels | low availability | supervisors resolve the engine root before constructing and passing the private invocation path |
| INV-05 daemon/worker cleanup could race after response publication and turn a successful guest response into a worker error | low availability | claimed-file cleanup is idempotent and treats a concurrent not-found result as success |
| INV-06 malformed or replaced response files could return early from daemon validation before normal mailbox cleanup | low availability/storage | response processing is isolated from a cleanup path that runs for success, timeout, route loss, and every validation error |
| INV-07 a guest could submit an excessive WIT header list before the shared response validator ran, and a replaced request filename could disagree with its envelope id | medium availability | the host rejects body/header counts before translation, and workers require the claimed filename and validated envelope identity to match |

## Adversarial checks

- permission denial with a configured broker
- duplicate receive before responding
- response id mismatch
- invalid status and oversized response body
- authority-form, fragment, plain traversal, encoded traversal, and host-header rejection
- exact generation/run readiness revalidation on both sides of the process boundary
- atomic create-new publication and bounded regular-file reads
- monotonic daemon timeout plus guest receive clamping
- end-to-end two-replica update, readiness, authenticated invocation, response, shutdown, and mailbox cleanup
- legacy 0.4 component compatibility remains in the cross-platform CI corpus

## Residual risk and non-goals

- Another process with the same user authority can inspect or deny mutable mailbox files. The mailbox is not presented as a same-user confidentiality boundary.
- Delivery is not a durable exactly-once queue. A timeout can leave the caller uncertain whether guest code began work, so application-level idempotency remains necessary.
- Bodies are copied through JSON envelopes in this first slice. Streaming and shared-memory transports need separate lifetime, quota, cancellation, and parser review.
- There is no HTTP listener, TLS, remote identity, public endpoint policy, typed inter-cartridge edge authorization, or async Component Model service transport yet.
- Native worker authority sandboxes, kernel resource controls, peer credentials, independent review, and signed/notarized installers remain external release gates.
