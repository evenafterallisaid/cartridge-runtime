# Engine routing membership

The engine publishes the local set of replicas that are safe to receive traffic. This is a membership plane, not an ingress proxy: it does not open a listener, terminate TLS, choose a load-balancing algorithm, or grant network authority.

Use the daemon API through:

```text
cartridge engine routes <stack> --root <engine-root>
cartridge engine routes <stack> --root <engine-root> --json
```

## Publication rules

A target is published only when all of these are true:

- its exact desired or rollout generation is still authorized
- the replica is desired, running, and has a current run id
- a configured readiness probe has reached `ready`, or an unprobed worker has reached `running`
- rollout progress has enabled the candidate ordinal
- the old ordinal has not entered drain intent

The coordinator writes route removal before it saves drain intent. Supervisors therefore cannot observe an instruction to drain while the authoritative routing table still contains that replica. Stop and remove mutations also publish an empty membership set before returning.

## Identity and recovery

Each snapshot carries a random routing epoch, a monotonic sequence within that epoch, publication time, rollout id, exact generation and run identities, and a checksum over the complete document. Normal membership changes increment the sequence. Recovery from an invalid regular file starts a new epoch at sequence one, so a consumer cannot mistake rebuilt state for an older sequence in the previous epoch.

The daemon validates the on-disk document and then independently derives the expected target set from current desired state, rollout progress, and generation-scoped runtime status. A valid but stale document is rejected. Changed, oversized, unsorted, duplicate, cross-stack, or non-regular files are rejected. Regular-file corruption can be rebuilt because routing is derived state; symlinks and other special files are never followed or replaced.

Consumers must query the authenticated daemon rather than reading `routes.json` directly. They should treat an error, missing snapshot, epoch change, or empty target list as no routable endpoints. A future ingress implementation must preserve that fail-closed behavior and fence any cached connection against both generation and run id.
