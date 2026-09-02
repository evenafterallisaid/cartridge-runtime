# Engine routing membership

The engine publishes the local set of replicas that are safe to receive traffic. It can now invoke those targets through a bounded local broker, but it is not a network ingress proxy: it does not open an HTTP listener, terminate TLS, or grant guest network authority.

Use the daemon API through:

```text
cartridge engine routes <stack> --root <engine-root>
cartridge engine routes <stack> --root <engine-root> --json
cartridge engine invoke <stack> <instance> --root <engine-root> --path /health
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

Consumers must query the authenticated daemon rather than reading `routes.json` directly. They should treat an error, missing snapshot, epoch change, or empty target list as no routable endpoints. The local invocation broker additionally derives whether its exact pinned target remains ready before delivery and while waiting for a response, so unrelated membership changes do not widen authority or abort valid work. Future HTTP ingress must preserve that fail-closed behavior and fence every in-flight request against generation and run id.

See [local service invocation](service-invocation.md) for the guest contract, queue limits, timeout semantics, and remaining ingress layers.
