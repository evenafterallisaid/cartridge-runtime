# Local service invocation

The engine can deliver a bounded request to a ready cartridge replica without granting the cartridge a socket. This is the first inbound service slice and the transport underneath future HTTP ingress and typed cartridge-to-cartridge calls.

The example service opts in twice: its package requests `permissions.serve = true`, and its stack instance includes `serve` in `allow`. The guest then receives and answers host-owned requests with `serve-next` and `serve-respond`.

```sh
cartridge engine invoke service-stack api --root dist/engine \
  --method post --path /v1/check --header content-type=text/plain --body ping
```

`engine invoke` uses the existing encrypted, authenticated daemon protocol. It selects only a currently ready target for the named instance and pins the request to that replica's stack revision, generation, ordinal, run id, and readiness identity. A restart, drain, stop, removal, or rollout decision that removes the target cancels the request instead of moving it to another process.

## Limits and backpressure

- request and response bodies are each limited to 256 KiB
- paths are origin-form, at most 8 KiB, and reject authority forms, fragments, controls, traversal, encoded dots, encoded slashes, and backslashes
- headers use the shared HTTP validator: 128 entries and 64 KiB total, with host-controlled and hop-by-hop fields rejected
- guest receive timeouts are 10 ms to 30 seconds and are clamped to the worker's wall-clock deadline
- one guest request may be active at a time, each replica has at most 16 queued or claimed requests, and the daemon has a bounded authenticated client pool
- request and response envelopes are regular-file-only, capped at 2 MiB, atomically published, and removed after completion, timeout, route loss, or worker exit

The file handoff is an internal cross-process transport, not a public API or durable queue. Delivery is at most once from the guest's point of view after claim. A caller must retry explicitly after timeout and should use its own idempotency key when the operation is not naturally idempotent.

## Security boundary

The worker still has no ambient TCP, UDP, DNS, directory, environment, terminal, or process API. `serve` grants only the ability to receive the validated request records selected by the engine. The daemon rechecks authoritative ready membership while waiting, and the worker checks it again before exposing a request to guest code.

The engine-root files are private to the current user, but they do not protect against another process already running as that user. Such a process can inspect or deny the mailbox just as it can interfere with other mutable engine state. Native restricted-token/AppContainer and Unix authority sandboxes remain the release boundary that narrows this same-user risk.

This slice does not open an HTTP listener, terminate TLS, accept remote traffic, provide rate-limit policy, stream bodies, or connect one cartridge's declared WIT service edge to another. Those layers must reuse this ready-only, deadline-bound handoff rather than granting raw sockets.
