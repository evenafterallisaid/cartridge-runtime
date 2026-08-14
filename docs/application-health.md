# Application health

Cartridge can gate a stack instance on signals emitted by the running WASM component. This is opt-in: instances without a health policy retain process-based readiness for compatibility.

## Stack policy

```toml
[instances.health]
startup_timeout_ms = 1000
readiness_timeout_ms = 3000
liveness_timeout_ms = 1000
failure_threshold = 2
```

- `startup_timeout_ms` is the maximum host time until any valid signal arrives.
- `readiness_timeout_ms` is the maximum host time until `ready` arrives. It must be at least the startup timeout.
- `liveness_timeout_ms` is the maximum silence after readiness before one liveness failure is recorded.
- `failure_threshold` is the number of consecutive explicit-unhealthy or missed-liveness observations before the worker is terminated. Restart behavior then follows the instance restart policy.

Timeouts range from 100 milliseconds to five minutes. Failure thresholds range from one to ten. The exact policy is included in the checksum-bound stack plan.

## Guest API

The `cartridge:api/host@0.4.0` interface exports `health-report(state, detail)`. Rust guests generated with `wit-bindgen` can call it like this:

```rust
use bindings::cartridge::api::host::{HealthState, health_report};

health_report(HealthState::Started, "");
// initialize dependencies and application state
health_report(HealthState::Ready, "");

// call this periodically while serving
health_report(HealthState::Heartbeat, "");

// the supervisor records a generic failure, not this private detail
health_report(HealthState::Unhealthy, "dependency unavailable");
```

`started` and `heartbeat` prove only that the reporting channel is active. Only `ready` transitions the replica from `starting` to `running`. A later `ready` clears prior probe failures. Completed jobs configured with a probe must report ready before returning successfully.

The call is a no-op outside a supervisor-provided channel, so the same component remains runnable from the CLI, replay tools, and older unprobed stack manifests. Health reports are intentionally excluded from deterministic execution traces because they are control-plane observations rather than guest-visible results.

## Security boundary

Every worker attempt receives a random 256-bit channel key and a path derived by the engine from its validated stack, replica, generation, and run identity. Reports use random XChaCha20-Poly1305 nonces, bind the run id as associated data, carry a strictly increasing sequence, and are limited to 4 KiB. A worker can submit at most 4,096 reports during one run. The supervisor schedules from receipt time, so forged guest timestamps cannot extend a deadline.

Guest detail is capped at 512 bytes, encrypted in the ephemeral report, and never copied into durable status, logs, or daemon health responses. The supervisor removes canonical stale reports under its exclusive lease before starting another generation. Unexpected files, symlinks, special files, or cleanup inventories over 4,096 entries fail closed before deletion.

This mechanism detects application mistakes and dependency failures. A malicious component can still lie about its own health. Independent command, HTTP, service-edge, metric, and operator gates remain future layers for stronger rollout decisions.
