# Rolling updates

`Cartridge.stack.toml` can bind a rolling policy to each instance:

```toml
[instances.update]
order = "start-first"
max_surge = 1
max_unavailable = 0
min_ready_ms = 2000
progress_deadline_ms = 300000
drain_timeout_ms = 30000
```

`start-first` prefers a candidate replica while surge capacity remains. `stop-first` prefers draining a previous replica while the unavailable budget permits it. At least one of `max_surge` or `max_unavailable` must be nonzero. Each value is bounded against the declared replica count, and aggregate surge across one stack is capped at 64 replicas above its normal 256-replica ceiling.

Plan format 4 includes every non-default policy in the plan digest. Existing format-2 plans remain readable only without health or rolling policy, and format-3 plans remain readable only without rolling policy. New plans always use format 4.

## Scheduler invariants

The engine scheduler consumes generation-separated sets of previous and candidate replica ordinals. It rejects out-of-range ordinals, readiness that is not backed by an active process, minimum-ready state that is not backed by readiness, terminal candidates that are still active, and active counts above `replicas + max_surge`.

Given a valid observation, it returns one deterministic action:

- start the lowest missing candidate ordinals within surge capacity;
- drain previous ordinals without taking ready capacity below `replicas - max_unavailable`;
- wait for readiness, minimum-ready time, or availability capacity;
- complete only after every previous replica is gone and every candidate is available;
- roll back after a terminal candidate or the progress deadline.

The policy, decision engine, and daemon executor are implemented. Activated transactions create a bounded, checksummed execution checkpoint that records topology changes, enabled candidate ordinals, drain deadlines, monotonic action sequences, and progress timestamps. Interrupted checkpoint replacement recovers from a validated previous copy.

Old and candidate generations have independently validated targets, supervisor leases, observed runtime files, health-channel roots, and mutable-state directories. That prevents concurrent generations from sharing authority or state even when they use the same package digest. Authority for both targets exists only while the exact rollout checkpoint remains activated.

The daemon translates each durable scheduler action into generation-scoped candidate starts and previous-generation drains. Candidate workers must satisfy process and configured application readiness before an old ordinal can drain. Drains share one absolute timeout across the batch, terminate the complete worker process tree, and become durable acknowledgements before the scheduler advances. The coordinator resumes from the same checkpoint after daemon restart, rolls back terminal candidates, and never authorizes more than the stack-wide replica-plus-surge ceiling, including disjoint scale-and-rename updates.

There is no inbound service router yet, so this is availability-safe process replacement rather than a claim of zero-downtime HTTP traffic. Stateful generation handoff also waits for the migration/rollback-receipt gate; generation-keyed state deliberately prevents implicit sharing during a rollout.
