# Storage

Cartridge storage is a capability, not a filesystem mount. A guest works with bounded string keys and byte values. The runtime chooses the namespace from the validated cartridge id and passes that namespace to a backend the guest cannot access directly.

## Guest interface

The storage portion of the WIT 0.3 contract exposes the original key/value operations plus revision-guarded transactions:

```text
storage-get(key) -> value or none
storage-put(key, value)
storage-delete(key) -> deleted
storage-list(prefix) -> sorted keys
storage-revision() -> revision
storage-compare-exchange(revision, key, expected, replacement) -> applied, revision
storage-apply(revision, mutations) -> applied, revision
```

WIT 0.2 introduced these transaction semantics. WIT 0.3 preserves them and adds media capabilities. Cartridges built against either older package version must be rebuilt; the versioned import makes an old binary fail at linking instead of silently receiving different semantics.

Keys are ASCII, at most 256 bytes, and may contain alphanumeric characters, `-`, `_`, `.`, and `/`. Empty path segments, `.` and `..` segments, drive prefixes, backslashes, and leading or trailing slashes are rejected. These rules keep snapshots portable even though the in-memory backend does not turn keys into paths.

## Isolation and limits

The backend contract includes a namespace on every operation. A cartridge never supplies that namespace, so two cartridges using the same key still address different state.

Each manifest sets three limits:

- total bytes in the namespace
- number of keys
- bytes in one value

The backend calculates the complete post-write usage before changing the map. A failed replacement leaves the previous value intact. Listing uses lexical order so tests and traces do not depend on hash-map iteration.

Revisions are namespace-wide monotonic counters. A compare-exchange succeeds only when both its revision and expected value match. A batch contains 1 to 128 unique put-or-delete mutations and is limited to 16 MiB of keys and values. The backend validates the complete final key and byte usage before changing anything, commits every mutation in one revision, and returns `applied = false` without mutation when the revision is stale. Returning to byte-identical state does not return to an older revision, so stale tokens cannot pass after an A→B→A sequence.

The manifest also declares the state schema expected by the component. Live execution prepares the namespace for that schema and refuses to run when existing state or a snapshot branch has a different version. This turns a package upgrade with old state into an explicit migration problem instead of undefined guest behavior.

## Recording and replay

Storage is observable state and therefore part of deterministic replay. Live reads record the returned bytes, length, and digest. Live writes record the key, value length, digest, and outcome. Deletes and listings record their result. Transaction traces bind the supplied revision and a bounded digest of valid request contents, then record the applied flag and resulting revision.

During ordinary replay, reads return the recorded bytes. Writes and deletes are checked against the trace but are not applied to the backend. This prevents debugging an old execution from modifying current application state. Capsule replay uses a stricter disposable mode: it starts from the bound source snapshot, checks recorded reads and listings against that branch, applies validated writes and deletes only to the branch, then requires the exported result digest to match the capsule. Malformed bytes, mismatched source state, changed keys, and changed write contents are reported as the first divergence.

Traces may contain private storage values and should be treated as sensitive files.

## Backends

`MemoryStorage` is shared by runs made through the same `Runtime` instance. It is deterministic, thread-safe, and useful for tests and embedders that provide their own lifecycle. CLI runs without `--state-dir` intentionally remain ephemeral.

`DirectoryStorage` persists the same contract beneath a caller-selected root. Namespace directory names are SHA-256 digests of cartridge ids. Each operation takes an exclusive operating-system file lock, so separate runtime processes cannot interleave read-modify-write commits.

`SnapshotStorage` creates a private in-memory branch from a portable snapshot. The input snapshot is immutable, and no durable namespace is opened. A branch can be discarded after execution or exported as a new snapshot, which makes it suitable for migration rehearsals, test matrices, and debugging with edited inputs.

```sh
cartridge run app.cartridge --state-dir ./state -- first-run
cartridge storage status app.cartridge --state-dir ./state
cartridge storage recover app.cartridge --state-dir ./state
cartridge storage export app.cartridge --state-dir ./state --output backup.cartridge-state.json
cartridge storage inspect backup.cartridge-state.json
cartridge storage migration-plan app.cartridge --from-schema 0
cartridge storage migrate app.cartridge old.cartridge-state.json \
  --output migrated.cartridge-state.json
cartridge storage migrate-commit app.cartridge --state-dir ./state \
  --rollback-output rollback.cartridge-state.json \
  --receipt-output migration-receipt.json
cartridge storage migration-recover app.cartridge migration-receipt.json \
  --state-dir ./state
cartridge run app.cartridge --from-snapshot backup.cartridge-state.json \
  --snapshot-output branch.cartridge-state.json -- experiment
cartridge storage restore app.cartridge backup.cartridge-state.json --state-dir ./state --dry-run
```

State commits are immutable generations, and the durable generation is also the namespace revision. The backend flushes a new temporary snapshot, renames it to a previously unused generation, and retains the prior valid generation. Incomplete temporary files are ignored and removed by the next write. Every generation contains a digest over its canonical payload; corrupt committed generations block normal access until explicit recovery quarantines them.

The internal generation files are a recovery mechanism, not the portable snapshot format. Export produces a separately versioned envelope containing cartridge identity, the state schema and revision, and sorted key/value data. Snapshot comparison reports revision changes plus changed keys, lengths, and digests without printing values. Restore rejects another cartridge's snapshot and any state that exceeds the package limits, then replaces the namespace in one generation while keeping its revision ahead of both histories.

Dry-run restore performs the same validation and reports added, replaced, removed, and unchanged key counts without changing state. Migration rehearsal executes every declared step against a fresh snapshot branch, validates the intermediate schema and quotas, and writes a new portable snapshot only after the complete plan succeeds. It never opens the durable backend.

`storage migrate-commit` exports the live generation to a new rollback file before guest migration code runs, executes every step in an isolated worker, writes a checksummed intent receipt, then conditionally replaces durable state in one generation. The final lock-protected commit compares the durable generation token, schema, and entries with the captured source. If another process commits while migration is running, the migration fails even if that process later restores byte-identical state; this closes the usual compare-and-swap ABA race. Traps, quota failures, worker deadlines, and stale-source failures all leave durable state unmodified; once created, recovery artifacts are retained for inspection.

The receipt binds the exact package component, source and target schemas, source generation, isolated migration revision, predicted commit generation, and both snapshot digests. `storage migration-recover` checks current state and the retained target generation under one namespace lock. It can prove a commit landed after the worker was interrupted, prove that another commit won the generation race, or decline to guess once journal pruning removed the needed evidence. See the [receipt format](migration-receipt-format.md).
