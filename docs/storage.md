# Storage

Cartridge storage is a capability, not a filesystem mount. A guest works with bounded string keys and byte values. The runtime chooses the namespace from the validated cartridge id and passes that namespace to a backend the guest cannot access directly.

## Guest interface

The current WIT contract exposes four operations:

```text
storage-get(key) -> value or none
storage-put(key, value)
storage-delete(key) -> deleted
storage-list(prefix) -> sorted keys
```

Keys are ASCII, at most 256 bytes, and may contain alphanumeric characters, `-`, `_`, `.`, and `/`. Empty path segments, `.` and `..` segments, drive prefixes, backslashes, and leading or trailing slashes are rejected. These rules keep snapshots portable even though the in-memory backend does not turn keys into paths.

## Isolation and limits

The backend contract includes a namespace on every operation. A cartridge never supplies that namespace, so two cartridges using the same key still address different state.

Each manifest sets three limits:

- total bytes in the namespace
- number of keys
- bytes in one value

The backend calculates the complete post-write usage before changing the map. A failed replacement leaves the previous value intact. Listing uses lexical order so tests and traces do not depend on hash-map iteration.

## Recording and replay

Storage is observable state and therefore part of deterministic replay. Live reads record the returned bytes, length, and digest. Live writes record the key, value length, digest, and outcome. Deletes and listings record their result.

During replay, reads return the recorded bytes. Writes and deletes are checked against the trace but are not applied to the backend. This prevents debugging an old execution from modifying current application state. Malformed bytes, mismatched digests, changed keys, and changed write contents are reported as the first divergence.

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
cartridge run app.cartridge --from-snapshot backup.cartridge-state.json \
  --snapshot-output branch.cartridge-state.json -- experiment
cartridge storage restore app.cartridge backup.cartridge-state.json --state-dir ./state --dry-run
```

State commits are immutable generations. The backend flushes a new temporary snapshot, renames it to a previously unused generation, and retains the prior valid generation. Incomplete temporary files are ignored and removed by the next write. Every generation contains a digest over its canonical payload; corrupt committed generations block normal access until explicit recovery quarantines them.

The internal generation files are a recovery mechanism, not the portable snapshot format. Export produces a separately versioned envelope containing only cartridge identity and sorted key/value data. Snapshot comparison reports changed keys, lengths, and digests without printing values. Restore rejects another cartridge's snapshot and any state that exceeds the package limits, then replaces the namespace in one generation.

Dry-run restore performs the same validation and reports added, replaced, removed, and unchanged key counts without changing state. Snapshot branches complete the other half of the migration foundation: a future migration runner can transform isolated state, compare the result, validate quotas, and commit through the existing restore path.
