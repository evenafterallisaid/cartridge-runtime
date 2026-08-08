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

## Current backend

`MemoryStorage` is shared by runs made through the same `Runtime` instance. It is deterministic, thread-safe, and useful for tests and embedders that provide their own lifecycle. The CLI creates one runtime per process, so its state is intentionally ephemeral for now.

The durable backend will use runtime-owned directories, process locking, crash-safe replacement, explicit corruption detection, and recovery tests on Windows, macOS, and Linux. Snapshot and migration commands will be built on that backend rather than encoding persistence assumptions into the guest ABI.
