# Durable storage format v2

The directory backend stores one isolated journal directory per cartridge namespace:

```text
<state root>/
  <sha256 of cartridge id>/
    namespace.lock
    state-00000000000000000007.json
    state-00000000000000000008.json
    corrupt-state-...json
```

The cartridge id is never used as a path. It is validated by the package reader, then hashed to select the namespace directory. The state payload still contains the original id so moving a generation into another namespace is detected.

## Generation envelope

Each committed file contains an envelope:

```json
{
  "payload": {
    "format_version": 2,
    "namespace": "dev.example.app",
    "generation": 8,
    "state_schema": 3,
    "entries": {
      "settings/theme": "6461726b"
    }
  },
  "payload_sha256": "..."
}
```

Values use lowercase hexadecimal encoding. Keys are sorted because the payload uses an ordered map. `payload_sha256` is calculated over the compact JSON serialization of `payload`, making accidental modification detectable before values are returned to a cartridge. Version 1 generations remain readable and are treated as schema `0`; every new commit uses version 2.

## Commit protocol

Writers hold `namespace.lock` across the complete read-modify-write transaction:

1. Remove incomplete `pending-*.tmp` files.
2. Validate both retained committed generations.
3. Apply the operation in memory and check its post-write quota.
4. Write the next generation to a newly created temporary file.
5. Flush the temporary file and close it.
6. Rename it to a generation name that has never existed.
7. Flush directory metadata where the operating system exposes that operation.
8. Retain the newest two generations.

The active state is the highest valid generation, so no mutable head pointer can disagree with the journal. A crash before the rename leaves only a disposable temporary file. A crash after the rename leaves either the previous generation or the new one as the highest visible commit.

## Corruption and recovery

Normal access rejects malformed JSON, changed payload digests, mismatched namespace or generation identity, invalid keys, invalid value encoding, and oversized state files. It does not silently fall back because that could hide acknowledged data loss.

`cartridge storage recover` validates every retained generation. If at least one is valid, corrupt generations are renamed with a `corrupt-` prefix and the newest valid generation becomes active. Recovery refuses to manufacture empty state when every committed generation is corrupt.

This format is internal and may change before 1.0. Portable export and restore use the separate [storage snapshot format](snapshot-format.md), which has its own version and compatibility rules.
