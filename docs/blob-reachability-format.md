# Blob reachability manifest format v1

A reachability manifest is a reusable, portable root set for content-addressed blob collection. Its suggested suffix is `.cartridge-blobs.json`.

```json
{
  "payload": {
    "format_version": 1,
    "sources": [
      {
        "kind": "snapshot",
        "sha256": "..."
      },
      {
        "kind": "capsule",
        "sha256": "..."
      }
    ],
    "objects": {
      "<blob sha256>": 1048576
    }
  },
  "payload_sha256": "..."
}
```

Sources and objects are sorted and deduplicated by their canonical JSON representation. Snapshot source hashes are validated snapshot payload digests. Capsule source hashes are validated capsule payload digests after all bound artifacts and cross-file semantics pass verification. Paths are deliberately excluded so moving a backup set does not change its identity.

`objects` maps lowercase SHA-256 addresses to exact byte lengths. Readers reject unknown fields, unsupported versions, empty or excessive source sets, invalid digests, objects above the global blob-size limit, more than 100,000 objects, documents above 16 MiB, and payload digest mismatches. Writers refuse to overwrite an existing file.

The manifest is safe to use as a garbage-collection root only after it validates. Collection additionally verifies that every named object exists, hashes to its address, and has the declared length while holding the store lock. Validation failure occurs before any unreachable object is removed.

The payload digest detects accidental or malicious modification after creation but is not a signature. Authentication and authorization remain future signing and trust-store work.
