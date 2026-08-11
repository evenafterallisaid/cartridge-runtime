# Storage snapshot format v3

A storage snapshot is a portable representation of one cartridge namespace. Its suggested suffix is `.cartridge-state.json`.

```json
{
  "payload": {
    "format_version": 3,
    "cartridge_id": "dev.example.app",
    "state_schema": 3,
    "state_revision": 42,
    "entries": {
      "settings/theme": "6461726b"
    }
  },
  "payload_sha256": "..."
}
```

Entries use sorted keys and lowercase hexadecimal values. `state_revision` preserves the namespace's ABA-safe transaction clock across branches and machines. `payload_sha256` covers the compact JSON serialization of the payload. Readers reject unknown fields, unsupported versions, invalid cartridge ids, unsafe keys, malformed value data, and digest mismatches. Versions 1 and 2 remain readable with revision `0`; new exports use version 3.

## Portability boundary

Snapshots deliberately omit:

- host paths and namespace directory hashes
- lock files and journal generations
- creation timestamps and platform metadata
- runtime implementation details
- permission grants and secrets outside cartridge state

The same logical state therefore produces the same payload and digest on Windows, macOS, and Linux. The envelope is independent of the durable journal format and can evolve under its own version.

## Inspection and comparison

```sh
cartridge storage inspect backup.cartridge-state.json
cartridge storage diff before.cartridge-state.json after.cartridge-state.json
```

Inspection reports identity, state schema, state revision, entry count, byte count, format, and payload digest. Diffing reports identity, schema, and revision changes before the first changed key, and reports only value lengths and SHA-256 digests rather than stored values.

## Restore

Restore requires a package so the runtime can derive the expected cartridge id and current storage limits:

```sh
cartridge storage restore app.cartridge backup.cartridge-state.json \
  --state-dir ./state --dry-run
```

The runtime rejects cross-cartridge restores, snapshots whose schema differs from the package, oversized values, excessive key counts, and quota overflow before acquiring a commit. A dry run compares current and proposed state without mutation. A committed restore takes the namespace lock and writes the complete snapshot as one new durable generation, leaving the previous generation as its rollback point. The new revision is one greater than both the live durable revision and the imported snapshot revision, so importing an older backup can never make a stale transaction token current again.

Migration commits use a stricter conditional restore. The runtime captures the durable generation token and complete source snapshot, migrates an isolated branch, then compares the locked live namespace with that source immediately before writing. A generation, schema, key, or value change aborts the commit, which prevents a long migration from erasing concurrent durable writes and detects ABA changes that return to the same bytes.

Export refuses to overwrite an existing output file. Snapshots may contain private application data and are not encrypted in v3; they should be protected like any other backup.

## Isolated branch execution

A cartridge can run against a private copy of a snapshot without reading or changing durable state:

```sh
cartridge run app.cartridge --from-snapshot before.cartridge-state.json \
  --snapshot-output after.cartridge-state.json -- scenario-a
```

The runtime validates cartridge identity, state schema, and current manifest quotas before execution. Writes, deletes, and quota usage apply only to the branch. If `--snapshot-output` is omitted, the branch is discarded; if supplied, the final state is written as a new snapshot without overwriting an existing file. The input can therefore be reused across a test matrix and compared with every result.
