# Storage snapshot format v1

A storage snapshot is a portable representation of one cartridge namespace. Its suggested suffix is `.cartridge-state.json`.

```json
{
  "payload": {
    "format_version": 1,
    "cartridge_id": "dev.example.app",
    "entries": {
      "settings/theme": "6461726b"
    }
  },
  "payload_sha256": "..."
}
```

Entries use sorted keys and lowercase hexadecimal values. `payload_sha256` covers the compact JSON serialization of the payload. Readers reject unknown fields, unsupported versions, invalid cartridge ids, unsafe keys, malformed value data, and digest mismatches.

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

Inspection reports identity, entry count, byte count, format, and payload digest. Diffing reports the first changed key with value lengths and SHA-256 digests; it does not print the stored values.

## Restore

Restore requires a package so the runtime can derive the expected cartridge id and current storage limits:

```sh
cartridge storage restore app.cartridge backup.cartridge-state.json \
  --state-dir ./state --dry-run
```

The runtime rejects cross-cartridge restores, oversized values, excessive key counts, and quota overflow before acquiring a commit. A dry run compares current and proposed state without mutation. A committed restore takes the namespace lock and writes the complete snapshot as one new durable generation, leaving the previous generation as its rollback point.

Export refuses to overwrite an existing output file. Snapshots may contain private application data and are not encrypted in v1; they should be protected like any other backup.
