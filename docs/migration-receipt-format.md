# Migration receipt format v1

A migration receipt is an immutable intent record written after every isolated migration step succeeds and before the durable compare-and-swap commit begins. Its suggested suffix is `.cartridge-migration.json`.

```json
{
  "payload": {
    "format_version": 1,
    "cartridge_id": "dev.example.app",
    "package_version": "2.0.0",
    "component_sha256": "...",
    "source_generation": 12,
    "target_generation": 13,
    "source_schema": 2,
    "target_schema": 3,
    "source_snapshot_sha256": "...",
    "target_snapshot_sha256": "..."
  },
  "payload_sha256": "..."
}
```

The target generation must be exactly one greater than the source, matching the storage backend's one-generation migration commit. Schemas must increase. All digests use 64 lowercase hexadecimal characters. `payload_sha256` covers the compact JSON serialization of `payload`; unknown fields, invalid identities, generation gaps, non-increasing schemas, oversized documents, and digest mismatches are rejected.

## Write ordering

The durable command observes this order:

1. capture the source generation and portable rollback snapshot under the namespace lock
2. flush the create-new rollback output
3. run the complete migration plan on isolated snapshot branches
4. validate the target snapshot and flush the create-new receipt
5. reacquire the namespace lock and commit only if generation, schema, and entries still match the source

A crash before step 4 cannot have committed. Once a valid receipt exists, recovery compares its evidence with durable generations. The namespace commit itself remains an atomic immutable-generation rename.

## Recovery states

- `not_committed`: the source is still current, or the receipt's target generation exists with a different digest
- `committed`: the receipt's target generation and digest are current
- `committed_then_changed`: the target generation still exists in retained history but a later generation is current
- `indeterminate`: later journal pruning or external recovery removed enough evidence that neither outcome can be proven

Recovery checks package id, version, component digest, and target schema before looking at state. Current and retained target generations are read under one namespace lock. Receipts contain hashes and metadata only; they do not expose stored values.

The payload checksum provides corruption and accidental-tampering detection, not authenticity. Anyone who can replace a receipt can recalculate an unkeyed digest. Developer signatures and signed recovery artifacts belong to the package-signing milestone before distribution is treated as a security boundary.
