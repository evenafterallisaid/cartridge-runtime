# Backup and recovery

Backups should separate replaceable software from irreplaceable identity and state.

## Back up

1. Export each cartridge namespace with `storage export`, providing its trusted package signature and trust store.
2. Create a blob reachability manifest from snapshots and capsules, then copy every referenced content-addressed object.
3. Keep package signatures, the trust store, registry index, and transparency log with the packages they describe.
4. Back up developer/release recovery keys offline. Do not place the active signing key in the same archive.
5. Retain migration receipts and rollback snapshots until the upgraded state has been verified.

Validate a backup before relying on it:

```sh
cartridge storage inspect app.cartridge-state.json
cartridge blob roots verify backup.cartridge-blobs.json --store blobs
cartridge registry audit --root registry --trust trust.json
cartridge capsule verify crash.cartridge-capsule.json
```

## Restore

Install and verify the signed package first. Run `storage restore --dry-run`, confirm identity/schema/quota changes, then commit the restore. Imported revisions cannot make an old compare-exchange token current again. Restore writes one new durable generation and retains the prior generation as its rollback point.

If the newest durable generation is corrupt, `storage recover` quarantines it and activates the newest valid retained generation. If every retained generation is corrupt, recovery fails rather than manufacturing empty state.

Runtime rollback is independent:

```sh
cartridge release rollback --root runtime-install
```

It selects the previously verified runtime artifact without changing packages, grants, snapshots, or live cartridge state.

## Disaster cases

- Lost active package key: sign a revocation with its registered offline recovery key, generate a new key, and publish a new version.
- Compromised registry: rebuild from signed content-addressed objects and compare the transparency chain with an independent copy.
- Interrupted migration: inspect the migration receipt with `storage migration-recover`; keep its rollback snapshot regardless of console output.
- Reproducible crash: retain the package, source snapshot, trace, result snapshot, and capsule. Capsule replay uses a disposable branch and does not mutate durable state.
- Lost trust store and all recovery keys: authenticity cannot be reconstructed from unkeyed hashes. Restore from an independently protected trust backup or re-establish trust manually.
