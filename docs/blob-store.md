# Content-addressed blobs

The blob store keeps immutable files under their lowercase SHA-256 address. It is intended for large state that should not be duplicated inside key/value snapshots.

```sh
cartridge blob put video.bin --store ./blobs
cartridge blob verify <sha256> --store ./blobs
cartridge blob get <sha256> --store ./blobs --output restored.bin
cartridge blob gc --store ./blobs --keep <sha256>
cartridge blob gc --store ./blobs --snapshot backup.cartridge-state.json
cartridge blob gc --store ./blobs --capsule run.cartridge-capsule.json
cartridge blob gc --store ./blobs --keep <sha256> --apply
```

Put, verification, and materialization stream through fixed-size buffers and enforce a 256 MiB per-object ceiling. Objects use create-new private files and a two-character digest shard. Repeated puts verify and reuse the existing object. Materialization copies into a new file instead of hard-linking the stored object, so changing an exported file cannot corrupt the store. Store operations share a finite-wait exclusive lock, and startup removes abandoned ingest files left by an interrupted writer.

Garbage collection is a dry run unless `--apply` is present. It validates every retained address, refuses symlinks or unexpected entries, hashes the complete removal set before deleting its first object, and reports object and byte totals. Explicit `--keep` roots can be combined with up to 256 `--snapshot` and `--capsule` roots and 100,000 total retained references. Snapshots are checksum-validated; capsules and all of their bound artifacts are verified before both source and result snapshots contribute references. Collection verifies every artifact-derived object and its declared size under the store lock before removing the first unreachable object, so a missing, corrupt, or inconsistent retained blob fails closed.

## Reference value

A blob reference is a canonical storage value rather than a filename or host path. Its binary representation is:

```text
"cartridge-blob-v1\0" | 64-byte lowercase sha256 | 8-byte big-endian length
```

`BlobReference::new`, `encode`, and `decode` are public from `cartridge-storage` and re-exported by `cartridge-runtime`. Snapshot reachability ignores ordinary values. A value beginning with the reference prefix must have the exact length, lowercase digest, and a declared size no larger than the global blob limit or reachability extraction fails. Two references to the same digest must agree on size.

References count toward normal key/value quotas. The referenced object does not: its separate store quota and lifecycle remain future guest-ABI work. Deleting a reference makes the object eligible for a later collection but never deletes it synchronously. Traces record the reference bytes like any other small storage value; they do not embed blob contents.

Blob hashes provide integrity and deduplication, not authenticity or confidentiality. Low-entropy content is guessable from its address. Package signing and encrypted stores are separate concerns.

The current lock prevents cooperating Cartridge processes from racing puts, reads, and garbage collection. It is not a defense against another process with permission to rewrite the store directly; the runtime should place stores in an OS-private application-data directory.
