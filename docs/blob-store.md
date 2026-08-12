# Content-addressed blobs

The blob store keeps immutable files under their lowercase SHA-256 address. It is intended for large state that should not be duplicated inside key/value snapshots.

```sh
cartridge blob put video.bin --store ./blobs
cartridge blob verify <sha256> --store ./blobs
cartridge blob get <sha256> --store ./blobs --output restored.bin
cartridge blob list --store ./blobs
cartridge blob audit --store ./blobs
cartridge blob roots create --snapshot backup.cartridge-state.json \
  --capsule run.cartridge-capsule.json --output backup.cartridge-blobs.json
cartridge blob roots inspect backup.cartridge-blobs.json
cartridge blob roots verify backup.cartridge-blobs.json --store ./blobs
cartridge blob gc --store ./blobs --keep <sha256>
cartridge blob gc --store ./blobs --snapshot backup.cartridge-state.json
cartridge blob gc --store ./blobs --capsule run.cartridge-capsule.json
cartridge blob gc --store ./blobs --manifest backup.cartridge-blobs.json
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

## Root manifests

`blob roots create` resolves up to 256 validated snapshots and capsules into a portable, path-free manifest. It records each source by kind and semantic payload digest, sorts and deduplicates sources and objects, and binds the complete payload with SHA-256. The command refuses to overwrite an existing output. `roots inspect` validates and summarizes the document; `roots verify` checks every declared object and byte length under the store lock. Garbage collection accepts multiple manifests alongside direct artifact and explicit digest roots.

Root manifests avoid repeatedly opening large capsule backup sets, but they are integrity records rather than signatures. A valid manifest proves its object set has not changed since creation; it does not establish who selected those roots. See the [format document](blob-reachability-format.md).

## Inventory and audit

`blob list` walks the complete store under its lock, validates layout and every object digest, and emits objects in deterministic address order. It fails instead of returning a partial inventory if any object is corrupt. `blob audit` uses the same bounded walk but reports every content-corrupt object it can safely identify, then exits unsuccessfully when issues exist. Unsafe shard names, symlinks, unexpected entries, and stores over 100,000 objects fail immediately because continuing would make path or resource assumptions unsafe.

Blob hashes provide integrity and deduplication, not authenticity or confidentiality. Low-entropy content is guessable from its address. Package signing and encrypted stores are separate concerns.

The current lock prevents cooperating Cartridge processes from racing puts, reads, and garbage collection. It is not a defense against another process with permission to rewrite the store directly; the runtime should place stores in an OS-private application-data directory.
