# Content-addressed blobs

The blob store keeps immutable files under their lowercase SHA-256 address. It is intended for large state that should not be duplicated inside key/value snapshots.

```sh
cartridge blob put video.bin --store ./blobs
cartridge blob verify <sha256> --store ./blobs
cartridge blob get <sha256> --store ./blobs --output restored.bin
cartridge blob gc --store ./blobs --keep <sha256>
cartridge blob gc --store ./blobs --keep <sha256> --apply
```

Put, verification, and materialization stream through fixed-size buffers and enforce a 256 MiB per-object ceiling. Objects use create-new private files and a two-character digest shard. Repeated puts verify and reuse the existing object. Materialization copies into a new file instead of hard-linking the stored object, so changing an exported file cannot corrupt the store. Store operations share a finite-wait exclusive lock, and startup removes abandoned ingest files left by an interrupted writer.

Garbage collection is a dry run unless `--apply` is present. It validates every retained address, refuses symlinks or unexpected entries, hashes each removal candidate before counting or deleting it, and reports object and byte totals. The caller supplies the retained set; automatic reachability from snapshots and capsules is the next blob milestone.

Blob hashes provide integrity and deduplication, not authenticity or confidentiality. Low-entropy content is guessable from its address. Package signing and encrypted stores are separate concerns.

The current lock prevents cooperating Cartridge processes from racing puts, reads, and garbage collection. It is not a defense against another process with permission to rewrite the store directly; the runtime should place stores in an OS-private application-data directory.
