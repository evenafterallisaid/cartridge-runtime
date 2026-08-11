# Execution capsule manifest v1

An execution capsule manifest binds the exact inputs and observable artifacts of one snapshot-backed run without copying package bytes, trace events, arguments, outputs, or private state values into the manifest. Its suggested suffix is `.cartridge-capsule.json`.

```sh
cartridge capsule create app.cartridge \
  --source before.cartridge-state.json \
  --trace run.trace.json \
  --result after.cartridge-state.json \
  --output run.cartridge-capsule.json

cartridge capsule inspect run.cartridge-capsule.json
cartridge capsule verify run.cartridge-capsule.json
cartridge capsule diff run.cartridge-capsule.json other.cartridge-capsule.json
cartridge capsule replay run.cartridge-capsule.json
```

The manifest records:

- package id, version, component digest, and raw package-file digest
- runtime version plus argument count, byte count, and canonical argument-list digest
- source and result snapshot schemas, key counts, byte counts, payload digests, and raw file digests
- trace format, event count, output length and digest, fuel consumed, and raw trace-file digest
- portable relative paths and byte lengths for every referenced artifact
- a digest over the complete canonical manifest payload

Arguments, output text, storage keys, values, and trace events stay in their original artifacts. Inspecting a capsule therefore reveals sizes and equality-bearing hashes but not those contents.

## Directory model

Capsules use forward-slash relative paths. Creation requires every referenced file to live beneath the capsule manifest's directory. Verification rejects absolute paths, drive prefixes, backslashes, empty segments, `.` and `..`, non-files, symlink escapes, oversized artifacts, and paths longer than the format limit.

This confinement makes a capsule tree movable between Windows, macOS, and Linux and prevents an untrusted manifest from turning verification into an arbitrary file reader. Move the manifest and its referenced files together while preserving their relative layout.

## Verification

Verification performs two layers of checks:

1. raw file length and SHA-256 for the package, source snapshot, trace, and result snapshot
2. semantic decoding and cross-artifact identity checks for package id/version/component, state schema, runtime, invocation digest, trace summary, and snapshot summaries

Artifacts are digested again after semantic parsing, narrowing concurrent replacement races to changes made after verification returns. Creation runs the same complete verifier before reporting success. Inputs and manifest decoding are bounded before allocation, and capsule output uses create-new private-file semantics plus a flushed directory entry.

The v1 manifest proves artifact integrity and internal consistency. Replay additionally demonstrates that the current runtime can reproduce the bound result state from the source and trace. Like snapshots and receipts, unkeyed hashes do not provide author authenticity; package signing remains a separate security milestone.

## Difference and replay

`capsule diff` reports the first difference in a stable order: package identity, runtime and invocation, raw package, source state, trace, then result state. It compares semantic metadata and content digests rather than artifact filenames, so an unchanged capsule tree can be relocated without becoming different. Values, arguments, output text, and trace events are not printed.

`capsule replay` first verifies every bound artifact in the parent, launches a deadline-supervised helper, verifies the capsule again in that worker, and replays the recorded invocation through the current runtime. The worker executes an already-loaded package, source snapshot, and trace rather than reopening them after verification, then re-verifies the complete capsule before reporting success. Replay must consume the complete ordered trace and reproduce its output and fuel result. Recorded storage reads and listings must match the disposable source branch; successful writes and deletes are applied only to that branch. The exported branch must exactly reproduce the bound result snapshot digest.

Cross-platform replay detects runtime, component, invocation, event, source-state, output, fuel, or result-state divergence without opening live durable storage.
