# Security policy

This repository is pre-alpha and does not yet claim to safely execute hostile cartridges. Please do not publish security reports containing working exploits in a public issue.

Report suspected vulnerabilities privately through GitHub's security advisory feature. Include the affected revision, operating system, reproduction steps, and the smallest cartridge or archive that demonstrates the issue.

The intended boundary is documented in `docs/architecture.md`. Missing permission prompts, archive validation bypasses, resource-limit bypasses, and host crashes caused by a cartridge are all considered security issues.

## Current hardening

The runtime enforces decompressed archive budgets, bounded Wasm memories, tables, and host resources, finite fuel and wall-clock budgets, bounded WASI waits, finite storage-lock waits, bounded traces and diagnostic inputs, and control-safe terminal output. Public CLI execution compiles and runs cartridges in a supervised helper process with a cleared, minimal environment and a hard parent-side deadline. Migration and capsule-replay steps run on disposable snapshot branches, and stateful replay must reproduce the committed result digest. Package assets are bound by individual digests and a package-wide integrity root; callers can verify one asset without inflating the others. The blob store streams bounded objects, verifies them before use, serializes mutation and collection, and cleans abandoned ingest files. Durable state, snapshots, traces, and blob objects use private Unix permissions when created. Security regression fixtures and parser fuzz targets cover the main untrusted formats.

These controls reduce denial-of-service and local data-exposure risks, but this remains a pre-alpha boundary. In particular:

- cartridge ids are not authenticated until package signing and a trust store exist
- helper processes do not yet enter platform-native OS sandboxes or receive kernel-enforced memory and CPU quotas
- applications embedding the `cartridge-runtime` library execute in process and must provide their own process boundary for hostile inputs
- traces intentionally contain replay data, including storage reads, and must be treated as secrets
- redacted trace hashes can still reveal low-entropy values through guessing
- Unix file locking is advisory against unrelated processes with direct filesystem access

Do not run hostile third-party cartridges as a privileged operating-system user.
