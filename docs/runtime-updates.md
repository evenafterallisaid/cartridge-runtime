# Signed runtime updates

Runtime releases are independent from cartridge versions and state. A release document binds its channel, semantic version, publication time, minimum updater version, signing key, and one exact digest/length/filename per platform target.

```sh
cartridge release create cartridge-runtime \
  --target x86_64-pc-windows-msvc --version 1.0.0 \
  --key release.key.json --output runtime-1.0.0.json
cartridge release verify runtime-1.0.0.json --trust runtime-trust.json
cartridge release install runtime-1.0.0.json cartridge-runtime \
  --target x86_64-pc-windows-msvc --trust runtime-trust.json \
  --root runtime-install
cartridge release status --root runtime-install
cartridge release rollback --root runtime-install
```

The updater reads and hashes an artifact once, compares those bytes with trusted signed metadata, and writes those exact bytes into a versioned directory. It never modifies cartridge state. Activation changes only a checksummed local selection document after the complete artifact is durable. The last active release remains installed as a rollback slot. Downgrades outside rollback require `--allow-downgrade`.

Update state uses a finite-wait process lock and interruption backup. Startup restores a valid backup when the active document is missing or corrupt and fails closed when neither copy is valid. Every status and rollback operation hashes the selected artifact again.

Release signing keys should be separate from developer package keys and backed by an offline recovery key. macOS notarization and Windows Authenticode are additional distribution gates: the portable Ed25519 signature protects Cartridge metadata and bytes but does not replace the operating system's publisher checks.
