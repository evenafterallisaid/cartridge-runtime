# Compatibility policy

The 1.0 candidate freezes the package container at format `1` and the guest API at `cartridge:api@0.4.0`. Versions before that freeze are development formats and do not create a permanent support obligation.

From the first stable release:

- package, signature, registry, trace, snapshot, capsule, reachability, migration-receipt, and runtime-release readers support every documented format version for the full `1.x` runtime line
- a new format version is additive or ships with an explicit migration/export path
- unknown format versions fail before execution or mutation
- a stable WIT package version is never changed in place; incompatible changes use a new package version and can coexist in the host during a documented transition window
- security fixes may reject inputs previously accepted only when those inputs violate a documented invariant or are unsafe to process
- removal of a stable interface requires at least two minor releases of deprecation and a migration note

## Negotiation

A manifest can declare a host API range and capability versions:

```toml
[compatibility]
host_api = "^0.4"

[compatibility.capabilities]
storage = "^1"
graphics = ">=1, <2"
```

Negotiation happens after bounded package validation and before component compilation or guest execution. A version requirement for a capability whose permission is disabled is invalid. Unknown or incompatible requirements fail closed. `cartridge platform app.cartridge` prints the exact negotiated profile.

## Corpus

The cross-platform CI corpus runs the same packages, snapshots, traces, capsules, migration fixtures, signing operations, registry operations, and updater rollback sequence on Windows, macOS, and Linux. Compatibility fixtures are retained when a stable format changes. A release cannot delete an old fixture merely to make the current reader pass.

The policy does not promise byte-identical wall-clock timing or native GPU pixels. Deterministic traces, canonical CPU media receipts, state digests, and declared result values are the portable comparison boundary.
