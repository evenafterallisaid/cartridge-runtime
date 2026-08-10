# State migrations

Cartridge state has a schema version independent from the package and snapshot format versions. A package declares the schema its component expects and the upgrade edges it supports:

```toml
[state]
schema = 3

[[state.migrations]]
name = "add-profile"
from = 0
to = 1

[[state.migrations]]
name = "split-settings"
from = 1
to = 3
```

Schema `0` is the compatibility value for packages and state created before schema tracking existed. Positive schemas require the storage capability. Migration names use the same short lowercase identifier rules as service aliases.

Every edge must increase the schema, stay within the package's current schema, and have a unique name and source version. Every declared edge must eventually reach the current schema. Skipped versions are allowed when they are explicit, such as `1 -> 3`; downgrades are not inferred.

## Planning

The CLI can build the exact ordered path without executing the component or opening durable state:

```sh
cartridge storage migration-plan app.cartridge --from-schema 0
cartridge storage migration-plan app.cartridge --from-schema 0 --json
```

A plan records its own format version, cartridge identity and version, component digest, source and target schemas, and ordered migration declarations. Planning fails when the source is newer than the package, a path is missing, or the manifest graph is ambiguous.

An empty plan means the source is already current. It does not mean arbitrary old state is compatible.

## Execution

Live runs prepare storage for the manifest schema before component execution. Memory, directory, and snapshot-backed state reject a different schema. Durable generation format v1 and snapshot format v1 are still readable and are interpreted as schema `0`.

A migratable component targets the `migratable-cartridge` WIT world and exports:

```wit
migrate: func(name: string, source: u32, target: u32) -> result<_, string>;
```

The runtime supplies all three values from the validated manifest plan. The guest cannot choose or skip a schema edge.

Execute a rehearsal from a portable snapshot:

```sh
cartridge storage migrate app.cartridge old.cartridge-state.json \
  --output migrated.cartridge-state.json
```

Every step starts with a fresh in-memory branch made from the preceding validated snapshot and a fresh Wasmtime store. A successful step may export only the exact destination schema declared by the plan. The intermediate snapshot is checked for identity, integrity, key count, total bytes, and per-value limits before it becomes input to the next step. A trap, guest error, quota failure, missing export, or deadline leaves the source snapshot unchanged and creates no output file.

Migration execution uses the package's normal capability policy and storage quota. Each step receives its own fuel and wall-time budget. A plan is limited to 64 executed steps and ten minutes of declared aggregate wall time, and the CLI runs the entire rehearsal in a killable helper process with a separate parent deadline.

This command deliberately does not touch durable state. To migrate a live namespace and commit the result explicitly:

```sh
cartridge storage migrate-commit app.cartridge --state-dir ./state \
  --rollback-output before-migration.cartridge-state.json
```

The worker captures the rollback snapshot before it invokes guest code. It migrates private branches exactly like a rehearsal, then takes the namespace lock and commits only if durable schema and entries still match the captured source. A concurrent write makes the command fail without overwriting either version. A successful transformation is written as exactly one new durable generation. The rollback output uses create-new semantics and is never silently replaced.

If recovery is needed, use the package version whose manifest expects the rollback snapshot's schema:

```sh
cartridge storage restore old-app.cartridge before-migration.cartridge-state.json \
  --state-dir ./state --dry-run
cartridge storage restore old-app.cartridge before-migration.cartridge-state.json \
  --state-dir ./state
```

The rollback file remains useful even when migration traps or times out because durable state is untouched in those cases. A crash after the atomic commit but before the worker reports success is intentionally treated as an indeterminate result: inspect durable schema and the rollback file before retrying. A future commit receipt will make that recovery decision mechanical.
