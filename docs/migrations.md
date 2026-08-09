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

## Runtime boundary

Live runs prepare storage for the manifest schema before component execution. Memory, directory, and snapshot-backed state reject a different schema. Durable generation format v1 and snapshot format v1 are still readable and are interpreted as schema `0`.

Migration execution is the next storage slice. It will run each planned step against an isolated snapshot branch, produce a new snapshot tagged with the destination schema, validate the result, and only then allow one transactional durable commit. The planner does not pretend those execution guarantees exist yet.
