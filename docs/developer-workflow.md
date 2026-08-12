# Developer workflow

The developer commands are intentionally project-local. They do not install packages or reuse desktop grants.

## Create and check a project

`cartridge new demo --language rust` creates a directory without overwriting an existing path. Rust, TinyGo, and JavaScript templates carry the same checked-in WIT contract and a `Cartridge.dev.toml` build description.

`cartridge check demo` validates both project files, manifest limits, normalized component paths, symlink-free source traversal, permissions, and package-size inputs. `cartridge profile demo` adds component, source, asset, fuel, memory, and timeout budgets. `cartridge schema` emits bounded JSON Schema metadata for editors.

Build commands are argument arrays rather than shell strings. They are developer-controlled code and run with the developer's normal environment; they are never read from an installed `.cartridge` archive.

## Build, watch, and reload

`cartridge dev demo` fingerprints source and assets in stable path order, builds after a change, packages to a private temporary archive, and launches through the normal supervised worker. Build output and `.git` data are excluded from the fingerprint.

`--once` performs one cycle for scripts and CI. `--preserve-state` keeps the cartridge's namespaced state only while identity and schema are compatible. A schema change without a complete declared migration is rejected before the new component runs. A valid schema transition must be committed through the storage migration commands first.

## Conformance and traces

`cartridge conformance app.cartridge` compiles the component, checks its imports against the current runtime before guest execution, runs it in a supervised worker, and then performs deterministic replay. The command fails on an API mismatch, trap, timeout, unexpected capability event, output difference, fuel difference, or media-receipt difference.

`cartridge trace export run.trace.json --output timeline.json` writes the bounded timeline interchange format used by desktop trace viewers. The export is full-fidelity and may contain sensitive capability outcomes; use `trace redact` before sharing data.
