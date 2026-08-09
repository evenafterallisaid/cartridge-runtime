# Cartridge format v1

A `.cartridge` file is a ZIP archive used as a container, not as an extraction bundle.

```text
cartridge.toml
component.wasm
assets/<relative paths>
```

`cartridge.toml` is the canonical, normalized manifest produced by the packer. Its integrity block contains the lowercase SHA-256 digest of `component.wasm` and a path-to-digest map covering every packaged asset. The runtime rejects archives containing unsafe names, duplicate entries, unexpected files, files larger than the configured package limits, missing integrity entries, or mismatched content.

## Source manifest

```toml
format_version = 1

[cartridge]
id = "dev.cartridge.hello"
name = "Hello Cartridge"
version = "0.1.0"
description = "Small end-to-end example"

[permissions]
clock = true
random = false
assets = true
storage = true

[runtime]
fuel = 10000000
memory_bytes = 67108864
timeout_ms = 30000
storage_bytes = 1048576
storage_keys = 1024
storage_value_bytes = 262144

[state]
schema = 1

[[state.migrations]]
name = "initialize-state"
from = 0
to = 1
```

The packer supplies the integrity block. Cartridge IDs use reverse-domain notation and versions follow Semantic Versioning. Runtime limits include an instruction budget, a linear-memory ceiling, a wall-time deadline between 1 millisecond and 5 minutes, and three independent storage ceilings. Storage values cannot be larger than the total storage quota.

The optional state section declares the schema expected by the current component and the monotonic upgrade paths it supports. Packages without the section use schema `0`. See [state migrations](migrations.md) for validation and planning rules.

## Relationships

Cartridges can request narrow, versioned services from other cartridges:

```toml
[[dependencies]]
alias = "image-codec"
cartridge = "dev.example.image-codec"
version = "^1.2"
interfaces = ["example:media/decode@1.0.0"]
optional = false
reason = "decodes imported textures"

[[services.provides]]
name = "thumbnailer"
interface = "example:media/thumbnail@1.0.0"
visibility = "dependency"
description = "creates image previews"
```

These declarations are requests and advertisements, not grants. Runtime policy controls whether a resolved connection may be activated.

## Compatibility

Readers must reject unknown `format_version` values. Additive manifest fields within a version should have safe defaults. ABI compatibility is handled separately by the version in the WIT package name.
