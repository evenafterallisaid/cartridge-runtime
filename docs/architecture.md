# Architecture

## Design goals

Cartridge Runtime separates portable application logic from operating-system authority. The same component should run on each supported desktop platform while the host remains responsible for permissions, resource limits, packaging, and future native integrations.

The current execution path is:

```text
.cartridge archive
  -> parse and validate manifest
  -> verify component and asset digests
  -> configure permissions and limits
  -> instantiate component with Wasmtime
  -> route WIT imports through HostState
  -> record events or inject and compare replay events
```

## Trust boundaries

The component is untrusted. The host validates all paths, bounds random-data requests, limits WebAssembly fuel and memory, and never extracts archive entries onto disk. Packaged assets are held in memory and addressed by normalized relative paths.

WASI is linked for language-runtime compatibility, but it is not the cartridge permission model. The context has no terminal, environment, arguments, or preopened directories, and its network interfaces are disabled. When clock or randomness permission is absent, the corresponding WASI services use inert deterministic providers instead of host state. Cartridges should use `cartridge:api/host` when they need observable, traceable capability results.

The `.cartridge` archive is also untrusted. Duplicate entries, malformed manifests, unexpected component names, oversized files, and digest mismatches are rejected before execution.

The first release is not a complete sandbox. Wasmtime provides the component isolation boundary, while the host controls which imports are linked. A security review, signed packages, cache isolation, and operating-system sandbox profiles are required before cartridges should be treated as safe to exchange publicly.

## Portability boundary

The WIT package is the portable ABI. A component imports `cartridge:api/host`, not Win32, Cocoa, or a Linux desktop API. Platform adapters can later implement richer capabilities behind stable interfaces:

```text
cartridge component
        |
        v
versioned WIT capabilities
        |
   +----+----+
   |    |    |
Windows macOS Linux
```

Applications that only use common capabilities remain byte-for-byte portable. Target-specific capabilities will live in explicit packages so portability loss is visible in component metadata.

## Cartridge relationships

Isolation is the default, not a ban on cooperation. A cartridge may declare a dependency on a specific version range and a precise list of WIT interfaces. The resolver selects a technically compatible provider, while a separate grant policy decides whether the connection is allowed.

Calls will pass through a runtime broker. The caller receives the declared service interface, not the provider's memory, storage, or other capabilities. Any delegated resource is restricted to the intersection of provider authority, interface contract, caller grant, and resource scope.

The manifest and direct resolver are implemented. Live multi-instance wiring and persistent user grants are not yet implemented. The full design is in [composition.md](composition.md).

## Tracing and replay

Every call through the cartridge capability API receives a monotonically increasing sequence number. Trace format v2 binds the recording to a component digest and argument list. During replay, nondeterministic clock and random results come from the trace; deterministic calls are recomputed and compared. Output, fuel usage, missing events, and extra events are checked after execution.

Replay currently works at capability boundaries. The next debugger layer will add linear-memory checkpoints and state hashes, which are needed for reverse stepping inside longer executions.

The trace format is versioned independently from the cartridge format so either can evolve without silently changing the other.
