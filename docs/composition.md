# Cartridge composition

Cartridges are isolated units, but isolation does not mean they must remain unrelated. The system is designed around explicit composition: a cartridge can request a versioned service from another cartridge, the resolver can find a compatible provider, and the runtime can ask the user whether that connection should exist.

The manifest describes requested relationships. It never grants them by itself.

## Relationship model

```text
caller manifest
  requests cartridge id + version range + WIT interfaces
        |
        v
dependency resolver
  selects a compatible installed provider
        |
        v
grant policy
  user or administrator accepts a narrow connection
        |
        v
runtime broker
  passes typed calls, resources, and cancellation
        |
        v
provider cartridge
```

The caller does not receive the provider's memory, files, storage namespace, network grants, or host handles. It receives only the interfaces listed in the dependency declaration and approved by policy.

## Manifest declarations

A caller can request another cartridge:

```toml
[[dependencies]]
alias = "image-codec"
cartridge = "dev.example.image-codec"
version = "^1.2"
interfaces = ["example:media/decode@1.0.0"]
optional = false
reason = "decodes textures imported by the project"
```

A provider can advertise typed services:

```toml
[[services.provides]]
name = "decoder"
interface = "example:media/decode@1.0.0"
visibility = "dependency"
description = "decodes supported image formats into pixel buffers"
```

Interfaces use WIT package identity and semantic versions. A dependency must request at least one interface; depending on a cartridge without stating the required authority is rejected.

## Visibility

Provided services have three visibility levels:

- `private` — unavailable to other cartridges
- `dependency` — available only through an explicit dependency and grant
- `public` — discoverable, but still requires an explicit grant before use

Public does not mean ambient or anonymous. It affects discovery, not permission.

## Resolution and grants

Resolution and permission are separate steps.

The resolver answers technical questions:

- is the requested cartridge installed?
- does an installed version satisfy the semantic-version range?
- does that version provide every requested interface?
- is each interface externally visible?
- which compatible version should be selected?

The grant policy answers authority questions:

- may this caller use this provider?
- which interfaces are approved?
- is the grant permanent, session-only, or one-shot?
- may the provider learn the caller's identity?
- may either side delegate a received resource?

The current resolver selects the highest compatible direct provider and preserves unresolved optional dependencies in its output. Transitive graph solving, persistent grants, and live component wiring are later runtime milestones.

## Capability non-amplification

A provider cannot lend authority it does not possess. A caller also does not inherit all provider authority merely because it can invoke one service.

If cartridge A can call a thumbnail service in cartridge B, and B can read a user-selected photo directory, A should not automatically gain directory access. B can return a thumbnail result, or the runtime can pass a specific opaque image resource, but the original directory handle remains outside A's authority.

Delegation follows an intersection rule:

```text
delegated authority = provider authority
                    ∩ interface contract
                    ∩ caller grant
                    ∩ resource-specific restrictions
```

Opaque resources need provenance, expiry, and revocation metadata. The runtime should be able to explain where a handle came from and which connection currently holds it.

## Process and memory isolation

The first implementation can host several Wasm component instances in one native runtime process because Wasm memories and resource tables remain separate. Higher-risk adapters such as codecs, GPU access, and native device integrations may later run in worker processes.

Service calls must never exchange raw pointers. Values cross through the Component Model canonical ABI, while larger objects use typed resources or content-addressed blobs.

## Lifecycle

Providers should be activated on demand rather than all running at login. The supervisor will eventually manage:

- cold start and warm instances
- reference-counted activation
- idle suspension
- cancellation and deadlines
- provider crashes
- restart limits and circuit breakers
- version upgrades with active clients
- background-service permission

Required dependency failure blocks the relevant caller operation or launch. Optional dependency failure is visible to the cartridge through feature discovery and must not silently change authority.

## Cycles

Dependency graphs may contain legitimate cycles at the package level, but activation cycles can deadlock. The graph resolver should distinguish static compatibility from runtime activation.

Potential rules:

- reject constructor-time cyclic calls
- activate components before connecting service edges
- require asynchronous calls across cycle edges
- detect wait-for cycles and return a typed failure
- include the activation graph in diagnostic traces

## Upgrades

An installed provider update must not silently alter the selected service contract. The resolver pins an exact selected version for a launch plan. Upgrades create a new plan, rerun compatibility checks, and may require renewed permission if interfaces or requested authority change.

Side-by-side provider versions may be necessary when two callers require incompatible major versions. Persistent data migration belongs to the provider and must be transactional.

## Shared data

Direct access to another cartridge's storage remains forbidden. Cooperation uses one of these explicit patterns:

- request/response values through a service interface
- immutable content-addressed blobs
- runtime-owned shared documents with participant grants
- scoped resources selected by the user
- append-only event streams with declared schemas

Shared documents and event streams should be first-class runtime resources. Treating another cartridge's private directory as a shared database would destroy the isolation boundary.

## User experience

A permission prompt should explain relationships as a graph, not as an unexplained list of technical package names:

```text
Photo Board wants to use Image Codec

Allows:
  decode selected images

Does not allow:
  access to Image Codec settings
  access to its files or network permissions
```

Users should be able to inspect, revoke, and temporarily disable edges later. Revocation must close live resources and make subsequent calls fail with a typed permission error.

## Remote services

The same service contract could eventually be routed to another trusted device. Remote routing must be visibly different from local composition because it changes privacy, latency, availability, and replay behavior.

The broker would keep the WIT interface stable while adding:

- peer identity and encryption
- explicit remote-use permission
- serialization and size budgets
- deadlines and retry policy
- offline behavior
- trace recording at both ends
- version negotiation

Remote execution is a post-local-composition feature, not a shortcut around implementing the local security model.

## Implementation stages

1. Manifest declarations and validation.
2. Direct dependency resolver and CLI inspection.
3. Installed-cartridge catalog and exact-version lock plans.
4. Persistent user grants.
5. In-process broker for synchronous typed services.
6. Async calls, cancellation, and activation supervision.
7. Opaque resource delegation with provenance.
8. Transitive graph solving and cycle diagnostics.
9. Worker-process isolation for selected providers.
10. Optional encrypted routing between devices.
