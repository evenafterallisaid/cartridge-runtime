# Networking and device mesh

Raw WASI TCP, UDP, and name lookup stay disabled. A cartridge can request bounded HTTP through the host only when `permissions.http` is enabled and the manifest declares exact scopes.

```toml
[permissions]
http = true

[[http.scopes]]
scheme = "https"
host = "api.example.com"
path_prefix = "/v1"
methods = ["GET"]
```

Scopes match scheme, host, effective port, path-segment prefix, and method. Credentials and fragments in URLs, control characters, hop-by-hop headers, cleartext non-loopback HTTP, and redirects outside host policy are rejected. Requests are capped at 1 MiB and responses at 4 MiB.

`--http-fixtures fixtures.json` supplies a host-owned offline transport. HTTP outcomes are included in execution traces, so replay validates the request fingerprint and returns the recorded response without consulting DNS or a live transport.

The `cartridge-network` crate also supplies transport-independent device-mesh primitives: stable X25519 peer identities, authenticated XChaCha20-Poly1305 sessions with replay rejection, bounded message channels, content-addressed chunk transfer, convergent last-writer-wins documents, rollback datagram windows, and a seeded latency/jitter/loss/reordering simulator. Discovery exposes opaque route tokens rather than placing IP addresses in guest identity.

NAT traversal and live socket ownership intentionally remain host-adapter work. Guests never receive socket handles, peer addresses, or cryptographic secrets.
