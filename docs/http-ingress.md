# Loopback HTTP ingress

`cartridge engine ingress` exposes one named stack instance through the existing authenticated invocation broker. It binds only IPv4 `127.0.0.1`; the default port is chosen by the OS and the listener URL is printed at startup.

Start the engine, install the service example, apply `tests/fixtures/Cartridge.service.stack.toml`, and wait for `service-stack` to become healthy. Create a private token file containing 32 cryptographically random bytes encoded as 64 lowercase hexadecimal characters. Keep that file outside the repository and readable only by your account. The gateway reads it once at startup; restart with a new token file to rotate credentials.

```sh
cartridge engine ingress service-stack api --root dist/engine \
  --token-file /private/path/ingress.token --port 8080
```

Clients send `Authorization: Bearer <token>` and the exact `Host: 127.0.0.1:8080`. The ingress token is distinct from the daemon credential and never reaches the cartridge. The gateway forwards GET, HEAD, POST, PUT, PATCH, and DELETE requests, preserving their origin-form path and query string. The daemon selects a ready replica and applies its existing run identity, capability, queue, cancellation, and deadline checks.

This milestone supports local API clients. Browser-origin requests are rejected, including same-origin fetches carrying an Origin header; browser login/session support is a later feature. There is no CORS opt-out or unauthenticated route. Host validation prevents arbitrary DNS names from reaching the service through rebinding. All routes require the token, including health requests.

## Bounds and protocol

- HTTP/1.1 only, one request per connection, no upgrades or streaming
- 16 KiB request head, 128 unique headers, 256 KiB body in either direction
- four concurrent clients; excess accepted connections close immediately
- three seconds total to read a request, three seconds total to write its response
- configurable guest timeout of 10–30,000 ms, default 5,000 ms
- duplicate headers, transfer encoding, folded headers, Expect, invalid path forms, and ambiguous framing are rejected
- the host owns response framing, strips CORS headers, and adds `no-store` and `nosniff`
- engine errors return a generic 503 without exposing engine paths or diagnostic details

Ctrl+C stops admission and waits for bounded in-flight work to finish. The gateway is a separate foreground process; it neither modifies the stack manifest nor survives its own process exit. A token holder can invoke only the stack and instance selected at startup, including their future ready revisions, and cannot use this HTTP port to mutate engine configuration.

## Remaining work

Declared ingress policy and daemon ownership, browser sessions, streaming, rate limits, TLS, and remote exposure remain separate milestones. Local processes running as the same OS user can read that user's files and interfere with local services; the token is not a native authority sandbox.
