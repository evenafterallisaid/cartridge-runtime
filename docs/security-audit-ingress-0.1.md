# Loopback ingress review

Scope: the foreground HTTP gateway, parsing and response framing, credential boundary, resource admission, and its existing daemon invocation integration. This is an internal code review and regression exercise, not independent assurance.

## Controls verified

- binds only `127.0.0.1`, with exact numeric Host authority matching
- mandatory separate 256-bit bearer credential, removed before guest delivery
- no browser Origin admission or CORS response opt-out
- one fixed stack/instance, no HTTP engine-management endpoints
- duplicate fields, folded lines, transfer encoding, Expect, upgrades, proxy authentication, and connection-nominated fields rejected
- headers bounded before parsing, content length checked before body allocation
- three-second absolute read/write deadlines, four admitted clients, no persistent HTTP connections
- response framing controlled by the host, informational responses rejected, HEAD and no-body statuses handled explicitly
- guest errors and daemon diagnostics replaced with generic failures
- ready-replica fencing, queue bounds, permission checks, and cancellation inherited from the invocation broker

## Findings corrected during review

1. A bounded token read alone could accept a valid token followed by excessive line endings and an unread suffix. Reject files reaching the read cap before trimming.
2. A listener could advertise itself while its daemon was unreachable. Authenticate a daemon ping before binding and publishing the URL.
3. Guest-provided response headers could undermine ingress browser policy or HTTP framing. Strip CORS and unsupported hop-by-hop headers and enforce host-owned cache/framing fields.
4. Accepted Windows sockets could inherit nonblocking behavior and fail on fragmented POST requests. Explicitly restore blocking mode before applying absolute I/O deadlines; verify with the engine-backed POST smoke test.

## Residual limits

Same-user native processes can inspect the token file or deny local service. Four slow clients can consume the bounded admission pool until their absolute deadlines expire; this milestone does not promise fair scheduling or per-client rate limits. Delivery is not exactly once, and disconnecting a client does not undo work already dispatched. A gateway follows ready revisions of its named instance; it is not pinned to a package digest for its entire lifetime. The HTTP subset intentionally rejects streaming and browser-origin clients. Native authority sandbox and independent review gates remain open.

Regression coverage includes malformed/authentication/framing cases, actual TCP request and response handling, bodyless responses, and real engine-backed GET/POST/HEAD plus missing-token, Origin, and Host rejection across the CI operating-system matrix.
