# Identity and registry

Cartridge signs the exact bytes of a `.cartridge` archive with Ed25519. The signed identity also includes the cartridge id, semantic version, component digest, asset-tree root, package digest, and byte length. Any byte change invalidates verification.

Unsigned packages remain valid for local development. `cartridge verify` checks archive integrity; `cartridge identity verify` checks authorship, optionally against a trust store.

```sh
cartridge identity keygen --output developer.key.json
cartridge identity sign app.cartridge --key developer.key.json --output app.signature.json
cartridge identity trust app.signature.json --store trust.json --label "local developer"
cartridge identity verify app.cartridge app.signature.json --trust trust.json
cartridge registry init registry
cartridge registry publish app.cartridge app.signature.json --trust trust.json --root registry
cartridge registry resolve dev.example.app "^1" --root registry
cartridge registry audit --root registry --trust trust.json
```

Developer key files are created without overwrite. On Unix they are restricted to the owner; on Windows they inherit the containing directory ACL, so keep them in a private user directory or OS credential vault. Back up a separate recovery key offline.

Routine rotation is authorized by both old and new keys. Emergency revocation can be signed by the active key or a recovery key registered when trust is established. Registry versions are immutable: a second package with the same id and version is accepted only when its digest is identical. The append-only hash chain makes index history tampering detectable, while `registry audit` re-verifies every stored package and signature.

The current registry is a local protocol/reference implementation. A remote service must preserve the same content-addressed object, immutability, signature, and transparency invariants.
