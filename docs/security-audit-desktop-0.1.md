# Desktop shell security review

Date: 2026-08-14

Scope: the initial Tauri desktop shell, its webview-to-Rust command boundary, reviewed-plan lifecycle, local application data path, frontend build, and dependency graphs.

## Result

No known exploitable issue remains in the reviewed first-shell boundary on the current Windows and macOS targets. The app currently controls desired state only. It does not run stack instances, broker secrets, import packages, expose a local network listener, or enter a privileged OS context.

## Finding fixed during review

| id | severity | finding | resolution |
| --- | --- | --- | --- |
| DESK-01 | high | the UI displayed one exact plan but the first apply command rebuilt a new plan from the manifest, allowing installed-catalog drift between review and apply | the Rust backend now retains the reviewed plan outside the webview, accepts only its digest on apply, and reopens and verifies every locked root/provider package before recording that exact plan |
| DESK-02 | high | the initial desktop lockfile resolved vulnerable `quick-xml` and `time` releases | the dependency graph was advanced through `plist` 1.10 and `time` 0.3.51; the independent lockfile now scans with zero vulnerability advisories |

The package re-verification boundary is implemented in `cartridge-engine` and has a regression test that changes installed package bytes after review.

## Boundary decisions

- The window loads bundled local assets and has a restrictive content security policy. No remote URL is configured.
- The app enables no filesystem, shell, HTTP, process, clipboard, updater, or dialog plugin permissions.
- The webview never supplies library or engine roots. Rust derives both from the per-user application data directory.
- Stack selection uses a normal HTML file input. The frontend rejects files over 1 MiB and the Rust parser enforces the same limit again.
- Dynamic cartridge, stack, event, digest, and error data is written with DOM text nodes rather than HTML injection.
- Desktop preferences use a bounded, versioned, deny-unknown JSON model in the private native app-data directory. Writes use a private temporary file and atomic persistence; links, non-files, oversized input, and unknown fields fail closed.
- Runtime preferences are explicitly new-stack authoring defaults. They cannot override an imported manifest or disable package verification and enforcement.
- Sandbox-disabled plans require a visible second confirmation and the engine independently requires the matching explicit flag.
- The app data directory rejects links and non-directories and requests mode `0700` when it creates the directory on Unix.
- There is one local window and no remote webview capability.

## Verification

- TypeScript strict check and production Vite build
- native Windows Tauri compilation and strict Clippy
- visual inspection of the real WebView2 window at its default size
- live invocation of the dashboard command through the compiled app
- root workspace strict Clippy and engine regression suite
- npm advisory scan and RustSec scan of the independent desktop lockfile
- CI compilation of the native shell on Windows, macOS, and Linux, plus separate RustSec checks for the root and desktop lockfiles
- native preference round-trip, replacement, oversized-input, unknown-field, and non-file regression tests

## Residual and future gates

- Every future execution path must re-verify package identity and trusted signature immediately before worker activation; apply-time verification is not a launch-time guarantee.
- Package import should use a narrow native picker command that accepts only bounded regular `.cartridge` files and never exposes general filesystem read capability to the webview.
- A future daemon connection must authenticate the local peer and authorize mutations. It must not trust the webview, a loopback port, or possession of a predictable socket path by itself.
- Secret values must remain in a native broker. They must not cross the webview IPC boundary or enter plan/event JSON.
- Logs and traces require bounded streaming, redaction, and terminal-safe rendering before they are displayed.
- Updater, URL opening, clipboard, drag/drop, and plugin additions require explicit capabilities and a new review.
- Signed installers, Windows WebView2 servicing assumptions, macOS signing/notarization, Linux WebKit packaging, accessibility testing, and independent assessment remain release gates.
- The Linux Tauri dependency graph still emits upstream maintenance warnings for GTK3-era crates and an unsoundness advisory in `glib` 0.18.5. They are target-specific transitive dependencies rather than findings in Cartridge code, but Linux production packaging remains blocked until the Tauri/WebKitGTK graph moves to a resolved line or the affected surface is independently contained and reviewed.
