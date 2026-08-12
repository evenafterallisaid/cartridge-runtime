# Desktop library

`cartridge-desktop` is the shared native shell backend for Windows, macOS, and Linux. The current command-line shell is keyboard- and screen-reader-friendly; graphical shells consume the same permission prompts, catalog, history, recovery, and rendering policies instead of reimplementing authority decisions.

## Installation and catalog

Installation first copies a package into a bounded staging file while hashing it, verifies that exact staged archive, then links it into a content-addressed location. A cartridge id and semantic version are immutable once installed. Search covers ids, names, descriptions, and installed versions. Profiles are validated sets of installed cartridge ids.

`.cartridge` file handling is recognized independently from OS registration. Platform installers can register the extension without changing the package-opening path. Runtime channel/version state is stored separately from cartridge versions so a shell updater can stage or roll back the runtime without rewriting installed packages.

## Permissions

Preflight returns requested, granted, and missing capabilities in a stable order. The accessible prompt model gives every capability a visible label and plain-language description plus named approve and cancel actions.

Persistent grants are bound to the complete requested-capability set. If an update changes that set, its old grant does not authorize the new version. Session grants live only in the current shell process. A grant outside the package's declared request is rejected, and either one capability or the complete grant can be revoked.

The CLI surfaces this model through `cartridge library preflight`, `grant`, `revoke`, and `run`. `library run --allow graphics` is a session-only approval for that launch process.

## Recovery and monitoring

Launches are written as running before execution. If the shell opens after an interrupted launch, that record becomes terminated. Three consecutive failed or interrupted launches enable safe mode for that cartridge; the rest of the library still opens. Invalid library metadata is quarantined under `recovery` and replaced with an empty valid index.

History is bounded, as are per-launch resource samples. Samples require monotonic elapsed time and record fuel, memory, and audio underruns. Full trace timelines use the versioned trace-viewer export rather than being duplicated in the library index.

## Graphics presentation

The deterministic 2D renderer remains the canonical CPU implementation. A desktop shell can select accelerated presentation through `GraphicsPresenter` without exposing device handles or mapped GPU memory to a guest. GPU mode requires robust buffer access, helper-process isolation, and bounded buffers, textures, shaders, render passes, and commands.

This interface is the security boundary for a future WebGPU-style 3D graph. It does not claim that the current 2D stream becomes modern 3D merely by sending it to a GPU; portable 3D needs versioned shader, pipeline, texture, buffer, and render-pass WIT types.
