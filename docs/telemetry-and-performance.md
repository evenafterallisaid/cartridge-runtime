# Telemetry and performance

The runtime has no telemetry upload endpoint. Traces, launch history, resource samples, audio counters, and stability reports remain local files. Sharing one is an explicit file operation; `trace redact` should be used before sharing trace diagnostics.

`stability benchmark` measures cold runtime construction, package validation, compilation, instantiation, and one run. `stability soak` performs one live run and repeatedly replays its exact trace through one runtime, detecting unconsumed events, result/fuel drift, invalid capability outcomes, and media receipt differences.

```sh
cartridge stability benchmark app.cartridge --iterations 25 --output benchmark.json
cartridge stability soak app.cartridge --iterations 1000 --output soak.json
```

Reports are bounded, create-new, private local JSON marked `local_only`. They include OS/architecture, iteration count, min/median/p95/max time, the declared linear-memory ceiling, fuel, event count, output digest, media counts, and time spent in headless graphics/audio rendering. They contain no automatic machine id, username, host path, network address, or upload token. The measurement loop runs in a killable worker with a one-hour outer ceiling.

Release baselines should run optimized binaries on an otherwise idle machine. Compare like-for-like OS, architecture, power mode, and hardware. A timing regression is not automatically a security defect, but unbounded growth, deadline escape, replay drift, or a large unexplained p95 change blocks a release candidate. Native worker RSS and real-device audio latency remain platform-adapter measurements; the deterministic headless renderer does not pretend to measure either.
