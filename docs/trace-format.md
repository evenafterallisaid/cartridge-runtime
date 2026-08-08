# Trace format v2

A trace is an executable record of one cartridge invocation. It identifies the exact component, stores the arguments supplied to it, records each call through the cartridge capability API, and stores the final observable result.

```json
{
  "format_version": 2,
  "runtime_version": "0.1.0",
  "cartridge_id": "dev.cartridge.hello",
  "cartridge_version": "0.1.0",
  "component_sha256": "...",
  "args": ["Clyde"],
  "events": [],
  "result": {
    "output": "...",
    "fuel_consumed": 8883
  }
}
```

## Recording

Each event receives a zero-based sequence number. An event contains a capability name, an operation name, and the value observable by the guest. Clock and random values are stored in full because replay must return the same inputs without consulting the live host.

Packaged asset reads record their path, length, and SHA-256 digest instead of duplicating asset contents. Logs record the level and bounded message that reached the host.

## Replay

The runtime validates these fields before compiling the component:

- trace format version
- cartridge id and version
- component digest
- invocation arguments

During execution, clock and random calls take their results from the next trace event. Deterministic calls such as logs and asset reads are executed normally and compared with the recorded event. The runtime stops at the first different sequence and reports the expected and actual operations or values.

Replay also fails when execution produces an extra event, leaves recorded events unused, changes its final output, or consumes a different amount of fuel.

## Inspection and comparison

Trace tooling does not compile or execute the cartridge:

```sh
cartridge trace inspect run.trace.json
cartridge trace inspect run.trace.json --json
cartridge trace diff first.trace.json second.trace.json
```

Inspection validates the header, component digest, zero-based event sequence, and capability labels before producing a summary. Comparison reports one difference at a time in execution order: invocation identity, the first changed event, then the final output or fuel use. The same comparison is available as structured JSON for future debugger and editor integrations.

## Compatibility

The trace format is versioned independently from the cartridge archive and WIT API. A runtime must reject trace versions it does not understand. Additive fields are not silently ignored in v2 because traces are debugger inputs and accidental ambiguity is worse than an explicit conversion step.

Runtime upgrades may change fuel accounting or capability behavior. A future trace migration command can convert formats when the semantic difference is understood; the runtime should not guess.

## Privacy

Traces can contain command arguments, logs, random bytes, network responses, input events, and future storage results. They must be treated as potentially sensitive diagnostic files. Redaction and encrypted crash bundles are required before traces are convenient to share publicly.
