// only loaded by vite's explicit development preview, never by the native app
const stacks = [
  { stack: "personal-workspace", state: "applied", instance_count: 3, desired_replicas: 4, revision: 8 },
  { stack: "media-pipeline", state: "applied", instance_count: 2, desired_replicas: 2, revision: 12 },
  { stack: "local-api", state: "applied", instance_count: 1, desired_replicas: 2, revision: 3 },
  { stack: "nightly-archive", state: "stopped", instance_count: 1, desired_replicas: 0, revision: 6 },
].map((stack) => ({ ...stack, plan_sha256: "a".repeat(64), event_sha256: "b".repeat(64) }));
let settings = { version: 1, theme: "light", density: "comfortable", animations: true, default_security: "strict", default_sandbox: "required" };

export function previewInvoke(command: string, args?: Record<string, unknown>): unknown {
  if (command === "get_settings") return settings;
  if (command === "save_settings") { settings = args?.settings as typeof settings; return settings; }
  if (command === "dashboard") return {
    engine: { state: "online", message: null, info: { protocol_version: 4, instance_id: "preview", pid: 0, started_at_ms: Date.now(), active_supervisors: 3, max_supervisors: 8, workers_per_stack: 4, known_stacks: 4, applied_stacks: 3 } },
    stacks: structuredClone(stacks),
    packages: [
      { cartridge_id: "dev.cartridge.service", name: "Service Cartridge", versions: ["0.1.0"], safe_mode: true },
      { cartridge_id: "dev.cartridge.media", name: "Media Toolkit", versions: ["0.2.0", "0.1.0"], safe_mode: true },
    ],
  };
  if (command === "stack_events") return [];
  if (command === "stack_details") return { plan: null, runtime: null };
  if (command === "stop_stack") {
    const stack = stacks.find((item) => item.stack === args?.stack);
    if (stack) { stack.state = "stopped"; stack.desired_replicas = 0; }
    return {};
  }
  throw new Error("This action needs the native app. Preview data stays on this page.");
}
