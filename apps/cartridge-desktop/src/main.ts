import { invoke } from "@tauri-apps/api/core";
import "./style.css";

const MAX_STACK_BYTES = 1024 * 1024;

type StackState = "applied" | "stopped" | "removed";
type View = "stacks" | "library" | "resources" | "activity" | "settings";

type ThemePreference = "system" | "light" | "dark";
type DensityPreference = "comfortable" | "compact";
type SecurityPreference = "strict" | "balanced" | "permissive";
type SandboxPreference = "required" | "preferred" | "disabled";

interface LibraryEntry {
  cartridge_id: string;
  name: string;
  versions: string[];
  safe_mode: boolean;
}

interface StackStatus {
  stack: string;
  revision: number;
  state: StackState;
  plan_sha256: string | null;
  instance_count: number;
  desired_replicas: number;
  event_sha256: string;
}

interface PlannedInstance {
  name: string;
  cartridge_id: string;
  version: string;
  package_sha256: string;
  replicas: number;
  desired: "running" | "stopped";
  allowed: string[];
  denied: string[];
}

interface PlannedResource {
  name: string;
  kind: string;
  owner: string;
  retention: string;
  quota_bytes: number | null;
}

interface StackPlan {
  stack: string;
  security: {
    profile: "strict" | "balanced" | "permissive";
    sandbox: "required" | "preferred" | "disabled";
  };
  instances: PlannedInstance[];
  resources: PlannedResource[];
  secrets: Array<{ name: string; required: boolean }>;
  warnings: string[];
  plan_sha256: string;
}

interface EngineEvent {
  revision: number;
  stack: string;
  kind: "apply" | "stop" | "remove";
  created_at_ms: number;
  plan: StackPlan | null;
  event_sha256: string;
}

interface Dashboard {
  packages: LibraryEntry[];
  stacks: StackStatus[];
}

interface AppSettings {
  version: 1;
  theme: ThemePreference;
  density: DensityPreference;
  animations: boolean;
  default_security: SecurityPreference;
  default_sandbox: SandboxPreference;
}

const defaultSettings: AppSettings = {
  version: 1,
  theme: "system",
  density: "comfortable",
  animations: true,
  default_security: "strict",
  default_sandbox: "required",
};

const content = required<HTMLElement>("content");
const inspector = required<HTMLElement>("inspector");
const fileInput = required<HTMLInputElement>("stack-file");
const notice = required<HTMLElement>("notice");
const title = required<HTMLElement>("view-title");
const description = required<HTMLElement>("view-description");
const search = required<HTMLInputElement>("global-search");
const engineStatus = required<HTMLElement>("engine-status");
const confirmDialog = required<HTMLDialogElement>("confirm-dialog");
const previewBanner = required<HTMLElement>("preview-banner");

let dashboard: Dashboard = { packages: [], stacks: [] };
let currentView: View = "stacks";
let currentPlan: StackPlan | null = null;
let refreshing = false;
let mutating = false;
let query = "";
let stackFilter: "all" | StackState = "all";
let settings: AppSettings = defaultSettings;
let settingsQueue: Promise<void> = Promise.resolve();
let bannerDismissed = false;

function required<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`missing element: ${id}`);
  return value as T;
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const value = document.createElement(tag);
  if (className) value.className = className;
  if (text !== undefined) value.textContent = text;
  return value;
}

function shortDigest(value: string | null): string {
  return value ? `${value.slice(0, 12)}…` : "—";
}

function formatBytes(value: number | null): string {
  if (value === null) return "Unlimited";
  const units = ["B", "KB", "MB", "GB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount < 10 && unit > 0 ? amount.toFixed(1) : Math.round(amount)} ${units[unit]}`;
}

function showNotice(message: string, tone: "ok" | "error" = "ok"): void {
  notice.textContent = message;
  notice.className = `notice ${tone}`;
  window.setTimeout(() => notice.classList.add("hidden"), 5200);
}

async function refresh(): Promise<void> {
  if (refreshing) return;
  refreshing = true;
  engineStatus.classList.add("working");
  try {
    dashboard = await invoke<Dashboard>("dashboard");
    engineStatus.className = "engine-status";
    engineStatus.querySelector("span")!.textContent = "Engine ready";
    required<HTMLElement>("stack-count").textContent = String(dashboard.stacks.length);
    required<HTMLElement>("package-count").textContent = String(dashboard.packages.length);
    render();
  } catch (error) {
    engineStatus.className = "engine-status error";
    engineStatus.querySelector("span")!.textContent = "Engine unavailable";
    content.replaceChildren(emptyState("Engine unavailable", String(error), "error"));
    showNotice(String(error), "error");
  } finally {
    refreshing = false;
  }
}

function render(): void {
  const pages: Record<View, readonly [string, string]> = {
    stacks: ["Stacks", "Define and manage multi-cartridge applications."],
    library: ["Packages", "Installed cartridge packages available to local stacks."],
    resources: ["Resources", "Persistent state and blob allocations declared by stacks."],
    activity: ["Activity", "Immutable control-plane changes from the local engine journal."],
    settings: ["Settings", "Configure the desktop experience and defaults for new stacks."],
  };
  const page = pages[currentView];
  title.textContent = page[0];
  description.textContent = page[1];
  search.placeholder = currentView === "settings" ? "Search settings" : "Search current view";
  document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === currentView);
  });
  required<HTMLElement>("load-button").classList.toggle("hidden", currentView !== "stacks");
  required<HTMLElement>("page-refresh").classList.toggle("hidden", currentView === "settings");
  previewBanner.classList.toggle("hidden", bannerDismissed || currentView === "settings");
  if (currentView === "stacks") renderStacks();
  if (currentView === "library") renderLibrary();
  if (currentView === "resources") void renderResources();
  if (currentView === "activity") void renderActivity();
  if (currentView === "settings") renderSettings();
}

function renderSettings(): void {
  const page = element("div", "settings-page");
  page.append(settingsIntro());

  const appearance = settingsSection("Appearance", "Personalize this desktop without changing runtime policy.");
  appearance.append(
    settingRow("Theme", "Follow the operating system or choose a fixed appearance.", segmentedControl<ThemePreference>([
      ["system", "System"],
      ["light", "Light"],
      ["dark", "Dark"],
    ], settings.theme, (theme) => updateSettings({ theme }))),
    settingRow("Density", "Adjust table and navigation spacing.", segmentedControl<DensityPreference>([
      ["comfortable", "Comfortable"],
      ["compact", "Compact"],
    ], settings.density, (density) => updateSettings({ density }))),
    settingRow("Interface motion", "Use short transitions when switching views and opening panels.", toggleControl(settings.animations, (animations) => updateSettings({ animations }))),
  );
  page.append(appearance);

  const runtime = settingsSection("New stack defaults", "These values prefill future create flows. Imported manifests remain authoritative and are never silently weakened.");
  runtime.append(
    settingRow("Security profile", "Default capability posture for a newly authored stack.", selectControl<SecurityPreference>([
      ["strict", "Strict"],
      ["balanced", "Balanced"],
      ["permissive", "Permissive"],
    ], settings.default_security, (default_security) => updateSettings({ default_security }))),
    settingRow("Worker sandbox", "Default native isolation requirement for new workloads.", selectControl<SandboxPreference>([
      ["required", "Required"],
      ["preferred", "Preferred"],
      ["disabled", "Disabled"],
    ], settings.default_sandbox, (default_sandbox) => updateSettings({ default_sandbox }))),
  );
  page.append(runtime);

  const boundary = settingsSection("Runtime", "Current local engine and WebAssembly boundary.");
  boundary.append(
    readOnlySetting("Engine", "Local per-user control plane", "Desired state"),
    readOnlySetting("WebAssembly", "WASI 0.2 component model", "Preview 2"),
    readOnlySetting("Package identity", "Exact bytes rechecked before apply", "Always on"),
    readOnlySetting("Workload supervisor", "Worker reconciliation is not active in this preview", "Pending"),
  );
  page.append(boundary);

  const footer = element("div", "settings-footer");
  const reset = element("button", "button secondary", "Restore defaults");
  reset.type = "button";
  reset.addEventListener("click", () => updateSettings(defaultSettings));
  footer.append(element("span", undefined, "Preferences are stored in Cartridge's private app-data directory."), reset);
  page.append(footer);

  if (query) {
    const normalized = query.toLowerCase();
    page.querySelectorAll<HTMLElement>(".settings-section").forEach((section) => {
      const rows = [...section.querySelectorAll<HTMLElement>(".setting-row")];
      rows.forEach((row) => row.classList.toggle("hidden", !row.textContent!.toLowerCase().includes(normalized)));
      section.classList.toggle("hidden", rows.every((row) => row.classList.contains("hidden")));
    });
  }
  content.replaceChildren(page);
}

function settingsIntro(): HTMLElement {
  const value = element("div", "settings-intro");
  const mark = element("div", "settings-mark");
  mark.append(element("i"), element("i"), element("i"));
  const copy = element("div");
  copy.append(element("strong", undefined, "Local by default"), element("span", undefined, "Desktop preferences stay on this machine. Runtime security remains manifest-bound and fail-closed."));
  value.append(mark, copy);
  return value;
}

function settingsSection(heading: string, copy: string): HTMLElement {
  const section = element("section", "settings-section");
  const header = element("header");
  header.append(element("h2", undefined, heading), element("p", undefined, copy));
  section.append(header);
  return section;
}

function settingRow(label: string, copy: string, control: HTMLElement): HTMLElement {
  const row = element("div", "setting-row");
  const text = element("div", "setting-copy");
  text.append(element("strong", undefined, label), element("span", undefined, copy));
  row.append(text, control);
  return row;
}

function readOnlySetting(label: string, copy: string, value: string): HTMLElement {
  return settingRow(label, copy, element("span", "setting-value", value));
}

function segmentedControl<T extends string>(options: Array<readonly [T, string]>, selected: T, onChange: (value: T) => void): HTMLElement {
  const group = element("div", "segmented-control");
  group.setAttribute("role", "group");
  for (const [value, label] of options) {
    const button = element("button", value === selected ? "active" : "", label);
    button.type = "button";
    button.setAttribute("aria-pressed", String(value === selected));
    button.addEventListener("click", () => onChange(value));
    group.append(button);
  }
  return group;
}

function selectControl<T extends string>(options: Array<readonly [T, string]>, selected: T, onChange: (value: T) => void): HTMLSelectElement {
  const select = element("select", "settings-select");
  for (const [value, label] of options) {
    const option = element("option", undefined, label);
    option.value = value;
    option.selected = value === selected;
    select.append(option);
  }
  select.addEventListener("change", () => onChange(select.value as T));
  return select;
}

function toggleControl(checked: boolean, onChange: (value: boolean) => void): HTMLButtonElement {
  const button = element("button", checked ? "toggle-control active" : "toggle-control");
  button.type = "button";
  button.setAttribute("role", "switch");
  button.setAttribute("aria-checked", String(checked));
  button.setAttribute("aria-label", "Toggle interface motion");
  button.append(element("i"));
  button.addEventListener("click", () => onChange(!checked));
  return button;
}

function updateSettings(patch: Partial<AppSettings>): void {
  const next = { ...settings, ...patch };
  settings = next;
  applySettings();
  renderSettings();
  settingsQueue = settingsQueue.then(async () => {
    await invoke<AppSettings>("save_settings", { settings: next });
  }).catch((error) => showNotice(String(error), "error"));
}

function applySettings(): void {
  const dark = settings.theme === "dark" || (settings.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  document.documentElement.dataset.density = settings.density;
  document.documentElement.dataset.motion = settings.animations ? "on" : "off";
}

function renderStacks(): void {
  const normalized = query.toLowerCase();
  const stacks = dashboard.stacks.filter((stack) => {
    const matchesQuery = stack.stack.toLowerCase().includes(normalized);
    const matchesState = stackFilter === "all" || stack.state === stackFilter;
    return matchesQuery && matchesState;
  });
  const shell = tableShell();
  shell.prepend(stackToolbar());
  const table = element("table", "data-table");
  table.append(tableHead(["Name", "Status", "Instances", "Desired replicas", "Revision", "Plan", ""]));
  const body = element("tbody");
  for (const stack of stacks) body.append(stackRow(stack));
  table.append(body);
  shell.append(table);
  if (stacks.length === 0) {
    shell.append(emptyState(
      dashboard.stacks.length === 0 ? "No stacks" : "No matching stacks",
      dashboard.stacks.length === 0
        ? "Create a stack from a Cartridge.stack.toml manifest to record its desired state."
        : "Try a different search term or status filter.",
      "stack",
    ));
  }
  content.replaceChildren(shell);
}

function stackToolbar(): HTMLElement {
  const toolbar = element("div", "table-toolbar");
  const tabs = element("div", "filter-tabs");
  const counts: Array<["all" | StackState, string, number]> = [
    ["all", "All", dashboard.stacks.length],
    ["applied", "Applied", dashboard.stacks.filter((item) => item.state === "applied").length],
    ["stopped", "Stopped", dashboard.stacks.filter((item) => item.state === "stopped").length],
    ["removed", "Removed", dashboard.stacks.filter((item) => item.state === "removed").length],
  ];
  for (const [value, label, count] of counts) {
    const button = element("button", value === stackFilter ? "active" : "");
    button.type = "button";
    button.append(document.createTextNode(label), element("b", undefined, String(count)));
    button.addEventListener("click", () => {
      stackFilter = value;
      renderStacks();
    });
    tabs.append(button);
  }
  const summary = element("span", "table-summary", `${dashboard.stacks.length} total`);
  toolbar.append(tabs, summary);
  return toolbar;
}

function tableShell(): HTMLElement {
  return element("div", "table-shell");
}

function tableHead(labels: string[]): HTMLTableSectionElement {
  const head = element("thead");
  const row = element("tr");
  for (const label of labels) row.append(element("th", undefined, label));
  head.append(row);
  return head;
}

function stackRow(stack: StackStatus): HTMLTableRowElement {
  const row = element("tr");
  row.tabIndex = 0;
  row.addEventListener("click", () => showStack(stack));
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") showStack(stack);
  });
  const name = element("td");
  const identity = element("div", "primary-cell");
  identity.append(element("span", "stack-cube"), element("strong", undefined, stack.stack));
  name.append(identity);
  const state = element("td");
  state.append(statusBadge(stack.state));
  row.append(
    name,
    state,
    element("td", "numeric", String(stack.instance_count)),
    element("td", "numeric", String(stack.desired_replicas)),
    element("td", "numeric", String(stack.revision)),
    element("td", "digest-cell", shortDigest(stack.plan_sha256)),
  );
  const actions = element("td", "actions-cell");
  const menu = element("button", "row-menu", "•••");
  menu.type = "button";
  menu.setAttribute("aria-label", `Actions for ${stack.stack}`);
  menu.addEventListener("click", (event) => {
    event.stopPropagation();
    showStack(stack);
  });
  actions.append(menu);
  row.append(actions);
  return row;
}

function statusBadge(state: StackState): HTMLElement {
  const labels: Record<StackState, string> = {
    applied: "Applied",
    stopped: "Stopped",
    removed: "Removed",
  };
  const badge = element("span", `status-badge ${state}`);
  badge.append(element("i"), document.createTextNode(labels[state]));
  return badge;
}

function renderLibrary(): void {
  const normalized = query.toLowerCase();
  const packages = dashboard.packages.filter((entry) =>
    `${entry.name} ${entry.cartridge_id}`.toLowerCase().includes(normalized),
  );
  const shell = tableShell();
  const toolbar = element("div", "table-toolbar");
  toolbar.append(
    element("strong", "toolbar-title", "Installed packages"),
    element("span", "table-summary", `${packages.length} package${packages.length === 1 ? "" : "s"}`),
  );
  shell.append(toolbar);
  const table = element("table", "data-table package-table");
  table.append(tableHead(["Package", "Identifier", "Versions", "Latest", "Health"]));
  const body = element("tbody");
  for (const entry of packages) {
    const row = element("tr");
    const packageName = element("td");
    const primary = element("div", "primary-cell");
    primary.append(element("span", "package-cube", entry.name.slice(0, 1).toUpperCase()), element("strong", undefined, entry.name));
    packageName.append(primary);
    const health = element("td");
    health.append(statusBadge(entry.safe_mode ? "stopped" : "applied"));
    health.lastElementChild!.lastChild!.textContent = entry.safe_mode ? "Safe mode" : "Ready";
    row.append(
      packageName,
      element("td", "mono-cell", entry.cartridge_id),
      element("td", "numeric", String(entry.versions.length)),
      element("td", "mono-cell", entry.versions.at(-1) ?? "—"),
      health,
    );
    body.append(row);
  }
  table.append(body);
  shell.append(table);
  if (packages.length === 0) {
    shell.append(emptyState(
      dashboard.packages.length === 0 ? "No packages installed" : "No matching packages",
      dashboard.packages.length === 0
        ? "Package import is the next desktop milestone. Installed CLI packages can already be planned and run."
        : "Try a different search term.",
      "package",
    ));
  }
  content.replaceChildren(shell);
}

async function renderResources(): Promise<void> {
  const view = currentView;
  content.replaceChildren(loadingRow("Reading declared resources…"));
  try {
    const journals = await loadJournals();
    if (currentView !== view) return;
    const resources = journals.flatMap(({ stack, events }) => {
      const latest = events.at(-1)?.plan;
      return latest?.resources.map((resource) => ({ ...resource, stack })) ?? [];
    });
    const shell = tableShell();
    const toolbar = element("div", "table-toolbar");
    toolbar.append(element("strong", "toolbar-title", "Declared resources"), element("span", "table-summary", `${resources.length} total`));
    shell.append(toolbar);
    const table = element("table", "data-table");
    table.append(tableHead(["Name", "Stack", "Owner", "Type", "Quota", "Retention"]));
    const body = element("tbody");
    for (const resource of resources) {
      const row = element("tr");
      row.append(
        element("td", "strong-cell", resource.name),
        element("td", undefined, resource.stack),
        element("td", undefined, resource.owner),
        element("td", "capitalized", resource.kind),
        element("td", undefined, formatBytes(resource.quota_bytes)),
        element("td", "capitalized", resource.retention),
      );
      body.append(row);
    }
    table.append(body);
    shell.append(table);
    if (resources.length === 0) shell.append(emptyState("No resources", "Applied stacks have not declared persistent state or blob resources.", "resource"));
    content.replaceChildren(shell);
  } catch (error) {
    content.replaceChildren(emptyState("Could not read resources", String(error), "error"));
  }
}

async function renderActivity(): Promise<void> {
  const view = currentView;
  content.replaceChildren(loadingRow("Reading engine journal…"));
  try {
    const journals = await loadJournals();
    if (currentView !== view) return;
    const events = journals
      .flatMap(({ events }) => events)
      .sort((left, right) => right.created_at_ms - left.created_at_ms)
      .filter((event) => `${event.stack} ${event.kind}`.toLowerCase().includes(query.toLowerCase()))
      .slice(0, 250);
    const shell = tableShell();
    const toolbar = element("div", "table-toolbar");
    toolbar.append(element("strong", "toolbar-title", "Engine journal"), element("span", "table-summary", `${events.length} events`));
    shell.append(toolbar);
    const table = element("table", "data-table");
    table.append(tableHead(["Event", "Stack", "Revision", "Time", "Digest"]));
    const body = element("tbody");
    for (const event of events) {
      const row = element("tr");
      const kind = element("td");
      kind.append(eventBadge(event.kind));
      row.append(
        kind,
        element("td", "strong-cell", event.stack),
        element("td", "numeric", String(event.revision)),
        element("td", undefined, new Date(event.created_at_ms).toLocaleString()),
        element("td", "digest-cell", shortDigest(event.event_sha256)),
      );
      body.append(row);
    }
    table.append(body);
    shell.append(table);
    if (events.length === 0) shell.append(emptyState("No activity", "Engine events appear after the first stack apply.", "activity"));
    content.replaceChildren(shell);
  } catch (error) {
    content.replaceChildren(emptyState("Could not read activity", String(error), "error"));
  }
}

async function loadJournals(): Promise<Array<{ stack: string; events: EngineEvent[] }>> {
  return Promise.all(
    dashboard.stacks.map(async (stack) => ({
      stack: stack.stack,
      events: await invoke<EngineEvent[]>("stack_events", { stack: stack.stack }),
    })),
  );
}

function eventBadge(kind: EngineEvent["kind"]): HTMLElement {
  const value = element("span", `event-badge ${kind}`, kind);
  return value;
}

function loadingRow(message: string): HTMLElement {
  const row = element("div", "loading-row");
  row.append(element("i"), document.createTextNode(message));
  return row;
}

function emptyState(heading: string, detail: string, kind: string): HTMLElement {
  const value = element("div", "empty-state");
  const icon = element("div", `empty-icon ${kind}`);
  icon.textContent = kind === "error" ? "!" : "+";
  value.append(icon, element("strong", undefined, heading), element("p", undefined, detail));
  if (kind === "stack" && dashboard.stacks.length === 0) {
    const button = element("button", "button primary", "Create stack");
    button.type = "button";
    button.addEventListener("click", () => fileInput.click());
    value.append(button);
  }
  return value;
}

function switchView(view: View): void {
  if (view !== currentView) {
    query = "";
    search.value = "";
  }
  currentView = view;
  closeInspector();
  render();
}

async function loadStack(file: File): Promise<void> {
  if (file.size > MAX_STACK_BYTES) {
    showNotice("Stack manifest exceeds the 1 MiB limit.", "error");
    return;
  }
  try {
    const plan = await invoke<StackPlan>("plan_stack", { manifest: await file.text() });
    currentPlan = plan;
    renderPlan(plan, file.name);
  } catch (error) {
    currentPlan = null;
    showNotice(String(error), "error");
  }
}

function renderPlan(plan: StackPlan, source: string): void {
  const wrapper = element("div", "details-content plan-details");
  wrapper.append(detailsHeader("Review stack", plan.stack, closeInspector));

  const sourceRow = element("div", "review-source");
  sourceRow.append(element("span", undefined, "Manifest"), element("strong", undefined, source));
  wrapper.append(sourceRow);

  const policy = element("div", "policy-grid");
  policy.append(
    detailMetric("Security profile", plan.security.profile),
    detailMetric("Worker sandbox", plan.security.sandbox, plan.security.sandbox === "disabled"),
    detailMetric("Instances", String(plan.instances.length)),
    detailMetric("Resources", String(plan.resources.length)),
  );
  wrapper.append(policy);

  const digest = element("section", "details-section");
  digest.append(element("h3", undefined, "Exact plan digest"), element("code", "full-digest", plan.plan_sha256));
  wrapper.append(digest);

  const instances = element("section", "details-section");
  instances.append(element("h3", undefined, "Resolved instances"));
  for (const instance of plan.instances) instances.append(planInstance(instance));
  wrapper.append(instances);

  if (plan.warnings.length > 0) {
    const warnings = element("div", "warning-callout");
    warnings.append(element("strong", undefined, "Review required"));
    for (const warning of plan.warnings) warnings.append(element("p", undefined, warning));
    wrapper.append(warnings);
  }

  const footer = element("div", "details-footer");
  const cancel = element("button", "button secondary", "Cancel");
  cancel.type = "button";
  cancel.addEventListener("click", closeInspector);
  const apply = element("button", "button primary", "Apply stack");
  apply.type = "button";
  apply.addEventListener("click", () => void applyCurrentPlan());
  footer.append(cancel, apply);
  wrapper.append(footer);
  inspector.replaceChildren(wrapper);
  inspector.classList.add("open");
}

function detailsHeader(label: string, heading: string, close: () => void): HTMLElement {
  const header = element("header", "details-header");
  const copy = element("div");
  copy.append(element("span", undefined, label), element("h2", undefined, heading));
  const button = element("button", "close-button", "×");
  button.type = "button";
  button.setAttribute("aria-label", "Close details");
  button.addEventListener("click", close);
  header.append(copy, button);
  return header;
}

function detailMetric(label: string, value: string, warning = false): HTMLElement {
  const metric = element("div", warning ? "detail-metric warning" : "detail-metric");
  metric.append(element("span", undefined, label), element("strong", "capitalized", value));
  return metric;
}

function planInstance(instance: PlannedInstance): HTMLElement {
  const card = element("article", "instance-review");
  const head = element("div");
  const copy = element("div");
  copy.append(element("strong", undefined, instance.name), element("span", undefined, instance.cartridge_id));
  head.append(copy, element("code", undefined, instance.version));
  card.append(head, element("code", "package-digest", instance.package_sha256));
  card.append(capabilityRow("Allowed", instance.allowed, false));
  if (instance.denied.length > 0) card.append(capabilityRow("Denied", instance.denied, true));
  return card;
}

function capabilityRow(label: string, values: string[], denied: boolean): HTMLElement {
  const row = element("div", "capability-row");
  row.append(element("span", undefined, label));
  const list = element("div");
  for (const value of values) list.append(element("b", denied ? "denied" : "", value));
  if (values.length === 0) list.append(element("b", "muted", "None"));
  row.append(list);
  return row;
}

async function applyCurrentPlan(): Promise<void> {
  const plan = currentPlan;
  if (!plan || mutating) return;
  const insecure = plan.security.sandbox === "disabled";
  if (insecure) {
    const approved = await confirmAction(
      "Apply without worker sandboxing?",
      "This manifest explicitly disables native worker sandboxing. The setting will be recorded in the engine journal.",
      "Apply anyway",
    );
    if (!approved) return;
  }
  mutating = true;
  try {
    const report = await invoke<{ changed: boolean }>("apply_stack", {
      planSha256: plan.plan_sha256,
      allowInsecure: insecure,
    });
    currentPlan = null;
    closeInspector();
    showNotice(report.changed ? "Stack desired state updated." : "Stack already matches the reviewed plan.");
    await refresh();
  } catch (error) {
    showNotice(String(error), "error");
  } finally {
    mutating = false;
  }
}

function showStack(stack: StackStatus): void {
  const wrapper = element("div", "details-content");
  wrapper.append(detailsHeader("Stack details", stack.stack, closeInspector));
  const status = element("div", "details-status");
  status.append(statusBadge(stack.state), element("span", undefined, `Revision ${stack.revision}`));
  wrapper.append(status);
  const metrics = element("div", "policy-grid");
  metrics.append(
    detailMetric("Instances", String(stack.instance_count)),
    detailMetric("Desired replicas", String(stack.desired_replicas)),
  );
  wrapper.append(metrics);
  const identity = element("section", "details-section definition-list");
  identity.append(element("h3", undefined, "Identity"));
  identity.append(definition("Plan digest", stack.plan_sha256 ?? "Removed"), definition("Event digest", stack.event_sha256));
  wrapper.append(identity);
  const note = element("div", "neutral-callout");
  note.append(element("strong", undefined, "Desired state only"), element("p", undefined, "The local supervisor is not active, so applied does not mean a worker process is running."));
  wrapper.append(note);
  const footer = element("div", "details-footer");
  const stop = element("button", "button secondary", "Stop");
  stop.type = "button";
  stop.disabled = stack.state !== "applied";
  stop.addEventListener("click", () => void mutateStack("stop_stack", stack.stack));
  const remove = element("button", "button danger", "Remove");
  remove.type = "button";
  remove.disabled = stack.state === "removed";
  remove.addEventListener("click", () => void removeStack(stack.stack));
  footer.append(stop, remove);
  wrapper.append(footer);
  inspector.replaceChildren(wrapper);
  inspector.classList.add("open");
}

function definition(label: string, value: string): HTMLElement {
  const row = element("div");
  row.append(element("dt", undefined, label), element("dd", undefined, value));
  return row;
}

async function removeStack(stack: string): Promise<void> {
  const approved = await confirmAction(
    `Remove ${stack}?`,
    "The stack will be tombstoned. Its checksum-chained audit journal will be retained.",
    "Remove stack",
  );
  if (approved) await mutateStack("remove_stack", stack);
}

async function mutateStack(command: "stop_stack" | "remove_stack", stack: string): Promise<void> {
  if (mutating) return;
  mutating = true;
  try {
    await invoke(command, { stack });
    closeInspector();
    showNotice(command === "stop_stack" ? "Stack desired state stopped." : "Stack tombstoned.");
    await refresh();
  } catch (error) {
    showNotice(String(error), "error");
  } finally {
    mutating = false;
  }
}

function confirmAction(heading: string, copy: string, action: string): Promise<boolean> {
  required<HTMLElement>("confirm-title").textContent = heading;
  required<HTMLElement>("confirm-copy").textContent = copy;
  required<HTMLElement>("confirm-button").textContent = action;
  confirmDialog.showModal();
  return new Promise((resolve) => {
    confirmDialog.addEventListener("close", () => resolve(confirmDialog.returnValue === "confirm"), { once: true });
  });
}

function closeInspector(): void {
  inspector.classList.remove("open");
  inspector.replaceChildren(emptyState("No selection", "Select a stack or review a new manifest.", "details"));
}

document.querySelectorAll<HTMLButtonElement>(".nav-item").forEach((button) => {
  button.addEventListener("click", () => switchView(button.dataset.view as View));
});
required<HTMLButtonElement>("load-button").addEventListener("click", () => fileInput.click());
required<HTMLButtonElement>("refresh-button").addEventListener("click", () => void refresh());
required<HTMLButtonElement>("page-refresh").addEventListener("click", () => void refresh());
required<HTMLButtonElement>("dismiss-banner").addEventListener("click", () => {
  bannerDismissed = true;
  previewBanner.classList.add("hidden");
});
fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file) void loadStack(file);
  fileInput.value = "";
});
search.addEventListener("input", () => {
  query = search.value.trim();
  render();
});
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
    event.preventDefault();
    search.focus();
  }
  if (event.key === "Escape" && inspector.classList.contains("open")) closeInspector();
});

window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (settings.theme === "system") applySettings();
});

async function initialize(): Promise<void> {
  try {
    settings = await invoke<AppSettings>("get_settings");
  } catch (error) {
    showNotice(String(error), "error");
  }
  applySettings();
  await refresh();
}

void initialize();
