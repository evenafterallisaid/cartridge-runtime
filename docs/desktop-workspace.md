# Desktop workspace

The desktop keeps stack management in a compact table, with a workspace summary above it. Applied stacks and replica counts describe desired state, not observed health. Supervisor capacity comes from the authenticated daemon.

- Pin stacks with the star to keep them first, or use Pinned to show only favorites. Pins are device-local preferences, capped at 256 entries.
- Sort by name, desired replica count, or revision number. Revisions are local to each stack, not global creation timestamps.
- Stop an applied stack from its row after confirmation. The existing authenticated native command performs the mutation; an offline engine disables the control.
- Pause live refresh while inspecting a changing workspace. Automatic refresh also pauses for modal dialogs and focused table controls.
- Open Quick actions with Ctrl/Command+K. Search navigation, packages, stacks, import actions, refresh, or theme. Use arrows and Enter to select, Escape to dismiss.

Navigation uses restrained translucent surfaces. Raised controls use highlights and short press transitions; tables stay opaque. Both themes retain keyboard focus indicators, and reduced-motion and reduced-transparency system preferences suppress their corresponding effects.

## Development preview

From `apps/cartridge-desktop`, run `npm run dev` and open `http://127.0.0.1:5173/?preview=1`. The DEMO label identifies sample data. Supported preview actions mutate only that page's fixture data. This branch is gated on Vite development mode and the absence of Tauri; the production build omits the fixture module entirely.

Validation for this revision: TypeScript/Vite production build, dependency audit, light/dark visual inspection, pin/filter/sort checks, confirmed and cancelled sample stop, paused refresh, and keyboard command-palette navigation. Native engine permissions and resource policy are unchanged.
