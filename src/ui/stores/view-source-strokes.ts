/**
 * View-source-strokes store. The session-local half of the per-source
 * arrow-*style* feature (Part A of `docs/plans/toasty-zooming-harp.md`).
 *
 * The split mirrors `view-source-colors.ts`, but with ONE deliberate
 * divergence:
 *
 *   - **Master toggle — session-local, here.** One bool, "style arrows by
 *     source" on/off, persisted to localStorage as a plain string exactly
 *     like `view-source-colors`'s `coloringEnabled`. This is a *viewer*
 *     preference ("do I want this channel right now"), not a document fact,
 *     so it lives here and NEVER touches `LayoutSpec` — turning the
 *     auto-assignment off doesn't discard the user's saved manual overrides.
 *
 *   - **Manual overrides — on `LayoutSpec`, NOT here** (the divergence from
 *     colours, whose overrides are viewer-local in `view-source-colors.ts`).
 *     The user chose that arrow *styles* travel WITH the document, so the
 *     per-source style-name map is `LayoutSpec.strokeStyles` (added in
 *     chunk A2), written via `layout.ts::setSourceStroke`, and read in
 *     `GraphView` off `activeLayout().strokeStyles`. This store owns none of
 *     that — only the on/off switch.
 *
 *   - **Fanout threshold — reused, NOT owned here.** Auto-assignment uses
 *     the SAME `useColorThreshold()` knob the colour channel uses. Both
 *     `assignSourceColors` and `assignSourceStrokes` walk the identical
 *     `multiFanoutSources(graph, threshold)` list, so a shared threshold
 *     keeps the colour index and the stroke index aligned: source S is
 *     `color[i]` AND `stroke[i]`, a stable matched (colour, dash) pair. A
 *     separate stroke threshold would return an interleaved superset and
 *     desync the pair. If strokes ever need to extend to more sources than
 *     colours (the catalogue reaches 24, the palette runs out at 8), split
 *     the threshold then — do not pre-build it.
 *
 * **Default OFF** (unlike colours, which ship ON). A3a is the plumbing
 * chunk and ships no picker, so the toggle is only reachable from tests
 * until the A3b picker lands — OFF means every existing visual/smoke
 * baseline renders byte-identically. The *shipped product* default is a
 * separate call to confirm with the user at A3b (the colours ON default
 * came from an explicit choice on 2026-05-19).
 */

import { createSignal } from "solid-js";

const ENABLED_STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";

/**
 * Hydrate the master toggle. Defensive against missing localStorage
 * (private mode, disabled cookies, server-rendered context). Default is
 * **false** — the feature ships OFF (see file header). The only way a user
 * lands on `true` is by having previously enabled it.
 */
const loadInitialEnabled = (): boolean => {
  try {
    if (typeof localStorage === "undefined") return false;
    // Missing entry → default OFF. Explicit "true" string → ON. Anything
    // else (corrupted / partial write) → default.
    return localStorage.getItem(ENABLED_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
};

const [strokeStylingEnabled, setStrokeStylingEnabledSignal] = createSignal<boolean>(
  loadInitialEnabled(),
);

export const useSourceStrokeStylingEnabled = () => strokeStylingEnabled;

const persistEnabled = (enabled: boolean): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(ENABLED_STORAGE_KEY, enabled ? "true" : "false");
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

export const setSourceStrokeStylingEnabled = (enabled: boolean): void => {
  setStrokeStylingEnabledSignal(enabled);
  persistEnabled(enabled);
};

export const toggleSourceStrokeStylingEnabled = (): void => {
  setStrokeStylingEnabledSignal((prev) => {
    const next = !prev;
    persistEnabled(next);
    return next;
  });
};

// ─── Test hooks ───────────────────────────────────────────────────────────

/**
 * Hard reset for tests. Production code never calls this. Clears the
 * in-memory signal + the persisted blob so each test starts from a clean
 * baseline. NOTE: the default is OFF, so a render test that expects styled
 * edges MUST call `setSourceStrokeStylingEnabled(true)` after this reset —
 * otherwise it asserts on the un-styled fall-through and passes for the
 * wrong reason (the `jsdom_replication_off_default` gotcha class).
 */
export const __resetSourceStrokesForTests = (): void => {
  setStrokeStylingEnabledSignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(ENABLED_STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
