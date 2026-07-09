/**
 * View-source-strokes store. The session-local half of the per-source
 * arrow-*style* feature (Part A of `docs/plans/toasty-zooming-harp.md`).
 *
 * The split mirrors `view-source-colors.ts`, but with TWO deliberate
 * divergences:
 *
 *   - **Master toggle — PER-SPEC, session-persisted, here.** Unlike colours,
 *     whose master toggle is one GLOBAL bool, the stroke channel's enable
 *     state is keyed by `spec.id`, because its *shipped default differs per
 *     built-in*: OFF everywhere EXCEPT SHA-256, which ships ON (user-decided
 *     2026-07-09). SHA-256 is the one shipped spec with more distinct sources
 *     than the 8-colour Okabe-Ito palette, so colours *repeat* there and the
 *     orthogonal dash channel earns its keep from first open; every other
 *     cipher (AES/DES/Speck/RSA) has few enough sources that colour alone
 *     suffices, so a global dash-on would only add noise. The persisted map
 *     stores only the entries that DIVERGE from the per-spec default (an
 *     explicit user flip); an entry equal to the default is dropped, so
 *     "reset" is simply "forget the override" and the shipped default returns.
 *     This is a *viewer* preference, so it NEVER touches `LayoutSpec` —
 *     flipping it off doesn't discard the user's saved manual overrides.
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
 */

import { createSignal } from "solid-js";

const ENABLED_STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";

/**
 * The one spec that ships with arrow styling ON. Matched by prefix so a
 * future step-type `@N` bump (`sha-256@2`) keeps the default without a code
 * change here. Every other built-in ships OFF.
 */
const STROKE_ON_BY_DEFAULT_PREFIX = "sha-256";

/**
 * Per-spec shipped default: ON iff the spec is SHA-256 (see file header).
 * Pure — the single source of truth for "what does this spec do before the
 * user touches the toggle," shared by the reactive read and the drop-to-
 * default persistence discipline.
 */
export const defaultStrokeStylingFor = (specId: string): boolean =>
  specId.startsWith(STROKE_ON_BY_DEFAULT_PREFIX);

/**
 * Persisted shape: `{ [specId]: boolean }`, holding ONLY the specs whose
 * enable state diverges from `defaultStrokeStylingFor`. A spec absent from
 * the map renders at its shipped default. Keeping the map minimal (drop-on-
 * match) means clearing an override is byte-cheap and the default can evolve
 * without stale entries pinning old behaviour.
 */
type StrokeEnabledMap = { readonly [specId: string]: boolean };

/**
 * Hydrate the per-spec override map. Defensive against missing localStorage
 * (private mode, disabled cookies, server context) AND against the LEGACY
 * A3a format — that chunk stored a single `"true"`/`"false"` string under
 * this same key. `JSON.parse("true")` yields a boolean, not an object, so
 * the shape guard below discards it and we start from the (empty → all
 * shipped defaults) baseline. No shipped user has a stroke override yet
 * (A3a shipped no picker), so nothing is lost.
 */
const loadInitialEnabledMap = (): StrokeEnabledMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(ENABLED_STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: { [specId: string]: boolean } = {};
    for (const [specId, val] of Object.entries(parsed as Record<string, unknown>)) {
      // Keep only real booleans; ignore anything corrupted / half-written.
      if (typeof val === "boolean") out[specId] = val;
    }
    return out;
  } catch {
    return {};
  }
};

const [enabledMap, setEnabledMapSignal] = createSignal<StrokeEnabledMap>(loadInitialEnabledMap());

const persistEnabledMap = (map: StrokeEnabledMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(ENABLED_STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/**
 * Reactive read of one spec's effective enable state: the user's explicit
 * override if present, else the shipped per-spec default. Use from JSX with
 * `useSourceStrokeStylingEnabled(() => spec().id)` so it recomputes on both
 * the map change AND the active-spec change.
 */
export const useSourceStrokeStylingEnabled = (specId: () => string): (() => boolean) => {
  return () => {
    const id = specId();
    return enabledMap()[id] ?? defaultStrokeStylingFor(id);
  };
};

/**
 * Set one spec's enable state. When the requested value equals the spec's
 * shipped default the entry is DROPPED (drop-on-match, mirroring the colour
 * overrides' drop-empty discipline) so the persisted map stays minimal and a
 * later default change isn't shadowed by a stale entry.
 */
export const setSourceStrokeStylingEnabled = (specId: string, enabled: boolean): void => {
  const current = enabledMap();
  const next = { ...current };
  if (enabled === defaultStrokeStylingFor(specId)) {
    delete (next as { [specId: string]: boolean })[specId];
  } else {
    next[specId] = enabled;
  }
  setEnabledMapSignal(next);
  persistEnabledMap(next);
};

/** Flip one spec's enable state relative to its CURRENT effective value. */
export const toggleSourceStrokeStylingEnabled = (specId: string): void => {
  const currentlyEnabled = enabledMap()[specId] ?? defaultStrokeStylingFor(specId);
  setSourceStrokeStylingEnabled(specId, !currentlyEnabled);
};

// ─── Test hooks ───────────────────────────────────────────────────────────

/**
 * Hard reset for tests. Production code never calls this. Clears the
 * in-memory map + the persisted blob so each test starts from the shipped
 * per-spec defaults. NOTE: SHA-256 defaults ON, every other spec OFF — a
 * render test on a NON-SHA-256 spec that expects styled edges MUST call
 * `setSourceStrokeStylingEnabled(specId, true)` after this reset, otherwise
 * it asserts on the un-styled fall-through and passes for the wrong reason
 * (the `jsdom_replication_off_default` gotcha class).
 */
export const __resetSourceStrokesForTests = (): void => {
  setEnabledMapSignal({});
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(ENABLED_STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
