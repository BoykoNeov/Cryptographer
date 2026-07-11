/**
 * View-source-strokes store. The session-local half of the per-source
 * arrow-*style* feature (Part A of `docs/plans/toasty-zooming-harp.md`).
 *
 * The split mirrors `view-source-colors.ts`, but with TWO deliberate
 * divergences:
 *
 *   - **Master toggle — PER-SPEC, session-persisted, here.** Unlike colours,
 *     whose master toggle is one GLOBAL bool, the stroke channel's enable
 *     state is keyed by `spec.id`. Its shipped default is now UNIVERSAL —
 *     **ON for every spec** (user-decided 2026-07-11: "the same [on by default]
 *     for Blowfish and all future ciphers and hashes"). Before 2026-07-11 the
 *     default was OFF everywhere EXCEPT SHA-256 (2026-07-09) and RSA
 *     (2026-07-10); the user then extended styling-on to every cipher and hash.
 *     The per-spec keying is retained (not collapsed to a global bool) so an
 *     explicit per-spec OFF still persists independently. The enable default
 *     and the threshold default (below) stay in lock-step (both universal).
 *     The persisted map stores only the entries that DIVERGE from the per-spec
 *     default (an explicit user flip); an entry equal to the default is
 *     dropped, so "reset" is simply "forget the override" and the shipped
 *     default returns. This is a *viewer* preference, so it NEVER touches
 *     `LayoutSpec` — flipping it off doesn't discard the user's saved manual
 *     overrides.
 *
 *   - **Manual overrides — on `LayoutSpec`, NOT here** (the divergence from
 *     colours, whose overrides are viewer-local in `view-source-colors.ts`).
 *     The user chose that arrow *styles* travel WITH the document, so the
 *     per-source style-name map is `LayoutSpec.strokeStyles` (added in
 *     chunk A2), written via `layout.ts::setSourceStroke`, and read in
 *     `GraphView` off `activeLayout().strokeStyles`. This store owns none of
 *     that — only the on/off switch.
 *
 *   - **Fanout threshold — OWNED here, INDEPENDENT of colours (2026-07-10).**
 *     Auto-assignment walks `multiFanoutSources(graph, threshold)` with the
 *     stroke channel's OWN threshold (`useStrokeThreshold`), a separate
 *     per-spec counter from the colour channel's. Until 2026-07-10 the two
 *     channels shared `view-source-colors`'s single knob so a source's colour
 *     index and dash index stayed aligned (source S = `color[i]` AND
 *     `stroke[i]`); the user split them into two counters so the cutoffs move
 *     independently. The trade-off is deliberate: with different thresholds a
 *     source may be coloured but un-dashed (or vice versa), and the (colour,
 *     dash) pairing is no longer index-locked. Same per-spec-default +
 *     drop-on-match discipline as the enable map — now UNIVERSAL: every spec
 *     defaults to 1 (style every source) as of 2026-07-11.
 */

import { createSignal } from "solid-js";

const ENABLED_STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";

/**
 * Per-spec shipped default — now UNIVERSAL: arrow styling ships **ON for every
 * spec** (user-decided 2026-07-11 — "the same [on by default] for Blowfish and
 * all future ciphers and hashes"). Before 2026-07-11 only SHA-256 + RSA shipped
 * ON and every other built-in OFF; that prefix distinction is gone. Kept as a
 * per-spec function (rather than a bare `true`) so callers stay stable and a
 * future per-family divergence has a single seam. Pure — the single source of
 * truth for "what does this spec do before the user touches the toggle," shared
 * by the reactive read and the drop-to-default persistence discipline.
 */
export const defaultStrokeStylingFor = (_specId: string): boolean => true;

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

// ─── Auto-styling fanout threshold (per-spec, 2026-07-10) ────────────────
//
// The stroke channel's OWN fanout cutoff, INDEPENDENT of the colour channel's
// (`view-source-colors.ts`). See the file header ("Fanout threshold — OWNED
// here") for why the two were split. A source is auto-STYLED when its fanout
// is `>=` this threshold. Same per-spec-default + drop-on-match discipline as
// the enable map above, now UNIVERSAL: every spec defaults to 1 (style EVERY
// source) as of 2026-07-11. Viewer-local, never on `LayoutSpec`.

const STROKE_THRESHOLD_STORAGE_KEY = "cryptographer.viewSourceStrokeThreshold";

export const DEFAULT_STROKE_THRESHOLD = 1;
export const STROKE_THRESHOLD_MIN = 0;
export const STROKE_THRESHOLD_MAX = 99;

/**
 * Shipped per-spec default stroke threshold — now UNIVERSAL:
 * `DEFAULT_STROKE_THRESHOLD` (1) for every spec, so every source is auto-styled
 * on first open (in lock-step with the enable default above). Kept as a
 * per-spec function so callers stay stable and a future per-family divergence
 * has a single seam.
 */
export const defaultStrokeThresholdFor = (_specId: string): number => DEFAULT_STROKE_THRESHOLD;

/** Clamp to [MIN, MAX] and round; non-finite falls back to `fallback`. */
const clampStrokeThreshold = (value: number, fallback: number): number => {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(STROKE_THRESHOLD_MIN, Math.min(STROKE_THRESHOLD_MAX, Math.round(value)));
};

/**
 * Persisted shape: `{ [specId]: number }`, holding ONLY specs whose threshold
 * diverges from `defaultStrokeThresholdFor` (drop-on-match). Defensive against
 * missing localStorage and against any corrupted / non-object blob.
 */
type StrokeThresholdMap = { readonly [specId: string]: number };

const loadInitialStrokeThresholds = (): StrokeThresholdMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(STROKE_THRESHOLD_STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: { [specId: string]: number } = {};
    for (const [specId, val] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof val === "number" && Number.isFinite(val)) {
        out[specId] = clampStrokeThreshold(val, defaultStrokeThresholdFor(specId));
      }
    }
    return out;
  } catch {
    return {};
  }
};

const [strokeThresholdMap, setStrokeThresholdMapSignal] = createSignal<StrokeThresholdMap>(
  loadInitialStrokeThresholds(),
);

const persistStrokeThresholds = (map: StrokeThresholdMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STROKE_THRESHOLD_STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/**
 * Reactive read of one spec's effective stroke threshold: the user's override
 * if present, else the per-spec shipped default. Use from JSX with
 * `useStrokeThreshold(() => spec().id)`.
 */
export const useStrokeThreshold = (specId: () => string): (() => number) => {
  return () => {
    const id = specId();
    return strokeThresholdMap()[id] ?? defaultStrokeThresholdFor(id);
  };
};

/**
 * Set one spec's auto-styling fanout threshold. Out-of-range clamps to
 * [MIN, MAX]; non-finite falls back to the spec's default. Drop-on-match when
 * the resolved value equals the spec's shipped default.
 */
export const setStrokeThreshold = (specId: string, value: number): void => {
  const next = clampStrokeThreshold(value, defaultStrokeThresholdFor(specId));
  const current = strokeThresholdMap();
  const nextMap = { ...current };
  if (next === defaultStrokeThresholdFor(specId)) {
    delete (nextMap as { [specId: string]: number })[specId];
  } else {
    nextMap[specId] = next;
  }
  setStrokeThresholdMapSignal(nextMap);
  persistStrokeThresholds(nextMap);
};

// ─── Test hooks ───────────────────────────────────────────────────────────

/**
 * Hard reset for tests. Production code never calls this. Clears the
 * in-memory maps + the persisted blobs so each test starts from the shipped
 * per-spec defaults. NOTE (2026-07-11): every spec now defaults ON at threshold
 * 1 — a render test that wants the UN-styled fall-through must explicitly
 * `setSourceStrokeStylingEnabled(specId, false)` after this reset (the inverse
 * of the pre-2026-07-11 gotcha, where non-SHA specs defaulted OFF).
 */
export const __resetSourceStrokesForTests = (): void => {
  setEnabledMapSignal({});
  setStrokeThresholdMapSignal({});
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(ENABLED_STORAGE_KEY);
      localStorage.removeItem(STROKE_THRESHOLD_STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
