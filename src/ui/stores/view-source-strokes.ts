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
 *     built-in*: OFF everywhere EXCEPT SHA-256 (user-decided 2026-07-09) and
 *     RSA (user-decided 2026-07-10), which both ship ON. SHA-256 has more
 *     distinct sources than the 8-colour Okabe-Ito palette, so colours
 *     *repeat* there and the orthogonal dash channel earns its keep from first
 *     open; RSA joins it so its bigint dataflow reads fully styled by default.
 *     The remaining ciphers (AES/DES/Speck) have few enough sources that
 *     colour alone suffices, so a dash-on there would only add noise. The
 *     enable default and the threshold default (below) are driven by the SAME
 *     prefix set so the two stay in lock-step. The persisted map
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
 *     drop-on-match discipline as the enable map: SHA-256 defaults to 1 (style
 *     every source), every other built-in to 3.
 */

import { createSignal } from "solid-js";

const ENABLED_STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";

/**
 * The spec families that ship with arrow styling ON: SHA-256 and RSA (see
 * file header). Matched by prefix so a future step-type `@N` bump
 * (`sha-256@2`) keeps the default without a code change here, and `"rsa"`
 * covers BOTH `rsa@1` (encrypt) and `rsa-decrypt@1`. Every other built-in
 * ships OFF. This same set also drives `defaultStrokeThresholdFor` below so
 * the enable and threshold defaults stay in lock-step.
 */
const STROKE_ON_BY_DEFAULT_PREFIXES = ["sha-256", "rsa"] as const;

/**
 * Per-spec shipped default: ON iff the spec is one of the styled families
 * above (see file header). Pure — the single source of truth for "what does
 * this spec do before the user touches the toggle," shared by the reactive
 * read and the drop-to-default persistence discipline.
 */
export const defaultStrokeStylingFor = (specId: string): boolean =>
  STROKE_ON_BY_DEFAULT_PREFIXES.some((p) => specId.startsWith(p));

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
// the enable map above: SHA-256 and RSA default to 1 (style EVERY source —
// SHA-256 saturates the 8-colour palette so the orthogonal dash channel earns
// its keep on first open, RSA ships fully styled by user request), every other
// built-in to 3 (only the biggest fan-outs). Viewer-local, never on
// `LayoutSpec`.

const STROKE_THRESHOLD_STORAGE_KEY = "cryptographer.viewSourceStrokeThreshold";

export const DEFAULT_STROKE_THRESHOLD = 3;
export const STROKE_THRESHOLD_MIN = 0;
export const STROKE_THRESHOLD_MAX = 99;

/**
 * Shipped per-spec default stroke threshold: 1 for the styled families
 * (SHA-256, RSA — style every source), else `DEFAULT_STROKE_THRESHOLD` (3).
 * Reuses the same prefix set as the enable default so the two ship in
 * lock-step.
 */
export const defaultStrokeThresholdFor = (specId: string): number =>
  STROKE_ON_BY_DEFAULT_PREFIXES.some((p) => specId.startsWith(p)) ? 1 : DEFAULT_STROKE_THRESHOLD;

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
 * per-spec defaults. NOTE: SHA-256 defaults ON (threshold 1), every other spec
 * OFF (threshold 3) — a render test on a NON-SHA-256 spec that expects styled
 * edges MUST call `setSourceStrokeStylingEnabled(specId, true)` after this
 * reset, otherwise it asserts on the un-styled fall-through and passes for the
 * wrong reason (the `jsdom_replication_off_default` gotcha class).
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
