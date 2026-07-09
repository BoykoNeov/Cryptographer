/**
 * Source-stroke coding: assign a distinct stroke *style* to every canonical
 * source that fans out to ≥ 2 consumers, as a second disambiguation channel
 * alongside the per-source *colour* (`source-colors.ts`). Where colour lets
 * the eye group "all these arrows came from THIS source," the stroke style is
 * an orthogonal channel that keeps sources tellable-apart even when their
 * colours collide — which they do on dense specs: SHA-256 has far more
 * distinct sources than the 8-entry Okabe-Ito palette, so colours *repeat*.
 * The style channel also helps colour-blind readers.
 *
 * Pure module — no Solid signals, no DOM. Mirrors `source-colors.ts`:
 * the store owns the session master toggle + manual overrides, this file
 * owns the deterministic auto-assignment + the style catalogue. The
 * canonical-source resolution (`resolveCanonicalSource`) and the
 * multi-fanout selection (`multiFanoutSources`) are REUSED from
 * `source-colors.ts` — they are identical logic and must not drift.
 *
 * Design (see `docs/plans/toasty-zooming-harp.md` "Part A"):
 *
 *   - **Styles TRAVEL with the document** (the divergence from colours,
 *     which are deliberately viewer-local). The persisted/consumed value is
 *     a single opaque **name string**, stored on `LayoutSpec.strokeStyles`
 *     (wired in the persistence chunk). This module is the ONE place that
 *     expands a name into its four-channel bundle, so the schema surface
 *     stays a plain `{ [sourceId]: string }` map and the picker is one
 *     `<select>`.
 *
 *   - **Multi-channel composite.** A pure `stroke-dasharray` catalogue tops
 *     out around 6–8 reliably-distinct patterns in a thicket of thin
 *     overlapping lines. So a style is a composite of four SVG-native
 *     channels — `stroke-dasharray`, `stroke-linecap` (round dots vs square
 *     ticks), a weight *multiplier* (`widthMul`, applied ON TOP of the
 *     density/emphasis width — never overwriting it), and a
 *     `stroke-dashoffset` phase shift. Individually each channel is weak
 *     past a point, but their product space stays separable much longer.
 *
 *   - **Tiered extension, NOT modulo cycling.** Eight base patterns × three
 *     tiers (plain / heavy / phase) = 24 concrete enumerated entries. Auto-
 *     assign walks them by canonical-source index, so the cleanest pure-dash
 *     entries get used first and the compound weight/phase entries only
 *     appear once a spec has many sources. Cycling within the first 24 (e.g.
 *     `CATALOGUE[i % 8]`) would repeat a style after 8 sources and silently
 *     defeat the whole multi-channel rationale — SHA-256, the spec this
 *     feature exists for, has more sources than that.
 *
 *   - **Index 0 = `solid` baseline** (user-confirmed). Unlike
 *     `colorForSourceIndex(0)` which returns a real colour (orange),
 *     `strokeForSourceIndex(0)` returns the unstyled `solid` entry: styles
 *     mark the *extra* sources, so a single-source graph stays clean.
 *
 *   - **Deterministic alphabetical assignment** — same as colours, so
 *     screenshots stay stable without per-test baselining.
 */

import type { CipherGraph, GraphEdge } from "./graph";
import { multiFanoutSources, resolveCanonicalSource } from "./source-colors";

// Re-export the shared canonical-source resolver so consumers can import
// stroke + colour resolution from one module without reaching into
// `source-colors.ts` for the shared helper. Same function, no drift.
export { resolveCanonicalSource } from "./source-colors";

/**
 * A fully-resolved stroke style: the four orthogonal channels a rendered
 * `<path>` applies. `dasharray === null` + `widthMul === 1` +
 * `dashoffset` absent is the `solid` baseline (all four channels omitted →
 * byte-identical to today's un-styled edge).
 */
export type StrokeStyle = {
  /** Stable name — the value persisted on `LayoutSpec.strokeStyles`. */
  readonly name: string;
  /** SVG `stroke-dasharray`, or `null` for a continuous line. */
  readonly dasharray: string | null;
  /** SVG `stroke-linecap`: `round` turns a `0 N` pattern into round dots. */
  readonly linecap: "butt" | "round";
  /**
   * Weight *multiplier* applied on top of the base computed stroke width.
   * MUST multiply (not overwrite) the density/emphasis width so those still
   * win their part — enforced at the render site.
   */
  readonly widthMul: number;
  /** SVG `stroke-dashoffset` phase shift; absent = no phase. */
  readonly dashoffset?: number;
};

/**
 * The eight base dash patterns (tier 0). Ordered cleanest-first: the earliest
 * entries are the most reliably tellable-apart at canvas scale, so low source
 * indices get them. `solid` (index 0) is the unstyled baseline.
 *
 * Patterns echo the existing dash usage in `app.css`
 * (`.graph-edge-feedback { stroke-dasharray: 4 3 }`) so they scale with
 * density the same way.
 */
const BASE_STROKE_PATTERNS: readonly {
  readonly name: string;
  readonly dasharray: string | null;
  readonly linecap: "butt" | "round";
}[] = [
  { name: "solid", dasharray: null, linecap: "butt" },
  { name: "round-dot", dasharray: "0 5", linecap: "round" },
  { name: "short-dash", dasharray: "4 3", linecap: "butt" },
  { name: "long-dash", dasharray: "10 4", linecap: "butt" },
  { name: "dash-dot", dasharray: "8 3 1 3", linecap: "butt" },
  { name: "sparse-dot", dasharray: "0 8", linecap: "round" },
  { name: "dash-dot-dot", dasharray: "8 3 1 3 1 3", linecap: "butt" },
  { name: "long-short", dasharray: "10 4 4 4", linecap: "butt" },
];

/** Number of base patterns per tier — the tier boundary for `strokeForSourceIndex`. */
export const STROKE_TIER_SIZE = BASE_STROKE_PATTERNS.length;

/** Weight multiplier applied to the "heavy" tier (indices 8..15). */
const HEAVY_WIDTH_MUL = 1.75;

/**
 * Half the period of a `stroke-dasharray` pattern (sum of its lengths ÷ 2),
 * used as the `dashoffset` for the "phase" tier so two otherwise-identical
 * patterns interleave instead of aligning. Returns `undefined` for a `null`
 * (solid) dasharray — a phase shift on a continuous line is a no-op, so the
 * phase-tier `solid-phase` entry carries no offset and reads like `solid`
 * (acceptable graceful degradation at the 17th source).
 */
const halfPeriod = (dasharray: string | null): number | undefined => {
  if (dasharray === null) return undefined;
  const sum = dasharray
    .split(/\s+/)
    .map(Number)
    .reduce((a, b) => a + b, 0);
  return sum / 2;
};

/**
 * Build the ordered composite catalogue: base patterns (tier 0), then the
 * same patterns re-walked with `widthMul` 1.75 (tier 1, `*-heavy`), then
 * re-walked with a half-period `dashoffset` (tier 2, `*-phase`). 24 concrete
 * entries — enumerated, not modulo-cycled, so `strokeStyleByName` is a plain
 * lookup with no suffix parsing.
 */
const buildCatalogue = (): readonly StrokeStyle[] => {
  const plain: StrokeStyle[] = BASE_STROKE_PATTERNS.map((p) => ({
    name: p.name,
    dasharray: p.dasharray,
    linecap: p.linecap,
    widthMul: 1,
  }));
  const heavy: StrokeStyle[] = BASE_STROKE_PATTERNS.map((p) => ({
    name: `${p.name}-heavy`,
    dasharray: p.dasharray,
    linecap: p.linecap,
    widthMul: HEAVY_WIDTH_MUL,
  }));
  const phase: StrokeStyle[] = BASE_STROKE_PATTERNS.map((p) => {
    const off = halfPeriod(p.dasharray);
    // `exactOptionalPropertyTypes`: only include `dashoffset` when defined.
    return off === undefined
      ? { name: `${p.name}-phase`, dasharray: p.dasharray, linecap: p.linecap, widthMul: 1 }
      : {
          name: `${p.name}-phase`,
          dasharray: p.dasharray,
          linecap: p.linecap,
          widthMul: 1,
          dashoffset: off,
        };
  });
  return [...plain, ...heavy, ...phase];
};

/**
 * The full ordered catalogue of composite stroke styles (24 entries). The
 * single source of truth shared by auto-assignment and the picker.
 */
export const STROKE_STYLE_CATALOGUE: readonly StrokeStyle[] = buildCatalogue();

/** The unstyled baseline — index 0, and the fallback for unknown names. */
export const SOLID_STROKE: StrokeStyle = STROKE_STYLE_CATALOGUE[0] ?? {
  name: "solid",
  dasharray: null,
  linecap: "butt",
  widthMul: 1,
};

// Name → bundle lookup, built once from the catalogue.
const STYLE_BY_NAME: ReadonlyMap<string, StrokeStyle> = new Map(
  STROKE_STYLE_CATALOGUE.map((s) => [s.name, s]),
);

/**
 * Expand a persisted style *name* into its four-channel bundle. Unknown or
 * legacy names fall back to `solid` (forward-compat: a document written by a
 * future, larger catalogue opens on an older build without hard-failing — it
 * just renders the unrecognised sources unstyled). Never returns undefined.
 */
export const strokeStyleByName = (name: string): StrokeStyle =>
  STYLE_BY_NAME.get(name) ?? SOLID_STROKE;

/**
 * Map a 0-based source index to its assigned stroke style. Index 0 →
 * `solid` (baseline). Indices 1..23 walk the catalogue tail (compound
 * weight/phase entries appear only once the pure-dash tiers are exhausted).
 * Past the catalogue the styles cycle (`index % 24`) — acceptable graceful
 * degradation at 24+ sources, where the paired per-source *colour* (which
 * keeps extending via golden-angle) still separates the collision.
 */
export const strokeForSourceIndex = (index: number): StrokeStyle => {
  const entry = STROKE_STYLE_CATALOGUE[index % STROKE_STYLE_CATALOGUE.length];
  return entry ?? SOLID_STROKE;
};

/**
 * Build the auto-stroke map for one graph: canonical source id → style
 * *name*. Deterministic on graph structure (+ `threshold`), mirroring
 * `assignSourceColors` — sources sorted alphabetically, `multiFanoutSources`
 * (reused) selects the fanout ≥ `threshold` set, `strokeForSourceIndex`
 * assigns by position. The alphabetically-first source gets `solid`.
 *
 * The returned map covers sources with fanout ≥ `threshold` (default 2);
 * callers fall through to the un-styled path for any edge whose canonical
 * source isn't in the map.
 */
export const assignSourceStrokes = (
  graph: CipherGraph,
  threshold = 2,
): ReadonlyMap<string, string> => {
  const sources = multiFanoutSources(graph, threshold);
  const map = new Map<string, string>();
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    // `noUncheckedIndexedAccess` makes this `string | undefined` even though
    // `i < sources.length` bounds the access. Guard explicitly.
    if (src === undefined) continue;
    map.set(src, strokeForSourceIndex(i).name);
  }
  return map;
};

/**
 * Resolve the final stroke-style *name* for one edge given the precomputed
 * auto-stroke map + any manual overrides. Returns `undefined` for edges that
 * should NOT be styled (endpoint-pill sources, single-fanout sources absent
 * from both maps) so the caller can fall through to the un-styled path.
 * Manual overrides win over the auto map (mirrors `colorForEdge`).
 */
export const strokeForEdge = (
  edge: GraphEdge,
  graph: CipherGraph,
  autoStrokes: ReadonlyMap<string, string>,
  manualOverrides: ReadonlyMap<string, string>,
): string | undefined => {
  const canonical = resolveCanonicalSource(edge, graph);
  if (canonical === undefined) return undefined;
  return manualOverrides.get(canonical) ?? autoStrokes.get(canonical);
};
