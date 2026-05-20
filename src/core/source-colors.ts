/**
 * Source-color coding: assign a distinct color to every canonical source
 * that fans out to ≥ 2 consumers. The renderer paints those colors onto
 * the matching edges (and their start-dots + bundle `×N` pills) so the eye
 * can track "all these arrows originated from THIS source" at a glance
 * without tracing each line back to its origin.
 *
 * Pure module — no Solid signals, no DOM. The `view-source-colors` store
 * owns the master toggle and manual overrides; this file owns the
 * deterministic auto-assignment + canonical-source resolution.
 *
 * Design (see `docs/plans/source-color-coding.md` for the full rationale):
 *
 *   - **Canonical source.** Replica nodes (Slice 6 + 7b's synthetic
 *     `${src}@->${consumer}` ids) point back to their original source via
 *     `node.replicaOf`. We collapse to the canonical id for both counting
 *     and coloring, so all 11 of AES-128's `key-expansion@->round.N.add-
 *     round-key` replicas count as one source with fanout 11 and share
 *     one color.
 *
 *   - **Endpoint pills are NOT colorable.** Plaintext / ciphertext pills
 *     have no "source" in the multi-fanout sense (they ARE the source).
 *     Edges originating from them fall through to today's kind-based
 *     styling.
 *
 *   - **Deterministic alphabetical assignment.** Sources are sorted
 *     alphabetically by canonical id; `palette[0]` goes to the
 *     alphabetically-first multi-fanout source. Same graph → same colors,
 *     so screenshot tests stay stable without per-test color baselining.
 *     Trade-off: the "biggest" source (highest fanout) doesn't get
 *     palette[0] — but stable screenshots beat that heuristic. User
 *     confirmed alphabetical 2026-05-19.
 *
 *   - **Palette + algorithmic extension.** First 8 sources get the
 *     curated Okabe-Ito colorblind-safe set (minus red, reserved for
 *     warning glyphs, minus black, indistinguishable from the default
 *     state stroke; magenta substituted). Sources 9+ get
 *     golden-angle-stepped HSL colors so any N stays distinguishable. The
 *     algorithmic tail isn't colorblind-safe; the first 8 (the common
 *     case for shipped ciphers) is.
 */

import { type CipherGraph, type GraphEdge, isEndpointId } from "./graph";

/**
 * Curated 8-color palette. Okabe-Ito colorblind-safe set with three
 * substitutions:
 *   - Pure red (`#D55E00`) → dropped (reserved for warning glyphs).
 *   - Black (`#000000`) → magenta (`#CC00CC`): black was
 *     indistinguishable from the default state stroke on the canvas.
 *   - Sky blue (`#56B4E9`) → barn red (`#7C0A02`): sky blue was
 *     perceptually too close to the canvas's `var(--accent)`
 *     light-blue, so source-coloured aux edges drawn in sky blue read
 *     the same as un-coloured aux edges. Tried sienna brown first
 *     (`#8C564B`) per advisor recommendation; user picked barn red
 *     for a saturated warm anchor that's also distinct from
 *     orange (`#E69F00`) and rose-pink (`#CC79A7`). User-flagged
 *     2026-05-19.
 *
 * The dark blue (`#0072B2`) is kept as the palette's blue anchor; it
 * has enough chroma + value distance from the accent to read clearly.
 */
export const SOURCE_COLOR_PALETTE: readonly string[] = [
  "#E69F00", // orange
  "#7C0A02", // barn red (substituted for Okabe-Ito's sky blue)
  "#009E73", // bluish green
  "#F0E442", // yellow
  "#0072B2", // dark blue
  "#CC79A7", // rose pink
  "#999999", // grey
  "#CC00CC", // magenta (substituted for Okabe-Ito's black)
];

/**
 * Golden angle in degrees. Maximally-distinct hue spacing for any N:
 * starting at hue 0 and stepping by 137.508° produces a sequence where
 * the first K values are all roughly evenly distributed around the wheel,
 * regardless of what K is. Used for source indices ≥ 8.
 */
const GOLDEN_ANGLE_DEG = 137.508;

/**
 * Saturation + luminance for algorithmically-generated colors. Tuned to
 * approximately match the perceived brightness of the curated palette so
 * the visual boundary between palette-served and generated colors isn't
 * a brightness cliff. Fixed across all generated colors so no source
 * looks "more important" because it happens to land brighter.
 */
const GENERATED_SATURATION_PCT = 65;
const GENERATED_LUMINANCE_PCT = 55;

/**
 * Resolve the canonical source id for an edge. Replica nodes
 * (`replicaOf` set) point back to their original source. Plain leaves
 * are their own canonical id. Edges originating from synthetic endpoint
 * pills return `undefined` — pills aren't colorable.
 *
 * Returns `undefined` for endpoint-pill sources so the caller can skip
 * coloring early. Returns the canonical id otherwise (replicas resolved).
 */
export const resolveCanonicalSource = (edge: GraphEdge, graph: CipherGraph): string | undefined => {
  if (isEndpointId(edge.from)) return undefined;
  const node = graph.nodes.find((n) => n.stepId === edge.from);
  return node?.replicaOf ?? edge.from;
};

/**
 * Build a canonical-source → fanout map for one graph. Single pass
 * over `graph.edges`; replicas collapse to their `replicaOf` source.
 * Endpoint-pill sources are skipped (pills have no upstream).
 * Internal helper for both `multiFanoutSources` and
 * `allColorableSources`.
 */
const sourceFanoutMap = (graph: CipherGraph): Map<string, number> => {
  // Single pass to build the replica lookup. `replicaOf` is undefined for
  // non-replicas; we still record the entry so `.get()` distinguishes
  // "node exists, not a replica" from "node not in graph."
  const replicaOfByStepId = new Map<string, string | undefined>();
  // Also remember which nodes are synthetic rejoins. A `feistel-round`'s
  // rejoin chip emits two outgoing edges by construction (new_L → next
  // round's L track, new_R → next round's R track), so it always trips
  // the fanout ≥ 2 threshold — but pedagogically both arrows are halves
  // of the SAME combined state, not distinct sources. Colouring the
  // crossover X turns visual continuity into visual noise; user-flagged
  // 2026-05-20 Phase 6e smoke. Exclude rejoin synthetics from the count
  // so they don't get auto-coloured (and so they don't show up in the
  // panel as a colourable source even when the "include single-output"
  // sub-toggle is on — the panel walks the same map).
  const rejoinSynthetics = new Set<string>();
  for (const node of graph.nodes) {
    replicaOfByStepId.set(node.stepId, node.replicaOf);
    if (node.synthetic === "rejoin") rejoinSynthetics.add(node.stepId);
  }
  const counts = new Map<string, number>();
  for (const edge of graph.edges) {
    if (isEndpointId(edge.from)) continue;
    if (rejoinSynthetics.has(edge.from)) continue;
    const canonical = replicaOfByStepId.get(edge.from) ?? edge.from;
    counts.set(canonical, (counts.get(canonical) ?? 0) + 1);
  }
  return counts;
};

/**
 * Return the alphabetically-sorted canonical sources with fanout ≥ 2.
 * These are the sources `assignSourceColors` auto-assigns palette
 * entries to, AND the sources the panel lists by default.
 *
 * Why the threshold: a single-fanout source's one edge is already
 * unambiguously traceable to its origin, so colouring it adds visual
 * noise without pedagogical gain. The user can still manually colour
 * single-fanout sources by flipping the "include single-output
 * sources" panel toggle (2026-05-19 follow-up — see
 * `view-source-colors`'s `useIncludeSingleSources`).
 */
export const multiFanoutSources = (graph: CipherGraph): readonly string[] => {
  const counts = sourceFanoutMap(graph);
  const result: string[] = [];
  for (const [id, count] of counts) {
    if (count >= 2) result.push(id);
  }
  // Alphabetical so the assignment is deterministic across renders /
  // sessions. Locale-naive `Array.sort()` (lexicographic) is intentional:
  // canonical source ids are ASCII-only step identifiers like
  // `key-expansion`, `compute-block-count`, never user-localized strings.
  result.sort();
  return result;
};

/**
 * Return EVERY canonical source with at least one outgoing edge,
 * alphabetically sorted. Used by the panel when the "include
 * single-output sources" sub-toggle is ON — gives the user a row for
 * each source so they can manually pick a colour even when the auto
 * pass left it un-assigned.
 *
 * Auto-colouring still uses `multiFanoutSources` (single-fanout
 * sources start un-coloured). The panel listing is the only place
 * the difference shows up.
 */
export const allColorableSources = (graph: CipherGraph): readonly string[] => {
  const counts = sourceFanoutMap(graph);
  return [...counts.keys()].sort();
};

/**
 * Convert HSL (with `h` in degrees, `s` + `l` in percent 0..100) to a
 * `#RRGGBB` hex string. Used by `colorForSourceIndex` for indices ≥ 8.
 *
 * Why hex everywhere (rather than mixing palette hex + algorithmic HSL):
 * the `<input type="color">` swatch in the source-colors panel ONLY
 * accepts `#RRGGBB`, so emitting hex uniformly means the panel can
 * round-trip auto-assigned colors through the picker without an
 * intermediate format conversion. The renderer's SVG `stroke`
 * attribute happily accepts either format, so this is purely an
 * authoring-UX simplification.
 */
const hslToHex = (hDeg: number, sPct: number, lPct: number): string => {
  const s = sPct / 100;
  const l = lPct / 100;
  // Standard HSL → RGB conversion using chroma/intermediate/lightness-offset
  // decomposition (see https://en.wikipedia.org/wiki/HSL_and_HSV#Converting_to_RGB).
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hh = hDeg / 60;
  const x = c * (1 - Math.abs((hh % 2) - 1));
  let r = 0;
  let g = 0;
  let b = 0;
  if (hh < 1) {
    r = c;
    g = x;
  } else if (hh < 2) {
    r = x;
    g = c;
  } else if (hh < 3) {
    g = c;
    b = x;
  } else if (hh < 4) {
    g = x;
    b = c;
  } else if (hh < 5) {
    r = x;
    b = c;
  } else {
    r = c;
    b = x;
  }
  const m = l - c / 2;
  const toByteHex = (v: number): string => {
    const clamped = Math.max(0, Math.min(255, Math.round((v + m) * 255)));
    return clamped.toString(16).padStart(2, "0");
  };
  return `#${toByteHex(r)}${toByteHex(g)}${toByteHex(b)}`;
};

/**
 * Map a 0-based source index to its assigned color. Indices 0..7 hit the
 * curated palette in order; indices ≥ 8 generate an HSL color via
 * golden-angle hue stepping AND convert to hex (`#RRGGBB`) so the
 * authoring color picker can round-trip every auto-assigned color.
 * Caller is expected to pass a non-negative integer; behavior is
 * undefined for negatives / NaN.
 */
export const colorForSourceIndex = (index: number): string => {
  // Read the palette slot first (returns `undefined` past the end under
  // `noUncheckedIndexedAccess`). If present, that's the answer; if not,
  // fall through to the algorithmic branch.
  const fromPalette = SOURCE_COLOR_PALETTE[index];
  if (fromPalette !== undefined) return fromPalette;
  const hue = (index * GOLDEN_ANGLE_DEG) % 360;
  return hslToHex(hue, GENERATED_SATURATION_PCT, GENERATED_LUMINANCE_PCT);
};

/**
 * Build the auto-color map for one graph. Deterministic on graph
 * structure: identical graphs produce identical maps, so a screenshot
 * recorded today still matches the canvas tomorrow.
 *
 * The returned map covers ONLY multi-fanout sources. Callers must fall
 * through to today's kind-based styling for any edge whose canonical
 * source isn't in the map.
 */
export const assignSourceColors = (graph: CipherGraph): ReadonlyMap<string, string> => {
  const sources = multiFanoutSources(graph);
  const map = new Map<string, string>();
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    // `noUncheckedIndexedAccess` makes this `string | undefined` even
    // though `i < sources.length` bounds the access. Guard explicitly.
    if (src === undefined) continue;
    map.set(src, colorForSourceIndex(i));
  }
  return map;
};

/**
 * Resolve the final color for one edge given the precomputed auto-color
 * map + any manual overrides. Returns `undefined` for edges that should
 * NOT be colored (endpoint-pill sources, single-fanout sources). The
 * caller handles fall-through to kind-based styling.
 *
 * Manual overrides win over the auto map. Source absent from both maps
 * means single-fanout (or unknown) → caller falls through.
 */
export const colorForEdge = (
  edge: GraphEdge,
  graph: CipherGraph,
  autoColors: ReadonlyMap<string, string>,
  manualOverrides: ReadonlyMap<string, string>,
): string | undefined => {
  const canonical = resolveCanonicalSource(edge, graph);
  if (canonical === undefined) return undefined;
  return manualOverrides.get(canonical) ?? autoColors.get(canonical);
};
