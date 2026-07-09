/**
 * Curated default layouts for the shipped built-in ciphers/hashes
 * (graph-legibility plan, Part B — `docs/plans/toasty-zooming-harp.md`).
 *
 * ## What this is
 * A pure `specId → LayoutSpec` map plus the read-time helpers that layer a
 * curated arrangement UNDER the user's own layout. A built-in with a curated
 * default opens pre-arranged (positions, collapses, replication overrides)
 * instead of raw auto-layout; the user's drags still win and still persist /
 * travel exactly as before.
 *
 * ## Why a standalone map (not a field on `CipherSpec`)
 * Keying on the stable built-in `spec.id` (`"sha-256@1"`, `"aes-128@1"`, …)
 * keeps the document format and the canonical built-in specs untouched. The
 * curated default is a **pure read-time fallback**: it is NEVER written to
 * localStorage or the Save/Share sidecar, so spec-only-save byte-stability is
 * preserved (a user who hasn't dragged anything still saves no `layout`
 * sidecar; the recipient re-derives the same curated default from the id).
 *
 * ## Merge, not replace (user-decided 2026-07-09)
 * `effectiveLayout()` in `GraphView` is `mergeLayoutSpecs(curated, user)` — a
 * per-key overlay where the user wins per id. Dragging ONE node persists only
 * that node (against the raw user layout, see the store setters) while every
 * other node keeps its curated position. This diverges from the plan's
 * original whole-object `??` (which would have reverted the whole arrangement
 * on the first drag); the user chose curation-preserving merge.
 *
 * ## B1 scope
 * The real `CURATED_DEFAULT_LAYOUTS` map ships EMPTY. With no entries,
 * `curatedDefaultFor` returns `null` for every shipped spec and
 * `effectiveLayout() === userLayout()` — i.e. this module is a provable no-op
 * in the shipped app until Part B's later chunks author one layout per cipher
 * (browser-driven, SHA-256 first). The `__setCuratedDefaultsForTests` seam
 * lets the mechanism tests exercise the fallback/merge/reset paths without
 * depending on that hand-authored content.
 */

import type { LayoutSpec, RelativePosition, ReplicationMode, StepPosition } from "./document";

/**
 * The curated built-in layouts, keyed by stable `spec.id`. EMPTY in B1 —
 * populated one cipher at a time in Part B's later chunks. Keys must be real
 * built-in spec ids (cross-checked in `tests/default-layouts.test.ts`).
 */
export const CURATED_DEFAULT_LAYOUTS: { readonly [specId: string]: LayoutSpec } = {};

/**
 * Test-only override of the curated map. Mirrors the `__reset*ForTests` seams
 * in the layout / edit-history stores. When set, `curatedDefaultFor` reads
 * this instead of the shipped catalogue so a jsdom test can inject a curated
 * default for an arbitrary spec id. `null` (the default) means "use the real
 * catalogue".
 */
let overrideForTests: { readonly [specId: string]: LayoutSpec } | null = null;

/** Inject a curated-defaults map for tests. Pass `null` via the reset below. */
export const __setCuratedDefaultsForTests = (map: {
  readonly [specId: string]: LayoutSpec;
}): void => {
  overrideForTests = map;
};

/** Restore the real (shipped) curated catalogue. Call in test teardown. */
export const __resetCuratedDefaultsForTests = (): void => {
  overrideForTests = null;
};

/**
 * The curated default `LayoutSpec` for a built-in spec id, or `null` when the
 * id has no curated arrangement (every id in B1; a duplicated-round spec whose
 * id has bumped past `@1`; any non-built-in). A clean miss, never an error.
 */
export const curatedDefaultFor = (specId: string): LayoutSpec | null => {
  const map = overrideForTests ?? CURATED_DEFAULT_LAYOUTS;
  return map[specId] ?? null;
};

/** Dedup-preserving union of two id lists (order: base first, then new). */
const unionIds = (a: readonly string[], b: readonly string[]): string[] => {
  const seen = new Set(a);
  const out = [...a];
  for (const id of b) {
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
};

/**
 * Per-key overlay of a user `LayoutSpec` on top of a curated `base`. The user
 * wins per id in every merged sub-map (`positions`, `relativePositions`,
 * `replicationModes`); the collapse sets union (and `getEffectiveCollapsedSet`'s
 * `(defaults ∪ collapsed) − expanded` subtract lets a user-expand of a
 * curated-collapsed group win). `flowDirection` takes the user's value.
 *
 * **`strokeStyles` is deliberately NOT merged.** Per-source arrow styles are a
 * viewer channel: `GraphView` reads `strokeStyles` off the USER layout (not the
 * merged/effective one), and SHA-256's auto-assignment (`view-source-strokes`)
 * covers the only spec that needs them, so curated layouts intentionally carry
 * none. Merging them here would be dead — the effective-layout consumers never
 * read `strokeStyles` — and would mislead a future author into thinking a
 * curated stroke renders. If curated strokes are ever wanted, that's a
 * deliberate change touching BOTH this merge and the reader at once.
 *
 * PURE — no Solid, no store. The result is used ONLY for rendering and is
 * never persisted, so it does NOT need `buildLayoutSpec`'s exact key-order /
 * omission discipline; it still omits empty optionals so readers that do
 * `l.replicationModes ?? {}` behave identically to an un-merged layout.
 *
 * Callers guarantee `base`/`over` are non-null (the `GraphView` memo handles
 * the "only one exists" cases before reaching here).
 */
export const mergeLayoutSpecs = (base: LayoutSpec, over: LayoutSpec): LayoutSpec => {
  const positions: { [stepId: string]: StepPosition } = {
    ...base.positions,
    ...over.positions,
  };
  const relativePositions: { [id: string]: RelativePosition } = {
    ...(base.relativePositions ?? {}),
    ...(over.relativePositions ?? {}),
  };
  const replicationModes: { [sourceId: string]: ReplicationMode } = {
    ...(base.replicationModes ?? {}),
    ...(over.replicationModes ?? {}),
  };
  const collapsedGroups = unionIds(base.collapsedGroups, over.collapsedGroups);
  const expandedGroups = unionIds(base.expandedGroups ?? [], over.expandedGroups ?? []);

  return {
    positions,
    collapsedGroups,
    flowDirection: over.flowDirection,
    ...(Object.keys(replicationModes).length > 0 ? { replicationModes } : {}),
    ...(Object.keys(relativePositions).length > 0 ? { relativePositions } : {}),
    ...(expandedGroups.length > 0 ? { expandedGroups } : {}),
    // strokeStyles intentionally omitted from the effective layout — see the
    // docstring above (GraphView reads strokes off the USER layout).
  };
};
