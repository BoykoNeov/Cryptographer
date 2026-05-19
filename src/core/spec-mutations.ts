/**
 * Pure helpers that produce new CipherSpec values from old ones. The spec
 * tree is `readonly`, so mutations always return a fresh tree — Solid stores
 * compare references to decide what to re-render, so handing back the same
 * object would cause subtle bugs.
 *
 * These exist so the UI can edit a single step's params (e.g. "swap the
 * S-box") without knowing how to walk the tree itself.
 */

import type {
  CipherSpec,
  IterateGroup,
  Json,
  StateShape,
  StepGroup,
  StepLeaf,
  StepNode,
} from "./types";

// ─── Walking the tree ─────────────────────────────────────────────────────

/**
 * Find a leaf step by id, anywhere in the tree (depth-first). Returns null
 * if no leaf with that id exists or if the id refers to a group.
 *
 * Group ids and leaf ids share the same namespace, so we explicitly check
 * `kind === "step"` to avoid returning a group masquerading as a leaf.
 */
export const findStep = (spec: CipherSpec, stepId: string): StepLeaf | null => {
  const visit = (nodes: readonly StepNode[]): StepLeaf | null => {
    for (const node of nodes) {
      if (node.kind === "step") {
        if (node.id === stepId) return node;
      } else if (node.kind === "feistel-round") {
        for (const track of node.tracks) {
          const found = visit(track.children);
          if (found) return found;
        }
      } else {
        const found = visit(node.children);
        if (found) return found;
      }
    }
    return null;
  };
  return visit(spec.steps);
};

// ─── Editing one step ─────────────────────────────────────────────────────

/**
 * Replace one leaf step's params. Returns a NEW spec; the original is
 * untouched. If `stepId` doesn't match any leaf, returns the original spec
 * by reference (caller can detect the no-op via `result === spec`).
 *
 * `params` is the full new params object — this is a replacement, not a
 * merge. The UI editors construct a complete new params object themselves
 * because Json is recursive and a deep merge has too many edge cases.
 */
export const updateStepParams = (spec: CipherSpec, stepId: string, params: Json): CipherSpec => {
  let changed = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    return nodes.map((node) => {
      if (node.kind === "step") {
        if (node.id !== stepId) return node;
        changed = true;
        return { ...node, params };
      }
      if (node.kind === "feistel-round") {
        // Descend into each track's children, rebuilding only tracks that
        // contain the targeted leaf. Reference-equality preserved on
        // untouched tracks AND on the round itself when no track changes.
        let trackChanged = false;
        const newTracks = node.tracks.map((track) => {
          const updated = visit(track.children);
          if (updated === track.children) return track;
          trackChanged = true;
          return { ...track, children: updated };
        });
        if (!trackChanged) return node;
        return { ...node, tracks: newTracks };
      }
      const newChildren = visit(node.children);
      // If nothing changed inside this group, return the original group
      // node so reference equality holds for unaffected branches.
      if (newChildren === node.children) return node;
      return { ...node, children: newChildren };
    });
  };

  const newSteps = visit(spec.steps);
  if (!changed) return spec;
  return { ...spec, steps: newSteps };
};

// ─── Bulk edit by step type ───────────────────────────────────────────────

/**
 * Apply a partial update to every leaf step whose `type` matches `stepType`.
 * The update function receives the existing params and returns the new
 * params. Used for "apply S-box change to all byte-substitution steps."
 *
 * Why this exists: each step has its OWN copy of the S-box in its params
 * (the architecture treats params as per-step JSON). For AES, every round
 * shares the same S-box conceptually — so the UI offers a one-click way to
 * propagate an edit to all matching steps.
 */
export const updateAllStepsByType = (
  spec: CipherSpec,
  stepType: string,
  update: (params: Json) => Json,
): CipherSpec => {
  let changed = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    return nodes.map((node) => {
      if (node.kind === "step") {
        if (node.type !== stepType) return node;
        const newParams = update(node.params);
        if (newParams === node.params) return node;
        changed = true;
        return { ...node, params: newParams };
      }
      if (node.kind === "feistel-round") {
        let trackChanged = false;
        const newTracks = node.tracks.map((track) => {
          const updated = visit(track.children);
          if (updated === track.children) return track;
          trackChanged = true;
          return { ...track, children: updated };
        });
        if (!trackChanged) return node;
        return { ...node, tracks: newTracks };
      }
      const newChildren = visit(node.children);
      if (newChildren === node.children) return node;
      return { ...node, children: newChildren };
    });
  };

  const newSteps = visit(spec.steps);
  if (!changed) return spec;
  return { ...spec, steps: newSteps };
};

// ─── Comparing two specs ──────────────────────────────────────────────────

/**
 * A single per-cell change inside a numeric-array param (S-box entry,
 * MixColumns matrix cell, shift offset, …). Two flavors:
 *   • `kind: "1d"` for flat number arrays — `index` is the array offset
 *     (used for shifts, rcon, and other small flat tables).
 *   • `kind: "2d"` for nested 2D number arrays (MixColumns matrix) AND for
 *     flat-256 byte tables (AES-style S-box) where the canonical view is
 *     a 16×16 grid. `compareSpecs` decomposes index → (row, col) at diff
 *     time so consumers don't need to know the source shape.
 */
export type ParamCellDiff =
  | { readonly kind: "1d"; readonly index: number; readonly from: number; readonly to: number }
  | {
      readonly kind: "2d";
      readonly row: number;
      readonly col: number;
      readonly from: number;
      readonly to: number;
    };

/** A single param-level difference between two specs. */
export type SpecParamDiff = {
  /** The leaf stepId where the change was observed (or `"*"` for tree-level changes). */
  readonly stepId: string;
  /**
   * The top-level key in the leaf's params object whose value differs.
   * Special values: `"(type)"` if the step's `type` changed; `"(structure)"`
   * if the tree shape diverged (insertion, removal, reorder); `"*"` for
   * spec-id mismatch ("(cipher swapped)") or trailing-length differences.
   */
  readonly paramName: string;
  /**
   * The step's `type` field at the diff site, when known. Optional because
   * tree-level markers (`"(cipher swapped)"`, `"(structure)"`, trailing
   * length deltas) don't have a single step. Currently unused by the
   * formatter — kept so future presentations (e.g. "round.1 SubBytes
   * S-box") can prefix human-readable labels without re-walking the spec.
   */
  readonly stepType?: string;
  /**
   * Populated when both sides of the diff are JSON scalars (number / string
   * / boolean / null). The formatter renders these as "param X → Y".
   */
  readonly scalar?: { readonly from: Json; readonly to: Json };
  /**
   * Populated when both sides of the diff are number arrays of matching
   * shape (flat OR 2D). The formatter renders these per-cell with row/col
   * or index coordinates and uses the active ByteFormat for the values.
   * An empty array here means the arrays compare equal AT THE NUMERIC
   * LEVEL (shouldn't happen — `jsonEqual` would have short-circuited —
   * but defended against in the consumer).
   */
  readonly cells?: readonly ParamCellDiff[];
};

/**
 * Pure deep-equality on Json values. We can't use `===` (object identity)
 * because the spec store rebuilds the tree on every edit; we don't want to
 * pull in a dependency for one helper. Json is a finite recursive shape, so
 * a 20-line walker is enough.
 */
const jsonEqual = (a: Json, b: Json): boolean => {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!jsonEqual(a[i] ?? null, b[i] ?? null)) return false;
    }
    return true;
  }
  if (typeof a === "object" && typeof b === "object") {
    const ao = a as { [k: string]: Json };
    const bo = b as { [k: string]: Json };
    const ak = Object.keys(ao);
    const bk = Object.keys(bo);
    if (ak.length !== bk.length) return false;
    for (const k of ak) {
      if (!Object.hasOwn(bo, k)) return false;
      if (!jsonEqual(ao[k] ?? null, bo[k] ?? null)) return false;
    }
    return true;
  }
  return false;
};

/**
 * Per-key diff carrier produced by `classifyKeyDiff`. Mirrors the shape of
 * `SpecParamDiff` without the stepId/stepType context — those are added
 * later when `compareSpecs` walks the tree.
 */
type KeyDiffInfo = {
  readonly scalar?: { readonly from: Json; readonly to: Json };
  readonly cells?: readonly ParamCellDiff[];
};

/** True if `v` is a JSON scalar (number / string / boolean / null). */
const isJsonScalar = (v: Json): boolean => v === null || typeof v !== "object";

/** True if every element of `v` is a JS number — i.e. a flat byte/int array. */
const isFlatNumberArray = (v: Json): v is number[] =>
  Array.isArray(v) && v.every((e) => typeof e === "number");

/**
 * True if `v` is a 2D number array (array of equal-length number rows).
 * Used to detect the MixColumns matrix shape (4×4 row-of-rows) so we can
 * decompose changes into `(row, col)` pairs rather than spilling raw
 * flattened indexes into the legend.
 */
const is2dNumberArray = (v: Json): v is number[][] =>
  Array.isArray(v) &&
  v.length > 0 &&
  v.every((row) => Array.isArray(row) && row.every((e) => typeof e === "number"));

/**
 * Classify a single keys-differ situation into a richer diff carrier. The
 * three flavors we handle:
 *   • Both scalars → `{ scalar: { from, to } }`. Lets the legend render
 *     `rounds 10 → 12` instead of `rounds changed`.
 *   • Both flat number arrays of equal length → `{ cells: [...] }`. For a
 *     length-256 array we treat it as the canonical AES S-box (16×16) and
 *     decompose every index into `(row, col)`. Other lengths keep the 1D
 *     `index` form (used by `shifts`, `rcon`, etc.).
 *   • Both 2D number arrays of matching shape → `{ cells: [...] }` with
 *     `(row, col)` pairs straight from the nesting. Matches MixColumns.
 *
 * Everything else (object-replaced-with-array, nested object diffs, mixed
 * shapes) collapses to `{}` — the formatter falls back to "X changed",
 * preserving the pre-extension behavior for diffs we can't summarize.
 */
const classifyKeyDiff = (a: Json, b: Json): KeyDiffInfo => {
  // Scalars on both sides → before/after values.
  if (isJsonScalar(a) && isJsonScalar(b)) {
    return { scalar: { from: a, to: b } };
  }

  // Flat number array, equal length → per-cell diffs.
  if (isFlatNumberArray(a) && isFlatNumberArray(b) && a.length === b.length) {
    const cells: ParamCellDiff[] = [];
    // Length-256 arrays are the AES S-box / inverse S-box convention; render
    // as the canonical 16×16 (row, col) grid the editor itself uses. Any
    // other length stays in flat-`index` form because there's no shared
    // visualization convention to lean on.
    const decomposeAsTable = a.length === 256;
    for (let i = 0; i < a.length; i++) {
      const av = a[i] ?? 0;
      const bv = b[i] ?? 0;
      if (av !== bv) {
        if (decomposeAsTable) {
          // index → (row, col) with row = high nibble, col = low nibble.
          // Same convention as `SboxEditor.tsx`.
          cells.push({ kind: "2d", row: i >> 4, col: i & 15, from: av, to: bv });
        } else {
          cells.push({ kind: "1d", index: i, from: av, to: bv });
        }
      }
    }
    return { cells };
  }

  // 2D number array with matching outer + inner shapes → per-cell diffs
  // with explicit (row, col). Mismatched shapes fall through to {}.
  if (is2dNumberArray(a) && is2dNumberArray(b) && a.length === b.length) {
    const shapesMatch = a.every((row, r) => row.length === (b[r]?.length ?? -1));
    if (shapesMatch) {
      const cells: ParamCellDiff[] = [];
      for (let r = 0; r < a.length; r++) {
        const rowA = a[r] ?? [];
        const rowB = b[r] ?? [];
        for (let c = 0; c < rowA.length; c++) {
          const av = rowA[c] ?? 0;
          const bv = rowB[c] ?? 0;
          if (av !== bv) cells.push({ kind: "2d", row: r, col: c, from: av, to: bv });
        }
      }
      return { cells };
    }
  }

  // Anything else: caller falls back to the "X changed" summary.
  return {};
};

/**
 * Enumerate the top-level keys that differ between two Json values, returning
 * the full per-key diff info so the caller can produce richer `SpecParamDiff`
 * entries. If either side isn't an object (array, primitive), return a single
 * `"*"` marker — params replaced wholesale aren't worth diving into.
 */
const diffJsonObjectKeysRich = (
  a: Json,
  b: Json,
): readonly { readonly key: string; readonly info: KeyDiffInfo }[] => {
  const aIsObj = a !== null && typeof a === "object" && !Array.isArray(a);
  const bIsObj = b !== null && typeof b === "object" && !Array.isArray(b);
  if (!aIsObj || !bIsObj) return [{ key: "*", info: {} }];
  const ao = a as { [k: string]: Json };
  const bo = b as { [k: string]: Json };
  const keys = new Set<string>([...Object.keys(ao), ...Object.keys(bo)]);
  const out: { key: string; info: KeyDiffInfo }[] = [];
  for (const k of keys) {
    const av = ao[k] ?? null;
    const bv = bo[k] ?? null;
    if (!jsonEqual(av, bv)) out.push({ key: k, info: classifyKeyDiff(av, bv) });
  }
  return out;
};

/**
 * Diff two CipherSpecs and return the list of param-level changes. Used by
 * the run-history store to produce "what changed between this run and the
 * previous one" descriptions. Walks both trees in parallel; on a structural
 * mismatch (different ids, different kinds, different lengths) emits a
 * `"(structure)"` marker rather than trying to enumerate.
 *
 * Reference-equal specs short-circuit to no changes. Different spec.id
 * (e.g. mode swap encrypt→decrypt) returns a single `"(cipher swapped)"`
 * marker since per-step comparison isn't meaningful across cipher families.
 */
export const compareSpecs = (a: CipherSpec, b: CipherSpec): readonly SpecParamDiff[] => {
  if (a === b) return [];
  if (a.id !== b.id) {
    return [{ stepId: "*", paramName: "(cipher swapped)" }];
  }
  const changes: SpecParamDiff[] = [];

  const visit = (na: readonly StepNode[], nb: readonly StepNode[]): void => {
    const len = Math.min(na.length, nb.length);
    for (let i = 0; i < len; i++) {
      const x = na[i];
      const y = nb[i];
      if (!x || !y) continue;
      if (x.kind !== y.kind || x.id !== y.id) {
        changes.push({ stepId: x.id, paramName: "(structure)" });
        continue;
      }
      if (x.kind === "step" && y.kind === "step") {
        if (x.type !== y.type) {
          changes.push({ stepId: x.id, stepType: x.type, paramName: "(type)" });
        } else if (!jsonEqual(x.params, y.params)) {
          // Walk the params object and ask `classifyKeyDiff` to attach value
          // info to each differing key. Bare diffs (no scalar/cells) preserve
          // the legacy "X changed" rendering path in describeDelta.
          const entries = diffJsonObjectKeysRich(x.params, y.params);
          for (const { key, info } of entries) {
            changes.push({
              stepId: x.id,
              stepType: x.type,
              paramName: key,
              ...(info.scalar !== undefined ? { scalar: info.scalar } : {}),
              ...(info.cells !== undefined ? { cells: info.cells } : {}),
            });
          }
        }
      } else if (x.kind === "group" && y.kind === "group") {
        visit(x.children, y.children);
      } else if (x.kind === "iterate" && y.kind === "iterate") {
        // Mirror the group branch — recurse into iterate bodies so any
        // param edits inside an iterate body show up in the diff. (The
        // pre-feistel union narrowed `x.kind === y.kind` to "group" only,
        // implicitly skipping iterates; with feistel-round now in the
        // union we explicitly enumerate to keep TS happy AND preserve the
        // descent semantics across all container kinds.)
        visit(x.children, y.children);
      } else if (x.kind === "feistel-round" && y.kind === "feistel-round") {
        // Per-track recursion. Track count mismatch is already flagged
        // above as a `(structure)` change via the `x.kind !== y.kind`
        // guard (kind is the same here, but a future kind-tag bump would
        // catch it). For now, recurse into the min of the two track
        // counts; a Phase-3 cipher swap that adds tracks would surface
        // as an `(unequal tracks)` change.
        const trackLen = Math.min(x.tracks.length, y.tracks.length);
        for (let ti = 0; ti < trackLen; ti++) {
          const xt = x.tracks[ti];
          const yt = y.tracks[ti];
          if (xt && yt) visit(xt.children, yt.children);
        }
        if (x.tracks.length !== y.tracks.length) {
          changes.push({ stepId: x.id, paramName: "(tracks added/removed)" });
        }
      }
    }
    if (na.length !== nb.length) {
      changes.push({ stepId: "*", paramName: "(steps added/removed)" });
    }
  };

  visit(a.steps, b.steps);
  return changes;
};

// ─── Structural mutations (Slice 4 of the 2D editor plan) ────────────────
// Pure helpers for the visual editor's drag-to-reorder, palette-insert, and
// "remove this step" operations. Each preserves reference equality on
// branches the operation doesn't touch — same discipline as
// `updateStepParams` above. Each throws if the targeted stepId doesn't
// exist (silent no-ops would be a footgun for the visual editor: the
// palette's drop coordinate is meant to be authoritative, and a typo'd id
// in calling code should surface immediately, not vanish into a no-op).
//
// The mutators don't validate the *contents* of `newStep` against the
// registry — that's the runtime's job at execution time. Adding a leaf
// with an unknown `type` produces a spec that fails to run; this is the
// same contract `updateStepParams` honors.

/**
 * Structural neighborhood of a node in the spec tree.
 *  - `node` is the matched node itself (leaf, group, or iterate).
 *  - `parent` is the group/iterate container holding it, or `null` when the
 *    node lives at the top level of `spec.steps`.
 *  - `indexInParent` is the node's position in its sibling array.
 *
 * Unlike `findStep` (leaves-only), this returns ANY node kind so the
 * visual editor can anchor inserts to groups too (e.g. "drop this new step
 * after the round.5 group, not inside it").
 */
export type StepLocation = {
  readonly node: StepNode;
  readonly parent: StepGroup | IterateGroup | null;
  readonly indexInParent: number;
};

/**
 * Find a node (leaf OR group OR iterate) by id and return its structural
 * neighborhood. Depth-first; returns null on no match. Ids are assumed
 * unique within a spec — if duplicates exist the first match in DFS order
 * wins (mirrors `findStep`).
 */
export const findStepAndParent = (spec: CipherSpec, stepId: string): StepLocation | null => {
  const visit = (
    nodes: readonly StepNode[],
    parent: StepGroup | IterateGroup | null,
  ): StepLocation | null => {
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      if (!node) continue;
      if (node.id === stepId) return { node, parent, indexInParent: i };
      if (node.kind === "step") continue;
      if (node.kind === "feistel-round") {
        // Feistel-round in Phase 2: read-paths descend into tracks for
        // findStep lookups, but the `parent` returned for a leaf inside a
        // track must be a StepGroup or IterateGroup (not a FeistelRoundGroup)
        // by today's `StepLocation` contract. Treat feistel-round as a
        // descent barrier here: callers that need to locate a leaf inside
        // a Feistel track use the lower-level `findStep` instead. DES
        // (Phase 3) will widen the StepLocation type to carry track
        // membership when the structural editor needs it.
        continue;
      }
      const found = visit(node.children, node);
      if (found) return found;
    }
    return null;
  };
  return visit(spec.steps, null);
};

/**
 * Internal walker shared by every structural mutator. Locates the array
 * that *directly contains* `anchorStepId`, calls `transform` with that
 * array + the anchor's index in it, and rebuilds the surrounding tree.
 * Returns null if no node carried that id (lets each caller raise its
 * own contextual error).
 *
 * Reference-equality discipline: if `transform` returns the same array it
 * was given (the no-op case for reorder-to-same-index), the function
 * returns the original spec by reference. Branches that don't contain
 * the anchor keep their original group/iterate node references too —
 * same pattern as `updateStepParams`.
 */
const transformParentArray = (
  spec: CipherSpec,
  anchorStepId: string,
  transform: (children: readonly StepNode[], indexOfAnchor: number) => readonly StepNode[],
): CipherSpec | null => {
  let found = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    // First: is the anchor at THIS level? If so, this is the splice site.
    const idx = nodes.findIndex((n) => n.id === anchorStepId);
    if (idx >= 0) {
      found = true;
      return transform(nodes, idx);
    }
    // Otherwise recurse into groups/iterates, threading found-state so we
    // don't accidentally re-visit if the user's spec has an id collision.
    let mutated = false;
    const newChildren = nodes.map((n) => {
      if (n.kind === "step" || found) return n;
      // Feistel-round opacity (Phase 2): the structural mutators (insert,
      // remove, reorder) treat a `feistel-round` as a leaf — they don't
      // descend into per-track children. DES (Phase 3) will need
      // per-track structural support (insertions into the R track of a
      // round, etc.) which will require a track-aware StepLocation +
      // splice-into-track helpers. The toy Feistel spec exercised by
      // Phase 2 tests is built in one shot and never mutated.
      if (n.kind === "feistel-round") return n;
      const updatedChildren = visit(n.children);
      if (updatedChildren === n.children) return n;
      mutated = true;
      return { ...n, children: updatedChildren };
    });
    return mutated ? newChildren : nodes;
  };

  const newSteps = visit(spec.steps);
  if (!found) return null;
  if (newSteps === spec.steps) return spec; // identity short-circuit
  return { ...spec, steps: newSteps };
};

/**
 * Insert `newStep` immediately after `afterStepId`, into the same parent
 * (top level, group, or iterate body). Throws if no node with that id
 * exists.
 *
 * The new step's `id` is NOT checked for uniqueness — id management is
 * the caller's responsibility (the palette generates unique ids; the
 * load path validates at parse time).
 */
export const insertStepAfter = (
  spec: CipherSpec,
  afterStepId: string,
  newStep: StepNode,
): CipherSpec => {
  const result = transformParentArray(spec, afterStepId, (children, idx) => [
    ...children.slice(0, idx + 1),
    newStep,
    ...children.slice(idx + 1),
  ]);
  if (!result) throw new Error(`insertStepAfter: no step with id "${afterStepId}"`);
  return result;
};

/**
 * Insert `newStep` immediately before `beforeStepId`. Mirror of
 * `insertStepAfter`; same throw-on-missing contract.
 */
export const insertStepBefore = (
  spec: CipherSpec,
  beforeStepId: string,
  newStep: StepNode,
): CipherSpec => {
  const result = transformParentArray(spec, beforeStepId, (children, idx) => [
    ...children.slice(0, idx),
    newStep,
    ...children.slice(idx),
  ]);
  if (!result) throw new Error(`insertStepBefore: no step with id "${beforeStepId}"`);
  return result;
};

/**
 * Prepend `newStep` as the first child of the container identified by
 * `containerId`. Works on both empty and non-empty containers, and on
 * both `group` and `iterate` kinds. Throws if no node has that id or if
 * the id resolves to a leaf (mirrors the throw-on-missing contract of
 * `insertStepAfter` / `insertStepBefore`).
 *
 * Why this is its own primitive: the visual editor's `into-start` drop
 * semantic — "drop on a container header means land at position 0 of
 * its body" — needs to work even when the body is EMPTY. The natural
 * implementation via `insertStepBefore(firstChildId, ...)` has nothing
 * to anchor on in that case, so the spec store's previous code path
 * silently fell through to `root-append` and the dropped step landed at
 * the end of the top-level spec rather than inside the targeted empty
 * container. This helper closes that gap.
 *
 * Reference equality preserved on branches the operation doesn't touch
 * — same discipline as the surrounding mutators.
 */
export const prependChildToContainer = (
  spec: CipherSpec,
  containerId: string,
  newStep: StepNode,
): CipherSpec => {
  let found = false;
  let leafCollision = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    let mutated = false;
    const next = nodes.map((n) => {
      if (found || leafCollision) return n;
      if (n.id === containerId) {
        if (n.kind === "step") {
          // Caller passed a leaf's id where a container was expected. Flag
          // and let the outer code throw with a precise message — silently
          // doing nothing would mask a real wiring bug at the call site.
          leafCollision = true;
          return n;
        }
        if (n.kind === "feistel-round") {
          // No unambiguous "default track" for a round-level prepend in
          // Phase 2 — DES (Phase 3) will introduce per-track prepend
          // helpers when its structural editor lands. Treat the same as
          // a leaf-collision so the caller fails loudly.
          leafCollision = true;
          return n;
        }
        found = true;
        mutated = true;
        return { ...n, children: [newStep, ...n.children] };
      }
      if (n.kind === "step") return n;
      if (n.kind === "feistel-round") return n;
      const updated = visit(n.children);
      if (updated === n.children) return n;
      mutated = true;
      return { ...n, children: updated };
    });
    return mutated ? next : nodes;
  };

  const newSteps = visit(spec.steps);
  if (leafCollision) {
    throw new Error(
      `prependChildToContainer: id "${containerId}" resolves to a leaf, not a container`,
    );
  }
  if (!found) {
    throw new Error(`prependChildToContainer: no node with id "${containerId}"`);
  }
  return { ...spec, steps: newSteps };
};

/**
 * Remove the node identified by `stepId` from its parent. Removing the
 * sole child of a group leaves an empty group standing — empty groups
 * are valid in the data model and may carry meaningful labels the user
 * wants to keep (a future "fill this round with…" UI affordance).
 * Throws if no node has that id.
 */
export const removeStep = (spec: CipherSpec, stepId: string): CipherSpec => {
  const result = transformParentArray(spec, stepId, (children, idx) => [
    ...children.slice(0, idx),
    ...children.slice(idx + 1),
  ]);
  if (!result) throw new Error(`removeStep: no step with id "${stepId}"`);
  return result;
};

/**
 * Move the node identified by `stepId` to a new position WITHIN ITS
 * CURRENT PARENT. `newIndexInParent` is the target slot in the sibling
 * array after the move; out-of-range values are clamped to the valid
 * range `[0, siblings.length - 1]`. Moving to the current index is a
 * no-op and returns the original spec by reference. Throws if no node
 * has that id.
 *
 * Cross-parent moves (e.g. drag a leaf out of round.3 into round.5) are
 * intentionally not supported by this function. Callers can express that
 * as `removeStep` + `insertStepAfter` to keep the semantics explicit.
 */
export const reorderStep = (
  spec: CipherSpec,
  stepId: string,
  newIndexInParent: number,
): CipherSpec => {
  const result = transformParentArray(spec, stepId, (children, idx) => {
    if (children.length === 0) return children;
    const clamped = Math.max(0, Math.min(newIndexInParent, children.length - 1));
    if (clamped === idx) return children; // identity → outer short-circuits
    const moving = children[idx];
    if (!moving) return children;
    // Build the new order: first splice the moving node out, then splice
    // it back in at the clamped index. Doing it in two steps keeps the
    // index math obvious — `clamped` is the post-removal slot, which is
    // what callers naturally think in.
    const without = [...children.slice(0, idx), ...children.slice(idx + 1)];
    return [...without.slice(0, clamped), moving, ...without.slice(clamped)];
  });
  if (!result) throw new Error(`reorderStep: no step with id "${stepId}"`);
  return result;
};

// ─── Duplicate-round ──────────────────────────────────────────────────────
//
// Insert a clone of an AES round group, renumber surrounding siblings to
// keep round labels matching their key index, bump key-expansion's
// `rounds` (and morph its type `@1 → @2` so the schedule actually
// extends), and report a rename map for layout-pin migration.
//
// Two directions:
//
//   forward (encrypt). Source matches `^round\.\d+$`. Clone goes AFTER
//   source. Subsequent siblings (still in the same parent — typically
//   `spec.steps`, or the children of an `iterate` for multi-block AES)
//   that match `round.K` get renumbered `K → K+1`, and any AddRoundKey
//   inside such a group has its `auxName` `roundKey.K → roundKey.K+1`
//   in lockstep.
//
//   reverse (decrypt). Source matches `^inv-round\.\d+$`. Decrypt specs
//   sit in reverse round order (inv-initial at the top, inv-round.0 at
//   the bottom), so the renumber direction flips: the clone goes BEFORE
//   source and EARLIER siblings (which carry higher inv-round numbers)
//   get renumbered. The companion `inv-initial.add-round-key` leaf —
//   which reads `roundKey.{rounds}` and sits at the very top of the
//   decrypt body — also gets its auxName bumped.
//
// The mutator does not assert "the spec is well-formed AES." It rewrites
// what it can see and leaves unrelated nodes alone. Misuse (e.g. invoking
// reverse on a forward-shaped spec) returns a structurally valid spec
// that just won't compute anything sensible — the runtime catches the
// downstream consequences.

/** Outcome of `duplicateRoundGroup`. The rename map is keyed `oldId → newId`. */
export type DuplicateRoundResult = {
  readonly spec: CipherSpec;
  readonly renames: ReadonlyMap<string, string>;
};

const ROUND_ID_RE = /^round\.(\d+)$/;
const INV_ROUND_ID_RE = /^inv-round\.(\d+)$/;
const ROUND_LABEL_RE = /^Round (\d+)/;
const INV_ROUND_LABEL_RE = /^Inverse Round (\d+)/;
const ADD_ROUND_KEY_TYPE = "generic.add-round-key@1";
const KEY_EXPANSION_V1 = "aes.key-expansion@1";
const KEY_EXPANSION_V2 = "aes.key-expansion@2";

/**
 * Renumber one round group: rewrite the group's id, the canonical prefix
 * on every child leaf id, the group's display label if it follows the
 * canonical "Round N" / "Inverse Round N" pattern, and any AddRoundKey
 * leaf's `auxName` that points at `roundKey.{fromN}`. Records every id
 * rewrite into `renames` so the layout migration can follow.
 *
 * Non-canonical children (e.g. user-inserted leaves the palette added
 * inside this round) pass through unchanged for ids/labels but still get
 * the auxName bump if they're AddRoundKey leaves with the matching index.
 */
const renumberRoundGroup = (
  group: StepGroup,
  fromN: number,
  toN: number,
  direction: "forward" | "reverse",
  renames: Map<string, string>,
): StepGroup => {
  const idPrefix = direction === "forward" ? "round" : "inv-round";
  const oldGroupId = `${idPrefix}.${fromN}`;
  const newGroupId = `${idPrefix}.${toN}`;
  if (group.id === oldGroupId) renames.set(oldGroupId, newGroupId);

  const oldChildPrefix = `${idPrefix}.${fromN}.`;
  const newChildPrefix = `${idPrefix}.${toN}.`;
  const oldAuxName = `roundKey.${fromN}`;
  const newAuxName = `roundKey.${toN}`;

  const newChildren = group.children.map((child) => {
    if (child.kind !== "step") {
      // Nested groups inside a round group aren't a shape any canonical
      // AES spec produces, but the data model allows them. Leave the inner
      // id alone — only the outer round's renumber is in scope here.
      return child;
    }
    let newId = child.id;
    if (child.id.startsWith(oldChildPrefix)) {
      newId = newChildPrefix + child.id.slice(oldChildPrefix.length);
      renames.set(child.id, newId);
    }
    let newParams = child.params;
    if (child.type === ADD_ROUND_KEY_TYPE) {
      const p = child.params as { readonly auxName?: unknown };
      if (p && typeof p.auxName === "string" && p.auxName === oldAuxName) {
        newParams = { ...(p as Record<string, Json>), auxName: newAuxName };
      }
    }
    return { ...child, id: newId, params: newParams };
  });

  // Update the label if it follows the canonical pattern, preserving any
  // suffix the user might've left (e.g. " (final, no MixColumns)").
  const labelRe = direction === "forward" ? ROUND_LABEL_RE : INV_ROUND_LABEL_RE;
  let newLabel = group.label;
  if (typeof group.label === "string") {
    const m = group.label.match(labelRe);
    if (m) {
      const baseWord = direction === "forward" ? "Round" : "Inverse Round";
      const suffix = group.label.slice(m[0].length);
      newLabel = `${baseWord} ${toN}${suffix}`;
    }
  }

  return {
    ...group,
    id: newGroupId,
    ...(newLabel !== undefined ? { label: newLabel } : {}),
    children: newChildren,
  };
};

/**
 * Bump the `roundKey.K` auxName on `inv-initial.add-round-key` by 1.
 * Returns the original leaf reference if no bump applies (params shape
 * unexpected, auxName doesn't match the pattern) so reference equality
 * holds when the surrounding mutation is a no-op.
 */
const bumpInvInitialAuxName = (leaf: StepLeaf): StepLeaf => {
  if (leaf.type !== ADD_ROUND_KEY_TYPE) return leaf;
  const p = leaf.params as { readonly auxName?: unknown };
  if (!p || typeof p.auxName !== "string") return leaf;
  const m = p.auxName.match(/^roundKey\.(\d+)$/);
  if (!m || !m[1]) return leaf;
  const k = Number.parseInt(m[1], 10);
  return {
    ...leaf,
    params: { ...(p as Record<string, Json>), auxName: `roundKey.${k + 1}` },
  };
};

/**
 * Locate the AES key-expansion leaf at the top level of `spec.steps`,
 * bump its `rounds` param by 1, and morph the type from `@1 → @2` (the
 * schedule needs the relaxed-rounds executor to accept the new count).
 * Throws if no key-expansion leaf exists at the top level — every
 * shipped AES spec puts it there, including ECB (key-expansion sits
 * outside the iterate so it runs once).
 */
const bumpKeyExpansion = (spec: CipherSpec): CipherSpec => {
  let found = false;
  const newSteps = spec.steps.map((node) => {
    if (found) return node;
    if (
      node.kind === "step" &&
      (node.type === KEY_EXPANSION_V1 || node.type === KEY_EXPANSION_V2)
    ) {
      found = true;
      const p = node.params as { readonly rounds?: unknown };
      const currentRounds = typeof p?.rounds === "number" ? p.rounds : 0;
      return {
        ...node,
        type: KEY_EXPANSION_V2,
        params: {
          ...(p as Record<string, Json>),
          rounds: currentRounds + 1,
        },
      };
    }
    return node;
  });
  if (!found) {
    throw new Error(
      "duplicateRoundGroup: no aes.key-expansion@* leaf at the top level of the spec",
    );
  }
  return { ...spec, steps: newSteps };
};

/**
 * Insert a clone of an AES round group, renumber siblings + key schedule
 * accordingly, and return the updated spec plus a `oldId → newId` rename
 * map. See the section header above for the forward/reverse semantics.
 *
 * Throws if `sourceId` doesn't resolve to a group node, if the id doesn't
 * follow the round/inv-round naming convention for the requested
 * direction, or if no top-level key-expansion leaf is found.
 */
export const duplicateRoundGroup = (
  spec: CipherSpec,
  sourceId: string,
  direction: "forward" | "reverse",
): DuplicateRoundResult => {
  const loc = findStepAndParent(spec, sourceId);
  if (!loc) throw new Error(`duplicateRoundGroup: no node with id "${sourceId}"`);
  if (loc.node.kind !== "group") {
    throw new Error(
      `duplicateRoundGroup: source "${sourceId}" must be a group, got ${loc.node.kind}`,
    );
  }
  const idRe = direction === "forward" ? ROUND_ID_RE : INV_ROUND_ID_RE;
  const m = sourceId.match(idRe);
  if (!m || !m[1]) {
    throw new Error(
      `duplicateRoundGroup: source id "${sourceId}" doesn't match the round-id format for direction "${direction}"`,
    );
  }
  const sourceN = Number.parseInt(m[1], 10);
  const cloneN = sourceN + 1;
  const renames = new Map<string, string>();

  // Build the clone: same source group renumbered to the next round
  // index. The clone itself isn't a rename of an existing id (no entry
  // in `renames`), but its AddRoundKey auxName points at `roundKey.{cloneN}`
  // so the bumped schedule's new entry feeds it.
  const clone = renumberRoundGroupClone(loc.node, sourceN, cloneN, direction);

  // Walk the immediate parent's children. Insert the clone and renumber
  // affected siblings in one pass.
  const oldChildren = loc.parent ? loc.parent.children : spec.steps;
  const sourceIdx = loc.indexInParent;
  const newChildren: StepNode[] = [];

  if (direction === "forward") {
    // Keep everything up to and including source unchanged.
    for (let i = 0; i <= sourceIdx; i++) {
      const n = oldChildren[i];
      if (n) newChildren.push(n);
    }
    // Splice clone in.
    newChildren.push(clone);
    // Renumber subsequent siblings whose ids match `round.K`. Other node
    // kinds (e.g. iterate, non-round groups, leaves like split/concat
    // for multi-block parents) pass through.
    for (let i = sourceIdx + 1; i < oldChildren.length; i++) {
      const n = oldChildren[i];
      if (!n) continue;
      if (n.kind === "group") {
        const km = n.id.match(idRe);
        if (km?.[1]) {
          const k = Number.parseInt(km[1], 10);
          newChildren.push(renumberRoundGroup(n, k, k + 1, direction, renames));
          continue;
        }
      }
      newChildren.push(n);
    }
  } else {
    // reverse: walk earlier siblings; renumber inv-round.K (K > sourceN)
    // and bump the inv-initial.add-round-key auxName. Source and later
    // siblings (lower inv-round numbers, plus inv-round.0) pass through.
    for (let i = 0; i < sourceIdx; i++) {
      const n = oldChildren[i];
      if (!n) continue;
      if (n.kind === "step" && n.id === "inv-initial.add-round-key") {
        newChildren.push(bumpInvInitialAuxName(n));
        continue;
      }
      if (n.kind === "group") {
        const km = n.id.match(idRe);
        if (km?.[1]) {
          const k = Number.parseInt(km[1], 10);
          if (k > sourceN) {
            newChildren.push(renumberRoundGroup(n, k, k + 1, direction, renames));
            continue;
          }
        }
      }
      newChildren.push(n);
    }
    // Insert clone immediately before source.
    newChildren.push(clone);
    // Source + everything after stays as-is.
    for (let i = sourceIdx; i < oldChildren.length; i++) {
      const n = oldChildren[i];
      if (n) newChildren.push(n);
    }
  }

  // Splice the rebuilt array back into the spec. If source was at the
  // top level (no parent), we replace `spec.steps` directly. Otherwise
  // walk the tree once to replace the parent's children — reusing the
  // existing `transformParentArray` would re-search by id, but the
  // child-array transform fits its signature cleanly.
  let specAfterSplice: CipherSpec;
  if (loc.parent === null) {
    specAfterSplice = { ...spec, steps: newChildren };
  } else {
    const replaced = replaceParentChildrenByRef(spec, loc.parent, newChildren);
    if (!replaced) {
      throw new Error("duplicateRoundGroup: internal — could not splice children back into parent");
    }
    specAfterSplice = replaced;
  }

  // Finally, bump the key schedule. This is independent of which parent
  // held the source — key-expansion is always at the top level (single-
  // block and ECB both put it there, outside the iterate).
  const finalSpec = bumpKeyExpansion(specAfterSplice);
  return { spec: finalSpec, renames };
};

/**
 * Clone variant of `renumberRoundGroup` for the freshly-inserted copy.
 * The clone is a NEW group, not a rename of an existing one — so we
 * don't write to the rename map (no old id existed to map FROM). Behavior
 * is otherwise identical to the live renumber path.
 */
const renumberRoundGroupClone = (
  group: StepGroup,
  fromN: number,
  toN: number,
  direction: "forward" | "reverse",
): StepGroup => {
  // Reuse the same logic but throw away the rename entries; the clone's
  // ids are new and have no old layout pins to migrate.
  const discardedRenames = new Map<string, string>();
  return renumberRoundGroup(group, fromN, toN, direction, discardedRenames);
};

/**
 * Walk the spec, find the exact parent reference, and return a new spec
 * with that parent's children replaced. Returns null if the parent isn't
 * found (treated as an internal error by the caller — it just was located
 * by `findStepAndParent`). Branches without the parent reuse their
 * original references.
 */
const replaceParentChildrenByRef = (
  spec: CipherSpec,
  parent: StepGroup | IterateGroup,
  newChildren: readonly StepNode[],
): CipherSpec | null => {
  let found = false;
  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    return nodes.map((n) => {
      if (found) return n;
      if (n === parent) {
        found = true;
        return { ...n, children: newChildren };
      }
      if (n.kind === "step") return n;
      // AES-only path: `duplicateRoundGroup` (the only caller of this
      // helper) never targets a parent inside a feistel-round. Treat
      // feistel-round as opaque for now; Phase 3 will revisit if DES
      // ever needs a structural splice via this helper.
      if (n.kind === "feistel-round") return n;
      const next = visit(n.children);
      if (next === n.children) return n;
      return { ...n, children: next };
    });
  };
  const newSteps = visit(spec.steps);
  if (!found) return null;
  return { ...spec, steps: newSteps };
};

// ─── Padding-scheme overlay ───────────────────────────────────────────────
// Layer a padding chain onto a canonical cipher spec without modifying the
// canonical spec itself. The step types listed in `PADDING_STEP_TYPES` are
// reserved for this overlay — `applyPaddingScheme` strips any existing
// instance before inserting the new chain, so calling it repeatedly with
// the same scheme is a no-op (idempotent).
//
// Encrypt + <scheme>: prepend [<scheme>-pad → load-block] to spec.steps. Input
//   shape becomes `bytes` (variable-length); the runtime seeds with BytesState
//   and the load-block frame transitions to MatrixState before AES runs.
// Decrypt + <scheme>: append   [store-block → <scheme>-unpad] to spec.steps.
//   Input shape stays `matrix4x4-bytes` (the ciphertext is one block). The
//   final state after the chain is BytesState (0..blockSize bytes of
//   recovered plaintext, depending on scheme).
// scheme=none: strips any existing chain and returns the canonical spec
//   unchanged (or as close to it as `applyPaddingScheme` was last fed).
//
// Adding a new scheme: register the pad/unpad step types in the registry,
// extend the `PaddingScheme` union below, add its (pad, unpad) type pair
// to `SCHEME_STEP_TYPES`, and (in the UI store) extend `paddingLimits` +
// `PADDING_SCHEME_LABELS`. No edits to the rest of this function needed.

export type PaddingScheme = "none" | "pkcs7" | "zero-pad" | "iso7816-4";

/**
 * Per-scheme step-type pair. Keyed by every non-`none` scheme so the
 * encrypt/decrypt overlay branches can build leaves without a per-scheme
 * `if` ladder. Extending: register the step types, then add a row here.
 */
const SCHEME_STEP_TYPES: Record<
  Exclude<PaddingScheme, "none">,
  { padType: string; unpadType: string; padId: string; unpadId: string }
> = {
  pkcs7: {
    padType: "generic.pkcs7-pad@1",
    unpadType: "generic.pkcs7-unpad@1",
    padId: "pkcs7-pad",
    unpadId: "pkcs7-unpad",
  },
  "zero-pad": {
    padType: "generic.zero-pad@1",
    unpadType: "generic.zero-unpad@1",
    padId: "zero-pad",
    unpadId: "zero-unpad",
  },
  "iso7816-4": {
    padType: "generic.iso7816-4-pad@1",
    unpadType: "generic.iso7816-4-unpad@1",
    padId: "iso7816-4-pad",
    unpadId: "iso7816-4-unpad",
  },
};

/**
 * Step types reserved for the padding overlay. Derived from
 * `SCHEME_STEP_TYPES` plus the two shape-bridge steps so adding a new
 * scheme automatically extends what gets stripped on a re-apply.
 *
 * Exported (Slice 8) so the palette can exclude these types — they're
 * managed by the padding selector and would silently vanish on the next
 * padding toggle if a user palette-dropped one (see `applyPaddingScheme`
 * below: every call starts with `stripPaddingLeaves(spec.steps)`).
 */
export const PADDING_STEP_TYPES: ReadonlySet<string> = new Set<string>([
  ...Object.values(SCHEME_STEP_TYPES).flatMap((s) => [s.padType, s.unpadType]),
  "generic.load-block@1",
  "generic.store-block@1",
]);

/** AES block size — the only value supported by this overlay today. */
const AES_BLOCK_SIZE = 16;

/**
 * Strip every top-level leaf whose `type` is in `PADDING_STEP_TYPES`. We
 * walk only the top level: the canonical AES specs put all their per-round
 * work inside `group` nodes, and the overlay's pad/load/unpad/store leaves
 * are always inserted at the top — so a top-level filter cleans the overlay
 * without risking damage to round groups.
 */
const stripPaddingLeaves = (steps: readonly StepNode[]): readonly StepNode[] =>
  steps.filter((n) => !(n.kind === "step" && PADDING_STEP_TYPES.has(n.type)));

/**
 * Detect a multi-block cipher spec by looking for an `iterate` node at the
 * top level. Multi-block AES (ECB/CBC/CTR factories) put their iterate
 * loop at the top level; non-iterating specs (single-block AES, Speck)
 * don't have one. Used to branch `applyPaddingScheme`: multi-block specs
 * already do their own BytesState↔MatrixState shape handling inside the
 * loop, so the overlay only needs to add pad/unpad — no load/store-block.
 */
const hasIterateNode = (steps: readonly StepNode[]): boolean =>
  steps.some((n) => n.kind === "iterate");

/**
 * Layer a padding chain onto a cipher spec.
 *
 * Idempotent: any pre-existing padding leaves are stripped before the new
 * chain is inserted, so feeding the same (spec, mode, scheme) pair twice
 * produces structurally equivalent output. The canonical spec is reachable
 * by passing scheme=`"none"` — useful when the user toggles the padding
 * selector back to off.
 *
 * Three shape branches:
 *  1. Multi-block AES (has an `iterate` node) — pad on encrypt / unpad on
 *     decrypt, no load/store-block (the iterate body handles state shape).
 *  2. Single-block AES (`stateShape === "matrix4x4-bytes"`) — today's path:
 *     prepend [pad, load-block] on encrypt or append [store-block, unpad]
 *     on decrypt.
 *  3. Anything else (Speck32/64) — overlay is a no-op for now; the user's
 *     preference is preserved in the store and re-applies when the user
 *     flips back to an AES variant.
 *
 * Pure: returns a new spec; the input spec is not mutated. New StepLeaf
 * objects are emitted on each call (no shared param references between
 * leaves — that's the same hygiene the cipher-spec factories follow).
 */
export const applyPaddingScheme = (
  spec: CipherSpec,
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
): CipherSpec => {
  const stripped = stripPaddingLeaves(spec.steps);

  // ── Branch 1: multi-block (ECB/CBC/CTR) ────────────────────────────────
  // The iterate node already handles BytesState ↔ MatrixState transitions
  // via the split-blocks / concat-blocks boundary steps inside the spec.
  // All we add here is the pad/unpad at the outer BytesState boundary.
  if (hasIterateNode(stripped)) {
    if (scheme === "none") {
      return { ...spec, steps: stripped };
    }
    const { padType, unpadType, padId, unpadId } = SCHEME_STEP_TYPES[scheme];
    if (mode === "encrypt") {
      const padLeaf: StepLeaf = {
        kind: "step",
        id: padId,
        type: padType,
        params: { blockSize: AES_BLOCK_SIZE },
      };
      return { ...spec, steps: [padLeaf, ...stripped] };
    }
    // decrypt
    const unpadLeaf: StepLeaf = {
      kind: "step",
      id: unpadId,
      type: unpadType,
      params: { blockSize: AES_BLOCK_SIZE },
    };
    return { ...spec, steps: [...stripped, unpadLeaf] };
  }

  // ── Branch 3: non-AES single-block (Speck) ─────────────────────────────
  // The padding overlay's load-block/store-block leaves are hardcoded for
  // AES's 4×4 byte matrix. For any cipher whose state shape isn't that
  // matrix (today: Speck32/64, which uses BytesState) the overlay can't
  // apply meaningfully — silently skip it and return the canonical spec.
  // The padding store still carries the user's preference, so flipping
  // back to an AES variant re-applies the choice without losing it.
  // A future block-size-aware load/store rework will let Speck adopt the
  // same padding chain.
  if (spec.stateShape !== "matrix4x4-bytes") {
    return { ...spec, steps: stripped };
  }

  if (scheme === "none") {
    // Canonical path: matrix-direct input, no padding chain. Keep the
    // original `inputs.plaintext.shape` and `stateShape` since the
    // canonical specs already describe the matrix-direct flow.
    return {
      ...spec,
      stateShape: "matrix4x4-bytes",
      inputs: {
        ...spec.inputs,
        plaintext: { shape: "matrix4x4-bytes" },
      },
      steps: stripped,
    };
  }

  const { padType, unpadType, padId, unpadId } = SCHEME_STEP_TYPES[scheme];

  if (mode === "encrypt") {
    const padLeaf: StepLeaf = {
      kind: "step",
      id: padId,
      type: padType,
      params: { blockSize: AES_BLOCK_SIZE },
    };
    const loadLeaf: StepLeaf = {
      kind: "step",
      id: "load-block",
      type: "generic.load-block@1",
      params: { blockSize: AES_BLOCK_SIZE },
    };
    // Input now arrives as BytesState (variable length, range depends on
    // scheme — see paddingLimits in the UI store). The load-block frame
    // is the visible transition into the AES 4×4 matrix.
    const plaintextShape: StateShape = "bytes";
    return {
      ...spec,
      stateShape: "matrix4x4-bytes",
      inputs: {
        ...spec.inputs,
        plaintext: { shape: plaintextShape },
      },
      steps: [padLeaf, loadLeaf, ...stripped],
    };
  }

  // mode === "decrypt"
  const storeLeaf: StepLeaf = {
    kind: "step",
    id: "store-block",
    type: "generic.store-block@1",
    params: {},
  };
  const unpadLeaf: StepLeaf = {
    kind: "step",
    id: unpadId,
    type: unpadType,
    params: { blockSize: AES_BLOCK_SIZE },
  };
  // Decrypt input is still the 16-byte ciphertext block — matrix-direct.
  // The unpad chain runs at the END, after AES has finished, producing
  // a BytesState of the recovered plaintext.
  return {
    ...spec,
    stateShape: "matrix4x4-bytes",
    inputs: {
      ...spec.inputs,
      plaintext: { shape: "matrix4x4-bytes" },
    },
    steps: [...stripped, storeLeaf, unpadLeaf],
  };
};
