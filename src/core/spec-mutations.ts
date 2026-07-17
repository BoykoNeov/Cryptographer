/**
 * Pure helpers that produce new CipherSpec values from old ones. The spec
 * tree is `readonly`, so mutations always return a fresh tree — Solid stores
 * compare references to decide what to re-render, so handing back the same
 * object would cause subtle bugs.
 *
 * These exist so the UI can edit a single step's params (e.g. "swap the
 * S-box") without knowing how to walk the tree itself.
 */

// Layering exception (key-schedule-decomposition K1b): `duplicateRoundGroup`
// is AES-specific by construction (it hardcodes `round.N` / `roundKey.N` and
// the `key-schedule` group id), so it legitimately reaches into the AES
// key-schedule builder to REBUILD the decomposed schedule at the new round
// count. This is the one core→ciphers import; it's justified by this function
// not being generic core. See `bumpKeyExpansion` below.
import { buildAesKeyScheduleNative } from "../ciphers/aes-key-schedule-builder-native";
import type {
  CipherSpec,
  ForEachSubgraphNode,
  ForEachSubgraphWithHistoryNode,
  IterateGroup,
  Json,
  PortBinding,
  StepGroup,
  StepLeaf,
  StepNode,
} from "./types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "./types";

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

// ─── Rewiring one input port ──────────────────────────────────────────────

/**
 * Rebind (or clear) ONE input port on a leaf step. Returns a NEW spec; the
 * original is untouched. This is the headless core of the port-wiring editor
 * (universal-port plan Phase 4d-bis): the in-app affordance for the user to
 * change which upstream output port an input port reads from. Until this
 * landed, `portInputs` was source-file-only (every shipped cipher declared
 * its wiring in TypeScript).
 *
 * `binding` of `null` CLEARS the port (deletes the key from `portInputs`),
 * which is how the dropdown's "— unwired —" choice flows through. A non-null
 * binding overwrites (or adds) the entry for `portName`.
 *
 * **This function imposes NO legality check.** Scope-legality (only same-scope
 * sources are reachable at runtime) is enforced UPSTREAM, by the editor only
 * ever offering scope-legal targets (`legalSourcesForInput` in
 * `port-sources.ts`) — so a cross-scope binding can never be constructed here.
 * Shape (byteLength) mismatches are deliberately allowed: they coerce at run
 * time as a visible trace step ("permissiveness IS the pedagogy"). Keeping
 * this mutation a dumb setter mirrors `updateStepParams` and keeps the
 * round-trip (Save/Share/Load) trivially correct — no schema bump, since
 * `portInputs` is already part of `StepLeaf`.
 *
 * Ref-equality is preserved on every untouched branch (Solid stores diff by
 * reference). If `stepId` matches no leaf — or the requested change is a
 * no-op (clearing an already-absent port, or rebinding to the identical
 * target) — the ORIGINAL spec is returned by reference so the caller can
 * detect the no-op via `result === spec` and skip a redundant re-run.
 */
export const setPortBinding = (
  spec: CipherSpec,
  stepId: string,
  portName: string,
  binding: PortBinding | null,
): CipherSpec => {
  let changed = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    return nodes.map((node) => {
      if (node.kind === "step") {
        if (node.id !== stepId) return node;

        const current = node.portInputs?.[portName];
        if (binding === null) {
          // Clearing a port that isn't bound is a no-op — return by reference.
          if (current === undefined) return node;
          // Rebuild portInputs without this key. `{ [portName]: _, ...rest }`
          // destructure-omit keeps the other bindings intact by value.
          const { [portName]: _dropped, ...rest } = node.portInputs ?? {};
          changed = true;
          // Normalize an emptied map back to ABSENT (not `{}`) so two
          // semantically-equal specs serialize identically — preserving the
          // "spec-only saves are byte-stable" property the URL-share hash
          // relies on. Strip the key entirely rather than leaving `portInputs: {}`.
          if (Object.keys(rest).length === 0) {
            const { portInputs: _omit, ...nodeWithout } = node;
            return nodeWithout;
          }
          return { ...node, portInputs: rest };
        }

        // Rebinding to the identical target is a no-op — return by reference.
        if (
          current !== undefined &&
          current.node === binding.node &&
          current.port === binding.port
        ) {
          return node;
        }
        changed = true;
        return {
          ...node,
          portInputs: { ...node.portInputs, [portName]: binding },
        };
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
 *
 * **`idFilter` — role-scoping for a type used in two roles.** Some step
 * types appear in distinct semantic roles distinguished only by leaf id.
 * Since the key-schedule-decomposition (2026-06-01), `byte-substitute@1`
 * is BOTH round-body SubBytes (class-2 inverse cross-mode mirror) AND
 * key-schedule SubWord (class-1 identity mirror — the schedule uses the
 * FORWARD S-box even when decrypting, FIPS-197 §5.2). A type-wide
 * broadcast across all `byte-substitute@1` leaves would corrupt one role
 * with the other's value. When `idFilter` is supplied, only matching-type
 * leaves whose id ALSO passes the filter are updated; the rest are returned
 * by reference (preserving structural sharing + the no-op short-circuit).
 */
export const updateAllStepsByType = (
  spec: CipherSpec,
  stepType: string,
  update: (params: Json) => Json,
  idFilter?: (id: string) => boolean,
): CipherSpec => {
  let changed = false;

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    return nodes.map((node) => {
      if (node.kind === "step") {
        if (node.type !== stepType) return node;
        if (idFilter && !idFilter(node.id)) return node;
        const newParams = update(node.params);
        if (newParams === node.params) return node;
        changed = true;
        return { ...node, params: newParams };
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

// ─── Editing a published cipher constant ──────────────────────────────────

/**
 * Replace the bytes of one named entry in `spec.cipherConstants`
 * (scaffolding-suppression A1). Returns a NEW spec; the original is
 * untouched. No-op (returns `spec` by reference) when the spec has no
 * `cipherConstants` or no entry named `name` — the constants editor only
 * surfaces names that exist, so a miss means a stale id.
 *
 * Other constants are preserved by reference. The runtime re-materializes
 * the edited bytes into `aux[name]` on the next run, so every consumer
 * (every `aux-load-bytes@1` that reads `name`) sees the new value in
 * lockstep — that single-source-of-truth property is the whole point of
 * moving constants off per-step params.
 */
export const updateCipherConstant = (
  spec: CipherSpec,
  name: string,
  bytes: Uint8Array,
): CipherSpec => {
  const current = spec.cipherConstants;
  if (!current || !(name in current)) return spec;
  return { ...spec, cipherConstants: { ...current, [name]: bytes } };
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
        // param edits inside an iterate body show up in the diff. We
        // explicitly enumerate each container kind to keep TS happy AND
        // preserve the descent semantics across all of them.
        visit(x.children, y.children);
      } else if (x.kind === "for-each-subgraph" && y.kind === "for-each-subgraph") {
        // Same rationale as the iterate branch — descend into bodies so
        // param edits inside a for-each-subgraph surface in run-history-diff.
        visit(x.children, y.children);
      } else if (
        x.kind === "for-each-subgraph-with-history" &&
        y.kind === "for-each-subgraph-with-history"
      ) {
        // Slice 2.0c — same descent posture as the other iteration kinds.
        // Lookback-offsets / historyEntryByteLength / iterationCount edits
        // surface via the structural-change path (kind matches but the
        // offset arrays differ); body param edits surface via the recursion.
        visit(x.children, y.children);
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
 *  - `parent` is the container holding it, or `null` when the node
 *    lives at the top level of `spec.steps`.
 *  - `indexInParent` is the node's position in its sibling array.
 *
 * Unlike `findStep` (leaves-only), this returns ANY node kind so the
 * visual editor can anchor inserts to groups too (e.g. "drop this new step
 * after the round.5 group, not inside it").
 */
export type StepLocation = {
  readonly node: StepNode;
  readonly parent:
    | StepGroup
    | IterateGroup
    | ForEachSubgraphNode
    | ForEachSubgraphWithHistoryNode
    | null;
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
    parent: StepGroup | IterateGroup | ForEachSubgraphNode | ForEachSubgraphWithHistoryNode | null,
  ): StepLocation | null => {
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i];
      if (!node) continue;
      if (node.id === stepId) return { node, parent, indexInParent: i };
      if (node.kind === "step") continue;
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
        found = true;
        mutated = true;
        return { ...n, children: [newStep, ...n.children] };
      }
      if (n.kind === "step") return n;
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
/** Pre-F3 byte-native AddRoundKey's round-key fetch leaf (carried `auxName:
 *  roundKey.N`). Superseded by `xor-with-aux@1` below; kept in the bump
 *  predicates as a harmless no-op for any older in-flight spec. */
const AUX_LOAD_BYTES_TYPE = "aux-load-bytes@1";
/** Byte-native AddRoundKey (Finding F3, 2026-05-30): a single `xor-with-aux@1`
 *  leaf that reads `roundKey.N` from aux via `params.auxName` (replaced the
 *  fetch-rk + xor pair). Its `auxName` is what the round renumber bumps. */
const XOR_WITH_AUX_TYPE = "xor-with-aux@1";
// The DECOMPOSED key schedule (key-schedule-decomposition K1a) is a single
// top-level group with this id; its publish tail carries the round count.
const KEY_SCHEDULE_GROUP_ID = "key-schedule";
const PUBLISH_ROUND_KEYS_TYPE = "aes.publish-round-keys@1";

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

  // Port-binding node remap (byte-native rounds, Slice B1). A round's
  // internal port edges reference either the group's own `in` port (the
  // group id) or a sibling leaf by its `round.N.*` id. Both renumber
  // mechanically: `port(round.N, …) → port(round.toN, …)` and
  // `port(round.N.x, …) → port(round.toN.x, …)`. Cross-boundary `seedInput`
  // is NOT mechanical (it points at the PREVIOUS round, which shifts +1) and
  // is recomputed below. Returns the same reference when nothing changes so
  // legacy matrix rounds (no portInputs) stay reference-stable.
  const remapBindingNode = (b: PortBinding): PortBinding => {
    if (b.node === oldGroupId) return port(newGroupId, b.port);
    if (b.node.startsWith(oldChildPrefix)) {
      return port(newChildPrefix + b.node.slice(oldChildPrefix.length), b.port);
    }
    return b;
  };
  const remapPortInputs = (
    pi: Readonly<Record<string, PortBinding>> | undefined,
  ): Readonly<Record<string, PortBinding>> | undefined => {
    if (pi === undefined) return undefined;
    let changed = false;
    const next: Record<string, PortBinding> = {};
    for (const [k, b] of Object.entries(pi)) {
      const nb = remapBindingNode(b);
      if (nb !== b) changed = true;
      next[k] = nb;
    }
    return changed ? next : pi;
  };

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
    // Bump the round-key auxName on whichever leaf consumes it. Legacy
    // matrix rounds carry it on `generic.add-round-key@1`; byte-native rounds
    // carry it on the merged `xor-with-aux@1` AddRoundKey leaf (Finding F3)
    // via `params.auxName`. (`aux-load-bytes@1` was the pre-F3 fetch-rk leaf
    // — kept in the predicate as a harmless no-op for older in-flight specs.)
    let newParams = child.params;
    if (
      child.type === ADD_ROUND_KEY_TYPE ||
      child.type === AUX_LOAD_BYTES_TYPE ||
      child.type === XOR_WITH_AUX_TYPE
    ) {
      const p = child.params as { readonly auxName?: unknown };
      if (p && typeof p.auxName === "string" && p.auxName === oldAuxName) {
        newParams = { ...(p as Record<string, Json>), auxName: newAuxName };
      }
    }
    // Byte-native rounds wire their internal data flow via portInputs;
    // remap those references to the renumbered ids. Absent on legacy
    // matrix rounds ⇒ reference-stable no-op.
    const newPortInputs = remapPortInputs(child.portInputs);
    return {
      ...child,
      id: newId,
      params: newParams,
      ...(newPortInputs !== undefined ? { portInputs: newPortInputs } : {}),
    };
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

  // Byte-native group port contract (Slice B1). `bodyOutput` points at a
  // direct child (`round.N.add-round-key`) and renumbers mechanically.
  // `seedInput` crosses the group boundary to the PREVIOUS round's output,
  // so it can't be remapped through the rename map — the predecessor shifts
  // +1 for BOTH the clone (which seeds from its source, = toN-1) and every
  // renumbered sibling. Recompute it from the new index instead. Forward
  // only: the byte-native decrypt rounds (with their own seedInput chain)
  // land in Slice B1.2; today's reverse path is matrix (no seedInput).
  const newBodyOutput =
    group.bodyOutput !== undefined ? remapBindingNode(group.bodyOutput) : undefined;
  let newSeedInput = group.seedInput;
  if (group.seedInput !== undefined && direction === "forward") {
    // round 1 seeds from the initial AddRoundKey LEAF (its output port is
    // "output"); rounds ≥2 seed from the previous round GROUP's published
    // "out" port — matching `buildAesEncryptBodyNative`. `toN === 1` is
    // unreachable via duplicate (clone/renumber targets are always ≥2) but
    // kept correct for completeness.
    newSeedInput =
      toN === 1 ? port("initial.add-round-key", "output") : port(`round.${toN - 1}`, "out");
  }

  return {
    ...group,
    id: newGroupId,
    ...(newLabel !== undefined ? { label: newLabel } : {}),
    children: newChildren,
    ...(newSeedInput !== undefined ? { seedInput: newSeedInput } : {}),
    ...(newBodyOutput !== undefined ? { bodyOutput: newBodyOutput } : {}),
  };
};

/**
 * Bump the `roundKey.K` auxName on the inverse-initial AddRoundKey by 1.
 * The auxName lives on different leaves in the two AES shapes: the legacy
 * matrix decrypt carries it on `inv-initial.add-round-key`
 * (`generic.add-round-key@1`); the byte-native decrypt (Finding F3) carries
 * it on the SAME id `inv-initial.add-round-key`, now a `xor-with-aux@1` leaf
 * whose `params.auxName` holds `roundKey.{rounds}`. (Pre-F3 byte-native
 * decrypt carried it on a separate `inv-initial.fetch-rk` `aux-load-bytes@1`
 * leaf — that type stays in the predicate as a harmless no-op.) This helper
 * accepts all three leaf types and only acts on the one whose params actually
 * hold a matching `auxName`.
 *
 * Returns the original leaf reference if no bump applies (wrong type, params
 * shape unexpected, auxName doesn't match the pattern) so reference equality
 * holds when the surrounding mutation is a no-op.
 */
const bumpInvInitialAuxName = (leaf: StepLeaf): StepLeaf => {
  if (
    leaf.type !== ADD_ROUND_KEY_TYPE &&
    leaf.type !== AUX_LOAD_BYTES_TYPE &&
    leaf.type !== XOR_WITH_AUX_TYPE
  )
    return leaf;
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

/** Nk (master-key words) from the spec's declared key length (16/24/32 → 4/6/8). */
const aesNkFromSpec = (spec: CipherSpec): number => {
  const byteLength = spec.inputs.key.byteLength;
  if (byteLength !== 16 && byteLength !== 24 && byteLength !== 32) {
    throw new Error(
      `duplicateRoundGroup: spec.inputs.key.byteLength must be 16/24/32 (got ${byteLength})`,
    );
  }
  return byteLength / 4;
};

/**
 * Bump the AES key schedule for a duplicated round by REBUILDING it at the new
 * round count. The key schedule is the decomposed `key-schedule` group
 * (key-schedule-decomposition K1a); its internal structure (recurrence groups,
 * word count, the Nk-vs-round-key repack) is a function of the round count, so
 * it cannot be bumped by editing a param the way the old monolithic leaf was.
 * `buildAesKeyScheduleNative(rounds+1, Nk)` regenerates it — including a longer
 * Rcon sequence (computed at build time) — which is exactly why duplicate-round
 * is agnostic to the unroll-vs-iterate structure (advisor 2026-06-01).
 *
 * Current round count is read off the publish tail's `rounds` param; Nk from
 * the spec's declared key length. Throws if no top-level `key-schedule` group
 * exists — every shipped AES spec puts it there (single-block AND ECB/CBC,
 * outside the iterate so it runs once).
 */
const bumpKeyExpansion = (spec: CipherSpec): CipherSpec => {
  let found = false;
  const newSteps = spec.steps.map((node) => {
    if (found) return node;
    if (node.kind === "group" && node.id === KEY_SCHEDULE_GROUP_ID) {
      found = true;
      const publish = node.children.find(
        (c): c is StepLeaf => c.kind === "step" && c.type === PUBLISH_ROUND_KEYS_TYPE,
      );
      const p = publish?.params as { readonly rounds?: unknown } | undefined;
      const currentRounds = typeof p?.rounds === "number" ? p.rounds : 0;
      return buildAesKeyScheduleNative(currentRounds + 1, aesNkFromSpec(spec));
    }
    return node;
  });
  if (!found) {
    throw new Error(
      "duplicateRoundGroup: no top-level `key-schedule` group in the spec (expected the decomposed AES key schedule from buildAesKeyScheduleNative)",
    );
  }
  return { ...spec, steps: newSteps };
};

/**
 * Recompute the byte-native decrypt `seedInput` chain across a freshly
 * assembled list of reverse-direction children (Slice B1.2).
 *
 * The forward duplicate recomputes each round's `seedInput` inline during the
 * renumber walk because the predecessor (`round.{toN-1}`) is a pure function
 * of the new index. The reverse chain is the dual and DESCENDS — the highest
 * inverse round seeds from `inv-initial.add-round-key`, every lower one from
 * the next-HIGHER round's exit — so a renumbered round's correct seed depends
 * on the post-insert neighbour set, which the per-group renumber walk can't
 * see. Three positions would otherwise need bespoke handling: the clone, the
 * renumbered siblings, AND the (unchanged) source round when it WAS the anchor
 * (duplicating the highest inverse round bumps the clone into the anchor slot,
 * leaving the source needing to seed from the clone). Recomputing the whole
 * chain positionally here erases all three special cases.
 *
 * No-op for the legacy matrix decrypt: its inverse round groups carry no
 * `seedInput` (the matrix state threads implicitly), so this returns the same
 * children reference. Only the byte-native rebuild has `seedInput` to fix.
 */
const rewireReverseSeedInputChain = (children: readonly StepNode[]): readonly StepNode[] => {
  const invRoundIndices = children
    .filter(
      (n): n is StepGroup =>
        n.kind === "group" && n.seedInput !== undefined && INV_ROUND_ID_RE.test(n.id),
    )
    .map((g) => Number.parseInt(INV_ROUND_ID_RE.exec(g.id)?.[1] ?? "", 10));
  if (invRoundIndices.length === 0) return children; // matrix decrypt: nothing to rewire
  const maxIdx = Math.max(...invRoundIndices);

  let changed = false;
  const next = children.map((n) => {
    if (n.kind !== "group" || n.seedInput === undefined) return n;
    const m = INV_ROUND_ID_RE.exec(n.id);
    if (!m || !m[1]) return n;
    const idx = Number.parseInt(m[1], 10);
    const newSeed =
      idx === maxIdx
        ? port("inv-initial.add-round-key", "output")
        : port(`inv-round.${idx + 1}`, "out");
    if (newSeed.node === n.seedInput.node && newSeed.port === n.seedInput.port) return n;
    changed = true;
    return { ...n, seedInput: newSeed };
  });
  return changed ? next : children;
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
  // Defensive: the duplicate-round affordance is shaped around AES's
  // per-round-indexed schedule + the renumber walk's assumption that every
  // relevant child is a group/iterate/leaf. For-each-subgraph (Slice 2.0a) iterates a
  // body with `:r{i}` indexing — duplicate-round semantics on its
  // children would mean per-iteration content shifts, which isn't a
  // designed operation. Bail loudly until a motivating feature lands.
  if (loc.parent?.kind === "for-each-subgraph") {
    throw new Error(
      `duplicateRoundGroup: source "${sourceId}" lives inside a for-each-subgraph body; duplicate-round there isn't supported (per-iteration content shifts aren't a designed operation)`,
    );
  }
  if (loc.parent?.kind === "for-each-subgraph-with-history") {
    // Defensive: same rationale as the for-each-subgraph guard. Slice 2.0c
    // ships per-iteration lookback semantics; duplicating a round inside
    // the body would shift every iteration's body content, which the
    // renumber walk + the lookback indexing weren't designed for. Bail
    // loudly until a motivating feature lands.
    throw new Error(
      `duplicateRoundGroup: source "${sourceId}" lives inside a for-each-subgraph-with-history body; duplicate-round there isn't supported (per-iteration content shifts aren't a designed operation)`,
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
      // The inverse-initial round-key reference lives on `inv-initial.add-round-key`
      // — `generic.add-round-key@1` (matrix) or `xor-with-aux@1` (byte-native,
      // Finding F3). The pre-F3 `inv-initial.fetch-rk` (`aux-load-bytes@1`) is
      // gone, but matching it stays harmless. The bump no-ops on a leaf that
      // doesn't actually hold a matching auxName.
      if (
        n.kind === "step" &&
        (n.id === "inv-initial.add-round-key" || n.id === "inv-initial.fetch-rk")
      ) {
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

  // Byte-native decrypt (reverse) carries an explicit descending `seedInput`
  // chain that the per-group renumber walk can't fix locally — recompute it
  // positionally across the assembled children. No-op for matrix decrypt
  // (no `seedInput`) and for the forward direction (handled inline above).
  const splicedChildren =
    direction === "reverse" ? rewireReverseSeedInputChain(newChildren) : newChildren;

  // Splice the rebuilt array back into the spec. If source was at the
  // top level (no parent), we replace `spec.steps` directly. Otherwise
  // walk the tree once to replace the parent's children — reusing the
  // existing `transformParentArray` would re-search by id, but the
  // child-array transform fits its signature cleanly.
  let specAfterSplice: CipherSpec;
  if (loc.parent === null) {
    specAfterSplice = { ...spec, steps: splicedChildren };
  } else {
    const replaced = replaceParentChildrenByRef(spec, loc.parent, splicedChildren);
    if (!replaced) {
      throw new Error("duplicateRoundGroup: internal — could not splice children back into parent");
    }
    specAfterSplice = replaced;
  }

  // Bump the key schedule. This is independent of which parent held the
  // source — key-expansion is always at the top level (single-block and ECB
  // both put it there, outside the iterate).
  let finalSpec = bumpKeyExpansion(specAfterSplice);

  // Byte-native AES (Slice B1) names its cipher exit via `spec.outputFrom`
  // (= `port(round.{last}, "out")`). A FORWARD duplicate shifts the final
  // round up (round.10 → round.11), so the exit binding must follow the
  // rename or the cipher would publish a mid-round's output (taking the
  // result from a now-full round and SKIPPING the real final round). Legacy
  // matrix specs have no `outputFrom` (final state = walk exit) so this is a
  // no-op there; in reverse the final inv-round.0 isn't renamed so it's also
  // untouched. Remap through the same rename map the renumber built.
  if (finalSpec.outputFrom !== undefined) {
    const renamed = renames.get(finalSpec.outputFrom.node);
    if (renamed !== undefined) {
      finalSpec = { ...finalSpec, outputFrom: { ...finalSpec.outputFrom, node: renamed } };
    }
  }

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
      const next = visit(n.children);
      if (next === n.children) return n;
      return { ...n, children: next };
    });
  };
  const newSteps = visit(spec.steps);
  if (!found) return null;
  return { ...spec, steps: newSteps };
};

// ─── Composite capture + clone (compose-and-save, universal-port Phase 4f) ──
// A "composite" is a reusable, named building block the user saves out of an
// existing GROUP (e.g. an AES round) and later drops back onto any spec from
// the palette's "my elements" section. It is PURE JSON — a `StepGroup`
// template — NOT a registered step type with a synthesized executor, so the
// dropped copy's internals stay fully visible + scrubbable (the project's
// "cipher = JSON, not code" invariant). See docs/plans/compose-and-save.md.
//
// Group-scope isolation (the runtime walks a group body in an isolated
// nodeOutputs map; only the group's published `out` escapes) gives a captured
// group a clean boundary FOR FREE: exactly one port input (its `seedInput`,
// injected as `port(groupId,"in")`), one published output (`bodyOutput` →
// `outputPorts`, default `["out"]`), plus any number of aux reads (aux is the
// only cross-scope channel — e.g. a round's `xor-with-aux@1` reading
// `aux["roundKey.N"]`). A dropped composite that reads aux only computes
// correctly if that aux cell exists in the new context; otherwise the existing
// coerce / aux-missing machinery surfaces it in the trace — on-brand, not a
// special case here.

/** Collect every node id (leaves AND containers) in a spec — one namespace. */
export const collectSpecIds = (spec: CipherSpec): Set<string> => {
  const ids = new Set<string>();
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      ids.add(n.id);
      if (n.kind !== "step") visit(n.children);
    }
  };
  visit(spec.steps);
  return ids;
};

export type CloneGroupResult = {
  readonly group: StepGroup;
  readonly renames: ReadonlyMap<string, string>;
};

/**
 * Guard: a Phase 4f v1 composite subtree supports `step` + nested `group`
 * nodes only. Looping/branching containers (`iterate` / `for-each-subgraph` /
 * `for-each-subgraph-with-history` / `feistel-round`) carry multi-scope chain
 * bindings that don't compose cleanly when re-instantiated at a new insertion
 * point — out of scope until a motivating feature lands. Throws loudly so the
 * store never holds an unsupported template (and `cloneGroupWithFreshIds`'s
 * rebuild can assume step|group throughout).
 */
const assertCompositeSubtreeSupported = (group: StepGroup): void => {
  const visit = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (n.kind === "step") continue;
      if (n.kind !== "group") {
        throw new Error(
          `composite subtree contains an unsupported "${n.kind}" container ("${n.id}") — Phase 4f v1 supports leaves + nested groups only`,
        );
      }
      visit(n.children);
    }
  };
  visit(group.children);
};

/**
 * Clone a group subtree under a fresh, collision-free id, regenerating every
 * descendant id and rebasing every INTERNAL port reference (each node's
 * `portInputs`, plus the group's own `seedInput`/`bodyOutput`) through the
 * old→new id map. External references (a `seedInput` aimed at a node OUTSIDE
 * the subtree, or `$input`) pass through untouched — the caller decides whether
 * to keep or clear them. (The captured template clears `seedInput`, so the only
 * binding that matters in practice is each child's internal `port(groupId,"in")`
 * seed reference, which DOES rebase because the group id is in the rename map.)
 *
 * `newGroupBaseId` is the desired root id; it (and every derived child id) is
 * deduped against `existingIds` so the clone never collides with the live spec.
 * Descendants that follow the readable `<oldGroupId>.<suffix>` convention keep
 * their suffix under the new root; any that don't are namespaced under it.
 *
 * v1 scope: `step` + `group` only (see `assertCompositeSubtreeSupported`); the
 * rebuild throws on any other kind defensively.
 */
export const cloneGroupWithFreshIds = (
  group: StepGroup,
  newGroupBaseId: string,
  existingIds: ReadonlySet<string>,
): CloneGroupResult => {
  const oldGroupId = group.id;
  const taken = new Set<string>(existingIds);
  const renames = new Map<string, string>();

  // Reserve a unique id, recording it so two clones / siblings can't collide.
  const freshId = (candidate: string): string => {
    let id = candidate;
    let n = 2;
    while (taken.has(id)) id = `${candidate}-${n++}`;
    taken.add(id);
    return id;
  };

  // Dedupe the ROOT first; every descendant id derives from the deduped root so
  // the clone reads consistently (root `aes-round-2` ⇒ child
  // `aes-round-2.sub-bytes`, never a mix of the original + deduped prefixes).
  const rootId = freshId(newGroupBaseId);
  renames.set(oldGroupId, rootId);

  const assignDescendant = (oldId: string): string =>
    freshId(
      oldId.startsWith(`${oldGroupId}.`)
        ? `${rootId}${oldId.slice(oldGroupId.length)}` // preserve `.suffix`
        : `${rootId}.${oldId}`, // fallback: namespace an unconventional id
    );

  const assign = (node: StepNode): void => {
    if (node.id !== oldGroupId) renames.set(node.id, assignDescendant(node.id));
    if (node.kind === "step") return;
    if (node.kind !== "group") {
      throw new Error(
        `cloneGroupWithFreshIds: unsupported node kind "${node.kind}" in composite subtree (id "${node.id}")`,
      );
    }
    for (const child of node.children) assign(child);
  };
  assign(group);

  const remapBinding = (b: PortBinding): PortBinding => {
    const to = renames.get(b.node);
    return to === undefined ? b : { node: to, port: b.port };
  };
  const remapPortInputs = (
    pi: Readonly<Record<string, PortBinding>> | undefined,
  ): Readonly<Record<string, PortBinding>> | undefined => {
    if (pi === undefined) return undefined;
    const next: Record<string, PortBinding> = {};
    for (const [k, b] of Object.entries(pi)) next[k] = remapBinding(b);
    return next;
  };

  const rebuildLeaf = (leaf: StepLeaf): StepLeaf => {
    const pi = remapPortInputs(leaf.portInputs);
    return {
      ...leaf,
      id: renames.get(leaf.id) ?? leaf.id,
      ...(pi !== undefined ? { portInputs: pi } : {}),
    };
  };

  const rebuildGroup = (g: StepGroup): StepGroup => {
    const children = g.children.map((c) => {
      if (c.kind === "step") return rebuildLeaf(c);
      if (c.kind === "group") return rebuildGroup(c);
      // Unreachable — `assign` already rejected non-step/non-group nodes.
      throw new Error(`cloneGroupWithFreshIds: unexpected node kind "${c.kind}"`);
    });
    const pi = remapPortInputs(g.portInputs);
    return {
      ...g,
      id: renames.get(g.id) ?? g.id,
      children,
      ...(pi !== undefined ? { portInputs: pi } : {}),
      ...(g.seedInput !== undefined ? { seedInput: remapBinding(g.seedInput) } : {}),
      ...(g.bodyOutput !== undefined ? { bodyOutput: remapBinding(g.bodyOutput) } : {}),
    };
  };

  return { group: rebuildGroup(group), renames };
};

/**
 * Produce a context-free composite template from an existing group in `spec`.
 * The template is the group with its `seedInput` CLEARED (so it carries no
 * dependency on its original neighbours — the drop path rebinds the seed to the
 * new insertion point), `defaultCollapsed: true` (it reads as one chip on the
 * canvas), and `label` set to the user-chosen `name`. Internal `portInputs` +
 * the children's `port(groupId,"in")` seed references are kept verbatim; the
 * drop-time `cloneGroupWithFreshIds` rebases them to the freshly-generated ids.
 *
 * Throws if `groupId` is not a `group`, if the group is empty, or if its
 * subtree contains a looping/branching container (see
 * `assertCompositeSubtreeSupported`). Pure — returns a fresh `StepGroup`; the
 * caller (composites store) wraps it with a composite id + createdAt.
 */
export const captureCompositeFromGroup = (
  spec: CipherSpec,
  groupId: string,
  name: string,
): StepGroup => {
  const loc = findStepAndParent(spec, groupId);
  if (!loc) throw new Error(`captureCompositeFromGroup: no node with id "${groupId}"`);
  if (loc.node.kind !== "group") {
    throw new Error(
      `captureCompositeFromGroup: "${groupId}" must be a group, got ${loc.node.kind}`,
    );
  }
  const group = loc.node;
  if (group.children.length === 0) {
    throw new Error(`captureCompositeFromGroup: group "${groupId}" is empty`);
  }
  assertCompositeSubtreeSupported(group);

  // Build the context-free template explicitly (rather than spread-then-delete)
  // so `seedInput` is provably omitted under exactOptionalPropertyTypes. The
  // children + their internal wiring carry through by reference; the spec tree
  // is readonly so sharing is safe.
  return {
    kind: "group",
    id: group.id,
    label: name,
    children: group.children,
    defaultCollapsed: true,
    ...(group.portInputs !== undefined ? { portInputs: group.portInputs } : {}),
    ...(group.outputPorts !== undefined ? { outputPorts: group.outputPorts } : {}),
    ...(group.bodyOutput !== undefined ? { bodyOutput: group.bodyOutput } : {}),
    // seedInput intentionally omitted — context-free template.
  };
};

/** Anchor flavors for inserting a composite (mirrors `insertStepIntoSpec`). */
export type CompositeInsertAnchor =
  | { readonly kind: "after"; readonly stepId: string }
  | { readonly kind: "before"; readonly stepId: string }
  | { readonly kind: "into-start"; readonly containerId: string }
  | { readonly kind: "root-append" };

/**
 * The synthetic body-entry port a seeded group / port-mode iterate injects
 * (`port(id,"in")`). `undefined` for any container that doesn't seed its body.
 * Used as the seed source when a composite lands at the head of such a body.
 */
const seededContainerInPort = (node: StepNode): PortBinding | undefined =>
  (node.kind === "group" || node.kind === "iterate") && node.seedInput !== undefined
    ? port(node.id, "in")
    : undefined;

/**
 * Choose the `seedInput` binding for a composite GROUP being inserted at
 * `anchor`, so the dropped copy is wired into the data flow by default — the
 * "insert into the pipeline" semantics. This matters because the 4d-bis port
 * editor only rewires LEAF input ports (a container `seedInput` is not a
 * rebindable target), so a dropped composite MUST arrive with its seed bound or
 * its first child's `port(groupId,"in")` read dangles with no in-app fix.
 *
 * Rules (resolved against the spec BEFORE insertion):
 *   - after  X     → seed = X's primary output (the composite follows X).
 *   - before X     → seed = X's preceding sibling's primary output; if X is
 *                    first in its scope, the scope's seed (`$input` at top, else
 *                    the parent container's `in`), else undefined.
 *   - into-start C → seed = `port(C,"in")` when C seeds its body, else undefined.
 *   - root-append  → seed = the last top-level node's primary output, or
 *                    `port($input,"out")` when the spec is empty.
 *
 * `primaryOut(node)` resolves a node's published output port (registry-driven
 * for leaves; `outputPorts[0] ?? "out"` for containers) — passed in so this
 * helper stays registry-free + unit-testable. Returns `undefined` when no
 * sensible default exists (the composite then arrives unbound).
 */
export const pickSeedBinding = (
  spec: CipherSpec,
  anchor: CompositeInsertAnchor,
  primaryOut: (node: StepNode) => string,
): PortBinding | undefined => {
  if (anchor.kind === "after") {
    const loc = findStepAndParent(spec, anchor.stepId);
    return loc ? port(loc.node.id, primaryOut(loc.node)) : undefined;
  }
  if (anchor.kind === "before") {
    const loc = findStepAndParent(spec, anchor.stepId);
    if (!loc) return undefined;
    const siblings = loc.parent ? loc.parent.children : spec.steps;
    const pred = loc.indexInParent > 0 ? siblings[loc.indexInParent - 1] : undefined;
    if (pred) return port(pred.id, primaryOut(pred));
    // Composite becomes first in this scope: seed from the scope's own source.
    return loc.parent === null
      ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT)
      : seededContainerInPort(loc.parent);
  }
  if (anchor.kind === "into-start") {
    const loc = findStepAndParent(spec, anchor.containerId);
    return loc ? seededContainerInPort(loc.node) : undefined;
  }
  // root-append
  const last = spec.steps.length > 0 ? spec.steps[spec.steps.length - 1] : undefined;
  return last ? port(last.id, primaryOut(last)) : port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT);
};

// ─── Padding-scheme overlay ───────────────────────────────────────────────
// Layer a padding chain onto a canonical cipher spec without modifying the
// canonical spec itself. The step types listed in `PADDING_STEP_TYPES` are
// reserved for this overlay — `applyPaddingScheme` strips any existing
// instance before inserting the new chain, so calling it repeatedly with
// the same scheme is a no-op (idempotent).
//
// Encrypt + <scheme>: prepend a <scheme>-pad reading `$input`, and repoint the
//   body's former `$input` consumers at the pad's output.
// Decrypt + <scheme>: append a <scheme>-unpad reading the cipher's exit, and
//   move `spec.outputFrom` onto it, so the spec's result is the stripped
//   plaintext (0..blockSize bytes, depending on scheme) rather than the
//   still-padded block.
// scheme=none: strips any existing chain and returns the canonical spec
//   unchanged (or as close to it as `applyPaddingScheme` was last fed).
//
// The overlay splices into the PORT graph. It once wove a
// [pad → load-block] / [store-block → unpad] chain around a `matrix4x4-bytes`
// state thread, bridging bytes↔matrix on the way in and out; Phase 5 Slice 5.1
// (2026-05-30) retired `MatrixState` and both bridge steps with it. Every spec
// is port-native byte-flat now, so there is no shape to bridge — only a pad to
// wire in.
//
// The block width comes from the CALLER (`blockByteLength`), not from a
// constant here: the overlay is cipher-agnostic, and a hardcoded 16 is what
// used to scope it to AES by spec-id prefix. See `docs/plans/foamy-prancing-wren.md`.
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

/**
 * The port name a Phase-1 *lifted* legacy step (`generic.pkcs7-pad@1` et al.)
 * publishes its transformed bytes under. The lift's `ProjectionMetadata`
 * declares `stateInputPort`/`stateOutputPort: "state"`, and the runtime
 * records ported outputs under that name (`port-projection.ts` →
 * `runtime.ts` `nodeOutputs`). So a byte-native consumer wiring to a pad's
 * output reads `port(padId, "state")` — NOT `"output"` (which is the
 * convention only for the new no-prefix port-native primitives like
 * `xor@1`/`byte-substitute@1`).
 */
const LIFTED_STATE_PORT = "state";

const port = (node: string, portName: string): PortBinding => ({ node, port: portName });

/**
 * Can the padding overlay target this spec?
 *
 * The gate used to be `spec.stateShape === "bytes" && spec.id.startsWith("aes")`
 * — an id-prefix scope that existed for one reason: the pad's `blockSize` was
 * hardcoded to 16, which is a lie for Speck (4) / DES (8) / Blowfish (8), and
 * every port-native cipher shares the `"bytes"` shape, so shape alone couldn't
 * tell them apart. Now that the caller supplies the block size, the id prefix
 * has nothing left to do and the overlay works for any block cipher.
 *
 * `blockByteLength === undefined` is what scopes it instead, and it means
 * exactly "the caller has no block cipher here": a hash, RSA, or a cipher with
 * no `BlockCipherCore` yet. Absence disables the overlay, so a spec the caller
 * can't vouch for is returned canonical rather than padded on a guessed size.
 *
 * The `stateShape` check is belt-and-braces — every shipped spec is `"bytes"`
 * since Phase 5 Slice 5.1 retired `MatrixState`. It stays because a pad
 * spliced into a non-byte state thread would be silently wrong, and the check
 * costs nothing.
 */
const overlayApplies = (
  spec: CipherSpec,
  blockByteLength: number | undefined,
): blockByteLength is number => blockByteLength !== undefined && spec.stateShape === "bytes";

/**
 * Recursively rewrite every `portInputs` binding in the tree through
 * `rewriteBinding` (identity ⇒ no-op for a binding). Pure — returns a fresh
 * tree only where a rewrite occurred (reference-stable on untouched
 * branches). The byte-native padding branch uses this to splice a pad into
 * the port graph (repoint `$input` consumers to the pad) and — on the
 * reverse — to restore the canonical `$input` wiring before a strip leaves a
 * dangling reference to a removed pad leaf.
 */
const rewriteAllPortInputs = (
  steps: readonly StepNode[],
  rewriteBinding: (b: PortBinding) => PortBinding,
): readonly StepNode[] => {
  const rewritePortInputs = (
    pi: Readonly<Record<string, PortBinding>> | undefined,
  ): Readonly<Record<string, PortBinding>> | undefined => {
    if (pi === undefined) return undefined;
    let changed = false;
    const next: Record<string, PortBinding> = {};
    for (const [k, b] of Object.entries(pi)) {
      const nb = rewriteBinding(b);
      if (nb !== b) changed = true;
      next[k] = nb;
    }
    return changed ? next : pi;
  };

  // Recurse into a node's children FIRST, on the intact discriminant (a
  // union-spread would erase the `kind`↔fields correlation and break the
  // narrowing). Then rewrite the node's own portInputs.
  const rewriteNode = (n: StepNode): StepNode => {
    let withChildren: StepNode = n;
    if (n.kind !== "step") {
      // group / iterate / for-each-subgraph / for-each-subgraph-with-history
      const nc = visit(n.children);
      if (nc !== n.children) withChildren = { ...n, children: nc };
    }
    const newPi = rewritePortInputs(withChildren.portInputs);
    let result: StepNode =
      newPi !== undefined && newPi !== withChildren.portInputs
        ? { ...withChildren, portInputs: newPi }
        : withChildren;
    // Container `seedInput` is the OTHER place a `$input` reference can live
    // (the byte-native ECB iterate reads `$input` there, not via portInputs —
    // Slice B1.4). Only looping containers + `group` carry it; `step` doesn't.
    if (result.kind !== "step" && result.seedInput !== undefined) {
      const ns = rewriteBinding(result.seedInput);
      if (ns !== result.seedInput) result = { ...result, seedInput: ns };
    }
    return result;
  };

  const visit = (nodes: readonly StepNode[]): readonly StepNode[] => {
    let anyChanged = false;
    const out = nodes.map((n) => {
      const next = rewriteNode(n);
      if (next !== n) anyChanged = true;
      return next;
    });
    return anyChanged ? out : nodes;
  };

  return visit(steps);
};

/** The pad-leaf ids the byte-native branch may have spliced in (for restore). */
const PADDING_PAD_IDS: ReadonlySet<string> = new Set<string>(
  Object.values(SCHEME_STEP_TYPES).map((s) => s.padId),
);
const PADDING_UNPAD_IDS: ReadonlySet<string> = new Set<string>(
  Object.values(SCHEME_STEP_TYPES).map((s) => s.unpadId),
);

/** Repoint `$input` consumers to `port(padNode, "state")` (pad-splice). */
const repointInputSourceConsumers = (
  steps: readonly StepNode[],
  padNode: string,
): readonly StepNode[] =>
  rewriteAllPortInputs(steps, (b) =>
    b.node === INPUT_SOURCE_ID && b.port === INPUT_SOURCE_PORT
      ? port(padNode, LIFTED_STATE_PORT)
      : b,
  );

/**
 * Restore the canonical `$input` wiring: any binding that points at a known
 * pad leaf's `state` output is repointed back to `$input`. Run BEFORE a
 * strip so removing the pad leaf can't leave a dangling reference. Pad ids
 * are reserved (`PADDING_PAD_IDS`), so this only ever touches overlay edges.
 */
const restoreInputSourceConsumers = (steps: readonly StepNode[]): readonly StepNode[] =>
  rewriteAllPortInputs(steps, (b) =>
    PADDING_PAD_IDS.has(b.node) && b.port === LIFTED_STATE_PORT
      ? port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT)
      : b,
  );

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
 * Layer a padding chain onto a cipher spec.
 *
 * Idempotent: any pre-existing padding leaves are stripped before the new
 * chain is inserted, so feeding the same (spec, mode, scheme) pair twice
 * produces structurally equivalent output. The canonical spec is reachable
 * by passing scheme=`"none"` — useful when the user toggles the padding
 * selector back to off.
 *
 * @param blockByteLength the block width the pad should fill to, or
 *   `undefined` when the caller has no block cipher here (a hash, RSA, or a
 *   cipher with no `BlockCipherCore`) — which disables the overlay entirely.
 *   Required rather than optional *on purpose*: a defaulted-to-16 param would
 *   silently pad an 8-byte-block cipher to 16, and an optional one would let a
 *   call site forget the argument and silently get no overlay at all. Making
 *   every caller name its block size — or name its absence — is the point.
 *
 * Pure: returns a new spec; the input spec is not mutated. New StepLeaf
 * objects are emitted on each call (no shared param references between
 * leaves — that's the same hygiene the cipher-spec factories follow).
 */
export const applyPaddingScheme = (
  spec: CipherSpec,
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  blockByteLength: number | undefined,
): CipherSpec => {
  const stripped = stripPaddingLeaves(spec.steps);

  // ── Not an overlay target ──────────────────────────────────────────────
  // A hash, RSA, or a cipher with no core: return the spec canonical
  // (stripped of any overlay a previous cipher selection left behind). The
  // padding store still holds the user's preference, so flipping back to a
  // cipher that HAS a core re-applies their choice without losing it.
  if (!overlayApplies(spec, blockByteLength)) {
    return { ...spec, steps: stripped };
  }

  // ── The port-native overlay ────────────────────────────────────────────
  // Every shipped spec carries a flat state on raw ports (no `MatrixState`
  // thread — Phase 5 Slice 5.1): the plaintext arrives on the reserved
  // `$input` source and the cipher exit is named by `spec.outputFrom`. So
  // there is no state thread to splice into and no bytes↔matrix bridge to
  // insert; the retired matrix overlay's [pad → load-block] /
  // [store-block → unpad] chain has no counterpart here.
  //
  // Instead we splice the pad directly into the port graph: prepend a pad
  // reading `$input`, then repoint every `$input` consumer to the pad's
  // output. That consumer lives in one of TWO places depending on the spec:
  //   • a leaf's `portInputs` — AES single-block's initial AddRoundKey `input`
  //     (the merged `xor-with-aux@1` leaf since Finding F3);
  //   • a container's `seedInput` — the ECB/CBC iterate, and also Blowfish
  //     single-block, whose round 1 is a port-mode `group` seeded from `$input`
  //     with no leaf referencing it at all.
  // `repointInputSourceConsumers` handles both: despite the name,
  // `rewriteAllPortInputs` walks container `seedInput` as well as every
  // portInputs key (see its `rewriteNode`). A portInputs-only rewrite would
  // splice a pad that nothing consumes — the body would keep reading raw
  // `$input` and the run would SUCCEED on unpadded bytes.
  // The pad is a Phase-1 lifted step, so its output port is named `"state"`
  // (LIFTED_STATE_PORT), not `"output"`.
  // Idempotency: a prior call may have repointed `$input` consumers to a
  // pad (encrypt) or moved `outputFrom` onto an unpad (decrypt). `stripped`
  // removed those LEAVES; we must also repair the EDGES before re-applying,
  // or a leftover binding dangles at the removed pad/unpad. Restore both
  // first, then re-derive from that canonical wiring.
  const inputRestored = restoreInputSourceConsumers(stripped);
  // Restore `outputFrom`: if it points at a known unpad, recover the
  // unpad's captured cipher-exit binding from the PRE-strip spec.
  let canonicalOutputFrom = spec.outputFrom;
  if (canonicalOutputFrom !== undefined && PADDING_UNPAD_IDS.has(canonicalOutputFrom.node)) {
    const priorUnpad = findStep(spec, canonicalOutputFrom.node);
    const captured = priorUnpad?.portInputs?.[LIFTED_STATE_PORT];
    canonicalOutputFrom = captured ?? canonicalOutputFrom;
  }
  const restoredSpec: CipherSpec = {
    ...spec,
    steps: inputRestored,
    ...(canonicalOutputFrom !== undefined ? { outputFrom: canonicalOutputFrom } : {}),
  };

  if (scheme === "none") {
    // No `load-block`/`store-block` ever existed in a port-native spec, so
    // the restored wiring IS the canonical spec. Shape stays `"bytes"`.
    return restoredSpec;
  }
  const { padType, unpadType, padId, unpadId } = SCHEME_STEP_TYPES[scheme];
  if (mode === "encrypt") {
    const padLeaf: StepLeaf = {
      kind: "step",
      id: padId,
      type: padType,
      params: { blockSize: blockByteLength },
      // Pad reads the raw plaintext from `$input` on its `state` input port.
      portInputs: { [LIFTED_STATE_PORT]: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
    };
    // The body's `$input` consumers now read the padded bytes instead.
    const repointed = repointInputSourceConsumers(inputRestored, padId);
    return { ...restoredSpec, steps: [padLeaf, ...repointed] };
  }
  // decrypt: append an unpad reading the current cipher exit, then move
  // `outputFrom` to the unpad's output so the spec's result is the stripped
  // plaintext rather than the still-padded block.
  const unpadLeaf: StepLeaf = {
    kind: "step",
    id: unpadId,
    type: unpadType,
    params: { blockSize: blockByteLength },
    ...(canonicalOutputFrom !== undefined
      ? { portInputs: { [LIFTED_STATE_PORT]: canonicalOutputFrom } }
      : {}),
  };
  return {
    ...restoredSpec,
    steps: [...inputRestored, unpadLeaf],
    outputFrom: port(unpadId, LIFTED_STATE_PORT),
  };
};
