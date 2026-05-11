/**
 * Pure helpers that produce new CipherSpec values from old ones. The spec
 * tree is `readonly`, so mutations always return a fresh tree — Solid stores
 * compare references to decide what to re-render, so handing back the same
 * object would cause subtle bugs.
 *
 * These exist so the UI can edit a single step's params (e.g. "swap the
 * S-box") without knowing how to walk the tree itself.
 */

import type { CipherSpec, Json, StateShape, StepLeaf, StepNode } from "./types";

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
 * Enumerate the top-level keys that differ between two Json values, when
 * both sides are plain objects. If either side isn't an object (array,
 * primitive), return a single `"*"` marker meaning "params replaced
 * wholesale" — we don't try to diff inside arrays here because the user-
 * visible params (S-box, MixColumns matrix) carry their identity at the
 * object-key level, not at array-element level.
 */
const diffJsonObjectKeys = (a: Json, b: Json): readonly string[] => {
  const aIsObj = a !== null && typeof a === "object" && !Array.isArray(a);
  const bIsObj = b !== null && typeof b === "object" && !Array.isArray(b);
  if (!aIsObj || !bIsObj) return ["*"];
  const ao = a as { [k: string]: Json };
  const bo = b as { [k: string]: Json };
  const keys = new Set<string>([...Object.keys(ao), ...Object.keys(bo)]);
  const out: string[] = [];
  for (const k of keys) {
    if (!jsonEqual(ao[k] ?? null, bo[k] ?? null)) out.push(k);
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
          changes.push({ stepId: x.id, paramName: "(type)" });
        } else if (!jsonEqual(x.params, y.params)) {
          const keys = diffJsonObjectKeys(x.params, y.params);
          for (const k of keys) changes.push({ stepId: x.id, paramName: k });
        }
      } else if (x.kind === "group" && y.kind === "group") {
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
 */
const PADDING_STEP_TYPES: ReadonlySet<string> = new Set<string>([
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
 * Layer a padding chain onto a cipher spec.
 *
 * Idempotent: any pre-existing padding leaves are stripped before the new
 * chain is inserted, so feeding the same (spec, mode, scheme) pair twice
 * produces structurally equivalent output. The canonical spec is reachable
 * by passing scheme=`"none"` — useful when the user toggles the padding
 * selector back to off.
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
