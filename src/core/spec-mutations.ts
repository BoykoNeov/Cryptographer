/**
 * Pure helpers that produce new CipherSpec values from old ones. The spec
 * tree is `readonly`, so mutations always return a fresh tree — Solid stores
 * compare references to decide what to re-render, so handing back the same
 * object would cause subtle bugs.
 *
 * These exist so the UI can edit a single step's params (e.g. "swap the
 * S-box") without knowing how to walk the tree itself.
 */

import type { CipherSpec, Json, StepLeaf, StepNode } from "./types";

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
