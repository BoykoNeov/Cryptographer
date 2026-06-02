/**
 * Composites store — the user's "my elements" library (universal-port Phase 4f,
 * compose-and-save). A composite is a reusable building block the user saved
 * out of an existing group (e.g. an AES round) via the graph view's
 * `[save as element]` button; it shows up in a dedicated palette section and
 * drops a fresh, fully editable copy onto any spec.
 *
 * A composite is PURE JSON — a `StepGroup` template (produced by
 * `captureCompositeFromGroup`) — not a registered step type with a synthesized
 * executor. So nothing here touches the runtime/registry: the library is just
 * persisted spec fragments, and dropping one INLINES a clone (see
 * `insertCompositeIntoSpec` in `stores/spec.ts`). Because the drop inlines, any
 * saved/shared `CipherDocument` is self-contained and never references this
 * library — which is why it can be a localStorage-only sidecar with NO
 * document-schema bump, exactly mirroring `stores/layout.ts`.
 *
 * GLOBAL, not per-spec: a "my elements" library spans every cipher (unlike the
 * per-`spec.id` layout sidecar). Persisted as one JSON blob — a map keyed by
 * composite id — under `cryptographer.composites`.
 *
 * Public API mirrors the established store pattern (cf. `stores/layout.ts`):
 * read via `useComposites()` / `listComposites()`, write via small dedicated
 * setters that update the signal AND persist atomically.
 */

import type { StepGroup } from "@/core/types";
import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.composites";

/**
 * One saved composite. `group` is the context-free template
 * (`captureCompositeFromGroup` cleared its `seedInput` and set `label` = the
 * user-chosen name); `name` is surfaced in the palette; `createdAt` orders the
 * list (newest considerations aside, stable insertion order is what the user
 * expects). `id` is the library key, distinct from the template's spec id.
 */
export type CompositeDefinition = {
  readonly id: string;
  readonly name: string;
  readonly group: StepGroup;
  readonly createdAt: number;
};

/** All composites in one map: composite id → definition. One JSON blob. */
type CompositeMap = { readonly [id: string]: CompositeDefinition };

/**
 * Lightweight structural check for a persisted `CompositeDefinition`. Not a
 * full schema validation — the "trust but verify the broad shape" pass for
 * localStorage rehydration. A failed entry is silently dropped on boot rather
 * than crashing the session (matches `stores/layout.ts::isLayoutSpec`).
 */
const isCompositeDefinition = (v: unknown): v is CompositeDefinition => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  if (typeof o.id !== "string" || typeof o.name !== "string") return false;
  if (typeof o.createdAt !== "number") return false;
  const g = o.group as Record<string, unknown> | null;
  if (g === null || typeof g !== "object" || Array.isArray(g)) return false;
  // The template must look like a group node with children.
  return g.kind === "group" && typeof g.id === "string" && Array.isArray(g.children);
};

/**
 * Read the persisted library from localStorage. Defensive against missing
 * localStorage (vitest node env), quota/private-mode throws, corrupted JSON,
 * and wrong-shape entries — on any failure return an empty map and continue.
 */
const loadInitial = (): CompositeMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: { [id: string]: CompositeDefinition } = {};
    for (const [id, value] of Object.entries(parsed)) {
      if (isCompositeDefinition(value)) out[id] = value;
    }
    return out;
  } catch {
    return {};
  }
};

/** Persist the in-memory map to localStorage. Best-effort; failures ignored. */
const persist = (map: CompositeMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Quota / private-mode / disabled cookies. Ignore.
  }
};

const [compositeMap, setCompositeMapSignal] = createSignal<CompositeMap>(loadInitial());

/** Reactive read of the full library map. Palette consumes via createMemo. */
export const useComposites = (): (() => CompositeMap) => compositeMap;

/**
 * Snapshot of every saved composite, oldest-first (stable insertion order). The
 * palette renders this; consumers that need reactivity read `useComposites()`
 * and sort, but the common read is this convenience.
 */
export const listComposites = (): readonly CompositeDefinition[] =>
  Object.values(compositeMap()).sort((a, b) => a.createdAt - b.createdAt);

/** Look up one composite by its library id (undefined if absent). */
export const getComposite = (id: string): CompositeDefinition | undefined => compositeMap()[id];

/**
 * Generate a library id that's unique within the current map. `crypto.randomUUID`
 * when available (browser + Node ≥19), else a timestamp+random fallback re-rolled
 * on the rare collision. Distinct from spec node ids — the leading `composite.`
 * prefix keeps it out of the spec-id namespace.
 */
const freshCompositeId = (map: CompositeMap): string => {
  const make = (): string =>
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? `composite.${crypto.randomUUID()}`
      : `composite.${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  let id = make();
  while (map[id] !== undefined) id = make();
  return id;
};

/**
 * Save a context-free composite template (from `captureCompositeFromGroup`) to
 * the library. The display name is taken from the template's `label` (capture
 * set it to the user's chosen name). Validates the boundary defensively — the
 * template must be a non-empty group — and throws a friendly message otherwise
 * (capture already enforces this; this guards against a malformed direct call).
 * Returns the saved definition (with its fresh library id + timestamp).
 */
export const saveComposite = (template: StepGroup): CompositeDefinition => {
  if (template.kind !== "group" || template.children.length === 0) {
    throw new Error("saveComposite: a composite must be a non-empty group");
  }
  const map = compositeMap();
  const def: CompositeDefinition = {
    id: freshCompositeId(map),
    name: template.label,
    group: template,
    createdAt: Date.now(),
  };
  const next = { ...map, [def.id]: def };
  setCompositeMapSignal(next);
  persist(next);
  return def;
};

/** Remove one composite from the library. No-op if the id is unknown. */
export const deleteComposite = (id: string): void => {
  const map = compositeMap();
  if (map[id] === undefined) return;
  const next = { ...map };
  delete (next as { [id: string]: CompositeDefinition })[id];
  setCompositeMapSignal(next);
  persist(next);
};

/**
 * Rename one composite. Updates both the library `name` AND the template's
 * `label` so a subsequent drop carries the new name (the label is what the
 * dropped group shows + what derives its fresh id). No-op if the id is unknown
 * or the name is unchanged.
 */
export const renameComposite = (id: string, name: string): void => {
  const map = compositeMap();
  const existing = map[id];
  if (existing === undefined || existing.name === name) return;
  const next: CompositeMap = {
    ...map,
    [id]: { ...existing, name, group: { ...existing.group, label: name } },
  };
  setCompositeMapSignal(next);
  persist(next);
};
