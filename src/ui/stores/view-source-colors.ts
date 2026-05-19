/**
 * View-source-colors store. Two pieces of state for the source-color
 * coding feature (see `docs/plans/source-color-coding.md`):
 *
 *   1. **Global master toggle** — one bool, persisted to localStorage as a
 *      simple string, identical pattern to `view-replication.ts`'s
 *      `replicationEnabled`. Default ON: the user explicitly chose
 *      "initially all arrows are colored" via `AskUserQuestion` on
 *      2026-05-19. Disabling reverts every edge to today's kind-based
 *      styling.
 *
 *   2. **Per-spec manual overrides** — one map per spec.id, persisted as
 *      a JSON blob `{ [specId]: { [canonicalSourceId]: cssColor } }`.
 *      Same per-spec shape as `view-zoom.ts` and `view-density.ts`.
 *      Auto-colors derive from graph structure (`assignSourceColors` in
 *      `core/source-colors.ts`) and are NEVER stored — only manual
 *      user overrides hit localStorage.
 *
 * Why per-spec for overrides (not global): a user who manually picked
 * red for AES's `key-expansion` doesn't expect Serpent's `key-expansion`
 * to also turn red — these are conceptually different cipher contexts,
 * even when the canonical source ids happen to overlap. The per-spec
 * scoping mirrors how `view-zoom` and `view-density` already partition.
 *
 * Why GLOBAL for the master toggle: the toggle is "do I want this
 * feature right now," not "what does this spec mean." User flipping it
 * once should affect every cipher they look at — matches
 * `replicationEnabled`.
 *
 * Why viewer-local (NOT on `LayoutSpec`): same reasoning as
 * `view-zoom.ts` — these are VIEWER preferences, not document facts.
 * Save/Share's byte-stability guarantee stays intact because nothing
 * here touches `LayoutSpec`.
 */

import { createSignal } from "solid-js";

// ─── Master toggle (global) ───────────────────────────────────────────────

const ENABLED_STORAGE_KEY = "cryptographer.viewSourceColoringEnabled";

/**
 * Hydrate the master toggle. Defensive against missing localStorage
 * (private mode, disabled cookies, server-rendered context). Default
 * value is **true** — the feature ships ON. The only way a user lands
 * on `false` is by having previously disabled it.
 */
const loadInitialEnabled = (): boolean => {
  try {
    if (typeof localStorage === "undefined") return true;
    const raw = localStorage.getItem(ENABLED_STORAGE_KEY);
    // Missing entry → default ON. Explicit "false" string → OFF. Anything
    // else (corrupted / partial write) → default.
    if (raw === null) return true;
    return raw !== "false";
  } catch {
    return true;
  }
};

const [coloringEnabled, setColoringEnabledSignal] = createSignal<boolean>(loadInitialEnabled());

export const useSourceColoringEnabled = () => coloringEnabled;

export const setSourceColoringEnabled = (enabled: boolean): void => {
  setColoringEnabledSignal(enabled);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(ENABLED_STORAGE_KEY, enabled ? "true" : "false");
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

export const toggleSourceColoringEnabled = (): void => {
  setColoringEnabledSignal((prev) => {
    const next = !prev;
    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(ENABLED_STORAGE_KEY, next ? "true" : "false");
      }
    } catch {
      // Ignore persist failures.
    }
    return next;
  });
};

// ─── Include single-output sources sub-toggle (2026-05-19) ───────────────
//
// When the master toggle is ON, the colors panel lists only multi-fanout
// sources by default (the ones that get auto-assigned colours). This
// sub-toggle expands the listing to include single-fanout sources too,
// so users can manually pick a colour for any source even when the auto
// pass left it un-assigned. Single-fanout sources do NOT get auto-
// assigned colours regardless of this toggle — they start uncoloured
// and only paint when the user picks one.
//
// Default OFF: matches the user's "don't cram the chooser" framing.
// Global (not per-spec) for consistency with the master toggle —
// it's a panel-growth preference, not a document fact.

const INCLUDE_SINGLE_STORAGE_KEY = "cryptographer.viewSourceColorsIncludeSingle";

const loadInitialIncludeSingle = (): boolean => {
  try {
    if (typeof localStorage === "undefined") return false;
    return localStorage.getItem(INCLUDE_SINGLE_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
};

const [includeSingleSources, setIncludeSingleSourcesSignal] = createSignal<boolean>(
  loadInitialIncludeSingle(),
);

export const useIncludeSingleSources = () => includeSingleSources;

export const setIncludeSingleSources = (include: boolean): void => {
  setIncludeSingleSourcesSignal(include);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(INCLUDE_SINGLE_STORAGE_KEY, include ? "true" : "false");
    }
  } catch {
    // Ignore persist failures.
  }
};

export const toggleIncludeSingleSources = (): void => {
  setIncludeSingleSourcesSignal((prev) => {
    const next = !prev;
    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(INCLUDE_SINGLE_STORAGE_KEY, next ? "true" : "false");
      }
    } catch {
      // Ignore persist failures.
    }
    return next;
  });
};

// ─── Per-spec manual overrides ────────────────────────────────────────────

const OVERRIDES_STORAGE_KEY = "cryptographer.viewSourceColorOverrides";

/**
 * Persisted shape: `{ [specId]: { [canonicalSourceId]: cssColor } }`.
 * Empty inner objects are dropped on write so the persisted blob stays
 * minimal — matches the "no entry === default" invariant used by
 * `view-zoom.ts`.
 */
export type SourceColorOverridesMap = {
  readonly [specId: string]: { readonly [sourceId: string]: string };
};

/** Hydrate from localStorage. Same defensive style as `view-zoom.ts`. */
const loadInitialOverrides = (): SourceColorOverridesMap => {
  try {
    if (typeof localStorage === "undefined") return {};
    const raw = localStorage.getItem(OVERRIDES_STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: { [specId: string]: { [sourceId: string]: string } } = {};
    for (const [specId, perSpec] of Object.entries(parsed)) {
      if (perSpec === null || typeof perSpec !== "object" || Array.isArray(perSpec)) continue;
      const inner: { [sourceId: string]: string } = {};
      for (const [sourceId, color] of Object.entries(perSpec as Record<string, unknown>)) {
        // Defensive: keep only strings, drop anything that doesn't look
        // like a value the renderer would honor. We don't validate the
        // CSS color syntax here (browsers fall back to invalid values
        // gracefully); just shape-check.
        if (typeof color !== "string") continue;
        inner[sourceId] = color;
      }
      if (Object.keys(inner).length > 0) out[specId] = inner;
    }
    return out;
  } catch {
    return {};
  }
};

const [overridesMap, setOverridesMapSignal] = createSignal<SourceColorOverridesMap>(
  loadInitialOverrides(),
);

/** Persist best-effort; failures don't break the session. */
const persistOverrides = (map: SourceColorOverridesMap): void => {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(OVERRIDES_STORAGE_KEY, JSON.stringify(map));
    }
  } catch {
    // Quota / private-mode / disabled cookies. Ignore.
  }
};

/**
 * Reactive read of one spec's manual overrides. Returns an empty
 * `ReadonlyMap` when no entry exists, so callers can call `.get()`
 * without a null check. Use this from JSX.
 */
export const useManualSourceColors = (
  specId: () => string,
): (() => ReadonlyMap<string, string>) => {
  return () => {
    const perSpec = overridesMap()[specId()];
    if (perSpec === undefined) return EMPTY_MAP;
    return new Map(Object.entries(perSpec));
  };
};

/** Shared empty map so the common case allocates nothing. */
const EMPTY_MAP: ReadonlyMap<string, string> = new Map();

/**
 * Set one source's color override on one spec. Pass an empty string to
 * remove the override (revert to auto-assigned). When the spec ends up
 * with no overrides, the entry is dropped entirely so the persisted
 * blob stays minimal.
 */
export const setSourceColorOverride = (
  specId: string,
  canonicalSource: string,
  color: string,
): void => {
  const current = overridesMap();
  const perSpec = { ...(current[specId] ?? {}) };
  if (color === "") {
    delete perSpec[canonicalSource];
  } else {
    perSpec[canonicalSource] = color;
  }
  const next = { ...current };
  if (Object.keys(perSpec).length === 0) {
    delete (next as { [specId: string]: { [sourceId: string]: string } })[specId];
  } else {
    next[specId] = perSpec;
  }
  setOverridesMapSignal(next);
  persistOverrides(next);
};

/** Remove ONE source's override (revert to auto-assigned color). */
export const clearSourceColorOverride = (specId: string, canonicalSource: string): void => {
  setSourceColorOverride(specId, canonicalSource, "");
};

/** Remove ALL manual overrides for one spec. The "[clear all manual]"
 *  panel-footer button calls this. */
export const clearAllSourceColorOverrides = (specId: string): void => {
  const current = overridesMap();
  if (!(specId in current)) return;
  const next = { ...current };
  delete (next as { [specId: string]: { [sourceId: string]: string } })[specId];
  setOverridesMapSignal(next);
  persistOverrides(next);
};

// ─── Per-spec panel-open state (session-only, mirrors replication panel) ──

const [colorsPanelOpenMap, setColorsPanelOpenMap] = createSignal<{
  readonly [specId: string]: boolean;
}>({});

/** Reactive read of the panel's open/closed state for one spec. Defaults
 *  closed so a new spec doesn't immediately commandeer screen space. */
export const useColorsPanelOpen = (specId: () => string): (() => boolean) => {
  return () => colorsPanelOpenMap()[specId()] ?? false;
};

export const setColorsPanelOpen = (specId: string, open: boolean): void => {
  const current = colorsPanelOpenMap();
  const next = { ...current };
  if (open) {
    next[specId] = true;
  } else {
    delete (next as { [specId: string]: boolean })[specId];
  }
  setColorsPanelOpenMap(next);
};

export const toggleColorsPanelOpen = (specId: string): void => {
  const open = colorsPanelOpenMap()[specId] ?? false;
  setColorsPanelOpen(specId, !open);
};

// ─── Test hooks ───────────────────────────────────────────────────────────

/**
 * Hard reset for tests. Production code never calls this. Clears the
 * in-memory signals + the persisted blobs so each test starts from a
 * clean baseline.
 */
export const __resetSourceColorsForTests = (): void => {
  setColoringEnabledSignal(true);
  setOverridesMapSignal({});
  setColorsPanelOpenMap({});
  setIncludeSingleSourcesSignal(false);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(ENABLED_STORAGE_KEY);
      localStorage.removeItem(OVERRIDES_STORAGE_KEY);
      localStorage.removeItem(INCLUDE_SINGLE_STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
