/**
 * Tests for the view-density store (commit 3 of the graph-readability
 * sequence). Mirrors `layout-store.test.ts`'s localStorage-shim pattern
 * so we can observe both the in-memory signal AND what gets persisted.
 *
 * Coverage targets:
 *   - Default density is "normal" (so the pre-density layout stays the
 *     byte-for-byte default for first-run users).
 *   - setViewDensity updates the signal AND persists to localStorage.
 *   - A persisted value rehydrates on the next "boot" (simulated by
 *     re-importing the module fresh via `vi.resetModules`).
 *   - Defensive load: missing localStorage / corrupted value / unknown
 *     enum value all fall back to "normal".
 *   - DENSITY_SCALE is symmetric around 1.0 and "normal" is exactly 1.0
 *     (pins the byte-stability of the default rendering — if a future
 *     refactor accidentally bumps it to 0.99 / 1.01, this test fails).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ─── localStorage polyfill ─────────────────────────────────────────────────
// Same shape + helpers as tests/layout-store.test.ts so the contract for
// "what a vitest test running in node env needs" is consistent across the
// store-tests in this project.

type MutableStorage = {
  store: Map<string, string>;
  getItem: (k: string) => string | null;
  setItem: (k: string, v: string) => void;
  removeItem: (k: string) => void;
  clear: () => void;
};

const makeStorage = (): MutableStorage => {
  const store = new Map<string, string>();
  return {
    store,
    getItem: (k) => store.get(k) ?? null,
    setItem: (k, v) => {
      store.set(k, v);
    },
    removeItem: (k) => {
      store.delete(k);
    },
    clear: () => {
      store.clear();
    },
  };
};

const installStorage = (storage: MutableStorage): void => {
  (globalThis as unknown as { localStorage: MutableStorage }).localStorage = storage;
};

const uninstallStorage = (): void => {
  (globalThis as unknown as { localStorage: MutableStorage | undefined }).localStorage = undefined;
};

const STORAGE_KEY = "cryptographer.viewDensity";

// ─── Per-test setup ────────────────────────────────────────────────────────

let storage: MutableStorage;

beforeEach(() => {
  storage = makeStorage();
  installStorage(storage);
  // Reset the module so each test sees a fresh `loadInitial` call against
  // the current storage shim. Without this, the module-scope signal would
  // carry the previous test's value through.
  vi.resetModules();
});

afterEach(() => {
  uninstallStorage();
});

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("view-density store — defaults", () => {
  it("defaults to 'normal' on first load (no persisted value)", async () => {
    const { useViewDensity } = await import("@/ui/stores/view-density");
    expect(useViewDensity()()).toBe("normal");
  });

  it("DENSITY_SCALE is symmetric around 1.0 and normal === 1.0 exactly", async () => {
    const { DENSITY_SCALE } = await import("@/ui/stores/view-density");
    // "normal" must be EXACTLY 1.0 — otherwise pre-density traces / layouts
    // would shift by a fraction of a pixel and the prior label-truncation
    // tests + drag tests would need re-baselining.
    expect(DENSITY_SCALE.normal).toBe(1.0);
    // Symmetric: compact below 1.0, spacious above, equal-distance.
    expect(DENSITY_SCALE.compact).toBeLessThan(1.0);
    expect(DENSITY_SCALE.spacious).toBeGreaterThan(1.0);
    expect(1.0 - DENSITY_SCALE.compact).toBeCloseTo(DENSITY_SCALE.spacious - 1.0, 6);
  });

  it("ALL_VIEW_DENSITIES contains exactly the three locked presets", async () => {
    const { ALL_VIEW_DENSITIES } = await import("@/ui/stores/view-density");
    expect([...ALL_VIEW_DENSITIES]).toEqual(["compact", "normal", "spacious"]);
  });
});

describe("view-density store — setViewDensity persistence", () => {
  it("setViewDensity updates the signal", async () => {
    const { setViewDensity, useViewDensity } = await import("@/ui/stores/view-density");
    setViewDensity("compact");
    expect(useViewDensity()()).toBe("compact");
    setViewDensity("spacious");
    expect(useViewDensity()()).toBe("spacious");
  });

  it("setViewDensity persists to localStorage", async () => {
    const { setViewDensity } = await import("@/ui/stores/view-density");
    setViewDensity("compact");
    expect(storage.getItem(STORAGE_KEY)).toBe("compact");
  });

  it("rehydrates the persisted value on re-import", async () => {
    // Seed storage directly, then re-import — simulates a page reload after
    // the user picked their density in a prior session.
    storage.setItem(STORAGE_KEY, "spacious");
    vi.resetModules();
    const { useViewDensity } = await import("@/ui/stores/view-density");
    expect(useViewDensity()()).toBe("spacious");
  });
});

describe("view-density store — defensive load", () => {
  it("returns 'normal' when localStorage is unavailable", async () => {
    uninstallStorage();
    vi.resetModules();
    const { useViewDensity } = await import("@/ui/stores/view-density");
    expect(useViewDensity()()).toBe("normal");
  });

  it("ignores an unknown persisted value (forward-compat / corrupted entry)", async () => {
    storage.setItem(STORAGE_KEY, "compactish-future-value");
    vi.resetModules();
    const { useViewDensity } = await import("@/ui/stores/view-density");
    expect(useViewDensity()()).toBe("normal");
  });

  it("__resetViewDensityForTests restores the default + clears storage", async () => {
    const { __resetViewDensityForTests, setViewDensity, useViewDensity } = await import(
      "@/ui/stores/view-density"
    );
    setViewDensity("compact");
    expect(storage.getItem(STORAGE_KEY)).toBe("compact");
    __resetViewDensityForTests();
    expect(useViewDensity()()).toBe("normal");
    expect(storage.getItem(STORAGE_KEY)).toBeNull();
  });
});
