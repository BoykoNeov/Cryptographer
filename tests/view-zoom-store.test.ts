/**
 * Tests for the view-zoom store (Slice 3 of the graph-narrative-and-zoom
 * plan). Mirrors `view-density-store.test.ts`'s localStorage-shim pattern
 * so we can observe both the in-memory signal AND what gets persisted.
 *
 * Coverage targets:
 *   - Default zoom is exactly 1.0 (so the pre-zoom layout stays the
 *     byte-for-byte default for first-run users).
 *   - setViewZoom updates the signal AND persists to localStorage.
 *   - Zoom is clamped to [VIEW_ZOOM_MIN, VIEW_ZOOM_MAX] (no NaN, no
 *     extreme values bleeding into the SVG width formula).
 *   - A persisted value rehydrates on the next "boot" (simulated by
 *     re-importing the module fresh via `vi.resetModules`).
 *   - Defensive load: missing localStorage / corrupted JSON / wrong types
 *     all fall back to the default empty map.
 *   - Setting zoom back to 1.0 drops the entry from the persisted map
 *     (keeps localStorage minimal and matches the "no entry === default"
 *     invariant readers depend on).
 *   - Zoom is per-spec: AES-128 zoom and Speck-32 zoom are independent.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ─── localStorage polyfill ─────────────────────────────────────────────────
// Same shape as tests/view-density-store.test.ts.

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

const STORAGE_KEY = "cryptographer.viewZoom";

// ─── Per-test setup ────────────────────────────────────────────────────────

let storage: MutableStorage;

beforeEach(() => {
  storage = makeStorage();
  installStorage(storage);
  vi.resetModules();
});

afterEach(() => {
  uninstallStorage();
});

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("view-zoom store — defaults", () => {
  it("default zoom is exactly 1.0 (byte-stable with pre-Slice-3 rendering)", async () => {
    const { VIEW_ZOOM_DEFAULT, getViewZoom } = await import("@/ui/stores/view-zoom");
    // Pinning the literal here so a future refactor that bumps the default
    // to 1.05 / 0.95 fails this test FIRST and points at the cause.
    expect(VIEW_ZOOM_DEFAULT).toBe(1.0);
    // Zero entries → reader returns the default.
    expect(getViewZoom("aes-128@1")).toBe(1.0);
  });

  it("min/max bracket the supported range symmetrically around 1.0", async () => {
    const { VIEW_ZOOM_MIN, VIEW_ZOOM_MAX } = await import("@/ui/stores/view-zoom");
    expect(VIEW_ZOOM_MIN).toBe(0.5);
    expect(VIEW_ZOOM_MAX).toBe(2.0);
    // Min × max === default². Geometric symmetry — zooming out by N×, then
    // in by N×, returns to the original.
    expect(VIEW_ZOOM_MIN * VIEW_ZOOM_MAX).toBeCloseTo(1.0, 6);
  });
});

describe("view-zoom store — setViewZoom persistence", () => {
  it("setViewZoom updates the signal AND persists to localStorage", async () => {
    const { setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("aes-128@1", 1.5);
    expect(getViewZoom("aes-128@1")).toBe(1.5);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = raw ? JSON.parse(raw) : null;
    expect(parsed).toEqual({ "aes-128@1": 1.5 });
  });

  it("rehydrates the persisted value on re-import", async () => {
    storage.setItem(STORAGE_KEY, JSON.stringify({ "aes-128@1": 1.7 }));
    vi.resetModules();
    const { getViewZoom } = await import("@/ui/stores/view-zoom");
    expect(getViewZoom("aes-128@1")).toBe(1.7);
  });

  it("setting zoom back to 1.0 drops the entry (keeps storage minimal)", async () => {
    const { setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("aes-128@1", 1.5);
    setViewZoom("aes-128@1", 1.0);
    expect(getViewZoom("aes-128@1")).toBe(1.0);
    // Persisted map should be empty {} — the entry got pruned.
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    expect(raw ? JSON.parse(raw) : null).toEqual({});
  });

  it("zoom is per-spec — distinct ids store independent values", async () => {
    const { setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("aes-128@1", 1.5);
    setViewZoom("speck-32-64-be@1", 0.75);
    expect(getViewZoom("aes-128@1")).toBe(1.5);
    expect(getViewZoom("speck-32-64-be@1")).toBe(0.75);
  });
});

describe("view-zoom store — clamping", () => {
  it("clamps below VIEW_ZOOM_MIN to VIEW_ZOOM_MIN", async () => {
    const { VIEW_ZOOM_MIN, setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("s", 0.1);
    expect(getViewZoom("s")).toBe(VIEW_ZOOM_MIN);
  });

  it("clamps above VIEW_ZOOM_MAX to VIEW_ZOOM_MAX", async () => {
    const { VIEW_ZOOM_MAX, setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("s", 5);
    expect(getViewZoom("s")).toBe(VIEW_ZOOM_MAX);
  });

  it("NaN / non-finite collapse to the default (1.0)", async () => {
    const { setViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("s", Number.NaN);
    expect(getViewZoom("s")).toBe(1.0);
    setViewZoom("s", Number.POSITIVE_INFINITY);
    expect(getViewZoom("s")).toBe(1.0);
  });

  it("setViewZoom returns the clamped value that was actually applied", async () => {
    const { VIEW_ZOOM_MAX, setViewZoom } = await import("@/ui/stores/view-zoom");
    expect(setViewZoom("s", 5)).toBe(VIEW_ZOOM_MAX);
  });
});

describe("view-zoom store — stepViewZoom / resetViewZoom", () => {
  it("stepViewZoom(+1) increments by VIEW_ZOOM_BUTTON_STEP", async () => {
    const { VIEW_ZOOM_BUTTON_STEP, stepViewZoom, getViewZoom } = await import(
      "@/ui/stores/view-zoom"
    );
    stepViewZoom("s", 1);
    expect(getViewZoom("s")).toBeCloseTo(1.0 + VIEW_ZOOM_BUTTON_STEP, 6);
  });

  it("repeated stepViewZoom never accumulates floating-point drift", async () => {
    const { stepViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    // Step up 5×, down 5× — without rounding the value can drift away from
    // 1.0 by enough to fail an `=== 1.0` check (`1.0 - 0.1 - 0.1 ...` is
    // famously not 0.0).
    stepViewZoom("s", 1);
    stepViewZoom("s", 1);
    stepViewZoom("s", 1);
    stepViewZoom("s", 1);
    stepViewZoom("s", 1);
    stepViewZoom("s", -1);
    stepViewZoom("s", -1);
    stepViewZoom("s", -1);
    stepViewZoom("s", -1);
    stepViewZoom("s", -1);
    expect(getViewZoom("s")).toBe(1.0);
  });

  it("resetViewZoom returns to 1.0 and drops the entry", async () => {
    const { setViewZoom, resetViewZoom, getViewZoom } = await import("@/ui/stores/view-zoom");
    setViewZoom("s", 1.5);
    resetViewZoom("s");
    expect(getViewZoom("s")).toBe(1.0);
    expect(storage.getItem(STORAGE_KEY)).toBe("{}");
  });
});

describe("view-zoom store — defensive load", () => {
  it("returns empty map when localStorage is unavailable", async () => {
    uninstallStorage();
    vi.resetModules();
    const { getViewZoom } = await import("@/ui/stores/view-zoom");
    expect(getViewZoom("aes-128@1")).toBe(1.0);
  });

  it("ignores corrupted JSON and falls back to default", async () => {
    storage.setItem(STORAGE_KEY, "{not valid json");
    vi.resetModules();
    const { getViewZoom } = await import("@/ui/stores/view-zoom");
    expect(getViewZoom("aes-128@1")).toBe(1.0);
  });

  it("ignores non-numeric entries inside an otherwise-valid blob", async () => {
    storage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        "aes-128@1": "1.5", // string, not number → dropped
        "speck-32-64-be@1": 1.3, // valid → kept
      }),
    );
    vi.resetModules();
    const { getViewZoom } = await import("@/ui/stores/view-zoom");
    expect(getViewZoom("aes-128@1")).toBe(1.0);
    expect(getViewZoom("speck-32-64-be@1")).toBe(1.3);
  });

  it("clamps out-of-range persisted values on rehydrate", async () => {
    storage.setItem(STORAGE_KEY, JSON.stringify({ "aes-128@1": 99 }));
    vi.resetModules();
    const { VIEW_ZOOM_MAX, getViewZoom } = await import("@/ui/stores/view-zoom");
    expect(getViewZoom("aes-128@1")).toBe(VIEW_ZOOM_MAX);
  });

  it("__resetViewZoomForTests restores defaults + clears storage", async () => {
    const { __resetViewZoomForTests, setViewZoom, getViewZoom } = await import(
      "@/ui/stores/view-zoom"
    );
    setViewZoom("aes-128@1", 1.5);
    expect(storage.getItem(STORAGE_KEY)).not.toBeNull();
    __resetViewZoomForTests();
    expect(getViewZoom("aes-128@1")).toBe(1.0);
    expect(storage.getItem(STORAGE_KEY)).toBeNull();
  });
});
