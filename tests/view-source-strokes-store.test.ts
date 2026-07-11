// @vitest-environment jsdom
//
// jsdom because the store touches localStorage. The signal itself is
// framework code; we test the public API + persistence shape.

/**
 * Tests for `src/ui/stores/view-source-strokes.ts` — the per-spec master
 * toggle for the per-source arrow-*style* channel (Part A of
 * `docs/plans/toasty-zooming-harp.md`, chunks A3a + A3b).
 *
 * Unlike the colours store (one GLOBAL bool, ships ON), the stroke toggle is
 * keyed by `spec.id`. Its shipped default is now UNIVERSAL — ON for every spec
 * (user-decided 2026-07-11; before that, OFF everywhere except SHA-256 /
 * 2026-07-09 and RSA / 2026-07-10). The per-spec keying is retained so an
 * explicit per-spec OFF still persists independently. The store owns no
 * manual-override map (those live on `LayoutSpec.strokeStyles`, chunk A2) but
 * DOES own its own fanout threshold as of 2026-07-10 (split from the colour
 * threshold — a per-spec number map with the same discipline). So the
 * properties to pin are:
 *
 *   1. Per-spec default: ON for every spec (universal).
 *   2. Explicit overrides persist and win over the default.
 *   3. Drop-on-match: setting a spec back to its default removes the entry,
 *      so the persisted map stays minimal (and a future default change is
 *      never shadowed by a stale entry).
 *   4. Threshold: per-spec default (1, universal), clamped, with the same
 *      drop-on-match discipline as the enable map.
 */

import {
  DEFAULT_STROKE_THRESHOLD,
  STROKE_THRESHOLD_MAX,
  __resetSourceStrokesForTests,
  defaultStrokeStylingFor,
  defaultStrokeThresholdFor,
  setSourceStrokeStylingEnabled,
  setStrokeThreshold,
  toggleSourceStrokeStylingEnabled,
  useSourceStrokeStylingEnabled,
  useStrokeThreshold,
} from "@/ui/stores/view-source-strokes";
import { beforeEach, describe, expect, it } from "vitest";

const STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";
const THRESHOLD_STORAGE_KEY = "cryptographer.viewSourceStrokeThreshold";
const SHA = "sha-256@1";
const AES = "aes-128@1";

/** Read the persisted override map (or {} if absent/corrupt). */
const readMap = (): Record<string, unknown> => {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
};

/** Read the persisted threshold map (or {} if absent/corrupt). */
const readThresholdMap = (): Record<string, unknown> => {
  const raw = localStorage.getItem(THRESHOLD_STORAGE_KEY);
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
};

beforeEach(() => {
  __resetSourceStrokesForTests();
});

describe("source-stroke per-spec master toggle", () => {
  it("defaultStrokeStylingFor: ON for EVERY spec (universal default, 2026-07-11)", () => {
    // Pre-2026-07-11 only SHA-256 + RSA shipped ON; the user then extended
    // styling-on to every cipher and hash. No spec ships OFF anymore.
    expect(defaultStrokeStylingFor("sha-256@1")).toBe(true);
    expect(defaultStrokeStylingFor("sha-256@2")).toBe(true);
    expect(defaultStrokeStylingFor("rsa@1")).toBe(true);
    expect(defaultStrokeStylingFor("rsa-decrypt@1")).toBe(true);
    expect(defaultStrokeStylingFor("aes-128@1")).toBe(true);
    expect(defaultStrokeStylingFor("des@1")).toBe(true);
    expect(defaultStrokeStylingFor("blowfish@1")).toBe(true);
  });

  it("reactive read falls back to the per-spec default (ON) when no override exists", () => {
    // Every spec now ships styled — Blowfish and all future ciphers/hashes
    // included (user-decided 2026-07-11).
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(true);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(true);
  });

  it("an explicit override wins over the default and persists per-spec", () => {
    // Default is now ON for every spec, so the divergent value is `false`.
    setSourceStrokeStylingEnabled(AES, false);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(false);
    // SHA-256 (untouched) still reads its own default (ON).
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(true);
    expect(readMap()).toEqual({ [AES]: false });
  });

  it("setting a spec back to its shipped default DROPS the entry (drop-on-match)", () => {
    // Every spec now defaults ON: turning one OFF writes an entry, turning it
    // back ON (== default) removes it, so the persisted map returns to empty.
    setSourceStrokeStylingEnabled(AES, false);
    expect(readMap()).toEqual({ [AES]: false });
    setSourceStrokeStylingEnabled(AES, true);
    expect(readMap()).toEqual({});
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(true);
  });

  it("SHA-256 turned OFF writes an explicit false (diverges from its ON default)", () => {
    setSourceStrokeStylingEnabled(SHA, false);
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(false);
    expect(readMap()).toEqual({ [SHA]: false });
    // Back to default (ON) drops the entry.
    setSourceStrokeStylingEnabled(SHA, true);
    expect(readMap()).toEqual({});
  });

  it("toggle flips relative to the CURRENT effective value (default-aware)", () => {
    // AES starts ON (universal default) → toggle → OFF (explicit false written).
    toggleSourceStrokeStylingEnabled(AES);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(false);
    expect(readMap()).toEqual({ [AES]: false });
    // Toggle again → back to default ON → entry dropped.
    toggleSourceStrokeStylingEnabled(AES);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(true);
    expect(readMap()).toEqual({});

    // SHA-256 also starts ON → toggle → OFF (explicit false written).
    toggleSourceStrokeStylingEnabled(SHA);
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(false);
    expect(readMap()).toEqual({ [SHA]: false });
  });
});

describe("source-stroke per-spec fanout threshold", () => {
  it("defaultStrokeThresholdFor: 1 (universal default) for every spec", () => {
    expect(defaultStrokeThresholdFor("sha-256@1")).toBe(1);
    expect(defaultStrokeThresholdFor("sha-256@2")).toBe(1);
    expect(defaultStrokeThresholdFor("rsa@1")).toBe(1);
    expect(defaultStrokeThresholdFor("rsa-decrypt@1")).toBe(1);
    expect(defaultStrokeThresholdFor("aes-128@1")).toBe(DEFAULT_STROKE_THRESHOLD);
    expect(defaultStrokeThresholdFor("des@1")).toBe(DEFAULT_STROKE_THRESHOLD);
    expect(DEFAULT_STROKE_THRESHOLD).toBe(1);
  });

  it("reactive read falls back to the per-spec default when no override exists", () => {
    expect(useStrokeThreshold(() => SHA)()).toBe(1);
    expect(useStrokeThreshold(() => AES)()).toBe(DEFAULT_STROKE_THRESHOLD);
  });

  it("an explicit override persists per-spec and wins over the default", () => {
    setStrokeThreshold(AES, 0);
    expect(useStrokeThreshold(() => AES)()).toBe(0);
    // SHA-256 (untouched) still reads its own default.
    expect(useStrokeThreshold(() => SHA)()).toBe(1);
    expect(readThresholdMap()).toEqual({ [AES]: 0 });
  });

  it("clamps out-of-range high to MAX; non-finite falls back to the spec default", () => {
    setStrokeThreshold(AES, 999);
    expect(useStrokeThreshold(() => AES)()).toBe(STROKE_THRESHOLD_MAX);
    setStrokeThreshold(AES, Number.NaN);
    // NaN → spec default (1, universal) → drop-on-match → back to default.
    expect(useStrokeThreshold(() => AES)()).toBe(DEFAULT_STROKE_THRESHOLD);
    expect(readThresholdMap()).toEqual({});
  });

  it("setting a spec back to its shipped default DROPS the entry (drop-on-match)", () => {
    setStrokeThreshold(AES, 5);
    expect(readThresholdMap()).toEqual({ [AES]: 5 });
    setStrokeThreshold(AES, DEFAULT_STROKE_THRESHOLD);
    expect(readThresholdMap()).toEqual({});
    expect(useStrokeThreshold(() => AES)()).toBe(DEFAULT_STROKE_THRESHOLD);
  });

  it("SHA-256 set to a non-1 value writes an explicit entry; back to 1 drops it", () => {
    setStrokeThreshold(SHA, 4);
    expect(useStrokeThreshold(() => SHA)()).toBe(4);
    expect(readThresholdMap()).toEqual({ [SHA]: 4 });
    setStrokeThreshold(SHA, 1);
    expect(readThresholdMap()).toEqual({});
  });
});
