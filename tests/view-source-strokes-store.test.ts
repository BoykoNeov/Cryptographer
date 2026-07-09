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
 * keyed by `spec.id` because its shipped default differs per built-in: OFF
 * everywhere EXCEPT SHA-256, which ships ON (user-decided 2026-07-09). The
 * store owns no manual-override map (those live on `LayoutSpec.strokeStyles`,
 * chunk A2) and no threshold (reused from `view-source-colors`). So the
 * properties to pin are:
 *
 *   1. Per-spec default: SHA-256 ON, every other spec OFF.
 *   2. Explicit overrides persist and win over the default.
 *   3. Drop-on-match: setting a spec back to its default removes the entry,
 *      so the persisted map stays minimal (and a future default change is
 *      never shadowed by a stale entry).
 */

import {
  __resetSourceStrokesForTests,
  defaultStrokeStylingFor,
  setSourceStrokeStylingEnabled,
  toggleSourceStrokeStylingEnabled,
  useSourceStrokeStylingEnabled,
} from "@/ui/stores/view-source-strokes";
import { beforeEach, describe, expect, it } from "vitest";

const STORAGE_KEY = "cryptographer.viewSourceStrokesEnabled";
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

beforeEach(() => {
  __resetSourceStrokesForTests();
});

describe("source-stroke per-spec master toggle", () => {
  it("defaultStrokeStylingFor: ON for SHA-256 (any @N), OFF for every other spec", () => {
    expect(defaultStrokeStylingFor("sha-256@1")).toBe(true);
    expect(defaultStrokeStylingFor("sha-256@2")).toBe(true);
    expect(defaultStrokeStylingFor("aes-128@1")).toBe(false);
    expect(defaultStrokeStylingFor("des@1")).toBe(false);
    expect(defaultStrokeStylingFor("rsa@1")).toBe(false);
  });

  it("reactive read falls back to the per-spec default when no override exists", () => {
    // The reason A3b ships OFF-except-SHA-256: SHA-256 saturates the 8-colour
    // palette so the dash channel earns its keep on first open; the others
    // have few enough sources that colour alone suffices.
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(true);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(false);
  });

  it("an explicit override wins over the default and persists per-spec", () => {
    setSourceStrokeStylingEnabled(AES, true);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(true);
    // SHA-256 (untouched) still reads its own default.
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(true);
    expect(readMap()).toEqual({ [AES]: true });
  });

  it("setting a spec back to its shipped default DROPS the entry (drop-on-match)", () => {
    // AES default is OFF: turning it ON writes an entry, turning it back OFF
    // (== default) removes it, so the persisted map returns to empty.
    setSourceStrokeStylingEnabled(AES, true);
    expect(readMap()).toEqual({ [AES]: true });
    setSourceStrokeStylingEnabled(AES, false);
    expect(readMap()).toEqual({});
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(false);
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
    // AES starts OFF → toggle → ON (entry written).
    toggleSourceStrokeStylingEnabled(AES);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(true);
    expect(readMap()).toEqual({ [AES]: true });
    // Toggle again → back to default OFF → entry dropped.
    toggleSourceStrokeStylingEnabled(AES);
    expect(useSourceStrokeStylingEnabled(() => AES)()).toBe(false);
    expect(readMap()).toEqual({});

    // SHA-256 starts ON → toggle → OFF (explicit false written).
    toggleSourceStrokeStylingEnabled(SHA);
    expect(useSourceStrokeStylingEnabled(() => SHA)()).toBe(false);
    expect(readMap()).toEqual({ [SHA]: false });
  });
});
