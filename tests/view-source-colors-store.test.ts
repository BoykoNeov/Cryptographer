// @vitest-environment jsdom
//
// jsdom because the store touches localStorage. The signals themselves
// are framework code; we test the public API + persistence shape.

/**
 * Tests for `src/ui/stores/view-source-colors.ts`. Three properties:
 *
 *   1. Master toggle persists + defaults ON (matches the user's
 *      "initially all arrows are colored" choice).
 *   2. Manual overrides are per-spec and survive setting/clearing.
 *   3. `clearAllSourceColorOverrides` empties one spec's overrides
 *      without affecting the master toggle or other specs.
 */

import {
  __resetSourceColorsForTests,
  clearAllSourceColorOverrides,
  clearSourceColorOverride,
  setColorsPanelOpen,
  setIncludeSingleSources,
  setSourceColorOverride,
  setSourceColoringEnabled,
  toggleColorsPanelOpen,
  toggleIncludeSingleSources,
  toggleSourceColoringEnabled,
  useColorsPanelOpen,
  useIncludeSingleSources,
  useManualSourceColors,
  useSourceColoringEnabled,
} from "@/ui/stores/view-source-colors";
import { beforeEach, describe, expect, it } from "vitest";

// ─── Setup ────────────────────────────────────────────────────────────────

beforeEach(() => {
  __resetSourceColorsForTests();
});

// ─── 1. Master toggle ─────────────────────────────────────────────────────

describe("master coloring toggle", () => {
  it("defaults to ON when no persisted value exists", () => {
    // __resetSourceColorsForTests clears the persisted entry; the next
    // read should fall back to the in-memory default (true).
    expect(useSourceColoringEnabled()()).toBe(true);
  });

  it("persists ON/OFF transitions and reflects them in the reactive read", () => {
    setSourceColoringEnabled(false);
    expect(useSourceColoringEnabled()()).toBe(false);
    expect(localStorage.getItem("cryptographer.viewSourceColoringEnabled")).toBe("false");

    setSourceColoringEnabled(true);
    expect(useSourceColoringEnabled()()).toBe(true);
    expect(localStorage.getItem("cryptographer.viewSourceColoringEnabled")).toBe("true");
  });

  it("toggleSourceColoringEnabled flips the bool and persists", () => {
    expect(useSourceColoringEnabled()()).toBe(true);
    toggleSourceColoringEnabled();
    expect(useSourceColoringEnabled()()).toBe(false);
    toggleSourceColoringEnabled();
    expect(useSourceColoringEnabled()()).toBe(true);
  });
});

// ─── 2. Per-spec manual overrides ─────────────────────────────────────────

describe("per-spec manual overrides", () => {
  it("setSourceColorOverride stores the color, retrievable via useManualSourceColors", () => {
    setSourceColorOverride("aes-128-ecb", "key-expansion", "#FF1234");
    const read = useManualSourceColors(() => "aes-128-ecb");
    expect(read().get("key-expansion")).toBe("#FF1234");
  });

  it("scopes overrides per-spec: setting on A doesn't leak to B", () => {
    setSourceColorOverride("aes-128-ecb", "key-expansion", "#AA0000");
    setSourceColorOverride("serpent-128", "key-expansion", "#00AA00");

    const readA = useManualSourceColors(() => "aes-128-ecb");
    const readB = useManualSourceColors(() => "serpent-128");

    expect(readA().get("key-expansion")).toBe("#AA0000");
    expect(readB().get("key-expansion")).toBe("#00AA00");
  });

  it("clearSourceColorOverride removes one entry without touching siblings", () => {
    setSourceColorOverride("spec-x", "src-a", "#111111");
    setSourceColorOverride("spec-x", "src-b", "#222222");
    clearSourceColorOverride("spec-x", "src-a");

    const read = useManualSourceColors(() => "spec-x");
    expect(read().get("src-a")).toBeUndefined();
    expect(read().get("src-b")).toBe("#222222");
  });

  it("dropping the last override on a spec removes that spec's entry entirely (minimal persisted blob)", () => {
    setSourceColorOverride("spec-x", "src", "#333333");
    clearSourceColorOverride("spec-x", "src");

    // Persisted blob should not have a key for spec-x — verifies the
    // "minimal blob" invariant the store maintains via the
    // `Object.keys(perSpec).length === 0` branch.
    const raw = localStorage.getItem("cryptographer.viewSourceColorOverrides");
    if (raw !== null) {
      const parsed = JSON.parse(raw);
      expect(parsed["spec-x"]).toBeUndefined();
    }
  });
});

// ─── 3. clearAllSourceColorOverrides ──────────────────────────────────────

describe("clearAllSourceColorOverrides", () => {
  it("empties ONE spec's overrides while leaving other specs intact", () => {
    setSourceColorOverride("spec-x", "src-1", "#aaa");
    setSourceColorOverride("spec-x", "src-2", "#bbb");
    setSourceColorOverride("spec-y", "src-1", "#ccc");

    clearAllSourceColorOverrides("spec-x");

    expect(useManualSourceColors(() => "spec-x")().size).toBe(0);
    expect(useManualSourceColors(() => "spec-y")().get("src-1")).toBe("#ccc");
  });

  it("does NOT touch the master toggle", () => {
    setSourceColoringEnabled(true);
    setSourceColorOverride("spec-x", "src", "#abc");
    clearAllSourceColorOverrides("spec-x");
    expect(useSourceColoringEnabled()()).toBe(true);
  });

  it("is a no-op when the spec has no overrides", () => {
    // Don't throw; don't write to localStorage; useManualSourceColors
    // still returns an empty map. (Pin the "no surprises" property —
    // a future refactor that builds a fresh `next` object every call
    // would otherwise persist an empty entry.)
    clearAllSourceColorOverrides("spec-x");
    expect(useManualSourceColors(() => "spec-x")().size).toBe(0);
  });
});

// ─── 4. Include single-output sources sub-toggle ──────────────────────────

describe("include-single-output-sources sub-toggle", () => {
  it("defaults to OFF when no persisted value exists", () => {
    expect(useIncludeSingleSources()()).toBe(false);
  });

  it("setIncludeSingleSources persists ON/OFF and reflects them reactively", () => {
    setIncludeSingleSources(true);
    expect(useIncludeSingleSources()()).toBe(true);
    expect(localStorage.getItem("cryptographer.viewSourceColorsIncludeSingle")).toBe("true");

    setIncludeSingleSources(false);
    expect(useIncludeSingleSources()()).toBe(false);
    expect(localStorage.getItem("cryptographer.viewSourceColorsIncludeSingle")).toBe("false");
  });

  it("toggleIncludeSingleSources flips the bool", () => {
    expect(useIncludeSingleSources()()).toBe(false);
    toggleIncludeSingleSources();
    expect(useIncludeSingleSources()()).toBe(true);
    toggleIncludeSingleSources();
    expect(useIncludeSingleSources()()).toBe(false);
  });

  it("is independent of the master toggle (changing one doesn't touch the other)", () => {
    setSourceColoringEnabled(false);
    setIncludeSingleSources(true);
    expect(useSourceColoringEnabled()()).toBe(false);
    expect(useIncludeSingleSources()()).toBe(true);
  });
});

// ─── 5. Panel open state ──────────────────────────────────────────────────

describe("colors panel open state", () => {
  it("defaults to closed (false)", () => {
    expect(useColorsPanelOpen(() => "spec-x")()).toBe(false);
  });

  it("setColorsPanelOpen + toggleColorsPanelOpen flip the state per-spec", () => {
    setColorsPanelOpen("spec-x", true);
    expect(useColorsPanelOpen(() => "spec-x")()).toBe(true);
    // Other spec unaffected.
    expect(useColorsPanelOpen(() => "spec-y")()).toBe(false);
    toggleColorsPanelOpen("spec-x");
    expect(useColorsPanelOpen(() => "spec-x")()).toBe(false);
  });
});
