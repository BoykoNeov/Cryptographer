/**
 * Part B mechanism tests for curated default layouts
 * (graph-legibility plan, `docs/plans/toasty-zooming-harp.md`).
 *
 * Covers the PURE half of Part B: the catalogue's shape, the
 * `curatedDefaultFor` lookup + test seam, and — the load-bearing piece —
 * `mergeLayoutSpecs`'s per-key overlay (user wins per id, curated fills gaps).
 * The reactive GraphView wiring (reader split + reset-button split + suppress
 * flag) is exercised in the jsdom companion test.
 */

import { describe, expect, it } from "vitest";
import {
  CURATED_DEFAULT_LAYOUTS,
  __resetCuratedDefaultsForTests,
  __setCuratedDefaultsForTests,
  curatedDefaultFor,
  mergeLayoutSpecs,
} from "../src/core/default-layouts";
import type { LayoutSpec } from "../src/core/document";
import { LayoutSpecSchema } from "../src/core/document-schema";

describe("CURATED_DEFAULT_LAYOUTS catalogue", () => {
  it("every curated entry validates against LayoutSpecSchema", () => {
    // Vacuous while the catalogue is empty (B1); becomes a real gate the moment
    // a later chunk authors a layout. A malformed curated LayoutSpec would fail
    // `.strict()` parse here before it ever reaches the renderer.
    for (const [id, layout] of Object.entries(CURATED_DEFAULT_LAYOUTS)) {
      expect(LayoutSpecSchema.safeParse(layout), `entry ${id} must parse`).toMatchObject({
        success: true,
      });
    }
  });

  it("every curated key looks like a built-in spec id (`name@N`)", () => {
    // Structural stand-in for the full defaults/hashDefaults cross-check (those
    // tables are module-private). B2+ should tighten this to the real id set as
    // it populates the catalogue; the shape check catches a fat-fingered key now.
    for (const id of Object.keys(CURATED_DEFAULT_LAYOUTS)) {
      expect(id, `key ${id}`).toMatch(/^[a-z0-9-]+@\d+$/);
    }
  });

  it("ships empty in B1 (mechanism is a no-op until layouts are authored)", () => {
    expect(Object.keys(CURATED_DEFAULT_LAYOUTS)).toHaveLength(0);
  });
});

describe("curatedDefaultFor", () => {
  it("returns null for an id with no curated default", () => {
    expect(curatedDefaultFor("sha-256@1")).toBeNull();
    expect(curatedDefaultFor("not-a-real-id@9")).toBeNull();
  });

  it("test seam injects and resets a curated map", () => {
    const injected: LayoutSpec = {
      positions: { "round.0": { x: 10, y: 20 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    __setCuratedDefaultsForTests({ "sha-256@1": injected });
    try {
      expect(curatedDefaultFor("sha-256@1")).toBe(injected);
      expect(curatedDefaultFor("aes-128@1")).toBeNull();
    } finally {
      __resetCuratedDefaultsForTests();
    }
    expect(curatedDefaultFor("sha-256@1")).toBeNull();
  });
});

describe("mergeLayoutSpecs — per-key overlay, user wins per id", () => {
  it("user positions win per id; curated fills the gaps", () => {
    const curated: LayoutSpec = {
      positions: { a: { x: 1, y: 1 }, b: { x: 2, y: 2 }, c: { x: 3, y: 3 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const user: LayoutSpec = {
      positions: { b: { x: 99, y: 99 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const merged = mergeLayoutSpecs(curated, user);
    expect(merged.positions).toEqual({
      a: { x: 1, y: 1 }, // curated
      b: { x: 99, y: 99 }, // user overrides
      c: { x: 3, y: 3 }, // curated
    });
  });

  it("collapsedGroups union (dedup), preserving base-first order", () => {
    const curated: LayoutSpec = {
      positions: {},
      collapsedGroups: ["g1", "g2"],
      flowDirection: "ltr",
    };
    const user: LayoutSpec = {
      positions: {},
      collapsedGroups: ["g2", "g3"],
      flowDirection: "ltr",
    };
    expect(mergeLayoutSpecs(curated, user).collapsedGroups).toEqual(["g1", "g2", "g3"]);
  });

  it("expandedGroups union — a user expand of a curated-collapsed group survives the merge", () => {
    // Curated collapses `round.5`; user explicitly expanded it. The union keeps
    // both, and `getEffectiveCollapsedSet`'s (collapsed − expanded) subtract
    // lets the user's expand win at render time.
    const curated: LayoutSpec = {
      positions: {},
      collapsedGroups: ["round.5"],
      flowDirection: "ltr",
    };
    const user: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      expandedGroups: ["round.5"],
    };
    const merged = mergeLayoutSpecs(curated, user);
    expect(merged.collapsedGroups).toEqual(["round.5"]);
    expect(merged.expandedGroups).toEqual(["round.5"]);
  });

  it("replicationModes / relativePositions merge with user winning per id", () => {
    const curated: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      replicationModes: { s0: "always", s1: "never" },
      relativePositions: { chipA: { dx: 1, dy: 1 } },
    };
    const user: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      replicationModes: { s1: "always", s2: "never" },
      relativePositions: { chipA: { dx: 9, dy: 9 }, chipB: { dx: 2, dy: 2 } },
    };
    const merged = mergeLayoutSpecs(curated, user);
    expect(merged.replicationModes).toEqual({ s0: "always", s1: "always", s2: "never" });
    expect(merged.relativePositions).toEqual({
      chipA: { dx: 9, dy: 9 },
      chipB: { dx: 2, dy: 2 },
    });
  });

  it("strokeStyles is NOT carried into the effective layout (viewer channel, read off the user layout)", () => {
    // GraphView reads per-source arrow styles off the USER layout, not the
    // merged/effective one, so the merge deliberately drops the field — merging
    // it would be dead and would mislead a future curated-stroke author.
    const curated: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      strokeStyles: { s0: "short-dash" },
    };
    const user: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      strokeStyles: { s3: "long-dash" },
    };
    expect("strokeStyles" in mergeLayoutSpecs(curated, user)).toBe(false);
  });

  it("omits empty optionals (present-but-empty would differ from absent)", () => {
    const curated: LayoutSpec = {
      positions: { a: { x: 1, y: 1 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const user: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const merged = mergeLayoutSpecs(curated, user);
    expect("replicationModes" in merged).toBe(false);
    expect("relativePositions" in merged).toBe(false);
    expect("expandedGroups" in merged).toBe(false);
    expect("strokeStyles" in merged).toBe(false);
  });

  it("flowDirection comes from the user layout", () => {
    const curated: LayoutSpec = { positions: {}, collapsedGroups: [], flowDirection: "ltr" };
    const user: LayoutSpec = { positions: {}, collapsedGroups: [], flowDirection: "ltr" };
    expect(mergeLayoutSpecs(curated, user).flowDirection).toBe("ltr");
  });
});
