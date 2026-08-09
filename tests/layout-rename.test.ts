/**
 * Tests for `renameLayoutIds` and `renameSpecLayoutIds` from
 * `src/ui/stores/layout.ts`. The duplicate-round feature (Phase 3) uses
 * these helpers to migrate persisted layout pins, collapsed-group
 * markers, and per-source replication-mode overrides when the spec
 * mutator renumbers rounds.
 *
 * Three property groups:
 *   1. Pure `renameLayoutIds` — every field rewrites; un-renamed ids
 *      pass through; empty rename map is a referential no-op.
 *   2. `replicationModes` handling — present + non-empty stays;
 *      becomes-empty drops the field (byte-stability invariant); absent
 *      stays absent.
 *   3. `renameSpecLayoutIds` (the in-place store action) — writes
 *      through the signal AND localStorage; no-ops on missing spec.
 */

import type { LayoutSpec } from "@/core/document";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  renameLayoutIds,
  renameSpecLayoutIds,
  setLayoutForSpec,
} from "@/ui/stores/layout";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── 1. Pure renameLayoutIds ─────────────────────────────────────────────

describe("renameLayoutIds — positions", () => {
  it("renames pinned positions per the map; un-renamed ids pass through", () => {
    const layout: LayoutSpec = {
      positions: {
        "round.3": { x: 100, y: 50 },
        "round.4": { x: 200, y: 50 },
        "key-expansion": { x: 0, y: 0 },
      },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const renames = new Map([
      ["round.3", "round.4"],
      ["round.4", "round.5"],
    ]);
    const result = renameLayoutIds(layout, renames);

    // round.3 → round.4: position (100, 50) carries to round.4.
    // round.4 → round.5: original (200, 50) at round.4 carries to round.5.
    // Note: when both old AND new ids appear in the rename map, ordering
    // of `Object.entries` decides which "wins" at the destination. The
    // duplicate-round mutator emits non-overlapping shifts (a strict
    // up-shift), so the destination keys are always distinct.
    // Here the destinations round.4 and round.5 are distinct because the
    // shift is a contiguous renumber. The position at the NEW round.4
    // is the one carried from old round.3.
    expect(result.positions["round.4"]).toEqual({ x: 100, y: 50 });
    expect(result.positions["round.5"]).toEqual({ x: 200, y: 50 });
    // Un-renamed key-expansion stays.
    expect(result.positions["key-expansion"]).toEqual({ x: 0, y: 0 });
    // Old keys are gone.
    expect(result.positions["round.3"]).toBeUndefined();
  });

  it("returns the input by reference for an empty rename map", () => {
    const layout: LayoutSpec = {
      positions: { foo: { x: 1, y: 2 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const result = renameLayoutIds(layout, new Map());
    expect(result).toBe(layout); // referential equality
  });
});

describe("renameLayoutIds — collapsedGroups", () => {
  it("renames each id; un-renamed ids stay", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: ["round.3", "round.7", "key-expansion"],
      flowDirection: "ltr",
    };
    const renames = new Map([
      ["round.3", "round.4"],
      ["round.7", "round.8"],
    ]);
    const result = renameLayoutIds(layout, renames);
    expect(result.collapsedGroups).toEqual(["round.4", "round.8", "key-expansion"]);
  });
});

// ─── 2. replicationModes handling ────────────────────────────────────────

describe("renameLayoutIds — replicationModes", () => {
  it("renames keys; preserves the mode values verbatim", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      replicationModes: {
        "round.3.sub-bytes": "always",
        "key-expansion": "never",
      },
    };
    const renames = new Map([["round.3.sub-bytes", "round.4.sub-bytes"]]);
    const result = renameLayoutIds(layout, renames);

    expect(result.replicationModes).toEqual({
      "round.4.sub-bytes": "always",
      "key-expansion": "never",
    });
  });

  it("drops the field entirely when the rename empties it (byte stability)", () => {
    // Edge case: a rename map that maps every replicationModes key to
    // something else AND the something-else collides with existing keys.
    // The simpler check: an empty replicationModes object should be
    // omitted, not present-but-empty.
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      replicationModes: {},
    };
    const renames = new Map([["foo", "bar"]]);
    const result = renameLayoutIds(layout, renames);
    // The result must not carry a present-but-empty replicationModes,
    // since that would differ from an absent one at JSON serialization
    // (Slice 7's URL share + Slice 5's spec-only save both depend on
    // this).
    expect(Object.hasOwn(result, "replicationModes")).toBe(false);
  });

  it("leaves `replicationModes` absent when the input had no such field", () => {
    const layout: LayoutSpec = {
      positions: { foo: { x: 1, y: 1 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    const renames = new Map([["foo", "bar"]]);
    const result = renameLayoutIds(layout, renames);
    expect(Object.hasOwn(result, "replicationModes")).toBe(false);
  });
});

// ─── 2b. strokeStyles handling (Part A) ──────────────────────────────────
// strokeStyles keys on the CANONICAL source id — the same namespace as
// replicationModes — so a rename must remap it in parallel, and it must
// stay the LAST optional field to preserve byte-stable insertion order.

describe("renameLayoutIds — strokeStyles", () => {
  it("renames keys; preserves the style-name values verbatim", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      strokeStyles: {
        "round.3.sub-bytes": "short-dash",
        "key-expansion": "long-dash-heavy",
      },
    };
    const renames = new Map([["round.3.sub-bytes", "round.4.sub-bytes"]]);
    const result = renameLayoutIds(layout, renames);

    expect(result.strokeStyles).toEqual({
      "round.4.sub-bytes": "short-dash",
      "key-expansion": "long-dash-heavy",
    });
  });

  it("drops the field entirely when the input strokeStyles is empty (byte stability)", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      strokeStyles: {},
    };
    const result = renameLayoutIds(layout, new Map([["foo", "bar"]]));
    expect(Object.hasOwn(result, "strokeStyles")).toBe(false);
  });

  it("emits every optional field in buildLayoutSpec's order (byte-stable key order)", () => {
    // With every optional field populated, renameLayoutIds must reproduce
    // buildLayoutSpec's insertion order or a duplicate-round rename would
    // silently change a shared doc's bytes.
    const layout: LayoutSpec = {
      positions: { "round.3": { x: 1, y: 1 } },
      collapsedGroups: ["round.5"],
      flowDirection: "ltr",
      replicationModes: { "key-expansion": "always" },
      relativePositions: { "key-expansion@->round.3": { dx: 2, dy: 3 } },
      expandedGroups: ["round.7"],
      strokeStyles: { "key-expansion": "short-dash" },
      expandedLabels: ["round.9"],
    };
    const result = renameLayoutIds(layout, new Map([["round.3", "round.4"]]));
    expect(Object.keys(result)).toEqual([
      "positions",
      "collapsedGroups",
      "flowDirection",
      "replicationModes",
      "relativePositions",
      "expandedGroups",
      "strokeStyles",
      "expandedLabels",
    ]);
  });
});

describe("renameLayoutIds — expandedLabels (Option B)", () => {
  it("renames each id; un-renamed ids stay", () => {
    // `expandedLabels` keys real CONTAINER ids — exactly what the
    // duplicate-round mutator renumbers. This is the one field whose
    // omission from the remap `tsc` cannot catch: the layout would still
    // compile, still persist, and simply point at a round that no longer
    // exists, snapping the user's expanded label shut on duplicate.
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      expandedLabels: ["round.3", "round.9"],
    };
    const result = renameLayoutIds(layout, new Map([["round.3", "round.4"]]));

    expect(result.expandedLabels).toEqual(["round.4", "round.9"]);
  });

  it("leaves `expandedLabels` absent when the input had no such field", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: ["round.3"],
      flowDirection: "ltr",
    };
    const result = renameLayoutIds(layout, new Map([["round.3", "round.4"]]));
    expect(Object.hasOwn(result, "expandedLabels")).toBe(false);
  });

  it("drops the field entirely when the input expandedLabels is empty (byte stability)", () => {
    const layout: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
      expandedLabels: [],
    };
    const result = renameLayoutIds(layout, new Map([["foo", "bar"]]));
    expect(Object.hasOwn(result, "expandedLabels")).toBe(false);
  });
});

// ─── 3. renameSpecLayoutIds (in-place store action) ──────────────────────

describe("renameSpecLayoutIds — persistence", () => {
  beforeEach(() => {
    __resetLayoutsForTests();
  });

  afterEach(() => {
    __resetLayoutsForTests();
  });

  it("rewrites positions and collapsedGroups via the signal", () => {
    const before: LayoutSpec = {
      positions: { "round.3": { x: 10, y: 20 } },
      collapsedGroups: ["round.5"],
      flowDirection: "ltr",
    };
    setLayoutForSpec("aes-128@1", before);

    const renames = new Map([
      ["round.3", "round.4"],
      ["round.5", "round.6"],
    ]);
    renameSpecLayoutIds("aes-128@1", renames);

    const after = getLayoutForSpec("aes-128@1");
    expect(after?.positions).toEqual({ "round.4": { x: 10, y: 20 } });
    expect(after?.collapsedGroups).toEqual(["round.6"]);
  });

  it("is a no-op when the spec has no persisted layout", () => {
    // `aes-128@1` has no entry yet. The action should not create one.
    renameSpecLayoutIds("aes-128@1", new Map([["round.3", "round.4"]]));
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("is a no-op when the rename map is empty", () => {
    const before: LayoutSpec = {
      positions: { foo: { x: 1, y: 2 } },
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    setLayoutForSpec("aes-128@1", before);
    renameSpecLayoutIds("aes-128@1", new Map());
    // Same content. The store may or may not preserve ===, but the
    // observable state is unchanged.
    expect(getLayoutForSpec("aes-128@1")).toEqual(before);
  });
});
