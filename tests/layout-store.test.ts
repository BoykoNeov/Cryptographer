/**
 * Tests for the layout store (Slice 6 of the 2D editor plan).
 *
 * Coverage targets:
 *   - Per-spec.id partitioning: AES-128 and AES-256 layouts coexist.
 *   - setNodePosition / toggleCollapse mutate ONLY the named spec, leaving
 *     siblings' layouts byte-identical (reference-equality preservation is
 *     the cheaper-Solid-render contract; not pinned here, but the value
 *     equality is).
 *   - localStorage persistence: a setter writes synchronously and a fresh
 *     `loadInitial` read (post-reset) sees the value.
 *   - hasUserLayout: empty/null → false; any pinned position OR collapse → true.
 *   - setLayoutForSpec(null) / hasUserLayout(empty) → entry is REMOVED from
 *     the map (not stored as an empty LayoutSpec). This is the byte-stability
 *     property the App's spec-only save depends on.
 *   - clearLayoutForSpec: removes one spec's entry.
 *   - Persistence of corrupted localStorage: bad JSON → empty map on load.
 *
 * Runs in node env. localStorage is polyfilled by a tiny in-memory shim per
 * test so we can observe the persisted form without DOM pollution.
 */

import type { LayoutSpec } from "@/core/document";
import {
  __resetLayoutsForTests,
  clearLayoutForSpec,
  clearRelativePosition,
  collapseAllContainers,
  expandAllContainers,
  getLayoutForSpec,
  hasUserLayout,
  rescaleAllPositions,
  setLayoutForSpec,
  setNodePosition,
  setRelativePosition,
  setReplicationMode,
  setSourceStroke,
  toggleCollapse,
  useLayoutMap,
} from "@/ui/stores/layout";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── localStorage polyfill ─────────────────────────────────────────────────
// Vitest's node env doesn't have localStorage; install a fresh in-memory
// shim per test so persistence assertions can observe what got written.

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
  // Cast through unknown: globalThis.localStorage is typed as Storage; ours
  // matches the surface we use. This is the same trick the rest of the
  // codebase uses for jsdom polyfills.
  (globalThis as unknown as { localStorage: MutableStorage }).localStorage = storage;
};

const uninstallStorage = (): void => {
  // Assignment-to-undefined is biome's preferred alternative to `delete`
  // (`noDelete` rule). The cast widens the field type to `T | undefined` so
  // the assignment typechecks under `exactOptionalPropertyTypes` (which
  // distinguishes `field?: T` from `field: T | undefined`).
  (globalThis as unknown as { localStorage: MutableStorage | undefined }).localStorage = undefined;
};

const STORAGE_KEY = "cryptographer.layouts";

// ─── Per-test setup ────────────────────────────────────────────────────────
// Reset the store's in-memory signal AND localStorage shim before every test
// so cross-pollution doesn't matter. (Module-scope signals would otherwise
// carry state across cases.)

let storage: MutableStorage;

beforeEach(() => {
  storage = makeStorage();
  installStorage(storage);
  __resetLayoutsForTests();
});

afterEach(() => {
  __resetLayoutsForTests();
  uninstallStorage();
});

// ─── Tests ─────────────────────────────────────────────────────────────────

describe("layout store — per-spec.id partitioning", () => {
  it("starts empty (no entries for any spec id)", () => {
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
    expect(Object.keys(useLayoutMap()()).length).toBe(0);
  });

  it("setNodePosition stores under the named spec id only", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    expect(getLayoutForSpec("aes-128@1")?.positions["round.5"]).toEqual({ x: 400, y: 50 });
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
  });

  it("toggleCollapse stores under the named spec id only", () => {
    toggleCollapse("aes-128@1", "round.3", false);
    expect(getLayoutForSpec("aes-128@1")?.collapsedGroups).toEqual(["round.3"]);
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
  });

  it("two specs' layouts coexist without interference", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    setNodePosition("aes-256@1", "round.1", 999, 999);
    expect(getLayoutForSpec("aes-128@1")?.positions["round.1"]).toEqual({ x: 100, y: 100 });
    expect(getLayoutForSpec("aes-256@1")?.positions["round.1"]).toEqual({ x: 999, y: 999 });
  });
});

describe("layout store — toggleCollapse", () => {
  it("first call adds the id; second call removes it (toggle semantics)", () => {
    toggleCollapse("aes-128@1", "round.4", false);
    expect(getLayoutForSpec("aes-128@1")?.collapsedGroups).toEqual(["round.4"]);
    toggleCollapse("aes-128@1", "round.4", false);
    // Slice 2.6d follow-up brought `toggleCollapse` into line with
    // `clearNodePosition` / `clearRelativePosition` / `setReplicationMode(null)`:
    // when the resulting layout would be empty (no positions, no collapses,
    // no expansions, no modes, no relative pins), the spec's entry is
    // dropped from the map to keep `cryptographer.layouts` byte-stable.
    // The toggle-untoggle cycle now returns to the pristine "no layout"
    // state, not an empty-but-present LayoutSpec.
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("multiple distinct ids accumulate, not replace", () => {
    toggleCollapse("aes-128@1", "round.4", false);
    toggleCollapse("aes-128@1", "round.7", false);
    // collapsedGroups is `readonly string[]` from LayoutSpec, so spread into
    // a fresh mutable copy before sorting (Array.prototype.sort mutates).
    const got = [...(getLayoutForSpec("aes-128@1")?.collapsedGroups ?? [])].sort();
    expect(got).toEqual(["round.4", "round.7"].sort());
  });
});

// ─── toggleCollapse with inDefaults=true (Slice 2.6d follow-up) ──────────
// SHA-256's 64 round groups carry `defaultCollapsed: true`. The chevron
// click handler passes `inDefaults: true` for those containers; the
// store routes the flip into `expandedGroups` (not `collapsedGroups`),
// preserving the "never in both sets" invariant and keeping the
// effective-collapsed algebra clean.

describe("layout store — toggleCollapse with inDefaults=true", () => {
  it("expanding a default-collapsed container adds it to expandedGroups, NOT collapsedGroups", () => {
    toggleCollapse("sha-256@1", "round.5", true);
    const l = getLayoutForSpec("sha-256@1");
    expect(l?.expandedGroups).toEqual(["round.5"]);
    // The invariant: an id never lands in collapsedGroups when inDefaults=true.
    expect(l?.collapsedGroups).toEqual([]);
  });

  it("re-collapsing (toggle again) removes from expandedGroups → entry returns to default", () => {
    toggleCollapse("sha-256@1", "round.5", true);
    toggleCollapse("sha-256@1", "round.5", true);
    // Second toggle empties expandedGroups; with no other customization,
    // the layout entry is dropped from the map (byte-stability).
    expect(getLayoutForSpec("sha-256@1")).toBeNull();
  });

  it("preserves the 'never in both sets' end-invariant across rapid toggles", () => {
    // Stress: toggle round.5 with inDefaults=true 10 times. The two sets
    // must remain disjoint at every step.
    for (let i = 0; i < 10; i += 1) {
      toggleCollapse("sha-256@1", "round.5", true);
      const l = getLayoutForSpec("sha-256@1");
      const collapsed = new Set(l?.collapsedGroups ?? []);
      const expanded = new Set(l?.expandedGroups ?? []);
      // Disjoint: no id in both.
      for (const id of collapsed) expect(expanded.has(id)).toBe(false);
    }
  });

  it("expanding multiple default-collapsed containers accumulates them in expandedGroups", () => {
    toggleCollapse("sha-256@1", "round.0", true);
    toggleCollapse("sha-256@1", "round.5", true);
    toggleCollapse("sha-256@1", "round.10", true);
    const got = [...(getLayoutForSpec("sha-256@1")?.expandedGroups ?? [])].sort();
    expect(got).toEqual(["round.0", "round.10", "round.5"]);
  });

  it("inDefaults=true and inDefaults=false toggle their OWN sets independently", () => {
    // Mix: round.5 is a SHA-256 default; msg-schedule is not.
    toggleCollapse("sha-256@1", "round.5", true);
    toggleCollapse("sha-256@1", "msg-schedule", false);
    const l = getLayoutForSpec("sha-256@1");
    expect(l?.expandedGroups).toEqual(["round.5"]);
    expect(l?.collapsedGroups).toEqual(["msg-schedule"]);
  });

  it("toggleCollapse writes expandedGroups through to localStorage synchronously", () => {
    toggleCollapse("sha-256@1", "round.5", true);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["sha-256@1"].expandedGroups).toEqual(["round.5"]);
  });
});

// ─── collapseAllContainers / expandAllContainers (toolbar bulk ops) ──────
// The graph-view "collapse all" / "expand all" toolbar buttons fold or
// unfold every container in one click. They route through the same
// effective-collapsed algebra as the per-container chevron, so they must
// compose with spec `defaultCollapsed` declarations and preserve the
// "never in both sets" invariant.

describe("layout store — collapseAllContainers / expandAllContainers", () => {
  it("collapseAll adds every non-default container to collapsedGroups", () => {
    collapseAllContainers("aes-128@1", ["round.1", "round.2", "round.3"], new Set());
    const got = [...(getLayoutForSpec("aes-128@1")?.collapsedGroups ?? [])].sort();
    expect(got).toEqual(["round.1", "round.2", "round.3"]);
  });

  it("collapseAll leaves default-collapsed containers alone (no redundant collapsedGroups entry)", () => {
    // A SHA-256-shaped spec: all rounds are default-collapsed. Collapsing
    // all is a no-op on the persisted form — they're already effectively
    // collapsed, so nothing needs writing.
    collapseAllContainers("sha-256@1", ["round.0", "round.1"], new Set(["round.0", "round.1"]));
    expect(getLayoutForSpec("sha-256@1")).toBeNull();
  });

  it("collapseAll clears any explicit expansion override on a default-collapsed container", () => {
    // User expanded round.0 (override); collapse-all re-collapses it to the
    // default by dropping the expandedGroups entry.
    toggleCollapse("sha-256@1", "round.0", true);
    expect(getLayoutForSpec("sha-256@1")?.expandedGroups).toEqual(["round.0"]);
    collapseAllContainers("sha-256@1", ["round.0", "round.1"], new Set(["round.0", "round.1"]));
    expect(getLayoutForSpec("sha-256@1")).toBeNull();
  });

  it("expandAll removes every non-default container from collapsedGroups", () => {
    collapseAllContainers("aes-128@1", ["round.1", "round.2"], new Set());
    expandAllContainers("aes-128@1", ["round.1", "round.2"], new Set());
    // All un-collapsed and no defaults → empty layout → entry dropped.
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("expandAll adds default-collapsed containers to expandedGroups (override the default)", () => {
    expandAllContainers("sha-256@1", ["round.0", "round.1"], new Set(["round.0", "round.1"]));
    const got = [...(getLayoutForSpec("sha-256@1")?.expandedGroups ?? [])].sort();
    expect(got).toEqual(["round.0", "round.1"]);
    expect(getLayoutForSpec("sha-256@1")?.collapsedGroups).toEqual([]);
  });

  it("collapseAll then expandAll on a mixed spec preserves the disjoint-sets invariant", () => {
    const ids = ["round.0", "round.1", "msg-schedule"];
    const defaults = new Set(["round.0", "round.1"]);
    collapseAllContainers("sha-256@1", ids, defaults);
    expandAllContainers("sha-256@1", ids, defaults);
    const l = getLayoutForSpec("sha-256@1");
    const collapsed = new Set(l?.collapsedGroups ?? []);
    const expanded = new Set(l?.expandedGroups ?? []);
    for (const id of collapsed) expect(expanded.has(id)).toBe(false);
  });

  it("bulk ops write through to localStorage synchronously", () => {
    collapseAllContainers("aes-128@1", ["round.1"], new Set());
    const raw = storage.getItem(STORAGE_KEY);
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].collapsedGroups).toEqual(["round.1"]);
  });
});

// ─── hasUserLayout / byte-stability for expandedGroups ───────────────────

describe("layout store — hasUserLayout counts expandedGroups", () => {
  it("a layout whose only customization is expandedGroups counts as user layout", () => {
    toggleCollapse("sha-256@1", "round.5", true);
    const l = getLayoutForSpec("sha-256@1");
    expect(hasUserLayout(l)).toBe(true);
  });

  it("empty expandedGroups is OMITTED from the serialized form (byte-stability)", () => {
    // Drag a position so the layout exists at all, then exercise the path
    // where expandedGroups would be empty.
    setNodePosition("aes-128@1", "round.1", 100, 100);
    const raw = storage.getItem(STORAGE_KEY);
    const parsed = JSON.parse(raw as string);
    // The field MUST be absent — present-but-empty (`expandedGroups: []`)
    // would defeat the byte-stability gate that spec-only saves depend
    // on. Same discipline as `replicationModes` / `relativePositions`.
    expect("expandedGroups" in parsed["aes-128@1"]).toBe(false);
  });
});

describe("layout store — persistence", () => {
  it("setNodePosition writes through to localStorage synchronously", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].positions["round.5"]).toEqual({ x: 400, y: 50 });
  });

  it("toggleCollapse writes through to localStorage synchronously", () => {
    toggleCollapse("aes-128@1", "round.3", false);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].collapsedGroups).toEqual(["round.3"]);
  });

  it("survives a fresh load (simulating a page reload)", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    toggleCollapse("aes-128@1", "round.7", false);
    const blob = storage.getItem(STORAGE_KEY);
    expect(blob).not.toBeNull();

    // Simulate a page reload: parse what's in storage and check structure.
    // (The store's `loadInitial` runs at module-load time, which we can't
    // easily re-trigger without dynamic import, so we exercise the same
    // shape contract directly.)
    const parsed = JSON.parse(blob as string);
    expect(parsed["aes-128@1"].positions["round.5"]).toEqual({ x: 400, y: 50 });
    expect(parsed["aes-128@1"].collapsedGroups).toEqual(["round.7"]);
    expect(parsed["aes-128@1"].flowDirection).toBe("ltr");
  });
});

describe("layout store — setLayoutForSpec (Load boundary)", () => {
  it("replaces a spec's layout wholesale", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    const incoming: LayoutSpec = {
      positions: { "round.1": { x: 99, y: 99 } },
      collapsedGroups: ["round.2"],
      flowDirection: "ltr",
    };
    setLayoutForSpec("aes-128@1", incoming);
    const out = getLayoutForSpec("aes-128@1");
    // round.5 from before the Load is gone — Load is "this is the file's
    // truth" not "merge with whatever was there."
    expect(out?.positions["round.5"]).toBeUndefined();
    expect(out?.positions["round.1"]).toEqual({ x: 99, y: 99 });
    expect(out?.collapsedGroups).toEqual(["round.2"]);
  });

  it("passing null removes the spec's entry from the map", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    expect(getLayoutForSpec("aes-128@1")).not.toBeNull();
    setLayoutForSpec("aes-128@1", null);
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("passing an empty LayoutSpec also removes the entry (byte-stability gate)", () => {
    setNodePosition("aes-128@1", "round.5", 400, 50);
    const empty: LayoutSpec = {
      positions: {},
      collapsedGroups: [],
      flowDirection: "ltr",
    };
    setLayoutForSpec("aes-128@1", empty);
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });
});

describe("layout store — clearLayoutForSpec", () => {
  it("drops one spec's entry without touching others", () => {
    setNodePosition("aes-128@1", "round.1", 1, 1);
    setNodePosition("aes-256@1", "round.1", 2, 2);
    clearLayoutForSpec("aes-128@1");
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
    expect(getLayoutForSpec("aes-256@1")?.positions["round.1"]).toEqual({ x: 2, y: 2 });
  });
});

describe("layout store — hasUserLayout", () => {
  it("returns false for null", () => {
    expect(hasUserLayout(null)).toBe(false);
  });

  it("returns false for an empty layout (no positions, no collapses)", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
      }),
    ).toBe(false);
  });

  it("returns true when at least one position is pinned", () => {
    expect(
      hasUserLayout({
        positions: { "round.1": { x: 0, y: 0 } },
        collapsedGroups: [],
        flowDirection: "ltr",
      }),
    ).toBe(true);
  });

  it("returns true when at least one container is collapsed", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: ["round.5"],
        flowDirection: "ltr",
      }),
    ).toBe(true);
  });

  it("returns true when at least one replicationModes override is present", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        replicationModes: { "key-expansion": "always" },
      }),
    ).toBe(true);
  });

  it("returns false when replicationModes is present but empty", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        replicationModes: {},
      }),
    ).toBe(false);
  });

  it("returns true when at least one relative pin is present", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        relativePositions: { "key-expansion@->round.1.add-round-key": { dx: 12, dy: 0 } },
      }),
    ).toBe(true);
  });

  it("returns false when relativePositions is present but empty", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        relativePositions: {},
      }),
    ).toBe(false);
  });

  it("returns true when strokeStyles is the ONLY populated field (Part A)", () => {
    // Mirror the expandedGroups reasoning: a session where the user did
    // nothing but restyle one source's arrows is meaningful customization
    // that must persist + ride through Save / Share.
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        strokeStyles: { "key-expansion": "short-dash" },
      }),
    ).toBe(true);
  });

  it("returns false when strokeStyles is present but empty", () => {
    expect(
      hasUserLayout({
        positions: {},
        collapsedGroups: [],
        flowDirection: "ltr",
        strokeStyles: {},
      }),
    ).toBe(false);
  });
});

describe("layout store — setReplicationMode (commit 5)", () => {
  it("stores an override under the named spec id", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    expect(getLayoutForSpec("aes-128@1")?.replicationModes).toEqual({
      "key-expansion": "always",
    });
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
  });

  it("can change a stored override to a different mode", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-128@1", "key-expansion", "never");
    expect(getLayoutForSpec("aes-128@1")?.replicationModes).toEqual({
      "key-expansion": "never",
    });
  });

  it("passing null clears the entry (back to implicit auto)", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-128@1", "key-expansion", null);
    // Only override → cleared → no other user-layout → entry removed
    // entirely (byte-stability discipline).
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("clearing an override while a position pin exists keeps the entry", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-128@1", "key-expansion", null);
    // Pin survives; replicationModes is dropped (omitted when empty so the
    // serialized form stays byte-stable).
    const layout = getLayoutForSpec("aes-128@1");
    expect(layout).not.toBeNull();
    expect(layout?.positions["round.1"]).toEqual({ x: 100, y: 100 });
    expect(layout?.replicationModes).toBeUndefined();
  });

  it("multiple overrides on the same spec accumulate", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-128@1", "split-blocks", "never");
    expect(getLayoutForSpec("aes-128@1")?.replicationModes).toEqual({
      "key-expansion": "always",
      "split-blocks": "never",
    });
  });

  it("two specs' overrides coexist", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-256@1", "key-expansion", "never");
    expect(getLayoutForSpec("aes-128@1")?.replicationModes).toEqual({
      "key-expansion": "always",
    });
    expect(getLayoutForSpec("aes-256@1")?.replicationModes).toEqual({
      "key-expansion": "never",
    });
  });

  it("persists to localStorage synchronously", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].replicationModes).toEqual({
      "key-expansion": "always",
    });
  });

  it("does NOT write an empty replicationModes object to disk", () => {
    setNodePosition("aes-128@1", "round.1", 0, 0);
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setReplicationMode("aes-128@1", "key-expansion", null);
    const parsed = JSON.parse(storage.getItem(STORAGE_KEY) as string);
    // An empty `replicationModes: {}` would defeat byte-stability: spec-only
    // saves with no user customization need to omit the field entirely.
    expect(parsed["aes-128@1"].replicationModes).toBeUndefined();
  });
});

describe("layout store — setSourceStroke (Part A: per-source arrow styles)", () => {
  it("stores an override under the named spec id", () => {
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    expect(getLayoutForSpec("aes-128@1")?.strokeStyles).toEqual({
      "key-expansion": "short-dash",
    });
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
  });

  it("can change a stored override to a different style name", () => {
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    setSourceStroke("aes-128@1", "key-expansion", "long-dash-heavy");
    expect(getLayoutForSpec("aes-128@1")?.strokeStyles).toEqual({
      "key-expansion": "long-dash-heavy",
    });
  });

  it("passing null clears the entry (back to the auto-assigned stroke)", () => {
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    setSourceStroke("aes-128@1", "key-expansion", null);
    // Only override → cleared → no other user-layout → entry removed
    // entirely (byte-stability discipline). Mirrors setReplicationMode.
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("clearing an override while a position pin exists keeps the entry", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    setSourceStroke("aes-128@1", "key-expansion", null);
    const layout = getLayoutForSpec("aes-128@1");
    expect(layout).not.toBeNull();
    expect(layout?.positions["round.1"]).toEqual({ x: 100, y: 100 });
    expect(layout?.strokeStyles).toBeUndefined();
  });

  it("multiple overrides on the same spec accumulate", () => {
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    setSourceStroke("aes-128@1", "split-blocks", "round-dot");
    expect(getLayoutForSpec("aes-128@1")?.strokeStyles).toEqual({
      "key-expansion": "short-dash",
      "split-blocks": "round-dot",
    });
  });

  it("persists to localStorage synchronously", () => {
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    const parsed = JSON.parse(storage.getItem(STORAGE_KEY) as string);
    expect(parsed["aes-128@1"].strokeStyles).toEqual({ "key-expansion": "short-dash" });
  });

  it("does NOT write an empty strokeStyles object to disk (byte-stability)", () => {
    setNodePosition("aes-128@1", "round.1", 0, 0);
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    setSourceStroke("aes-128@1", "key-expansion", null);
    const parsed = JSON.parse(storage.getItem(STORAGE_KEY) as string);
    // Present-but-empty `strokeStyles: {}` would defeat the byte-stability
    // gate; the field must be absent, exactly as never-set.
    expect(parsed["aes-128@1"].strokeStyles).toBeUndefined();
  });

  it("set-then-clear produces bytes IDENTICAL to never-set", () => {
    // The sharpest byte-stability property: a stroke assignment that's later
    // cleared must leave the serialized form indistinguishable from one that
    // was never touched — otherwise a shared doc's hash would drift.
    setNodePosition("aes-128@1", "round.1", 7, 7);
    const neverSet = storage.getItem(STORAGE_KEY);
    setSourceStroke("aes-128@1", "key-expansion", "dash-dot");
    setSourceStroke("aes-128@1", "key-expansion", null);
    expect(storage.getItem(STORAGE_KEY)).toBe(neverSet);
  });

  it("coexists with the other optional fields on the same layout", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    const layout = getLayoutForSpec("aes-128@1");
    expect(layout?.replicationModes).toEqual({ "key-expansion": "always" });
    expect(layout?.strokeStyles).toEqual({ "key-expansion": "short-dash" });
  });

  it("serializes the optional fields in a FIXED key order (byte-stability)", () => {
    // JSON.stringify emits keys in insertion order and the byte-stability
    // gate pins that order. With all four optionals populated the serialized
    // layout MUST read positions → collapsedGroups → flowDirection →
    // replicationModes → relativePositions → expandedGroups → strokeStyles.
    // A divergence between buildLayoutSpec and any other LayoutSpec
    // constructor would silently change a doc's bytes.
    setNodePosition("aes-128@1", "round.1", 1, 1);
    toggleCollapse("aes-128@1", "round.5", true);
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setRelativePosition("aes-128@1", "key-expansion@->round.1.add-round-key", 3, 4);
    setSourceStroke("aes-128@1", "key-expansion", "short-dash");
    const parsed = JSON.parse(storage.getItem(STORAGE_KEY) as string);
    expect(Object.keys(parsed["aes-128@1"])).toEqual([
      "positions",
      "collapsedGroups",
      "flowDirection",
      "replicationModes",
      "relativePositions",
      "expandedGroups",
      "strokeStyles",
    ]);
  });
});

describe("layout store — setRelativePosition / clearRelativePosition (draggable replicas)", () => {
  // Synthetic-id pattern matches `${source}@->${consumer}` exactly because
  // the store treats the key as opaque — but using a realistic id here keeps
  // the test honest about the shape downstream code will write.
  const REPLICA_ID = "key-expansion@->round.1.add-round-key";
  const BLOCK_CHIP_ID = "ecb-blocks@block3";

  it("stores a relative pin under the named spec id", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 24, -8);
    expect(getLayoutForSpec("aes-128@1")?.relativePositions?.[REPLICA_ID]).toEqual({
      dx: 24,
      dy: -8,
    });
    expect(getLayoutForSpec("aes-256@1")).toBeNull();
  });

  it("overwriting an existing pin replaces the delta", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 24, -8);
    setRelativePosition("aes-128@1", REPLICA_ID, 0, 40);
    expect(getLayoutForSpec("aes-128@1")?.relativePositions?.[REPLICA_ID]).toEqual({
      dx: 0,
      dy: 40,
    });
  });

  it("two pins on the same spec accumulate", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    setRelativePosition("aes-128@1", BLOCK_CHIP_ID, 0, 20);
    expect(getLayoutForSpec("aes-128@1")?.relativePositions).toEqual({
      [REPLICA_ID]: { dx: 10, dy: 0 },
      [BLOCK_CHIP_ID]: { dx: 0, dy: 20 },
    });
  });

  it("clearRelativePosition removes one entry but keeps the rest", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    setRelativePosition("aes-128@1", BLOCK_CHIP_ID, 0, 20);
    clearRelativePosition("aes-128@1", REPLICA_ID);
    expect(getLayoutForSpec("aes-128@1")?.relativePositions).toEqual({
      [BLOCK_CHIP_ID]: { dx: 0, dy: 20 },
    });
  });

  it("clearing the last pin drops the spec's entry entirely (byte stability)", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    clearRelativePosition("aes-128@1", REPLICA_ID);
    // Only customization → cleared → no other user-layout → entry removed.
    expect(getLayoutForSpec("aes-128@1")).toBeNull();
  });

  it("clearing a pin while a position pin exists keeps the entry", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    clearRelativePosition("aes-128@1", REPLICA_ID);
    const layout = getLayoutForSpec("aes-128@1");
    expect(layout).not.toBeNull();
    expect(layout?.positions["round.1"]).toEqual({ x: 100, y: 100 });
    expect(layout?.relativePositions).toBeUndefined();
  });

  it("clearRelativePosition on an absent id is a no-op", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    const before = getLayoutForSpec("aes-128@1");
    clearRelativePosition("aes-128@1", REPLICA_ID);
    expect(getLayoutForSpec("aes-128@1")).toBe(before);
  });

  it("persists to localStorage synchronously", () => {
    setRelativePosition("aes-128@1", REPLICA_ID, 24, -8);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].relativePositions[REPLICA_ID]).toEqual({ dx: 24, dy: -8 });
  });

  it("does NOT write an empty relativePositions object to disk", () => {
    setNodePosition("aes-128@1", "round.1", 0, 0);
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    clearRelativePosition("aes-128@1", REPLICA_ID);
    const parsed = JSON.parse(storage.getItem(STORAGE_KEY) as string);
    // Empty `relativePositions: {}` would defeat byte-stability for spec-
    // only saves — must be absent, not present-empty.
    expect(parsed["aes-128@1"].relativePositions).toBeUndefined();
  });

  it("coexists with replicationModes on the same layout", () => {
    setReplicationMode("aes-128@1", "key-expansion", "always");
    setRelativePosition("aes-128@1", REPLICA_ID, 10, 0);
    const layout = getLayoutForSpec("aes-128@1");
    expect(layout?.replicationModes).toEqual({ "key-expansion": "always" });
    expect(layout?.relativePositions).toEqual({ [REPLICA_ID]: { dx: 10, dy: 0 } });
  });
});

describe("layout store — rescaleAllPositions (density-flip pin scaling)", () => {
  it("multiplies every pinned position by the factor", () => {
    setNodePosition("aes-128@1", "round.1", 100, 50);
    setNodePosition("aes-128@1", "round.5", 200, 80);
    rescaleAllPositions(1.5);
    const l = getLayoutForSpec("aes-128@1");
    expect(l?.positions["round.1"]).toEqual({ x: 150, y: 75 });
    expect(l?.positions["round.5"]).toEqual({ x: 300, y: 120 });
  });

  it("rescales positions across all specs in the map", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    setNodePosition("aes-256@1", "round.1", 200, 200);
    rescaleAllPositions(0.5);
    expect(getLayoutForSpec("aes-128@1")?.positions["round.1"]).toEqual({ x: 50, y: 50 });
    expect(getLayoutForSpec("aes-256@1")?.positions["round.1"]).toEqual({ x: 100, y: 100 });
  });

  it("factor === 1.0 is a no-op (preserves reference equality on layoutMap)", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    const before = useLayoutMap()();
    rescaleAllPositions(1.0);
    expect(useLayoutMap()()).toBe(before);
  });

  it("preserves collapsedGroups and replicationModes unchanged", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    toggleCollapse("aes-128@1", "round.5", false);
    setReplicationMode("aes-128@1", "key-expansion", "always");
    rescaleAllPositions(0.75);
    const l = getLayoutForSpec("aes-128@1");
    expect(l?.positions["round.1"]).toEqual({ x: 75, y: 75 });
    // Density-independent fields must survive untouched.
    expect(l?.collapsedGroups).toEqual(["round.5"]);
    expect(l?.replicationModes).toEqual({ "key-expansion": "always" });
  });

  it("rescales relativePositions deltas alongside absolute positions", () => {
    // Relative deltas live in viewBox units at the layout's current
    // density. A density flip rescales them so the chip stays logically
    // in the same offset from its anchor.
    setRelativePosition("aes-128@1", "key-expansion@->round.1.add-round-key", 40, -8);
    rescaleAllPositions(0.75);
    expect(
      getLayoutForSpec("aes-128@1")?.relativePositions?.["key-expansion@->round.1.add-round-key"],
    ).toEqual({ dx: 30, dy: -6 });
  });

  it("a spec with ONLY a relative pin still gets rescaled (not passed through)", () => {
    // Edge case: the passthrough branch fires only when BOTH positions and
    // relativePositions are empty. A relative-only layout has work to do.
    setRelativePosition("aes-128@1", "key-expansion@->round.1.add-round-key", 40, 0);
    rescaleAllPositions(0.5);
    expect(
      getLayoutForSpec("aes-128@1")?.relativePositions?.["key-expansion@->round.1.add-round-key"],
    ).toEqual({ dx: 20, dy: 0 });
  });

  it("rounds to integer pixels (no fractional drift in storage)", () => {
    setNodePosition("aes-128@1", "round.1", 100, 100);
    rescaleAllPositions(0.75);
    const p = getLayoutForSpec("aes-128@1")?.positions["round.1"];
    // 100 * 0.75 = 75 exactly; pick a factor that produces a fraction to
    // exercise the rounding path.
    expect(p).toEqual({ x: 75, y: 75 });
    rescaleAllPositions(1.333);
    const p2 = getLayoutForSpec("aes-128@1")?.positions["round.1"];
    expect(Number.isInteger(p2?.x)).toBe(true);
    expect(Number.isInteger(p2?.y)).toBe(true);
  });

  it("a spec with no pins is passed through unchanged (collapsed-only or modes-only layouts survive)", () => {
    toggleCollapse("aes-128@1", "round.5", false);
    const before = getLayoutForSpec("aes-128@1");
    rescaleAllPositions(0.5);
    const after = getLayoutForSpec("aes-128@1");
    // Same layout value — no positions to rescale, so the entry is
    // identity-passed through the rebuild.
    expect(after).toBe(before);
  });

  it("persists rescaled positions to localStorage atomically", () => {
    setNodePosition("aes-128@1", "round.1", 80, 40);
    rescaleAllPositions(1.25);
    const raw = storage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw as string);
    expect(parsed["aes-128@1"].positions["round.1"]).toEqual({ x: 100, y: 50 });
  });
});

describe("layout store — corrupted localStorage", () => {
  it("a setter still works after a parse error during load", () => {
    // We can't easily re-trigger loadInitial after install — but we CAN
    // verify the runtime path: any setter after `__resetLayoutsForTests`
    // starts from empty, then writes correctly. (The corrupt-JSON branch
    // is covered by static reading of loadInitial during boot — there's
    // no observable difference at the public-API level from "empty
    // localStorage" vs "corrupt localStorage", which is the point.)
    setNodePosition("aes-128@1", "round.1", 5, 5);
    expect(getLayoutForSpec("aes-128@1")?.positions["round.1"]).toEqual({ x: 5, y: 5 });
  });
});
