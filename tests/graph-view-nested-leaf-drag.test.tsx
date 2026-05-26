// @vitest-environment jsdom

/**
 * GraphView — nested-leaf draggability (Slice S2(j)).
 *
 * SHA-256's expanded `msg-schedule` for-each-subgraph body contains
 * leaves with multi-input fan-IN (`sigma0` 3-in, `w-t` 4-in). Pre-S2(j)
 * the user reported "all the blocks are immovable" — couldn't manually
 * untangle the converging arrows. The `isDraggable` gate at GraphView
 * line ~5453 restricted drag to `isReplicaLike || isRootLevel`; nested
 * non-replica leaves were excluded.
 *
 * Post-S2(j): every leaf is draggable. Nested non-replica leaves get
 * the RELATIVE-pin path (same as replicas/chips, Slice 3) — their
 * auto-position is the iterate-flow layout, and the user delta is
 * persisted in `LayoutSpec.relativePositions`. The layout passes
 * already apply the delta to nested children (lines ~1299, ~1452,
 * ~1746 in GraphView.tsx), so no layout change is needed.
 *
 * This test pins the user-visible contract: simulate a drag on a SHA-256
 * nested non-replica leaf, assert a `relativePositions` entry is written.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { GraphView } from "@/ui/components/GraphView";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetLayoutsForTests, getLayoutForSpec, toggleCollapse } from "@/ui/stores/layout";
import { __resetSpecForTests, setHash } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SHA256_SPEC_ID = "sha-256@1";

const seedSha256Trace = (): void => {
  const trace = runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    portedDispatchEnabled: true,
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetReplicationForTests();
  __resetLayoutsForTests();
};

const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

describe("GraphView — nested non-replica leaf draggability (Slice S2(j))", () => {
  beforeEach(() => {
    resetAll();
    setHash("sha-256");
    seedSha256Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("leaves inside a GROUP (e.g. round.0.Sigma1) stay NON-draggable (S2(j) scope boundary)", () => {
    // S2(j)'s draggability flip is narrow: iteration-style containers
    // only (iterate, for-each-subgraph, for-each-subgraph-with-history).
    // Group children (AES round bodies, SHA-256 compression rounds —
    // both `kind: "group"`) keep the legacy non-draggable wiring so the
    // onClick path several click-based tests depend on stays intact.
    // This test pins the scope boundary so a future widening doesn't
    // silently break those click tests.
    toggleCollapse(SHA256_SPEC_ID, "round.0", true);

    const { container } = render(() => <GraphView />);
    const leaf = container.querySelector('[data-testid="graph-leaf-round.0.Sigma1"]');
    expect(leaf).not.toBeNull();
    if (!leaf) return;

    // No draggable class on group children.
    expect(leaf.classList.contains("graph-leaf-draggable")).toBe(false);

    // A pointerdown + move sequence on a non-draggable leaf writes
    // nothing to either pin map.
    leaf.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    window.dispatchEvent(pointerEvt("pointermove", 250, 225));
    window.dispatchEvent(pointerEvt("pointerup", 250, 225));

    const layout = getLayoutForSpec(SHA256_SPEC_ID);
    expect(layout?.positions["round.0.Sigma1"]).toBeUndefined();
    expect(layout?.relativePositions?.["round.0.Sigma1"]).toBeUndefined();
  });

  it("dragging a leaf inside an EXPANDED for-each-subgraph iteration body persists a relative pin", () => {
    // The user-reported case: open msg-schedule, drag one of the
    // multi-input convergence leaves (`w-t` here — 4 incoming edges).
    // `msg-schedule` is `defaultCollapsed: true`; force expansion so
    // its body leaves are rendered as draggable chips.
    toggleCollapse(SHA256_SPEC_ID, "msg-schedule", true);

    const { container } = render(() => <GraphView />);

    const leaf = container.querySelector('[data-testid="graph-leaf-w-t"]');
    expect(leaf).not.toBeNull();
    if (!leaf) return;

    // Drag w-t 40 px left and 60 px up (negative deltas exercise the
    // "no (0,0) clamp" branch of the relative-pin path).
    leaf.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    window.dispatchEvent(pointerEvt("pointermove", 160, 140));
    window.dispatchEvent(pointerEvt("pointerup", 160, 140));

    const layout = getLayoutForSpec(SHA256_SPEC_ID);
    expect(layout?.positions["w-t"]).toBeUndefined();
    const rel = layout?.relativePositions?.["w-t"];
    expect(rel).toBeDefined();
    expect(rel?.dx).toBeCloseTo(-40, 0);
    expect(rel?.dy).toBeCloseTo(-60, 0);
  });

  it("sub-threshold movement on an iteration-body leaf does NOT write a pin (click-vs-drag preserved)", () => {
    // Below the 4 px drag threshold, the gesture is a CLICK, not a
    // drag — relativePositions stays empty. Pins that S2(j)'s gate
    // flip didn't break the click-vs-drag discipline for the newly
    // draggable iteration-body leaves. `w-t` is inside the
    // `msg-schedule` for-each-subgraph-with-history, so it's the
    // analogue inside the now-draggable scope.
    toggleCollapse(SHA256_SPEC_ID, "msg-schedule", true);

    const { container } = render(() => <GraphView />);
    const leaf = container.querySelector('[data-testid="graph-leaf-w-t"]');
    expect(leaf).not.toBeNull();
    if (!leaf) return;

    // Move only 2 px — below DRAG_THRESHOLD_PX (4).
    leaf.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    window.dispatchEvent(pointerEvt("pointermove", 202, 200));
    window.dispatchEvent(pointerEvt("pointerup", 202, 200));

    const layout = getLayoutForSpec(SHA256_SPEC_ID);
    // Neither map has an entry — neither path was triggered.
    expect(layout?.relativePositions?.["w-t"]).toBeUndefined();
    expect(layout?.positions["w-t"]).toBeUndefined();
  });
});
