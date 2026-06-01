// @vitest-environment jsdom

/**
 * Slice 3 of the draggable-replicas plan (2026-05-19).
 *
 * Drag-handler integration: pointerdown on a replica chip now triggers
 * the RELATIVE-pin path of `startNodeDrag`, writing a `(dx, dy)` delta
 * via `setRelativePosition` rather than an absolute pin via
 * `setNodePosition`. Verifies the user-visible contract:
 *
 *   - A real drag on a replica chip writes the synthetic id into the
 *     `relativePositions` map, not `positions`.
 *   - The accumulated delta is the drag distance divided by the current
 *     zoom (1.0× in the test, so the delta matches client-pixel input).
 *   - A sub-threshold movement still does NOT pin anything (same
 *     click-vs-drag discipline as the legacy absolute-pin path).
 *
 * Since the key-schedule decomposition (K1c) the high-fanout aux source is
 * `key-schedule.publish` (inside the default-collapsed `key-schedule` group).
 * The test EXPANDS that group and sets the per-source `replicationMode`
 * override to "always" before rendering, so the graph then contains synthetic
 * ids of shape `key-schedule.publish@->round.N.add-round-key`.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  setReplicationMode,
  toggleCollapse,
} from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { setReplicationEnabled } from "@/ui/stores/view-replication";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const seedAes128Trace = (): void => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });
  setTrace(trace);
};

const resetAll = (): void => {
  __resetAutoRerunForTests();
  __resetByteFormatForTests();
  __resetCipherForTests();
  __resetHistoryForTests();
  __resetPaddingForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewModeForTests();
  __resetLayoutsForTests();
};

const pointerEvt = (type: string, x: number, y: number): MouseEvent => {
  const e = new MouseEvent(type, { clientX: x, clientY: y, bubbles: true });
  Object.defineProperty(e, "pointerId", { value: 1 });
  return e;
};

describe("GraphView — block-chip drag (Slice 3 — collapsed-iterate path)", () => {
  // Block chips reach the renderer through a DIFFERENT path than aux replicas:
  // collapsing an iterate via `toggleCollapse` swaps its body for N synthetic
  // chips (`iterateId@blockI`) marked with `blockChipOf` (not `replicaOf`).
  // The replica drag tests above exercise the `replicaOf` arm of `isReplicaLike`;
  // this section covers the `blockChipOf` arm with the same wire-up contract,
  // catching a hypothetical future regression where one path's gate falls out
  // of sync with the other.
  //
  // Setup is bespoke: AES-128 ECB (not single-block) so an `ecb-blocks`
  // iterate exists; 4-block plaintext so the chip-row has visible chips;
  // toggleCollapse to surface them as leaves with `@block` ids.

  // Sentinel imports + helpers (mirrored shape; ECB needs additional store
  // resets for cipher-mode + view-density that the replica tests don't).

  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("dragging a block chip writes a relativePositions entry under the @block synthetic id", async () => {
    // Inline the ECB setup so the test stays self-contained alongside the
    // replica tests above. setCipherMode lives in stores/spec (NOT
    // stores/cipher-mode — the former rebuilds the canonical pair).
    const { setCipherMode } = await import("@/ui/stores/spec");
    const { aes128EcbSpec } = await import("@/ciphers/aes-128-ecb");
    const { makeBytesState } = await import("@/core/state/bytes");
    const { toggleCollapse } = await import("@/ui/stores/layout");

    setCipherMode("ecb");
    const ecbKey = "000102030405060708090a0b0c0d0e0f";
    const ecbPt =
      "6bc1bee22e409f96e93d7e117393172a" +
      "ae2d8a571e03ac9c9eb76fac45af8e51" +
      "30c81c46a35ce411e5fbc1191a0a52ef" +
      "f69f2445df4f9b17ad2b417be66c3710";
    const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(ecbPt)),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex(ecbKey)]]),
      // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    });
    setTrace(trace);

    // Collapse the iterate so chips appear.
    toggleCollapse(aes128EcbSpec.id, "ecb-blocks", false);

    const { container } = render(() => <GraphView />);

    // Find any block chip — id format is `ecb-blocks@block${i}`.
    const chip = container.querySelector('[data-testid^="graph-leaf-ecb-blocks@block"]');
    expect(chip).not.toBeNull();
    if (!chip) return;
    const CHIP_ID = (chip.getAttribute("data-testid") ?? "").replace(/^graph-leaf-/, "");
    expect(CHIP_ID).toMatch(/^ecb-blocks@block\d+$/);

    // Drag the chip.
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 150, 130));
    window.dispatchEvent(pointerEvt("pointerup", 150, 130));

    const layout = getLayoutForSpec(aes128EcbSpec.id);
    // Pin lands in relativePositions under the synthetic id, not in
    // absolute positions — same `blockChipOf` arm of `isReplicaLike` the
    // drag wire-up uses.
    expect(layout?.positions[CHIP_ID]).toBeUndefined();
    const rel = layout?.relativePositions?.[CHIP_ID];
    expect(rel).toBeDefined();
    expect(rel?.dx).toBeCloseTo(50, 0);
    expect(rel?.dy).toBeCloseTo(30, 0);
  });
});

describe("GraphView — replica chip drag (Slice 3, draggable-replicas plan)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  /**
   * Common setup: seed AES-128 trace + force the key-schedule's publish-tail
   * replication so replica chips appear in the rendered graph. Returns the
   * specId.
   *
   * Since the key-schedule decomposition (K1c) the high-fanout aux source is
   * `key-schedule.publish`, which lives INSIDE the default-collapsed
   * `key-schedule` group. We must EXPAND that group first (otherwise the only
   * fan-out source is the `key-schedule` CONTAINER, which replication skips),
   * then force `key-schedule.publish` to "always" so its cross-scope
   * consumer-scope replica chips (`key-schedule.publish@->...`) render.
   */
  const renderWithReplicas = (): string => {
    seedAes128Trace();
    const specId = useSpec()().id;
    // Master switch must be ON for ANY replication to apply — independent
    // of the per-source override below. Default in the user's session is
    // also driven from localStorage, but the test runs in jsdom with a
    // fresh module so it defaults to off; flip it on explicitly.
    setReplicationEnabled(true);
    // Expand the default-collapsed `key-schedule` group so its `publish` leaf
    // becomes a visible, replicable source (in-defaults ⇒ inDefaults=true).
    toggleCollapse(specId, "key-schedule", true);
    setReplicationMode(specId, "key-schedule.publish", "always");
    return specId;
  };

  it("dragging a replica chip writes a relativePositions entry, not a positions entry", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);

    // Find any one replica chip. The synthetic id format is
    // `${src}@->${consumer}` — the `@->` infix is the unambiguous marker.
    // Using a wildcard testid query lets the test stay robust if the
    // first-encountered replica's consumer changes over time.
    const chip = container.querySelector('[data-testid*="@->"]');
    expect(chip).not.toBeNull();
    if (!chip) return;
    const REPLICA_ID = (chip.getAttribute("data-testid") ?? "").replace(/^graph-leaf-/, "");
    expect(REPLICA_ID).toContain("@->");

    // No layout pins before drag (replicationMode counts, but no positions).
    const before = getLayoutForSpec(specId);
    expect(before?.positions ?? {}).toEqual({});
    expect(before?.relativePositions).toBeUndefined();

    // Drag the chip 60 px right + 25 px down.
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 160, 125));
    window.dispatchEvent(pointerEvt("pointerup", 160, 125));

    const after = getLayoutForSpec(specId);
    // Absolute pins must NOT carry this synthetic id — the drag wrote a
    // relative pin, not an absolute pin.
    expect(after?.positions[REPLICA_ID]).toBeUndefined();
    // Relative pins should carry the cumulative delta.
    const rel = after?.relativePositions?.[REPLICA_ID];
    expect(rel).toBeDefined();
    expect(rel?.dx).toBeCloseTo(60, 0);
    expect(rel?.dy).toBeCloseTo(25, 0);
  });

  it("a sub-threshold drag on a replica chip does NOT write a relative pin (click, not drag)", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid^="graph-leaf-key-schedule.publish@->"]');
    expect(chip).not.toBeNull();
    if (!chip) return;

    // pointerdown + 2 px move + up — below the 4 px DRAG_THRESHOLD_PX.
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 102, 100));
    window.dispatchEvent(pointerEvt("pointerup", 102, 100));

    // The threshold gate prevents the pin write. Layout still carries the
    // forced replicationMode but no relativePositions entry.
    const after = getLayoutForSpec(specId);
    expect(after?.relativePositions).toBeUndefined();
  });

  it("clicking the per-node reset glyph clears the relative pin (Slice 4)", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid*="@->"]');
    expect(chip).not.toBeNull();
    if (!chip) return;
    const REPLICA_ID = (chip.getAttribute("data-testid") ?? "").replace(/^graph-leaf-/, "");

    // First: drag the chip so a pin exists.
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 160, 110));
    window.dispatchEvent(pointerEvt("pointerup", 160, 110));
    expect(getLayoutForSpec(specId)?.relativePositions?.[REPLICA_ID]).toBeDefined();

    // Reset glyph should now exist (it renders only when a pin exists).
    const resetGlyph = container.querySelector(`[data-testid="graph-reset-pin-${REPLICA_ID}"]`);
    expect(resetGlyph).not.toBeNull();
    if (!resetGlyph) return;

    // Click clears the pin.
    resetGlyph.dispatchEvent(new MouseEvent("click", { bubbles: true }));

    // The pin is gone; since this was the only customization, the whole
    // relativePositions field is now absent (per the byte-stability
    // discipline in the store).
    expect(getLayoutForSpec(specId)?.relativePositions).toBeUndefined();
  });

  it("the reset glyph is NOT rendered for chips without a pin", () => {
    renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid*="@->"]');
    if (!chip) return;
    const REPLICA_ID = (chip.getAttribute("data-testid") ?? "").replace(/^graph-leaf-/, "");
    // No drag has happened, so no pin exists yet — the glyph should not
    // render. The presence-gated render in LeafRect is the safety belt
    // against showing a "reset" affordance with nothing to reset.
    expect(container.querySelector(`[data-testid="graph-reset-pin-${REPLICA_ID}"]`)).toBeNull();
  });

  it("toolbar 'reset layout' button is disabled when nothing is customized (Slice 5)", () => {
    // Spec is freshly reset → no positions, no collapses, no replication
    // overrides, no relative pins → hasUserLayout(null) === false → button
    // disabled. The replicationEnabled toggle is a SESSION-level flag
    // (not stored on LayoutSpec), so flipping it on doesn't make the
    // button live.
    seedAes128Trace();
    setReplicationEnabled(true);
    const { container } = render(() => <GraphView />);
    const btn = container.querySelector(
      '[data-testid="graph-view-layout-reset"]',
    ) as HTMLButtonElement | null;
    expect(btn).not.toBeNull();
    expect(btn?.disabled).toBe(true);
  });

  it("toolbar 'reset layout' button activates once a chip is pinned, and a confirmed click clears everything (Slice 5)", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);

    // Initially button is disabled (replicationMode counts as a
    // customization actually — let me re-check). The forced replication
    // mode IS persisted in the layout, so hasUserLayout(activeLayout())
    // returns true immediately. The button should be enabled even before
    // any drag.
    const btn = container.querySelector(
      '[data-testid="graph-view-layout-reset"]',
    ) as HTMLButtonElement | null;
    expect(btn).not.toBeNull();
    if (!btn) return;
    expect(btn.disabled).toBe(false);

    // Drag a chip so we have BOTH a replicationMode AND a relative pin.
    const chip = container.querySelector('[data-testid*="@->"]');
    if (!chip) return;
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 140, 110));
    window.dispatchEvent(pointerEvt("pointerup", 140, 110));
    expect(getLayoutForSpec(specId)?.relativePositions).toBeDefined();

    // Stub window.confirm → user approves the reset.
    const originalConfirm = window.confirm;
    window.confirm = () => true;
    try {
      btn.click();
    } finally {
      window.confirm = originalConfirm;
    }

    // All four layers are gone — entry dropped from the map entirely.
    expect(getLayoutForSpec(specId)).toBeNull();
  });

  it("toolbar 'reset layout' button does nothing when the confirm prompt is cancelled", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid*="@->"]');
    if (!chip) return;
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 140, 110));
    window.dispatchEvent(pointerEvt("pointerup", 140, 110));
    const before = getLayoutForSpec(specId);
    expect(before).not.toBeNull();

    const btn = container.querySelector(
      '[data-testid="graph-view-layout-reset"]',
    ) as HTMLButtonElement;
    // Stub window.confirm → user cancels.
    const originalConfirm = window.confirm;
    window.confirm = () => false;
    try {
      btn.click();
    } finally {
      window.confirm = originalConfirm;
    }

    // Layout still in place — cancel keeps the user's work.
    const after = getLayoutForSpec(specId);
    expect(after).not.toBeNull();
    expect(after?.relativePositions).toEqual(before?.relativePositions);
  });

  it("a second drag accumulates onto the existing pin instead of overwriting it", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid^="graph-leaf-key-schedule.publish@->"]');
    expect(chip).not.toBeNull();
    if (!chip) return;
    const REPLICA_ID = (chip.getAttribute("data-testid") ?? "").replace(/^graph-leaf-/, "");

    // First drag: 30 px right.
    chip.dispatchEvent(pointerEvt("pointerdown", 100, 100));
    window.dispatchEvent(pointerEvt("pointermove", 130, 100));
    window.dispatchEvent(pointerEvt("pointerup", 130, 100));
    expect(getLayoutForSpec(specId)?.relativePositions?.[REPLICA_ID]?.dx).toBeCloseTo(30, 0);

    // Second drag: 20 px right again. New total dx should be ~50, not ~20.
    // The chip may have moved in the DOM, so re-query by testid.
    const chip2 = container.querySelector(`[data-testid="graph-leaf-${REPLICA_ID}"]`);
    if (!chip2) return;
    chip2.dispatchEvent(pointerEvt("pointerdown", 200, 200));
    window.dispatchEvent(pointerEvt("pointermove", 220, 200));
    window.dispatchEvent(pointerEvt("pointerup", 220, 200));

    expect(getLayoutForSpec(specId)?.relativePositions?.[REPLICA_ID]?.dx).toBeCloseTo(50, 0);
  });
});
