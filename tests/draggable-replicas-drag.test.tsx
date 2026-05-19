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
 * AES-128 single-block doesn't auto-replicate `key-expansion` (the
 * default threshold isn't tripped). The test forces it by setting the
 * per-source `replicationMode` override to "always" before rendering,
 * so the graph then contains synthetic ids of shape
 * `key-expansion@->round.N.add-round-key`.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests, getLayoutForSpec, setReplicationMode } from "@/ui/stores/layout";
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
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
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

describe("GraphView — replica chip drag (Slice 3, draggable-replicas plan)", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  /**
   * Common setup: seed AES-128 trace + force key-expansion replication so
   * replica chips appear in the rendered graph. Returns the specId.
   */
  const renderWithReplicas = (): string => {
    seedAes128Trace();
    const specId = useSpec()().id;
    // Master switch must be ON for ANY replication to apply — independent
    // of the per-source override below. Default in the user's session is
    // also driven from localStorage, but the test runs in jsdom with a
    // fresh module so it defaults to off; flip it on explicitly.
    setReplicationEnabled(true);
    setReplicationMode(specId, "key-expansion", "always");
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
    const chip = container.querySelector('[data-testid^="graph-leaf-key-expansion@->"]');
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

  it("a second drag accumulates onto the existing pin instead of overwriting it", () => {
    const specId = renderWithReplicas();
    const { container } = render(() => <GraphView />);
    const chip = container.querySelector('[data-testid^="graph-leaf-key-expansion@->"]');
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
