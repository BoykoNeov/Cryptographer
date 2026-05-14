// @vitest-environment jsdom

/**
 * Tests for the three delete affordances added alongside the state-shape
 * contract slice:
 *
 *   1. `removeStepFromSpec(stepId)` — the spec-store wrapper around
 *      core's `removeStep`. Lenient: doesn't throw on stale ids, just
 *      console.warns.
 *   2. The × button on each graph node (LeafRect + ContainerRect). We
 *      verify the SVG element exists with the expected `data-testid`,
 *      then click it and assert the spec lost the corresponding node.
 *   3. The "Delete this step" button in the ParamEditor.
 *
 * Keyboard shortcut (Delete/Backspace) is exercised through the same
 * node-removal path — assert the spec mutates correctly via a synthetic
 * keydown on the focused node.
 *
 * Why one test file for all three: the assertions all live downstream of
 * the same `setSpec` mutation, so testing them together makes the
 * end-to-end contract obvious. The shared `seedAes128Trace` + `resetAll`
 * helpers live above each block.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { findStep } from "@/core/spec-mutations";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { GraphView } from "@/ui/components/GraphView";
import { ParamEditor } from "@/ui/components/ParamEditor";
import { __resetAutoRerunForTests } from "@/ui/stores/auto-rerun";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetHistoryForTests } from "@/ui/stores/history";
import { __resetLayoutsForTests } from "@/ui/stores/layout";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, removeStepFromSpec, useSpec } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { __resetViewModeForTests } from "@/ui/stores/view-mode";
import { __resetReplicationForTests } from "@/ui/stores/view-replication";
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
  __resetCipherModeForTests();
  __resetHistoryForTests();
  __resetLayoutsForTests();
  __resetPaddingForTests();
  __resetReplicationForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetViewDensityForTests();
  __resetViewModeForTests();
};

describe("removeStepFromSpec — store wrapper", () => {
  beforeEach(resetAll);
  afterEach(resetAll);

  it("removes the named leaf from the live spec", () => {
    const spec = useSpec();
    // Pick a real leaf id from the default AES-128 spec.
    const targetId = "round.1.sub-bytes";
    expect(findStep(spec(), targetId)).not.toBeNull();
    removeStepFromSpec(targetId);
    expect(findStep(spec(), targetId)).toBeNull();
  });

  it("removes a container (group) + all descendants", () => {
    const spec = useSpec();
    const containerId = "round.1";
    // Pre-state: every round.1.* leaf exists.
    expect(findStep(spec(), "round.1.sub-bytes")).not.toBeNull();
    expect(findStep(spec(), "round.1.shift-rows")).not.toBeNull();
    removeStepFromSpec(containerId);
    // Post-state: ALL of them gone (removeStep is tree-aware).
    const after = spec();
    const round1 = after.steps.find((n) => n.id === "round.1");
    expect(round1).toBeUndefined();
    expect(findStep(after, "round.1.sub-bytes")).toBeNull();
    expect(findStep(after, "round.1.shift-rows")).toBeNull();
  });

  it("is lenient on a stale id (warns, does not throw)", () => {
    // Stale id paths shouldn't crash the UI — useful when a delete
    // races with another spec edit.
    expect(() => removeStepFromSpec("nonexistent.step")).not.toThrow();
  });
});

describe("GraphView — × button removes nodes", () => {
  beforeEach(() => {
    resetAll();
    seedAes128Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("clicking a leaf's × removes it from the spec", () => {
    const spec = useSpec();
    const targetId = "round.1.sub-bytes";
    expect(findStep(spec(), targetId)).not.toBeNull();

    const { container } = render(() => <GraphView />);
    const deleteBtn = container.querySelector(`[data-testid="graph-delete-${targetId}"]`);
    expect(deleteBtn, "× button should exist on every non-replica leaf").not.toBeNull();
    if (!deleteBtn) throw new Error("unreachable");
    // SVG <g> doesn't have a native click() like buttons do; dispatch.
    deleteBtn.dispatchEvent(new Event("click", { bubbles: true, cancelable: true }));

    expect(findStep(spec(), targetId)).toBeNull();
  });

  it("clicking a container's × removes the whole container", () => {
    const spec = useSpec();
    const containerId = "round.1";
    expect(spec().steps.some((n) => n.id === containerId)).toBe(true);

    const { container } = render(() => <GraphView />);
    const deleteBtn = container.querySelector(`[data-testid="graph-delete-${containerId}"]`);
    expect(deleteBtn).not.toBeNull();
    if (!deleteBtn) throw new Error("unreachable");
    deleteBtn.dispatchEvent(new Event("click", { bubbles: true, cancelable: true }));

    expect(spec().steps.some((n) => n.id === containerId)).toBe(false);
  });

  it("Delete keypress on a focused leaf removes it", () => {
    const spec = useSpec();
    const targetId = "round.1.shift-rows";

    const { container } = render(() => <GraphView />);
    // Find the leaf's outer <g> — it has data-drop-anchor matching the
    // leaf id (clickTargetId == leaf id for non-replicas).
    const leafGroup = container.querySelector(`[data-drop-anchor="${targetId}"]`);
    expect(leafGroup).not.toBeNull();
    if (!leafGroup) throw new Error("unreachable");
    const event = new KeyboardEvent("keydown", {
      key: "Delete",
      bubbles: true,
      cancelable: true,
    });
    leafGroup.dispatchEvent(event);

    expect(findStep(spec(), targetId)).toBeNull();
  });
});

describe("ParamEditor — Delete button", () => {
  beforeEach(() => {
    resetAll();
    seedAes128Trace();
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("clicking 'Delete this step' removes the editor's target leaf", () => {
    const spec = useSpec();
    const targetId = "round.1.sub-bytes";
    const targetStep = findStep(spec(), targetId);
    expect(targetStep).not.toBeNull();
    if (!targetStep) throw new Error("unreachable");

    // Synthesize the frame the App.tsx wires into ParamEditor — it
    // only needs `stepId` to be resolvable via findStep.
    const frame = {
      index: 0,
      path: ["round.1"],
      stepId: targetId,
      stepType: targetStep.type,
      params: targetStep.params,
      stateBefore: { shape: "matrix4x4-bytes" as const, bytes: new Uint8Array(16) },
      stateAfter: { shape: "matrix4x4-bytes" as const, bytes: new Uint8Array(16) },
      auxRead: new Map(),
      auxWritten: new Map(),
    };

    const { container } = render(() => <ParamEditor frame={frame} />);
    const btn = container.querySelector<HTMLButtonElement>('[data-testid="param-editor-delete"]');
    expect(btn).not.toBeNull();
    if (!btn) throw new Error("unreachable");
    btn.click();

    expect(findStep(spec(), targetId)).toBeNull();
  });
});
