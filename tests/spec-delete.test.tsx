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
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
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
  // Byte-native AES-128 (Slice B1): bytes state + ported dispatch (port-native
  // primitives have no legacy executor).
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    portedDispatchEnabled: true,
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

  // UX-F regression (2026-05-23) — the per-leaf Delete handler exists
  // uniformly on every LeafRect (line ~5687 in GraphView.tsx), so a
  // leaf living inside a feistel-round's L-track must also accept
  // Delete and round-trip back to the synthetic L-passthrough chip.
  // Specifically pinning the DES case because UX-F was raised against
  // DES — populating L-track via a palette drop, then re-emptying it.
  it("Delete keypress on a feistel-track leaf removes it and re-emits the L-passthrough chip (UX-F, DES)", async () => {
    const { setCipher, useSpec, insertStepIntoSpec } = await import("@/ui/stores/spec");
    const spec = useSpec();
    setCipher("des");

    // Populate round.1's L-track via the same store API the graph
    // view's drop handler uses, so the test mirrors the real user
    // flow as closely as possible.
    const newLeafId = insertStepIntoSpec("generic.byte-substitution@1", {
      kind: "into-track-start",
      roundId: "round.1",
      trackIdx: 0,
    });
    expect(findStep(spec(), newLeafId)).not.toBeNull();

    const { container } = render(() => <GraphView />);

    // Dispatch Delete on the L-track-resident leaf.
    const leafGroup = container.querySelector(`[data-drop-anchor="${newLeafId}"]`);
    expect(leafGroup, "the inserted L-track leaf must render").not.toBeNull();
    if (!leafGroup) throw new Error("unreachable");
    leafGroup.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Delete", bubbles: true, cancelable: true }),
    );

    // Spec-level: the inserted leaf is gone.
    expect(findStep(spec(), newLeafId)).toBeNull();

    // Graph-level: the L-passthrough chip re-emerges. The synthetic
    // chip is rendered by `PassthroughChip` (not `LeafRect`) and
    // carries its own `graph-passthrough-${stepId}` testid hook (see
    // GraphView.tsx:5904 — Phase 6b-ii, commit 6556ef6).
    const passthrough = container.querySelector(
      `[data-testid="graph-passthrough-round.1:passthrough-0"]`,
    );
    expect(passthrough, "L-passthrough chip re-renders after the round-trip").not.toBeNull();
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

    // ParamEditor takes a stepId directly (the trace-coupling fix
    // decoupled the editor from TraceFrame so palette-dropped steps with
    // no frame yet are still editable). We just pass the target id.
    const { container } = render(() => <ParamEditor stepId={targetId} />);
    const btn = container.querySelector<HTMLButtonElement>('[data-testid="param-editor-delete"]');
    expect(btn).not.toBeNull();
    if (!btn) throw new Error("unreachable");
    btn.click();

    expect(findStep(spec(), targetId)).toBeNull();
  });
});
