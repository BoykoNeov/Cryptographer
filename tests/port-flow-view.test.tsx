// @vitest-environment jsdom

/**
 * Slice 2.9b of the universal-port-dataflow plan
 * (`docs/plans/slice-2-9-port-aware-provenance.md`).
 *
 * Pin `PortFlowView`'s contract: render a port-native trace frame as a
 * vertical stack of input rows + output rows, each row labelled by port
 * name and filled with one `.bytes-cell` per byte.
 *
 * Test seam matches `tests/frame-port-values.test.ts` — run the real
 * SHA-256 abc trace and consume the runtime-emitted port-native frames
 * (no synthetic frame construction). The frame is the gold reference
 * for port name set + byte lengths.
 *
 * What stays OUT of scope (deferred to Slice 2.9c/d):
 *   - hover provenance highlighting
 *   - click / cell selection
 *   - cross-row outline of contributing source cells
 *
 * Cells render display-only here. Format toggle IS exercised because
 * it costs nothing more and the cells are unreadable without it.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import type { TraceFrame } from "@/core/types";
import { PortFlowView, isPortNativeFrame } from "@/ui/components/PortFlowView";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixture helpers ─────────────────────────────────────────────────────

const runSha256AbcTrace = () =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    portedDispatchEnabled: true,
  });

const findFrameByStepType = (
  frames: readonly TraceFrame[],
  stepType: string,
  predicate?: (f: TraceFrame) => boolean,
): TraceFrame => {
  for (const f of frames) {
    if (f.stepType !== stepType) continue;
    if (predicate && !predicate(f)) continue;
    return f;
  }
  throw new Error(`no frame with stepType=${stepType} matched predicate`);
};

// ─── isPortNativeFrame predicate ─────────────────────────────────────────

describe("isPortNativeFrame", () => {
  it("returns true for a pure port-native SHA-256 frame", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    expect(isPortNativeFrame(t1)).toBe(true);
  });

  it("returns false for a lifted-legacy ported frame (port fields undefined)", () => {
    // Construct a minimal legacy-shaped frame; the predicate only looks
    // at the optional port fields, so a hand-rolled frame is enough here.
    const legacyFrame: TraceFrame = {
      index: 0,
      path: [],
      stepId: "x",
      stepType: "generic.byte-substitution@1",
      params: {},
      stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
      stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
      auxRead: new Map(),
      auxWritten: new Map(),
    };
    expect(isPortNativeFrame(legacyFrame)).toBe(false);
  });
});

// ─── 5-way add-mod-32 (T1) — the canonical multi-input fixture ──────────

describe("PortFlowView — 5-way add-mod-32 T1 frame", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("renders 5 input rows + 1 output row", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={t1} />);

    const inputRows = container.querySelectorAll(
      ".port-flow-section[data-section='inputs'] .port-row",
    );
    const outputRows = container.querySelectorAll(
      ".port-flow-section[data-section='outputs'] .port-row",
    );
    expect(inputRows.length).toBe(5);
    expect(outputRows.length).toBe(1);
  });

  it("each input row carries 4 cells (32-bit operand width)", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={t1} />);
    const inputRows = container.querySelectorAll(
      ".port-flow-section[data-section='inputs'] .port-row",
    );
    for (const row of inputRows) {
      const cells = row.querySelectorAll(".bytes-cell");
      expect(cells.length).toBe(4);
    }
  });

  it("port labels carry the canonical port names operand0..operand4 + output", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={t1} />);
    const inputLabels = Array.from(
      container.querySelectorAll(".port-flow-section[data-section='inputs'] .port-label"),
    ).map((el) => el.textContent ?? "");
    for (let i = 0; i < 5; i++) {
      expect(inputLabels[i]).toContain(`operand${i}`);
    }
    const outputLabel = container.querySelector(
      ".port-flow-section[data-section='outputs'] .port-label",
    );
    expect(outputLabel?.textContent ?? "").toContain("output");
  });

  it("renders a divider between input and output sections", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={t1} />);
    const divider = container.querySelector(".port-flow-divider");
    expect(divider).not.toBeNull();
  });

  it("byte cells re-render text when the format toggle flips", () => {
    const trace = runSha256AbcTrace();
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={t1} />);
    const firstCellText = (): string =>
      container.querySelector(".port-row .bytes-cell")?.textContent ?? "";
    // Default format is "hex"; expect a 2-char lowercase hex byte.
    expect(firstCellText()).toMatch(/^[0-9a-f]{2}$/);
    setByteFormat("decimal");
    // Decimal: a 1..3-digit base-10 string.
    expect(firstCellText()).toMatch(/^\d+$/);
  });
});

// ─── 3-way xor (σ-family) — smoke check the row count generalises ───────

describe("PortFlowView — 3-way xor frame", () => {
  afterEach(() => cleanup());

  it("renders 3 input rows + 1 output row for an inputCount=3 xor", () => {
    const trace = runSha256AbcTrace();
    const xor3 = findFrameByStepType(
      trace.frames,
      "xor@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 3,
    );
    const { container } = render(() => <PortFlowView frame={xor3} />);
    const inputRows = container.querySelectorAll(
      ".port-flow-section[data-section='inputs'] .port-row",
    );
    const outputRows = container.querySelectorAll(
      ".port-flow-section[data-section='outputs'] .port-row",
    );
    expect(inputRows.length).toBe(3);
    expect(outputRows.length).toBe(1);
  });
});

// ─── Constant-load (outputs-only) — no inputs header, no divider ────────

describe("PortFlowView — outputs-only frame", () => {
  afterEach(() => cleanup());

  it("renders no inputs section and no divider when the frame has no input ports", () => {
    // Synthesize a frame with portInputs as an empty map and portOutputs
    // non-empty. The runtime produces this shape for `constant-load@1`
    // (no inputs declared) — frame-port-values pins the SHA-256 trace's
    // 5-way add path, not constants, so we hand-roll the minimal frame
    // here to keep the predicate-coverage tight without grepping the
    // trace for the exact constant leaf.
    const frame: TraceFrame = {
      index: 0,
      path: [],
      stepId: "constant",
      stepType: "constant-load@1",
      params: { value: "0x6a09e667" },
      stateBefore: { shape: "bytes", bytes: new Uint8Array(0) },
      stateAfter: { shape: "bytes", bytes: new Uint8Array(0) },
      auxRead: new Map(),
      auxWritten: new Map(),
      portInputs: new Map(),
      portOutputs: new Map([["output", new Uint8Array([0x6a, 0x09, 0xe6, 0x67])]]),
    };
    const { container } = render(() => <PortFlowView frame={frame} />);
    expect(container.querySelector(".port-flow-section[data-section='inputs']")).toBeNull();
    expect(container.querySelector(".port-flow-divider")).toBeNull();
    const outputRows = container.querySelectorAll(
      ".port-flow-section[data-section='outputs'] .port-row",
    );
    expect(outputRows.length).toBe(1);
    expect(outputRows[0]?.querySelectorAll(".bytes-cell").length).toBe(4);
  });
});
