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
 * Cell-level provenance HOVER was deferred in the 2.9c-e "honest close" and
 * rebuilt port-native in the inspector-cell-hover plan (Slice 2, 2026-06-04);
 * the bottom describe block ("cell-level provenance hover") now exercises it.
 * Still out of scope: click / cell selection.
 *
 * Format toggle IS exercised because it costs nothing more and the cells are
 * unreadable without it.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, TraceFrame } from "@/core/types";
import { PortFlowView, isPortNativeFrame } from "@/ui/components/PortFlowView";
import { __resetByteFormatForTests, setByteFormat } from "@/ui/stores/format";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

// ─── Fixture helpers ─────────────────────────────────────────────────────

const runSha256AbcTrace = () =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
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

// ─── Cell-level provenance hover (inspector-cell-hover plan, Slice 2) ────
//
// These pin the JS wiring: hovering an OUTPUT cell highlights the contributing
// INPUT cell(s) via `lookupProvenance(frame.stepType)`. NOTE (per
// `feedback_jsdom_pointer_events_gap`): `fireEvent` bypasses CSS hit-testing,
// so these confirm the handler/signal logic but NOT that `pointer-events`
// works live — that is the Slice 3 browser smoke's job. The read-time stepId
// gate (not an effect-clear) is the load-bearing stale-frame guard, exercised
// by the scrub test below.

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PLAINTEXT = "00112233445566778899aabbccddeeff";

const runAes128Trace = () =>
  runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PLAINTEXT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });

/** NodeList index with a throwing guard (noUncheckedIndexedAccess-friendly). */
const at = (list: NodeListOf<Element>, i: number): Element => {
  const el = list.item(i);
  if (el === null) throw new Error(`no element at index ${i}`);
  return el;
};

const outputCells = (container: HTMLElement): NodeListOf<Element> =>
  container.querySelectorAll(".port-flow-section[data-section='outputs'] .bytes-cell");
const sourceCells = (container: HTMLElement): NodeListOf<Element> =>
  container.querySelectorAll(".bytes-cell.provenance-source");

describe("PortFlowView — cell-level provenance hover", () => {
  beforeEach(() => __resetByteFormatForTests());
  afterEach(() => {
    cleanup();
    __resetByteFormatForTests();
  });

  it("hovering an xor output cell highlights the same-index cell in every operand row", () => {
    const trace = runSha256AbcTrace();
    const xor3 = findFrameByStepType(
      trace.frames,
      "xor@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 3,
    );
    const { container } = render(() => <PortFlowView frame={xor3} />);
    fireEvent.mouseEnter(at(outputCells(container), 1)); // output byte index 1
    const sources = sourceCells(container);
    expect(sources.length).toBe(3); // operand0[1], operand1[1], operand2[1]
    for (const s of sources) expect(s.getAttribute("title")).toBe("index 1");
    // Mouse leave clears the highlight.
    fireEvent.mouseLeave(at(outputCells(container), 1));
    expect(sourceCells(container).length).toBe(0);
  });

  it("a hover captured on one frame paints nothing after scrubbing (read-time stepId gate)", () => {
    const trace = runSha256AbcTrace();
    const xor3 = findFrameByStepType(
      trace.frames,
      "xor@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 3,
    );
    const t1 = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const [frame, setFrame] = createSignal<TraceFrame>(xor3);
    const { container } = render(() => <PortFlowView frame={frame()} />);
    fireEvent.mouseEnter(at(outputCells(container), 1));
    expect(sourceCells(container).length).toBe(3);
    setFrame(t1); // scrub to a different-stepId frame
    expect(sourceCells(container).length).toBe(0);
  });

  it("hovering a MixColumns output cell highlights 4 same-column inputs with GF labels", () => {
    const trace = runAes128Trace();
    const mix = findFrameByStepType(trace.frames, "gf-matrix-multiply@1");
    const { container } = render(() => <PortFlowView frame={mix} />);
    fireEvent.mouseEnter(at(outputCells(container), 5)); // column 1, row 1
    const sources = sourceCells(container);
    expect(sources.length).toBe(4);
    // The 4 contributors are the same-column input cells {4,5,6,7}.
    const idxs = Array.from(sources)
      .map((s) => s.getAttribute("title"))
      .sort();
    expect(idxs).toEqual(["index 4", "index 5", "index 6", "index 7"]);
    // Each contributor carries a GF coefficient badge "×N".
    const badges = container.querySelectorAll(".provenance-label");
    expect(badges.length).toBe(4);
    for (const b of badges) expect(b.textContent ?? "").toMatch(/^×\d+$/);
  });

  it("split-bytes: different output rows highlight different input cells ((portName,cellIndex) keying)", () => {
    const trace = runSha256AbcTrace();
    const split = findFrameByStepType(trace.frames, "split-bytes@1");
    const { container } = render(() => <PortFlowView frame={split} />);
    const outRows = container.querySelectorAll(
      ".port-flow-section[data-section='outputs'] .port-row",
    );
    expect(outRows.length).toBeGreaterThanOrEqual(2);
    const cellIn = (row: Element, i: number): Element => at(row.querySelectorAll(".bytes-cell"), i);
    // output0[0] → one input cell.
    fireEvent.mouseEnter(cellIn(at(outRows, 0), 0));
    const src0 = Array.from(sourceCells(container)).map((s) => s.getAttribute("title"));
    expect(src0.length).toBe(1);
    fireEvent.mouseLeave(cellIn(at(outRows, 0), 0));
    // output1[0] → a DIFFERENT input cell (offset by widths[0]); proves the
    // (portName,cellIndex) key disambiguates the multiple output rows.
    fireEvent.mouseEnter(cellIn(at(outRows, 1), 0));
    const src1 = Array.from(sourceCells(container)).map((s) => s.getAttribute("title"));
    expect(src1.length).toBe(1);
    expect(src1[0]).not.toBe(src0[0]);
  });

  it("AddRoundKey (xor-with-aux): the projected `operand` round-key port is on the real frame", () => {
    // De-risk check (a) converted from a code-reading claim to an empirical
    // fact: the runtime projects aux[roundKey.N] onto a port literally named
    // `operand` (meta.auxReadPorts), so BOTH AddRoundKey sources land on ONE
    // PortFlowView surface — no RoundKeyPanel coordination like the old design.
    const trace = runAes128Trace();
    const ark = findFrameByStepType(trace.frames, "xor-with-aux@1");
    expect(ark.portInputs?.has("operand")).toBe(true);
    const { container } = render(() => <PortFlowView frame={ark} />);
    fireEvent.mouseEnter(at(outputCells(container), 3));
    const sources = sourceCells(container);
    expect(sources.length).toBe(2); // input[3] + operand[3]
    const rows = Array.from(sources).map((s) =>
      s.closest(".port-row")?.getAttribute("data-port-name"),
    );
    expect(new Set(rows)).toEqual(new Set(["input", "operand"]));
  });

  it("an approximate primitive (add-mod-32) highlights nothing on hover (missing never wrong)", () => {
    const trace = runSha256AbcTrace();
    const add = findFrameByStepType(
      trace.frames,
      "add-mod-32@1",
      (f) => (f.params as { inputCount?: number }).inputCount === 5,
    );
    const { container } = render(() => <PortFlowView frame={add} />);
    fireEvent.mouseEnter(at(outputCells(container), 0));
    expect(sourceCells(container).length).toBe(0);
    // Its output cells are not even marked hoverable (no exact mapping).
    expect(container.querySelectorAll(".bytes-cell.provenance-hoverable").length).toBe(0);
  });
});
