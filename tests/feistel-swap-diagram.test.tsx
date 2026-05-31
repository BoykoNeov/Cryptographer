// @vitest-environment jsdom

/**
 * `FeistelSwapDiagram` — port-native DES (Slice 5.3d).
 *
 * Drives the rebuilt swap diagram against a REAL port-native DES trace (no
 * `feistel-round`, no `branchPath`). Pins: it renders for a round-body frame
 * and hides outside a round; the F-stack shows the four DES F-leaves; the
 * active leaf gets the accent; clicking a leaf scrubs; the xor-K leaf shows a
 * K_i cross-reference; and — the crown jewel — the swap-zone wires CROSS for a
 * swap round (1..15) and run STRAIGHT for the round-16 no-swap exception.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { FeistelSwapDiagram } from "@/ui/components/FeistelSwapDiagram";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, __setSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_PT = "0123456789abcdef";
const DES_KEY = "133457799bbcdff1";

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

const seed = (): Trace => {
  __setSpecForTests(desSpec);
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
  });
  setTrace(trace);
  return trace;
};

const frameById = (trace: Trace, id: string): TraceFrame => {
  const f = trace.frames.find((fr) => fr.stepId === id);
  if (!f) throw new Error(`expected a ${id} frame`);
  return f;
};

describe("FeistelSwapDiagram — port-native DES", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing outside a round (initial-permutation frame)", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "initial-permutation")} />
    ));
    expect(container.querySelector(".feistel-swap-diagram")).toBeNull();
  });

  it("renders the SVG for a round-body frame and shows the swap state in the header", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.expand-R")} />
    ));
    expect(container.querySelector(".feistel-swap-diagram")).not.toBeNull();
    expect(container.querySelector("svg.feistel-swap-diagram-svg")).not.toBeNull();
    expect(container.querySelector(".feistel-swap-diagram-kind")?.textContent).toBe("swap");
  });

  it("the F-stack shows the four DES F-leaves in order", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.expand-R")} />
    ));
    const labels = Array.from(container.querySelectorAll(".feistel-swap-diagram-leaf-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toEqual(["expand-R", "xor-K", "s-boxes", "p-permute"]);
  });

  it("the active frame's leaf gets the accent class", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.s-boxes")} />
    ));
    const active = container.querySelectorAll(".feistel-swap-diagram-leaf-active");
    expect(active.length).toBe(1);
    expect(active[0]?.querySelector(".feistel-swap-diagram-leaf-label")?.textContent).toBe(
      "s-boxes",
    );
  });

  it("clicking an F-stack leaf scrubs the trace to that leaf's frame", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.expand-R")} />
    ));
    const sboxes = container.querySelector(
      '[data-testid="feistel-swap-diagram-leaf-round.5.s-boxes"]',
    );
    if (!sboxes) throw new Error("s-boxes leaf missing");
    fireEvent.click(sboxes);
    const expected = trace.frames.findIndex((f) => f.stepId === "round.5.s-boxes");
    expect(useFrameIndex()()).toBe(expected);
  });

  it("only the round-key-consuming leaf (xor-K) shows a K_i cross-reference", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.expand-R")} />
    ));
    // Round 5 reads roundKey.4 → "K4".
    const keyref = container.querySelector(
      '[data-testid="feistel-swap-diagram-keyref-round.5.xor-K"]',
    );
    expect(keyref).not.toBeNull();
    expect(keyref?.textContent ?? "").toContain("4");
    // The passthrough F-leaves carry no key reference.
    expect(
      container.querySelector('[data-testid="feistel-swap-diagram-keyref-round.5.expand-R"]'),
    ).toBeNull();
  });

  it("the swap-zone wires CROSS for a swap round (5) and run STRAIGHT for round 16", () => {
    const trace = seed();
    const swapRound = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.5.recombine")} />
    ));
    const mix5 = swapRound.container.querySelector(".feistel-swap-diagram-wire-mix");
    // swap → the combined half crosses from the left column to the right.
    expect(mix5?.getAttribute("x1")).not.toBe(mix5?.getAttribute("x2"));
    expect(swapRound.container.querySelector(".feistel-swap-diagram-kind")?.textContent).toBe(
      "swap",
    );
    cleanup();

    const noSwap = render(() => (
      <FeistelSwapDiagram frame={frameById(trace, "round.16.recombine")} />
    ));
    const mix16 = noSwap.container.querySelector(".feistel-swap-diagram-wire-mix");
    // no-swap → straight down (same x at top and bottom).
    expect(mix16?.getAttribute("x1")).toBe(mix16?.getAttribute("x2"));
    expect(noSwap.container.querySelector(".feistel-swap-diagram-kind")?.textContent).toBe(
      "no swap",
    );
  });
});
