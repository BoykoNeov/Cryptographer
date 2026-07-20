// @vitest-environment jsdom

/**
 * `<ChaChaQuarterRoundDiagram />` — the linear view's quarter-round picture.
 *
 * The pure model is covered in `tests/chacha-diagram.test.ts`; this file covers
 * the seam the model can't: that the component self-detects from the active
 * frame, renders the twelve operations, and stays completely inert for every
 * other cipher. That last property is the one that would break quietly — a
 * diagram that rendered for AES would be nonsense, but nothing else in the app
 * would fail.
 */

import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { analyzeChaChaDoubleRound } from "@/core/chacha-shape";
import type { StepGroup, StepNode, TraceFrame } from "@/core/types";
import { ChaChaQuarterRoundDiagram } from "@/ui/components/ChaChaQuarterRoundDiagram";
import { __resetSpecForTests, setCipher } from "@/ui/stores/spec";
import { __resetTraceForTests } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/** The first recognized double round of the shipped ChaCha spec. */
const firstRound = () => {
  let found: StepGroup | null = null;
  const walk = (nodes: readonly StepNode[]): void => {
    for (const n of nodes) {
      if (found) return;
      if (n.kind === "group") {
        if (analyzeChaChaDoubleRound(n)) {
          found = n;
          return;
        }
        walk(n.children);
      } else if (n.kind === "iterate") walk(n.children);
    }
  };
  walk(chacha20EncryptSpec.steps);
  if (!found) throw new Error("no double round");
  const shape = analyzeChaChaDoubleRound(found);
  if (!shape) throw new Error("no shape");
  return { group: found as StepGroup, shape };
};

const frameAt = (stepId: string, path: readonly string[]): TraceFrame =>
  ({ stepId, path }) as unknown as TraceFrame;

const resetAll = (): void => {
  __resetTraceForTests();
  __resetSpecForTests();
};

describe("<ChaChaQuarterRoundDiagram />", () => {
  beforeEach(() => {
    resetAll();
    // `__resetSpecForTests` does not reset the cipher selector, and the
    // component reads the ACTIVE spec — so it must be set explicitly or the
    // diagram looks for ChaCha rounds in whatever cipher leaked in.
    setCipher("chacha20");
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders twelve operation boxes for a quarter-round frame", () => {
    const { group, shape } = firstRound();
    const leaf = shape.quarterRounds[0]?.ops[3]?.nodeId as string;
    const { container } = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt(leaf, ["chacha-blocks", group.id])} />
    ));
    expect(container.querySelector(".chacha-qr-diagram")).not.toBeNull();
    expect(container.querySelectorAll("[data-testid^='chacha-qr-op-']").length).toBe(12);
  });

  it("labels the four rails with the state words this quarter round mixes", () => {
    // The RFC's own identity for the round, recovered from wiring. Quarter
    // round 4 is the first diagonal one: QUARTERROUND(0, 5, 10, 15).
    const { group, shape } = firstRound();
    const leaf = shape.quarterRounds[4]?.ops[0]?.nodeId as string;
    const { container } = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt(leaf, ["chacha-blocks", group.id])} />
    ));
    const rails = ["a", "b", "c", "d"].map(
      (r) => container.querySelector(`[data-testid='chacha-qr-rail-${r}']`)?.textContent,
    );
    expect(rails).toEqual(["a (w0)", "b (w5)", "c (w10)", "d (w15)"]);
    expect(container.textContent).toContain("QUARTERROUND(0, 5, 10, 15)");
  });

  it("shows the RFC's rotation constants, not their right-rotate complements", () => {
    // 16/12/8/7 — the reason `rotate-bits-left@1` exists. If this ever reads
    // 16/20/24/25 the diagram has started drawing the wrong primitive.
    const { group, shape } = firstRound();
    const leaf = shape.quarterRounds[0]?.ops[2]?.nodeId as string;
    const { container } = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt(leaf, ["chacha-blocks", group.id])} />
    ));
    const text = container.textContent ?? "";
    for (const bits of [16, 12, 8, 7]) expect(text).toContain(`≪${bits}`);
    for (const bits of [20, 24, 25]) expect(text).not.toContain(`≪${bits}`);
  });

  it("accents the operation holding the active frame — 'you are here'", () => {
    const { group, shape } = firstRound();
    const ops = shape.quarterRounds[1]?.ops ?? [];
    const activeIndex = 7;
    const { container } = render(() => (
      <ChaChaQuarterRoundDiagram
        frame={frameAt(ops[activeIndex]?.nodeId as string, ["chacha-blocks", group.id])}
      />
    ));
    const accented = container.querySelectorAll(".chacha-qr-diagram-active");
    expect(accented.length).toBe(1);
    expect(accented[0]?.getAttribute("data-testid")).toBe(`chacha-qr-op-${activeIndex}`);
  });

  it("names the round column or diagonal in the prose", () => {
    const { group, shape } = firstRound();
    const columnLeaf = shape.quarterRounds[0]?.ops[0]?.nodeId as string;
    const { container, unmount } = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt(columnLeaf, ["chacha-blocks", group.id])} />
    ));
    expect(container.textContent).toContain("column");
    unmount();

    const diagonalLeaf = shape.quarterRounds[6]?.ops[0]?.nodeId as string;
    const second = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt(diagonalLeaf, ["chacha-blocks", group.id])} />
    ));
    expect(second.container.textContent).toContain("diagonal");
  });

  it("renders nothing on the split or the concat", () => {
    // They belong to the double round as a whole, so there is no single
    // quarter round to draw — and drawing an arbitrary one would be a lie.
    const { group, shape } = firstRound();
    for (const id of [shape.splitId, shape.concatId]) {
      const { container, unmount } = render(() => (
        <ChaChaQuarterRoundDiagram frame={frameAt(id, ["chacha-blocks", group.id])} />
      ));
      expect(container.querySelector(".chacha-qr-diagram")).toBeNull();
      unmount();
    }
  });

  it("is inert for another cipher — the property that would break quietly", () => {
    setCipher("aes-128");
    const { container } = render(() => (
      <ChaChaQuarterRoundDiagram frame={frameAt("round.1.sub-bytes", ["round.1"])} />
    ));
    expect(container.querySelector(".chacha-qr-diagram")).toBeNull();
  });
});
