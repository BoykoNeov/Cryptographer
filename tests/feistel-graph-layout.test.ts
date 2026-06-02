// @vitest-environment jsdom
//
// jsdom (not node) because importing `layoutRoot` from GraphView.tsx pulls in
// `solid-js/web` at module init, which touches `window`. The component is
// never rendered — we drive the pure `layoutRoot` export with the Feistel map.

/**
 * End-to-end check of the canonical Feistel LAYOUT integration: feeding
 * `layoutRoot` the `feistelRounds` map (id → `FeistelRoundShape`) must lay a
 * DES round's children out in the two-column canonical form, while a NON-Feistel
 * round (AES) is byte-identical with vs without the map (the branch only fires
 * for shaped groups). Pins the wiring between `analyzeFeistelRound`,
 * `feistelRoundPlacement`, and `layoutNode`'s Feistel branch.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { type FeistelRoundShape, analyzeFeistelRound } from "@/core/feistel-shape";
import { type CipherGraph, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

const feistelRoundsOf = (spec: CipherSpec): Map<string, FeistelRoundShape> => {
  const m = new Map<string, FeistelRoundShape>();
  const walk = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "step") continue;
      if (node.kind === "group") {
        const shape = analyzeFeistelRound(node);
        if (shape !== null) m.set(node.id, shape);
      }
      walk(node.children);
    }
  };
  walk(spec.steps);
  return m;
};

const desGraph = (): CipherGraph => {
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
  });
  return deriveAuxGraph(trace, desSpec);
};

describe("Feistel canonical layout — DES round via layoutRoot", () => {
  it("detects all 16 DES rounds as Feistel-shaped (and NOT the outer `rounds` group)", () => {
    const rounds = feistelRoundsOf(desSpec);
    for (let r = 1; r <= 16; r++) expect(rounds.has(`round.${r}`), `round.${r}`).toBe(true);
    expect(rounds.has("rounds")).toBe(false);
  });

  it("lays round.1 out canonically: F-stack right of fxor, split above recombine", () => {
    const g = desGraph();
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(
      g,
      new Map(),
      consts,
      new Set(),
      undefined,
      new Map(),
      feistelRoundsOf(desSpec),
    );
    const box = (id: string) => {
      const b = boxes.get(id);
      if (!b) throw new Error(`no box for ${id}`);
      return b;
    };
    // F-function column is to the RIGHT of the L rail (fxor).
    expect(box("round.1.expand-R").x).toBeGreaterThan(box("round.1.fxor").x);
    expect(box("round.1.xor-K").x).toBe(box("round.1.expand-R").x);
    // split sits above the F stack; recombine sits below it.
    expect(box("round.1.split").y).toBeLessThan(box("round.1.expand-R").y);
    expect(box("round.1.recombine").y).toBeGreaterThan(box("round.1.p-permute").y);
    // fxor is level with the last F leaf (p-permute).
    expect(box("round.1.fxor").y).toBe(box("round.1.p-permute").y);
  });

  it("leaves a NON-Feistel spec (AES) byte-identical with vs without the Feistel map", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]),
    });
    const g = deriveAuxGraph(trace, aes128Spec);
    const consts = layoutConstantsFor("normal");
    const without = layoutRoot(g, new Map(), consts);
    // AES has no Feistel-shaped groups, so passing the (empty) map changes nothing.
    const withMap = layoutRoot(
      g,
      new Map(),
      consts,
      new Set(),
      undefined,
      new Map(),
      feistelRoundsOf(aes128Spec),
    );
    expect(feistelRoundsOf(aes128Spec).size).toBe(0);
    expect(withMap.canvasW).toBe(without.canvasW);
    expect(withMap.canvasH).toBe(without.canvasH);
  });
});
