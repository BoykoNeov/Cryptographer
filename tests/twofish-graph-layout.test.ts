// @vitest-environment jsdom
//
// jsdom (not node) because importing `layoutRoot` from GraphView.tsx pulls in
// `solid-js/web` at module init, which touches `window`. The component is
// never rendered — we drive the pure `layoutRoot` export with the Twofish map.

/**
 * End-to-end check of the canonical Twofish 4-rail LAYOUT integration: feeding
 * `layoutRoot` the `twofishRounds` map (id → `TwofishRoundShape`) lays a round's
 * children out in the 4-rail canonical form (two g columns left, rolR1 atop g1,
 * PHT below, mix rails right, recombine at the bottom), while a NON-Twofish spec
 * (AES) is byte-identical with vs without the map. Pins the wiring between
 * `analyzeTwofishRound`, `twofishRoundPlacement`, and `layoutNode`'s Twofish
 * branch (the parameter slot AFTER `feistelRounds`).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { twofishSpec } from "@/ciphers/twofish";
import { type CipherGraph, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { type TwofishRoundShape, analyzeTwofishRound } from "@/core/twofish-shape";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { layoutConstantsFor, layoutRoot } from "@/ui/components/GraphView";
import { describe, expect, it } from "vitest";

const twofishRoundsOf = (spec: CipherSpec): Map<string, TwofishRoundShape> => {
  const m = new Map<string, TwofishRoundShape>();
  const walk = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      if (node.kind === "step") continue;
      if (node.kind === "group") {
        const shape = analyzeTwofishRound(node);
        if (shape !== null) m.set(node.id, shape);
      }
      walk(node.children);
    }
  };
  walk(spec.steps);
  return m;
};

const twofishGraph = (): CipherGraph => {
  const trace = runSpec(twofishSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("00000000000000000000000000000000")],
    ]),
  });
  return deriveAuxGraph(trace, twofishSpec);
};

describe("Twofish canonical 4-rail layout — round via layoutRoot", () => {
  it("detects all 16 Twofish rounds as 4-rail-shaped", () => {
    const rounds = twofishRoundsOf(twofishSpec);
    for (let r = 0; r < 16; r++) expect(rounds.has(`round.${r}`), `round.${r}`).toBe(true);
    expect(rounds.size).toBe(16);
  });

  it("lays round.0 out canonically: two g columns left, rolR1 atop g1, mix rails right, recombine bottom", () => {
    const g = twofishGraph();
    const consts = layoutConstantsFor("normal");
    const { boxes } = layoutRoot(
      g,
      new Map(),
      consts,
      new Set(),
      undefined,
      new Map(),
      new Map(), // feistelRounds (empty)
      twofishRoundsOf(twofishSpec),
    );
    const box = (id: string) => {
      const b = boxes.get(id);
      if (!b) throw new Error(`no box for ${id}`);
      return b;
    };
    // g0 column is left of the g1 column.
    expect(box("round.0.g0.split").x).toBeLessThan(box("round.0.g1.split").x);
    // rolR1 rides atop the g1 column (same x, above the g1 stack).
    expect(box("round.0.rolR1").x).toBe(box("round.0.g1.split").x);
    expect(box("round.0.rolR1").y).toBeLessThan(box("round.0.g1.split").y);
    // split above the g stacks; recombine below the PHT.
    expect(box("round.0.split").y).toBeLessThan(box("round.0.g0.split").y);
    expect(box("round.0.recombine").y).toBeGreaterThan(box("round.0.f0").y);
    // the R2/R3 mix rails sit to the right of the g band.
    expect(box("round.0.r2x").x).toBeGreaterThan(box("round.0.g1.split").x);
    expect(box("round.0.r3r").x).toBeGreaterThan(box("round.0.r2x").x);
  });

  it("leaves a NON-Twofish spec (AES) byte-identical with vs without the Twofish map", () => {
    const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]),
    });
    const g = deriveAuxGraph(trace, aes128Spec);
    const consts = layoutConstantsFor("normal");
    const without = layoutRoot(g, new Map(), consts);
    const withMap = layoutRoot(
      g,
      new Map(),
      consts,
      new Set(),
      undefined,
      new Map(),
      new Map(),
      twofishRoundsOf(aes128Spec),
    );
    expect(twofishRoundsOf(aes128Spec).size).toBe(0);
    expect(withMap.canvasW).toBe(without.canvasW);
    expect(withMap.canvasH).toBe(without.canvasH);
  });
});
