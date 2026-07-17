/**
 * Twofish linear-diagram model (`src/core/twofish-diagram.ts`) — the pure
 * derivation behind the linear view's abstract round picture.
 *
 * The properties worth pinning here are the ones a learner would be MISLED by
 * if they broke silently:
 *   - the swap really is the 4-way rotation `(R2′, R3′, R0, R1)`, read off the
 *     recombine's argument order rather than hardcoded;
 *   - each rail is labelled with the word it actually mixes, and each `⊕` with
 *     the F it actually consumes (a rail mislabelled F0-vs-F1 would teach the
 *     wrong cipher);
 *   - rotations are named the way the Twofish paper names them (ROL 8), not the
 *     way the builder encodes them (ROR 24 — every left turn ships as its
 *     right-turn complement);
 *   - encrypt and decrypt BOTH render, since they differ in their two 1-bit
 *     rotations and the order those sit on the rails.
 */

import { twofishSpec } from "@/ciphers/twofish";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import { findStepAndParent } from "@/core/spec-mutations";
import { twofishDiagramModel } from "@/core/twofish-diagram";
import { analyzeTwofishRound } from "@/core/twofish-shape";
import type { CipherSpec, StepGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

const roundGroup = (spec: CipherSpec, id: string): StepGroup => {
  const located = findStepAndParent(spec, id);
  if (!located || located.node.kind !== "group") throw new Error(`expected a group at ${id}`);
  return located.node;
};

/** Build the diagram model for a round of a real Twofish spec. */
const modelFor = (spec: CipherSpec, roundId: string) => {
  const group = roundGroup(spec, roundId);
  const shape = analyzeTwofishRound(group);
  if (!shape) throw new Error(`${roundId} was not recognized as a Twofish round`);
  const model = twofishDiagramModel(shape, group);
  if (!model) throw new Error(`${roundId} produced no diagram model`);
  return model;
};

describe("twofishDiagramModel — the swap", () => {
  it("reads the 4-way rotation (R2′, R3′, R0, R1) off the recombine argument order", () => {
    const m = modelFor(twofishSpec, "round.5");
    // Slots 0/1 take the two MIXED words (R2, R3); slots 2/3 take the words
    // carried through untouched (R0, R1). That rotation IS Twofish's swap.
    expect(m.swapSources).toEqual([2, 3, 0, 1]);
    expect(m.outputLabels).toEqual(["R2′", "R3′", "R0", "R1"]);
  });

  it("derives the same swap for the decrypt round (the rotations differ, the concat order does not)", () => {
    const m = modelFor(twofishDecryptSpec, "round.5");
    expect(m.swapSources).toEqual([2, 3, 0, 1]);
    expect(m.outputLabels).toEqual(["R2′", "R3′", "R0", "R1"]);
  });
});

describe("twofishDiagramModel — the mix rails", () => {
  it("labels each rail with the word it mixes and the F its xor consumes", () => {
    const [rail2, rail3] = modelFor(twofishSpec, "round.5").mixRails;
    // R2's rail mixes in F0; R3's mixes in F1. Swapping these would teach a
    // cipher that doesn't round-trip.
    expect(rail2.railIndex).toBe(2);
    expect(rail2.fIndex).toBe(0);
    expect(rail3.railIndex).toBe(3);
    expect(rail3.fIndex).toBe(1);
  });

  it("encrypt mixes R2 as ⊕-then-ROR 1, and R3 as ROL 1-then-⊕", () => {
    // Ferguson's ENCRYPT_RND: C = ROR(C ⊕ F0, 1); D = ROL(D, 1) ⊕ F1. The two
    // rails apply their rotation on OPPOSITE sides of the xor — the asymmetry
    // is what makes the round invertible, so the order must survive.
    const [rail2, rail3] = modelFor(twofishSpec, "round.5").mixRails;
    expect(rail2.nodes.map((n) => n.kind)).toEqual(["xor", "rotate"]);
    expect(rail2.nodes.map((n) => n.label)).toEqual(["⊕ F0", "ROR 1"]);
    expect(rail3.nodes.map((n) => n.kind)).toEqual(["rotate", "xor"]);
    expect(rail3.nodes.map((n) => n.label)).toEqual(["ROL 1", "⊕ F1"]);
  });

  it("decrypt inverts both rails: R2 becomes ROL 1-then-⊕, R3 becomes ⊕-then-ROR 1", () => {
    const [rail2, rail3] = modelFor(twofishDecryptSpec, "round.5").mixRails;
    expect(rail2.nodes.map((n) => n.label)).toEqual(["ROL 1", "⊕ F0"]);
    expect(rail3.nodes.map((n) => n.label)).toEqual(["⊕ F1", "ROR 1"]);
    // Still the right F on the right rail after the inversion.
    expect(rail2.fIndex).toBe(0);
    expect(rail3.fIndex).toBe(1);
  });
});

describe("twofishDiagramModel — rotation naming", () => {
  it("names the R1 pre-rotation ROL 8, the way the paper does — not ROR 24, the way the spec encodes it", () => {
    // `rolR1` ships as `rotate-bits-right@1 { bits: 24, wordBits: 32 }` because
    // the builder expresses every left turn as its right-turn complement.
    // Showing the raw param would make the diagram contradict the Twofish paper.
    const m = modelFor(twofishSpec, "round.5");
    expect(m.rolLabel).toBe("ROL 8");
  });
});

describe("twofishDiagramModel — structure passthrough", () => {
  it("carries the g stacks, the PHT, and the rol rail as separate element groups", () => {
    const m = modelFor(twofishSpec, "round.5");
    // The 8-bit rotation is NOT part of g — g0 has no such rotation, and a
    // learner must not read the turn as belonging inside the g box.
    expect(m.rolNodeId).toBe("round.5.rolR1");
    expect(m.g0Ids).not.toContain(m.rolNodeId);
    expect(m.g1Ids).not.toContain(m.rolNodeId);
    expect(m.g0Ids.length).toBeGreaterThan(0);
    expect(m.g1Ids.length).toBe(m.g0Ids.length);
    expect(m.phtIds).toContain("round.5.f0");
    expect(m.phtIds).toContain("round.5.f1");
    expect(m.splitId).toBe("round.5.split");
    expect(m.recombineId).toBe("round.5.recombine");
  });

  it("models every round of both directions (no round is left undrawable)", () => {
    for (let i = 0; i < 16; i++) {
      expect(() => modelFor(twofishSpec, `round.${i}`)).not.toThrow();
      expect(() => modelFor(twofishDecryptSpec, `round.${i}`)).not.toThrow();
    }
  });
});
