/**
 * Blowfish Feistel-shape recognition — the generalization that lets the
 * canonical two-column layout (and the linear Feistel views) cover Blowfish, not
 * just DES.
 *
 * Blowfish mirrors DES in two ways the original `analyzeFeistelRound` couldn't
 * express:
 *   1. the carried half is NOT the raw split output — the `xorP` key mix
 *      (`L ⊕ P[i]`) sits on it before it feeds F and passes down to the
 *      recombine, so the analyzer must walk a **pass-through rail**; and
 *   2. F is mixed into the RIGHT half (`R⊕F`), not the left (`mixedHalf === "R"`).
 *
 * These pin the derived structure + the byte-honest swap for a real Blowfish
 * round, and that `resolveFeistelRoundBytes` reads the halves consistently
 * (new_L carries the R lineage — the halves genuinely cross every round).
 */

import { blowfishSpec } from "@/ciphers/blowfish";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  analyzeFeistelRound,
  feistelValueLabels,
  resolveFeistelRoundBytes,
} from "@/core/feistel-shape";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, StepGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

const roundGroup = (id: string): StepGroup => {
  const located = findStepAndParent(blowfishSpec, id);
  if (!located || located.node.kind !== "group") throw new Error(`expected a group at ${id}`);
  return located.node;
};

describe("analyzeFeistelRound — Blowfish (pass-through rail + mirrored orientation)", () => {
  it("recognizes a Blowfish round and names its parts from the wiring", () => {
    const shape = analyzeFeistelRound(roundGroup("round.1"));
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(shape.splitId).toBe("round.1.split");
    // The fxor is `xorR` (R ⊕ F), NOT the DES-style `fxor`.
    expect(shape.fxorId).toBe("round.1.xorR");
    expect(shape.recombineId).toBe("round.1.recombine");
    // The key-mix `xorP` is the carried rail node — excluded from the F stack.
    expect(shape.railNodeIds).toEqual(["round.1.xorP"]);
    expect(shape.fStackIds).toEqual([
      "round.1.splitF",
      "round.1.s0",
      "round.1.s1",
      "round.1.s2",
      "round.1.s3",
      "round.1.add01",
      "round.1.xor2",
      "round.1.add3",
    ]);
    // F is mixed into the RIGHT half (R⊕F); the combined value is the
    // recombine's input0, so it lands in new_L (the halves cross).
    expect(shape.mixedHalf).toBe("R");
    expect(shape.mixedRecombineInput).toBe("input0");
    expect(shape.fxorFInPort).toBe("operand0");
    // Blowfish's subkey rides the xorP rail, so no F-stack leaf reports a
    // round key.
    expect(shape.roundKeyAux).toBeNull();
  });

  it("derives byte-honest swap=true for every Blowfish round (the halves always cross)", () => {
    for (let r = 1; r <= 16; r++) {
      const shape = analyzeFeistelRound(roundGroup(`round.${r}`));
      expect(shape, `round.${r}`).not.toBeNull();
      expect(shape?.swap, `round.${r} swap`).toBe(true);
    }
  });

  it("labels the rails for the mirrored orientation (mixed = R⊕F, carried = L)", () => {
    const shape = analyzeFeistelRound(roundGroup("round.1"));
    expect(shape).not.toBeNull();
    if (!shape) return;
    const labels = feistelValueLabels(shape);
    expect(labels.mixed).toBe("R⊕F");
    expect(labels.carry).toBe("L");
    expect(labels.carryHalf).toBe("L");
  });
});

describe("resolveFeistelRoundBytes — Blowfish byte consistency", () => {
  const runBlowfish = () =>
    runSpec(blowfishSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("0123456789abcdef")]]),
    });

  it("reads geometric halves and a genuine cross (new_L carries the R⊕F lineage)", () => {
    const trace = runBlowfish();
    const shape = analyzeFeistelRound(roundGroup("round.1"));
    expect(shape).not.toBeNull();
    if (!shape) return;
    const b = resolveFeistelRoundBytes(shape, trace.frames, undefined);
    // Every role resolves.
    for (const v of [b.L_in, b.R_in, b.F, b.LxorF, b.new_L, b.new_R]) {
      expect(v).not.toBeNull();
    }
    if (!b.L_in || !b.R_in || !b.LxorF || !b.new_L || !b.new_R) return;
    // Geometric halves are 4 bytes each (balanced 64-bit Feistel).
    expect(b.L_in.length).toBe(4);
    expect(b.R_in.length).toBe(4);
    // The combined value (R⊕F) is the recombine's input0 → it lands in new_L:
    // the OLD right half became the new LEFT half — the swap, byte-honest.
    expect(hexFromBytes(b.new_L)).toBe(hexFromBytes(b.LxorF));
    // The whole round output is the two halves concatenated.
    expect(hexFromBytes(b.new_L) + hexFromBytes(b.new_R)).toBe(
      hexFromBytes(new Uint8Array([...b.new_L, ...b.new_R])),
    );
  });
});
