/**
 * Port-native Feistel-shape analysis (Slice 5.3d).
 *
 * Pins the three pure functions in `core/feistel-shape.ts` that drive the
 * rebuilt Feistel/swap visualization:
 *   - `analyzeFeistelRound` recognizes a port-native DES round from its real
 *     split→…→xor→concat wiring (and rejects non-Feistel groups);
 *   - the SWAP is derived from the recombine's argument order (rounds 1..15 =
 *     swap, round 16 = no-swap) for BOTH encrypt and decrypt;
 *   - `resolveFeistelRoundBytes` reads the round halves from the child frames'
 *     port I/O and matches the FIPS 46-3 KAT (`des-kat.json`) for all 16 rounds.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { buildSha256Spec } from "@/ciphers/sha-256";
import {
  analyzeFeistelRound,
  findActiveFeistelRound,
  resolveFeistelRoundBytes,
} from "@/core/feistel-shape";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepGroup, StepNode, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";
import desKat from "./fixtures/des-kat.json";

// FIPS 46-3 Appendix B vector — the one in des-kat.json.
const DES_PT = "0123456789abcdef";
const DES_KEY = "133457799bbcdff1";
const desVector = desKat.vectors[0];
if (!desVector) throw new Error("des-kat.json is missing its first vector");

const roundGroup = (spec: CipherSpec, id: string): StepGroup => {
  const located = findStepAndParent(spec, id);
  if (!located || located.node.kind !== "group") {
    throw new Error(`expected a group node at ${id}`);
  }
  return located.node;
};

/** Collect every `group` node in a spec tree (for the null-case sweep). */
const collectGroups = (nodes: readonly StepNode[], out: StepGroup[] = []): StepGroup[] => {
  for (const n of nodes) {
    if (n.kind === "group") out.push(n);
    const children = (n as { children?: readonly StepNode[] }).children;
    if (Array.isArray(children)) collectGroups(children, out);
  }
  return out;
};

/** A minimal synthetic frame for the spec/trace-mismatch guard test. */
const fakeFrame = (path: string[], stepId: string): TraceFrame => ({
  index: 0,
  path,
  stepId,
  stepType: "x",
  params: {},
  stateBefore: makeBytesState(new Uint8Array(0)),
  stateAfter: makeBytesState(new Uint8Array(0)),
  auxRead: new Map(),
  auxWritten: new Map(),
});

const runDes = () =>
  runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
    portedDispatchEnabled: true,
  });

const xorHex = (a: string, b: string): string => {
  const x = bytesFromHex(a);
  const y = bytesFromHex(b);
  const out = new Uint8Array(x.length);
  for (let i = 0; i < x.length; i++) out[i] = (x[i] ?? 0) ^ (y[i] ?? 0);
  return hexFromBytes(out);
};

describe("analyzeFeistelRound — structural recognition", () => {
  it("recognizes a DES round and names its parts from the wiring", () => {
    const shape = analyzeFeistelRound(roundGroup(desSpec, "round.1"));
    expect(shape).not.toBeNull();
    if (!shape) return;
    expect(shape.roundId).toBe("round.1");
    expect(shape.splitId).toBe("round.1.split");
    expect(shape.fxorId).toBe("round.1.fxor");
    expect(shape.recombineId).toBe("round.1.recombine");
    expect(shape.fStackIds).toEqual([
      "round.1.expand-R",
      "round.1.xor-K",
      "round.1.s-boxes",
      "round.1.p-permute",
    ]);
    // L reads split.output0, R reads split.output1; F rides fxor.operand1.
    expect(shape.splitLPort).toBe("output0");
    expect(shape.splitRPort).toBe("output1");
    expect(shape.fxorFInPort).toBe("operand1");
    expect(shape.fxorOutPort).toBe("output");
    expect(shape.recombineOutPort).toBe("output");
    // Round 1 consumes K_1 from roundKey.0.
    expect(shape.roundKeyAux).toBe("roundKey.0");
  });

  it("derives swap=true for encrypt rounds 1..15 and swap=false for round 16", () => {
    for (let r = 1; r <= 16; r++) {
      const shape = analyzeFeistelRound(roundGroup(desSpec, `round.${r}`));
      expect(shape, `round.${r}`).not.toBeNull();
      expect(shape?.swap, `round.${r} swap`).toBe(r !== 16);
    }
  });

  it("derives the same swap pattern for DECRYPT (round 16 still no-swap, keys reversed)", () => {
    expect(analyzeFeistelRound(roundGroup(desDecryptSpec, "round.1"))?.swap).toBe(true);
    expect(analyzeFeistelRound(roundGroup(desDecryptSpec, "round.16"))?.swap).toBe(false);
    // Decrypt round 1 reads roundKey.15 (K_16); round 16 reads roundKey.0 (K_1).
    expect(analyzeFeistelRound(roundGroup(desDecryptSpec, "round.1"))?.roundKeyAux).toBe(
      "roundKey.15",
    );
    expect(analyzeFeistelRound(roundGroup(desDecryptSpec, "round.16"))?.roundKeyAux).toBe(
      "roundKey.0",
    );
  });

  it("returns null for the outer DES `rounds` group (bodyOutput → a child group, not a concat)", () => {
    expect(analyzeFeistelRound(roundGroup(desSpec, "rounds"))).toBeNull();
  });

  it("returns null for every AES group and every SHA-256 group (no false positives)", () => {
    for (const g of collectGroups(aes128Spec.steps)) {
      expect(analyzeFeistelRound(g), `aes group ${g.id}`).toBeNull();
    }
    for (const g of collectGroups(buildSha256Spec().steps)) {
      expect(analyzeFeistelRound(g), `sha group ${g.id}`).toBeNull();
    }
  });

  it("returns null when a round's recombine is rewired off the split/fxor shape", () => {
    // A hand-broken round: recombine reads its own split twice (no fxor input).
    const round = roundGroup(desSpec, "round.1");
    const broken: StepGroup = {
      ...round,
      children: round.children.map((c) =>
        c.kind === "step" && c.id === "round.1.recombine"
          ? {
              ...c,
              portInputs: {
                input0: { node: "round.1.split", port: "output0" },
                input1: { node: "round.1.split", port: "output1" },
              },
            }
          : c,
      ),
    };
    expect(analyzeFeistelRound(broken)).toBeNull();
  });
});

describe("findActiveFeistelRound — detection from frame.path", () => {
  it("resolves the round for a frame inside a DES round body", () => {
    const trace = runDes();
    const frame = trace.frames.find((f) => f.stepId === "round.5.expand-R");
    expect(frame).toBeDefined();
    if (!frame) return;
    const found = findActiveFeistelRound(frame, desSpec);
    expect(found?.shape.roundId).toBe("round.5");
  });

  it("returns null for a top-level frame outside any round (initial-permutation)", () => {
    const trace = runDes();
    const frame = trace.frames.find((f) => f.stepId === "initial-permutation");
    expect(frame).toBeDefined();
    if (!frame) return;
    expect(findActiveFeistelRound(frame, desSpec)).toBeNull();
  });

  it("guards a spec/trace mismatch: a non-member frame under a Feistel-named round → null", () => {
    // Every cipher names its rounds `round.N`, so during a cipher switch the
    // DES spec's Feistel-shaped `round.5` could match an AES frame whose path
    // also contains `round.5`. The leaf-membership guard rejects that: an
    // AES-style `round.5.mix-columns` is not a DES round.5 leaf.
    const mismatch = fakeFrame(["rounds", "round.5"], "round.5.mix-columns");
    expect(findActiveFeistelRound(mismatch, desSpec)).toBeNull();
    // A genuine DES leaf under the same round still resolves.
    const genuine = fakeFrame(["rounds", "round.5"], "round.5.expand-R");
    expect(findActiveFeistelRound(genuine, desSpec)?.shape.roundId).toBe("round.5");
  });
});

describe("resolveFeistelRoundBytes — KAT across all 16 rounds", () => {
  it("matches des-kat.json L_in/R_in/F/L⊕F/new_L/new_R for every round", () => {
    const trace = runDes();
    for (const rd of desVector.rounds) {
      const shape = analyzeFeistelRound(roundGroup(desSpec, `round.${rd.i}`));
      expect(shape, `round.${rd.i}`).not.toBeNull();
      if (!shape) continue;
      const b = resolveFeistelRoundBytes(shape, trace.frames, undefined);
      const hex = (v: Uint8Array | null): string => (v ? hexFromBytes(v) : "<null>");
      expect(hex(b.L_in), `round ${rd.i} L_in`).toBe(rd.L_in);
      expect(hex(b.R_in), `round ${rd.i} R_in`).toBe(rd.R_in);
      expect(hex(b.F), `round ${rd.i} F`).toBe(rd.F_out);
      // L⊕F is the XOR of L_in with F regardless of swap.
      const lxorf = xorHex(rd.L_in, rd.F_out);
      expect(hex(b.LxorF), `round ${rd.i} L⊕F`).toBe(lxorf);
      // new_L / new_R are the round output's PHYSICAL halves (the bytes that
      // flow on to the next round / FP). The swap decides which value lands in
      // which half: swap → new_L=R_in, new_R=L⊕F; no-swap → new_L=L⊕F, new_R=R_in.
      // (NB: des-kat.json's round-16 L_out/R_out use the logical swap-labelling
      // convention — L_out=R_in — which does NOT match the no-swap physical
      // byte order, so we assert against the swap-derived values, themselves
      // grounded in des-kat's R_in + F. The round-16 byte order is pinned
      // independently against `preFp` below.)
      const swap = rd.i !== 16;
      expect(hex(b.new_L), `round ${rd.i} new_L`).toBe(swap ? rd.R_in : lxorf);
      expect(hex(b.new_R), `round ${rd.i} new_R`).toBe(swap ? lxorf : rd.R_in);
    }
  });

  it("round 16's recombine output (no-swap) IS the DES preoutput before FP", () => {
    const trace = runDes();
    const shape = analyzeFeistelRound(roundGroup(desSpec, "round.16"));
    expect(shape?.swap).toBe(false);
    if (!shape) return;
    const b = resolveFeistelRoundBytes(shape, trace.frames, undefined);
    expect(b.new_L).not.toBeNull();
    expect(b.new_R).not.toBeNull();
    if (!b.new_L || !b.new_R) return;
    // The no-swap recombine = concat(L⊕F, R), and that 8-byte block is exactly
    // what FP consumes — pinned against des-kat's independent `preFp` field.
    expect(hexFromBytes(b.new_L) + hexFromBytes(b.new_R)).toBe(desVector.preFp);
  });
});
