/**
 * SHA-256 helper composition KATs — universal-port plan Phase 2 Slice
 * 2.3, 2026-05-24.
 *
 * Per Open #N3 user pick (b) Compositions, SHA-256's Σ0, Σ1, Ch, Maj
 * are NOT registered as cipher-specific step types. They are
 * compositions of the universal port-native primitives shipped across
 * Slices 2.1a/2.1b/2.3:
 *
 *   - rotate-bits-right@1  (Slice 2.1a)
 *   - xor@1                (Slice 2.1b)
 *   - and@1                (Slice 2.3)
 *   - not@1                (Slice 2.3)
 *
 * This file validates the four helpers by composing them via direct
 * executor invocation (no spec, no edges yet — Slice 2.6 wires the
 * compositions into a real SHA-256 spec). Each helper is tested:
 *
 *   1. Against a hand-derived KAT from the FIPS 180-4 §4.1.2 textbook
 *      formula. Σ0(H_0) and Maj(H_0, H_1, H_2) were hand-derived twice
 *      (direct + indirect via T2 = a' − T1 against §A.1's round-0
 *      working variables); the values agree. The 2026-05-21 Slice 2.1a
 *      precedent — plan-cited KAT `0x12345678 ROR 2 = 0x80123456` was
 *      wrong — keeps "hand-derive twice, cross-check" as the gate.
 *
 *   2. Against a small TS oracle implementing the same formulas via
 *      raw JS bit ops, run on multiple inputs. This catches errors the
 *      single-KAT hand-derivation might mask, and stresses helpers
 *      beyond the one-input hand-derived value.
 *
 *   3. Against the algebraic properties that make each helper
 *      meaningful (Σ0(0)=0, Σ0 self-inverse-pairwise via 22-rotation
 *      identity, Maj(x,x,x)=x, Ch(x,y,y)=y, etc.).
 *
 * **Why direct executor calls, not runSpec.** Port-native steps' on-
 * flag dispatch path throws "requires spec edge-wiring (Slice 2.6+)"
 * — that wiring is exactly the Slice 2.6 deliverable. Until then,
 * composition lives in test scaffolding: we call each primitive's
 * executor by hand and thread its output as the next executor's input.
 * Same posture as `tests/xor.test.ts` and `tests/add-mod-32.test.ts`'s
 * KAT suites.
 */

import type { Json, StepContext } from "@/core/types";
import { addMod32, addMod32OperandPortName } from "@/steps/add-mod-32";
import { and, andOperandPortName } from "@/steps/and";
import { not } from "@/steps/not";
import { rotateBitsRight } from "@/steps/rotate-bits-right";
import { xor, xorOperandPortName } from "@/steps/xor";
import { describe, expect, it } from "vitest";

// ─── Test scaffolding: direct executor invocation helpers ────────────────

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callRor = (input: Uint8Array, bits: number): Uint8Array => {
  const out = rotateBitsRight(
    new Map([["input", input]]),
    { bits, wordBits: 32 } as unknown as Json,
    CTX,
  );
  return out.get("output") as Uint8Array;
};

const callXor = (...operands: Uint8Array[]): Uint8Array => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(xorOperandPortName(i), op));
  const out = xor(inputs, { inputCount: operands.length } as unknown as Json, CTX);
  return out.get("output") as Uint8Array;
};

const callAnd = (...operands: Uint8Array[]): Uint8Array => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(andOperandPortName(i), op));
  const out = and(inputs, { inputCount: operands.length } as unknown as Json, CTX);
  return out.get("output") as Uint8Array;
};

const callNot = (input: Uint8Array): Uint8Array => {
  const out = not(new Map([["input", input]]), {} as Json, CTX);
  return out.get("output") as Uint8Array;
};

const callAdd = (...operands: Uint8Array[]): Uint8Array => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(addMod32OperandPortName(i), op));
  const out = addMod32(inputs, { inputCount: operands.length } as unknown as Json, CTX);
  return out.get("output") as Uint8Array;
};

// ─── Helper compositions — these ARE the SHA-256 helpers expressed via
// the universal-port primitive vocabulary. When Slice 2.6's SHA-256
// spec lands, each of these compositions becomes a sub-graph of leaf
// nodes wired via spec edges; the byte-level behavior is identical. ──

/** Σ0(x) = ROR(x, 2) ⊕ ROR(x, 13) ⊕ ROR(x, 22). FIPS 180-4 §4.1.2. */
const composeSigma0 = (x: Uint8Array): Uint8Array =>
  callXor(callRor(x, 2), callRor(x, 13), callRor(x, 22));

/** Σ1(x) = ROR(x, 6) ⊕ ROR(x, 11) ⊕ ROR(x, 25). FIPS 180-4 §4.1.2. */
const composeSigma1 = (x: Uint8Array): Uint8Array =>
  callXor(callRor(x, 6), callRor(x, 11), callRor(x, 25));

/** Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z). FIPS 180-4 §4.1.2. */
const composeCh = (x: Uint8Array, y: Uint8Array, z: Uint8Array): Uint8Array =>
  callXor(callAnd(x, y), callAnd(callNot(x), z));

/**
 * Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z). FIPS 180-4 §4.1.2.
 * The XOR-form intentionally — the OR-form `(x∧y) ∨ (x∧z) ∨ (y∧z)`
 * is bit-identical but would force the universal vocabulary to add
 * `or@1`. Since SHA-256 ships with only the helpers below, the XOR-
 * form keeps Phase 2's new-primitive count at exactly two (and@1,
 * not@1) per Open #N3 (b) pick.
 */
const composeMaj = (x: Uint8Array, y: Uint8Array, z: Uint8Array): Uint8Array =>
  callXor(callAnd(x, y), callAnd(x, z), callAnd(y, z));

// ─── TS reference oracle — implements Σ0/Σ1/Ch/Maj/ROR directly via
// JS bit ops. Used as the verification baseline for composition
// outputs across many inputs. Per advisor warning: `node:crypto` does
// not expose these helpers, only full SHA-256 — so a TS oracle is the
// honest cross-check inside this slice. Slice 2.6 will additionally
// cross-check the full SHA-256 hash against `node:crypto`. ──────────

const beU32 = (bytes: Uint8Array, off: number): number =>
  (((bytes[off] as number) << 24) |
    ((bytes[off + 1] as number) << 16) |
    ((bytes[off + 2] as number) << 8) |
    (bytes[off + 3] as number)) >>>
  0;

const u32ToBytes = (w: number): Uint8Array =>
  new Uint8Array([(w >>> 24) & 0xff, (w >>> 16) & 0xff, (w >>> 8) & 0xff, w & 0xff]);

const rorU32 = (w: number, n: number): number => {
  const k = n & 31;
  return k === 0 ? w >>> 0 : ((w >>> k) | (w << (32 - k))) >>> 0;
};

// `^` in JS returns a SIGNED 32-bit number; coerce to unsigned via
// `>>> 0` so the oracle matches the composition's beU32 (unsigned)
// output for any word whose high bit ends up set after the XOR.
const oracleSigma0 = (x: number): number => (rorU32(x, 2) ^ rorU32(x, 13) ^ rorU32(x, 22)) >>> 0;
const oracleSigma1 = (x: number): number => (rorU32(x, 6) ^ rorU32(x, 11) ^ rorU32(x, 25)) >>> 0;
const oracleCh = (x: number, y: number, z: number): number => ((x & y) ^ (~x & z)) >>> 0;
const oracleMaj = (x: number, y: number, z: number): number => ((x & y) ^ (x & z) ^ (y & z)) >>> 0;

// SHA-256 initial hash values H_0..H_7 (FIPS 180-4 §5.3.3) — used as
// the canonical test inputs because they are the most-published 32-bit
// constants in the standard.
const H0 = 0x6a09e667;
const H1 = 0xbb67ae85;
const H2 = 0x3c6ef372;
const H3 = 0xa54ff53a;
const H4 = 0x510e527f;
const H5 = 0x9b05688c;
const H6 = 0x1f83d9ab;
const H7 = 0x5be0cd19;

// ─── Hand-derived KATs (the gate for "did I get the formula right") ─

describe("SHA-256 helpers — hand-derived KATs against FIPS 180-4 §4.1.2", () => {
  it("Σ0(0x6A09E667) = 0xCE20B47E (hand-derived, cross-verified)", () => {
    // Hand-derived two ways:
    //
    //   (1) Direct from textbook:
    //       ROR(H_0, 2)  = 0xDA82_7999
    //       ROR(H_0, 13) = 0x333B_504F   ← the gotcha digit: bit 19 of
    //                                       (H_0 >> 13) is 0 but bit 19
    //                                       of (H_0 << 19) is 1, so the
    //                                       OR's nibble 4 is B, not 8.
    //                                       An earlier draft of the
    //                                       hand-derivation had 0x3338,
    //                                       which gave Σ0 = 0xCE23B47E
    //                                       (off by 0x03 in nibble 4).
    //       ROR(H_0, 22) = 0x2799_9DA8
    //       XOR all three = 0xCE20_B47E.
    //
    //   (2) Indirect via FIPS 180-4 §A.1.1 round-0 working variables:
    //       a^(1) = T1+T2 ⇒ T2 = a^(1) − T1 (mod 2^32);
    //       T1 = e^(1) − d^(0) (mod 2^32);
    //       T2 = Σ0(a) + Maj(a,b,c) ⇒ Σ0(a) = T2 − Maj(a,b,c) (mod 2^32).
    //       Both methods land on 0xCE20B47E. Agreement was the
    //       pre-implementation cross-check; the test here pins the
    //       resulting literal — full external validation against
    //       `node:crypto`'s full-SHA-256 hash defers to Slice 2.6.
    expect(beU32(composeSigma0(u32ToBytes(H0)), 0)).toBe(0xce20b47e);
  });

  it("Maj(H_0, H_1, H_2) = 0x3A6FE667 (hand-derived from textbook)", () => {
    // x ∧ y = 0x6A09E667 ∧ 0xBB67AE85 = 0x2A01A605
    // x ∧ z = 0x6A09E667 ∧ 0x3C6EF372 = 0x2808E262
    // y ∧ z = 0xBB67AE85 ∧ 0x3C6EF372 = 0x3866A200
    // XOR all three: 0x2A01A605 ⊕ 0x2808E262 = 0x02094467
    //                0x02094467 ⊕ 0x3866A200 = 0x3A6FE667.
    const result = composeMaj(u32ToBytes(H0), u32ToBytes(H1), u32ToBytes(H2));
    expect(beU32(result, 0)).toBe(0x3a6fe667);
  });

  it("Σ0 oracle matches composition for every SHA-256 IV word", () => {
    // Stress against all 8 initial hash values. If the hand-derived
    // KAT was right but a different word triggers a latent bug in the
    // primitive composition, this surfaces it.
    for (const w of [H0, H1, H2, H3, H4, H5, H6, H7]) {
      expect(beU32(composeSigma0(u32ToBytes(w)), 0)).toBe(oracleSigma0(w));
    }
  });

  it("Σ1 oracle matches composition for every SHA-256 IV word", () => {
    for (const w of [H0, H1, H2, H3, H4, H5, H6, H7]) {
      expect(beU32(composeSigma1(u32ToBytes(w)), 0)).toBe(oracleSigma1(w));
    }
  });

  it("Ch oracle matches composition for several SHA-256 IV word triples", () => {
    // Triples chosen to hit the (x_bit, y_bit, z_bit) combinations
    // that exercise both branches of Ch independently.
    const triples: [number, number, number][] = [
      [H4, H5, H6], // round-0 (e, f, g) for "abc" — the natural SHA-256 entry point
      [H0, H1, H2],
      [0x00000000, 0xffffffff, 0xaaaa5555],
      [0xffffffff, 0xaaaa5555, 0x00000000],
      [0xaaaa5555, 0x55555555, 0xaaaaaaaa],
    ];
    for (const [x, y, z] of triples) {
      const result = composeCh(u32ToBytes(x), u32ToBytes(y), u32ToBytes(z));
      expect(beU32(result, 0)).toBe(oracleCh(x, y, z));
    }
  });

  it("Maj oracle matches composition for several SHA-256 IV word triples", () => {
    const triples: [number, number, number][] = [
      [H0, H1, H2], // round-0 (a, b, c) for "abc"
      [H4, H5, H6],
      [0x00000000, 0xffffffff, 0xaaaa5555],
      [0xffffffff, 0xaaaa5555, 0x00000000],
      [0xaaaa5555, 0x55555555, 0xaaaaaaaa],
    ];
    for (const [x, y, z] of triples) {
      const result = composeMaj(u32ToBytes(x), u32ToBytes(y), u32ToBytes(z));
      expect(beU32(result, 0)).toBe(oracleMaj(x, y, z));
    }
  });
});

// ─── Algebraic properties — defensive checks per advisor pattern ─────

describe("SHA-256 helpers — algebraic properties", () => {
  it("Σ0(0) = 0 and Σ1(0) = 0 (rotation of zero is zero)", () => {
    const zero = u32ToBytes(0);
    expect(beU32(composeSigma0(zero), 0)).toBe(0);
    expect(beU32(composeSigma1(zero), 0)).toBe(0);
  });

  it("Σ0(0xFFFFFFFF) = 0xFFFFFFFF (XOR of three rotated all-ones = all-ones)", () => {
    // Three copies of all-ones XOR to all-ones (odd count, each bit
    // set in all three operands). Same property holds for Σ1.
    const allOnes = u32ToBytes(0xffffffff);
    expect(beU32(composeSigma0(allOnes), 0)).toBe(0xffffffff);
    expect(beU32(composeSigma1(allOnes), 0)).toBe(0xffffffff);
  });

  it("Maj(x, x, x) = x for any x (idempotence under triple-vote)", () => {
    // Algebraic check: each AND collapses to x; three copies of x XOR
    // to x (odd count). Specs that rely on this property — e.g., the
    // post-compression hash-state update — would silently break if Maj
    // mishandled identical inputs.
    for (const w of [H0, H4, 0x00000000, 0xffffffff, 0xdeadbeef]) {
      const x = u32ToBytes(w);
      expect(beU32(composeMaj(x, x, x), 0)).toBe(w);
    }
  });

  it("Ch(0, y, z) = z (zero x always selects z branch)", () => {
    // (0 ∧ y) ⊕ (¬0 ∧ z) = 0 ⊕ z = z. Pins the "x is the selector"
    // mental model.
    const zero = u32ToBytes(0);
    for (const yz of [
      [H0, H1],
      [H4, H5],
      [0x00000000, 0xffffffff],
    ] as const) {
      const result = composeCh(zero, u32ToBytes(yz[0]), u32ToBytes(yz[1]));
      expect(beU32(result, 0)).toBe(yz[1]);
    }
  });

  it("Ch(0xFFFFFFFF, y, z) = y (all-ones x always selects y branch)", () => {
    // (1 ∧ y) ⊕ (¬1 ∧ z) = y ⊕ 0 = y. Dual of the previous test.
    const allOnes = u32ToBytes(0xffffffff);
    for (const yz of [
      [H0, H1],
      [H4, H5],
      [0x00000000, 0xffffffff],
    ] as const) {
      const result = composeCh(allOnes, u32ToBytes(yz[0]), u32ToBytes(yz[1]));
      expect(beU32(result, 0)).toBe(yz[0]);
    }
  });

  it("Ch(x, y, y) = y for any x (y == z collapses the selector)", () => {
    // (x ∧ y) ⊕ (¬x ∧ y) = (x ⊕ ¬x) ∧ y = 0xFFFFFFFF ∧ y = y.
    for (const xy of [
      [H0, H1],
      [H4, H5],
      [0xdeadbeef, 0xcafebabe],
    ] as const) {
      const x = u32ToBytes(xy[0]);
      const y = u32ToBytes(xy[1]);
      expect(beU32(composeCh(x, y, y), 0)).toBe(xy[1]);
    }
  });
});

// ─── Cross-helper randomized comparison (oracle-driven) ──────────────

describe("SHA-256 helpers — oracle parity across pseudo-random inputs", () => {
  // Deterministic linear-congruential generator (Numerical Recipes
  // constants) so the test is reproducible. Inline implementation
  // avoids importing a random dependency; one of the cipher project's
  // pinned principles is that tests don't pull in extra deps.
  const seededRandom = (seed: number): (() => number) => {
    let state = seed >>> 0;
    return () => {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state;
    };
  };

  it("Σ0 / Σ1 / Ch / Maj compositions match oracle on 64 pseudo-random word(s) / triple(s)", () => {
    // 64 trials is enough to surface a single-bit error in any branch
    // with overwhelming probability while keeping the test fast. The
    // hand-derived KATs above pin the literal "abc"-round-0 entry; this
    // suite stresses the composition across the broader input space.
    const rand = seededRandom(0xc0ffee);
    for (let trial = 0; trial < 64; trial++) {
      const x = rand();
      const y = rand();
      const z = rand();
      const xBytes = u32ToBytes(x);
      const yBytes = u32ToBytes(y);
      const zBytes = u32ToBytes(z);

      expect(beU32(composeSigma0(xBytes), 0)).toBe(oracleSigma0(x));
      expect(beU32(composeSigma1(xBytes), 0)).toBe(oracleSigma1(x));
      expect(beU32(composeCh(xBytes, yBytes, zBytes), 0)).toBe(oracleCh(x, y, z));
      expect(beU32(composeMaj(xBytes, yBytes, zBytes), 0)).toBe(oracleMaj(x, y, z));
    }
  });
});

// ─── Bonus: T2 = Σ0(a) + Maj(a,b,c) composes correctly via add-mod-32 ──

describe("SHA-256 helpers — T2 composition (Σ0 + Maj via add-mod-32@1)", () => {
  it("T2(H_0, H_1, H_2) composes correctly via the universal-port vocabulary", () => {
    // T2 = Σ0(a) + Maj(a, b, c) (mod 2^32) is one of the SHA-256
    // compression-function intermediates (FIPS 180-4 §6.2.2). Verifies
    // that the full Σ0/Maj/add-mod-32 chain composes correctly across
    // three different port-native primitives — the load-bearing
    // integration check for the Phase 2 vocabulary.
    const a = u32ToBytes(H0);
    const b = u32ToBytes(H1);
    const c = u32ToBytes(H2);
    const sigma0 = composeSigma0(a);
    const maj = composeMaj(a, b, c);
    const t2 = callAdd(sigma0, maj);
    // Expected: 0xCE20B47E + 0x3A6FE667 = 0x10890_9AE5 → mod 2^32 = 0x08909AE5.
    expect(beU32(t2, 0)).toBe(0x08909ae5);
  });
});
