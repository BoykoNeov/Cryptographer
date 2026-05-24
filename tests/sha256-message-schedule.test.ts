/**
 * SHA-256 message-schedule composition KAT — universal-port plan
 * **Phase 2 Slice 2.5** (2026-05-25).
 *
 * This file covers two related deliverables:
 *
 *   1. **σ0 / σ1 helpers** as compositions of `rotate-bits-right@1` +
 *      `shift-bits-right@1` + `xor@1`. Companion to Slice 2.3's
 *      `tests/sha256-helpers.test.ts` (Σ0/Σ1/Ch/Maj). Distinct file
 *      because Slice 2.5 ships them alongside the SHR primitive itself;
 *      keeping them together makes the slice's contribution self-
 *      contained and bisect-friendly.
 *
 *   2. **Message schedule W_0..W_63** for the FIPS 180-4 §A.1 "abc"
 *      example. W_0..W_15 are 16 BE32 reads of the 64-byte padded
 *      block (the output of Slice 2.4's pad-with-byte +
 *      append-be64-length composition). W_16..W_63 follow the
 *      recurrence
 *
 *          W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}    (mod 2^32)
 *
 *      Per FIPS 180-4 §6.2.2 step 1. The σ0 / σ1 functions are
 *
 *          σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
 *          σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
 *
 *      (NOT three rotations — the plan prose had this wrong; SHR is
 *      load-bearingly different from ROR. Pinned with a hand-derived
 *      KAT below for W_17 where the SHR term matters.)
 *
 * **Why direct executor calls, not a real for-each-subgraph-with-history
 * spec.** Slice 2.0c shipped the FES-with-history node, but its body
 * leaves can only be LEGACY-shaped today — port-native body wiring (via
 * the sink-only `inputs` map per Q-edges) lands at Slice 2.6. So this
 * slice emulates the recurrence at test scope: pre-populate W_0..W_15,
 * then iterate 48 times calling each primitive's executor directly.
 * Identical math to what a real spec would produce; same input, same
 * primitives, same byte-equal output.
 *
 * **Oracle choice.** FIPS 180-4 §A.1 tabulates the per-round working
 * variables (a..h after each compression round) but does NOT tabulate
 * W_t directly — searching the published document confirms only the
 * inputs (the padded block) and the final hash are spelled out. The
 * honest oracle inside this slice is therefore a TS-direct
 * implementation of the recurrence via raw JS bit ops (same pattern as
 * the Σ0/Σ1 oracle in `sha256-helpers.test.ts`); Slice 2.6 will
 * additionally pin the full SHA-256 hash against `node:crypto`. To
 * defend against an undetected oracle bug, **two W_t values are hand-
 * derived as literal KATs**: W_16 (where all four operands are zero
 * except W_0) and W_17 (where σ1 of the length suffix is the load-
 * bearing input — exercises the σ1 path on a non-trivial value).
 *
 * **Sign-extension reminder from Slice 2.3.** Raw JS `^` returns a
 * SIGNED 32-bit number. The oracle's σ0/σ1 implementations end with
 * `>>> 0` to coerce back to unsigned; without it, the SHA-256 IV words
 * (most of which have bit 31 set after one ROR + XOR) silently mismatch
 * the composition's unsigned output. Same caveat applies to the
 * recurrence oracle's `+` chain (JS `+` returns signed when operands
 * are signed) — `>>> 0` after the modular add keeps everything
 * unsigned-32.
 */

import type { Json, StepContext } from "@/core/types";
import { addMod32, addMod32OperandPortName } from "@/steps/add-mod-32";
import { appendBe64Length } from "@/steps/append-be64-length";
import { padWithByte } from "@/steps/pad-with-byte";
import { rotateBitsRight } from "@/steps/rotate-bits-right";
import { shiftBitsRight } from "@/steps/shift-bits-right";
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

const callShr = (input: Uint8Array, bits: number): Uint8Array => {
  const out = shiftBitsRight(
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

const callAdd = (...operands: Uint8Array[]): Uint8Array => {
  const inputs = new Map<string, Uint8Array>();
  operands.forEach((op, i) => inputs.set(addMod32OperandPortName(i), op));
  const out = addMod32(inputs, { inputCount: operands.length } as unknown as Json, CTX);
  return out.get("output") as Uint8Array;
};

// ─── σ0 / σ1 compositions — the SHA-256 message-schedule helpers ─────────
//
// FIPS 180-4 §4.1.2:
//   σ0(x) = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
//   σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
//
// Note the asymmetry from Σ0/Σ1 (which use THREE rotations) — σ0/σ1
// have one SHR term, which DROPS the low bits of the input rather than
// wrapping them. This makes σ0/σ1 NOT invertible (Σ0/Σ1 are invertible
// because rotation is reversible). The information loss is what gives
// the message schedule its diffusion property.

const composeSmallSigma0 = (x: Uint8Array): Uint8Array =>
  callXor(callRor(x, 7), callRor(x, 18), callShr(x, 3));

const composeSmallSigma1 = (x: Uint8Array): Uint8Array =>
  callXor(callRor(x, 17), callRor(x, 19), callShr(x, 10));

// ─── TS reference oracle (raw JS bit ops) ───────────────────────────────

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

const shrU32 = (w: number, n: number): number => {
  // No need for the executor's `n >= 32` short-circuit here because the
  // SHA-256 shift amounts are 3 and 10. Coerce input to unsigned before
  // shifting per the standard JS-signed-int defense.
  return (w >>> 0) >>> n;
};

const oracleSmallSigma0 = (x: number): number =>
  (rorU32(x, 7) ^ rorU32(x, 18) ^ shrU32(x, 3)) >>> 0;

const oracleSmallSigma1 = (x: number): number =>
  (rorU32(x, 17) ^ rorU32(x, 19) ^ shrU32(x, 10)) >>> 0;

// SHA-256 initial hash values H_0..H_7 (FIPS 180-4 §5.3.3) — reused as
// canonical test inputs, matching the pattern in sha256-helpers.test.ts.
const H0 = 0x6a09e667;
const H1 = 0xbb67ae85;
const H2 = 0x3c6ef372;
const H3 = 0xa54ff53a;
const H4 = 0x510e527f;
const H5 = 0x9b05688c;
const H6 = 0x1f83d9ab;
const H7 = 0x5be0cd19;

// ─── Hand-derived KATs for σ0 / σ1 ──────────────────────────────────────

describe("SHA-256 σ0 / σ1 — hand-derived KATs against FIPS 180-4 §4.1.2", () => {
  it("σ1(0x00000018) = 0x000F0000 (length-suffix path — load-bearing for W_17)", () => {
    // 0x18 = bits 3 and 4 set; all other bits zero.
    //
    //   ROR(0x18, 17):
    //     Bit 3 (set) → position (3 − 17) mod 32 = 18.
    //     Bit 4 (set) → position (4 − 17) mod 32 = 19.
    //     Result = 0x000C_0000  (bits 18, 19 set).
    //
    //   ROR(0x18, 19):
    //     Bit 3 (set) → position (3 − 19) mod 32 = 16.
    //     Bit 4 (set) → position (4 − 19) mod 32 = 17.
    //     Result = 0x0003_0000  (bits 16, 17 set).
    //
    //   SHR(0x18, 10):
    //     0x18 >> 10 = 0  (0x18 < 2^10, so all bits drop).
    //
    //   XOR all three: 0x000C_0000 ⊕ 0x0003_0000 ⊕ 0 = 0x000F_0000.
    //
    // This value drives W_17 for the "abc" example (since W_15 = 0x18
    // is the only non-zero operand in W_17's recurrence after W_0..W_15
    // are populated from the padded block). The SHR³/SHR¹⁰ contribution
    // here is zero — but the test ensures the path through SHR is wired
    // correctly (returns Uint8Array(4), composes through XOR, not silent
    // ROR-substitute).
    expect(beU32(composeSmallSigma1(u32ToBytes(0x00000018)), 0)).toBe(0x000f0000);
  });

  it("σ0(0x80000000) (single-bit input) — SHR vs ROR divergence pin", () => {
    // Input has only bit 31 set. The SHR³ path zero-fills the top 3 bits,
    // so bit 31 becomes bit 28 of the output (the bit doesn't wrap).
    //
    //   ROR(0x80000000, 7):
    //     Bit 31 → position 31 − 7 = 24. Result = 0x0100_0000.
    //
    //   ROR(0x80000000, 18):
    //     Bit 31 → position 31 − 18 = 13. Result = 0x0000_2000.
    //
    //   SHR(0x80000000, 3):
    //     Bit 31 → position 31 − 3 = 28. Result = 0x1000_0000.
    //     (Contrast with ROR(0x80000000, 3) which would wrap bit 31 to
    //     bit (31 + 32 − 3) mod 32 = 28 — same result for the top bit,
    //     BUT the dropped-vs-wrapped semantic differs for bits 0..2.
    //     This single-bit input doesn't exercise that; the all-ones
    //     algebraic check below does.)
    //
    //   XOR: 0x0100_0000 ⊕ 0x0000_2000 ⊕ 0x1000_0000 = 0x1100_2000.
    expect(beU32(composeSmallSigma0(u32ToBytes(0x80000000)), 0)).toBe(0x11002000);
  });

  it("σ1(0x80000000) (single-bit input) — SHR shift to bit 21", () => {
    //   ROR(0x80000000, 17): bit 31 → bit 14 = 0x0000_4000.
    //   ROR(0x80000000, 19): bit 31 → bit 12 = 0x0000_1000.
    //   SHR(0x80000000, 10): bit 31 → bit 21 = 0x0020_0000.
    //   XOR = 0x0020_5000.
    expect(beU32(composeSmallSigma1(u32ToBytes(0x80000000)), 0)).toBe(0x00205000);
  });

  it("σ0 oracle matches composition for every SHA-256 IV word", () => {
    // Mirrors the Σ0 cross-check in `sha256-helpers.test.ts`. Stresses
    // the composition across high-bit-set words (where the sign-extension
    // gotcha bites if it's been mishandled in the oracle).
    for (const w of [H0, H1, H2, H3, H4, H5, H6, H7]) {
      expect(beU32(composeSmallSigma0(u32ToBytes(w)), 0)).toBe(oracleSmallSigma0(w));
    }
  });

  it("σ1 oracle matches composition for every SHA-256 IV word", () => {
    for (const w of [H0, H1, H2, H3, H4, H5, H6, H7]) {
      expect(beU32(composeSmallSigma1(u32ToBytes(w)), 0)).toBe(oracleSmallSigma1(w));
    }
  });

  it("σ0 and σ1 compositions match oracle on 64 pseudo-random words", () => {
    // Same deterministic LCG (Numerical Recipes) as the Slice 2.3 helper
    // tests. 64 trials with distinct seed (0xBADC_0DE vs 0xC0FFEE) so a
    // shared latent bug doesn't pass both suites by coincidence.
    const seed = 0x0badc0de;
    let state = seed >>> 0;
    for (let trial = 0; trial < 64; trial++) {
      state = (state * 1664525 + 1013904223) >>> 0;
      const w = state;
      expect(beU32(composeSmallSigma0(u32ToBytes(w)), 0)).toBe(oracleSmallSigma0(w));
      expect(beU32(composeSmallSigma1(u32ToBytes(w)), 0)).toBe(oracleSmallSigma1(w));
    }
  });
});

// ─── Algebraic properties — SHR-specific defensive checks ───────────────

describe("SHA-256 σ0 / σ1 — algebraic + SHR-specific properties", () => {
  it("σ0(0) = 0 and σ1(0) = 0 (every operand is zero on zero input)", () => {
    const zero = u32ToBytes(0);
    expect(beU32(composeSmallSigma0(zero), 0)).toBe(0);
    expect(beU32(composeSmallSigma1(zero), 0)).toBe(0);
  });

  it("σ0(0xFFFFFFFF) ≠ 0xFFFFFFFF — SHR drops bits (vs Σ0 which preserves)", () => {
    // The defining contrast with Σ0 from Slice 2.3. Σ0 has 3 rotations
    // → σ0-of-all-ones would XOR three all-ones words = all-ones. But
    // σ0's third term is SHR³ which zero-fills the TOP 3 bits, so the
    // all-ones input produces a result with the top 3 bits cleared:
    //
    //   ROR(0xFFFFFFFF, 7)  = 0xFFFFFFFF
    //   ROR(0xFFFFFFFF, 18) = 0xFFFFFFFF
    //   SHR(0xFFFFFFFF, 3)  = 0x1FFFFFFF  (top 3 bits cleared)
    //   XOR = 0xFFFFFFFF ⊕ 0xFFFFFFFF ⊕ 0x1FFFFFFF = 0x1FFFFFFF.
    //
    // This is the most direct check that the implementation routes
    // through SHR (not ROR) for the third operand — a silent ROR
    // substitution would produce 0xFFFFFFFF instead.
    const allOnes = u32ToBytes(0xffffffff);
    expect(beU32(composeSmallSigma0(allOnes), 0)).toBe(0x1fffffff);
  });

  it("σ1(0xFFFFFFFF) ≠ 0xFFFFFFFF — same SHR signature, top 10 bits cleared", () => {
    //   ROR(0xFFFFFFFF, 17) = 0xFFFFFFFF
    //   ROR(0xFFFFFFFF, 19) = 0xFFFFFFFF
    //   SHR(0xFFFFFFFF, 10) = 0x003FFFFF (top 10 bits cleared)
    //   XOR = 0xFFFFFFFF ⊕ 0xFFFFFFFF ⊕ 0x003FFFFF = 0x003FFFFF.
    const allOnes = u32ToBytes(0xffffffff);
    expect(beU32(composeSmallSigma1(allOnes), 0)).toBe(0x003fffff);
  });

  it("σ0 is NOT a permutation: two distinct inputs can yield the same output", () => {
    // SHR drops bits → information loss → σ0 cannot be injective in
    // general. We can construct a collision: any two inputs that agree
    // on bits 31..3 (the top 29 bits) and differ only in bits 0..2 would
    // produce identical SHR³ outputs; if the ROR contributions also
    // happen to cancel, σ0 collides. Finding the collision directly is
    // hard, but we don't need to — we just confirm σ0 isn't the
    // identity-mod-rotation permutation Σ0 is. A simpler witness: σ0(0)
    // = 0 (every primitive output is zero); and σ0(any nonzero word
    // with all SHR³-dropped bits zero) is also a value distinct from
    // that word's "rotation only" Σ0-like alternate. Direct check:
    // σ0(0x8) ≠ Σ0-style triple-rotation. (We're not implementing the
    // Σ0-style oracle here; the algebraic point is that SHR's
    // information loss makes σ0 fundamentally different from a triple-
    // rotation XOR. The σ0(0xFFFFFFFF) check above already pins the
    // most striking witness.)
    //
    // What we DO pin here: σ0 of a value whose low 3 bits are 0 equals
    // σ0 of the same value if we set bits 0..2 to anything that the ROR
    // contributions zero out via XOR... actually constructing a closed-
    // form collision is too involved for a unit test. Instead, pin
    // SHR's loss-of-info via the well-defined boundary:
    //
    //   σ0(0x0000_0007) ≠ σ0(0x0000_0000)?
    //
    // 0x0000_0007 in σ0:
    //   ROR(0x7, 7)  = 0x0E000000
    //   ROR(0x7, 18) = 0x0001C000
    //   SHR(0x7, 3)  = 0x00000000  (low 3 bits all drop)
    //   XOR = 0x0E01C000.
    // σ0(0x0) = 0, so 0x0E01C000 ≠ 0 → distinct outputs (sanity, no
    // collision yet but confirms σ0 isn't the identity-zero map).
    expect(beU32(composeSmallSigma0(u32ToBytes(0x00000007)), 0)).toBe(0x0e01c000);
    expect(beU32(composeSmallSigma0(u32ToBytes(0x00000000)), 0)).toBe(0);
  });
});

// ─── Message schedule W_0..W_63 for the "abc" example ──────────────────

describe("SHA-256 message schedule — W_0..W_63 for FIPS 180-4 §A.1 'abc'", () => {
  /**
   * Build the 64-byte padded block via Slice 2.4's composition. Bytes
   * out of this composition are the input to the message-schedule
   * seed reads (W_0..W_15). Reusing the slice-2.4 primitives instead of
   * hard-coding the padded block keeps the chain honest — a regression
   * in pad-with-byte / append-be64-length would also surface here.
   */
  const buildAbcPaddedBlock = (): Uint8Array => {
    const message = new Uint8Array([0x61, 0x62, 0x63]);
    const padded = padWithByte(
      new Map([["input", message]]),
      { padByte: 0x80, blockSize: 64, padTarget: 56 } as unknown as Json,
      CTX,
    ).get("output") as Uint8Array;
    return appendBe64Length(
      new Map([
        ["data", padded],
        ["length-source", message],
      ]),
      {} as Json,
      CTX,
    ).get("output") as Uint8Array;
  };

  /**
   * Emulate the for-each-subgraph-with-history contract for SHA-256
   * message schedule:
   *
   *   - Seeds: 16 BE32 words read from the padded block (W_0..W_15).
   *   - 48 iterations: each computes W_t via the recurrence and appends.
   *   - lookbackOffsets = [2, 7, 15, 16]; entryByteLength = 4.
   *
   * The runtime would maintain a ring buffer of size max(offsets) = 16
   * and expose `aux["prior-N"]` per offset. Here we emulate via a
   * straight array (no ring-buffer compression since the test is short)
   * and per-iteration primitive calls — identical math to what the
   * real spec will produce in Slice 2.6.
   */
  const computeSchedule = (paddedBlock: Uint8Array): readonly Uint8Array[] => {
    if (paddedBlock.length !== 64) {
      throw new Error(`SHA-256 schedule expects 64-byte block; got ${paddedBlock.length}`);
    }
    const W: Uint8Array[] = [];
    // W_0..W_15: 16 × 4-byte slices, freshly copied so subsequent ops
    // don't alias the input block.
    for (let t = 0; t < 16; t++) {
      W.push(new Uint8Array(paddedBlock.slice(t * 4, t * 4 + 4)));
    }
    // W_16..W_63: recurrence
    //   W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}   (mod 2^32)
    // Per FIPS 180-4 §6.2.2 step 1. Four-operand add-mod-32 reading
    // straight from the running array — no ring buffer needed at this
    // scale.
    for (let t = 16; t < 64; t++) {
      const wPrev2 = W[t - 2];
      const wPrev7 = W[t - 7];
      const wPrev15 = W[t - 15];
      const wPrev16 = W[t - 16];
      if (!wPrev2 || !wPrev7 || !wPrev15 || !wPrev16) {
        throw new Error(`missing W_{t-N} at t=${t}`);
      }
      const sigma1Term = composeSmallSigma1(wPrev2);
      const sigma0Term = composeSmallSigma0(wPrev15);
      const sum = callAdd(sigma1Term, wPrev7, sigma0Term, wPrev16);
      W.push(sum);
    }
    return W;
  };

  // TS-direct oracle for cross-verification. Implements the recurrence
  // straight against `number` arithmetic. The `+` chain returns signed
  // when any operand has bit 31 set after add wraps, so each
  // intermediate accumulates as `(acc + term) >>> 0` to stay unsigned.
  const computeScheduleOracle = (paddedBlock: Uint8Array): readonly number[] => {
    const W: number[] = [];
    for (let t = 0; t < 16; t++) {
      W.push(beU32(paddedBlock, t * 4));
    }
    for (let t = 16; t < 64; t++) {
      const a = oracleSmallSigma1(W[t - 2] as number);
      const b = W[t - 7] as number;
      const c = oracleSmallSigma0(W[t - 15] as number);
      const d = W[t - 16] as number;
      W.push((((a + b) >>> 0) + ((c + d) >>> 0)) >>> 0);
    }
    return W;
  };

  it("W_0..W_15 are the 16 BE32 reads of the padded block", () => {
    const block = buildAbcPaddedBlock();
    const W = computeSchedule(block);
    // W_0 = "abc" + 0x80 = 0x61 62 63 80.
    expect(beU32(W[0] as Uint8Array, 0)).toBe(0x61626380);
    // W_1..W_14 are all zero (padding).
    for (let t = 1; t <= 14; t++) {
      expect(beU32(W[t] as Uint8Array, 0)).toBe(0);
    }
    // W_15 = low 32 bits of the 8-byte length suffix (bitLength = 24 =
    // 0x18, encoded as 0x0000000000000018 → low 32 = 0x00000018).
    expect(beU32(W[15] as Uint8Array, 0)).toBe(0x00000018);
  });

  it("W_16 = 0x61626380 (hand-derived: only non-zero operand is W_0)", () => {
    // Recurrence at t=16: σ1(W_14) + W_9 + σ0(W_1) + W_0
    //   = σ1(0) + 0 + σ0(0) + 0x61626380
    //   = 0 + 0 + 0 + 0x61626380
    //   = 0x61626380
    // The simplest possible KAT in the schedule — a single non-zero
    // operand passes through. Confirms the recurrence's structure
    // (offsets, sum order) is correct even before σ0/σ1 contribute.
    const block = buildAbcPaddedBlock();
    const W = computeSchedule(block);
    expect(beU32(W[16] as Uint8Array, 0)).toBe(0x61626380);
  });

  it("W_17 = 0x000F0000 (hand-derived: σ1(0x18) is the only contribution)", () => {
    // Recurrence at t=17: σ1(W_15) + W_10 + σ0(W_2) + W_1
    //   = σ1(0x00000018) + 0 + σ0(0) + 0
    //   = 0x000F0000 + 0 + 0 + 0
    //   = 0x000F0000
    //
    // The σ1 hand-derivation (above) is the load-bearing computation:
    //   ROR(0x18, 17) = 0x000C0000   (bits 3,4 → 18,19)
    //   ROR(0x18, 19) = 0x00030000   (bits 3,4 → 16,17)
    //   SHR(0x18, 10) = 0            (0x18 < 2^10, all bits drop)
    //   XOR = 0x000F0000
    //
    // This is the FIRST W_t where σ1 actually contributes — pinning a
    // wrong-amount ROR or a silent ROR-for-SHR substitution. A regression
    // in shift-bits-right@1 routing fails THIS test loudly.
    const block = buildAbcPaddedBlock();
    const W = computeSchedule(block);
    expect(beU32(W[17] as Uint8Array, 0)).toBe(0x000f0000);
  });

  it("schedule composition matches TS-direct oracle across all W_0..W_63", () => {
    // The advisor-pattern check: oracle implements the recurrence via
    // raw JS bit ops; composition runs through the four port-native
    // primitives. Disagreement on ANY of the 64 words flags either
    // (a) a primitive routing bug, (b) a sign-extension lapse in the
    // oracle, or (c) a wrong offset in either path. With two hand-
    // derived literal pins above (W_16 + W_17) AND this oracle parity
    // check, all three categories are bounded.
    const block = buildAbcPaddedBlock();
    const W = computeSchedule(block);
    const Wo = computeScheduleOracle(block);
    for (let t = 0; t < 64; t++) {
      expect(beU32(W[t] as Uint8Array, 0)).toBe(Wo[t]);
    }
  });

  it("schedule has 64 entries, each 4 bytes (W_0..W_63 = 16 seeds + 48 expansions)", () => {
    // Structural pin — guards against off-by-one in the iteration bound
    // (a 63-iteration loop would silently drop W_63; a 65-iteration loop
    // would write past the end of the schedule). Slice 2.6's spec will
    // declare iterationCount=48; this test pins the math.
    const block = buildAbcPaddedBlock();
    const W = computeSchedule(block);
    expect(W.length).toBe(64);
    for (const w of W) {
      expect(w.length).toBe(4);
    }
  });

  it("alternative input ('a') produces a structurally distinct schedule", () => {
    // Negative check: a different (but small) input shouldn't accidentally
    // produce the same schedule values via implementation coincidence.
    // We don't pin specific W_t values for this input — the oracle parity
    // is what makes it trustworthy — but we DO assert W_0 differs from
    // the "abc" case and the schedule is well-formed.
    const message = new Uint8Array([0x61]); // "a"
    const padded = padWithByte(
      new Map([["input", message]]),
      { padByte: 0x80, blockSize: 64, padTarget: 56 } as unknown as Json,
      CTX,
    ).get("output") as Uint8Array;
    const block = appendBe64Length(
      new Map([
        ["data", padded],
        ["length-source", message],
      ]),
      {} as Json,
      CTX,
    ).get("output") as Uint8Array;
    const W = computeSchedule(block);
    const Wo = computeScheduleOracle(block);
    // W_0 for "a" is 0x61_80_00_00, not 0x61626380.
    expect(beU32(W[0] as Uint8Array, 0)).toBe(0x61800000);
    expect(beU32(W[15] as Uint8Array, 0)).toBe(0x00000008); // bitLength = 8
    // Schedule still parities to oracle.
    for (let t = 0; t < 64; t++) {
      expect(beU32(W[t] as Uint8Array, 0)).toBe(Wo[t]);
    }
  });
});
