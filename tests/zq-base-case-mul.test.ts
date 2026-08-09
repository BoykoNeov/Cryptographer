/**
 * `zq-base-case-mul@1` — FIPS 203 Algorithm 12 (`BaseCaseMultiply`), and
 * Algorithm 11 (`MultiplyNTTs`) when applied to all 128 pairs at once.
 * ML-KEM P2, `docs/plans/unified-stargazing-quasar.md`.
 *
 * This is the step P2's plan called "pointwise multiplication", and the name is
 * the trap: multiplying two transformed polynomials element by element is what
 * every other transform buys you and it is **wrong here**, because this
 * transform stops at 128 degree-1 polynomials rather than 256 constants. That
 * mistake is asserted against directly rather than merely avoided.
 *
 * ## The oracles, in the order they prove things
 *
 *  1. **The γ table against FIPS 203 Appendix A, two independent ways.** Every
 *     entry re-derived from `17^(2·BitRev7(i)+1)` — the exponent the plan's own
 *     prose loses the `+ 1` from — and then the ± pairing relation
 *     `γ[2i] = ZETAS[64+i]`, `γ[2i+1] = q − ZETAS[64+i]`, which makes the upper
 *     half of the *published* ζ table a second check on this one.
 *  2. **The convolution theorem, end to end through the SHIPPED specs.**
 *     `INTT(NTT(f) ⊛ NTT(g))` must equal the schoolbook product
 *     `f·g mod (X²⁵⁶+1)`, computed here from the definition. This is the strong
 *     one, and it is what closes P2: it checks the step against something that
 *     is not the step.
 *
 *     `tests/ntt-3329-256-kat.test.ts` runs the same theorem against its OWN
 *     inline base-case multiply, and that inline version stays exactly where it
 *     is. Replacing it with a call to this step would delete P1's oracle and
 *     turn its convolution test into a tautology — all green, checking nothing.
 *     Two files, two independent implementations, on purpose.
 *  3. **The degree-1 algebra**, spot-checked by hand: in `Z_q[X]/(X²−γ)`,
 *     `X · X = γ`.
 *  4. **Wiring**, including the `k = 1` / `k = 128` polymorphism that lets the
 *     same executor serve P3's per-pair loop and the whole-polynomial form.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  GAMMAS,
  GAMMA_TABLE_BYTES,
  ML_KEM_N,
  ML_KEM_Q,
  NTT_ROOT,
  Q_BYTES,
  ZETAS,
  packPoly,
  unpackPoly,
} from "@/ciphers/mlkem-constants";
import { buildInverseNttSpec, buildNttSpec } from "@/ciphers/ntt-3329-256";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, Json, StepContext } from "@/core/types";
import { zqBaseCaseMul } from "@/steps/zq-base-case-mul";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
const BE: Json = { coeffBytes: 2, littleEndian: false };
const registry = buildDefaultRegistry();

/** `base^exp mod m`, written here so the γ derivation shares nothing with src. */
const powMod = (base: number, exp: number, m: number): number => {
  let r = 1;
  let b = base % m;
  let e = exp;
  while (e > 0) {
    if (e % 2 === 1) r = (r * b) % m;
    b = (b * b) % m;
    e = Math.floor(e / 2);
  }
  return r;
};

/** Reverse the low seven bits of `i`. */
const bitRev7 = (i: number): number => {
  let r = 0;
  for (let b = 0; b < 7; b++) if ((i & (1 << b)) !== 0) r |= 1 << (6 - b);
  return r;
};

const runMul = (a: readonly number[], b: readonly number[], gamma: readonly number[]): number[] =>
  unpackPoly(
    zqBaseCaseMul(
      new Map([
        ["a", packPoly(a)],
        ["b", packPoly(b)],
        ["gamma", packPoly(gamma)],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output") as Uint8Array,
  );

/** All 128 pairs at once — `MultiplyNTTs`. */
const runMulAll = (a: readonly number[], b: readonly number[]): number[] =>
  unpackPoly(
    zqBaseCaseMul(
      new Map([
        ["a", packPoly(a)],
        ["b", packPoly(b)],
        ["gamma", GAMMA_TABLE_BYTES],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output") as Uint8Array,
  );

// ─── The shipped NTT specs ────────────────────────────────────────────────

const runPoly = (spec: CipherSpec, coeffs: readonly number[]): number[] => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: packPoly(coeffs) },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return unpackPoly(trace.finalState.bytes);
};
const forward = (c: readonly number[]): number[] => runPoly(buildNttSpec(), c);
const inverse = (c: readonly number[]): number[] => runPoly(buildInverseNttSpec(), c);

/**
 * `f·g mod (X²⁵⁶ + 1)` the long way. `X²⁵⁶ = −1`, so anything that overflows the
 * degree bound comes back with its sign flipped. Shares no code with anything
 * under test.
 */
const schoolbookMul = (f: readonly number[], g: readonly number[]): number[] => {
  const out = new Array<number>(ML_KEM_N).fill(0);
  for (let i = 0; i < ML_KEM_N; i++) {
    for (let j = 0; j < ML_KEM_N; j++) {
      const term = ((f[i] as number) * (g[j] as number)) % ML_KEM_Q;
      const k = i + j;
      if (k < ML_KEM_N) out[k] = ((out[k] as number) + term) % ML_KEM_Q;
      else out[k - ML_KEM_N] = ((out[k - ML_KEM_N] as number) - term + ML_KEM_Q) % ML_KEM_Q;
    }
  }
  return out;
};

/** The mistake this step exists to prevent: element-wise multiplication. */
const elementWiseMul = (a: readonly number[], b: readonly number[]): number[] =>
  a.map((x, i) => (x * (b[i] as number)) % ML_KEM_Q);

const sample = (seed: number): number[] => {
  const out: number[] = [];
  let x = seed;
  for (let i = 0; i < ML_KEM_N; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out.push(x % ML_KEM_Q);
  }
  return out;
};

// ─── 1. The γ table ───────────────────────────────────────────────────────

describe("the γ table — FIPS 203 Algorithm 11's per-pair modulus", () => {
  it("every entry is 17^(2·BitRev7(i) + 1) mod 3329 — note the +1", () => {
    // The plan describes these as "the 128 ζ² base-case values", which drops the
    // +1 and gives 1, 3328, 1729, 1600, … instead of 17, 3312, 2761, 568, …
    expect(GAMMAS.length).toBe(128);
    for (let i = 0; i < 128; i++) {
      expect({ i, g: GAMMAS[i] }).toEqual({
        i,
        g: powMod(NTT_ROOT, 2 * bitRev7(i) + 1, ML_KEM_Q),
      });
    }
    expect(GAMMAS.slice(0, 8)).toEqual([17, 3312, 2761, 568, 583, 2746, 2649, 680]);
    // And the wrong reading, so it cannot quietly become the right one.
    expect(GAMMAS.slice(0, 4)).not.toEqual(ZETAS.slice(0, 4).map((z) => (z * z) % ML_KEM_Q));
  });

  it("is the upper half of the published ζ table, alternately negated", () => {
    // γ[2i] = ZETAS[64+i] and γ[2i+1] = q − ZETAS[64+i]. A SECOND independent
    // check against FIPS 203 Appendix A: a transcription slip in either table
    // breaks this relation.
    for (let i = 0; i < 64; i++) {
      expect({ i, even: GAMMAS[2 * i], odd: GAMMAS[2 * i + 1] }).toEqual({
        i,
        even: ZETAS[64 + i],
        odd: ML_KEM_Q - (ZETAS[64 + i] as number),
      });
    }
  });

  it("consecutive pairs really are negatives of each other", () => {
    for (let i = 0; i < 64; i++) {
      expect(((GAMMAS[2 * i] as number) + (GAMMAS[2 * i + 1] as number)) % ML_KEM_Q).toBe(0);
    }
  });
});

// ─── 2. The convolution theorem, through the shipped specs ────────────────

describe("the convolution theorem — the oracle that closes P2", () => {
  const PAIRS: readonly (readonly [readonly number[], readonly number[]])[] = [
    // The constant 1 is the multiplicative identity — the easiest case to be
    // wrong about while looking right.
    [[1, ...new Array<number>(ML_KEM_N - 1).fill(0)], sample(7)],
    // X · X^254 = X^255, which does NOT wrap. Its neighbour below does.
    [
      [0, 1, ...new Array<number>(ML_KEM_N - 2).fill(0)],
      [...new Array<number>(ML_KEM_N - 2).fill(0), 1, 0],
    ],
    [sample(1), sample(2)],
    [sample(31337), sample(4242)],
    // Everything at the top of the range, so every product and sum wraps.
    [
      new Array<number>(ML_KEM_N).fill(ML_KEM_Q - 1),
      new Array<number>(ML_KEM_N).fill(ML_KEM_Q - 1),
    ],
  ];

  PAIRS.forEach(([f, g], n) => {
    it(`pair ${n}: INTT(NTT(f) ⊛ NTT(g)) equals the schoolbook product`, () => {
      expect(inverse(runMulAll(forward(f), forward(g)))).toEqual(schoolbookMul(f, g));
    });
  });

  it("element-wise multiplication gives a DIFFERENT and wrong answer", () => {
    // The assertion the plan's "pointwise" wording makes necessary. If this ever
    // goes green, the step has become element-wise.
    const [f, g] = [sample(1), sample(2)];
    const wrong = inverse(elementWiseMul(forward(f), forward(g)));
    expect(wrong).not.toEqual(schoolbookMul(f, g));
  });

  it("a single shared γ instead of one per pair also gives a wrong answer", () => {
    // The second plausible mistake: right shape, wrong table. Every pair
    // multiplies in its own ring.
    const [f, g] = [sample(1), sample(2)];
    const sharedGamma = new Array<number>(128).fill(GAMMAS[0] as number);
    const wrong = inverse(runMul(forward(f), forward(g), sharedGamma));
    expect(wrong).not.toEqual(schoolbookMul(f, g));
  });

  it("X · X²⁵⁵ = −1, so the wrap-around sign is right", () => {
    const x = [0, 1, ...new Array<number>(ML_KEM_N - 2).fill(0)];
    const x255 = [...new Array<number>(ML_KEM_N - 1).fill(0), 1];
    const expected = [ML_KEM_Q - 1, ...new Array<number>(ML_KEM_N - 1).fill(0)];
    expect(inverse(runMulAll(forward(x), forward(x255)))).toEqual(expected);
  });
});

// ─── 3. The degree-1 algebra, by hand ─────────────────────────────────────

describe("one pair at a time — multiplication in Z_q[X]/(X² − γ)", () => {
  it("computes (a₀ + a₁X)(b₀ + b₁X) with X² folded to γ", () => {
    // (2 + 3X)(5 + 7X) = 10 + 29X + 21X², and X² = 11, so 10 + 231 = 241 and 29X.
    expect(runMul([2, 3], [5, 7], [11])).toEqual([241, 29]);
  });

  it("X · X = γ — the defining relation of the little ring", () => {
    for (const g of [1, 17, 3312, ML_KEM_Q - 1]) {
      expect(runMul([0, 1], [0, 1], [g])).toEqual([g % ML_KEM_Q, 0]);
    }
  });

  it("1 is the identity", () => {
    expect(runMul([1, 0], [1234, 2345], [17])).toEqual([1234, 2345]);
  });

  it("reduces the a₁b₁γ term at full precision", () => {
    // a₁·b₁·γ with all three near q reaches ~3.7 × 10¹⁰ — far past what a
    // 2-byte element holds. Reducing the operands first and letting the product
    // wrap is a different, wrong function.
    const q = ML_KEM_Q;
    const [a1, b1, g] = [q - 1, q - 1, q - 1];
    const expected = (((a1 * b1) % q) * g) % q;
    expect(runMul([0, a1], [0, b1], [g])).toEqual([expected, 0]);
  });
});

// ─── 4. Wiring ────────────────────────────────────────────────────────────

describe("wiring and loud failures", () => {
  it("is registered under its bare name", () => {
    expect(registry.has("zq-base-case-mul@1")).toBe(true);
    expect(registry.getDoc("zq-base-case-mul@1")).toBeDefined();
  });

  it("is polymorphic over k: 128 pairs at once equals 128 single-pair calls", () => {
    // The property that lets P3 drop this same executor inside an iterate with
    // γ arriving one at a time, instead of needing a second step type.
    const [a, b] = [sample(11), sample(22)];
    const bulk = runMulAll(a, b);
    const oneAtATime: number[] = [];
    for (let i = 0; i < 128; i++) {
      oneAtATime.push(
        ...runMul(
          [a[2 * i] as number, a[2 * i + 1] as number],
          [b[2 * i] as number, b[2 * i + 1] as number],
          [GAMMAS[i] as number],
        ),
      );
    }
    expect(oneAtATime).toEqual(bulk);
  });

  it("throws on an odd coefficient count — pairs are the whole point", () => {
    expect(() => runMul([1, 2, 3], [1, 2, 3], [1, 2])).toThrow(/whole number of PAIRS/);
  });

  it("throws when γ does not have one entry per pair", () => {
    expect(() => runMul([1, 2, 3, 4], [1, 2, 3, 4], [1])).toThrow(/its own γ/);
    expect(() => runMul([1, 2, 3, 4], [1, 2, 3, 4], [1, 2, 3])).toThrow(/its own γ/);
  });

  it("throws on mismatched operand lengths and a missing modulus", () => {
    expect(() => runMul([1, 2, 3, 4], [1, 2], [1, 2])).toThrow(/same length/);
    expect(() =>
      zqBaseCaseMul(
        new Map([
          ["a", packPoly([1, 2])],
          ["b", packPoly([1, 2])],
          ["gamma", packPoly([1])],
        ]),
        BE,
        ctx,
      ),
    ).toThrow(/modulus/);
  });
});
