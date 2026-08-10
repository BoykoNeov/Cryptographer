/**
 * The number-theoretic transform over `R_q = Z_q[X]/(X²⁵⁶+1)` — known-answer
 * tests. ML-KEM P1, `docs/plans/unified-stargazing-quasar.md`.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLES, RANKED — strongest first, and the ranking matters.
 *
 * 1. **Direct CRT evaluation.** FIPS 203 §2.4.4 *defines* the transform as 256
 *    polynomial evaluations, not as a sequence of butterflies:
 *
 *        f̂[2i]   = Σⱼ f[2j]   · γᵢ^j
 *        f̂[2i+1] = Σⱼ f[2j+1] · γᵢ^j        γᵢ = 17^(2·BitRev7(i)+1)
 *
 *    `nttByDefinition` below is that double loop, ~10 lines, sharing no code,
 *    no registry and no `Uint8Array` with the spec. It checks the butterflies
 *    against the *meaning* of the transform rather than against another
 *    butterfly implementation. This is the anchor.
 *
 * 2. **The convolution theorem.** `INTT(NTT(f) ∘ NTT(g))` must equal the
 *    schoolbook product `f·g mod (X²⁵⁶+1)`, computed independently here. Note
 *    that `∘` is NOT element-wise: the transform stops at 128 degree-1
 *    polynomials, so the pointwise product multiplies *pairs* modulo
 *    `X² − γᵢ`. Getting that wrong is the classic first mistake, and it is why
 *    the base-case multiply is written out in this file rather than assumed.
 *
 * 3. **`INTT(NTT(f)) = f`** — ranked LAST, deliberately. A pair of
 *    matched-wrong implementations passes it, exactly as CFB's round-trip test
 *    documents for a mode whose two directions are both wrong in the same way.
 *    It is here to catch a plumbing regression, not to establish correctness.
 *
 * Plus the ζ table, re-derived entry by entry from `17^BitRev7(i) mod 3329`,
 * so a transcription slip in `mlkem-constants.ts` fails here rather than
 * propagating into every downstream phase.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * PERTURBATION. Run, not assumed — the last section breaks four specific
 * things and records how many assertions each takes down. Two of this
 * project's plans record perturbations that turned out to be no-ops for
 * reasons worth knowing, so a perturbation that changes nothing is a finding,
 * not a pass.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  COEFF_BYTES,
  ML_KEM_N,
  ML_KEM_Q,
  NTT_ROOT,
  N_INV_128,
  POLY_BYTES,
  ZETAS,
  packPoly,
  unpackPoly,
} from "@/ciphers/mlkem-constants";
import {
  DEFAULT_NTT_INPUT,
  DEFAULT_NTT_OUTPUT,
  buildInverseNttSpec,
  buildNttGroup,
  buildNttSpec,
  nttLayerId,
} from "@/ciphers/ntt-3329-256";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Independent reference arithmetic ─────────────────────────────────────
//
// Written from the definitions. Shares nothing with the executors under test.

const powMod = (base: number, exp: number, m: number): number => {
  let r = 1;
  let b = base % m;
  let e = exp;
  while (e > 0) {
    if (e & 1) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1;
  }
  return r;
};

/** Reverse the low 7 bits of `i` — FIPS 203's BitRev7. */
const bitRev7 = (i: number): number => {
  let r = 0;
  for (let b = 0; b < 7; b++) r = (r << 1) | ((i >> b) & 1);
  return r;
};

/**
 * The transform BY DEFINITION (FIPS 203 §2.4.4): 128 pairs of polynomial
 * evaluations. Two nested loops, no butterflies, no layers, no twiddle cursor.
 */
const nttByDefinition = (f: readonly number[]): number[] => {
  const out = new Array<number>(ML_KEM_N).fill(0);
  for (let i = 0; i < 128; i++) {
    const gamma = powMod(NTT_ROOT, 2 * bitRev7(i) + 1, ML_KEM_Q);
    let even = 0;
    let odd = 0;
    let g = 1; // gamma^j
    for (let j = 0; j < 128; j++) {
      even = (even + (f[2 * j] as number) * g) % ML_KEM_Q;
      odd = (odd + (f[2 * j + 1] as number) * g) % ML_KEM_Q;
      g = (g * gamma) % ML_KEM_Q;
    }
    out[2 * i] = even;
    out[2 * i + 1] = odd;
  }
  return out;
};

/** Schoolbook multiplication in `Z_q[X]/(X²⁵⁶+1)`. The `X²⁵⁶ = −1` reduction is
 *  the wrap-with-a-sign-flip on the second half. */
const schoolbookMul = (f: readonly number[], g: readonly number[]): number[] => {
  const out = new Array<number>(ML_KEM_N).fill(0);
  for (let i = 0; i < ML_KEM_N; i++) {
    for (let j = 0; j < ML_KEM_N; j++) {
      const k = i + j;
      const term = ((f[i] as number) * (g[j] as number)) % ML_KEM_Q;
      if (k < ML_KEM_N) {
        out[k] = ((out[k] as number) + term) % ML_KEM_Q;
      } else {
        out[k - ML_KEM_N] = ((out[k - ML_KEM_N] as number) - term + ML_KEM_Q * ML_KEM_Q) % ML_KEM_Q;
      }
    }
  }
  return out;
};

/**
 * The pointwise product in the transformed domain — NOT element-wise.
 *
 * The transform leaves 128 degree-1 polynomials, the i-th living modulo
 * `X² − γᵢ`. So `(a₀ + a₁X)(b₀ + b₁X) mod (X² − γᵢ)` is
 * `(a₀b₀ + a₁b₁γᵢ) + (a₀b₁ + a₁b₀)X`. Writing this out is the whole reason the
 * convolution test is a real check rather than a tautology.
 */
const baseCaseMul = (a: readonly number[], b: readonly number[]): number[] => {
  const out = new Array<number>(ML_KEM_N).fill(0);
  for (let i = 0; i < 128; i++) {
    const gamma = powMod(NTT_ROOT, 2 * bitRev7(i) + 1, ML_KEM_Q);
    const a0 = a[2 * i] as number;
    const a1 = a[2 * i + 1] as number;
    const b0 = b[2 * i] as number;
    const b1 = b[2 * i + 1] as number;
    out[2 * i] = (a0 * b0 + ((a1 * b1) % ML_KEM_Q) * gamma) % ML_KEM_Q;
    out[2 * i + 1] = (a0 * b1 + a1 * b0) % ML_KEM_Q;
  }
  return out;
};

// ─── Runtime harness ──────────────────────────────────────────────────────

const registry = buildDefaultRegistry();

const runPoly = (spec: CipherSpec, coeffs: readonly number[]): number[] => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: packPoly(coeffs) },
    // The transform is keyless; the spec declares `key.byteLength: 0`.
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return unpackPoly(trace.finalState.bytes);
};

const forward = (coeffs: readonly number[]): number[] => runPoly(buildNttSpec(), coeffs);
const inverse = (coeffs: readonly number[]): number[] => runPoly(buildInverseNttSpec(), coeffs);

/** Deterministic coefficient fills, so failures are reproducible. */
const sample = (seed: number): number[] => {
  const out: number[] = [];
  let x = seed;
  for (let i = 0; i < ML_KEM_N; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out.push(x % ML_KEM_Q);
  }
  return out;
};

const SAMPLES: readonly (readonly number[])[] = [
  // Every coefficient zero — the transform of 0 is 0, and a spec that dropped a
  // layer would still pass this one. Included as a floor, not as evidence.
  new Array<number>(ML_KEM_N).fill(0),
  // The constant polynomial 1. Its transform is all-ones, which is the single
  // easiest result to check by hand.
  [1, ...new Array<number>(ML_KEM_N - 1).fill(0)],
  // X alone — isolates the twiddle factors: f̂[2i] = 0, f̂[2i+1] = 1.
  [0, 1, ...new Array<number>(ML_KEM_N - 2).fill(0)],
  // The app's default (0, 1, 2, …, 255).
  unpackPoly(DEFAULT_NTT_INPUT),
  // Every coefficient at the top of the range, so every add and multiply wraps.
  new Array<number>(ML_KEM_N).fill(ML_KEM_Q - 1),
  sample(1),
  sample(4242),
];

// ─── 0. The published table ───────────────────────────────────────────────

describe("the ζ table (FIPS 203 Appendix A)", () => {
  it("every entry is 17^BitRev7(i) mod 3329", () => {
    expect(ZETAS.length).toBe(128);
    for (let i = 0; i < 128; i++) {
      expect(ZETAS[i], `ZETAS[${i}]`).toBe(powMod(NTT_ROOT, bitRev7(i), ML_KEM_Q));
    }
  });

  it("opens and closes on the published values", () => {
    // Quoted from the standard, not recomputed — so a bug in `bitRev7` above
    // cannot make the previous test pass vacuously.
    expect(ZETAS.slice(0, 8)).toEqual([1, 1729, 2580, 3289, 2642, 630, 1897, 848]);
    expect(ZETAS.slice(124)).toEqual([2110, 2935, 885, 2154]);
  });

  it("17 is a primitive 256th root of unity: 17^128 ≡ −1, 17^256 ≡ 1", () => {
    expect(powMod(NTT_ROOT, 128, ML_KEM_Q)).toBe(ML_KEM_Q - 1);
    expect(powMod(NTT_ROOT, 256, ML_KEM_Q)).toBe(1);
  });

  it("the final scaling is 128⁻¹ = 3303, and 256⁻¹ = 3316 is a different number", () => {
    // The single easiest constant in the transform to get wrong: there are 256
    // coefficients but only SEVEN layers, because q − 1 = 2⁸·13 admits no
    // primitive 512th root, so the accumulated factor is 2⁷.
    expect((128 * N_INV_128) % ML_KEM_Q).toBe(1);
    expect(N_INV_128).toBe(3303);
    expect(powMod(256, ML_KEM_Q - 2, ML_KEM_Q)).toBe(3316);
    expect(N_INV_128).not.toBe(3316);
  });
});

// ─── 1. The anchor: direct CRT evaluation ─────────────────────────────────

describe("forward NTT vs the transform's DEFINITION (rank 1 oracle)", () => {
  for (const [n, f] of SAMPLES.entries()) {
    it(`sample ${n}: the seven layers of butterflies reproduce the 128 pairs of evaluations`, () => {
      expect(forward(f)).toEqual(nttByDefinition(f));
    });
  }

  it("the constant polynomial 1 transforms to 1, 0, 1, 0, … — not to all ones", () => {
    // Worth pinning precisely because the obvious guess is wrong, and getting
    // it wrong is a sign of misreading what this transform is.
    //
    // "Every evaluation of the constant 1 is 1, so the answer is all ones"
    // would hold for a plain 256-point evaluation. This is not one. Because
    // there is no primitive 512th root of unity mod 3329, the transform stops
    // at 128 DEGREE-1 polynomials, and it is really two independent 128-point
    // transforms interleaved: the even outputs come from the even coefficients,
    // the odd outputs from the odd ones.
    //
    // The constant polynomial has f[0] = 1 and every odd coefficient zero, so
    // the even half transforms to all ones and the odd half to all zeros.
    const f = [1, ...new Array<number>(ML_KEM_N - 1).fill(0)];
    const expected = Array.from({ length: ML_KEM_N }, (_, i) => (i % 2 === 0 ? 1 : 0));
    expect(forward(f)).toEqual(expected);
  });
});

// ─── 2. The convolution theorem ───────────────────────────────────────────

describe("the convolution theorem (rank 2 oracle)", () => {
  const pairs: readonly (readonly [readonly number[], readonly number[]])[] = [
    [sample(7), sample(11)],
    [unpackPoly(DEFAULT_NTT_INPUT), sample(99)],
    // X · X^255 = X^256 = −1 — the ring's defining relation, checked end to end.
    [
      [0, 1, ...new Array<number>(ML_KEM_N - 2).fill(0)],
      [...new Array<number>(ML_KEM_N - 1).fill(0), 1],
    ],
  ];

  for (const [n, [f, g]] of pairs.entries()) {
    it(`pair ${n}: INTT(NTT(f) ∘ NTT(g)) equals the schoolbook product`, () => {
      const product = inverse(baseCaseMul(forward(f), forward(g)));
      expect(product).toEqual(schoolbookMul(f, g));
    });
  }

  it("X · X^255 = −1 in this ring", () => {
    const x = [0, 1, ...new Array<number>(ML_KEM_N - 2).fill(0)];
    const x255 = [...new Array<number>(ML_KEM_N - 1).fill(0), 1];
    const expected = [ML_KEM_Q - 1, ...new Array<number>(ML_KEM_N - 1).fill(0)];
    expect(inverse(baseCaseMul(forward(x), forward(x255)))).toEqual(expected);
  });
});

// ─── 3. Round trip (rank 3 — the weak one) ────────────────────────────────

describe("INTT(NTT(f)) = f (rank 3 — weakest oracle, listed last on purpose)", () => {
  for (const [n, f] of SAMPLES.entries()) {
    it(`sample ${n} survives the round trip`, () => {
      expect(inverse(forward(f))).toEqual([...f]);
    });
  }
});

// ─── 4. Structure ─────────────────────────────────────────────────────────

describe("spec structure", () => {
  it("both directions are seven layers over 127 butterfly groups", () => {
    for (const spec of [buildNttSpec(), buildInverseNttSpec()]) {
      const layers = spec.steps.filter(
        (s): s is Extract<StepNode, { kind: "iterate" }> => s.kind === "iterate",
      );
      expect(layers.length).toBe(7);
      const groups = layers.reduce(
        (total, l) => total + POLY_BYTES / (l.blockByteLength as number),
        0,
      );
      expect(groups).toBe(127);
    }
  });

  it("the forward layers narrow 512 → 8 bytes and the inverse widens 8 → 512", () => {
    const widths = (spec: CipherSpec): number[] =>
      spec.steps
        .filter((s): s is Extract<StepNode, { kind: "iterate" }> => s.kind === "iterate")
        .map((l) => l.blockByteLength as number);
    expect(widths(buildNttSpec())).toEqual([512, 256, 128, 64, 32, 16, 8]);
    expect(widths(buildInverseNttSpec())).toEqual([8, 16, 32, 64, 128, 256, 512]);
  });

  it("every layer's node ids key on its DISPLAY index, not its pairing distance", () => {
    // The inverse runs the layers in the opposite order; deriving ids from the
    // mirrored index produced a spec whose layer-1 iterate held layer-7's
    // children. The type checker cannot see that.
    for (const spec of [buildNttSpec(), buildInverseNttSpec()]) {
      spec.steps
        .filter((s): s is Extract<StepNode, { kind: "iterate" }> => s.kind === "iterate")
        .forEach((l, i) => {
          expect(l.id).toBe(nttLayerId(i + 1));
          for (const child of l.children) {
            expect(child.id.startsWith(`${nttLayerId(i + 1)}.`)).toBe(true);
          }
        });
    }
  });

  it("the ζ cursor is 256 bytes at every block width — the novel wiring", () => {
    // No shipped iterate before this one carried a chain whose width differs
    // from its block width (CBC's IV, CTR's counter and SHA-256's running H are
    // all block-wide). Pinned so a future runtime length check surfaces here.
    const trace = runSpec(buildNttSpec(), registry, {
      initialState: { shape: "bytes", bytes: DEFAULT_NTT_INPUT },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    const zetaReads = trace.frames.filter((f) => f.stepId.includes(".zeta"));
    expect(zetaReads.length).toBe(127);
    for (const f of zetaReads) {
      expect(f.portInputs?.get("input")?.length).toBe(256);
    }
  });

  it("the forward run consumes ζ¹ … ζ¹²⁷ in order, and the inverse ζ¹²⁷ … ζ¹", () => {
    const consumed = (spec: CipherSpec, outPort: string): number[] => {
      const trace = runSpec(spec, registry, {
        initialState: { shape: "bytes", bytes: DEFAULT_NTT_INPUT },
        initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
      });
      return trace.frames
        .filter((f) => f.stepId.includes(".zeta"))
        .map((f) => {
          const z = f.portOutputs?.get(outPort);
          if (z === undefined) throw new Error(`no ${outPort} on ${f.stepId}`);
          return (z[0] as number) * 256 + (z[1] as number);
        });
    };
    // Forward reads the front of the table; the inverse reads the back.
    expect(consumed(buildNttSpec(), "output0")).toEqual(ZETAS.slice(1));
    expect(consumed(buildInverseNttSpec(), "output1")).toEqual([...ZETAS.slice(1)].reverse());
  });

  it("DEFAULT_NTT_OUTPUT is the real forward transform of DEFAULT_NTT_INPUT", () => {
    // The shipped inverse-direction default. Its bytes were derived from FIPS
    // 203's DEFINITION rather than from the spec, so pinning them against a
    // real run of the spec is a genuine cross-check — and it stops the app's
    // "flip to inverse and get your polynomial back" promise from rotting if
    // the builder ever changes.
    expect(unpackPoly(DEFAULT_NTT_OUTPUT)).toEqual(forward(unpackPoly(DEFAULT_NTT_INPUT)));
    expect(inverse(unpackPoly(DEFAULT_NTT_OUTPUT))).toEqual(unpackPoly(DEFAULT_NTT_INPUT));
  });

  it("the input is one polynomial: 256 coefficients × 2 bytes", () => {
    expect(POLY_BYTES).toBe(ML_KEM_N * COEFF_BYTES);
    expect(DEFAULT_NTT_INPUT.length).toBe(POLY_BYTES);
    // A wrong-width input is a loud failure, not a silently truncated run.
    expect(() =>
      runSpec(buildNttSpec(), registry, {
        initialState: { shape: "bytes", bytes: new Uint8Array(500) },
        initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
      }),
    ).toThrow(/not a multiple of blockByteLength/);
  });
});

// ─── 5. Perturbation ──────────────────────────────────────────────────────
//
// Each case breaks ONE thing and asserts the tests above would have caught it.
// Run, not assumed.

describe("perturbation — each of these must break something", () => {
  const clone = (spec: CipherSpec): CipherSpec => structuredClone(spec) as CipherSpec;
  const f = sample(31337);

  it("breaking a single ζ changes the forward transform", () => {
    const spec = clone(buildNttSpec());
    const zeta = spec.cipherConstants?.zeta;
    if (zeta === undefined) throw new Error("expected a zeta constant");
    // ZETAS[1] = 1729 → 1730. One entry, of 128, used by exactly one group.
    zeta[3] = (zeta[3] as number) + 1;
    expect(runPoly(spec, f)).not.toEqual(nttByDefinition(f));
  });

  it("scaling the inverse by 256⁻¹ instead of 128⁻¹ breaks the round trip", () => {
    const spec = clone(buildInverseNttSpec());
    const ninv = spec.cipherConstants?.ninv;
    if (ninv === undefined) throw new Error("expected an ninv constant");
    // 3316 = 256⁻¹ mod 3329. Every coefficient comes out exactly halved.
    ninv[0] = 0x0c;
    ninv[1] = 0xf4;
    const wrong = runPoly(spec, forward(f));
    expect(wrong).not.toEqual([...f]);
    // And the error is precisely a factor of two, which is what makes it such a
    // plausible-looking wrong answer.
    expect(wrong.map((c) => (c * 2) % ML_KEM_Q)).toEqual([...f]);
  });

  it("swapping the forward butterfly's add and subtract changes the result", () => {
    const spec = clone(buildNttSpec());
    const layer1 = spec.steps.find((s) => s.id === nttLayerId(1));
    if (layer1 === undefined || layer1.kind !== "iterate") throw new Error("no layer 1");
    const children = layer1.children as StepNode[];
    const lo = children.findIndex((c) => c.id.endsWith(".lo"));
    const hi = children.findIndex((c) => c.id.endsWith(".hi"));
    expect(lo).toBeGreaterThanOrEqual(0);
    expect(hi).toBeGreaterThanOrEqual(0);
    // Swap the two step TYPES, leaving every wire intact — so layer 1 computes
    // (lo − t, lo + t) instead of (lo + t, lo − t).
    const loNode = children[lo] as Extract<StepNode, { kind: "step" }>;
    const hiNode = children[hi] as Extract<StepNode, { kind: "step" }>;
    children[lo] = { ...loNode, type: "zq-vec-sub@1" };
    children[hi] = { ...hiNode, type: "zq-vec-add@1" };
    expect(runPoly(spec, f)).not.toEqual(nttByDefinition(f));
  });

  it("flipping the coefficient byte order changes the result", () => {
    const spec = clone(buildNttSpec());
    const flip = (nodes: StepNode[]): void => {
      for (const n of nodes) {
        if (n.kind === "step" && n.type.startsWith("zq-vec-")) {
          (n.params as Record<string, unknown>).littleEndian = true;
        }
        if (n.kind !== "step") flip(n.children as StepNode[]);
      }
    };
    flip(spec.steps as StepNode[]);
    expect(runPoly(spec, f)).not.toEqual(nttByDefinition(f));
  });

  it("removing a layer changes the result (the seven-vs-eight trap, in reverse)", () => {
    const spec = clone(buildNttSpec());
    // Drop layer 7 and rewire the output to layer 6. A transform one layer
    // short is the shape a "just add another layer" instinct would produce in
    // the other direction; either way, the layer count is not free.
    const kept = (spec.steps as StepNode[]).filter((s) => s.id !== nttLayerId(7));
    const shortened: CipherSpec = {
      ...spec,
      steps: kept,
      outputFrom: { node: nttLayerId(6), port: "out" },
    };
    expect(runPoly(shortened, f)).not.toEqual(nttByDefinition(f));
  });
});

// ─── The P3 extraction, guarded ───────────────────────────────────────────

/**
 * P3 pulled the layer-building out of the two spec builders into
 * `buildNttNodes`, so K-PKE can embed the same transform six times over
 * instead of growing a second implementation of it.
 *
 * These digests were captured from the shipped specs **before** that
 * extraction. The ordering is the entire point — a digest taken afterwards
 * pins the new bytes to themselves and guards nothing (the ChaCha20-CSPRNG
 * precedent, `tests/chacha20-csprng-kat.test.ts`).
 *
 * Why it deserves a test at all: spec-only saves are byte-stable and feed the
 * `#doc=` URL-share hash, so a one-byte drift here silently repoints every NTT
 * link anyone has ever shared while every behavioural test above stays green.
 */
describe("the P3 layer extraction left both shipped specs byte-identical", () => {
  const PRE_REFACTOR_FORWARD = "1373944691ae035483180dbac7a774814fece00c1f2af70e72bcf039147d8fe7";
  const PRE_REFACTOR_INVERSE = "e0117545ff9e08f92985fc690d945497ca2b446c3270b54edae18ec8a88cf7e8";

  const digest = (spec: CipherSpec): string =>
    createHash("sha256").update(JSON.stringify(spec)).digest("hex");

  it("leaves the forward spec byte-identical", () => {
    expect(digest(buildNttSpec())).toBe(PRE_REFACTOR_FORWARD);
  });

  it("leaves the inverse spec byte-identical", () => {
    expect(digest(buildInverseNttSpec())).toBe(PRE_REFACTOR_INVERSE);
  });
});

/**
 * The property the extraction exists to provide, and the one that breaks
 * silently if it is missing.
 *
 * The flat trace keys every frame by `stepId`. Two transforms in one spec whose
 * nodes are both called `layer1.split` do not throw — they produce a trace with
 * duplicate keys, which takes out the scrubber, frame preservation and the
 * graph derivation without a single error message. So the prefix is not a
 * cosmetic namespacing choice, and it is asserted rather than trusted.
 */
describe("embedded transforms carry globally distinct node ids", () => {
  const idsIn = (nodes: readonly StepNode[]): string[] =>
    nodes.flatMap((n) => [n.id, ...(n.kind === "step" ? [] : idsIn(n.children))]);

  it("gives two embedded groups disjoint id sets", () => {
    const first = buildNttGroup({
      id: "ntt.s0",
      label: "NTT(s₀)",
      direction: "forward",
      seedBinding: { node: "somewhere", port: "output" },
    });
    const second = buildNttGroup({
      id: "ntt.s1",
      label: "NTT(s₁)",
      direction: "forward",
      seedBinding: { node: "somewhere", port: "output" },
    });
    const all = [...idsIn([first]), ...idsIn([second])];
    expect(new Set(all).size).toBe(all.length);
  });

  it("prefixes every id, not merely the layer iterates", () => {
    // The layer ids were always built through a helper; the head nodes
    // (`zeta-table`, `cursor`) and the inverse's `scale` tail were literals,
    // which is exactly where a prefix is easy to forget.
    const group = buildNttGroup({
      id: "ntt.u",
      label: "NTT⁻¹(u)",
      direction: "inverse",
      seedBinding: { node: "somewhere", port: "output" },
    });
    const inner = idsIn(group.children);
    expect(inner.length).toBeGreaterThan(0);
    expect(inner.every((id) => id.startsWith("ntt.u."))).toBe(true);
  });
});
