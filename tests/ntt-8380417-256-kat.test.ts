/**
 * The number-theoretic transform over `Z_8380417[X]/(X²⁵⁶+1)` — ML-DSA's
 * transform — known-answer tests. `docs/plans/refactored-petting-tide.md`, P1.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLES, RANKED — strongest first.
 *
 * 1. **Direct evaluation.** FIPS 204 §2.5 defines the transform as the 256
 *    evaluations `f̂[j] = f(ζ^(2·BitRev8(j)+1))` at the primitive 512th roots of
 *    unity. `nttByDefinition` is that double loop, sharing nothing with the
 *    butterflies. Unlike ML-KEM's (`ntt-3329-256-kat.test.ts`), these are
 *    evaluations at single points — there is no pairing, because this prime
 *    allows the eighth layer.
 *
 * 2. **The convolution theorem with an ELEMENT-WISE product.**
 *    `INTT(NTT(f) · NTT(g))` (coefficient by coefficient) must equal the
 *    schoolbook product. This is the line where the two transforms disagree on
 *    purpose: the same element-wise product is WRONG for ML-KEM, and the
 *    contrast test below runs it there and shows it fails.
 *
 * 3. **The published ζ table**, re-derived entry by entry, with the first
 *    entries quoted from FIPS 204 Appendix B rather than recomputed.
 *
 * 4. **`INTT(NTT(f)) = f`** — LAST: matched-wrong implementations pass it.
 *
 * Products here reach ~7·10¹³ — 46 bits, inside a double's exact range — so the
 * reference arithmetic reduces after every product and stays in `number`.
 *
 * PERTURBATION, run not assumed: the final section breaks the scaling constant,
 * one ζ, the table order and the layer count, and asserts each is caught.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_COEFF_BYTES,
  ML_DSA_N,
  ML_DSA_NTT_ROOT,
  ML_DSA_N_INV_256,
  ML_DSA_POLY_BYTES,
  ML_DSA_Q,
  ML_DSA_ZETAS,
  ML_DSA_ZETA_TABLE_BYTES,
  mlDsaCoeffBytes,
  packMlDsaPoly,
  unpackMlDsaPoly,
} from "@/ciphers/mldsa-constants";
import { packPoly, unpackPoly } from "@/ciphers/mlkem-constants";
import { buildInverseNttSpec, buildNttSpec, nttLayerId } from "@/ciphers/ntt-3329-256";
import {
  DEFAULT_ML_DSA_NTT_INPUT,
  DEFAULT_ML_DSA_NTT_OUTPUT,
  buildMlDsaInverseNttSpec,
  buildMlDsaNttSpec,
} from "@/ciphers/ntt-8380417-256";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, StepNode } from "@/core/types";
import { describe, expect, it } from "vitest";

const Q = ML_DSA_Q;
const N = ML_DSA_N;

// ─── Independent reference arithmetic ─────────────────────────────────────

const mulMod = (a: number, b: number): number => (a * b) % Q;

const powMod = (base: number, exp: number): number => {
  let r = 1;
  let b = base % Q;
  let e = exp;
  while (e > 0) {
    if (e & 1) r = mulMod(r, b);
    b = mulMod(b, b);
    e >>= 1;
  }
  return r;
};

/** Reverse the low 8 bits of `k` — FIPS 204's BitRev8. */
const bitRev8 = (k: number): number => {
  let r = 0;
  for (let b = 0; b < 8; b++) r = (r << 1) | ((k >> b) & 1);
  return r;
};

/** The transform BY DEFINITION: 256 evaluations at the primitive 512th roots. */
const nttByDefinition = (f: readonly number[]): number[] =>
  Array.from({ length: N }, (_, j) => {
    const x = powMod(ML_DSA_NTT_ROOT, 2 * bitRev8(j) + 1);
    let acc = 0;
    let xp = 1;
    for (let i = 0; i < N; i++) {
      acc = (acc + mulMod(f[i] as number, xp)) % Q;
      xp = mulMod(xp, x);
    }
    return acc;
  });

/** Schoolbook multiplication in `Z_q[X]/(X²⁵⁶+1)`. */
const schoolbookMul = (f: readonly number[], g: readonly number[], q = Q): number[] => {
  const n = f.length;
  const out = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const k = i + j;
      const term = ((f[i] as number) * (g[j] as number)) % q;
      if (k < n) out[k] = ((out[k] as number) + term) % q;
      else out[k - n] = ((out[k - n] as number) - term + q) % q;
    }
  }
  return out;
};

// ─── Runtime harness ──────────────────────────────────────────────────────

const registry = buildDefaultRegistry();

const runBytes = (spec: CipherSpec, bytes: Uint8Array): Uint8Array => {
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected a bytes final state");
  return trace.finalState.bytes;
};

const runPoly = (spec: CipherSpec, coeffs: readonly number[]): number[] =>
  unpackMlDsaPoly(runBytes(spec, packMlDsaPoly(coeffs)));

const forward = (coeffs: readonly number[]): number[] => runPoly(buildMlDsaNttSpec(), coeffs);
const inverse = (coeffs: readonly number[]): number[] =>
  runPoly(buildMlDsaInverseNttSpec(), coeffs);

/** Deterministic coefficient fills, so failures are reproducible. */
const sample = (seed: number): number[] => {
  const out: number[] = [];
  let x = seed;
  for (let i = 0; i < N; i++) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out.push(x % Q);
  }
  return out;
};

const SAMPLES: readonly (readonly number[])[] = [
  // Zero transforms to zero — a floor, not evidence.
  new Array<number>(N).fill(0),
  // The constant 1. Here (unlike ML-KEM) it really does transform to all ones:
  // every evaluation of a constant is that constant.
  [1, ...new Array<number>(N - 1).fill(0)],
  // X alone — the transform IS the list of evaluation points.
  [0, 1, ...new Array<number>(N - 2).fill(0)],
  unpackMlDsaPoly(DEFAULT_ML_DSA_NTT_INPUT),
  // Every coefficient at the top of the range, so every add and multiply wraps.
  new Array<number>(N).fill(Q - 1),
  sample(1),
  sample(4242),
];

// ─── 0. The published table ───────────────────────────────────────────────

describe("the ζ table (FIPS 204 Appendix B)", () => {
  it("entries 1…255 are 1753^BitRev8(k) mod 8380417", () => {
    expect(ML_DSA_ZETAS.length).toBe(256);
    for (let k = 1; k < 256; k++) {
      expect(ML_DSA_ZETAS[k], `ZETAS[${k}]`).toBe(powMod(ML_DSA_NTT_ROOT, bitRev8(k)));
    }
  });

  it("opens and closes on the published values", () => {
    // Quoted from the standard, not recomputed — so a bug in `bitRev8` above
    // cannot make the previous test pass vacuously.
    expect(ML_DSA_ZETAS.slice(0, 8)).toEqual([
      0, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    ]);
    expect(ML_DSA_ZETAS[128]).toBe(1753); // BitRev8(128) = 1, so this is ζ¹ itself
    expect(ML_DSA_ZETAS.slice(252)).toEqual([1900052, 7598542, 1054478, 7648983]);
  });

  it("1753 is a primitive 512th root of unity: 1753^256 ≡ −1, 1753^512 ≡ 1", () => {
    expect(powMod(ML_DSA_NTT_ROOT, 256)).toBe(Q - 1);
    expect(powMod(ML_DSA_NTT_ROOT, 512)).toBe(1);
  });

  it("the final scaling is 256⁻¹ = 8347681 — eight layers, so 2⁸", () => {
    expect(mulMod(256, ML_DSA_N_INV_256)).toBe(1);
    // ML-KEM's constant is 128⁻¹ because its prime allows only seven layers.
    // Here 128⁻¹ would be the wrong one, and it is a different number.
    expect(powMod(128, Q - 2)).not.toBe(ML_DSA_N_INV_256);
  });

  it("the table on the wire is 1024 bytes, four big-endian bytes an entry", () => {
    expect(ML_DSA_ZETA_TABLE_BYTES.length).toBe(1024);
    expect([...ML_DSA_ZETA_TABLE_BYTES.slice(4, 8)]).toEqual([...mlDsaCoeffBytes(4808194)]);
  });
});

// ─── 1. The anchor: direct evaluation ─────────────────────────────────────

describe("forward NTT vs the transform's DEFINITION (rank 1 oracle)", () => {
  for (const [n, f] of SAMPLES.entries()) {
    it(`sample ${n}: eight layers of butterflies reproduce the 256 evaluations`, () => {
      expect(forward(f)).toEqual(nttByDefinition(f));
    });
  }

  it("the constant polynomial 1 transforms to all ones — unlike ML-KEM's 1, 0, 1, 0", () => {
    // The ML-KEM suite pins the opposite result for its transform, because that
    // one stops at degree-1 pairs. Same input, different prime, different shape.
    const f = [1, ...new Array<number>(N - 1).fill(0)];
    expect(forward(f)).toEqual(new Array<number>(N).fill(1));
  });
});

// ─── 2. The convolution theorem ───────────────────────────────────────────

describe("the convolution theorem with an element-wise product (rank 2 oracle)", () => {
  const pairs: readonly [readonly number[], readonly number[]][] = [
    [sample(7), sample(8)],
    [sample(99), unpackMlDsaPoly(DEFAULT_ML_DSA_NTT_INPUT)],
    [new Array<number>(N).fill(Q - 1), sample(3)],
  ];

  for (const [n, [f, g]] of pairs.entries()) {
    it(`pair ${n}: INTT(NTT(f) · NTT(g)) equals the schoolbook product`, () => {
      const fh = forward(f);
      const gh = forward(g);
      const product = fh.map((a, i) => mulMod(a, gh[i] as number));
      expect(inverse(product)).toEqual(schoolbookMul(f, g));
    });
  }

  it("the SAME element-wise product is wrong for ML-KEM's seven-layer transform", () => {
    // The contrast the plan promises. ML-KEM's transform leaves 128 degree-1
    // pairs, so multiplying its outputs number by number is not polynomial
    // multiplication at all. Run it and watch it fail.
    const q = 3329;
    const f = sample(5).map((c) => c % q);
    const g = sample(6).map((c) => c % q);
    const run = (spec: CipherSpec, c: readonly number[]): number[] =>
      unpackPoly(runBytes(spec, packPoly(c)));
    const fh = run(buildNttSpec(), f);
    const gh = run(buildNttSpec(), g);
    const elementWise = fh.map((a, i) => (a * (gh[i] as number)) % q);
    expect(run(buildInverseNttSpec(), elementWise)).not.toEqual(schoolbookMul(f, g, q));
  });

  it("X · X^255 = −1 in this ring", () => {
    const x = [0, 1, ...new Array<number>(N - 2).fill(0)];
    const x255 = [...new Array<number>(N - 1).fill(0), 1];
    const product = forward(x).map((a, i) => mulMod(a, forward(x255)[i] as number));
    expect(inverse(product)).toEqual([Q - 1, ...new Array<number>(N - 1).fill(0)]);
  });
});

// ─── 3. Round trip — weakest, last ────────────────────────────────────────

describe("INTT(NTT(f)) = f (rank 4 — weakest oracle, listed last on purpose)", () => {
  for (const [n, f] of SAMPLES.entries()) {
    it(`sample ${n} survives the round trip`, () => {
      expect(inverse(forward(f))).toEqual([...f]);
    });
  }
});

// ─── 4. Structure ─────────────────────────────────────────────────────────

const iterates = (spec: CipherSpec) =>
  spec.steps.filter((s): s is Extract<StepNode, { kind: "iterate" }> => s.kind === "iterate");

describe("spec structure", () => {
  it("both directions are eight layers over 255 butterfly groups", () => {
    for (const spec of [buildMlDsaNttSpec(), buildMlDsaInverseNttSpec()]) {
      const layers = iterates(spec);
      expect(layers.length).toBe(8);
      const groups = layers.reduce(
        (total, l) => total + ML_DSA_POLY_BYTES / (l.blockByteLength as number),
        0,
      );
      expect(groups).toBe(255);
    }
  });

  it("the forward layers narrow 1024 → 8 bytes and the inverse widens 8 → 1024", () => {
    const widths = (spec: CipherSpec): number[] =>
      iterates(spec).map((l) => l.blockByteLength as number);
    expect(widths(buildMlDsaNttSpec())).toEqual([1024, 512, 256, 128, 64, 32, 16, 8]);
    expect(widths(buildMlDsaInverseNttSpec())).toEqual([8, 16, 32, 64, 128, 256, 512, 1024]);
  });

  it("every layer's node ids key on its DISPLAY index", () => {
    for (const spec of [buildMlDsaNttSpec(), buildMlDsaInverseNttSpec()]) {
      iterates(spec).forEach((l, i) => {
        expect(l.id).toBe(nttLayerId(i + 1));
        for (const child of l.children) {
          expect(child.id.startsWith(`${nttLayerId(i + 1)}.`)).toBe(true);
        }
      });
    }
  });

  it("every vector step and constant load is four bytes a coefficient", () => {
    const walk = (nodes: readonly StepNode[], out: StepNode[]): StepNode[] => {
      for (const n of nodes) {
        out.push(n);
        if (n.kind !== "step") walk(n.children, out);
      }
      return out;
    };
    for (const spec of [buildMlDsaNttSpec(), buildMlDsaInverseNttSpec()]) {
      for (const n of walk(spec.steps, [])) {
        if (n.kind !== "step") continue;
        const p = n.params as Record<string, unknown>;
        if (n.type.startsWith("zq-vec-")) expect(p.coeffBytes, n.id).toBe(ML_DSA_COEFF_BYTES);
        if (n.type === "aux-load-bytes@1" && p.auxName !== "zeta") {
          expect(p.byteLength, n.id).toBe(ML_DSA_COEFF_BYTES);
        }
      }
    }
  });

  it("the forward run consumes entries 1 … 255 in order, and the inverse 255 … 1", () => {
    const consumed = (spec: CipherSpec, input: Uint8Array, outPort: string): number[] => {
      const trace = runSpec(spec, registry, {
        initialState: { shape: "bytes", bytes: input },
        initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
      });
      return trace.frames
        .filter((f) => f.stepId.includes(".zeta"))
        .map((f) => {
          const z = f.portOutputs?.get(outPort);
          if (z === undefined) throw new Error(`no ${outPort} on ${f.stepId}`);
          return unpackMlDsaPoly(z)[0] as number;
        });
    };
    expect(consumed(buildMlDsaNttSpec(), DEFAULT_ML_DSA_NTT_INPUT, "output0")).toEqual(
      ML_DSA_ZETAS.slice(1),
    );
    expect(consumed(buildMlDsaInverseNttSpec(), DEFAULT_ML_DSA_NTT_OUTPUT, "output1")).toEqual(
      [...ML_DSA_ZETAS.slice(1)].reverse(),
    );
  });

  it("DEFAULT_ML_DSA_NTT_OUTPUT is the real forward transform of the default input", () => {
    // Its bytes came from the DEFINITION, so this is a genuine cross-check.
    expect(unpackMlDsaPoly(DEFAULT_ML_DSA_NTT_OUTPUT)).toEqual(
      nttByDefinition(unpackMlDsaPoly(DEFAULT_ML_DSA_NTT_INPUT)),
    );
    expect(runBytes(buildMlDsaNttSpec(), DEFAULT_ML_DSA_NTT_INPUT)).toEqual(
      DEFAULT_ML_DSA_NTT_OUTPUT,
    );
    expect(runBytes(buildMlDsaInverseNttSpec(), DEFAULT_ML_DSA_NTT_OUTPUT)).toEqual(
      DEFAULT_ML_DSA_NTT_INPUT,
    );
  });

  it("an ML-KEM-sized (512-byte) input is a loud failure, not a silent half-transform", () => {
    expect(() => runBytes(buildMlDsaNttSpec(), new Uint8Array(512))).toThrow(
      /not a multiple of blockByteLength/,
    );
  });
});

// ─── 5. Perturbation ──────────────────────────────────────────────────────

describe("perturbation — each of these must break something", () => {
  const clone = (spec: CipherSpec): CipherSpec => structuredClone(spec) as CipherSpec;
  const f = sample(31337);

  it("breaking a single ζ changes the forward transform", () => {
    const spec = clone(buildMlDsaNttSpec());
    const zeta = spec.cipherConstants?.zeta;
    if (zeta === undefined) throw new Error("expected a zeta constant");
    zeta[7] = (zeta[7] as number) ^ 1; // entry 1's low byte
    expect(runPoly(spec, f)).not.toEqual(nttByDefinition(f));
  });

  it("changing entry 0 changes NOTHING — the table's unused slot", () => {
    // Not a perturbation that should break anything: neither direction reads
    // entry 0. Pinned because it is the reason the published table can list it
    // as 0 instead of 1753⁰ = 1.
    const spec = clone(buildMlDsaNttSpec());
    const zeta = spec.cipherConstants?.zeta;
    if (zeta === undefined) throw new Error("expected a zeta constant");
    zeta.set(mlDsaCoeffBytes(1), 0);
    expect(runPoly(spec, f)).toEqual(nttByDefinition(f));
  });

  it("an ascending-exponent table (ζ^k instead of ζ^BitRev8(k)) agrees with nothing", () => {
    const spec = clone(buildMlDsaNttSpec());
    const zeta = spec.cipherConstants?.zeta;
    if (zeta === undefined) throw new Error("expected a zeta constant");
    for (let k = 0; k < 256; k++) zeta.set(mlDsaCoeffBytes(powMod(ML_DSA_NTT_ROOT, k)), k * 4);
    expect(runPoly(spec, f)).not.toEqual(nttByDefinition(f));
  });

  it("scaling the inverse by 128⁻¹ (ML-KEM's constant) doubles every coefficient", () => {
    // Without the scaling the eight layers return 256·f; 128⁻¹ removes only
    // half of that.
    const spec = clone(buildMlDsaInverseNttSpec());
    const ninv = spec.cipherConstants?.ninv;
    if (ninv === undefined) throw new Error("expected an ninv constant");
    ninv.set(mlDsaCoeffBytes(powMod(128, Q - 2)), 0);
    const wrong = runPoly(spec, forward(f));
    expect(wrong).not.toEqual([...f]);
    expect(wrong).toEqual(f.map((c) => (c * 2) % Q));
  });

  it("dropping the eighth layer changes the result", () => {
    const spec = clone(buildMlDsaNttSpec());
    const shortened: CipherSpec = {
      ...spec,
      steps: (spec.steps as StepNode[]).filter((s) => s.id !== nttLayerId(8)),
      outputFrom: { node: nttLayerId(7), port: "out" },
    };
    expect(runPoly(shortened, f)).not.toEqual(nttByDefinition(f));
  });
});
