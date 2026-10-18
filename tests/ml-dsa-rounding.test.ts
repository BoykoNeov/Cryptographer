/**
 * ML-DSA rounding and hints — Power2Round, Decompose, MakeHint, UseHint, the
 * hint count and the infinity-norm check (FIPS 204 §7.4; P2 of
 * `docs/plans/refactored-petting-tide.md`).
 *
 * ## How this ranks its evidence
 *
 * 1. **Exhaustive over the whole domain**, every `r` in `[0, q)` — 8,380,417
 *    values — against an oracle derived a DIFFERENT way from the
 *    implementation. The implementation reduces with `mod±` and then checks for
 *    the wrap-round special case; the oracle rounds with a floor division and
 *    detects the wrap by bucket index. They share no code, so a mistake in one
 *    is not copied into the other.
 * 2. **The FIPS 204 correctness property** `UseHint(MakeHint(z, r), r) =
 *    HighBits(r + z)` for `‖z‖∞ ≤ γ2`: exhaustive over `r` at the boundary
 *    values of `z`, and sampled at random `z` in between.
 * 3. **The executors**, driven through the registry, agree with the pure
 *    functions on the ports and fail loudly on bad wiring.
 * 4. **Both edge conventions**, one value either side: the norm check is a
 *    strict `<`, the hint count is `≤ ω`.
 *
 * The external, byte-level oracle for these steps — keys and signatures made
 * by Node and by `@noble/post-quantum` — is `tests/ml-dsa-44-oracle.test.ts`.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_44_GAMMA2,
  ML_DSA_44_OMEGA,
  ML_DSA_D,
  ML_DSA_Q,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
  packMlDsaPoly,
  unpackMlDsaPoly,
} from "@/ciphers/mldsa-constants";
import {
  decompose,
  highBits,
  makeHint,
  modPm,
  power2Round,
  toResidue,
  useHint,
} from "@/core/ml-dsa-arith";
import type { Json, PortedExecutor } from "@/core/types";
import { describe, expect, it } from "vitest";

const q = ML_DSA_Q;
const g2 = ML_DSA_44_GAMMA2;
const m = (q - 1) / (2 * g2);

// ─── Independent oracles ──────────────────────────────────────────────────

/**
 * Decompose, derived by FLOOR DIVISION rather than `mod±`. Bucket `j` covers
 * `(j·2γ2 − γ2, j·2γ2 + γ2]`, so `j = ⌊(r + γ2 − 1) / 2γ2⌋`. Index `m` is the
 * bucket centred on `q − 1 ≡ −1` — not a real bucket — and it folds into 0
 * with `r0 = r − q`, i.e. the distance below zero.
 */
const oracleDecompose = (r: number): { r1: number; r0: number } => {
  const j = Math.floor((r + g2 - 1) / (2 * g2));
  if (j === m) return { r1: 0, r0: r - q };
  return { r1: j, r0: r - j * 2 * g2 };
};

/** Power2Round by floor division: round to the nearest multiple of 2^d, ties down. */
const oraclePower2Round = (r: number, d: number): { r1: number; r0: number } => {
  const r1 = Math.floor((r + 2 ** (d - 1) - 1) / 2 ** d);
  return { r1, r0: r - r1 * 2 ** d };
};

// ─── Registry harness ─────────────────────────────────────────────────────

const registry = buildDefaultRegistry();
const P = { coeffBytes: 4, littleEndian: false } as const;

const exec = (
  type: string,
  ports: Record<string, Uint8Array>,
  params: Record<string, Json> = P,
): Map<string, Uint8Array> => {
  const def = registry.getRegistration(type);
  if (def === undefined || def.kind !== "ported") throw new Error(`${type} is not registered`);
  const run = def.executor as PortedExecutor;
  return run(new Map(Object.entries(ports)), params, {} as never) as Map<string, Uint8Array>;
};

const port = (out: Map<string, Uint8Array>, name: string): Uint8Array => {
  const v = out.get(name);
  if (v === undefined) throw new Error(`no output port ${name}`);
  return v;
};

const G2_BYTES = mlDsaCoeffBytes(g2);

/** A deterministic sample of residues, for the executor-level checks. */
const sampleResidues = (count: number, seed: number): number[] => {
  let x = seed >>> 0;
  const out: number[] = [];
  for (let i = 0; i < count; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out.push(x % q);
  }
  return out;
};

/** Values worth hitting deliberately: bucket edges, the wrap region, 0 and q−1. */
const EDGE_VALUES: number[] = (() => {
  const out = new Set<number>([0, 1, q - 1, q - 2, q - g2, q - g2 - 1, q - g2 + 1]);
  for (let j = 0; j <= m; j++) {
    for (const off of [-1, 0, 1]) {
      const c = j * 2 * g2 + g2 + off;
      if (c >= 0 && c < q) out.add(c);
    }
  }
  return [...out].sort((a, b) => a - b);
})();

// ─── Exhaustive ───────────────────────────────────────────────────────────

describe("Decompose — exhaustive over every r in [0, q)", () => {
  it("matches the floor-division oracle at all 8,380,417 values", () => {
    let mismatches = 0;
    let first = "";
    let wrapped = 0;
    for (let r = 0; r < q; r++) {
      const got = decompose(r, g2, q);
      const want = oracleDecompose(r);
      if (got.wrapped) wrapped++;
      if (got.r1 !== want.r1 || got.r0 !== want.r0) {
        if (mismatches === 0)
          first = `r=${r}: got (${got.r1}, ${got.r0}), want (${want.r1}, ${want.r0})`;
        mismatches++;
      }
    }
    expect(mismatches, first).toBe(0);
    // The special case fires for exactly the top γ2 values, q−γ2 … q−1. If the
    // count drifts, the fix-up has moved — not merely "still passes".
    expect(wrapped).toBe(g2);
  });

  it("returns only real buckets 0…m−1 and offsets within (−γ2, γ2] — except the wrap's −γ2", () => {
    // Every value, counted rather than asserted one by one — a million
    // `expect` calls cost half a minute and say nothing more.
    let bad = 0;
    let first = "";
    for (let r = 0; r < q; r++) {
      const { r1, r0, wrapped } = decompose(r, g2, q);
      // The wrap shifts r0 down by one, so its range is [−γ2, −1]: −γ2 itself
      // is reachable ONLY there. That is FIPS 204's own bound, not slack.
      const ok =
        r1 >= 0 &&
        r1 < m &&
        r0 >= (wrapped ? -g2 : -g2 + 1) &&
        r0 <= (wrapped ? -1 : g2) &&
        toResidue(r1 * 2 * g2 + r0, q) === r;
      if (!ok) {
        if (bad === 0) first = `r=${r}: (${r1}, ${r0}, wrapped=${wrapped})`;
        bad++;
      }
    }
    expect(bad, first).toBe(0);
  });

  it("puts 44 buckets in ML-DSA-44's range", () => {
    expect(m).toBe(44);
    expect(highBits(q - g2 - 1, g2, q)).toBe(43);
    expect(highBits(q - g2, g2, q)).toBe(0);
  });
});

describe("Power2Round — exhaustive over every r in [0, q)", () => {
  it("matches the floor-division oracle at d = 13", () => {
    let mismatches = 0;
    let first = "";
    for (let r = 0; r < q; r++) {
      const got = power2Round(r, ML_DSA_D, q);
      const want = oraclePower2Round(r, ML_DSA_D);
      if (got.r1 !== want.r1 || got.r0 !== want.r0) {
        if (mismatches === 0)
          first = `r=${r}: got (${got.r1}, ${got.r0}), want (${want.r1}, ${want.r0})`;
        mismatches++;
      }
    }
    expect(mismatches, first).toBe(0);
  });

  it("leaves t1 in 10 bits — the public key's packing width", () => {
    // bitlen(q − 1) − d = 23 − 13 = 10. A t1 of 1024 would not pack.
    let max = 0;
    for (let r = 0; r < q; r += 3) max = Math.max(max, power2Round(r, ML_DSA_D, q).r1);
    expect(max).toBeLessThan(2 ** 10);
  });

  it("rounds ties DOWN and is not truncation", () => {
    expect(power2Round(6144, 12, q)).toEqual({ r1: 1, r0: 2048 });
    expect(power2Round(6145, 12, q)).toEqual({ r1: 2, r0: -2047 });
    // Truncation would give r1 = 1 here.
    expect(power2Round(6145, 12, q).r1).not.toBe(Math.floor(6145 / 4096));
  });
});

describe("MakeHint / UseHint — the FIPS 204 correctness property", () => {
  const holds = (z: number, r: number): boolean =>
    useHint(makeHint(z, r, g2, q), r, g2, q) === oracleDecompose(toResidue(r + z, q)).r1;

  it("UseHint(MakeHint(z, r), r) = HighBits(r + z) for every r at z = 0, ±1, ±γ2", () => {
    for (const z of [0, 1, q - 1, g2, q - g2]) {
      let failures = 0;
      for (let r = 0; r < q; r++) if (!holds(z, r)) failures++;
      expect(failures, `z = ${z}`).toBe(0);
    }
  });

  it("holds for random z across the whole allowed range [−γ2, γ2]", () => {
    let x = 12345;
    const failures: string[] = [];
    for (let i = 0; i < 300_000; i++) {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      const r = x % q;
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      const z = toResidue((x % (2 * g2 + 1)) - g2, q);
      if (!holds(z, r)) failures.push(`r=${r}, z=${z}`);
    }
    expect(failures.slice(0, 3)).toEqual([]);
  });

  it("fails past the allowed range — so the property above is not vacuous", () => {
    // A drift of more than one bucket is beyond what one hint bit can repair.
    let failures = 0;
    for (let r = 0; r < q; r += 101) if (!holds(2 * g2 + 1, r)) failures++;
    expect(failures).toBeGreaterThan(0);
  });

  it("UseHint wraps round the circle in both directions", () => {
    // r just above 0: bucket 0, positive offset. A hint moves it UP to 1.
    expect(useHint(1, 5, g2, q)).toBe(1);
    // r in the wrap region: bucket 0, negative offset. A hint moves it DOWN,
    // and one below bucket 0 is bucket 43.
    expect(useHint(1, q - 5, g2, q)).toBe(m - 1);
    // r in bucket 43 with a positive offset moves UP to bucket 0.
    expect(useHint(1, 43 * 2 * g2 + 5, g2, q)).toBe(0);
  });
});

describe("modPm — centred reduction", () => {
  it("lands in (−α/2, α/2] for even α and [−(q−1)/2, (q−1)/2] for q", () => {
    expect(modPm(8192, 2 ** 13)).toBe(0);
    expect(modPm(4096, 2 ** 13)).toBe(4096);
    expect(modPm(4097, 2 ** 13)).toBe(-4095);
    expect(modPm((q - 1) / 2, q)).toBe((q - 1) / 2);
    expect(modPm((q + 1) / 2, q)).toBe(-(q - 1) / 2);
  });
});

// ─── Executors ────────────────────────────────────────────────────────────

describe("the executors agree with the arithmetic, on the ports", () => {
  const values = [...EDGE_VALUES, ...sampleResidues(400, 7)];
  const vec = packMlDsaPoly(values);

  it("ml-dsa.decompose@1 writes r1 and r0 mod q", () => {
    const out = exec("ml-dsa.decompose@1", { a: vec, gamma2: G2_BYTES, modulus: ML_DSA_Q_BYTES });
    const high = unpackMlDsaPoly(port(out, "high"));
    const low = unpackMlDsaPoly(port(out, "low"));
    values.forEach((r, i) => {
      const want = oracleDecompose(r);
      expect(high[i]).toBe(want.r1);
      expect(low[i]).toBe(toResidue(want.r0, q));
    });
  });

  it("ml-dsa.power2round@1 writes t1 and t0 mod q", () => {
    const out = exec(
      "ml-dsa.power2round@1",
      { a: vec, modulus: ML_DSA_Q_BYTES },
      { ...P, d: ML_DSA_D },
    );
    const high = unpackMlDsaPoly(port(out, "high"));
    const low = unpackMlDsaPoly(port(out, "low"));
    values.forEach((r, i) => {
      const want = oraclePower2Round(r, ML_DSA_D);
      expect(high[i]).toBe(want.r1);
      expect(low[i]).toBe(toResidue(want.r0, q));
    });
  });

  it("ml-dsa.make-hint@1 then ml-dsa.use-hint@1 recover HighBits(r + z)", () => {
    const zs = sampleResidues(values.length, 99).map((x) => toResidue((x % (2 * g2 + 1)) - g2, q));
    const z = packMlDsaPoly(zs);
    const h = port(
      exec("ml-dsa.make-hint@1", { z, r: vec, gamma2: G2_BYTES, modulus: ML_DSA_Q_BYTES }),
      "output",
    );
    const hint = unpackMlDsaPoly(h);
    expect(hint.every((b) => b === 0 || b === 1)).toBe(true);
    // Some coefficients really do drift — otherwise this proves nothing.
    expect(hint.some((b) => b === 1)).toBe(true);
    const used = unpackMlDsaPoly(
      port(
        exec("ml-dsa.use-hint@1", { h, r: vec, gamma2: G2_BYTES, modulus: ML_DSA_Q_BYTES }),
        "output",
      ),
    );
    values.forEach((r, i) => {
      expect(used[i]).toBe(oracleDecompose(toResidue(r + (zs[i] as number), q)).r1);
    });
  });

  it("refuses a γ2 that does not divide (q − 1)/2", () => {
    expect(() =>
      exec("ml-dsa.decompose@1", {
        a: vec,
        gamma2: mlDsaCoeffBytes(g2 + 1),
        modulus: ML_DSA_Q_BYTES,
      }),
    ).toThrow(/does not divide/);
  });

  it("refuses an unreduced coefficient rather than reducing it silently", () => {
    expect(() =>
      exec("ml-dsa.decompose@1", {
        a: packMlDsaPoly([q]),
        gamma2: G2_BYTES,
        modulus: ML_DSA_Q_BYTES,
      }),
    ).toThrow(/not a residue below q/);
  });

  it("refuses a hint that is not 0 or 1", () => {
    expect(() =>
      exec("ml-dsa.use-hint@1", {
        h: packMlDsaPoly([2]),
        r: packMlDsaPoly([5]),
        gamma2: G2_BYTES,
        modulus: ML_DSA_Q_BYTES,
      }),
    ).toThrow(/one bit/);
  });
});

describe("zq-vec-mul@1 — element-wise, the ML-DSA domain's product", () => {
  it("multiplies position by position at full precision", () => {
    const a = sampleResidues(256, 3);
    const b = sampleResidues(256, 4);
    const out = unpackMlDsaPoly(
      port(
        exec("zq-vec-mul@1", { a: packMlDsaPoly(a), b: packMlDsaPoly(b), modulus: ML_DSA_Q_BYTES }),
        "output",
      ),
    );
    a.forEach((ai, i) => {
      expect(out[i]).toBe(Number((BigInt(ai) * BigInt(b[i] as number)) % BigInt(q)));
    });
    // The products really exceed 32 bits, so a wrapping implementation would be
    // caught here: (q−1)² is 46 bits.
    expect((q - 1) * (q - 1)).toBeGreaterThan(2 ** 32);
  });

  it("differs from the per-pair base-case multiply on the same operands", () => {
    // The contrast the two steps exist to show. Same ports, same numbers; the
    // pair rule folds a₁b₁γ into the even slot and so cannot agree.
    const a = packMlDsaPoly([3, 5]);
    const b = packMlDsaPoly([7, 11]);
    const elementwise = unpackMlDsaPoly(
      port(exec("zq-vec-mul@1", { a, b, modulus: ML_DSA_Q_BYTES }), "output"),
    );
    const pairwise = unpackMlDsaPoly(
      port(
        exec("zq-base-case-mul@1", { a, b, gamma: mlDsaCoeffBytes(2), modulus: ML_DSA_Q_BYTES }),
        "output",
      ),
    );
    expect(elementwise).toEqual([21, 55]);
    expect(pairwise).toEqual([3 * 7 + 5 * 11 * 2, 3 * 11 + 5 * 7]);
  });

  it("refuses vectors of different lengths", () => {
    expect(() =>
      exec("zq-vec-mul@1", {
        a: packMlDsaPoly([1, 2]),
        b: packMlDsaPoly([1]),
        modulus: ML_DSA_Q_BYTES,
      }),
    ).toThrow(/same length/);
  });
});

describe("zq-inf-norm-below@1 — strict, and centred on zero", () => {
  const check = (values: number[], bound: number) => {
    const out = exec("zq-inf-norm-below@1", {
      a: packMlDsaPoly(values),
      bound: mlDsaCoeffBytes(bound),
      modulus: ML_DSA_Q_BYTES,
    });
    return { flag: port(out, "output")[0], norm: unpackMlDsaPoly(port(out, "norm"))[0] };
  };

  it("reads q − 5 as −5, a SMALL coefficient", () => {
    expect(check([q - 5, 3], 10)).toEqual({ flag: 1, norm: 5 });
  });

  it("rejects a coefficient exactly ON the bound, accepts one below it", () => {
    expect(check([100], 100).flag).toBe(0);
    expect(check([99], 100).flag).toBe(1);
    expect(check([q - 100], 100).flag).toBe(0);
    expect(check([q - 99], 100).flag).toBe(1);
  });

  it("reports the norm — the largest magnitude, either side of zero", () => {
    expect(check([7, q - 40, 12], 1000).norm).toBe(40);
    expect(check([(q - 1) / 2, (q + 1) / 2], q).norm).toBe((q - 1) / 2);
  });

  it("calls an empty vector small", () => {
    expect(check([], 1)).toEqual({ flag: 1, norm: 0 });
  });
});

describe("ml-dsa.hint-count@1 — at most ω, inclusive", () => {
  const count = (ones: number, omega = ML_DSA_44_OMEGA) => {
    const h = new Array<number>(1024).fill(0);
    for (let i = 0; i < ones; i++) h[i * 7] = 1;
    const out = exec("ml-dsa.hint-count@1", {
      h: packMlDsaPoly(h),
      omega: new Uint8Array([omega]),
    });
    const c = port(out, "count");
    return { flag: port(out, "output")[0], count: ((c[0] as number) << 8) | (c[1] as number) };
  };

  it("accepts exactly ω ones and rejects ω + 1", () => {
    expect(count(80)).toEqual({ flag: 1, count: 80 });
    expect(count(81)).toEqual({ flag: 0, count: 81 });
    expect(count(0)).toEqual({ flag: 1, count: 0 });
  });

  it("reads ω off its port, not a constant", () => {
    expect(count(5, 4).flag).toBe(0);
    expect(count(4, 4).flag).toBe(1);
  });
});
