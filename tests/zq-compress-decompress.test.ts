/**
 * `zq-compress@1` / `zq-decompress@1` — FIPS 203 §4.2.1 (ML-KEM P2,
 * `docs/plans/unified-stargazing-quasar.md`).
 *
 * These two are the only LOSSY operation in ML-KEM, and P2's plan flags them as
 * one of three independent places to be subtly wrong whose errors P3's `ek`
 * comparison catches only *in aggregate* — a compensating pair survives it. So
 * they are pinned here directly against the §4.2.1 formulas, **exhaustively**:
 * `q = 3329` and `d ≤ 12`, so the whole domain is ~40k evaluations per direction
 * and costs nothing.
 *
 * ## The oracle is not the implementation restated
 *
 * The executors round by adding half the denominator and flooring
 * (`(2·num + den) / (2·den)`). The oracle below instead takes the floor and then
 * **compares the two distances**, going up when the remainder is at least half
 * the denominator. Same function, different derivation — so a slip in the
 * algebra of one does not hide in the other. Both are exact `bigint`; there is
 * no floating point anywhere in this file, because `q/2^d` is not representable
 * and a `Math.round` oracle would disagree with the spec at values nobody would
 * think to spot-check.
 *
 * ## Five properties, in the order they matter
 *
 *  1. **The formulas, exhaustively.** Every `x ∈ [0, q)` and every
 *     `y ∈ [0, 2^d)`, for every `d ∈ 1..12`.
 *  2. **Ties round UP, and only one direction can see a tie.** `q` is odd, so
 *     compression can never land on a half-way value; `2^d` is even, so
 *     decompression can. Both halves are asserted rather than reasoned about,
 *     and the classic wrong implementation (truncate) is run alongside to prove
 *     the assertion is live rather than vacuous.
 *  3. **`Compress(Decompress(y)) = y` exactly**, for every `y` in range — but
 *     only while `2^d ≤ q`. Verified rather than assumed, and the verification
 *     paid: at `d = 12` it does NOT hold, because 4096 inputs cannot survive a
 *     trip through 3329 values. That is pigeonhole rather than a rounding slip,
 *     and it is why FIPS 203 defines `Compress_d` for `d < 12` only.
 *  4. **The error bound on `Decompress(Compress(x))`** — measured over the whole
 *     domain, in the ring's circular metric. That bound is the reason ML-KEM can
 *     decrypt correctly through a ciphertext that is not invertible, and it is
 *     the fact `zq-compress@1`'s own `detail` claims. A doc claim that no test
 *     checks is a doc claim that rots.
 *  5. **Wiring**: element counts, byte order, and the loud failures.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { Json, StepContext } from "@/core/types";
import { zqCompress } from "@/steps/zq-compress";
import { zqDecompress } from "@/steps/zq-decompress";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
const Q = 3329;
const Q_BIG = BigInt(Q);
const Q_BYTES = new Uint8Array([0x0d, 0x01]);
const params = (d: number, littleEndian = false): Json => ({ coeffBytes: 2, littleEndian, d });

/** The d values ML-KEM actually uses, plus the full legal span for good measure. */
const ML_KEM_DS = [1, 4, 5, 10, 11, 12] as const;
const ALL_DS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] as const;

const packBE = (coeffs: readonly number[]): Uint8Array => {
  const out = new Uint8Array(coeffs.length * 2);
  coeffs.forEach((c, i) => {
    out[i * 2] = (c >>> 8) & 0xff;
    out[i * 2 + 1] = c & 0xff;
  });
  return out;
};

const unpackBE = (bytes: Uint8Array): number[] => {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += 2)
    out.push((bytes[i] as number) * 256 + (bytes[i + 1] as number));
  return out;
};

// ─── The oracles: FIPS 203 §4.2.1, by distance comparison ─────────────────

/**
 * `round(num / den)` with ties rounded **up**, by taking the floor and then
 * asking whether the leftover is at least half the denominator. Deliberately
 * NOT the executors' add-half-and-floor identity.
 */
const roundHalfUp = (num: bigint, den: bigint): bigint => {
  const k = num / den;
  const rem = num - k * den;
  return 2n * rem >= den ? k + 1n : k;
};

/** True when `num / den` sits exactly half way between two integers. */
const isTie = (num: bigint, den: bigint): boolean => 2n * (num % den) === den;

/** `Compress_d(x) = ⌈(2^d/q)·x⌋ mod 2^d`. */
const compressOracle = (x: number, d: number): number => {
  const twoD = 1n << BigInt(d);
  return Number(roundHalfUp(twoD * BigInt(x), Q_BIG) % twoD);
};

/** `Decompress_d(y) = ⌈(q/2^d)·y⌋`. */
const decompressOracle = (y: number, d: number): number => {
  const twoD = 1n << BigInt(d);
  return Number(roundHalfUp(Q_BIG * BigInt(y), twoD) % Q_BIG);
};

/** The classic wrong implementation, kept so the tie assertions can be shown live. */
const compressTruncating = (x: number, d: number): number =>
  Number((((1n << BigInt(d)) * BigInt(x)) / Q_BIG) % (1n << BigInt(d)));
const decompressTruncating = (y: number, d: number): number =>
  Number((Q_BIG * BigInt(y)) / (1n << BigInt(d)));

/** Run a whole vector through an executor in one call. */
const runCompress = (coeffs: readonly number[], d: number, le = false): number[] => {
  const out = zqCompress(
    new Map([
      ["a", packBE(coeffs)],
      ["modulus", Q_BYTES],
    ]),
    params(d, le),
    ctx,
  ).get("output");
  return unpackBE(out as Uint8Array);
};

const runDecompress = (coeffs: readonly number[], d: number, le = false): number[] => {
  const out = zqDecompress(
    new Map([
      ["a", packBE(coeffs)],
      ["modulus", Q_BYTES],
    ]),
    params(d, le),
    ctx,
  ).get("output");
  return unpackBE(out as Uint8Array);
};

/** Distance on the circle Z_q — the metric the error bound is stated in. */
const ringDistance = (a: number, b: number): number => {
  const raw = Math.abs(a - b);
  return Math.min(raw, Q - raw);
};

// ─── 1. The formulas, exhaustively ────────────────────────────────────────

describe("zq-compress@1 / zq-decompress@1 — the FIPS 203 §4.2.1 formulas", () => {
  it("compresses every coefficient in [0, q) exactly as Compress_d does, for every d in 1..12", () => {
    const all = Array.from({ length: Q }, (_, x) => x);
    for (const d of ALL_DS) {
      expect({ d, out: runCompress(all, d) }).toEqual({
        d,
        out: all.map((x) => compressOracle(x, d)),
      });
    }
  });

  it("decompresses every value in [0, 2^d) exactly as Decompress_d does, for every d in 1..12", () => {
    for (const d of ALL_DS) {
      const all = Array.from({ length: 2 ** d }, (_, y) => y);
      expect({ d, out: runDecompress(all, d) }).toEqual({
        d,
        out: all.map((y) => decompressOracle(y, d)),
      });
    }
  });

  it("keeps compressed values inside [0, 2^d) — the trailing mod is not decoration", () => {
    // Rounding to nearest can carry past the last bucket: at d = 1 anything from
    // 2497 up rounds to 2, which does not fit in one bit and must wrap to 0.
    // That wrap is correct rather than a fudge — the coefficients live on a
    // circle, so the largest really are neighbours of the smallest.
    for (const d of ALL_DS) {
      const out = runCompress(
        Array.from({ length: Q }, (_, x) => x),
        d,
      );
      expect(out.every((v) => v >= 0 && v < 2 ** d)).toBe(true);
    }
    expect(runCompress([2496, 2497, 3328], 1)).toEqual([1, 0, 0]);
  });

  it("keeps decompressed values inside [0, q)", () => {
    for (const d of ALL_DS) {
      const out = runDecompress(
        Array.from({ length: 2 ** d }, (_, y) => y),
        d,
      );
      expect(out.every((v) => v >= 0 && v < Q)).toBe(true);
    }
  });
});

// ─── 2. Ties, and which direction can see one ─────────────────────────────

describe("rounding is to nearest with ties UP, and only decompression can hit a tie", () => {
  it("compression never lands on a half-way value, because q is odd", () => {
    // 2^(d+1)·x is even and q is odd, so they are never congruent mod 2q. Worth
    // asserting rather than reasoning about: it is the reason a *truncating*
    // compression still passes every tie-focused spot check anyone would write.
    for (const d of ALL_DS) {
      const twoD = 1n << BigInt(d);
      for (let x = 0; x < Q; x++) {
        expect(isTie(twoD * BigInt(x), Q_BIG)).toBe(false);
      }
    }
  });

  it("decompression DOES land on half-way values, and rounds them up", () => {
    // d = 1, y = 1: q/2 = 1664.5 exactly. Up is 1665; a truncating
    // implementation says 1664 and is wrong by one.
    expect(isTie(Q_BIG * 1n, 2n)).toBe(true);
    expect(runDecompress([1], 1)).toEqual([1665]);
    expect(decompressTruncating(1, 1)).toBe(1664);

    // The ties are not a one-off curiosity: count them across the domain so a
    // future refactor that quietly stops producing any is visible.
    let ties = 0;
    for (const d of ALL_DS) {
      const twoD = 1n << BigInt(d);
      for (let y = 0; y < 2 ** d; y++) if (isTie(Q_BIG * BigInt(y), twoD)) ties++;
    }
    expect(ties).toBeGreaterThan(0);
  });

  it("truncating instead of rounding is WRONG in both directions — the perturbation is run, not assumed", () => {
    // If this test ever goes green with the shipped executors, the executors
    // have started truncating.
    const xs = Array.from({ length: Q }, (_, x) => x);
    const shipped = runCompress(xs, 10);
    expect(shipped).not.toEqual(xs.map((x) => compressTruncating(x, 10)));

    const ys = Array.from({ length: 2 ** 10 }, (_, y) => y);
    expect(runDecompress(ys, 10)).not.toEqual(ys.map((y) => decompressTruncating(y, 10)));
  });
});

// ─── 3. The direction that DOES round-trip ────────────────────────────────

describe("Compress(Decompress(y)) = y — verified, not assumed", () => {
  it("recovers every bucket index exactly, for every d with 2^d ≤ q", () => {
    // d ≤ 11, which is every d FIPS 203 defines Compress_d at. A bucket's
    // centre is unambiguously inside that bucket, so this direction is exact.
    for (const d of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] as const) {
      const ys = Array.from({ length: 2 ** d }, (_, y) => y);
      expect({ d, out: runCompress(runDecompress(ys, d), d) }).toEqual({ d, out: ys });
    }
  });

  it("CANNOT hold at d = 12, and the reason is pigeonhole rather than a rounding slip", () => {
    // 2¹² = 4096 > q = 3329, so Decompress_12 has nowhere to put 4096 distinct
    // inputs — it collapses them onto 3329 values before any rounding rule gets
    // a say. This is exactly why FIPS 203 defines Compress_d only for d < 12
    // and gives the uncompressed case its own encoding (ByteEncode_12) instead.
    // Asserted rather than skipped: an implementation that appeared to round-trip
    // here would be reporting something impossible.
    const ys = Array.from({ length: 4096 }, (_, y) => y);
    const images = new Set(runDecompress(ys, 12));
    expect(images.size).toBe(Q);
    expect(runCompress(runDecompress(ys, 12), 12)).not.toEqual(ys);
  });
});

// ─── 4. The error bound the docs claim ────────────────────────────────────

describe("Decompress(Compress(x)) is near x, and the bound is what makes ML-KEM decrypt", () => {
  it("never moves a coefficient further than ceil(q / 2^(d+1)) around the ring", () => {
    // This is the number every correctness argument in FIPS 203 rests on, and
    // it is exactly the claim `zq-compress@1`'s detail makes to the learner.
    for (const d of ML_KEM_DS) {
      const xs = Array.from({ length: Q }, (_, x) => x);
      const back = runDecompress(runCompress(xs, d), d);
      const worst = xs.reduce((m, x, i) => Math.max(m, ringDistance(x, back[i] as number)), 0);
      expect({ d, ok: worst <= Math.ceil(Q / 2 ** (d + 1)) }).toEqual({ d, ok: true });
    }
  });

  it("is NOT the identity for d < 12 — the loss is real", () => {
    // The whole point of the pair. Stated as a count so it cannot pass by
    // accident on a lucky sample.
    const xs = Array.from({ length: Q }, (_, x) => x);
    for (const d of [1, 4, 5, 10, 11] as const) {
      const back = runDecompress(runCompress(xs, d), d);
      const moved = xs.filter((x, i) => x !== back[i]).length;
      expect({ d, lossy: moved > 0 }).toEqual({ d, lossy: true });
    }
  });

  it("d = 12 loses nothing at q = 3329 — which is why a public key uses it", () => {
    // 2^12 = 4096 > 3329, so every coefficient gets its own bucket. This is the
    // one d at which the "lossy" step is not lossy at all, and it is the reason
    // ByteEncode_12 is the public-key encoding.
    const xs = Array.from({ length: Q }, (_, x) => x);
    expect(runDecompress(runCompress(xs, 12), 12)).toEqual(xs);
  });
});

// ─── 5. Wiring ────────────────────────────────────────────────────────────

describe("wiring and loud failures", () => {
  it("is registered under both bare names", () => {
    const r = buildDefaultRegistry();
    expect(r.has("zq-compress@1")).toBe(true);
    expect(r.has("zq-decompress@1")).toBe(true);
    expect(r.getDoc("zq-compress@1")).toBeDefined();
    expect(r.getDoc("zq-decompress@1")).toBeDefined();
  });

  it("preserves the element count and the element width", () => {
    const out = zqCompress(
      new Map([
        ["a", packBE([0, 1, 1664, 3328])],
        ["modulus", Q_BYTES],
      ]),
      params(4),
      ctx,
    ).get("output");
    expect((out as Uint8Array).length).toBe(8);
  });

  it("honours littleEndian on the way in AND on the way out", () => {
    // The param is real, not decoration: the same bytes read little-endian are
    // different numbers, so they compress to different buckets.
    const be = runCompress([1000], 10, false);
    const packedLE = new Uint8Array([0xe8, 0x03]); // 1000 little-endian
    const outLE = zqCompress(
      new Map([
        ["a", packedLE],
        ["modulus", Q_BYTES],
      ]),
      params(10, true),
      ctx,
    ).get("output") as Uint8Array;
    // Same NUMBER in, so the same number out — but written back low byte first.
    expect([outLE[1], outLE[0]]).toEqual([
      ((be[0] as number) >>> 8) & 0xff,
      (be[0] as number) & 0xff,
    ]);
  });

  it("throws on a missing modulus port", () => {
    expect(() => zqCompress(new Map([["a", packBE([1])]]), params(4), ctx)).toThrow(/modulus/);
    expect(() => zqDecompress(new Map([["a", packBE([1])]]), params(4), ctx)).toThrow(/modulus/);
  });

  it("throws on a d that a coefficient cannot hold", () => {
    // coeffBytes = 2 caps d at 16; ask for 17 and the compressed value would
    // silently lose its top bits on the way out.
    const inputs = new Map([
      ["a", packBE([1])],
      ["modulus", Q_BYTES],
    ]);
    expect(() => zqCompress(inputs, params(17), ctx)).toThrow(/params\.d/);
    expect(() => zqCompress(inputs, params(0), ctx)).toThrow(/params\.d/);
    expect(() => zqDecompress(inputs, params(17), ctx)).toThrow(/params\.d/);
  });

  it("throws on a byte length that is not a whole number of coefficients", () => {
    expect(() =>
      zqCompress(
        new Map([
          ["a", new Uint8Array([1, 2, 3])],
          ["modulus", Q_BYTES],
        ]),
        params(4),
        ctx,
      ),
    ).toThrow(/whole number/);
  });
});
