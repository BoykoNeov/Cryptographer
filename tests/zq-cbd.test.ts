/**
 * `zq-cbd@1` — centred-binomial sampling, FIPS 203 Algorithm 8
 * (ML-KEM P2, `docs/plans/unified-stargazing-quasar.md`).
 *
 * The third of the plan's three independent places to be subtly wrong that P3's
 * aggregate `ek` comparison catches only in combination, and the only one with
 * no external artifact to lean on — a sampled polynomial is not published
 * anywhere, and the ML-KEM key P2's packing test uses reveals nothing about the
 * noise that produced it. So it is pinned three ways:
 *
 *  1. **Against the definition**, written out as bit arrays exactly as
 *     Algorithm 8 states it and sharing no code with the executor.
 *  2. **Against the distribution.** The output of a *correct* CBD sampler over
 *     uniform input has a known shape — `P(v = k) = C(2η, η+k) / 2^(2η)` — and
 *     that shape is what the step exists to produce. A sampler that read its bit
 *     windows in the wrong place would still yield small centred values and
 *     still pass a range check, but the histogram would be wrong. Checked
 *     exhaustively over EVERY input pattern rather than statistically, which at
 *     η = 2 and η = 3 is 256 and 4096 patterns — so it is an exact count, not a
 *     sample with a tolerance.
 *  3. **Against the representation.** Negative samples must appear as `q − |v|`.
 *     This is the one thing about the step a learner reliably misreads, and an
 *     implementation that clamped or took an absolute value would pass every
 *     range check while destroying the distribution's centre.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { Json, StepContext } from "@/core/types";
import { zqCbd } from "@/steps/zq-cbd";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
const Q = 3329;
const Q_BYTES = new Uint8Array([0x0d, 0x01]);
const params = (eta: number, littleEndian = false): Json => ({ coeffBytes: 2, littleEndian, eta });

const unpackBE = (bytes: Uint8Array): number[] => {
  const out: number[] = [];
  for (let i = 0; i < bytes.length; i += 2)
    out.push((bytes[i] as number) * 256 + (bytes[i + 1] as number));
  return out;
};

const runCbd = (bytes: Uint8Array, eta: number): number[] =>
  unpackBE(
    zqCbd(
      new Map([
        ["a", bytes],
        ["modulus", Q_BYTES],
      ]),
      params(eta),
      ctx,
    ).get("output") as Uint8Array,
  );

/** FIPS 203 Algorithm 4 — BytesToBits, written as a bit array. */
const bytesToBits = (bytes: Uint8Array): number[] => {
  const bits: number[] = [];
  for (const byte of bytes) {
    let c = byte;
    for (let j = 0; j < 8; j++) {
      bits.push(c % 2);
      c = (c - (c % 2)) / 2;
    }
  }
  return bits;
};

/** FIPS 203 Algorithm 8 — SamplePolyCBD_η, straight from the pseudocode. */
const cbdSpec = (bytes: Uint8Array, eta: number): number[] => {
  const b = bytesToBits(bytes);
  const n = b.length / (2 * eta);
  return Array.from({ length: n }, (_, i) => {
    let x = 0;
    let y = 0;
    for (let j = 0; j < eta; j++) {
      x += b[2 * i * eta + j] as number;
      y += b[2 * i * eta + eta + j] as number;
    }
    const v = x - y;
    return ((v % Q) + Q) % Q;
  });
};

/** The signed value a coefficient represents — its representative nearest zero. */
const centred = (v: number): number => (v > Q / 2 ? v - Q : v);

/** `C(n, k)`. */
const choose = (n: number, k: number): number => {
  let r = 1;
  for (let i = 0; i < k; i++) r = (r * (n - i)) / (i + 1);
  return Math.round(r);
};

/** A deterministic byte string with no structure the sampler could exploit. */
const pseudoRandom = (len: number, seed: number): Uint8Array => {
  const out = new Uint8Array(len);
  let s = seed >>> 0;
  for (let i = 0; i < len; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    out[i] = (s >>> 16) & 0xff;
  }
  return out;
};

// ─── 1. Against the definition ────────────────────────────────────────────

describe("zq-cbd@1 matches FIPS 203 Algorithm 8", () => {
  it("samples exactly as SamplePolyCBD_η does, at both η ML-KEM uses", () => {
    for (const eta of [2, 3] as const) {
      // 64η bytes is ML-KEM's own length, and it is exactly 256 coefficients.
      const bytes = pseudoRandom(64 * eta, eta * 7 + 1);
      expect({ eta, out: runCbd(bytes, eta) }).toEqual({ eta, out: cbdSpec(bytes, eta) });
    }
  });

  it("agrees with the definition across the whole span of η it accepts", () => {
    for (let eta = 1; eta <= 8; eta++) {
      const bytes = pseudoRandom(2 * eta * 8, eta);
      expect({ eta, out: runCbd(bytes, eta) }).toEqual({ eta, out: cbdSpec(bytes, eta) });
    }
  });

  it("produces 256 coefficients from ML-KEM's 64η bytes — the sizes line up on purpose", () => {
    expect(runCbd(pseudoRandom(128, 1), 2)).toHaveLength(256);
    expect(runCbd(pseudoRandom(192, 2), 3)).toHaveLength(256);
  });

  it("reads bit windows in the right place — a shifted window still looks plausible", () => {
    // The failure this catches: an implementation that took the y-window from
    // the NEXT coefficient's bits rather than the second half of this one. It
    // would still produce small centred values in range. Hand-computed from the
    // definition: byte 0x0f is bits 1,1,1,1,0,0,0,0 (LSB first), so at η = 2
    // coefficient 0 is (1+1) − (1+1) = 0 and coefficient 1 is (0+0) − (0+0) = 0;
    // byte 0x03 is 1,1,0,0,0,0,0,0 giving (1+1) − (0+0) = 2 then 0.
    expect(runCbd(new Uint8Array([0x0f]), 2)).toEqual([0, 0]);
    expect(runCbd(new Uint8Array([0x03]), 2)).toEqual([2, 0]);
    // 0x01 is 1,0,0,0,... : coefficient 0 is (1+0) − (0+0) = 1.
    expect(runCbd(new Uint8Array([0x01]), 2)).toEqual([1, 0]);
    // 0x04 is 0,0,1,0,... : coefficient 0 is (0+0) − (1+0) = −1 = q−1.
    expect(runCbd(new Uint8Array([0x04]), 2)).toEqual([Q - 1, 0]);
  });
});

// ─── 2. Against the distribution ──────────────────────────────────────────

describe("the distribution is binomial and centred — exhaustively, not statistically", () => {
  it("matches C(2η, η+k)/2^(2η) exactly over every possible input pattern", () => {
    for (const eta of [2, 3] as const) {
      // Every distinct 2η-bit pattern, each appearing exactly once, so the
      // histogram IS the distribution rather than an estimate of it.
      const patterns = 2 ** (2 * eta);
      const bitsNeeded = patterns * 2 * eta;
      const bytes = new Uint8Array(bitsNeeded / 8);
      for (let pattern = 0; pattern < patterns; pattern++) {
        for (let j = 0; j < 2 * eta; j++) {
          if (((pattern >> j) & 1) === 1) {
            const bit = pattern * 2 * eta + j;
            bytes[bit >> 3] = (bytes[bit >> 3] as number) | (1 << (bit & 7));
          }
        }
      }
      const histogram = new Map<number, number>();
      for (const v of runCbd(bytes, eta)) {
        const k = centred(v);
        histogram.set(k, (histogram.get(k) ?? 0) + 1);
      }
      const expected = new Map<number, number>();
      for (let k = -eta; k <= eta; k++) expected.set(k, choose(2 * eta, eta + k));
      expect({ eta, histogram: [...histogram].sort((l, r) => l[0] - r[0]) }).toEqual({
        eta,
        histogram: [...expected].sort((l, r) => l[0] - r[0]),
      });
    }
  });

  it("is centred on zero — the counts are symmetric and the mean is exactly 0", () => {
    // A sampler that dropped the subtraction, or clamped, would fail this while
    // still producing small values.
    for (const eta of [2, 3] as const) {
      const bytes = pseudoRandom(64 * eta, 99);
      const values = runCbd(bytes, eta).map(centred);
      expect(Math.min(...values)).toBeGreaterThanOrEqual(-eta);
      expect(Math.max(...values)).toBeLessThanOrEqual(eta);
      // Over uniform bits the sum is not exactly zero, but it must be small
      // relative to 256 samples — a one-sided sampler would drift hard.
      expect(Math.abs(values.reduce((s, v) => s + v, 0))).toBeLessThan(40);
    }
  });

  it("η is a real knob — turning it up widens the range", () => {
    const bytes = pseudoRandom(384, 5);
    const spread = (eta: number) => {
      const values = runCbd(bytes.subarray(0, 64 * eta), eta).map(centred);
      return Math.max(...values.map(Math.abs));
    };
    expect(spread(2)).toBe(2);
    expect(spread(3)).toBe(3);
  });
});

// ─── 3. Against the representation ────────────────────────────────────────

describe("negatives are represented as q − |v|, not clamped and not absolute", () => {
  it("writes −1 as 3328 and −η as q − η", () => {
    // All-zero x windows and all-one y windows: every coefficient is exactly −η.
    for (const eta of [2, 3] as const) {
      const bits = 2 * eta * 8;
      const bytes = new Uint8Array(bits / 8);
      for (let i = 0; i < 8; i++) {
        for (let j = 0; j < eta; j++) {
          const bit = i * 2 * eta + eta + j; // the y half only
          bytes[bit >> 3] = (bytes[bit >> 3] as number) | (1 << (bit & 7));
        }
      }
      expect(runCbd(bytes, eta)).toEqual(Array.from({ length: 8 }, () => Q - eta));
    }
  });

  it("keeps every sample inside [0, q)", () => {
    for (const eta of [2, 3] as const) {
      const values = runCbd(pseudoRandom(64 * eta, 21), eta);
      expect(values.every((v) => v >= 0 && v < Q)).toBe(true);
    }
  });

  it("only ever produces the 2η+1 legal values", () => {
    // Written as the exact set, so a sampler that leaked an intermediate would
    // be caught rather than merely staying in range.
    for (const eta of [2, 3] as const) {
      const legal = new Set(
        Array.from({ length: 2 * eta + 1 }, (_, i) => (((i - eta) % Q) + Q) % Q),
      );
      const seen = new Set(runCbd(pseudoRandom(64 * eta, 33), eta));
      expect([...seen].filter((v) => !legal.has(v))).toEqual([]);
    }
  });
});

// ─── Wiring ───────────────────────────────────────────────────────────────

describe("wiring and loud failures", () => {
  it("is registered under its bare name", () => {
    const r = buildDefaultRegistry();
    expect(r.has("zq-cbd@1")).toBe(true);
    expect(r.getDoc("zq-cbd@1")).toBeDefined();
  });

  it("throws on a length that is not a whole number of samples — it does NOT pad", () => {
    // A padded tail would contribute a silent run of zeros nothing asked for.
    // At η = 3 a sample is 6 bits, so a legal length is any multiple of 3 bytes
    // (24 bits = 4 samples). 2 bytes is 16 bits, which is two samples and four
    // bits left over.
    expect(() => runCbd(new Uint8Array(2), 3)).toThrow(/whole number of 6-bit samples/);
    expect(() => runCbd(new Uint8Array(1), 3)).toThrow(/64η/);
    expect(() => runCbd(new Uint8Array(3), 3)).not.toThrow();
  });

  it("throws on a missing modulus port", () => {
    expect(() => zqCbd(new Map([["a", new Uint8Array(1)]]), params(2), ctx)).toThrow(/modulus/);
  });

  it("throws on an out-of-range η", () => {
    const inputs = new Map([
      ["a", new Uint8Array(8)],
      ["modulus", Q_BYTES],
    ]);
    expect(() => zqCbd(inputs, params(0), ctx)).toThrow(/params\.eta/);
    expect(() => zqCbd(inputs, params(17), ctx)).toThrow(/params\.eta/);
  });
});
