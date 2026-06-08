/**
 * RSA Phase 4 — the traced extended-Euclid loop (decomposition of the
 * `mod-inverse@1` oracle). `docs/plans/shimmying-booping-moth.md`.
 *
 * **This is the load-bearing gate, and it is deliberately written to drive the
 * real `eea-step` executor** — not a re-implementation — because the design's
 * one genuinely silent failure mode is an unroll count `K = eeaMaxIterations(W)`
 * that is too SMALL: every other RSA test fixes the key (e=17, φ=3120 → always 4
 * iterations) and only varies the message, so a too-small K would produce a
 * wrong `d` for some USER-entered key while the whole suite stayed green
 * (`feedback_visual_smoke_vs_property_tests`).
 *
 * Euclid's worst case is consecutive Fibonacci numbers (Lamé's theorem). So we
 * drive the chain with the largest consecutive Fibonacci pair representable at
 * the working width, plus a batch of random coprime pairs, and assert (a) the
 * remainder reaches 0 strictly within K rungs and (b) the extracted coefficient
 * equals the independent `modInverseBigInt` oracle. If K is ever too small this
 * test fails — it is what PINS the bound.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildRsaSpec } from "@/ciphers/rsa";
import { bigIntToBytes, bytesToBigInt } from "@/core/big-int-codec";
import { runSpec } from "@/core/runtime";
import type { StepContext } from "@/core/types";
import { eeaExtract } from "@/steps/eea-extract";
import { eeaMaxIterations, eeaStep } from "@/steps/eea-step";
import { modInverseBigInt } from "@/steps/mod-inverse";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "eea", path: [], aux: new Map() };

/** Drive the REAL eea-step executor as a fixed K-rung chain seeded from
 *  (r=m, newR=a, t=0, newT=1), the standard EEA seeds. Returns the rung index
 *  at which the remainder first hit 0 (−1 if it never did within K) and the
 *  settled (r, t) slot the terminal extract would read. */
const runChain = (
  a: bigint,
  m: bigint,
  width: number,
  K: number,
): { convergedAt: number; r: bigint; t: bigint } => {
  const b = (v: bigint): Uint8Array => bigIntToBytes(v, width);
  const intOf = (u: Uint8Array | undefined): bigint => bytesToBigInt(u as Uint8Array);
  let r = b(m);
  let newR = b(a % m); // newR seed normalized into [0, m) — what the chain settles to
  let t = b(0n);
  let newT = b(1n);
  let convergedAt = -1;
  for (let i = 0; i < K; i++) {
    const out = eeaStep(
      new Map([
        ["r", r],
        ["newR", newR],
        ["t", t],
        ["newT", newT],
        ["modulus", b(m)],
      ]),
      {},
      ctx,
    );
    r = out.get("r") as Uint8Array;
    newR = out.get("newR") as Uint8Array;
    t = out.get("t") as Uint8Array;
    newT = out.get("newT") as Uint8Array;
    if (convergedAt === -1 && intOf(newR) === 0n) convergedAt = i;
  }
  return { convergedAt, r: intOf(r), t: intOf(t) };
};

/** Largest consecutive Fibonacci pair (a < m) with both < 2^(8·W) — Euclid's
 *  worst case at this width. For W=2: (F₂₃, F₂₄) = (28657, 46368). */
const largestFibPairUnder = (limit: bigint): { a: bigint; m: bigint } => {
  let prev = 1n;
  let cur = 1n;
  while (true) {
    const next = prev + cur;
    if (next >= limit) break;
    prev = cur;
    cur = next;
  }
  return { a: prev, m: cur }; // prev < cur, both < limit, gcd = 1
};

describe("eeaMaxIterations bound", () => {
  it("is the Lamé worst-case bound + margin (W=2 ⇒ 26)", () => {
    // ⌈1.4404 · 8 · 2⌉ + 2 = ⌈23.05⌉ + 2 = 24 + 2 = 26.
    expect(eeaMaxIterations(2)).toBe(26);
    // Monotone in the width, and always covers SHA-class widths too.
    expect(eeaMaxIterations(1)).toBe(14);
    expect(eeaMaxIterations(4)).toBe(49);
  });
});

describe("eea-step chain — Euclid worst case (the K-bound gate)", () => {
  for (const W of [1, 2, 3]) {
    it(`converges within K and matches the oracle at the Fibonacci worst case (W=${W})`, () => {
      const K = eeaMaxIterations(W);
      const { a, m } = largestFibPairUnder(1n << BigInt(8 * W));
      const { convergedAt, r, t } = runChain(a, m, W, K);
      // Converges, AND with the +2 headroom intact: a RAW e ≥ φ seed (which the
      // spec uses — newR0 = the unreduced `load-e` output) reaches newR=0 at
      // convergedAt+2 (one q=0 swap step + one reduction step to reach the
      // normalized state), so `convergedAt + 2 < K` is exactly the condition the
      // worst-case e ≥ φ key still fits the unrolled chain. Pinning it here stops
      // a future K-tightening from silently erasing that margin (the spec-level
      // e ≥ φ test below exercises the raw seed end-to-end).
      expect(
        convergedAt,
        `Fibonacci pair (${a}, ${m}) did not converge within K=${K}`,
      ).toBeGreaterThanOrEqual(0);
      expect(
        convergedAt + 2,
        `Fibonacci pair (${a}, ${m}) leaves no +2 headroom for a raw e ≥ φ seed (convergedAt=${convergedAt}, K=${K})`,
      ).toBeLessThan(K);
      // gcd of consecutive Fibonacci is 1, and the coefficient is the inverse.
      expect(r).toBe(1n);
      expect(t).toBe(modInverseBigInt(a, m));
    });
  }
});

describe("eea-step chain — random coprime pairs match modInverseBigInt", () => {
  it("derives the inverse for 200 random coprime pairs (W=2)", () => {
    const W = 2;
    const K = eeaMaxIterations(W);
    // Deterministic LCG so failures reproduce (no flaky randomness).
    let seed = 0x9e3779b9;
    const nextU16 = (): bigint => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return BigInt((seed >>> 8) % 65536);
    };
    const gcd = (x: bigint, y: bigint): bigint => (y === 0n ? x : gcd(y, x % y));
    let checked = 0;
    for (let tries = 0; tries < 4000 && checked < 200; tries++) {
      const m = nextU16();
      const a = nextU16();
      if (m < 2n || a < 1n || a >= m) continue;
      if (gcd(a, m) !== 1n) continue; // only invertible pairs have an inverse
      const { convergedAt, r, t } = runChain(a, m, W, K);
      expect(convergedAt, `pair (${a}, ${m}) overran K=${K}`).toBeGreaterThanOrEqual(0);
      expect(r).toBe(1n);
      expect(t).toBe(modInverseBigInt(a, m));
      checked++;
    }
    // Make sure the loop actually exercised the target count (guards a bug that
    // silently skips every pair).
    expect(checked).toBe(200);
  });
});

describe("eea-step — per-iteration recurrence (default key 17 mod 3120)", () => {
  it("matches the textbook division steps and reduces the coefficient mod φ", () => {
    const W = 2;
    const b = (v: bigint): Uint8Array => bigIntToBytes(v, W);
    const intOf = (u: Uint8Array | undefined): bigint => bytesToBigInt(u as Uint8Array);
    const step = (r: bigint, newR: bigint, t: bigint, newT: bigint) =>
      eeaStep(
        new Map([
          ["r", b(r)],
          ["newR", b(newR)],
          ["t", b(t)],
          ["newT", b(newT)],
          ["modulus", b(3120n)],
        ]),
        {},
        ctx,
      );
    // Seeds: r=3120, newR=17, t=0, newT=1.
    let out = step(3120n, 17n, 0n, 1n);
    // q = 183, newR' = 9, newT' = (0 − 183·1) mod 3120 = 2937 (= −183 reduced).
    expect(intOf(out.get("r"))).toBe(17n);
    expect(intOf(out.get("newR"))).toBe(9n);
    expect(intOf(out.get("t"))).toBe(1n);
    expect(intOf(out.get("newT"))).toBe(2937n);
    out = step(17n, 9n, 1n, 2937n); // q=1 → newR'=8, newT'=(1−2937) mod 3120 = 184
    expect(intOf(out.get("newR"))).toBe(8n);
    expect(intOf(out.get("newT"))).toBe(184n);
    out = step(9n, 8n, 2937n, 184n); // q=1 → newR'=1, newT'=(2937−184) mod 3120 = 2753
    expect(intOf(out.get("newR"))).toBe(1n);
    expect(intOf(out.get("newT"))).toBe(2753n);
    out = step(8n, 1n, 184n, 2753n); // q=8 → newR'=0 (DONE), r'=1 (gcd), t'=2753 (=d)
    expect(intOf(out.get("newR"))).toBe(0n);
    expect(intOf(out.get("r"))).toBe(1n);
    expect(intOf(out.get("t"))).toBe(2753n);
  });

  it("is an identity once newR = 0 (trailing rungs carry forward)", () => {
    const W = 2;
    const b = (v: bigint): Uint8Array => bigIntToBytes(v, W);
    const intOf = (u: Uint8Array | undefined): bigint => bytesToBigInt(u as Uint8Array);
    // The settled tuple (r=1, newR=0, t=2753, newT=0) must pass through unchanged.
    const out = eeaStep(
      new Map([
        ["r", b(1n)],
        ["newR", b(0n)],
        ["t", b(2753n)],
        ["newT", b(0n)],
        ["modulus", b(3120n)],
      ]),
      {},
      ctx,
    );
    expect(intOf(out.get("r"))).toBe(1n);
    expect(intOf(out.get("newR"))).toBe(0n);
    expect(intOf(out.get("t"))).toBe(2753n);
    expect(intOf(out.get("newT"))).toBe(0n);
  });
});

describe("eea-extract — gcd gate", () => {
  const b = (v: bigint): Uint8Array => bigIntToBytes(v, 2);
  it("emits the coefficient as the inverse when gcd = 1", () => {
    const out = eeaExtract(
      new Map([
        ["gcd", b(1n)],
        ["value", b(2753n)],
      ]),
      {},
      ctx,
    );
    expect(bytesToBigInt(out.get("output") as Uint8Array)).toBe(2753n);
  });
  it("throws 'not invertible' when gcd ≠ 1 (e and φ share a factor)", () => {
    // The classic failure: a non-1 gcd means no inverse exists.
    expect(() =>
      eeaExtract(
        new Map([
          ["gcd", b(6n)],
          ["value", b(0n)],
        ]),
        {},
        ctx,
      ),
    ).toThrow(/not invertible/);
  });
  it("reads the (r, t) slot, NOT (newR, newT) — passing the settled value through", () => {
    // eea-extract takes `gcd` (=final r) and `value` (=final t); it must not
    // touch newR/newT. Here gcd=1, value=2753 → output 2753 verbatim.
    const out = eeaExtract(
      new Map([
        ["gcd", b(1n)],
        ["value", b(2753n)],
      ]),
      {},
      ctx,
    );
    expect(bytesToBigInt(out.get("output") as Uint8Array)).toBe(2753n);
  });
});

describe("RSA spec-level — the chain seeds RAW e, so e ≥ φ must still derive d", () => {
  // The unit chain above seeds `newR = a % m`; the SPEC seeds `newR0 = the
  // unreduced `load-e` output`, so e ≥ φ is the one path those tests never drive.
  // It is trivially reachable — a user edits the `e` constant; `e = φ+1` is always
  // coprime to φ — and the raw seed costs ~2 extra leading Euclid steps (what the
  // +2 in K absorbs). Drive the ACTUAL spec with e ≥ φ and assert the derived `d`
  // frame matches the independent oracle (which reduces e mod φ internally).
  const W = 2;
  const registry = buildDefaultRegistry();
  const phi = 3120n; // φ for the default p=61, q=53
  const gcd = (x: bigint, y: bigint): bigint => (y === 0n ? x : gcd(y, x % y));
  // φ+1 (degenerate, d=1); φ+17 (d=2753); a mid value; one near the 2-byte ceiling.
  for (const e of [3121n, 3137n, 6359n, 62417n]) {
    if (gcd(e, phi) !== 1n) continue; // only coprime e has an inverse
    if (e >= 1n << BigInt(8 * W)) continue; // must fit the working width
    it(`derives d for e=${e} (≥ φ=${phi}) byte-equal to modInverseBigInt`, () => {
      const base = buildRsaSpec("encrypt", W);
      const spec = {
        ...base,
        cipherConstants: { ...base.cipherConstants, e: bigIntToBytes(e, W) },
      };
      const trace = runSpec(spec, registry, {
        initialState: { shape: "bytes", bytes: bigIntToBytes(2n, W) },
      });
      const dFrame = trace.frames.find((f) => f.stepId === "d");
      if (!dFrame) throw new Error('no "d" frame in the trace');
      const d = bytesToBigInt(dFrame.portOutputs?.get("output") as Uint8Array);
      expect(d).toBe(modInverseBigInt(e, phi));
    });
  }
});
