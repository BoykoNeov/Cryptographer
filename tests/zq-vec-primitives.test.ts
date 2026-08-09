/**
 * The Z_q vector primitives — `zq-vec-add@1`, `zq-vec-sub@1`,
 * `zq-vec-mul-scalar@1` (ML-KEM P1, `docs/plans/unified-stargazing-quasar.md`).
 *
 * These are the whole arithmetic surface of the number-theoretic transform, so
 * the properties checked here are the ones the transform's correctness rests on:
 *
 *  1. **Element-wise, never cross-element.** Perturbing coefficient `i` of an
 *     input must change coefficient `i` of the output and NOTHING else. This is
 *     the property that separates these steps from `add-mod@1` / `mod-mul@1`,
 *     which would read the same 512 bytes as one 4096-bit integer.
 *  2. **Results land in [0, q).** In particular a subtraction that would go
 *     negative wraps up rather than borrowing into the neighbouring
 *     coefficient — the failure that would silently corrupt the transform.
 *  3. **Full precision before reduction.** `a·s` for two values near q exceeds
 *     what a coefficient holds; reducing the operands and letting the product
 *     wrap gives a different, wrong answer.
 *  4. **The byte-order param is real.** Flipping `littleEndian` must change the
 *     numbers, or it is decoration.
 *
 * The reference arithmetic below is four lines of `BigInt` written from the
 * definitions, sharing no code with the executors.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { Json, StepContext } from "@/core/types";
import { zqVecAdd } from "@/steps/zq-vec-add";
import { zqVecMulScalar } from "@/steps/zq-vec-mul-scalar";
import { zqVecSub } from "@/steps/zq-vec-sub";
import { describe, expect, it } from "vitest";

const ctx: StepContext = { stepId: "t", path: [], aux: new Map() };
const Q = 3329;
const Q_BYTES = new Uint8Array([0x0d, 0x01]);
const BE: Json = { coeffBytes: 2, littleEndian: false };
const LE: Json = { coeffBytes: 2, littleEndian: true };

/** Pack coefficients big-endian, 2 bytes each. */
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
  for (let i = 0; i < bytes.length; i += 2) {
    out.push((bytes[i] as number) * 256 + (bytes[i + 1] as number));
  }
  return out;
};

/** A deterministic spread of coefficients across the whole range [0, q). */
const sample = (n: number, offset: number): number[] =>
  Array.from({ length: n }, (_, i) => (i * 719 + offset * 293) % Q);

describe("zq-vec-add@1", () => {
  it("adds coefficient i to coefficient i and reduces mod q", () => {
    const a = sample(64, 0);
    const b = sample(64, 1);
    const out = zqVecAdd(
      new Map([
        ["a", packBE(a)],
        ["b", packBE(b)],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    expect(out).toBeDefined();
    expect(unpackBE(out as Uint8Array)).toEqual(a.map((x, i) => (x + (b[i] as number)) % Q));
  });

  it("every output coefficient lies in [0, q)", () => {
    // Operands deliberately at the top of the range, so every sum crosses q.
    const a = Array.from({ length: 32 }, () => Q - 1);
    const out = zqVecAdd(
      new Map([
        ["a", packBE(a)],
        ["b", packBE(a)],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    for (const c of unpackBE(out as Uint8Array)) {
      expect(c).toBeGreaterThanOrEqual(0);
      expect(c).toBeLessThan(Q);
    }
    // (q-1) + (q-1) mod q = q - 2.
    expect(unpackBE(out as Uint8Array)[0]).toBe(Q - 2);
  });

  it("a length mismatch between a and b throws rather than padding", () => {
    expect(() =>
      zqVecAdd(
        new Map([
          ["a", packBE([1, 2, 3])],
          ["b", packBE([1, 2])],
          ["modulus", Q_BYTES],
        ]),
        BE,
        ctx,
      ),
    ).toThrow(/same length/);
  });
});

describe("zq-vec-sub@1", () => {
  it("subtracts coefficient i from coefficient i and reduces mod q", () => {
    const a = sample(64, 0);
    const b = sample(64, 1);
    const out = zqVecSub(
      new Map([
        ["a", packBE(a)],
        ["b", packBE(b)],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    expect(unpackBE(out as Uint8Array)).toEqual(
      a.map((x, i) => (((x - (b[i] as number)) % Q) + Q) % Q),
    );
  });

  it("a negative difference wraps up by q instead of borrowing", () => {
    // 3 - 5 = -2, which in Z_3329 is 3327. If this ever produced a borrow into
    // the neighbouring coefficient, the transform would be silently corrupt.
    const out = zqVecSub(
      new Map([
        ["a", packBE([3, 100, 0])],
        ["b", packBE([5, 1, 1])],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    expect(unpackBE(out as Uint8Array)).toEqual([3327, 99, 3328]);
  });
});

describe("zq-vec-mul-scalar@1", () => {
  it("multiplies every coefficient by the scalar and reduces mod q", () => {
    const a = sample(64, 0);
    const s = 1729; // zeta^1 — the transform's first twiddle factor
    const out = zqVecMulScalar(
      new Map([
        ["a", packBE(a)],
        ["scalar", packBE([s])],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    expect(unpackBE(out as Uint8Array)).toEqual(a.map((x) => (x * s) % Q));
  });

  it("forms the product at full precision — reducing operands first would differ", () => {
    // 3328 · 3328 = 11,075,584, far past what a 2-byte coefficient holds.
    // Correct answer: 11075584 mod 3329 = 1.
    const out = zqVecMulScalar(
      new Map([
        ["a", packBE([Q - 1])],
        ["scalar", packBE([Q - 1])],
        ["modulus", Q_BYTES],
      ]),
      BE,
      ctx,
    ).get("output");
    expect(unpackBE(out as Uint8Array)).toEqual([1]);
    // The wrong-but-plausible implementation — truncate the product to 16 bits
    // and then reduce — gives something else entirely. Asserted so the test
    // documents what it is ruling out.
    expect((11075584 & 0xffff) % Q).not.toBe(1);
  });

  it("rejects a scalar port that is not exactly one coefficient wide", () => {
    expect(() =>
      zqVecMulScalar(
        new Map([
          ["a", packBE([1, 2])],
          ["scalar", packBE([1, 2])],
          ["modulus", Q_BYTES],
        ]),
        BE,
        ctx,
      ),
    ).toThrow(/exactly one 2-byte coefficient/);
  });
});

describe("the family's shared contracts", () => {
  it("is element-wise: perturbing coefficient i changes only coefficient i", () => {
    const a = sample(16, 0);
    const b = sample(16, 1);
    const inputs = new Map([
      ["a", packBE(a)],
      ["b", packBE(b)],
      ["modulus", Q_BYTES],
    ]);
    const base = unpackBE(zqVecAdd(inputs, BE, ctx).get("output") as Uint8Array);
    for (let i = 0; i < a.length; i++) {
      const perturbed = [...a];
      perturbed[i] = ((a[i] as number) + 1) % Q;
      const out = unpackBE(
        zqVecAdd(
          new Map([
            ["a", packBE(perturbed)],
            ["b", packBE(b)],
            ["modulus", Q_BYTES],
          ]),
          BE,
          ctx,
        ).get("output") as Uint8Array,
      );
      const changed = out.map((v, j) => (v === base[j] ? null : j)).filter((j) => j !== null);
      expect(changed).toEqual([i]);
    }
  });

  it("littleEndian is a real parameter, not decoration", () => {
    // The operand must be one whose two readings differ ACROSS the modulus, or
    // the byte order cancels: reading LE and writing LE is an involution, so a
    // value below q would come back out unchanged under either convention and
    // the test would pass on a param that did nothing.
    //
    // Bytes 0x0C 0xFF read big-endian are 3327 (already reduced). Read
    // little-endian they are 0xFF0C = 65292, which reduces to 2041 = 0x07F9,
    // written back low byte first as 0xF9 0x07.
    const inputs = new Map([
      ["a", new Uint8Array([0x0c, 0xff])],
      ["b", packBE([0])],
      ["modulus", Q_BYTES],
    ]);
    const be = zqVecAdd(inputs, BE, ctx).get("output") as Uint8Array;
    const le = zqVecAdd(inputs, LE, ctx).get("output") as Uint8Array;
    expect(Array.from(be)).toEqual([0x0c, 0xff]);
    expect(Array.from(le)).toEqual([0xf9, 0x07]);
  });

  it("rejects a modulus too wide for the declared coefficient width", () => {
    // 70000 needs 17 bits; residues would silently lose their top bits.
    expect(() =>
      zqVecAdd(
        new Map([
          ["a", packBE([1])],
          ["b", packBE([1])],
          ["modulus", new Uint8Array([0x01, 0x11, 0x70])],
        ]),
        BE,
        ctx,
      ),
    ).toThrow(/does not fit/);
  });

  it("rejects a vector whose length is not a whole number of coefficients", () => {
    expect(() =>
      zqVecAdd(
        new Map([
          ["a", new Uint8Array(5)],
          ["b", new Uint8Array(5)],
          ["modulus", Q_BYTES],
        ]),
        BE,
        ctx,
      ),
    ).toThrow(/whole number of 2-byte coefficients/);
  });

  it("all three are registered with docs", () => {
    const registry = buildDefaultRegistry();
    for (const t of ["zq-vec-add@1", "zq-vec-sub@1", "zq-vec-mul-scalar@1"]) {
      expect(registry.types()).toContain(t);
      expect(registry.getDoc(t)?.name).toBeTruthy();
    }
  });
});
