/**
 * The ML-DSA packers — BitPack / BitUnpack, w1Encode, HintBitPack /
 * HintBitUnpack (P2 of `docs/plans/refactored-petting-tide.md`).
 *
 * The byte-exact evidence is `tests/ml-dsa-44-oracle.test.ts`: real keys and
 * signatures only come out right if every packer is. This file pins the
 * properties a learner reads off the step descriptions, each with the edge
 * that would break it — the flip `b − w`, the spare bit patterns the unpacker
 * deliberately does not reject, w1Encode's width following γ2, and every one
 * of HintBitUnpack's three refusal rules as a FLAG rather than a throw.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_44_GAMMA1,
  ML_DSA_44_GAMMA2,
  ML_DSA_44_OMEGA,
  ML_DSA_Q,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
  packMlDsaPoly,
  unpackMlDsaPoly,
} from "@/ciphers/mldsa-constants";
import { modPm, toResidue } from "@/core/ml-dsa-arith";
import type { Json } from "@/core/types";
import { describe, expect, it } from "vitest";

const q = ML_DSA_Q;
const P = { coeffBytes: 4, littleEndian: false } as const;
const registry = buildDefaultRegistry();
const c4 = mlDsaCoeffBytes;

const run = (
  type: string,
  ports: Record<string, Uint8Array>,
  params: Record<string, Json> = P,
): ReadonlyMap<string, Uint8Array> => {
  const def = registry.getRegistration(type);
  if (def === undefined) throw new Error(`${type} is not registered`);
  return def.executor(new Map(Object.entries(ports)), params, {} as never);
};
const out = (m: ReadonlyMap<string, Uint8Array>, name = "output"): Uint8Array => {
  const v = m.get(name);
  if (v === undefined) throw new Error(`no output port ${name}`);
  return v;
};

const residues = (signed: number[]): Uint8Array =>
  packMlDsaPoly(signed.map((v) => toResidue(v, q)));
const signedOf = (bytes: Uint8Array): number[] => unpackMlDsaPoly(bytes).map((v) => modPm(v, q));

const pack = (signed: number[], a: number, b: number) =>
  out(
    run("ml-dsa.bit-pack@1", {
      a: residues(signed),
      lower: c4(a),
      upper: c4(b),
      modulus: ML_DSA_Q_BYTES,
    }),
  );
const unpack = (bytes: Uint8Array, a: number, b: number) =>
  signedOf(
    out(
      run("ml-dsa.bit-unpack@1", { a: bytes, lower: c4(a), upper: c4(b), modulus: ML_DSA_Q_BYTES }),
    ),
  );

describe("ml-dsa.bit-pack@1 / bit-unpack@1 — a signed range, flipped", () => {
  it("stores w as b − w, low bit first: [2, 0, −2] in [−2, 2] is 0, 2, 4", () => {
    // 3 bits each: 000 | 010 | 100, packed LSB first → byte 0 = 0b0_100_010_000
    // over 9 bits, so we pad to 8 values to get whole bytes.
    const values = [2, 0, -2, 2, 2, 2, 2, 2];
    const bytes = pack(values, 2, 2);
    expect(bytes.length).toBe(3);
    expect(bytes[0]).toBe(0b0001_0000); // value0 = 0 (bits 0–2), value1 = 2 (bits 3–5)
    expect(((bytes[0] as number) >> 6) | (((bytes[1] as number) & 1) << 2)).toBe(4); // value2 = 4
  });

  it("round-trips every range ML-DSA-44 uses", () => {
    const cases: [number, number][] = [
      [2, 2],
      [4095, 4096],
      [ML_DSA_44_GAMMA1 - 1, ML_DSA_44_GAMMA1],
    ];
    for (const [a, b] of cases) {
      const values = Array.from({ length: 256 }, (_, i) => ((i * 7919) % (a + b + 1)) - a);
      expect(unpack(pack(values, a, b), a, b), `[−${a}, ${b}]`).toEqual(values);
    }
  });

  it("uses exactly bitlen(a + b) bits: 3, 13 and 18 per coefficient", () => {
    expect(pack(new Array(256).fill(0), 2, 2).length).toBe(96);
    expect(pack(new Array(256).fill(0), 4095, 4096).length).toBe(416);
    expect(pack(new Array(256).fill(0), ML_DSA_44_GAMMA1 - 1, ML_DSA_44_GAMMA1).length).toBe(576);
  });

  it("refuses a value outside the range instead of truncating it", () => {
    expect(() => pack([3, 0, 0, 0, 0, 0, 0, 0], 2, 2)).toThrow(/outside the range/);
    expect(() => pack([-3, 0, 0, 0, 0, 0, 0, 0], 2, 2)).toThrow(/outside the range/);
    // A rejected signing candidate can sit up to β past z's range — the reason
    // P4 selects zeros before packing rather than relying on this step.
    expect(() =>
      pack([ML_DSA_44_GAMMA1 + 1, ...new Array(3).fill(0)], ML_DSA_44_GAMMA1 - 1, ML_DSA_44_GAMMA1),
    ).toThrow(/outside the range/);
  });

  it("does NOT reject the spare 3-bit patterns 5, 6, 7 — they unpack to −3, −4, −5, as FIPS 204's does", () => {
    // Eight values of 3 bits: 5, 6, 7, then zeros, packed LSB first.
    const bits = [5, 6, 7, 0, 0, 0, 0, 0];
    const bytes = new Uint8Array(3);
    bits.forEach((v, i) => {
      for (let j = 0; j < 3; j++) {
        if ((v >> j) & 1)
          bytes[(i * 3 + j) >> 3] = (bytes[(i * 3 + j) >> 3] as number) | (1 << ((i * 3 + j) & 7));
      }
    });
    expect(unpack(bytes, 2, 2).slice(0, 3)).toEqual([-3, -4, -5]);
  });
});

describe("ml-dsa.w1-encode@1 — the width follows γ2", () => {
  const encode = (values: number[], gamma2: number) =>
    out(
      run("ml-dsa.w1-encode@1", {
        a: packMlDsaPoly(values),
        gamma2: c4(gamma2),
        modulus: ML_DSA_Q_BYTES,
      }),
    );

  it("packs ML-DSA-44's 44 buckets in 6 bits: 256 coefficients → 192 bytes", () => {
    const values = Array.from({ length: 256 }, (_, i) => i % 44);
    const bytes = encode(values, ML_DSA_44_GAMMA2);
    expect(bytes.length).toBe(192);
    // Same stream as the unsigned packer at d = 6.
    expect(bytes).toEqual(
      out(
        run(
          "zq-byte-encode@1",
          { a: packMlDsaPoly(values), modulus: ML_DSA_Q_BYTES },
          { ...P, d: 6 },
        ),
      ),
    );
  });

  it("packs ML-DSA-65/87's 16 buckets in 4 bits when γ2 = (q − 1)/32", () => {
    expect(encode(new Array(256).fill(15), (q - 1) / 32).length).toBe(128);
  });

  it("refuses an index that is not a real bucket", () => {
    expect(() => encode([44, ...new Array(255).fill(0)], ML_DSA_44_GAMMA2)).toThrow(/bucket index/);
  });
});

describe("ml-dsa.hint-pack@1 / hint-unpack@1 — positions, and three refusal rules", () => {
  const OMEGA = new Uint8Array([ML_DSA_44_OMEGA]);
  const hintWith = (positions: [number, number][]): number[] => {
    const h = new Array<number>(1024).fill(0);
    for (const [poly, j] of positions) h[poly * 256 + j] = 1;
    return h;
  };
  const packHint = (h: number[]) =>
    out(run("ml-dsa.hint-pack@1", { h: packMlDsaPoly(h), omega: OMEGA }));
  const unpackHint = (y: Uint8Array) => {
    const r = run("ml-dsa.hint-unpack@1", { input: y, omega: OMEGA });
    return { h: unpackMlDsaPoly(out(r)), valid: out(r, "valid")[0] };
  };

  const h = hintWith([
    [0, 3],
    [0, 200],
    [2, 0],
    [2, 1],
    [3, 255],
  ]);
  const y = packHint(h);

  it("lays out positions then running totals, ω + k = 84 bytes", () => {
    expect(y.length).toBe(84);
    expect([...y.subarray(0, 6)]).toEqual([3, 200, 0, 1, 255, 0]);
    expect([...y.subarray(80)]).toEqual([2, 2, 4, 5]);
  });

  it("round-trips", () => {
    expect(unpackHint(y)).toEqual({ h, valid: 1 });
  });

  const refused = (edit: (b: Uint8Array) => void) => {
    const bad = new Uint8Array(y);
    edit(bad);
    return unpackHint(bad);
  };

  it("rule 1: a running total that goes down — flagged, output all zeros", () => {
    const r = refused((b) => {
      b[81] = 1; // below polynomial 0's total of 2
    });
    expect(r.valid).toBe(0);
    expect(r.h.every((v) => v === 0)).toBe(true);
  });

  it("rule 1: a running total past ω", () => {
    expect(
      refused((b) => {
        b[83] = 81;
      }).valid,
    ).toBe(0);
  });

  it("rule 2: positions within a polynomial not strictly increasing (including a repeat)", () => {
    expect(
      refused((b) => {
        b[0] = 200;
        b[1] = 3;
      }).valid,
    ).toBe(0);
    expect(
      refused((b) => {
        b[1] = 3;
      }).valid,
    ).toBe(0);
  });

  it("rule 3: a non-zero byte after the last listed position — the one usually missed", () => {
    expect(
      refused((b) => {
        b[79] = 1;
      }).valid,
    ).toBe(0);
  });

  it("positions that DROP across a polynomial boundary are fine — order is per polynomial", () => {
    // Polynomial 0 ends at 200, polynomial 2 starts at 0. Not a violation.
    expect(unpackHint(y).valid).toBe(1);
  });

  it("pack refuses more than ω ones rather than overflowing into the totals", () => {
    const tooMany = hintWith(
      Array.from({ length: 81 }, (_, i) => [Math.floor(i / 64), i % 64] as [number, number]),
    );
    expect(() => packHint(tooMany)).toThrow(/more than ω/);
    // Exactly ω fits.
    const full = hintWith(
      Array.from({ length: 80 }, (_, i) => [Math.floor(i / 64), i % 64] as [number, number]),
    );
    expect(unpackHint(packHint(full)).valid).toBe(1);
  });
});
