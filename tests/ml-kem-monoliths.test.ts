/**
 * The five ML-KEM Keccak monoliths — direct executor tests.
 * ML-KEM P3, `docs/plans/unified-stargazing-quasar.md`.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * WHY THIS FILE EXISTS SEPARATELY FROM THE K-PKE KAT
 *
 * Only three of the five are load-bearing in P3: `sample-ntt`, `prf` and
 * `hash-g` are exercised end to end by `tests/k-pke-kat.test.ts`, which pins the
 * public key against Node 24's ML-KEM. `hash-h` and `kdf-j` belong to the FO
 * wrapper and no P3 spec calls them, so "it's covered by the KAT" would be
 * false for them. They are tested here against `node:crypto` directly.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * THE ORACLES
 *
 * 1. **`node:crypto`.** Node 22 ships SHA3-256/512 and SHAKE128/256, so the four
 *    hash-shaped monoliths have a live external oracle with no fixture needed.
 *    Note this is a genuinely independent sponge — OpenSSL's, not the app's.
 *
 * 2. **For `sample-ntt`, an independent rejection loop over Node's stream.**
 *    FIPS 203 publishes no SampleNTT test vector, so the check is: unpack the
 *    12-bit candidates out of a SHAKE128 stream produced by OpenSSL, run the
 *    rejection rule, and compare. The sponge under the two implementations is
 *    different code; only the (short, published) rejection rule is shared.
 *    Its aggregate oracle is the `ek` comparison in the K-PKE KAT.
 *
 * 3. **The squeeze-count distribution.** Measured, not hoped for — see the
 *    section at the bottom, and the note there about why "needs more than two
 *    blocks" would have been a vacuous assertion.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { ML_KEM_Q, Q_BYTES, unpackPoly } from "@/ciphers/mlkem-constants";
import type { Json, StepContext } from "@/core/types";
import { mlKemHashG } from "@/steps/ml-kem-hash-g";
import { mlKemHashH } from "@/steps/ml-kem-hash-h";
import { mlKemKdfJ } from "@/steps/ml-kem-kdf-j";
import { mlKemPrf } from "@/steps/ml-kem-prf";
import { mlKemSampleNtt } from "@/steps/ml-kem-sample-ntt";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-kem-768-seed-vectors.json";

// ─── Harness ──────────────────────────────────────────────────────────────

/** None of the five reads the context; the aux map stays empty. */
const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const one = (bytes: Uint8Array): ReadonlyMap<string, Uint8Array> => new Map([["input", bytes]]);

const outputOf = (outputs: ReadonlyMap<string, Uint8Array>, port = "output"): Uint8Array => {
  const value = outputs.get(port);
  if (value === undefined) throw new Error(`missing output port "${port}"`);
  return value;
};

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

/** The `zq-` family's params, shared by every lattice step. */
const VEC_PARAMS: Json = { coeffBytes: 2, littleEndian: false };

/** A handful of inputs that between them cross the rate boundary of every
 *  sponge involved (72, 136 and 168 bytes). */
const MESSAGES: readonly Uint8Array[] = [
  new Uint8Array(0),
  new Uint8Array([0]),
  new TextEncoder().encode("abc"),
  new Uint8Array(71).fill(0xa5),
  new Uint8Array(72).fill(0xa5),
  new Uint8Array(135).fill(0x5c),
  new Uint8Array(136).fill(0x5c),
  new Uint8Array(168).fill(0x11),
  new Uint8Array(500).fill(0xff),
];

// ─── 1. The four hash-shaped monoliths against node:crypto ────────────────

describe("G is SHA3-512 (FIPS 203 §4.1)", () => {
  for (const [i, m] of MESSAGES.entries()) {
    it(`matches node:crypto on message ${i} (${m.length} bytes)`, () => {
      const got = outputOf(mlKemHashG(one(m), {}, CTX));
      expect(got).toHaveLength(64);
      expect(hex(got)).toBe(createHash("sha3-512").update(m).digest("hex"));
    });
  }

  it("throws rather than hashing nothing when the input port is unwired", () => {
    // A missing port is a wiring error the learner can make in the editor; the
    // alternative — hashing the empty string — would be a plausible-looking
    // digest for a spec that is not connected.
    expect(() => mlKemHashG(new Map(), {}, CTX)).toThrow(/input/);
  });
});

describe("H is SHA3-256 (FIPS 203 §4.1)", () => {
  for (const [i, m] of MESSAGES.entries()) {
    it(`matches node:crypto on message ${i} (${m.length} bytes)`, () => {
      const got = outputOf(mlKemHashH(one(m), {}, CTX));
      expect(got).toHaveLength(32);
      expect(hex(got)).toBe(createHash("sha3-256").update(m).digest("hex"));
    });
  }

  it("agrees with the H(ek) the ML-KEM oracle itself computed", () => {
    // Not a second node:crypto call — this value was produced by OpenSSL's
    // ML-KEM implementation as part of a real expanded decapsulation key, so it
    // checks H against the thing that actually consumes it.
    for (const v of FIXTURE.vectors) {
      expect(hex(outputOf(mlKemHashH(one(unhex(v.ek)), {}, CTX)))).toBe(v.hEk);
    }
  });
});

describe("J is SHAKE256 squeezed to 32 bytes (FIPS 203 §4.1)", () => {
  for (const [i, m] of MESSAGES.entries()) {
    it(`matches node:crypto on message ${i} (${m.length} bytes)`, () => {
      const got = outputOf(mlKemKdfJ(one(m), {}, CTX));
      expect(got).toHaveLength(32);
      expect(hex(got)).toBe(createHash("shake256", { outputLength: 32 }).update(m).digest("hex"));
    });
  }

  it("differs from H on the same input", () => {
    // Both produce 32 bytes from one input, and a step wired to the wrong one of
    // the two would be invisible without this. SHA3-256 and SHAKE256 differ in
    // their domain-separation byte, not in their rate, so the outputs share
    // nothing.
    const m = MESSAGES[2] as Uint8Array;
    expect(hex(outputOf(mlKemKdfJ(one(m), {}, CTX)))).not.toBe(
      hex(outputOf(mlKemHashH(one(m), {}, CTX))),
    );
  });
});

describe("PRF is SHAKE256 squeezed to 64η bytes (FIPS 203 §4.1)", () => {
  const sigma = new Uint8Array(32).fill(0x2a);

  for (const eta of [2, 3]) {
    it(`matches node:crypto and yields 64·${eta} bytes`, () => {
      for (let n = 0; n < 6; n++) {
        const input = Uint8Array.from([...sigma, n]);
        const got = outputOf(mlKemPrf(one(input), { eta }, CTX));
        expect(got).toHaveLength(64 * eta);
        expect(hex(got)).toBe(
          createHash("shake256", { outputLength: 64 * eta })
            .update(input)
            .digest("hex"),
        );
      }
    });
  }

  it("gives six unrelated outputs for six counter values", () => {
    // The property the whole counter mechanism exists for: one 32-byte seed,
    // six independent noise polynomials.
    const seen = new Set<string>();
    for (let n = 0; n < 6; n++) {
      seen.add(hex(outputOf(mlKemPrf(one(Uint8Array.from([...sigma, n])), { eta: 2 }, CTX))));
    }
    expect(seen.size).toBe(6);
  });

  it("rejects an η the sampler could not consume", () => {
    expect(() => mlKemPrf(one(sigma), { eta: 0 }, CTX)).toThrow(/eta/);
    expect(() => mlKemPrf(one(sigma), {}, CTX)).toThrow(/eta/);
  });
});

// ─── 2. SampleNTT against an independent rejection loop ───────────────────

/**
 * FIPS 203 Algorithm 7, driven by OpenSSL's SHAKE128 rather than the app's.
 *
 * Deliberately structured differently from the executor: it squeezes a generous
 * bulk buffer up front and slices, where the executor squeezes block by block
 * on demand. If the app's incremental reader diverged from a bulk squeeze at a
 * block boundary — the one genuinely novel piece of code in `keccak-compute` —
 * these two would disagree.
 */
const sampleNttByDefinition = (seed: Uint8Array): number[] => {
  const stream = createHash("shake128", { outputLength: 168 * 12 })
    .update(seed)
    .digest();
  const out: number[] = [];
  let pos = 0;
  while (out.length < 256) {
    const c0 = stream[pos] as number;
    const c1 = stream[pos + 1] as number;
    const c2 = stream[pos + 2] as number;
    pos += 3;
    if (pos > stream.length) throw new Error("bulk buffer exhausted — widen it");
    const d1 = c0 + 256 * (c1 % 16);
    const d2 = (c1 >> 4) + 16 * c2;
    if (d1 < ML_KEM_Q) out.push(d1);
    if (d2 < ML_KEM_Q && out.length < 256) out.push(d2);
  }
  return out;
};

const runSampleNtt = (
  seed: Uint8Array,
  modulus: Uint8Array = Q_BYTES,
): { coeffs: number[]; squeezes: number } => {
  const outputs = mlKemSampleNtt(
    new Map([
      ["input", seed],
      ["modulus", modulus],
    ]),
    VEC_PARAMS,
    CTX,
  );
  const squeezeBytes = outputOf(outputs, "squeezes");
  return {
    coeffs: unpackPoly(outputOf(outputs)),
    squeezes: ((squeezeBytes[0] as number) << 8) | (squeezeBytes[1] as number),
  };
};

/** `ρ ‖ j ‖ i`, the seed one matrix entry is drawn from. */
const matrixSeed = (rho: Uint8Array, j: number, i: number): Uint8Array =>
  Uint8Array.from([...rho, j, i]);

/** ρ is the first half of `G(d ‖ k)`; k = 3 for ML-KEM-768. */
const rhoOf = (seed64: Uint8Array): Uint8Array =>
  outputOf(mlKemHashG(one(Uint8Array.from([...seed64.slice(0, 32), 3])), {}, CTX)).slice(0, 32);

describe("SampleNTT (FIPS 203 Algorithm 7)", () => {
  const rho = rhoOf(unhex((FIXTURE.vectors[0] as { seed: string }).seed));

  it("agrees with a rejection loop over an independently generated stream", () => {
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) {
        const seed = matrixSeed(rho, j, i);
        expect(runSampleNtt(seed).coeffs).toEqual(sampleNttByDefinition(seed));
      }
    }
  });

  it("produces 256 coefficients, every one below q", () => {
    // The property rejection sampling exists to provide. A reduce-instead-of-
    // reject implementation would also pass this, which is why it is paired with
    // the comparison above rather than standing alone.
    const { coeffs } = runSampleNtt(matrixSeed(rho, 0, 0));
    expect(coeffs).toHaveLength(256);
    expect(coeffs.every((c) => c >= 0 && c < ML_KEM_Q)).toBe(true);
  });

  it("distinguishes A[i][j] from A[j][i] — the byte order IS the transpose", () => {
    // The single fact that separates key generation's matrix from encryption's.
    expect(runSampleNtt(matrixSeed(rho, 0, 1)).coeffs).not.toEqual(
      runSampleNtt(matrixSeed(rho, 1, 0)).coeffs,
    );
  });

  it("follows an edited modulus, because q arrives on a port", () => {
    // The editable-q promise the whole lattice family is built on. A smaller
    // modulus rejects more candidates, so this also exercises a longer loop.
    const smallQ = new Uint8Array([0x00, 0xff]); // q = 255
    const { coeffs, squeezes } = runSampleNtt(matrixSeed(rho, 0, 0), smallQ);
    expect(coeffs.every((c) => c < 255)).toBe(true);
    // ~6% acceptance instead of ~81%, so it must squeeze far more.
    expect(squeezes).toBeGreaterThan(runSampleNtt(matrixSeed(rho, 0, 0)).squeezes);
  });
});

// ─── 3. The squeeze count is a random variable, measured ──────────────────

/**
 * The plan asked for "enough seeds that at least one matrix polynomial
 * demonstrably needs an extra squeeze block", and as worded that assertion is
 * VACUOUS. Acceptance is ~3329/4096, so 256 coefficients need ~315 candidates
 * ≈ 473 bytes: every draw already consumes three 168-byte blocks. "More than
 * two" is automatic and asserts nothing.
 *
 * What is not automatic is the VARIATION. Measured across these 162 draws:
 * 160 take three blocks and 2 take four. So the executor that squeezed a fixed
 * three blocks would be wrong roughly once in eighty polynomials — which is
 * exactly the "silently wrong on some seeds" failure the loop condition exists
 * to prevent, and it is asserted here rather than hoped for.
 */
describe("the number of squeeze blocks varies with the seed", () => {
  const counts: number[] = [];
  for (const v of FIXTURE.vectors) {
    const rho = rhoOf(unhex(v.seed));
    for (let i = 0; i < 3; i++) {
      for (let j = 0; j < 3; j++) counts.push(runSampleNtt(matrixSeed(rho, j, i)).squeezes);
    }
  }

  it("draws every matrix entry of every fixture seed", () => {
    expect(counts).toHaveLength(FIXTURE.vectors.length * 9);
  });

  it("does not spend the same number of blocks on every draw", () => {
    // THE assertion of this file. A fixed-budget implementation makes this set
    // a singleton.
    expect(new Set(counts).size).toBeGreaterThan(1);
  });

  it("has a modal cost of three blocks, with a tail above it", () => {
    const modal = 3;
    expect(counts.filter((c) => c === modal).length).toBeGreaterThan(counts.length / 2);
    expect(counts.some((c) => c > modal)).toBe(true);
    // And nothing below: a draw needing only two blocks would mean the
    // acceptance rate had been mis-derived.
    expect(counts.every((c) => c >= modal)).toBe(true);
  });
});

// ─── 4. Registration ──────────────────────────────────────────────────────

describe("all five monoliths are registered", () => {
  const registry = buildDefaultRegistry();

  for (const type of [
    "ml-kem.hash-g@1",
    "ml-kem.hash-h@1",
    "ml-kem.kdf-j@1",
    "ml-kem.prf@1",
    "ml-kem.sample-ntt@1",
  ]) {
    it(`${type} has an executor and documentation`, () => {
      expect(registry.has(type)).toBe(true);
      const doc = registry.getDoc(type);
      expect(doc?.name.length).toBeGreaterThan(0);
      // The "cross-reference monolith" rule: each of these must point the reader
      // at the decomposed sponge rather than claim it has none. Prose that read
      // like `blowfish.key-schedule@1`'s would be a lie, so the pointer is
      // asserted.
      expect(doc?.detail).toMatch(/SHA3|SHAKE/);
      expect(doc?.references?.length).toBeGreaterThan(0);
    });
  }
});
