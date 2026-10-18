/**
 * The ML-DSA one-frame steps — the NTT pair, H, the four samplers and the
 * message formatter (P2 of `docs/plans/refactored-petting-tide.md`).
 *
 * ## The evidence, ranked
 *
 * 1. **Each sampler against an independent rejection loop** driven by
 *    `node:crypto`'s SHAKE rather than the app's. The reference squeezes one
 *    generous bulk buffer and slices it; the executors squeeze block by block on
 *    demand. So a divergence at a block boundary — the new incremental reader's
 *    one genuinely novel job — would show here. (The ML-KEM precedent,
 *    `tests/ml-kem-monoliths.test.ts`.)
 * 2. **The NTT pair against the TRACED selector entry**, on the same inputs.
 *    Two implementations of one definition: FIPS 204 Algorithms 41/42 written
 *    out in the executor, and the butterfly spec P1 pinned against the
 *    evaluation definition. Agreement is what licenses the one-frame form.
 * 3. **Range and shape properties** a wrong rule would break.
 *
 * Byte-exact agreement with real ML-DSA keys and signatures — which pins the
 * index orders inside ExpandA / ExpandS / ExpandMask, the part a self-consistent
 * reference cannot — is `tests/ml-dsa-44-oracle.test.ts`.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { byteStream, shake128Reader, shake256Reader } from "@/ciphers/keccak-compute";
import {
  ML_DSA_44_GAMMA1,
  ML_DSA_44_TAU,
  ML_DSA_Q,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
  packMlDsaPoly,
  unpackMlDsaPoly,
} from "@/ciphers/mldsa-constants";
import { buildMlDsaInverseNttSpec, buildMlDsaNttSpec } from "@/ciphers/ntt-8380417-256";
import { modPm } from "@/core/ml-dsa-arith";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, Json } from "@/core/types";
import { describe, expect, it } from "vitest";

const q = ML_DSA_Q;
const P = { coeffBytes: 4, littleEndian: false } as const;
const registry = buildDefaultRegistry();

const exec = (
  type: string,
  ports: Record<string, Uint8Array>,
  params: Record<string, Json> = P,
): ReadonlyMap<string, Uint8Array> => {
  const def = registry.getRegistration(type);
  if (def === undefined) throw new Error(`${type} is not registered`);
  return def.executor(new Map(Object.entries(ports)), params, {} as never);
};

const port = (out: ReadonlyMap<string, Uint8Array>, name = "output"): Uint8Array => {
  const v = out.get(name);
  if (v === undefined) throw new Error(`no output port ${name}`);
  return v;
};

const bytesOf = (n: number, seed: number): Uint8Array =>
  Uint8Array.from({ length: n }, (_, i) => (i * 131 + seed * 17 + 7) & 0xff);

const shakeBulk = (alg: "shake128" | "shake256", input: Uint8Array, n: number): Uint8Array =>
  new Uint8Array(createHash(alg, { outputLength: n }).update(input).digest());

/** A bulk-buffer byte cursor, failing loudly if the buffer was too small. */
const cursor = (buf: Uint8Array) => {
  let pos = 0;
  return () => {
    if (pos >= buf.length) throw new Error("bulk buffer exhausted — widen it");
    return buf[pos++] as number;
  };
};

const signedPoly = (bytes: Uint8Array): number[] => unpackMlDsaPoly(bytes).map((v) => modPm(v, q));

// ─── The incremental reader ───────────────────────────────────────────────

describe("the incremental SHAKE readers", () => {
  it("shake256Reader streams exactly node:crypto's SHAKE256, across many block boundaries", () => {
    const msg = bytesOf(70, 1);
    const want = shakeBulk("shake256", msg, 5000);
    const stream = byteStream(shake256Reader(msg));
    const got = Uint8Array.from({ length: 5000 }, () => stream.next());
    expect(got).toEqual(want);
    expect(stream.consumed()).toBe(5000);
  });

  it("shake128Reader is unchanged by the generalisation", () => {
    const msg = bytesOf(34, 2);
    const want = shakeBulk("shake128", msg, 168 * 3);
    const next = shake128Reader(msg);
    expect(Uint8Array.from([...next(), ...next(), ...next()])).toEqual(want);
  });
});

// ─── The NTT pair against the traced spec ─────────────────────────────────

describe("ml-dsa.ntt@1 / ml-dsa.intt@1 agree with the traced NTT mod 8380417", () => {
  const runTraced = (spec: CipherSpec, bytes: Uint8Array): Uint8Array => {
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    return trace.finalState.bytes;
  };
  const polys = [0, 1, 2].map((s) =>
    packMlDsaPoly(Array.from({ length: 256 }, (_, i) => (i * 104729 + s * 7919 + 1) % q)),
  );

  it("forward: the one-frame transform equals the eight traced layers", () => {
    for (const poly of polys) {
      expect(port(exec("ml-dsa.ntt@1", { input: poly }, {}))).toEqual(
        runTraced(buildMlDsaNttSpec(), poly),
      );
    }
  });

  it("inverse: the one-frame transform equals the traced inverse", () => {
    for (const poly of polys) {
      expect(port(exec("ml-dsa.intt@1", { input: poly }, {}))).toEqual(
        runTraced(buildMlDsaInverseNttSpec(), poly),
      );
    }
  });

  it("transforms a vector polynomial by polynomial, and round-trips", () => {
    const vec = Uint8Array.from(polys.flatMap((p) => [...p]));
    const fwd = port(exec("ml-dsa.ntt@1", { input: vec }, {}));
    polys.forEach((poly, i) => {
      expect(fwd.subarray(i * 1024, (i + 1) * 1024)).toEqual(
        port(exec("ml-dsa.ntt@1", { input: poly }, {})),
      );
    });
    expect(port(exec("ml-dsa.intt@1", { input: fwd }, {}))).toEqual(vec);
  });

  it("refuses a partial polynomial or an unreduced coefficient", () => {
    expect(() => exec("ml-dsa.ntt@1", { input: new Uint8Array(1000) }, {})).toThrow(/whole number/);
    expect(() =>
      exec("ml-dsa.ntt@1", { input: packMlDsaPoly(new Array(256).fill(q)) }, {}),
    ).toThrow(/not a residue/);
  });
});

// ─── H ────────────────────────────────────────────────────────────────────

describe("ml-dsa.hash-h@1", () => {
  it("is SHAKE256 at the requested length", () => {
    for (const outBytes of [32, 64, 128]) {
      const input = bytesOf(50, outBytes);
      expect(port(exec("ml-dsa.hash-h@1", { input }, { outBytes }))).toEqual(
        shakeBulk("shake256", input, outBytes),
      );
    }
  });
});

// ─── ExpandA ──────────────────────────────────────────────────────────────

/** RejNTTPoly by definition, over OpenSSL's SHAKE128 in one bulk squeeze. */
const rejNttByDefinition = (seed: Uint8Array): number[] => {
  const next = cursor(shakeBulk("shake128", seed, 168 * 8));
  const out: number[] = [];
  while (out.length < 256) {
    const c = next() + 256 * next() + 65536 * (next() & 0x7f);
    if (c < q) out.push(c);
  }
  return out;
};

describe("ml-dsa.expand-a@1", () => {
  const rho = bytesOf(32, 3);
  const matrix = unpackMlDsaPoly(
    port(exec("ml-dsa.expand-a@1", { input: rho, modulus: ML_DSA_Q_BYTES }, { ...P, k: 4, l: 4 })),
  );

  it("draws Â[r][s] from ρ ‖ s ‖ r, row-major, by an independent rejection loop", () => {
    for (let r = 0; r < 4; r++) {
      for (let s = 0; s < 4; s++) {
        const entry = matrix.slice((r * 4 + s) * 256, (r * 4 + s + 1) * 256);
        expect(entry, `Â[${r}][${s}]`).toEqual(rejNttByDefinition(Uint8Array.from([...rho, s, r])));
      }
    }
  });

  it("is not its own transpose — the index order is load-bearing", () => {
    const entry01 = matrix.slice(256, 512);
    const entry10 = matrix.slice(4 * 256, 5 * 256);
    expect(entry01).not.toEqual(entry10);
  });

  it("follows k and l", () => {
    const out = port(
      exec("ml-dsa.expand-a@1", { input: rho, modulus: ML_DSA_Q_BYTES }, { ...P, k: 6, l: 5 }),
    );
    expect(out.length).toBe(6 * 5 * 1024);
  });
});

// ─── ExpandS ──────────────────────────────────────────────────────────────

const rejBoundedByDefinition = (seed: Uint8Array, eta: number): number[] => {
  const next = cursor(shakeBulk("shake256", seed, 136 * 8));
  const half = (b: number): number | null =>
    eta === 2 ? (b < 15 ? 2 - (b % 5) : null) : b < 9 ? 4 - b : null;
  const out: number[] = [];
  while (out.length < 256) {
    const z = next();
    const z0 = half(z & 15);
    const z1 = half(z >> 4);
    if (z0 !== null) out.push(z0);
    if (z1 !== null && out.length < 256) out.push(z1);
  }
  return out;
};

describe("ml-dsa.expand-s@1", () => {
  const rhoPrime = bytesOf(64, 4);

  for (const eta of [2, 4]) {
    it(`η = ${eta}: s1 then s2, polynomial r from ρ′ ‖ r as two LITTLE-endian bytes`, () => {
      const out = exec(
        "ml-dsa.expand-s@1",
        { input: rhoPrime, modulus: ML_DSA_Q_BYTES },
        { ...P, k: 4, l: 4, eta },
      );
      const s1 = signedPoly(port(out, "s1"));
      const s2 = signedPoly(port(out, "s2"));
      expect(s1.length).toBe(4 * 256);
      expect(s2.length).toBe(4 * 256);
      for (let r = 0; r < 8; r++) {
        const got = (r < 4 ? s1 : s2).slice((r % 4) * 256, ((r % 4) + 1) * 256);
        expect(got, `polynomial ${r}`).toEqual(
          rejBoundedByDefinition(Uint8Array.from([...rhoPrime, r & 0xff, r >> 8]), eta),
        );
      }
      expect([...s1, ...s2].every((v) => Math.abs(v) <= eta)).toBe(true);
    });
  }

  it("draws the values UNIFORMLY, not as a bell curve", () => {
    const out = exec(
      "ml-dsa.expand-s@1",
      { input: rhoPrime, modulus: ML_DSA_Q_BYTES },
      { ...P, k: 8, l: 8, eta: 2 },
    );
    const all = [...signedPoly(port(out, "s1")), ...signedPoly(port(out, "s2"))];
    const share = (v: number) => all.filter((x) => x === v).length / all.length;
    // 4096 draws; each of the five values should be near 0.2. A centred
    // binomial would put ~0.375 at 0 and ~0.0625 at ±2.
    for (const v of [-2, -1, 0, 1, 2]) {
      expect(share(v)).toBeGreaterThan(0.17);
      expect(share(v)).toBeLessThan(0.23);
    }
  });

  it("refuses an η FIPS 204 gives no rule for", () => {
    expect(() =>
      exec(
        "ml-dsa.expand-s@1",
        { input: rhoPrime, modulus: ML_DSA_Q_BYTES },
        { ...P, k: 4, l: 4, eta: 3 },
      ),
    ).toThrow(/2 or 4/);
  });
});

// ─── ExpandMask ───────────────────────────────────────────────────────────

/** ExpandMask by definition: one big bigint per polynomial, bits peeled off the bottom. */
const expandMaskByDefinition = (seed: Uint8Array, kappa: number, gamma1: number): number[] => {
  const c = 1 + Math.floor(Math.log2(gamma1 - 1)) + 1;
  const out: number[] = [];
  for (let r = 0; r < 4; r++) {
    const counter = kappa + r;
    const v = shakeBulk(
      "shake256",
      Uint8Array.from([...seed, counter & 0xff, counter >> 8]),
      32 * c,
    );
    let big = 0n;
    for (let i = v.length - 1; i >= 0; i--) big = (big << 8n) | BigInt(v[i] as number);
    const mask = (1n << BigInt(c)) - 1n;
    for (let i = 0; i < 256; i++) {
      out.push(gamma1 - Number((big >> BigInt(i * c)) & mask));
    }
  }
  return out;
};

describe("ml-dsa.expand-mask@1", () => {
  const seed = bytesOf(64, 5);
  const run = (kappa: number) =>
    signedPoly(
      port(
        exec(
          "ml-dsa.expand-mask@1",
          {
            input: seed,
            kappa: new Uint8Array([kappa >> 8, kappa & 0xff]),
            gamma1: mlDsaCoeffBytes(ML_DSA_44_GAMMA1),
            modulus: ML_DSA_Q_BYTES,
          },
          { ...P, l: 4 },
        ),
      ),
    );

  it("matches the definition, with κ big-endian on the port and little-endian in the hash", () => {
    // κ = 300 is 0x012C: a counter whose two bytes differ, so an endianness
    // slip in either direction changes the stream.
    for (const kappa of [0, 4, 300]) {
      expect(run(kappa), `κ = ${kappa}`).toEqual(
        expandMaskByDefinition(seed, kappa, ML_DSA_44_GAMMA1),
      );
    }
  });

  it("lands every coefficient in (−γ1, γ1], and differs from attempt to attempt", () => {
    const y0 = run(0);
    expect(y0.every((v) => v > -ML_DSA_44_GAMMA1 && v <= ML_DSA_44_GAMMA1)).toBe(true);
    expect(run(4)).not.toEqual(y0);
    // Attempt 2's first polynomial is NOT attempt 1's second one shifted: κ
    // advances by l, so their counter ranges are disjoint.
    expect(run(4).slice(0, 256)).not.toEqual(y0.slice(256, 512));
  });
});

// ─── SampleInBall ─────────────────────────────────────────────────────────

const sampleInBallByDefinition = (seed: Uint8Array, tau: number) => {
  const next = cursor(shakeBulk("shake256", seed, 136 * 4));
  const s = Array.from({ length: 8 }, next);
  const c = new Array<number>(256).fill(0);
  let rejections = 0;
  for (let i = 256 - tau; i < 256; i++) {
    let j = next();
    while (j > i) {
      rejections++;
      j = next();
    }
    const k = i + tau - 256;
    c[i] = c[j] as number;
    c[j] = ((s[k >> 3] as number) >> (k & 7)) & 1 ? -1 : 1;
  }
  return { c, rejections };
};

describe("ml-dsa.sample-in-ball@1", () => {
  for (const seedNo of [6, 7, 8]) {
    it(`matches the shuffle by definition (seed ${seedNo}), rejection count included`, () => {
      const seed = bytesOf(32, seedNo);
      const out = exec(
        "ml-dsa.sample-in-ball@1",
        { input: seed, modulus: ML_DSA_Q_BYTES },
        { ...P, tau: ML_DSA_44_TAU },
      );
      const want = sampleInBallByDefinition(seed, ML_DSA_44_TAU);
      expect(signedPoly(port(out))).toEqual(want.c);
      const rej = port(out, "rejections");
      expect(((rej[0] as number) << 8) | (rej[1] as number)).toBe(want.rejections);
      // Exactly τ nonzero, all ±1.
      expect(want.c.filter((v) => v !== 0).length).toBe(ML_DSA_44_TAU);
      expect(want.c.every((v) => v === 0 || v === 1 || v === -1)).toBe(true);
    });
  }

  it("really does reject — the count is not always zero", () => {
    const counts = [9, 10, 11, 12].map((n) => {
      const r = port(
        exec(
          "ml-dsa.sample-in-ball@1",
          { input: bytesOf(32, n), modulus: ML_DSA_Q_BYTES },
          { ...P, tau: 39 },
        ),
        "rejections",
      );
      return ((r[0] as number) << 8) | (r[1] as number);
    });
    expect(counts.some((c) => c > 0)).toBe(true);
  });
});

// ─── format-message ───────────────────────────────────────────────────────

describe("ml-dsa.format-message@1", () => {
  it("prepends 0 ‖ |ctx| ‖ ctx", () => {
    const m = Uint8Array.from([0xaa, 0xbb]);
    expect(port(exec("ml-dsa.format-message@1", { input: m }, {}))).toEqual(
      Uint8Array.from([0, 0, 0xaa, 0xbb]),
    );
    expect(port(exec("ml-dsa.format-message@1", { input: m }, { context: [1, 2, 3] }))).toEqual(
      Uint8Array.from([0, 3, 1, 2, 3, 0xaa, 0xbb]),
    );
  });

  it("allows a 255-byte context and refuses 256", () => {
    const m = new Uint8Array(1);
    expect(
      port(exec("ml-dsa.format-message@1", { input: m }, { context: new Array(255).fill(7) }))[1],
    ).toBe(255);
    expect(() =>
      exec("ml-dsa.format-message@1", { input: m }, { context: new Array(256).fill(7) }),
    ).toThrow(/at most 255/);
  });
});
