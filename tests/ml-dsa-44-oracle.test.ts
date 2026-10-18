/**
 * ML-DSA-44 assembled from the P2 steps, checked byte for byte against real
 * implementations (P2 of `docs/plans/refactored-petting-tide.md`).
 *
 * No spec ships for ML-DSA until P3/P4. This file composes the REGISTERED
 * executors — every call goes through `registry.getRegistration(type)`, never
 * a local re-implementation — into FIPS 204's three internal algorithms, and
 * holds them to an external oracle:
 *
 * - **Key generation (Algorithm 6)** must reproduce Node 24's public key AND
 *   its 2560-byte expanded private key from the same 32-byte seed. That pins
 *   H, ExpandA (including its index order), ExpandS, both NTTs, the matrix
 *   product, Power2Round and both packers in one go.
 * - **Verification (Algorithm 8)** must accept Node's randomized signatures and
 *   noble's deterministic ones, and reject the malformed ones Node rejects —
 *   one per HintBitUnpack refusal rule, plus a flipped c̃ bit.
 * - **Signing (Algorithm 7)** with `rnd = 0³²` must produce noble's
 *   deterministic signature EXACTLY. A wrong rejection rule changes how many
 *   attempts run, hence the mask, hence every byte — so this pins the four
 *   bound checks implicitly, along with ExpandMask, Decompose, MakeHint and the
 *   hint packer.
 *
 * The fixture (`tests/fixtures/ml-dsa-44-vectors.json`) was produced once by a
 * script in `W:/temp/claude/ml-dsa-oracle/`: Node's seed-import PKCS#8 for the
 * keys, `@noble/post-quantum` 0.7.1 for the deterministic signatures, each
 * cross-checked against the other both ways before anything was written. CI
 * runs Node 22, which has no ML-DSA, so everything Node-derived is captured.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_44_BETA,
  ML_DSA_44_ETA,
  ML_DSA_44_GAMMA1,
  ML_DSA_44_GAMMA2,
  ML_DSA_44_K,
  ML_DSA_44_L,
  ML_DSA_44_OMEGA,
  ML_DSA_44_TAU,
  ML_DSA_D,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
} from "@/ciphers/mldsa-constants";
import type { Json } from "@/core/types";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();
const P = { coeffBytes: 4, littleEndian: false } as const;
const K = ML_DSA_44_K;
const L = ML_DSA_44_L;
const POLY = 1024;

// ─── Plumbing: every operation is a registered executor ───────────────────

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

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (h: string): Uint8Array => new Uint8Array(Buffer.from(h, "hex"));
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const r = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    r.set(p, o);
    o += p.length;
  }
  return r;
};
const poly = (vec: Uint8Array, i: number): Uint8Array => vec.subarray(i * POLY, (i + 1) * POLY);
const repeat = (p: Uint8Array, n: number): Uint8Array => cat(...Array.from({ length: n }, () => p));

const Q = ML_DSA_Q_BYTES;
const c4 = mlDsaCoeffBytes;
const G2 = c4(ML_DSA_44_GAMMA2);
const OMEGA = new Uint8Array([ML_DSA_44_OMEGA]);

const H = (input: Uint8Array, outBytes: number) =>
  out(run("ml-dsa.hash-h@1", { input }, { outBytes }));
const ntt = (input: Uint8Array) => out(run("ml-dsa.ntt@1", { input }, {}));
const intt = (input: Uint8Array) => out(run("ml-dsa.intt@1", { input }, {}));
const add = (a: Uint8Array, b: Uint8Array) => out(run("zq-vec-add@1", { a, b, modulus: Q }));
const sub = (a: Uint8Array, b: Uint8Array) => out(run("zq-vec-sub@1", { a, b, modulus: Q }));
const mul = (a: Uint8Array, b: Uint8Array) => out(run("zq-vec-mul@1", { a, b, modulus: Q }));
const scale = (a: Uint8Array, s: number) =>
  out(run("zq-vec-mul-scalar@1", { a, scalar: c4(s), modulus: Q }));
const normBelow = (a: Uint8Array, bound: number): boolean =>
  out(run("zq-inf-norm-below@1", { a, bound: c4(bound), modulus: Q }))[0] === 1;
const neg = (a: Uint8Array) => sub(new Uint8Array(a.length), a);

const bitPack = (a: Uint8Array, lower: number, upper: number) =>
  out(run("ml-dsa.bit-pack@1", { a, lower: c4(lower), upper: c4(upper), modulus: Q }));
const bitUnpack = (a: Uint8Array, lower: number, upper: number) =>
  out(run("ml-dsa.bit-unpack@1", { a, lower: c4(lower), upper: c4(upper), modulus: Q }));

/** Â (row-major k·l transformed polys) times a vector of l transformed polys. */
const matVec = (aHat: Uint8Array, vHat: Uint8Array): Uint8Array => {
  const rows: Uint8Array[] = [];
  for (let r = 0; r < K; r++) {
    let acc: Uint8Array = new Uint8Array(POLY);
    for (let s = 0; s < L; s++) acc = add(acc, mul(poly(aHat, r * L + s), poly(vHat, s)));
    rows.push(acc);
  }
  return cat(...rows);
};

const expandA = (rho: Uint8Array) =>
  out(run("ml-dsa.expand-a@1", { input: rho, modulus: Q }, { ...P, k: K, l: L }));

// ─── FIPS 204 Algorithm 6 — ML-DSA.KeyGen_internal ────────────────────────

type KeyGenOptions = {
  /** Perturbation: the round-3 draft's H(ξ) without the ‖ k ‖ l separator. */
  readonly omitDomainSeparator?: boolean;
  /** Perturbation: build Âᵀ instead of Â (ρ ‖ r ‖ s instead of ρ ‖ s ‖ r). */
  readonly transposeA?: boolean;
};

const transpose = (aHat: Uint8Array): Uint8Array => {
  const parts: Uint8Array[] = [];
  for (let r = 0; r < K; r++) for (let s = 0; s < L; s++) parts.push(poly(aHat, s * L + r));
  return cat(...parts);
};

const keyGen = (xi: Uint8Array, opts: KeyGenOptions = {}) => {
  const seeds = H(opts.omitDomainSeparator ? xi : cat(xi, Uint8Array.from([K, L])), 128);
  const rho = seeds.subarray(0, 32);
  const rhoPrime = seeds.subarray(32, 96);
  const key = seeds.subarray(96, 128);
  let aHat = expandA(rho);
  if (opts.transposeA) aHat = transpose(aHat);
  const s = run(
    "ml-dsa.expand-s@1",
    { input: rhoPrime, modulus: Q },
    { ...P, k: K, l: L, eta: ML_DSA_44_ETA },
  );
  const s1 = out(s, "s1");
  const s2 = out(s, "s2");
  const t = add(intt(matVec(aHat, ntt(s1))), s2);
  const split = run("ml-dsa.power2round@1", { a: t, modulus: Q }, { ...P, d: ML_DSA_D });
  const t1 = out(split, "high");
  const t0 = out(split, "low");
  // pkEncode: ρ ‖ SimpleBitPack(t1, 2^(bitlen(q−1)−d) − 1) — the unsigned packer, d = 10.
  const pk = cat(
    rho,
    out(run("zq-byte-encode@1", { a: t1, modulus: Q }, { ...P, d: 23 - ML_DSA_D })),
  );
  const tr = H(pk, 64);
  const eta = ML_DSA_44_ETA;
  const half = 2 ** (ML_DSA_D - 1);
  const sk = cat(
    rho,
    key,
    tr,
    bitPack(s1, eta, eta),
    bitPack(s2, eta, eta),
    bitPack(t0, half - 1, half),
  );
  return { pk, sk };
};

// ─── FIPS 204 Algorithm 8 — ML-DSA.Verify_internal ────────────────────────

const Z_BYTES = 576; // 256 coefficients × 18 bits
const SIG_BYTES = 32 + L * Z_BYTES + ML_DSA_44_OMEGA + K;

const formatMessage = (message: Uint8Array, context: Uint8Array) =>
  out(run("ml-dsa.format-message@1", { input: message }, { context: [...context] }));

const verify = (pk: Uint8Array, mPrime: Uint8Array, sig: Uint8Array): boolean => {
  if (sig.length !== SIG_BYTES) return false;
  const rho = pk.subarray(0, 32);
  const t1 = out(
    run("zq-byte-decode@1", { a: pk.subarray(32), modulus: Q }, { ...P, d: 23 - ML_DSA_D }),
  );
  const cTilde = sig.subarray(0, 32);
  const z = bitUnpack(sig.subarray(32, 32 + L * Z_BYTES), ML_DSA_44_GAMMA1 - 1, ML_DSA_44_GAMMA1);
  const hint = run("ml-dsa.hint-unpack@1", { input: sig.subarray(32 + L * Z_BYTES), omega: OMEGA });
  if (out(hint, "valid")[0] !== 1) return false;
  const h = out(hint);

  const aHat = expandA(rho);
  const tr = H(pk, 64);
  const mu = H(cat(tr, mPrime), 64);
  const c = out(
    run("ml-dsa.sample-in-ball@1", { input: cTilde, modulus: Q }, { ...P, tau: ML_DSA_44_TAU }),
  );
  const cHat = ntt(c);
  const ct1 = mul(repeat(cHat, K), ntt(scale(t1, 2 ** ML_DSA_D)));
  const wApprox = intt(sub(matVec(aHat, ntt(z)), ct1));
  const w1 = out(run("ml-dsa.use-hint@1", { h, r: wApprox, gamma2: G2, modulus: Q }));
  const w1Bytes = out(run("ml-dsa.w1-encode@1", { a: w1, gamma2: G2, modulus: Q }));
  const cTilde2 = H(cat(mu, w1Bytes), 32);
  return normBelow(z, ML_DSA_44_GAMMA1 - ML_DSA_44_BETA) && hex(cTilde) === hex(cTilde2);
};

// ─── FIPS 204 Algorithm 7 — ML-DSA.Sign_internal ──────────────────────────

type Attempt = { readonly kappa: number; readonly rejectedBy: string | null };

const sign = (sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array) => {
  const rho = sk.subarray(0, 32);
  const key = sk.subarray(32, 64);
  const tr = sk.subarray(64, 128);
  const eta = ML_DSA_44_ETA;
  const etaBytes = (256 * 3) / 8; // 96 bytes per s polynomial at 3 bits
  const t0Bytes = (256 * 13) / 8; // 416 bytes per t0 polynomial
  const s2At = 128 + L * etaBytes;
  const t0At = s2At + K * etaBytes;
  const s1 = bitUnpack(sk.subarray(128, s2At), eta, eta);
  const s2 = bitUnpack(sk.subarray(s2At, t0At), eta, eta);
  const half = 2 ** (ML_DSA_D - 1);
  const t0 = bitUnpack(sk.subarray(t0At, t0At + K * t0Bytes), half - 1, half);

  const s1Hat = ntt(s1);
  const s2Hat = ntt(s2);
  const t0Hat = ntt(t0);
  const aHat = expandA(rho);
  const mu = H(cat(tr, mPrime), 64);
  const rhoPP = H(cat(key, rnd, mu), 64);

  const attempts: Attempt[] = [];
  for (let kappa = 0; kappa < 1000 * L; kappa += L) {
    const y = out(
      run(
        "ml-dsa.expand-mask@1",
        {
          input: rhoPP,
          kappa: new Uint8Array([kappa >> 8, kappa & 0xff]),
          gamma1: c4(ML_DSA_44_GAMMA1),
          modulus: Q,
        },
        { ...P, l: L },
      ),
    );
    const w = intt(matVec(aHat, ntt(y)));
    const w1 = out(run("ml-dsa.decompose@1", { a: w, gamma2: G2, modulus: Q }), "high");
    const w1Bytes = out(run("ml-dsa.w1-encode@1", { a: w1, gamma2: G2, modulus: Q }));
    const cTilde = H(cat(mu, w1Bytes), 32);
    const cHat = ntt(
      out(
        run("ml-dsa.sample-in-ball@1", { input: cTilde, modulus: Q }, { ...P, tau: ML_DSA_44_TAU }),
      ),
    );
    const cs1 = intt(mul(repeat(cHat, L), s1Hat));
    const cs2 = intt(mul(repeat(cHat, K), s2Hat));
    const z = add(y, cs1);
    const r0 = out(run("ml-dsa.decompose@1", { a: sub(w, cs2), gamma2: G2, modulus: Q }), "low");
    if (!normBelow(z, ML_DSA_44_GAMMA1 - ML_DSA_44_BETA)) {
      attempts.push({ kappa, rejectedBy: "z" });
      continue;
    }
    if (!normBelow(r0, ML_DSA_44_GAMMA2 - ML_DSA_44_BETA)) {
      attempts.push({ kappa, rejectedBy: "r0" });
      continue;
    }
    const ct0 = intt(mul(repeat(cHat, K), t0Hat));
    const h = out(
      run("ml-dsa.make-hint@1", { z: neg(ct0), r: add(sub(w, cs2), ct0), gamma2: G2, modulus: Q }),
    );
    if (!normBelow(ct0, ML_DSA_44_GAMMA2)) {
      attempts.push({ kappa, rejectedBy: "ct0" });
      continue;
    }
    if (out(run("ml-dsa.hint-count@1", { h, omega: OMEGA }))[0] !== 1) {
      attempts.push({ kappa, rejectedBy: "hint" });
      continue;
    }
    attempts.push({ kappa, rejectedBy: null });
    const sig = cat(
      cTilde,
      bitPack(z, ML_DSA_44_GAMMA1 - 1, ML_DSA_44_GAMMA1),
      out(run("ml-dsa.hint-pack@1", { h, omega: OMEGA })),
    );
    return { sig, attempts };
  }
  throw new Error("no acceptable candidate in 1000 attempts");
};

// ─── The fixture ──────────────────────────────────────────────────────────

type Sig = { message: string; context: string; deterministic: string; nodeRandomized: string };
type Key = { seed: string; pk: string; sk: string; signatures: Sig[] };
const KEYS = FIXTURE.keys as Key[];

describe("ML-DSA-44 key generation from the P2 steps = Node's keys", () => {
  for (const k of KEYS) {
    it(`seed ${k.seed.slice(0, 8)}…: pk (1312 B) and the expanded sk (2560 B) byte for byte`, () => {
      const { pk, sk } = keyGen(unhex(k.seed));
      expect(pk.length).toBe(1312);
      expect(sk.length).toBe(2560);
      expect(hex(pk)).toBe(k.pk);
      expect(hex(sk)).toBe(k.sk);
    });
  }

  it("perturbation: the round-3 H(ξ), without ‖ k ‖ l, breaks ρ itself", () => {
    const k = KEYS[1] as Key;
    const { pk } = keyGen(unhex(k.seed), { omitDomainSeparator: true });
    expect(hex(pk.subarray(0, 32))).not.toBe(k.pk.slice(0, 64));
  });

  it("perturbation: building Âᵀ leaves ρ and s1/s2 intact and breaks t1, tr and t0", () => {
    // The signature of a transposed matrix — the ExpandA index order inside the
    // step, made observable. ρ (pk[0:32]) and s1 ‖ s2 (sk[128:896]) do not
    // depend on Â; everything after the matrix product does.
    const k = KEYS[1] as Key;
    const { pk, sk } = keyGen(unhex(k.seed), { transposeA: true });
    const wantPk = unhex(k.pk);
    const wantSk = unhex(k.sk);
    expect(hex(pk.subarray(0, 32))).toBe(hex(wantPk.subarray(0, 32)));
    expect(hex(pk.subarray(32))).not.toBe(hex(wantPk.subarray(32)));
    expect(hex(sk.subarray(128, 128 + 8 * 96))).toBe(hex(wantSk.subarray(128, 128 + 8 * 96)));
    expect(hex(sk.subarray(64, 128))).not.toBe(hex(wantSk.subarray(64, 128)));
  });
});

describe("ML-DSA-44 verification from the P2 steps agrees with Node", () => {
  for (const [ki, k] of KEYS.entries()) {
    for (const [si, s] of k.signatures.entries()) {
      it(`key ${ki}, message ${si}${s.context ? " (with context)" : ""}: Node's and noble's signatures verify`, () => {
        const mPrime = formatMessage(unhex(s.message), unhex(s.context));
        const pk = unhex(k.pk);
        expect(verify(pk, mPrime, unhex(s.nodeRandomized))).toBe(true);
        expect(verify(pk, mPrime, unhex(s.deterministic))).toBe(true);
      });
    }
  }

  it("rejects exactly the malformed signatures Node rejects", () => {
    const k = KEYS[FIXTURE.malformed.keyIndex] as Key;
    const s = k.signatures[FIXTURE.malformed.signatureIndex] as Sig;
    const mPrime = formatMessage(unhex(s.message), unhex(s.context));
    for (const c of FIXTURE.malformed.cases) {
      expect(verify(unhex(k.pk), mPrime, unhex(c.signature)), c.name).toBe(c.nodeVerifies);
    }
    // Every refusal rule is represented, plus the unmodified control.
    expect(FIXTURE.malformed.cases.filter((c) => !c.nodeVerifies).length).toBe(5);
  });

  it("rejects a signature checked against the wrong context — the prefix is load-bearing", () => {
    const k = KEYS[0] as Key;
    const s = k.signatures[2] as Sig; // signed with context "app-ctx"
    expect(
      verify(
        unhex(k.pk),
        formatMessage(unhex(s.message), new Uint8Array(0)),
        unhex(s.deterministic),
      ),
    ).toBe(false);
  });
});

describe("ML-DSA-44 deterministic signing from the P2 steps = noble's bytes", () => {
  for (const [ki, k] of KEYS.entries()) {
    for (const [si, s] of k.signatures.entries()) {
      it(`key ${ki}, message ${si}: the signature, byte for byte`, () => {
        const mPrime = formatMessage(unhex(s.message), unhex(s.context));
        const { sig, attempts } = sign(unhex(k.sk), mPrime, new Uint8Array(32));
        expect(sig.length).toBe(SIG_BYTES);
        expect(hex(sig)).toBe(s.deterministic);
        // Shape of the loop: κ advances by l, and only the last attempt is kept.
        attempts.forEach((a, i) => expect(a.kappa).toBe(i * L));
        expect(attempts.at(-1)?.rejectedBy).toBeNull();
        expect(attempts.slice(0, -1).every((a) => a.rejectedBy !== null)).toBe(true);
      });
    }
  }

  it("the P3 default pair: noble's bytes, after exactly three attempts — rejected by z, then r0", () => {
    // `ML_DSA_44_DEFAULT_MESSAGE` was chosen for this shape, so P4's signing
    // trace opens on both common rejections. Pinned here, where the attempt
    // reasons are observable, rather than only stated in a comment.
    const d = FIXTURE.p3.defaultPair;
    const k = KEYS[d.keyIndex] as Key;
    const { sig, attempts } = sign(
      unhex(k.sk),
      formatMessage(unhex(d.message), unhex(d.context)),
      new Uint8Array(32),
    );
    expect(hex(sig)).toBe(d.deterministic);
    expect(attempts.map((a) => a.rejectedBy)).toEqual(["z", "r0", null]);
  });
});
