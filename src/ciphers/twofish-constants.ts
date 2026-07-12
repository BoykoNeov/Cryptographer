/**
 * Twofish constants + pure math oracle (Schneier, Kelsey, Whiting, Wagner,
 * Hall, Ferguson — 1998 AES finalist). Sixth cipher family, third Feistel.
 *
 * **Everything here was cross-checked against TWO independent references:**
 *   1. Niels Ferguson's reference C library (an executable oracle giving the
 *      key-dependent S-boxes, all 40 subkeys, and endpoint ciphertext), and
 *   2. the published Twofish specification's constants — the explicit MDS
 *      (GF(2⁸)/0x169) and RS (GF(2⁸)/0x14D) matrices, and the q0/q1 8×8-bit
 *      permutations built from the 4-bit t-tables per the paper's construction.
 * The two agree with each other and with this implementation at all three
 * levels (S-boxes/g, subkeys, ciphertext) — see `tests/twofish-vectors.test.ts`
 * for the pinned known-answer values. Per `feedback_crypto_verification`, the
 * first vector was pinned against those references, not hand-typed from recall.
 *
 * **Word convention is BIG-ENDIAN inside the spec (author decision).** Twofish
 * is little-endian throughout, but the generic ARX primitives (`add-mod-32@1`,
 * `rotate-bits-right@1`) decode/encode big-endian words. Reusing them (rather
 * than authoring LE variants) is strictly less code, so every 32-bit word
 * travels the spec ports as BE bytes; the LE↔BE crossing is localized to two
 * visible `permute@1` reversals at plaintext-in / ciphertext-out. The pure math
 * below works on plain `number` u32 values (endianness-free); the codecs at the
 * bottom serialize.
 *
 * v1 fixes the key at 128 bits (`k = 2`). 192/256-bit keys (the k=3/4
 * h-function branches) are deferred follow-ups.
 */

import { gfMulPoly } from "../core/state/matrix";

/** 16 rounds. */
export const TWOFISH_ROUNDS = 16;
/** 128-bit block = 16 bytes = four little-endian 32-bit words. */
export const TWOFISH_BLOCK_BYTES = 16;
/** v1 key size — 128 bits. `k = kCycles = 2`. */
export const TWOFISH_KEY_BYTES = 16;
/** ρ = 0x01010101 — the round-index multiplier feeding h in the key schedule. */
export const TWOFISH_RHO = 0x01010101;

const MASK32 = 0xffffffff;

// ─── q-permutation construction (paper §4.3.5 / Ferguson twofish.c) ──────────
//
// The two 8→8-bit q-boxes are GENERATED from four 4→4-bit t-tables each. Storing
// the derived 256-byte tables directly would work too, but building them from
// the 64-nibble seed is smaller, self-documenting, and exactly how the spec
// defines them. The construction is verbatim from the Twofish specification.

/** The eight 4-bit t-tables (two q-boxes × four sub-tables). */
const T_TABLES: readonly (readonly (readonly number[])[])[] = [
  [
    [0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4],
    [0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd],
    [0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1],
    [0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa],
  ],
  [
    [0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5],
    [0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8],
    [0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf],
    [0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa],
  ],
];

/** A 1-bit right rotation of a 4-bit value. */
const ror4 = (x: number): number => ((x >> 1) | ((x << 3) & 0x8)) & 0xf;

/** Build one 256-entry q-box from its four t-tables (spec §4.3.5). */
const makeQ = (t: readonly (readonly number[])[]): Uint8Array => {
  const q = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    let ae = i >> 4;
    let be = i & 0xf;
    let ao = ae ^ be;
    let bo = ae ^ ror4(be) ^ ((ae << 3) & 8);
    ae = t[0]?.[ao & 0xf] ?? 0;
    be = t[1]?.[bo & 0xf] ?? 0;
    ao = ae ^ be;
    bo = ae ^ ror4(be) ^ ((ae << 3) & 8);
    ae = t[2]?.[ao & 0xf] ?? 0;
    be = t[3]?.[bo & 0xf] ?? 0;
    q[i] = ((be << 4) | ae) & 0xff;
  }
  return q;
};

/** The two fixed q-permutations, q0 and q1. */
export const TWOFISH_Q0: Uint8Array = makeQ(T_TABLES[0] as readonly (readonly number[])[]);
export const TWOFISH_Q1: Uint8Array = makeQ(T_TABLES[1] as readonly (readonly number[])[]);

// ─── MDS + RS matrices (published spec constants) ────────────────────────────

/** MDS matrix over GF(2⁸)/0x169 (spec §4.3.2). Displayed verbatim as the
 *  `gf-matrix-multiply@2` matrix param so a reader can cross-check it. */
export const TWOFISH_MDS: readonly (readonly number[])[] = [
  [0x01, 0xef, 0x5b, 0x5b],
  [0x5b, 0xef, 0xef, 0x01],
  [0xef, 0x5b, 0x01, 0xef],
  [0xef, 0x01, 0xef, 0x5b],
];

/** RS matrix over GF(2⁸)/0x14D (spec §4.3.1) — 4×8, folds the key into the
 *  S-vector that keys the S-boxes. */
export const TWOFISH_RS: readonly (readonly number[])[] = [
  [0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e],
  [0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5],
  [0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19],
  [0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03],
];

/** Field polynomials — the reduction constants for the two Twofish GF(2⁸)s. */
export const TWOFISH_MDS_POLY = 0x169;
export const TWOFISH_RS_POLY = 0x14d;

// ─── Rotations over 32-bit words ─────────────────────────────────────────────

const rol32 = (x: number, n: number): number => (((x << n) | (x >>> (32 - n))) & MASK32) >>> 0;

// ─── MDS multiply (used by the oracle; the SPEC does this as
//     gf-matrix-multiply@2 + a byte-reversal) ──────────────────────────────

/**
 * Multiply the 4-byte vector `z` by the MDS matrix over GF(2⁸)/0x169, returning
 * a `number` u32. The result's byte `r` (MDS output row r) sits at bit `8·r` —
 * i.e. `out0 | out1<<8 | out2<<16 | out3<<24`. This matches Ferguson's
 * MDS_table packing and therefore the integer value g feeds into the round's
 * modular adds. (In the visible spec, `gf-matrix-multiply@2` emits the four
 * bytes `[out0,out1,out2,out3]` and a `permute [3,2,1,0]` reverses them into
 * the big-endian encoding of exactly this value.)
 */
const mdsMul = (z: readonly number[]): number => {
  let v = 0;
  for (let r = 0; r < 4; r++) {
    let acc = 0;
    for (let k = 0; k < 4; k++) {
      acc ^= gfMulPoly(TWOFISH_MDS[r]?.[k] ?? 0, z[k] ?? 0, TWOFISH_MDS_POLY);
    }
    v |= (acc & 0xff) << (8 * r);
  }
  return v >>> 0;
};

/** RS multiply: 8 key bytes → 4-byte S-vector word (returned as 4 bytes). */
const rsMul = (key8: readonly number[]): number[] => {
  const out: number[] = [];
  for (let r = 0; r < 4; r++) {
    let acc = 0;
    for (let k = 0; k < 8; k++) {
      acc ^= gfMulPoly(TWOFISH_RS[r]?.[k] ?? 0, key8[k] ?? 0, TWOFISH_RS_POLY);
    }
    out.push(acc & 0xff);
  }
  return out;
};

// ─── The result of a key schedule ────────────────────────────────────────────

export type TwofishKeySchedule = {
  /** The 40 expanded subkeys K[0..39] as u32 values. K0..3 input whitening,
   *  K4..7 output whitening, K8..39 round keys (2 per round). */
  readonly K: readonly number[];
  /** The four key-dependent byte→byte S-boxes s0..s3 (256 bytes each). */
  readonly S: readonly Uint8Array[];
  /** The 20 A_i intermediates (h of the even key words) as u32 values. */
  readonly A: readonly number[];
  /** The 20 B_i intermediates (h of the odd key words, already ROL 8). */
  readonly B: readonly number[];
  /** The S-vector words S_0, S_1 (k=2) as u32 values, for the pedagogy panel. */
  readonly Svec: readonly number[];
  /** The four master-key words M0..M3 (little-endian reads of the key). */
  readonly M: readonly number[];
};

/**
 * Build the four key-dependent byte→byte S-boxes for a 128-bit key (k=2).
 *
 * Each S-box folds three q-box layers with two S-vector XORs (spec §4.3.2 h
 * with L = the S-vector). The final q-layer differs per lane (lanes 0/2 close
 * with q1, lanes 1/3 with q0) — this is the layer Ferguson folds into his
 * MDS_table, and omitting it is the classic first-attempt bug:
 *
 *   s0(x) = q1[ q0[ q0[x] ⊕ L8  ] ⊕ L0 ]
 *   s1(x) = q0[ q0[ q1[x] ⊕ L9  ] ⊕ L1 ]
 *   s2(x) = q1[ q1[ q0[x] ⊕ L10 ] ⊕ L2 ]
 *   s3(x) = q0[ q1[ q1[x] ⊕ L11 ] ⊕ L3 ]
 *
 * where (L0..L3) = S_1 (RS of key bytes 8..15) and (L8..L11) = S_0 (RS of key
 * bytes 0..7) — the S-vector's word-order reversal L = (S_{k-1}…S_0).
 */
const buildSboxes = (svecBytes: { S0: number[]; S1: number[] }): Uint8Array[] => {
  const q0 = TWOFISH_Q0;
  const q1 = TWOFISH_Q1;
  const [L0, L1, L2, L3] = svecBytes.S1 as [number, number, number, number]; // outer XOR
  const [L8, L9, L10, L11] = svecBytes.S0 as [number, number, number, number]; // inner XOR
  const s0 = new Uint8Array(256);
  const s1 = new Uint8Array(256);
  const s2 = new Uint8Array(256);
  const s3 = new Uint8Array(256);
  for (let x = 0; x < 256; x++) {
    s0[x] = q1[(q0[(q0[x] ?? 0) ^ L8] ?? 0) ^ L0] ?? 0;
    s1[x] = q0[(q0[(q1[x] ?? 0) ^ L9] ?? 0) ^ L1] ?? 0;
    s2[x] = q1[(q1[(q0[x] ?? 0) ^ L10] ?? 0) ^ L2] ?? 0;
    s3[x] = q0[(q1[(q1[x] ?? 0) ^ L11] ?? 0) ^ L3] ?? 0;
  }
  return [s0, s1, s2, s3];
};

/**
 * h evaluation for the KEY SCHEDULE. The input word is always k·ρ (all four
 * bytes equal `kByte`), so this takes the single byte and the two S/key words
 * in Ferguson's spacing: Lbytes = [outer word (L0..3), inner word (L8..11)].
 * Returns the u32 h output (same three-q-layer + MDS chain as the S-boxes).
 */
const hKeySchedule = (kByte: number, outer: number[], inner: number[]): number => {
  const q0 = TWOFISH_Q0;
  const q1 = TWOFISH_Q1;
  const [L0, L1, L2, L3] = outer as [number, number, number, number];
  const [L8, L9, L10, L11] = inner as [number, number, number, number];
  const b0 = q1[(q0[(q0[kByte] ?? 0) ^ L8] ?? 0) ^ L0] ?? 0;
  const b1 = q0[(q0[(q1[kByte] ?? 0) ^ L9] ?? 0) ^ L1] ?? 0;
  const b2 = q1[(q1[(q0[kByte] ?? 0) ^ L10] ?? 0) ^ L2] ?? 0;
  const b3 = q0[(q1[(q1[kByte] ?? 0) ^ L11] ?? 0) ^ L3] ?? 0;
  return mdsMul([b0, b1, b2, b3]);
};

/** Little-endian read of 4 key bytes at offset `o` → u32. */
const keyWordLE = (key: Uint8Array, o: number): number =>
  ((key[o] ?? 0) |
    ((key[o + 1] ?? 0) << 8) |
    ((key[o + 2] ?? 0) << 16) |
    ((key[o + 3] ?? 0) << 24)) >>>
  0;

/**
 * The full Twofish 128-bit key schedule — the KAT oracle. Produces the 40
 * subkeys, the four key-dependent S-boxes, and the A/B/S-vector intermediates
 * the pedagogy panel surfaces.
 */
export const twofishKeySchedule = (key: Uint8Array): TwofishKeySchedule => {
  if (key.length !== TWOFISH_KEY_BYTES) {
    throw new Error(
      `twofish: v1 supports 128-bit keys only — expected ${TWOFISH_KEY_BYTES} key bytes, got ${key.length}`,
    );
  }
  const k = Array.from(key);
  // S-vector (k=2): S_0 = RS(key[0..7]), S_1 = RS(key[8..15]).
  const S0 = rsMul(k.slice(0, 8));
  const S1 = rsMul(k.slice(8, 16));
  const S = buildSboxes({ S0, S1 });

  // Even/odd key-word byte groups in Ferguson's h spacing.
  const Me = [k.slice(0, 4), k.slice(8, 12)] as [number[], number[]]; // key words 0, 2
  const Mo = [k.slice(4, 8), k.slice(12, 16)] as [number[], number[]]; // key words 1, 3

  const K: number[] = new Array(40).fill(0);
  const A: number[] = new Array(20).fill(0);
  const B: number[] = new Array(20).fill(0);
  for (let i = 0; i < 20; i++) {
    const a = hKeySchedule((2 * i) & 0xff, Me[0], Me[1]);
    let b = hKeySchedule((2 * i + 1) & 0xff, Mo[0], Mo[1]);
    b = rol32(b, 8);
    A[i] = a;
    B[i] = b;
    const k2i = (a + b) >>> 0; // PHT: K_{2i} = A + B
    const bb = (b + k2i) >>> 0; // A + 2B  (= A + B + B)
    K[2 * i] = k2i;
    K[2 * i + 1] = rol32(bb, 9); // K_{2i+1} = ROL(A + 2B, 9)
  }

  return {
    K,
    S,
    A,
    B,
    // Big-endian packing so the u32 hex reads in the same byte order as the
    // S-vector bytes themselves (display convenience for the pedagogy panel).
    Svec: [bytesBEToU32(Uint8Array.from(S0)), bytesBEToU32(Uint8Array.from(S1))],
    M: [keyWordLE(key, 0), keyWordLE(key, 4), keyWordLE(key, 8), keyWordLE(key, 12)],
  };
};

/** g(X) = MDS · (s0[x0], s1[x1], s2[x2], s3[x3]), x_i = byte i of X (LE, x0=LSB).
 *  Pure oracle helper — the spec expresses this as the visible g chain. */
const g = (x: number, S: readonly Uint8Array[]): number => {
  const x0 = x & 0xff;
  const x1 = (x >>> 8) & 0xff;
  const x2 = (x >>> 16) & 0xff;
  const x3 = (x >>> 24) & 0xff;
  return mdsMul([S[0]?.[x0] ?? 0, S[1]?.[x1] ?? 0, S[2]?.[x2] ?? 0, S[3]?.[x3] ?? 0]);
};

/** Little-endian block codecs (Twofish's native serialization). */
const blockToWordsLE = (b: Uint8Array): number[] => [
  keyWordLE(b, 0),
  keyWordLE(b, 4),
  keyWordLE(b, 8),
  keyWordLE(b, 12),
];
const wordsToBlockLE = (w: readonly number[]): Uint8Array => {
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    const v = (w[i] ?? 0) >>> 0;
    out[i * 4] = v & 0xff;
    out[i * 4 + 1] = (v >>> 8) & 0xff;
    out[i * 4 + 2] = (v >>> 16) & 0xff;
    out[i * 4 + 3] = (v >>> 24) & 0xff;
  }
  return out;
};

/**
 * Encrypt one 16-byte block — the end-to-end KAT oracle. The spec builder
 * reproduces this exact sequence out of port-native primitives; the vectors
 * test pins both against Ferguson's reference.
 */
export const twofishEncryptBlock = (key: Uint8Array, pt: Uint8Array): Uint8Array => {
  if (pt.length !== TWOFISH_BLOCK_BYTES) {
    throw new Error(`twofish: block must be ${TWOFISH_BLOCK_BYTES} bytes, got ${pt.length}`);
  }
  const { K, S } = twofishKeySchedule(key);
  const [p0, p1, p2, p3] = blockToWordsLE(pt) as [number, number, number, number];
  let A = (p0 ^ (K[0] ?? 0)) >>> 0; // input whitening
  let B = (p1 ^ (K[1] ?? 0)) >>> 0;
  let C = (p2 ^ (K[2] ?? 0)) >>> 0;
  let D = (p3 ^ (K[3] ?? 0)) >>> 0;
  for (let r = 0; r < TWOFISH_ROUNDS; r++) {
    const t0 = g(A, S);
    const t1 = g(rol32(B, 8), S);
    const f0 = (t0 + t1 + (K[8 + 2 * r] ?? 0)) >>> 0;
    const f1 = (t0 + 2 * t1 + (K[8 + 2 * r + 1] ?? 0)) >>> 0;
    C = (((C ^ f0) >>> 1) | ((C ^ f0) << 31)) >>> 0; // ROR(C ⊕ F0, 1)
    D = (rol32(D, 1) ^ f1) >>> 0; // ROL(D,1) ⊕ F1
    // Feistel swap.
    const nA = C;
    const nB = D;
    C = A;
    D = B;
    A = nA;
    B = nB;
  }
  // Undo the final swap, then output whitening K4..K7.
  const y0 = C;
  const y1 = D;
  const y2 = A;
  const y3 = B;
  return wordsToBlockLE([
    (y0 ^ (K[4] ?? 0)) >>> 0,
    (y1 ^ (K[5] ?? 0)) >>> 0,
    (y2 ^ (K[6] ?? 0)) >>> 0,
    (y3 ^ (K[7] ?? 0)) >>> 0,
  ]);
};

// ─── Big-endian word codecs (the spec's internal port convention) ────────────

/** u32 → 4 big-endian bytes. */
export const u32ToBytesBE = (v: number): Uint8Array => {
  const out = new Uint8Array(4);
  out[0] = (v >>> 24) & 0xff;
  out[1] = (v >>> 16) & 0xff;
  out[2] = (v >>> 8) & 0xff;
  out[3] = v & 0xff;
  return out;
};

/** 4 big-endian bytes at offset `o` → u32. */
export const bytesBEToU32 = (b: Uint8Array, o = 0): number =>
  (((b[o] ?? 0) << 24) | ((b[o + 1] ?? 0) << 16) | ((b[o + 2] ?? 0) << 8) | (b[o + 3] ?? 0)) >>> 0;
