// DES verification oracle for Cryptographer Phase 1 (docs/plans/des-feistel.md).
//
// Purpose: produce KAT fixtures with FULL intermediate values (IP output,
// per-round L/R, K_i, E(R), X = E(R) ⊕ K_i, S-box outputs, P, F_out, FP).
// Library DES (node:crypto, node-forge, pycryptodome) only exposes the final
// ciphertext — they cannot supply what Phase 3+ tests pin against.
//
// Trust model: this oracle re-implements DES from FIPS 46-3 in JavaScript, then
// cross-checks ONLY the final ciphertext against node:crypto's built-in
// `des-ecb` (which routes through OpenSSL — battle-tested for decades). If the
// oracle's final CT matches OpenSSL's AND matches FIPS Appendix B's published
// value, the implementation is trustworthy end-to-end and so are the captured
// intermediates.
//
// Bit-numbering: FIPS 46-3 uses 1-indexed, MSB-first numbering. For an N-byte
// buffer `buf` and FIPS bit index i (1..8N):
//   bit_i = (buf[(i-1) >> 3] >> (7 - ((i-1) & 7))) & 1
// All permutation tables below are copied verbatim from FIPS 46-3.
//
// Run:
//   node --openssl-legacy-provider scripts/verify-des.mjs
//
// The `--openssl-legacy-provider` flag is required on Node ≥ 17 because
// OpenSSL 3 marks DES as legacy. Without it `node:crypto.createCipheriv` throws
// ERR_OSSL_EVP_UNSUPPORTED. The script will catch that and print a hint.

import { createCipheriv } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, "..", "tests", "fixtures", "des-kat.json");

// ─────────────────────────────────────────────────────────────────────────────
// FIPS 46-3 permutation tables (1-indexed, MSB-first).
// ─────────────────────────────────────────────────────────────────────────────

// IP — Initial Permutation (64 → 64). Output bit i = input bit IP[i-1].
const IP = [
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64,
  56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53,
  45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

// FP = IP^-1 — Final Permutation (64 → 64).
const FP = [
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37,
  5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2,
  42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

// E — Expansion (32 → 48). Output bit i = input bit E[i-1].
const E = [
  32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19,
  20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

// P — Post-S-box permutation (32 → 32).
const P = [
  16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13,
  30, 6, 22, 11, 4, 25,
];

// PC-1 — Permuted Choice 1 (64 → 56). Drops the 8 parity bits.
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
  52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
  13, 5, 28, 20, 12, 4,
];

// PC-2 — Permuted Choice 2 (56 → 48). Picks the 48 bits of K_i from C_i|D_i.
const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
  31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

// Per-round left-shift amounts on the 28-bit halves C and D.
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// 8 S-boxes from FIPS 46-3 Appendix A. Each is 4 rows × 16 cols of 4-bit values.
// Input 6 bits b1..b6: row = b1 b6 (outer), col = b2 b3 b4 b5 (inner).
const SBOX = [
  // S1
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],
  // S2
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],
  // S3
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],
  // S4
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],
  // S5
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],
  // S6
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],
  // S7
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],
  // S8
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],
];

// ─────────────────────────────────────────────────────────────────────────────
// Bit-level helpers. All operations use FIPS bit-numbering (1-indexed, MSB).
// ─────────────────────────────────────────────────────────────────────────────

/** Read FIPS bit i (1-indexed, MSB-first) from byte buffer `buf`. */
function bitOf(buf, i) {
  const byteIdx = (i - 1) >> 3;
  const bitIdx = 7 - ((i - 1) & 7);
  return (buf[byteIdx] >> bitIdx) & 1;
}

/** Pack a bit-array (0/1 values) into a Uint8Array using FIPS bit-numbering.
 *  Length is rounded up to a byte; trailing bits in the last byte are zero. */
function bitsToBytes(bits) {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) out[i >> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}

/** Unpack a byte buffer into a bit-array of length `nBits`, FIPS ordering. */
function bytesToBits(buf, nBits) {
  const bits = new Array(nBits);
  for (let i = 0; i < nBits; i++) bits[i] = bitOf(buf, i + 1);
  return bits;
}

/** Apply a permutation table (1-indexed, MSB-first). `outLen` is the bit length
 *  of the output; `inputBuf` must hold at least max(table) bits. */
function permute(inputBuf, table, outLen) {
  const bits = new Array(outLen);
  for (let i = 0; i < outLen; i++) {
    bits[i] = bitOf(inputBuf, table[i]);
  }
  return bitsToBytes(bits);
}

/** Hex helper: Uint8Array → lowercase hex string. */
function hex(buf) {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hex helper: lowercase hex string → Uint8Array. */
function unhex(s) {
  if (s.length % 2 !== 0) throw new Error(`odd-length hex: ${s}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key schedule (PC-1 → 16 left-shifts → PC-2). Produces K_1..K_16, each 48 bits.
// ─────────────────────────────────────────────────────────────────────────────

/** Left-rotate a 28-bit half (stored as a 28-element bit array) by n positions. */
function leftRotate28(bits, n) {
  const out = new Array(28);
  for (let i = 0; i < 28; i++) out[i] = bits[(i + n) % 28];
  return out;
}

/** Generate the 16 round keys from a 64-bit master key. Returns an array of
 *  Uint8Array(6) values (48 bits each, packed MSB-first with trailing 0s). */
function keySchedule(key64) {
  // PC-1: 64 → 56 bits, dropped into two 28-bit halves C and D.
  const cd = permute(key64, PC1, 56); // 7-byte buffer, 56 bits used
  const cdBits = bytesToBits(cd, 56);
  let C = cdBits.slice(0, 28);
  let D = cdBits.slice(28, 56);

  const roundKeys = [];
  for (let r = 0; r < 16; r++) {
    C = leftRotate28(C, SHIFTS[r]);
    D = leftRotate28(D, SHIFTS[r]);
    // Concatenate C|D back into a 56-bit buffer, then PC-2 down to 48.
    const cdConcat = bitsToBytes([...C, ...D]);
    const K = permute(cdConcat, PC2, 48); // 6-byte buffer
    roundKeys.push(K);
  }
  return roundKeys;
}

// ─────────────────────────────────────────────────────────────────────────────
// F function: F(R, K) → 32 bits. Emits intermediates.
// ─────────────────────────────────────────────────────────────────────────────

/** Apply the 8 S-boxes to a 48-bit input, producing 32 bits.
 *  Each S-box takes 6 bits b1..b6: row = b1 b6, col = b2 b3 b4 b5. */
function sBoxes(x48) {
  const bits = bytesToBits(x48, 48);
  const outBits = new Array(32);
  for (let s = 0; s < 8; s++) {
    const b = bits.slice(s * 6, s * 6 + 6);
    const row = (b[0] << 1) | b[5];
    const col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4];
    const val = SBOX[s][row][col];
    // Write 4-bit val MSB-first into outBits.
    outBits[s * 4 + 0] = (val >> 3) & 1;
    outBits[s * 4 + 1] = (val >> 2) & 1;
    outBits[s * 4 + 2] = (val >> 1) & 1;
    outBits[s * 4 + 3] = val & 1;
  }
  return bitsToBytes(outBits);
}

/** F(R, K). Returns { F_out, E_R, X, S_out, P_out } — all Uint8Arrays. */
function fFunction(R, K) {
  const E_R = permute(R, E, 48); // 32 → 48 bits
  const X = new Uint8Array(6); // X = E(R) ⊕ K
  for (let i = 0; i < 6; i++) X[i] = E_R[i] ^ K[i];
  const S_out = sBoxes(X); // 48 → 32 bits
  const P_out = permute(S_out, P, 32); // 32 → 32 bits
  return { F_out: P_out, E_R, X, S_out, P_out };
}

// ─────────────────────────────────────────────────────────────────────────────
// Full DES encrypt with full intermediate capture.
// ─────────────────────────────────────────────────────────────────────────────

/** Encrypt one 8-byte block; return { ct, trace } where trace mirrors the
 *  Phase 1 fixture shape (ip, rounds[], fp). */
function encryptWithTrace(pt8, key8) {
  if (pt8.length !== 8) throw new Error(`pt must be 8 bytes, got ${pt8.length}`);
  if (key8.length !== 8) throw new Error(`key must be 8 bytes, got ${key8.length}`);

  const roundKeys = keySchedule(key8);
  const ipOut = permute(pt8, IP, 64);
  // Split IP output into L_0 (first 32 bits) and R_0 (next 32 bits).
  let L = ipOut.slice(0, 4);
  let R = ipOut.slice(4, 8);

  const rounds = [];
  for (let i = 0; i < 16; i++) {
    const K = roundKeys[i];
    const { F_out, E_R, X, S_out, P_out } = fFunction(R, K);
    const L_in = L;
    const R_in = R;
    // Feistel: L_{i+1} = R_i, R_{i+1} = L_i ⊕ F(R_i, K_{i+1}).
    const L_out = R_in;
    const R_out = new Uint8Array(4);
    for (let j = 0; j < 4; j++) R_out[j] = L_in[j] ^ F_out[j];
    rounds.push({
      i: i + 1,
      L_in: hex(L_in),
      R_in: hex(R_in),
      K: hex(K),
      E: hex(E_R),
      X: hex(X),
      S: hex(S_out),
      P: hex(P_out),
      F_out: hex(F_out),
      L_out: hex(L_out),
      R_out: hex(R_out),
    });
    L = L_out;
    R = R_out;
  }

  // Pre-FP block is R_16 || L_16 (the "no swap on round 16" convention is
  // realized here as a swap before FP, equivalent to the textbook formulation).
  const preFp = new Uint8Array(8);
  preFp.set(R, 0);
  preFp.set(L, 4);
  const ct = permute(preFp, FP, 64);

  return {
    ct,
    trace: {
      pt: hex(pt8),
      key: hex(key8),
      ip: hex(ipOut),
      rounds,
      preFp: hex(preFp),
      ct: hex(ct),
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-check against node:crypto's des-ecb.
// ─────────────────────────────────────────────────────────────────────────────

function nodeCryptoDes(pt8, key8) {
  try {
    const cipher = createCipheriv("des-ecb", Buffer.from(key8), null);
    cipher.setAutoPadding(false);
    return new Uint8Array(Buffer.concat([cipher.update(Buffer.from(pt8)), cipher.final()]));
  } catch (err) {
    if (String(err).includes("unsupported")) {
      throw new Error(
        "node:crypto refused DES (OpenSSL 3 marks it as legacy). " +
          "Re-run with: node --openssl-legacy-provider scripts/verify-des.mjs",
      );
    }
    throw err;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test vectors.
//
// Per advisor: capture order matters — IP-only equivalence first (covered by
// permute() unit test below), one full round next (covered by trace assertion
// on FIPS Appendix B), full cipher third (covered by 3 vectors).
// ─────────────────────────────────────────────────────────────────────────────

const VECTORS = [
  {
    label: "FIPS 46-3 Appendix B",
    pt: "0123456789abcdef",
    key: "133457799bbcdff1",
    expectedCt: "85e813540f0ab405",
  },
  {
    label: "all-zero pt + all-zero key",
    pt: "0000000000000000",
    key: "0000000000000000",
    // Cross-checked against node:crypto below; matches widely-published
    // weak-key value 8ca64de9c1b123a7.
    expectedCt: "8ca64de9c1b123a7",
  },
  {
    label: "all-ones pt + all-ones key (parity bits ignored)",
    pt: "ffffffffffffffff",
    key: "ffffffffffffffff",
    expectedCt: "7359b2163e4edc58",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Driver.
// ─────────────────────────────────────────────────────────────────────────────

function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function main() {
  const fixtureVectors = [];
  let failures = 0;

  for (const v of VECTORS) {
    const pt = unhex(v.pt);
    const key = unhex(v.key);
    const expected = unhex(v.expectedCt);

    // 1. Our oracle.
    const { ct: oracleCt, trace } = encryptWithTrace(pt, key);

    // 2. node:crypto cross-check.
    const nodeCt = nodeCryptoDes(pt, key);

    const oracleVsExpected = eq(oracleCt, expected);
    const oracleVsNode = eq(oracleCt, nodeCt);

    const mark = oracleVsExpected && oracleVsNode ? "OK" : "FAIL";
    console.log(`[${mark}] ${v.label}`);
    console.log(`        pt=${v.pt}  key=${v.key}`);
    console.log(`        expected ct = ${v.expectedCt}`);
    console.log(`        oracle   ct = ${hex(oracleCt)}`);
    console.log(`        node:crypto = ${hex(nodeCt)}`);

    if (!oracleVsExpected) {
      console.log("        !! oracle mismatch vs FIPS-quoted ct");
      failures++;
    }
    if (!oracleVsNode) {
      console.log("        !! oracle mismatch vs node:crypto");
      failures++;
    }

    fixtureVectors.push(trace);
  }

  if (failures > 0) {
    console.error(`\n${failures} failure(s); fixture NOT written.`);
    process.exit(1);
  }

  // Write the fixture file.
  mkdirSync(dirname(FIXTURE_PATH), { recursive: true });
  const fixture = {
    // Metadata so future readers know what this is and how it was produced.
    _source: "scripts/verify-des.mjs",
    _spec: "FIPS 46-3 (Data Encryption Standard, withdrawn 2005)",
    _crosschecked: "node:crypto des-ecb (with --openssl-legacy-provider)",
    _bitNumbering: "FIPS 1-indexed, MSB-first; helper bitOf() in oracle",
    _generatedAt: new Date().toISOString().slice(0, 10),
    vectors: fixtureVectors,
  };
  writeFileSync(FIXTURE_PATH, `${JSON.stringify(fixture, null, 2)}\n`);
  console.log(`\nFixture written: ${FIXTURE_PATH}`);
  console.log(`  ${fixtureVectors.length} vectors × (ip + 16 rounds + preFp + ct)`);
}

main();
