/**
 * SHA-256 KAT parity matrix — universal-port plan Phase 2 close, Slice 2.11c
 * (2026-06-01).
 *
 * The comprehensive known-answer-test gate for Phase 2. `tests/sha-256.test.ts`
 * pins the canonical single-block "abc" KAT + the spec/frame structure; THIS
 * file pins the multi-block fold (Slice 2.11b) across the full length range:
 *
 *   1. **Published FIPS 180-4 vectors** — §A.1 ("abc", 1 block) and §A.2 (the
 *      56-byte 448-bit message, 2 blocks). Plus the two universally-tabulated
 *      edge vectors (empty string, single "a"). Exact-hex assertions — the
 *      gold standard, independent of any implementation.
 *
 *   2. **Boundary cross-check vs `node:crypto`** — a curated set of lengths
 *      straddling every block transition (55↔56, 63↔64↔65, 119↔120, 127↔128,
 *      191↔192, 255↔256) up to the live UI cap (512 bytes). These are where a
 *      padding / block-count / chain-threading bug hides. node:crypto is the
 *      external oracle (per the project's crypto-verification convention) for
 *      the arbitrary-pattern messages FIPS doesn't tabulate.
 *
 *   3. **Fold-engagement pins** — assert the per-block iterate actually runs
 *      the right number of times: 55 bytes → 1 block, 56 → 2, 120 → 3. The
 *      56/64-byte cases produced WRONG digests before Slice 2.11b (single-block
 *      only); their flipping green here is the cleanest proof the multi-block
 *      path engaged.
 *
 *   4. **Bounded multi-block stress** behind the `SHA256_STRESS` env flag — a
 *      few-KB message byte-equal to node:crypto. (The Slice 2.11 sketch said
 *      "10 MB"; that predates the Slice 2.6d decomposition, which made the
 *      tracing runtime emit ~2299 frames PER 64-byte block — 10 MB ≈ 156k
 *      blocks ≈ 360M frames, infeasible. The bounded stress proves the fold
 *      across many blocks without the explosion; it stays out of `npm run
 *      check` so the gate stays fast.)
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { runSpec } from "@/core/runtime";
import type { Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const traceOf = (plaintext: Uint8Array): Trace =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: plaintext },
  });

const sha256Hex = (plaintext: Uint8Array): string => {
  const trace = traceOf(plaintext);
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

const nodeHex = (plaintext: Uint8Array): string =>
  bytesToHex(new Uint8Array(createHash("sha256").update(plaintext).digest()));

// Distinct unique blockIndex values stamped on the trace frames = the number
// of times the per-block `blocks` iterate ran. The fold-engagement discriminator.
const blockCount = (trace: Trace): number => {
  const seen = new Set<number>();
  for (const f of trace.frames) {
    if (f.blockIndex !== undefined) seen.add(f.blockIndex);
  }
  return seen.size;
};

// Deterministic, length-parameterized byte pattern (not all-zero — zeros can
// mask byte-order bugs).
const pattern = (len: number): Uint8Array =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (i * 31 + 7) & 0xff));

// ─── 1. Published FIPS 180-4 / canonical vectors (exact hex) ──────────────

describe("SHA-256 KAT matrix — published vectors (exact hex)", () => {
  const cases: ReadonlyArray<{
    readonly label: string;
    readonly bytes: Uint8Array;
    readonly digest: string;
  }> = [
    {
      label: "empty string (canonical)",
      bytes: new Uint8Array(),
      digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    {
      label: "'a' (canonical)",
      bytes: new TextEncoder().encode("a"),
      digest: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    },
    {
      label: "FIPS 180-4 §A.1 'abc' (1 block)",
      bytes: new TextEncoder().encode("abc"),
      digest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    {
      label: "FIPS 180-4 §A.2 56-byte 448-bit message (2 blocks)",
      bytes: new TextEncoder().encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      digest: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
  ];

  for (const c of cases) {
    it(`${c.label}`, () => {
      expect(sha256Hex(c.bytes)).toBe(c.digest);
      // Independent cross-check: our exact-hex expectation matches node:crypto
      // too (guards against a transcription error in the expectation itself).
      expect(nodeHex(c.bytes)).toBe(c.digest);
    });
  }
});

// ─── 2. Boundary cross-check vs node:crypto ───────────────────────────────

describe("SHA-256 KAT matrix — block-boundary cross-check vs node:crypto", () => {
  // Lengths straddling every block transition up to the 512-byte UI cap. The
  // padding rule appends 0x80 + a 64-bit length, so L bytes occupy
  // ceil((L + 9) / 64) blocks — transitions at L ≡ 55 (mod 64).
  const lengths = [
    0, 1, 2, 3, 31, 32, 54, 55, 56, 57, 63, 64, 65, 118, 119, 120, 127, 128, 191, 192, 255, 256,
    383, 384, 511, 512,
  ];
  for (const len of lengths) {
    it(`length ${len} bytes matches node:crypto`, () => {
      const msg = pattern(len);
      expect(sha256Hex(msg)).toBe(nodeHex(msg));
    });
  }
});

// ─── 3. Fold-engagement pins (multi-block path actually runs) ─────────────

describe("SHA-256 KAT matrix — per-block fold engages the right block count", () => {
  // L bytes → ceil((L + 9) / 64) blocks. These three exercise 1, 2, and 3
  // iterations of the `blocks` iterate. The 56-byte case is the FIRST that
  // crosses into a second block — it (and 64) silently mis-hashed before
  // Slice 2.11b, so a correct digest here AND a block count of 2 together
  // prove the fold path engaged (not a fluke single-block coincidence).
  const cases: ReadonlyArray<{ readonly len: number; readonly blocks: number }> = [
    { len: 0, blocks: 1 },
    { len: 55, blocks: 1 },
    { len: 56, blocks: 2 },
    { len: 64, blocks: 2 },
    { len: 119, blocks: 2 },
    { len: 120, blocks: 3 },
  ];
  for (const c of cases) {
    it(`${c.len} bytes → ${c.blocks} block(s), digest matches node:crypto`, () => {
      const msg = pattern(c.len);
      const trace = traceOf(msg);
      expect(blockCount(trace)).toBe(c.blocks);
      if (trace.finalState.shape !== "bytes") throw new Error("unreachable");
      expect(bytesToHex(trace.finalState.bytes)).toBe(nodeHex(msg));
    });
  }
});

// ─── 4. Bounded multi-block stress (opt-in: SHA256_STRESS) ────────────────

const stressIt = process.env.SHA256_STRESS ? it : it.skip;

describe("SHA-256 KAT matrix — bounded multi-block stress (opt-in)", () => {
  // Run with `SHA256_STRESS=1 npx vitest run tests/sha-256-kat-matrix.test.ts`.
  // Kept out of `npm run check`: ~2299 frames/block means a 4 KB message is
  // ~64 blocks ≈ 147k frames — fine for a one-off, too heavy for the gate.
  stressIt("4096-byte message (64 blocks) matches node:crypto", () => {
    const msg = pattern(4096);
    expect(sha256Hex(msg)).toBe(nodeHex(msg));
  });

  stressIt("a sweep of every length 0..256 matches node:crypto", () => {
    for (let len = 0; len <= 256; len++) {
      const msg = pattern(len);
      expect(sha256Hex(msg), `length ${len}`).toBe(nodeHex(msg));
    }
  });
});
