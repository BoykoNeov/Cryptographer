/**
 * SHA3-256 known-answer-test gate (FIPS 202), 2026-07-13.
 *
 * The correctness oracle for the whole assembled Keccak sponge:
 *
 *   1. **Published / canonical vectors** (exact hex) — the empty message,
 *      "abc" (FIPS 202 §A.1 example), and the classic "quick brown fox"
 *      vector. Implementation-independent gold standard.
 *
 *   2. **`node:crypto` cross-check across the 136-byte rate boundary** — lengths
 *      straddling every block transition (135↔136↔137, 271↔272↔273) up to a
 *      trace-legible cap. This is where a padding / block-count / chain-threading
 *      bug hides; node:crypto's `sha3-256` is the external oracle (project
 *      crypto-verification convention).
 *
 *   3. **Pad-merge edge case** — a message one byte short of a block, where the
 *      domain byte (0x06) and the trailing pad bit (0x80) merge into a single
 *      0x86. A frequent source of Keccak bugs.
 *
 *   4. **Fold-engagement pins** — the per-block sponge iterate runs the right
 *      number of times (blockIndex count): <136 bytes → 1 absorb, 136 → 2, 272
 *      → 3. Proof the multi-block absorb actually engaged.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha3256Spec } from "@/ciphers/sha3-256";
import { runSpec } from "@/core/runtime";
import type { Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const traceOf = (plaintext: Uint8Array): Trace =>
  runSpec(buildSha3256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: plaintext },
  });

const sha3Hex = (plaintext: Uint8Array): string => {
  const trace = traceOf(plaintext);
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

const nodeHex = (plaintext: Uint8Array): string =>
  bytesToHex(new Uint8Array(createHash("sha3-256").update(plaintext).digest()));

const blockCount = (trace: Trace): number => {
  const seen = new Set<number>();
  for (const f of trace.frames) {
    if (f.blockIndex !== undefined) seen.add(f.blockIndex);
  }
  return seen.size;
};

// Deterministic, non-zero byte pattern (zeros can mask byte-order bugs).
const pattern = (len: number): Uint8Array =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (i * 31 + 7) & 0xff));

// ─── 1. Published / canonical vectors (exact hex) ──────────────────────────

describe("SHA3-256 — published known-answer vectors", () => {
  it("empty message", () => {
    expect(sha3Hex(new Uint8Array(0))).toBe(
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    );
  });

  it('"abc" (FIPS 202 §A.1)', () => {
    expect(sha3Hex(new Uint8Array([0x61, 0x62, 0x63]))).toBe(
      "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    );
  });

  it('"The quick brown fox jumps over the lazy dog"', () => {
    const msg = new TextEncoder().encode("The quick brown fox jumps over the lazy dog");
    expect(sha3Hex(msg)).toBe("69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04");
  });
});

// ─── 2. node:crypto cross-check across the rate boundary ───────────────────

describe("SHA3-256 — byte-equal to node:crypto across block transitions", () => {
  // 135/136/137 straddle the first rate boundary; 271/272/273 the second.
  const lengths = [0, 1, 55, 71, 135, 136, 137, 200, 271, 272, 273];
  for (const len of lengths) {
    it(`length ${len}`, () => {
      const msg = pattern(len);
      expect(sha3Hex(msg)).toBe(nodeHex(msg));
    });
  }
});

// ─── 3. Pad-merge edge case ─────────────────────────────────────────────────

describe("SHA3-256 — pad10*1 merge case (one byte short of a block)", () => {
  it("135-byte message (domain 0x06 + 0x80 merge to 0x86) matches node:crypto", () => {
    const msg = pattern(135);
    expect(sha3Hex(msg)).toBe(nodeHex(msg));
  });

  it("136-byte message (exact rate → a full extra all-pad block) matches node:crypto", () => {
    const msg = pattern(136);
    expect(sha3Hex(msg)).toBe(nodeHex(msg));
  });
});

// ─── 4. Fold-engagement pins ────────────────────────────────────────────────

describe("SHA3-256 — sponge absorb fold runs the right number of blocks", () => {
  it("a sub-rate message absorbs in 1 block", () => {
    expect(blockCount(traceOf(pattern(100)))).toBe(1);
  });

  it("a 136-byte message absorbs in 2 blocks (padding adds a full block)", () => {
    expect(blockCount(traceOf(pattern(136)))).toBe(2);
  });

  it("a 272-byte message absorbs in 3 blocks", () => {
    expect(blockCount(traceOf(pattern(272)))).toBe(3);
  });
});
