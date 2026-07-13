/**
 * SHAKE128 / SHAKE256 known-answer-test gate (FIPS 202), 2026-07-13.
 *
 * The correctness oracle for the assembled Keccak sponge in **XOF mode** — the
 * variable-length squeeze loop that distinguishes SHAKE from SHA3-256:
 *
 *   1. **Published / canonical vectors** (exact hex) — the empty message and
 *      "abc" at a 32-byte output, for both variants. Implementation-independent
 *      gold standard.
 *
 *   2. **`node:crypto` cross-check across TWO axes** — message length (straddling
 *      the rate boundary, where a padding / absorb-fold bug hides) AND output
 *      length (straddling the rate boundary, where the *squeeze loop* engages).
 *      A fixed-digest hash test only sweeps the first axis; a XOF must sweep both
 *      or the squeeze-and-permute loop is literally untested. node:crypto's
 *      `shake128`/`shake256` with `{ outputLength }` is the external oracle
 *      (project crypto-verification convention).
 *
 *   3. **Pad-merge edge case** — a message one byte short of a block, where the
 *      SHAKE domain byte (0x1F) and the trailing pad bit (0x80) merge into a
 *      single 0x9F. The SHAKE analogue of SHA-3's 0x86.
 *
 *   4. **Squeeze-block-count pins** — the unrolled squeeze builds the right
 *      number of `squeeze.perm.{j}` permutation groups: outputLength ≤ rate → 0
 *      extra permutations (single extract), rate+1 → 1, etc. Proof the squeeze
 *      loop actually grows with the requested length.
 */

import { createHash } from "node:crypto";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type ShakeVariant, buildShakeSpec } from "@/ciphers/shake";
import { runSpec } from "@/core/runtime";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const RATE: Record<ShakeVariant, number> = { shake128: 168, shake256: 136 };

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const shakeHex = (variant: ShakeVariant, message: Uint8Array, outputLength: number): string => {
  const trace = runSpec(buildShakeSpec(variant, outputLength), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: message },
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

const nodeHex = (variant: ShakeVariant, message: Uint8Array, outputLength: number): string =>
  bytesToHex(new Uint8Array(createHash(variant, { outputLength }).update(message).digest()));

// Deterministic, non-zero byte pattern (zeros can mask byte-order bugs).
const pattern = (len: number): Uint8Array =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (i * 31 + 7) & 0xff));

// Count the `squeeze.perm.{j}` permutation groups in a built spec — the
// structural signature of the unrolled squeeze loop.
const squeezePermCount = (spec: CipherSpec): number =>
  spec.steps.filter((n) => n.kind === "group" && n.id.startsWith("squeeze.perm.")).length;

// ─── 1. Published / canonical vectors (exact hex) ──────────────────────────

describe("SHAKE — published known-answer vectors", () => {
  it('SHAKE128("abc") @ 32 bytes', () => {
    expect(shakeHex("shake128", new Uint8Array([0x61, 0x62, 0x63]), 32)).toBe(
      "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );
  });

  it("SHAKE128(empty) @ 32 bytes", () => {
    expect(shakeHex("shake128", new Uint8Array(0), 32)).toBe(
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    );
  });

  it('SHAKE256("abc") @ 32 bytes', () => {
    expect(shakeHex("shake256", new Uint8Array([0x61, 0x62, 0x63]), 32)).toBe(
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
    );
  });

  it("SHAKE256(empty) @ 32 bytes", () => {
    expect(shakeHex("shake256", new Uint8Array(0), 32)).toBe(
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
    );
  });
});

// ─── 2. node:crypto cross-check across message × output length ─────────────

describe("SHAKE — byte-equal to node:crypto across message and output lengths", () => {
  for (const variant of ["shake128", "shake256"] as const) {
    const rate = RATE[variant];
    // Messages straddle the rate boundary (absorb-fold axis).
    const messageLengths = [0, 3, rate - 1, rate, rate + 5, 2 * rate + 3];
    // Output lengths straddle the rate boundary (squeeze-loop axis) up to the cap.
    const outputLengths = [1, rate - 1, rate, rate + 1, 2 * rate, 200, 512];
    for (const mlen of messageLengths) {
      for (const olen of outputLengths) {
        it(`${variant} msg=${mlen} out=${olen}`, () => {
          const msg = pattern(mlen);
          expect(shakeHex(variant, msg, olen)).toBe(nodeHex(variant, msg, olen));
        });
      }
    }
  }
});

// ─── 3. Pad-merge edge case (one byte short of a block → 0x9F) ─────────────

describe("SHAKE — pad10*1 merge case (domain 0x1F + 0x80 → 0x9F)", () => {
  for (const variant of ["shake128", "shake256"] as const) {
    const rate = RATE[variant];
    it(`${variant} message one byte short of a block matches node:crypto`, () => {
      const msg = pattern(rate - 1);
      expect(shakeHex(variant, msg, 64)).toBe(nodeHex(variant, msg, 64));
    });
    it(`${variant} exact-rate message (full extra pad block) matches node:crypto`, () => {
      const msg = pattern(rate);
      expect(shakeHex(variant, msg, 64)).toBe(nodeHex(variant, msg, 64));
    });
  }
});

// ─── 4. Squeeze-block-count pins (the unrolled loop grows with length) ─────

describe("SHAKE — squeeze loop unrolls the right number of permutations", () => {
  for (const variant of ["shake128", "shake256"] as const) {
    const rate = RATE[variant];
    it(`${variant}: output ≤ rate → single extract, no extra permutation`, () => {
      expect(squeezePermCount(buildShakeSpec(variant, 1))).toBe(0);
      expect(squeezePermCount(buildShakeSpec(variant, rate))).toBe(0);
    });
    it(`${variant}: output rate+1 → 1 extra permutation`, () => {
      expect(squeezePermCount(buildShakeSpec(variant, rate + 1))).toBe(1);
    });
    it(`${variant}: output 3·rate → 2 extra permutations (ceil(3r/r)=3 blocks)`, () => {
      expect(squeezePermCount(buildShakeSpec(variant, 3 * rate))).toBe(2);
    });
  }
});
