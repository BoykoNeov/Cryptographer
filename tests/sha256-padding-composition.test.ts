/**
 * SHA-256 padding composition KAT — universal-port plan Phase 2 Slice 2.4
 * (2026-05-24).
 *
 * Pins the FIPS 180-4 §A.1 "abc" padded block as the result of chaining
 * `pad-with-byte@1` (with SHA-256 parameters) and `append-be64-length@1`
 * (using the original message as length-source). Cross-checked against
 * `node:crypto`'s SHA-256 only by way of the final hash (Slice 2.6's
 * job); this slice's gate is just the **64-byte preprocessing block**.
 *
 * Why this lives in a dedicated file:
 *  - The per-primitive test files (`pad-with-byte.test.ts`,
 *    `append-be64-length.test.ts`, `constant-load.test.ts`) verify each
 *    leaf in isolation. The composition exercises that the WIRING is
 *    correct (the `length-source` port reads from BEFORE padding, not
 *    AFTER) — the load-bearing property of the two-port decoupling.
 *  - Also covers the H_0..H_7 + K_0 byte sequences via `constant-load@1`
 *    (so the constant chips ship with their canonical FIPS values pinned
 *    here, not only in the per-primitive doc).
 *
 * Reference: FIPS 180-4 §A.1 "SHA-256 Example (Single-Block Message)"
 * — the expected padded 64-byte block is the canonical first-example.
 */

import type { Json, StepContext } from "@/core/types";
import { appendBe64Length } from "@/steps/append-be64-length";
import { constantLoad } from "@/steps/constant-load";
import { padWithByte } from "@/steps/pad-with-byte";
import { describe, expect, it } from "vitest";

// ─── Helpers ──────────────────────────────────────────────────────────────

const CTX: StepContext = { stepId: "test", path: [], aux: new Map() };

const callPad = (input: Uint8Array, params: Json): Uint8Array => {
  const out = padWithByte(new Map([["input", input]]), params, CTX);
  return out.get("output") as Uint8Array;
};

const callAppendLen = (data: Uint8Array, lengthSource: Uint8Array): Uint8Array => {
  const out = appendBe64Length(
    new Map([
      ["data", data],
      ["length-source", lengthSource],
    ]),
    {} as Json,
    CTX,
  );
  return out.get("output") as Uint8Array;
};

const callConst = (bytes: readonly number[]): Uint8Array => {
  const out = constantLoad(new Map(), { bytes: bytes as number[] }, CTX);
  return out.get("output") as Uint8Array;
};

const SHA256_PAD_PARAMS = { padByte: 0x80, blockSize: 64, padTarget: 56 };

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

// ─── (1) FIPS 180-4 §A.1 "abc" preprocessing ──────────────────────────────

describe("SHA-256 padding composition — 'abc' (FIPS 180-4 §A.1)", () => {
  it("pad-with-byte + append-be64-length composes to the canonical 64-byte padded block", () => {
    // Original message: ASCII "abc" — 3 bytes.
    const message = new Uint8Array([0x61, 0x62, 0x63]);

    // Step 1: pad to 56 bytes ending with 0x80 + zeros.
    const padded = callPad(message, SHA256_PAD_PARAMS);
    expect(padded.length).toBe(56);

    // Step 2: append 8-byte BE encoding of bitLength = 3 × 8 = 24 = 0x18.
    // Critical: length-source is the ORIGINAL message (3 bytes), NOT the
    // padded data (56 bytes). The wiring is the load-bearing property.
    const block = callAppendLen(padded, message);
    expect(block.length).toBe(64);

    // FIPS 180-4 §A.1 canonical padded block:
    //   "abc" || 0x80 || 52 × 0x00 || 0x0000000000000018  (64 bytes)
    //
    // Layout via template literal: "abc" (3 bytes = 6 hex) + sentinel +
    // 52 zero bytes (104 hex) + BE64(24) length suffix (16 hex) = 128.
    const expected = `616263 80${"00".repeat(52)}0000000000000018`.replace(/\s/g, "");
    expect(expected.length).toBe(128); // sanity: 64 bytes × 2 hex chars
    expect(hex(block)).toBe(expected);
  });

  it("decoupling check: passing PADDED bytes as length-source yields the WRONG suffix", () => {
    // This is the failure mode the two-port design protects against —
    // if a spec author wires `length-source` to the padded output by
    // mistake, the resulting suffix would encode 56 × 8 = 448 bits
    // instead of 24, and the hash output would not match any standard
    // KAT. Pinning the misuse explicitly so a future refactor that
    // collapses the two ports into one (and silently breaks the
    // bit-length semantics) fails CI.
    const message = new Uint8Array([0x61, 0x62, 0x63]);
    const padded = callPad(message, SHA256_PAD_PARAMS);

    const wrongBlock = callAppendLen(padded, padded); // BUG path
    expect(wrongBlock.length).toBe(64);

    // Last 8 bytes encode 56 × 8 = 448 = 0x1c0, not 24 = 0x18.
    // i.e., wrong-suffix last byte is 0xc0, not 0x18.
    expect(wrongBlock[63]).toBe(0xc0);
    expect(wrongBlock[62]).toBe(0x01);
  });
});

// ─── (2) Empty-input preprocessing ────────────────────────────────────────

describe("SHA-256 padding composition — empty message", () => {
  it("empty message → 56 + 8 = 64-byte block ending with 0x80 + 55 zeros + BE64(0)", () => {
    const message = new Uint8Array(0);
    const padded = callPad(message, SHA256_PAD_PARAMS);
    const block = callAppendLen(padded, message);

    expect(block.length).toBe(64);
    expect(block[0]).toBe(0x80);
    // Bytes [1, 56) are zeros. Bytes [56, 64) encode 0 in BE64 — all zeros.
    for (let i = 1; i < 64; i++) {
      expect(block[i]).toBe(0x00);
    }
  });
});

// ─── (3) Multi-block preprocessing (the 56-byte boundary) ────────────────

describe("SHA-256 padding composition — multi-block boundary", () => {
  it("55-byte input fits in a single 64-byte block", () => {
    const message = new Uint8Array(55).fill(0xaa);
    const padded = callPad(message, SHA256_PAD_PARAMS);
    expect(padded.length).toBe(56); // sentinel completes the 56-prefix

    const block = callAppendLen(padded, message);
    expect(block.length).toBe(64); // single block

    // BE64(55 × 8) = BE64(440) = 0x1b8. Low byte 0xb8, next byte 0x01.
    expect(block[63]).toBe(0xb8);
    expect(block[62]).toBe(0x01);
  });

  it("56-byte input forces a SECOND block (no room for the length suffix)", () => {
    const message = new Uint8Array(56).fill(0xbb);
    const padded = callPad(message, SHA256_PAD_PARAMS);
    expect(padded.length).toBe(120); // wrapped to next padTarget

    const block = callAppendLen(padded, message);
    expect(block.length).toBe(128); // two blocks (2 × 64)

    // BE64(56 × 8) = BE64(448) = 0x1c0.
    expect(block[127]).toBe(0xc0);
    expect(block[126]).toBe(0x01);

    // Sentinel lives at index 56 (right after the original 56 bytes).
    expect(block[56]).toBe(0x80);
    // Bytes [57, 120) are zeros (block 1 tail + block 2 head before
    // the length suffix at [120, 128)).
    for (let i = 57; i < 120; i++) {
      expect(block[i]).toBe(0x00);
    }
  });
});

// ─── (4) FIPS 180-4 H_0..H_7 + K_0 emitted by constant-load@1 ────────────

describe("SHA-256 constants via constant-load@1 (FIPS 180-4 §5.3.3 + §4.2.2)", () => {
  it("H_0..H_7 round-trip byte-equal", () => {
    // Canonical FIPS 180-4 §5.3.3 — first 32 bits of fractional parts of
    // square roots of the first 8 primes.
    const H = [
      [0x6a, 0x09, 0xe6, 0x67],
      [0xbb, 0x67, 0xae, 0x85],
      [0x3c, 0x6e, 0xf3, 0x72],
      [0xa5, 0x4f, 0xf5, 0x3a],
      [0x51, 0x0e, 0x52, 0x7f],
      [0x9b, 0x05, 0x68, 0x8c],
      [0x1f, 0x83, 0xd9, 0xab],
      [0x5b, 0xe0, 0xcd, 0x19],
    ];
    for (let i = 0; i < H.length; i++) {
      const out = callConst(H[i] as number[]);
      expect(Array.from(out)).toEqual(H[i]);
    }
  });

  it("K_0 = 0x428a2f98 — first round constant from cube root of 2", () => {
    const K0 = [0x42, 0x8a, 0x2f, 0x98];
    const out = callConst(K0);
    expect(Array.from(out)).toEqual(K0);
  });

  it("72 constant-load leaves (8 H + 64 K) can be instantiated without aliasing", () => {
    // Smoke test: synthesize all 72 SHA-256 constants and confirm every
    // call produces a fresh, independent Uint8Array. This is the
    // pedagogical-cost gate from Slice 2.4's Open #N2 user pick.
    const H = [
      [0x6a, 0x09, 0xe6, 0x67],
      [0xbb, 0x67, 0xae, 0x85],
      [0x3c, 0x6e, 0xf3, 0x72],
      [0xa5, 0x4f, 0xf5, 0x3a],
      [0x51, 0x0e, 0x52, 0x7f],
      [0x9b, 0x05, 0x68, 0x8c],
      [0x1f, 0x83, 0xd9, 0xab],
      [0x5b, 0xe0, 0xcd, 0x19],
    ];
    // Use a placeholder K table — actual K values are checked separately;
    // this test only counts the leaf instantiations.
    const K = Array.from({ length: 64 }, (_, i) => [i & 0xff, 0, 0, 0]);
    const all = [...H, ...K];
    expect(all.length).toBe(72);

    const buffers = all.map((bytes) => callConst(bytes));
    expect(buffers.length).toBe(72);

    // No two output buffers share underlying storage.
    for (let i = 0; i < buffers.length; i++) {
      for (let j = i + 1; j < buffers.length; j++) {
        expect((buffers[i] as Uint8Array).buffer).not.toBe((buffers[j] as Uint8Array).buffer);
      }
    }
  });
});
