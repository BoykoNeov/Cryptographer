/**
 * Slice 1.3 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`), updated for Slice 5.2.
 *
 * The SIX padding step types went **port-native in Slice 5.2** (2026-05-31):
 * they dropped their `legacy:` lift for true `PortedExecutor`s (bytes in/out
 * on the `state` port, `meta` retained for stateInputPort/stateOutputPort).
 *
 *   - `generic.pkcs7-pad@1`       - RFC 5652 §6.3 PKCS#7 padding
 *   - `generic.pkcs7-unpad@1`     - inverse; throws on malformed input
 *   - `generic.zero-pad@1`        - ISO/IEC 9797-1 method 1 (lossy)
 *   - `generic.zero-unpad@1`      - inverse; lossy, never throws on shape
 *   - `generic.iso7816-4-pad@1`   - sentinel-marked padding (0x80 + zeros)
 *   - `generic.iso7816-4-unpad@1` - inverse; throws on missing sentinel
 *
 * Because they no longer carry a legacy executor, a flag-OFF run throws
 * "requires portedDispatchEnabled" — there is no legacy frame stream left to
 * compare against. The original flag-off-vs-flag-on frame parity (suites a/c)
 * and the dual-path throw checks (suite d) were therefore reduced to flag-ON
 * assertions — the same reduction B2/B3/B4 applied to the cipher dispatch
 * tests once their bodies went port-native. The byte-level KAT behavior of
 * each scheme stays independently pinned by `tests/pkcs7-pad.test.ts`,
 * `tests/zero-pad.test.ts`, and `tests/iso7816-4-pad.test.ts`.
 *
 * Four test surfaces (all flag-ON):
 *
 *   (a) **Per-step-type KAT floor** — one synthetic spec per step type, run
 *       under ported dispatch; assert the padded/unpadded result.
 *   (b) **Pad+unpad round-trip equivalence** — pad then immediately unpad,
 *       assert the result equals the original input.
 *   (c) **Already-aligned input edge cases** — the three schemes diverge as
 *       documented (PKCS#7 full extra block, zero no-op, ISO 0x80 + zeros).
 *   (d) **Throw on malformed input** — pkcs7-unpad on a corrupt padded block,
 *       iso7816-4-unpad on an all-zeros block, both under the ported path.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Spec builder + ported run helper ───────────────────────────────────

/**
 * Single-step spec scaffolded for a padding leaf. Each step is exercised in
 * isolation so any drift surfaces in the smallest-possible failing assertion.
 */
const singleStepSpec = (id: string, stepType: string, blockSize: number): CipherSpec => ({
  id,
  name: `Slice 1.3 ${stepType} smoke`,
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    {
      kind: "step",
      id: "the-step",
      type: stepType,
      params: { blockSize },
    },
  ],
});

// Padding is port-native since Slice 5.2 → every run is flag-on.
const runPorted = (spec: CipherSpec, initial: Uint8Array): ReturnType<typeof runSpec> =>
  runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(initial),
  });

// 5-byte plaintext "apple" — short enough to fit in one 16-byte block.
const APPLE_5 = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);

// 16-byte aligned input — exercises the "already a clean block multiple"
// edge case that splits the three pad schemes most sharply.
const ALIGNED_16 = new Uint8Array(16).fill(0x42);

// ─── (a) Per-step-type KAT floor ────────────────────────────────────────

describe("runtime — ported dispatch, padding primitives (port-native since Slice 5.2)", () => {
  describe("(a) per-step-type KAT floor under ported dispatch", () => {
    it("generic.pkcs7-pad@1 pads 'apple' to a 16-byte block ending in 0x0b", () => {
      const spec = singleStepSpec("pkcs7-pad-smoke@1", "generic.pkcs7-pad@1", 16);
      const ported = runPorted(spec, APPLE_5);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[15]).toBe(0x0b); // 11 = 0x0b pad length
    });

    it("generic.pkcs7-unpad@1 strips PKCS#7 padding back to 'apple'", () => {
      // Pre-padded 16-byte input: "apple" + 11 copies of 0x0b.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);
      padded.fill(0x0b, 5);

      const spec = singleStepSpec("pkcs7-unpad-smoke@1", "generic.pkcs7-unpad@1", 16);
      const ported = runPorted(spec, padded);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("generic.zero-pad@1 pads 'apple' to a 16-byte block ending in 0x00", () => {
      const spec = singleStepSpec("zero-pad-smoke@1", "generic.zero-pad@1", 16);
      const ported = runPorted(spec, APPLE_5);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[15]).toBe(0x00);
    });

    it("generic.zero-unpad@1 strips trailing zeros back to 'apple'", () => {
      // Pre-zero-padded 16-byte input: "apple" + 11 zero bytes.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);

      const spec = singleStepSpec("zero-unpad-smoke@1", "generic.zero-unpad@1", 16);
      const ported = runPorted(spec, padded);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("generic.iso7816-4-pad@1 pads 'apple' with a 0x80 sentinel at offset 5", () => {
      const spec = singleStepSpec("iso7816-4-pad-smoke@1", "generic.iso7816-4-pad@1", 16);
      const ported = runPorted(spec, APPLE_5);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(ported.finalState.bytes[5]).toBe(0x80);
    });

    it("generic.iso7816-4-unpad@1 strips the sentinel + zeros back to 'apple'", () => {
      // Pre-padded: "apple" + 0x80 + 10 zero bytes = 16 total.
      const padded = new Uint8Array(16);
      padded.set(APPLE_5, 0);
      padded[5] = 0x80;

      const spec = singleStepSpec("iso7816-4-unpad-smoke@1", "generic.iso7816-4-unpad@1", 16);
      const ported = runPorted(spec, padded);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });
  });

  // ─── (b) Pad+unpad round-trip equivalence ────────────────────────────

  describe("(b) pad+unpad round-trip preserves original bytes under ported path", () => {
    const padUnpadSpec = (padType: string, unpadType: string, blockSize: number): CipherSpec => ({
      id: `roundtrip-${padType}@1`,
      name: `Slice 1.3 ${padType} + ${unpadType} round-trip`,
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "pad", type: padType, params: { blockSize } },
        { kind: "step", id: "unpad", type: unpadType, params: { blockSize } },
      ],
    });

    it("PKCS#7 round-trip recovers the original under ported dispatch", () => {
      const spec = padUnpadSpec("generic.pkcs7-pad@1", "generic.pkcs7-unpad@1", 16);
      const trace = runPorted(spec, APPLE_5);
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("zero-pad round-trip recovers the original (non-zero-terminating input) under ported dispatch", () => {
      const spec = padUnpadSpec("generic.zero-pad@1", "generic.zero-unpad@1", 16);
      const trace = runPorted(spec, APPLE_5);
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });

    it("ISO 7816-4 round-trip recovers the original under ported dispatch", () => {
      const spec = padUnpadSpec("generic.iso7816-4-pad@1", "generic.iso7816-4-unpad@1", 16);
      const trace = runPorted(spec, APPLE_5);
      if (trace.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(Array.from(trace.finalState.bytes)).toEqual(Array.from(APPLE_5));
    });
  });

  // ─── (c) Already-aligned input edge cases (the three schemes diverge) ──

  describe("(c) already-aligned input — three pad schemes diverge as documented", () => {
    it("PKCS#7 appends a full extra block of 0x10 when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("pkcs7-pad-aligned@1", "generic.pkcs7-pad@1", 16);
      const ported = runPorted(spec, ALIGNED_16);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(32);
      // Trailing 16 bytes are all 0x10 (= blockSize), per PKCS#7's "add full
      // extra block on alignment" rule. RFC 5652 §6.3.
      for (let i = 16; i < 32; i++) {
        expect(ported.finalState.bytes[i]).toBe(0x10);
      }
    });

    it("zero-pad is a no-op passthrough when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("zero-pad-aligned@1", "generic.zero-pad@1", 16);
      const ported = runPorted(spec, ALIGNED_16);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(16);
      expect(Array.from(ported.finalState.bytes)).toEqual(Array.from(ALIGNED_16));
    });

    it("ISO 7816-4 appends 0x80 + 15 zeros when input is already block-aligned (under ported)", () => {
      const spec = singleStepSpec("iso7816-4-pad-aligned@1", "generic.iso7816-4-pad@1", 16);
      const ported = runPorted(spec, ALIGNED_16);
      if (ported.finalState.shape !== "bytes") throw new Error("unexpected shape");
      expect(ported.finalState.bytes.length).toBe(32);
      expect(ported.finalState.bytes[16]).toBe(0x80);
      for (let i = 17; i < 32; i++) {
        expect(ported.finalState.bytes[i]).toBe(0x00);
      }
    });
  });

  // ─── (d) Throw on malformed input under the ported path ───────────────

  describe("(d) malformed-input throws survive the ported path", () => {
    it("pkcs7-unpad throws on a block with mismatched trailing bytes", () => {
      // 16-byte block claiming pad length 5 (last byte = 0x05) but with
      // a mismatched byte in the trailing pad region. Triggers the
      // "padding byte at offset N is X, expected 5" throw.
      const malformed = new Uint8Array(16);
      malformed.fill(0xab, 0, 11); // 11 data bytes
      malformed.fill(0x05, 11); // 5 supposed pad bytes
      malformed[12] = 0x99; // corrupt one of them

      const spec = singleStepSpec("pkcs7-unpad-malformed@1", "generic.pkcs7-unpad@1", 16);
      expect(() => runPorted(spec, malformed)).toThrow(
        /pkcs7-unpad: padding byte at offset 12 is 153, expected 5/,
      );
    });

    it("iso7816-4-unpad throws on an all-zeros block (no sentinel)", () => {
      const allZeros = new Uint8Array(16); // already zero-initialized

      const spec = singleStepSpec("iso7816-4-unpad-no-sentinel@1", "generic.iso7816-4-unpad@1", 16);
      expect(() => runPorted(spec, allZeros)).toThrow(/no 0x80 sentinel found/);
    });
  });
});
