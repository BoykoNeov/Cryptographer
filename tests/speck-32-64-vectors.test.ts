/**
 * Speck32/64 known-answer tests (Beaulieu et al. 2013, Table 4.1).
 *
 * The word-level KAT is the same for both byte conventions; we run it once
 * per convention to pin that the byte serialisation at the boundary is
 * correctly absorbed by the codec. A pre-implementation throwaway script
 * verified both expected ciphertexts before this file existed.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

describe("Speck32/64 (Beaulieu et al. 2013, Table 4.1)", () => {
  // BE-paper byte convention (paper-faithful visual order).
  describe("BE-paper byte convention", () => {
    const keyHex = "1918111009080100";
    const plaintextHex = "6574694c";
    const expectedHex = "a86842f2";

    it("encrypts the canonical test vector", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      expect(trace.finalState.shape).toBe("bytes");
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(expectedHex);
    });

    it("emits one frame per leaf step (decomposed schedule + 22 rounds = 152)", () => {
      // K2a (2026-06-01): the key schedule decomposed from a monolithic
      // `speck.key-schedule@1` leaf into ~130 port-native primitive leaves
      // (load-key + input-codec + master-split + 21 iterations × 6 leaves
      // each + publish = 130 frames), plus 22 round leaves = 152 total in
      // BE-paper mode. LE-NSA adds an output-concat + output-codec +
      // 22 byte-slice leaves on top of the 130 → its frame count differs.
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      expect(trace.frames.length).toBe(152);
    });

    it("produces all 22 round keys in aux", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      for (let i = 0; i < 22; i++) {
        const rk = trace.finalAux.get(`roundKey.${i}`);
        expect(rk).toBeInstanceOf(Uint8Array);
        expect((rk as Uint8Array).length).toBe(2); // 16 bits / 8
      }
      // roundKey.0 = k_0 = 0x0100 (paper). BE-encoded bytes are [0x01, 0x00].
      const rk0 = trace.finalAux.get("roundKey.0") as Uint8Array;
      expect(hexFromBytes(rk0)).toBe("0100");
    });
  });

  // LE-NSA byte convention (NSA reference / SUPERCOP).
  describe("LE-NSA byte convention", () => {
    const keyHex = "0001080910111819";
    const plaintextHex = "4c697465";
    const expectedHex = "f24268a8";

    it("encrypts the same word-level KAT under LE byte serialisation", () => {
      const trace = runSpec(speck32_64LeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      if (trace.finalState.shape !== "bytes") return;
      expect(hexFromBytes(trace.finalState.bytes)).toBe(expectedHex);
    });

    it("roundKey.0 differs only in byte order from the BE variant", () => {
      const trace = runSpec(speck32_64LeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      // BE rk0 is 01 00; LE rk0 is the same word (0x0100) written low-first → 00 01.
      const rk0 = trace.finalAux.get("roundKey.0") as Uint8Array;
      expect(hexFromBytes(rk0)).toBe("0001");
    });
  });

  it("emits a __coerce__ frame when keyed with the wrong byte length", () => {
    // K2a behavior change (2026-06-01): the legacy monolith threw a
    // descriptive `8 bytes` error from its own pre-condition check. The
    // decomposed schedule reads the master key via `aux-load-bytes@1` which
    // declares `byteLength: 8` on its output port; a wrong-sized aux value
    // triggers the runtime's port-length coercion (pad/truncate) and emits
    // a synthetic `__coerce__` frame the UI surfaces as a ⚠ badge. This is
    // the universal-port architecture's stated "coerce is visible, not
    // thrown" posture (see `coerce-timeline-badge.test.tsx`); the cipher
    // runs to completion with garbled output rather than crashing.
    // Picking a 7-byte value that's clearly NOT a prefix of the canonical key
    // 1918111009080100, so however the runtime coerces (zero-pad vs truncate)
    // it lands on a non-canonical 8-byte key and yields a non-canonical
    // ciphertext.
    const wrongLength = bytesFromHex("aabbccddeeff11"); // 7 bytes
    const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("6574694c")),
      initialAux: new Map<string, AuxValue>([["key", wrongLength]]),
    });
    const coerceFrames = trace.frames.filter((f) => f.stepType === "__coerce__");
    expect(coerceFrames.length).toBeGreaterThan(0);
    // The cipher completes but does NOT produce the canonical ciphertext.
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).not.toBe("a86842f2");
  });
});
