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

    it("emits one frame per leaf step (1 schedule + 22 rounds = 23)", () => {
      const trace = runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex(plaintextHex)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
        // Speck rounds are port-native since B2 → the spec requires ported dispatch.
      });
      expect(trace.frames.length).toBe(23);
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

  it("rejects keys with the wrong byte length", () => {
    // 7-byte key instead of 8 — should throw a clear error from the schedule step.
    const tooShort = bytesFromHex("19181110090801");
    expect(() =>
      runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
        initialState: makeBytesState(bytesFromHex("6574694c")),
        initialAux: new Map<string, AuxValue>([["key", tooShort]]),
        // Key-schedule is port-native since Slice 5.2 → the executor's
        // length validation fires under ported dispatch (flag-off would throw
        // "requires portedDispatchEnabled" before reaching it).
      }),
    ).toThrow(/8 bytes/);
  });
});
