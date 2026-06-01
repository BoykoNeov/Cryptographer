/**
 * Speck32/64 decryption KAT + round-trip tests.
 *
 * The inverse cipher uses the same key schedule and consumes the round keys
 * in reverse leaf order. Both byte conventions are exercised — same word-
 * level computation, different byte serialisation at the boundary.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const decrypt = (spec: CipherSpec, ctHex: string, keyHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ctHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    // Speck rounds are port-native since B2 → the spec requires ported dispatch.
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes final state");
  return hexFromBytes(trace.finalState.bytes);
};

const encrypt = decrypt; // same shape; aliasing for readability

describe("Speck32/64 decryption", () => {
  it("BE-paper: decrypts the KAT ciphertext to the KAT plaintext", () => {
    expect(decrypt(speck32_64BeDecryptSpec, "a86842f2", "1918111009080100")).toBe("6574694c");
  });

  it("LE-NSA: decrypts the KAT ciphertext to the KAT plaintext", () => {
    expect(decrypt(speck32_64LeDecryptSpec, "f24268a8", "0001080910111819")).toBe("4c697465");
  });

  // Round-trip across a handful of arbitrary 4-byte inputs — exercises a
  // broader chunk of the byte space than the single KAT does.
  it("BE-paper: encrypt+decrypt round-trip is identity over arbitrary inputs", () => {
    const keyHex = "1918111009080100";
    for (const pt of ["00000000", "ffffffff", "deadbeef", "0123abcd", "1f2e3d4c"]) {
      const ct = encrypt(speck32_64BeSpec, pt, keyHex);
      const recovered = decrypt(speck32_64BeDecryptSpec, ct, keyHex);
      expect(recovered).toBe(pt);
    }
  });

  it("LE-NSA: encrypt+decrypt round-trip is identity over arbitrary inputs", () => {
    const keyHex = "0001080910111819";
    for (const pt of ["00000000", "ffffffff", "deadbeef", "0123abcd", "1f2e3d4c"]) {
      const ct = encrypt(speck32_64LeSpec, pt, keyHex);
      const recovered = decrypt(speck32_64LeDecryptSpec, ct, keyHex);
      expect(recovered).toBe(pt);
    }
  });

  it("inverse cipher emits the decomposed schedule + 22 inverse rounds (152 frames in BE-paper)", () => {
    // K2a (2026-06-01): identical frame-count math as the encrypt side (the
    // forward key-schedule decomposition is shared across encrypt/decrypt).
    // Decrypt consumes the round keys in reverse leaf order but the schedule
    // itself runs forward, so the BE-paper frame count is the same 152.
    const trace = runSpec(speck32_64BeDecryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("a86842f2")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("1918111009080100")]]),
    });
    expect(trace.frames.length).toBe(152);
  });

  it("decrypt leaf 1 references roundKey.21; decrypt leaf 22 references roundKey.0", () => {
    // The reversal lives in the spec leaves; verify by inspecting the params
    // of the first and last round-inverse leaves.
    const firstLeaf = speck32_64BeDecryptSpec.steps[1];
    const lastLeaf = speck32_64BeDecryptSpec.steps[22];
    if (!firstLeaf || firstLeaf.kind !== "step") throw new Error("expected leaf 1");
    if (!lastLeaf || lastLeaf.kind !== "step") throw new Error("expected leaf 22");
    expect(firstLeaf.id).toBe("round-inverse.1");
    expect(lastLeaf.id).toBe("round-inverse.22");
    expect((firstLeaf.params as { roundKeyAux: string }).roundKeyAux).toBe("roundKey.21");
    expect((lastLeaf.params as { roundKeyAux: string }).roundKeyAux).toBe("roundKey.0");
  });
});
