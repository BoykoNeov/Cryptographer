import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

/**
 * The whole point of these tests is to validate the modularity claim:
 *   - aes128DecryptSpec uses the SAME registry as aes128Spec
 *   - No new step executors needed for decryption
 *   - Both forward and inverse share the same key-expansion step verbatim
 */

describe("AES-128 decryption (FIPS-197 §5.3)", () => {
  // Matched ciphertext/plaintext/key triples from FIPS-197 Appendix C.1.
  const plaintextHex = "00112233445566778899aabbccddeeff";
  const keyHex = "000102030405060708090a0b0c0d0e0f";
  const ciphertextHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

  it("decrypts the FIPS-197 C.1 ciphertext back to its plaintext", () => {
    const ct = matrixFromBytes(bytesFromHex(ciphertextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);

    const trace = runSpec(aes128DecryptSpec, buildDefaultRegistry(), {
      initialState: ct,
      initialAux,
    });

    expect(trace.finalState.shape).toBe("matrix4x4-bytes");
    if (trace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(plaintextHex);
  });

  it("encrypt then decrypt returns the original plaintext (round-trip)", () => {
    // Use a non-canonical plaintext to make sure we're not accidentally
    // encoding a constant somewhere in the trace.
    const pt = "deadbeefcafebabe1122334455667788";
    const k = "0f0e0d0c0b0a09080706050403020100";
    const registry = buildDefaultRegistry();
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(k)]]);

    // Forward: pt -> ct
    const fwd = runSpec(aes128Spec, registry, {
      initialState: matrixFromBytes(bytesFromHex(pt)),
      initialAux,
    });
    if (fwd.finalState.shape !== "matrix4x4-bytes") throw new Error("bad shape");
    const ct = hexFromBytes(fwd.finalState.bytes);
    expect(ct).not.toBe(pt); // sanity: encryption did *something*

    // Inverse: ct -> pt (using the same key, which the inverse re-expands)
    const inv = runSpec(aes128DecryptSpec, registry, {
      initialState: matrixFromBytes(bytesFromHex(ct)),
      initialAux,
    });
    if (inv.finalState.shape !== "matrix4x4-bytes") throw new Error("bad shape");
    expect(hexFromBytes(inv.finalState.bytes)).toBe(pt);
  });

  it("uses no step types beyond what the forward cipher uses", () => {
    // Modularity check: the registry built for forward AES is sufficient
    // for the inverse cipher too. If this test ever needs a registry tweak
    // to pass, something has accidentally hardcoded "encrypt" assumptions.
    const registry = buildDefaultRegistry();
    const ct = matrixFromBytes(bytesFromHex(ciphertextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);

    expect(() =>
      runSpec(aes128DecryptSpec, registry, { initialState: ct, initialAux }),
    ).not.toThrow();
  });

  it("emits the same number of frames as the forward cipher", () => {
    // 1 key-expansion + 1 initial AddRoundKey + 9 rounds × 4 substeps + 1
    // final round × 3 substeps = 41 frames. Same shape as forward, which
    // makes the side-by-side comparison meaningful in the UI.
    const ct = matrixFromBytes(bytesFromHex(ciphertextHex));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]);
    const trace = runSpec(aes128DecryptSpec, buildDefaultRegistry(), {
      initialState: ct,
      initialAux,
    });
    expect(trace.frames.length).toBe(41);
  });
});
