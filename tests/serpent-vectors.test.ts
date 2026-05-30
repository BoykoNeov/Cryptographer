/**
 * Serpent known-answer tests.
 *
 * The expected ciphertexts here were obtained by running the Python
 * reference implementation from `CryptoPlus/Cipher/pyserpent.py` (a
 * direct transcription of Anderson/Biham/Knudsen's reference code from
 * the AES submission). The reference test set is the standard
 * "single-bit key, all-zero plaintext" vector:
 *
 *   key       = 80…0  (byte 0 = 0x80, rest zero)
 *   plaintext = 00…0
 *
 * Under Serpent's LSB-first-within-bytes bit-stream convention, this
 * corresponds to setting state bit 7 of the key (the high bit of byte 0).
 * Both this implementation and the Python reference use the same
 * convention, so the byte sequence `80 00 … 00` produces identical bits
 * across both implementations.
 *
 * These vectors exercise the entire pipeline — key expansion (with
 * padding for the 128- and 192-bit variants), 32 rounds, IP and FP — and
 * a single-bit difference in either side propagates through the cipher's
 * full diffusion. A wholesale wrong byte order, wrong IP table, or wrong
 * S-box indexing in the schedule shows up as a mismatch on the first
 * frame.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const runCipher = (spec: CipherSpec, keyHex: string, inputHex: string): string => {
  // Serpent's round body is port-native since Slice B3 → the specs require
  // ported dispatch (the native rounds throw under the legacy path).
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
    portedDispatchEnabled: true,
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("Serpent known-answer tests (Python reference, key=80…0 / pt=0)", () => {
  it("Serpent-128: key=80…0, plaintext=0 → 264e5481eff42a4606abda06c0bfda3d", () => {
    expect(
      runCipher(
        serpent128Spec,
        "80000000000000000000000000000000",
        "00000000000000000000000000000000",
      ),
    ).toBe("264e5481eff42a4606abda06c0bfda3d");
  });

  it("Serpent-128 decrypts the reference ciphertext back to all-zero plaintext", () => {
    expect(
      runCipher(
        serpent128DecryptSpec,
        "80000000000000000000000000000000",
        "264e5481eff42a4606abda06c0bfda3d",
      ),
    ).toBe("00000000000000000000000000000000");
  });

  it("Serpent-192: key=80…0, plaintext=0 → 9e274ead9b737bb21efcfca548602689", () => {
    expect(
      runCipher(
        serpent192Spec,
        "800000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
      ),
    ).toBe("9e274ead9b737bb21efcfca548602689");
  });

  it("Serpent-192 decrypts the reference ciphertext back to all-zero plaintext", () => {
    expect(
      runCipher(
        serpent192DecryptSpec,
        "800000000000000000000000000000000000000000000000",
        "9e274ead9b737bb21efcfca548602689",
      ),
    ).toBe("00000000000000000000000000000000");
  });

  it("Serpent-256: key=80…0, plaintext=0 → a223aa1288463c0e2be38ebd825616c0", () => {
    expect(
      runCipher(
        serpent256Spec,
        "8000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
      ),
    ).toBe("a223aa1288463c0e2be38ebd825616c0");
  });

  it("Serpent-256 decrypts the reference ciphertext back to all-zero plaintext", () => {
    expect(
      runCipher(
        serpent256DecryptSpec,
        "8000000000000000000000000000000000000000000000000000000000000000",
        "a223aa1288463c0e2be38ebd825616c0",
      ),
    ).toBe("00000000000000000000000000000000");
  });
});

describe("Serpent known-answer tests — extra cross-checks against the Python reference", () => {
  // Additional vectors run through the Python reference at implementation
  // time. Each crosses a different code path (zero key, non-trivial
  // plaintext, sequential key bytes) so a regression in one piece of the
  // cipher gets caught even if the headline single-bit vector still works.
  it("Serpent-128: key=0 / pt=0 → 3620b17ae6a993d09618b8768266bae9", () => {
    expect(
      runCipher(
        serpent128Spec,
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
      ),
    ).toBe("3620b17ae6a993d09618b8768266bae9");
  });

  it("Serpent-128: key=0 / pt=80…0 → a3b35de7c358ddd82644678c64b8bcbb", () => {
    expect(
      runCipher(
        serpent128Spec,
        "00000000000000000000000000000000",
        "80000000000000000000000000000000",
      ),
    ).toBe("a3b35de7c358ddd82644678c64b8bcbb");
  });

  it("Serpent-128: key=seq / pt=mixed → b483819bfa8a71a71c508634cee948e6", () => {
    // key bytes = [0..15], plaintext bytes = [0, 16, 32, 48, ..., 240]
    expect(
      runCipher(
        serpent128Spec,
        "000102030405060708090a0b0c0d0e0f",
        "00102030405060708090a0b0c0d0e0f0",
      ),
    ).toBe("b483819bfa8a71a71c508634cee948e6");
  });
});
