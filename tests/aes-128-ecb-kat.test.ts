/**
 * NIST SP 800-38A Appendix F.1 — AES-128 in ECB mode, known-answer tests.
 *
 * - F.1.1: ECB-AES128.Encrypt
 * - F.1.2: ECB-AES128.Decrypt
 *
 * The plaintext / ciphertext samples are 4 × 16 = 64 bytes (4 blocks). Same
 * sample reused in F.2 (CBC) and F.5 (CTR) — when those phases land they
 * will reference these same byte sequences, just with different
 * ciphertexts.
 *
 * No padding overlay is exercised here: the input is already a clean
 * 64-byte multiple of the block size, so we feed it directly into the
 * unpadded ECB spec. PKCS#7 + multi-block boundary cases get their own
 * test file once `paddingLimits` is updated.
 *
 * Byte-native (scaffolding-suppression Slice B1.4): the ECB spec is a
 * port-graph (port-mode `iterate`) and runs on the universal port-native
 * dispatch path like every shipped spec.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "2b7e151628aed2a6abf7158809cf4f3c";

// SP 800-38A §F (concatenated 4 blocks, no spaces).
const PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

// SP 800-38A §F.1.1 (ECB-AES128.Encrypt).
const ECB_CIPHERTEXT_4_BLOCKS =
  "3ad77bb40d7a3660a89ecaf32466ef97" +
  "f5d3d58503b9699de785895a96fdbaaf" +
  "43b1cd7f598ece23881b00e3ed030688" +
  "7b0c785e27e8ad3f8223207104725dd4";

describe("AES-128 ECB (NIST SP 800-38A §F.1)", () => {
  it("F.1.1: encrypts the 4-block plaintext to the published ciphertext", () => {
    const initial = makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);

    const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: aux,
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(ECB_CIPHERTEXT_4_BLOCKS);
  });

  it("F.1.2: decrypts the 4-block ciphertext to the original plaintext", () => {
    const initial = makeBytesState(bytesFromHex(ECB_CIPHERTEXT_4_BLOCKS));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);

    const trace = runSpec(aes128EcbDecryptSpec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: aux,
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(PLAINTEXT_4_BLOCKS);
  });

  it("emits a frame per child step per iteration with :b{i} suffixes", () => {
    const initial = makeBytesState(bytesFromHex(PLAINTEXT_4_BLOCKS));
    const aux = new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]);
    const trace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: initial,
      initialAux: aux,
    });

    // DECOMPOSED key schedule (key-schedule-decomposition K1a) runs once,
    // outside the per-block loop: 114 non-iterating frames (load-key + 10
    // groups × 10 + word-stream + rk0..10 + publish). Each per-block body emits
    // the same 40 frames as byte-native single-block aes-128:
    //   initial AddRoundKey (1)
    //   + rounds 1..9 × 4 (sub/shift/mix/add — 36)
    //   + final round × 3 (sub/shift/add — 3) = 40
    // 4 blocks × 40 = 160 iterating frames. Total = 114 + 160 = 274.
    expect(trace.frames.length).toBe(274);

    // Spot-check: the first AddRoundKey inside iteration 0 must end in :b0.
    const firstAddRoundKey = trace.frames.find(
      (f) => f.stepId.startsWith("initial.add-round-key") && f.blockIndex === 0,
    );
    expect(firstAddRoundKey?.stepId).toBe("initial.add-round-key:b0");

    // And iteration 3's final-round AddRoundKey ends in :b3.
    const lastAddRoundKey = trace.frames.find(
      (f) => f.stepId.startsWith("round.10.add-round-key") && f.blockIndex === 3,
    );
    expect(lastAddRoundKey?.stepId).toBe("round.10.add-round-key:b3");
  });

  it("round-trips an arbitrary 32-byte plaintext through encrypt → decrypt", () => {
    const plaintext = bytesFromHex(
      "deadbeefcafebabe0011223344556677" + "8899aabbccddeefffeeddccbbaa99887",
    );
    const key = bytesFromHex("0123456789abcdef0123456789abcdef");

    const encTrace = runSpec(aes128EcbSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(plaintext),
      initialAux: new Map<string, AuxValue>([["key", key]]),
    });
    expect(encTrace.finalState.shape).toBe("bytes");
    if (encTrace.finalState.shape !== "bytes") return;

    const decTrace = runSpec(aes128EcbDecryptSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(encTrace.finalState.bytes),
      initialAux: new Map<string, AuxValue>([["key", key]]),
    });
    expect(decTrace.finalState.shape).toBe("bytes");
    if (decTrace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(decTrace.finalState.bytes)).toBe(hexFromBytes(plaintext));
  });
});
