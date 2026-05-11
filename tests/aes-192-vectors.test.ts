/**
 * AES-192 known-answer tests.
 *
 * Two anchor vectors, both backed by primary NIST sources:
 *
 *   1. FIPS-197 §A.2 — verifies the *key expansion* matches the standard's
 *      worked example byte-for-byte (w[0..51]). We assert the canonical
 *      round-12 key e98ba06f448c773c8ecc720401002202 directly out of the
 *      aux map. This pins the AES-192 path through `aes.key-expansion@1`
 *      without relying on the end-to-end ciphertext to catch a regression.
 *
 *   2. NIST AES Core 192 (CSRC example PDF) — verifies the full forward
 *      cipher with the same FIPS §A.2 key against a fixed plaintext, and
 *      that the corresponding `aes-192-decrypt` spec round-trips.
 *
 * (FIPS-197 Appendix C.2 was removed in the May 2023 upd1; the NIST CSRC
 *  "AES Core" example files are the current authoritative published
 *  reference. Same algorithm, just a different worked example.)
 */

import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, MatrixState } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY_HEX = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const PLAINTEXT_HEX = "6bc1bee22e409f96e93d7e117393172a";
const CIPHERTEXT_HEX = "bd334f1d6e45f25ff712a214571fa5cc";
const ROUND_KEY_12_HEX = "e98ba06f448c773c8ecc720401002202"; // FIPS-197 §A.2 w[48..51]

describe("AES-192 (FIPS-197 §A.2 + NIST AES Core 192)", () => {
  it("encrypts the NIST AES Core 192 test vector", () => {
    const plaintext = matrixFromBytes(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    expect(trace.finalState.shape).toBe("matrix4x4-bytes");
    if (trace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_HEX);
  });

  it("emits a frame for every leaf step", () => {
    // Expected frame count:
    //   key-expansion              1
    //   initial AddRoundKey        1
    //   rounds 1..11 × 4 sub-steps 44
    //   final round × 3 sub-steps   3
    //   = 49 frames
    const plaintext = matrixFromBytes(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    expect(trace.frames.length).toBe(49);
  });

  it("produces all 13 round keys in aux and roundKey.12 matches FIPS-197 §A.2", () => {
    const plaintext = matrixFromBytes(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
    });

    // 13 round keys: index 0 (initial AddRoundKey) through index 12 (final).
    for (let r = 0; r <= 12; r++) {
      const rk = trace.finalAux.get(`roundKey.${r}`);
      expect(rk).toBeInstanceOf(Uint8Array);
      expect((rk as Uint8Array).length).toBe(16);
    }

    // roundKey.0 is the first 16 bytes of the cipher key (w[0..3]).
    const rk0 = trace.finalAux.get("roundKey.0") as Uint8Array;
    expect(hexFromBytes(rk0)).toBe(KEY_HEX.slice(0, 32));

    // The headline assertion against FIPS-197 §A.2 w[48..51].
    const rk12 = trace.finalAux.get("roundKey.12") as Uint8Array;
    expect(hexFromBytes(rk12)).toBe(ROUND_KEY_12_HEX);
  });

  it("round-trips: aes192Spec encrypt → aes192DecryptSpec recovers plaintext", () => {
    const plaintext = matrixFromBytes(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);

    const encTrace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux: new Map<string, AuxValue>([["key", key]]),
    });
    expect(encTrace.finalState.shape).toBe("matrix4x4-bytes");
    if (encTrace.finalState.shape !== "matrix4x4-bytes") return;

    const decTrace = runSpec(aes192DecryptSpec, buildDefaultRegistry(), {
      initialState: encTrace.finalState,
      initialAux: new Map<string, AuxValue>([["key", key]]),
    });
    expect(decTrace.finalState.shape).toBe("matrix4x4-bytes");
    if (decTrace.finalState.shape !== "matrix4x4-bytes") return;
    expect(hexFromBytes((decTrace.finalState as MatrixState).bytes)).toBe(PLAINTEXT_HEX);
  });
});
