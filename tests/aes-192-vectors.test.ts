/**
 * AES-192 known-answer tests (byte-native, scaffolding-suppression Slice B1.3,
 * 2026-05-29).
 *
 * The spec is now built from port-native primitives (`byte-substitute@1` /
 * `permute@1` / `gf-matrix-multiply@1` / `xor@1` + `aux-load-bytes@1`) with no
 * legacy executor, so it runs ONLY under `portedDispatchEnabled: true` and
 * produces a `bytes` finalState. Mirrors `aes-vectors.test.ts` (AES-128).
 *
 * Two anchor vectors, both backed by primary NIST sources:
 *
 *   1. FIPS-197 §A.2 — verifies the *key expansion* matches the standard's
 *      worked example byte-for-byte (w[0..51]). We assert the canonical
 *      round-12 key e98ba06f448c773c8ecc720401002202 directly out of the
 *      aux map. Key expansion is unchanged by the byte-native rebuild (still
 *      the monolithic `aes.key-expansion@1`), so this pins the same path.
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
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY_HEX = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const PLAINTEXT_HEX = "6bc1bee22e409f96e93d7e117393172a";
const CIPHERTEXT_HEX = "bd334f1d6e45f25ff712a214571fa5cc";
const ROUND_KEY_12_HEX = "e98ba06f448c773c8ecc720401002202"; // FIPS-197 §A.2 w[48..51]

describe("AES-192 (FIPS-197 §A.2 + NIST AES Core 192)", () => {
  it("encrypts the NIST AES Core 192 test vector", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_HEX);
  });

  it("emits a frame for every leaf step", () => {
    // Byte-native AES-192 leaves (one frame each), after Finding F3 merged
    // AddRoundKey's fetch-rk + xor pair into one `xor-with-aux@1` leaf:
    //   key-expansion (1)
    //   initial.add-round-key (1)
    //   rounds 1..11 × 4 sub-steps (sub-bytes, shift-rows, mix-columns,
    //     add-round-key) = 44
    //   final round.12 × 3 sub-steps (no mix-columns) = 3
    //   = 49 frames
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
    });

    expect(trace.frames.length).toBe(49);
  });

  it("produces all 13 round keys in aux and roundKey.12 matches FIPS-197 §A.2", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
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
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);

    const encTrace = runSpec(aes192Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux: new Map<string, AuxValue>([["key", key]]),
      portedDispatchEnabled: true,
    });
    expect(encTrace.finalState.shape).toBe("bytes");
    if (encTrace.finalState.shape !== "bytes") return;

    const decTrace = runSpec(aes192DecryptSpec, buildDefaultRegistry(), {
      initialState: encTrace.finalState,
      initialAux: new Map<string, AuxValue>([["key", key]]),
      portedDispatchEnabled: true,
    });
    expect(decTrace.finalState.shape).toBe("bytes");
    if (decTrace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(decTrace.finalState.bytes)).toBe(PLAINTEXT_HEX);
  });
});
