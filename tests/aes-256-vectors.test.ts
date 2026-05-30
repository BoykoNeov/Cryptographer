/**
 * AES-256 known-answer tests (byte-native, scaffolding-suppression Slice B1.3,
 * 2026-05-29).
 *
 * The spec is now built from port-native primitives with no legacy executor,
 * so it runs ONLY under `portedDispatchEnabled: true` and produces a `bytes`
 * finalState. Mirrors `aes-192-vectors.test.ts`, with one extra assertion:
 * roundKey.3 (w[12..15] in FIPS-197 §A.3 terms) directly pins the AES-256
 * "SubWord every i%Nk==4 words" branch in the key-expansion executor. The
 * value of w[12] depends on the SubWord-only branch firing for i=12 — if a
 * future edit accidentally guards that branch on `Nk === 8 && i === 4`
 * instead of `Nk > 6 && i % Nk === 4`, the end-to-end KAT might still pass
 * by coincidence, but roundKey.3 would not match. Key expansion is unchanged
 * by the byte-native rebuild (still the monolithic `aes.key-expansion@1`).
 *
 * (FIPS-197 Appendix C.3 was removed in the May 2023 upd1; the NIST CSRC
 *  "AES Core 256" example file is the current authoritative published
 *  reference for the ECB encryption KAT.)
 */

import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY_HEX = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const PLAINTEXT_HEX = "6bc1bee22e409f96e93d7e117393172a";
const CIPHERTEXT_HEX = "f3eed1bdb5d2a03c064b5a7e3db181f8";

// FIPS-197 §A.3 worked example: round keys 3 and 14, packed in column-major
// 4-byte words. Round 3 (w[12..15]) is the first round whose w[12] passes
// through the AES-256-only SubWord-only branch — see the file header.
const ROUND_KEY_3_HEX = "a8b09c1a93d194cdbe49846eb75d5b9a";
const ROUND_KEY_14_HEX = "fe4890d1e6188d0b046df344706c631e";

describe("AES-256 (FIPS-197 §A.3 + NIST AES Core 256)", () => {
  it("encrypts the NIST AES Core 256 test vector", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    const trace = runSpec(aes256Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
    });

    expect(trace.finalState.shape).toBe("bytes");
    if (trace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(trace.finalState.bytes)).toBe(CIPHERTEXT_HEX);
  });

  it("emits a frame for every leaf step", () => {
    // Byte-native AES-256 leaves (one frame each), after Finding F3 merged
    // AddRoundKey's fetch-rk + xor pair into one `xor-with-aux@1` leaf:
    //   key-expansion (1)
    //   initial.add-round-key (1)
    //   rounds 1..13 × 4 sub-steps = 52
    //   final round.14 × 3 sub-steps (no mix-columns) = 3
    //   = 57 frames
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes256Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
    });

    expect(trace.frames.length).toBe(57);
  });

  it("produces all 15 round keys; roundKey.3 pins the Nk>6 SubWord-only branch", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const initialAux = new Map<string, AuxValue>([["key", bytesFromHex(KEY_HEX)]]);

    const trace = runSpec(aes256Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux,
      portedDispatchEnabled: true,
    });

    // 15 round keys: index 0 through index 14.
    for (let r = 0; r <= 14; r++) {
      const rk = trace.finalAux.get(`roundKey.${r}`);
      expect(rk).toBeInstanceOf(Uint8Array);
      expect((rk as Uint8Array).length).toBe(16);
    }

    // roundKey.0 is the first 16 bytes of the 32-byte cipher key (w[0..3]).
    const rk0 = trace.finalAux.get("roundKey.0") as Uint8Array;
    expect(hexFromBytes(rk0)).toBe(KEY_HEX.slice(0, 32));

    // roundKey.1 is the next 16 bytes (w[4..7]) — still part of the original
    // cipher key, no expansion math yet.
    const rk1 = trace.finalAux.get("roundKey.1") as Uint8Array;
    expect(hexFromBytes(rk1)).toBe(KEY_HEX.slice(32, 64));

    // roundKey.3 (w[12..15]) — the AES-256 SubWord-only branch pins here.
    const rk3 = trace.finalAux.get("roundKey.3") as Uint8Array;
    expect(hexFromBytes(rk3)).toBe(ROUND_KEY_3_HEX);

    // Final round key — covers the end-to-end expansion correctness.
    const rk14 = trace.finalAux.get("roundKey.14") as Uint8Array;
    expect(hexFromBytes(rk14)).toBe(ROUND_KEY_14_HEX);
  });

  it("round-trips: aes256Spec encrypt → aes256DecryptSpec recovers plaintext", () => {
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);

    const encTrace = runSpec(aes256Spec, buildDefaultRegistry(), {
      initialState: plaintext,
      initialAux: new Map<string, AuxValue>([["key", key]]),
      portedDispatchEnabled: true,
    });
    expect(encTrace.finalState.shape).toBe("bytes");
    if (encTrace.finalState.shape !== "bytes") return;

    const decTrace = runSpec(aes256DecryptSpec, buildDefaultRegistry(), {
      initialState: encTrace.finalState,
      initialAux: new Map<string, AuxValue>([["key", key]]),
      portedDispatchEnabled: true,
    });
    expect(decTrace.finalState.shape).toBe("bytes");
    if (decTrace.finalState.shape !== "bytes") return;
    expect(hexFromBytes(decTrace.finalState.bytes)).toBe(PLAINTEXT_HEX);
  });

  it("throws when rounds disagrees with the key length", () => {
    // Pair a 32-byte key with rounds=10 to trip the Nk+6===rounds assertion
    // in the shared key-expansion executor.
    const plaintext = makeBytesState(bytesFromHex(PLAINTEXT_HEX));
    const key = bytesFromHex(KEY_HEX);
    const initialAux = new Map<string, AuxValue>([["key", key]]);

    // Clone the AES-256 spec and corrupt its rounds param to 10.
    const corrupted = structuredClone(aes256Spec);
    const ke = corrupted.steps[0];
    if (!ke || ke.kind !== "step") throw new Error("expected key-expansion leaf at index 0");
    (ke as { params: Record<string, unknown> }).params = {
      ...(ke.params as Record<string, unknown>),
      rounds: 10,
    };

    expect(() =>
      runSpec(corrupted, buildDefaultRegistry(), {
        initialState: plaintext,
        initialAux,
        portedDispatchEnabled: true,
      }),
    ).toThrow(/rounds.*must equal Nk\+6/);
  });
});
