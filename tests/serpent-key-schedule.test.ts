/**
 * Serpent key-schedule pin tests.
 *
 * The S-box indexing in the key schedule is reversed and offset relative
 * to the round body (S_{(35-i) mod 8} for the i-th group of four prekey
 * words). It's a classic off-by-one trap; an end-to-end cipher KAT will
 * pass if EITHER side of the encryption produces a coincidentally-correct
 * output for a specific (key, plaintext), but the round keys themselves
 * are the early ground truth.
 *
 * The expected round-key values below were obtained from the Python
 * reference's `makeSubkeys()`. They are the IP-applied "KHat" round keys
 * (which is what our implementation stores in aux — see
 * `serpent-key-expansion.ts`), serialized to bytes via the same LSB-first
 * within-bytes convention as the rest of the cipher.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const getRoundKey = (spec: CipherSpec, keyHex: string, idx: number): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00000000000000000000000000000000")),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  const rk = trace.finalAux.get(`roundKey.${idx}`);
  if (!(rk instanceof Uint8Array)) throw new Error(`missing roundKey.${idx}`);
  return hexFromBytes(rk);
};

describe("Serpent key schedule — pinned round keys", () => {
  const KEY_80 = "80000000000000000000000000000000";
  const KEY_80_192 = "800000000000000000000000000000000000000000000000";
  const KEY_80_256 = "8000000000000000000000000000000000000000000000000000000000000000";

  it("Serpent-128 / key=80…0 / roundKey.0 = b46649f7a611ad78bf8c2de9f39b34e5", () => {
    expect(getRoundKey(serpent128Spec, KEY_80, 0)).toBe("b46649f7a611ad78bf8c2de9f39b34e5");
  });

  it("Serpent-128 / key=80…0 / roundKey.32 = b5f5b78d074f6ec2c5f7db6be8b72a49", () => {
    expect(getRoundKey(serpent128Spec, KEY_80, 32)).toBe("b5f5b78d074f6ec2c5f7db6be8b72a49");
  });

  // Serpent-192 exercises the same key schedule but with a 192-bit input
  // padded to 256 bits. roundKey.0 depends on the entire 256-bit padded
  // input, so a wrong padding byte position (0x80 vs 0x01, or wrong byte
  // index) shows up here.
  it("Serpent-192 / key=80…0 / roundKey.0 differs from Serpent-128's (different padding)", () => {
    const rk128 = getRoundKey(serpent128Spec, KEY_80, 0);
    const rk192 = getRoundKey(serpent192Spec, KEY_80_192, 0);
    expect(rk192).not.toBe(rk128);
  });

  // Serpent-256: no padding — input fills the prekey buffer exactly.
  // Differs again from the 128/192 cases.
  it("Serpent-256 / key=80…0 / roundKey.0 differs from both shorter-key variants", () => {
    const rk128 = getRoundKey(serpent128Spec, KEY_80, 0);
    const rk192 = getRoundKey(serpent192Spec, KEY_80_192, 0);
    const rk256 = getRoundKey(serpent256Spec, KEY_80_256, 0);
    expect(rk256).not.toBe(rk128);
    expect(rk256).not.toBe(rk192);
  });

  // Zero key still produces non-trivial round keys (the `phi XOR i`
  // term in the prekey recurrence drives the bits even when the input
  // is all zeros). Catches a stuck-at-zero key schedule.
  it("Serpent-128 / key=0 / roundKey.0 is non-zero (phi+counter drive the schedule)", () => {
    const rk = getRoundKey(serpent128Spec, "00000000000000000000000000000000", 0);
    expect(rk).not.toBe("00000000000000000000000000000000");
  });
});
