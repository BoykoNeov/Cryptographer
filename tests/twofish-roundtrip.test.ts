/**
 * Twofish decrypt + round-trip tests.
 *
 * Correctness of decrypt is pinned two ways (plan Phase 2): the encrypt KAT
 * (`tests/twofish-vectors.test.ts`) fixes encrypt against Ferguson's reference,
 * and here `decrypt(encrypt(x)) === x` proves decrypt is its exact inverse — a
 * symmetric enc/dec bug would break the encrypt KAT, and a decrypt-only bug
 * breaks the round-trip. The decrypt-KAT block additionally pins
 * `decrypt(publishedCT) === publishedPT` directly.
 *
 * Decrypt runs the same network with the 1-bit rotations inverted, the round
 * order + subkey consumption reversed, and the whitening subkeys swapped
 * (K0..3 ↔ K4..7) — one `buildTwofishSpec(direction)` parameterizes both.
 */

import { describe, expect, it } from "vitest";
import { buildDefaultRegistry } from "../src/ciphers/default-registry";
import { twofishSpec } from "../src/ciphers/twofish";
import { twofishDecryptSpec } from "../src/ciphers/twofish-decrypt";
import { runSpec } from "../src/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "../src/core/state/bytes";
import type { AuxValue, CipherSpec } from "../src/core/types";

const run = (spec: CipherSpec, keyHex: string, inHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("Twofish decrypt — known-answer (published CT → PT)", () => {
  // The exact vectors the encrypt KAT pins, run backwards.
  const cases: [string, string, string][] = [
    [
      "000102030405060708090a0b0c0d0e0f",
      "00112233445566778899aabbccddeeff",
      "df8451d26e0504bc19b0a93b049e3203",
    ],
    [
      "00000000000000000000000000000000",
      "00000000000000000000000000000000",
      "9f589f5cf6122c32b6bfec2f2ae8c35a",
    ],
    [
      "0123456789abcdeffedcba9876543210",
      "00112233445566778899aabbccddeeff",
      "568124261c4164dcb4dcbeeb440cf19b",
    ],
  ];
  for (const [key, pt, ct] of cases) {
    it(`key=${key} ct=${ct} → ${pt}`, () => {
      expect(run(twofishDecryptSpec, key, ct)).toBe(pt);
    });
  }
});

describe("Twofish round-trip — decrypt(encrypt(x)) === x", () => {
  const cases: [string, string][] = [
    ["000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff"],
    ["ffffffffffffffffffffffffffffffff", "0f0e0d0c0b0a09080706050403020100"],
    ["0123456789abcdeffedcba9876543210", "cafebabedeadbeef0123456789abcdef"],
    ["00112233445566778899aabbccddeeff", "00000000000000000000000000000000"],
  ];
  for (const [key, pt] of cases) {
    it(`key=${key} pt=${pt}`, () => {
      const ct = run(twofishSpec, key, pt);
      expect(run(twofishDecryptSpec, key, ct)).toBe(pt);
    });
  }
});
