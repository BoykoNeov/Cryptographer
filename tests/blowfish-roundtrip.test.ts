/**
 * Blowfish encrypt ↔ decrypt round-trip.
 *
 * Blowfish decryption is the SAME Feistel network with the P-array consumed in
 * reverse (rounds use P[17]..P[2]; whitening uses P[0], P[1]) — there are no
 * inverse S-boxes. These tests pin two properties:
 *   1. **Direct decrypt** — decrypting each published Eric-Young ciphertext
 *      recovers its plaintext (the reversed-P wiring is correct).
 *   2. **Round-trip** — encrypt then decrypt is the identity across several
 *      inputs (including edge blocks), the headline "it undoes itself" check.
 */

import { blowfishSpec } from "@/ciphers/blowfish";
import { blowfishDecryptSpec } from "@/ciphers/blowfish-decrypt";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

const run = (spec: CipherSpec, keyHex: string, inputHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

// key / plaintext / ciphertext (Eric Young / pycryptodome, 8-byte key).
const VECTORS: ReadonlyArray<readonly [string, string, string]> = [
  ["0000000000000000", "0000000000000000", "4ef997456198dd78"],
  ["ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"],
  ["0123456789abcdef", "1111111111111111", "61f9c3802281b096"],
  ["fedcba9876543210", "0123456789abcdef", "0aceab0fc6a0a28d"],
];

describe("Blowfish decrypt (reversed P-array)", () => {
  for (const [key, pt, ct] of VECTORS) {
    it(`decrypt(${ct}) with key ${key} → ${pt}`, () => {
      expect(run(blowfishDecryptSpec, key, ct)).toBe(pt);
    });
  }
});

describe("Blowfish encrypt ↔ decrypt round-trip", () => {
  const key = "0123456789abcdef";
  const inputs = [
    "0000000000000000",
    "ffffffffffffffff",
    "0123456789abcdef",
    "deadbeefcafef00d",
    "8000000000000000",
  ];
  for (const pt of inputs) {
    it(`round-trips ${pt} under key ${key}`, () => {
      const ct = run(blowfishSpec, key, pt);
      expect(run(blowfishDecryptSpec, key, ct)).toBe(pt);
    });
  }
});
