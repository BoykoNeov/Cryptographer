/**
 * Blowfish known-answer tests.
 *
 * The expected ciphertexts are the canonical Eric-Young Blowfish-ECB vectors
 * (the standard set shipped with the reference implementation), independently
 * regenerated with pycryptodome's `Crypto.Cipher.Blowfish` (ECB) during
 * implementation — see `docs/plans/blowfish.md`. All use an 8-byte key (v1
 * fixes the key length; variable-length keys are deferred).
 *
 * Two layers are checked so a failure localizes:
 *   1. **Helper layer** — `blowfishKeySchedule` + `blowfishEncryptWords` (the
 *      pure math oracle in `blowfish-constants.ts`, and the internals of the
 *      `blowfish.key-schedule@1` monolith) reproduce each vector. A failure
 *      here means the π tables / F function / key schedule math is wrong.
 *   2. **Spec layer** — the full `blowfishSpec` run through the runtime (visible
 *      key-mix → opaque 521-loop → 16 port-native Feistel rounds → whitening)
 *      reproduces each vector. A failure here (with the helper layer green)
 *      means the port-native round-body / aux-wiring diverges from the oracle.
 */

import { blowfishSpec } from "@/ciphers/blowfish";
import {
  blowfishEncryptWords,
  blowfishKeySchedule,
  bytesBEToU32,
  u32ToBytesBE,
} from "@/ciphers/blowfish-constants";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec } from "@/core/types";
import { describe, expect, it } from "vitest";

// key / plaintext / expected-ciphertext, all 8-byte hex (Eric Young / pycryptodome).
const VECTORS: ReadonlyArray<readonly [string, string, string]> = [
  ["0000000000000000", "0000000000000000", "4ef997456198dd78"],
  ["ffffffffffffffff", "ffffffffffffffff", "51866fd5b85ecb8a"],
  ["0123456789abcdef", "1111111111111111", "61f9c3802281b096"],
  ["0123456789abcdef", "0000000000000000", "245946885754369a"],
  ["fedcba9876543210", "0123456789abcdef", "0aceab0fc6a0a28d"],
];

/** Encrypt one block via the pure helper oracle (the monolith's internals). */
const encryptViaHelpers = (keyHex: string, ptHex: string): string => {
  const { P, S } = blowfishKeySchedule(bytesFromHex(keyHex));
  const pt = bytesFromHex(ptHex);
  const [xl, xr] = blowfishEncryptWords(bytesBEToU32(pt, 0), bytesBEToU32(pt, 4), P, S);
  const out = new Uint8Array(8);
  out.set(u32ToBytesBE(xl), 0);
  out.set(u32ToBytesBE(xr), 4);
  return hexFromBytes(out);
};

/** Encrypt one block via the full spec through the runtime. */
const runCipher = (spec: CipherSpec, keyHex: string, inputHex: string): string => {
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(inputHex)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(keyHex)]]),
  });
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes state");
  return hexFromBytes(trace.finalState.bytes);
};

describe("Blowfish known-answer tests (Eric Young / pycryptodome)", () => {
  describe("helper oracle (blowfishKeySchedule + blowfishEncryptWords)", () => {
    for (const [key, pt, ct] of VECTORS) {
      it(`key=${key} pt=${pt} → ${ct}`, () => {
        expect(encryptViaHelpers(key, pt)).toBe(ct);
      });
    }
  });

  describe("full spec through the runtime (port-native round body)", () => {
    for (const [key, pt, ct] of VECTORS) {
      it(`key=${key} pt=${pt} → ${ct}`, () => {
        expect(runCipher(blowfishSpec, key, pt)).toBe(ct);
      });
    }
  });
});
