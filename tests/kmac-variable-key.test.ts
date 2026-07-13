/**
 * KMAC variable-key-length known-answer-test gate (NIST SP 800-185 §4),
 * 2026-07-13.
 *
 * KMAC's key length is **variable** — SP 800-185 places no upper bound, and the
 * app models it "Option A": the key field is the source of truth, and the number
 * of bytes the user types drives `buildKmacSpec`'s `keyByteLength` (which the
 * builder threads into `inputs.key.byteLength`, the `key.load` aux-read width,
 * and, via `encode_string`, the key's `left_encode(8·len)` bit-length prefix).
 * The base `kmac-kat.test.ts` only proves the 32-byte NIST sample key; this gate
 * proves the builder is byte-correct at OTHER lengths.
 *
 * **Oracle.** `node:crypto` has no KMAC. Vectors were emitted from the
 * independent reference in `M:\claud_projects\temp\cshake-kmac-ref\ref.py`:
 *   - lengths ≥ strength/8 (kmac128 ≥ 16, kmac256 ≥ 32) are cross-checked against
 *     **pycryptodome** (which enforces those minimums) AND the from-scratch
 *     Keccak sponge;
 *   - shorter lengths are pinned by the from-scratch sponge alone (the same
 *     sponge that agrees with pycryptodome + the NIST published samples at the
 *     lengths where all three are defined — so its machinery is independently
 *     trusted).
 *
 * **Coverage of the `encode_string` width regimes.** `encode_string(K)` prefixes
 * the key with `left_encode(8·len(K))`, whose value width is where an
 * encoding bug hides (the classic "used byte length not bit length" footgun).
 * The lengths span both regimes: 1/8/16/31 give `8·len ≤ 248` (1-byte value)
 * and 40 gives `8·len = 320` (2-byte value); the base test's 32 (`8·32 = 256`,
 * the 2-byte boundary) complements them.
 *
 * The spec is driven through the runtime with the key seeded into `initialAux`
 * exactly as the app's run handler does (`new Map([["key", keyBytes]])`).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type KmacVariant, buildKmacSpec, readKmacKeyLength } from "@/ciphers/kmac";
import { runSpec } from "@/core/runtime";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/** The app's default KMAC key extends the NIST pattern 0x40+i (wrapping mod
 *  256). The variable-key control regenerates this pattern at whatever length. */
const appKey = (len: number): Uint8Array =>
  new Uint8Array(Array.from({ length: len }, (_, i) => (0x40 + i) & 0xff));

/** The app's default KMAC message: [0,1,2,3]. */
const MESSAGE = new Uint8Array([0, 1, 2, 3]);
const OUT_LEN = 32;

/** Drive a KMAC spec built AT THE KEY'S LENGTH through the runtime, with the key
 *  seeded into aux exactly as the app's run handler does. */
const kmacHexAtKeyLen = (variant: KmacVariant, key: Uint8Array): string => {
  const spec = buildKmacSpec(variant, new Uint8Array(0), OUT_LEN, key.length);
  const initialAux = new Map<string, AuxValue>([["key", key]]); // the app path
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: MESSAGE },
    initialAux,
  });
  if (trace.finalState.shape !== "bytes") {
    throw new Error(`expected bytes finalState, got ${trace.finalState.shape}`);
  }
  return bytesToHex(trace.finalState.bytes);
};

// ─── Reference vectors (emitted from the validated python reference) ────────
// message = [0,1,2,3], S = "", output = 32 bytes, key = (0x40+i) & 0xff.
const VAR_KEY_VECTORS: Record<KmacVariant, Record<number, string>> = {
  kmac128: {
    1: "80164d960f5b13895c0eddca612eaf8fe092abed0a8e02e827b7aaa11e34069d",
    8: "7a76682eac89971031af6db3b4a12e7441b26d32be7344103ab5102177157a6d",
    16: "f9d2e95f6bd65c2510b1c6613cb6bd3e9a9038b4b02b3ebf45cce82f137234ee",
    31: "78673e8340c6d559eb8e33b72ce5c1b03649f21aba8408c92fc5b3b4849c6a3f",
    40: "22903c58562dccac6712fbf8e33523f30e4fefe9d789a0552071b2cda83e97b8",
  },
  kmac256: {
    1: "770d686988d4e0d6b6bfb882a29cb107a6536705b25399839a0e2f887e99b5b6",
    8: "8de0bec49d070d148fb8e0efde01cce5ae9c7fba12262ac0c7e13ccf4e0ec591",
    16: "00db6337dc10d426134aa815f7d6c02cb10aea8a554b62393fee2a44a548bd6d",
    31: "30439d32e03d9e4969518af7c04798fe60807e5b029d403cf38f57829b37bb54",
    40: "e52df45fb22e73000621534e9372d8b58180956552270acc27f95ce71d71214a",
  },
  kmacxof128: {
    1: "38c9497ecd5cae70b3bab0051c9d4d0a5344bdc8ed6509ea809ffedb1eb89921",
    8: "7d819c8ef45deb33f786580d1b52e1f7eb484b2d4bfbfbb14c7655c29f59e3a5",
    16: "3e932555197bee65030e420f94a78cdfc295bc9bec1ea6803ed1414fca7b501e",
    31: "e0c0369dd963bddb451fa10983dfffdb34ee8a15bb3ab3dd3cba8daabfb275b6",
    40: "ce3c86de96c54fbc3ba534f41e0ae05abfb6e34ae95ea6d11a240ef825be7b46",
  },
  kmacxof256: {
    1: "fc5d0774138ac7927f7d1301400ca70cdae976508c4f42339f9e565ac422f346",
    8: "1200381c428986c9e9229cefb41d4c94ebb1bdd79ca7d570aeeb317240d096dc",
    16: "9efd06c036331eead49a7adbc54a722b7a1d978e22a295ad9c0ef011288e4bdf",
    31: "8eadcfe91ec2e739ee15a8a415d20f2cb01f1513604c4572d72602ecabdf1a80",
    40: "c4eadbedfa7803cc36ac42f1d4be08b3adc678164851ba7ec8d2f80d40d3a50a",
  },
};

describe("KMAC — variable key length is byte-correct vs the SP 800-185 reference", () => {
  for (const variant of Object.keys(VAR_KEY_VECTORS) as KmacVariant[]) {
    for (const [lenStr, want] of Object.entries(VAR_KEY_VECTORS[variant])) {
      const len = Number(lenStr);
      it(`${variant} keyLen=${len} (8·len=${8 * len}, ${8 * len < 256 ? "1-byte" : "2-byte"} left_encode)`, () => {
        expect(kmacHexAtKeyLen(variant, appKey(len))).toBe(want);
      });
    }
  }
});

// ─── The declared key length propagates through the whole key block ──────────

describe("KMAC — keyByteLength threads consistently through the built spec", () => {
  for (const len of [1, 16, 31, 40, 100]) {
    it(`buildKmacSpec(..., keyByteLength=${len}) declares length ${len} everywhere`, () => {
      const spec = buildKmacSpec("kmac128", new Uint8Array(0), OUT_LEN, len);
      // inputs.key is what the App's key-field length check reads.
      expect(spec.inputs.key.byteLength).toBe(len);
      // readKmacKeyLength (used by document-load sync-back) recovers the same.
      expect(readKmacKeyLength(spec)).toBe(len);
      // The aux-load-bytes read width must match, or the runtime would coerce
      // the key to the wrong length (silently producing a wrong MAC).
      const keyLoad = spec.steps.find((n) => n.kind === "step" && n.id === "key.load");
      if (keyLoad?.kind !== "step") throw new Error("key.load step missing");
      expect((keyLoad.params as { byteLength: number }).byteLength).toBe(len);
    });
  }
});

// ─── A key-length change actually changes the tag ────────────────────────────

describe("KMAC — key length is bound into the tag", () => {
  it("the same key-byte prefix at different declared lengths gives different tags", () => {
    // 16 bytes of 0x40.. vs 31 bytes of 0x40.. — the 16-byte prefix is shared,
    // but the length is encode_string'd, so the tags must differ.
    expect(kmacHexAtKeyLen("kmac128", appKey(16))).not.toBe(kmacHexAtKeyLen("kmac128", appKey(31)));
  });
});
