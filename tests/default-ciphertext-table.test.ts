/**
 * Pins `DEFAULT_CT_BYTES_BY_CIPHER` (stores/cipher.ts) to the actual cipher
 * implementations. The table feeds the decrypt-mode input field so that
 * switching cipher in decrypt mode lands on a ciphertext that round-trips
 * straight back to the canonical plaintext (the fix for the "DES decrypt
 * default ciphertext is 16 bytes → must be exactly 8 bytes" banner).
 *
 * Two layers of protection:
 *
 *  1. **Round-trip-by-construction.** For every cipher, the declared default
 *     ciphertext MUST equal `encrypt(DEFAULT_PT, DEFAULT_KEY)` run through the
 *     real canonical encrypt spec. This guarantees the table can never drift
 *     from the engine and dodges the Speck BE/LE and Serpent byte-convention
 *     traps that hand-derived constants would risk.
 *
 *  2. **Published-vector anchors (non-circularity).** Layer 1 alone is
 *     circular — a buggy engine would define a wrong "canonical" CT and the
 *     table would happily match it. So the entries with published KAT vectors
 *     (AES-128 FIPS-197 §C.1, Speck32/64 Beaulieu et al. under both byte
 *     conventions, DES FIPS 46-3 Appendix B) are ALSO asserted against their
 *     literal published values. A regression in the shared byte-flat engine
 *     breaks these anchors rather than silently redefining canonical.
 *     AES-192/256 + Serpent use the FIPS sequential plaintext under sequential
 *     keys (not the NIST AES Core `6bc1…` vectors), so they have no headline
 *     KAT to anchor here — they ride on their own KAT test files transitively
 *     via layer 1.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes256Spec } from "@/ciphers/aes-256";
import { blowfishSpec } from "@/ciphers/blowfish";
import { chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { twofishSpec } from "@/ciphers/twofish";
import { runSpec } from "@/core/runtime";
import { hexFromBytes } from "@/core/state/bytes";
import type { AuxValue, BytesState, CipherSpec } from "@/core/types";
import {
  CIPHER_OPTIONS,
  type Cipher,
  DEFAULT_CT_BYTES_BY_CIPHER,
  DEFAULT_IV_BYTES_BY_CIPHER,
  DEFAULT_KEY_BYTES_BY_CIPHER,
  DEFAULT_PT_BYTES_BY_CIPHER,
} from "@/ui/stores/cipher";
import { describe, expect, it } from "vitest";

/** Canonical single-block encrypt spec for each cipher variant. */
const encryptSpecs: Record<Cipher, CipherSpec> = {
  "aes-128": aes128Spec,
  "aes-192": aes192Spec,
  "aes-256": aes256Spec,
  "speck-32-64-be": speck32_64BeSpec,
  "speck-32-64-le": speck32_64LeSpec,
  "serpent-128": serpent128Spec,
  "serpent-192": serpent192Spec,
  "serpent-256": serpent256Spec,
  des: desSpec,
  blowfish: blowfishSpec,
  twofish: twofishSpec,
  // ChaCha20 has no single-block spec — "stream" is its only mode, and that
  // one spec IS the cipher. It is also the only entry here that needs an IV.
  chacha20: chacha20EncryptSpec,
};

/** Run a cipher's encrypt spec on its canonical default PT + key. */
const encryptDefault = (cipher: Cipher): string => {
  const initialState: BytesState = {
    shape: "bytes",
    bytes: DEFAULT_PT_BYTES_BY_CIPHER[cipher],
  };
  const initialAux = new Map<string, AuxValue>([["key", DEFAULT_KEY_BYTES_BY_CIPHER[cipher]]]);
  // Ciphers with a structured IV register a canonical one; the block ciphers
  // above register none and run single-block, where no IV is read. Mirrors
  // what App.tsx seeds before a run.
  const iv = DEFAULT_IV_BYTES_BY_CIPHER[cipher];
  if (iv !== undefined) initialAux.set("iv", iv);
  const trace = runSpec(encryptSpecs[cipher], buildDefaultRegistry(), {
    initialState,
    initialAux,
  });
  const fs = trace.finalState;
  if (fs.shape !== "bytes") throw new Error(`${cipher} produced non-bytes final state`);
  return hexFromBytes(fs.bytes);
};

describe("DEFAULT_CT_BYTES_BY_CIPHER — round-trips by construction", () => {
  for (const cipher of CIPHER_OPTIONS) {
    it(`${cipher}: declared CT == encrypt(default PT, default key)`, () => {
      expect(hexFromBytes(DEFAULT_CT_BYTES_BY_CIPHER[cipher])).toBe(encryptDefault(cipher));
    });
  }

  it("covers every cipher in CIPHER_OPTIONS (no variant left without a default CT)", () => {
    for (const cipher of CIPHER_OPTIONS) {
      expect(DEFAULT_CT_BYTES_BY_CIPHER[cipher]).toBeInstanceOf(Uint8Array);
      expect(DEFAULT_CT_BYTES_BY_CIPHER[cipher].length).toBeGreaterThan(0);
    }
  });
});

describe("DEFAULT_CT_BYTES_BY_CIPHER — published-vector anchors (non-circularity)", () => {
  // Literal published KAT values, independent of the engine under test.
  const anchors: ReadonlyArray<readonly [Cipher, string]> = [
    ["aes-128", "69c4e0d86a7b0430d8cdb78070b4c55a"], // FIPS-197 §C.1
    ["speck-32-64-be", "a86842f2"], // Beaulieu et al. (paper byte order)
    ["speck-32-64-le", "f24268a8"], // Beaulieu et al. (NSA-reference byte order)
    ["des", "85e813540f0ab405"], // FIPS 46-3 Appendix B
    ["blowfish", "61f9c3802281b096"], // Eric-Young Blowfish-ECB vector
    ["twofish", "df8451d26e0504bc19b0a93b049e3203"], // Ferguson reference (seq key)
    // RFC 8439 §2.4.2 — the whole 114-byte ciphertext, under that section's
    // key, nonce and initial counter of 1. The app's ChaCha20 defaults ARE
    // that vector, so the first thing a user sees is a published result.
    [
      "chacha20",
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b" +
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736" +
        "5af90bbf74a35be6b40b8eedf2785e42874d",
    ],
  ];
  for (const [cipher, expected] of anchors) {
    it(`${cipher} default CT matches its published vector`, () => {
      expect(hexFromBytes(DEFAULT_CT_BYTES_BY_CIPHER[cipher])).toBe(expected);
    });
  }
});
