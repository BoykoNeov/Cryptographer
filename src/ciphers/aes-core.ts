/**
 * AES as a `BlockCipherCore` — the adapter that lets the generic mode builders
 * (`modes/ecb.ts`, `modes/cbc.ts`) drive AES without knowing anything about it.
 *
 * This file is the *only* place the mode machine learns AES's specifics: that
 * its block is 16 bytes, that AES-128/192/256 run 10/12/14 rounds under
 * 16/24/32-byte keys, and which builders produce its round bodies. Everything
 * here is a thin re-expression of the existing byte-native builders — no AES
 * logic is reimplemented, and the specs the modes generate from this core are
 * byte-identical to what the old AES-specific mode builders produced.
 *
 * Adding another cipher to every mode means writing a sibling of this file —
 * that is the whole point of the `BlockCipherCore` seam.
 *
 * References: FIPS-197 (AES), §5.1 (Cipher), §5.2 (KeyExpansion), §5.3 (InvCipher).
 */

import type { PortBinding } from "../core/types";
import { buildAesKeyScheduleNative } from "./aes-key-schedule-builder-native";
import {
  aesNativeDecryptOutputFrom,
  aesNativeOutputFrom,
  buildAesDecryptBodyNative,
  buildAesEncryptBodyNative,
} from "./aes-round-builder-native";
import type { BlockCipherCore, CipherBody } from "./block-cipher-core";

/** The three AES key lengths. Each is its own `BlockCipherCore`. */
export type AesVariant = "aes-128" | "aes-192" | "aes-256";

/** FIPS-197 §5: rounds are a function of key length (Nr = Nk + 6). */
const ROUNDS_BY_VARIANT: Readonly<Record<AesVariant, number>> = {
  "aes-128": 10,
  "aes-192": 12,
  "aes-256": 14,
};

const KEY_BYTES_BY_VARIANT: Readonly<Record<AesVariant, number>> = {
  "aes-128": 16,
  "aes-192": 24,
  "aes-256": 32,
};

const VARIANT_DISPLAY: Readonly<Record<AesVariant, string>> = {
  "aes-128": "AES-128",
  "aes-192": "AES-192",
  "aes-256": "AES-256",
};

/** AES's block is 128 bits regardless of key length (FIPS-197 §5, Nb = 4). */
const AES_BLOCK_BYTES = 16;

/**
 * Build the `BlockCipherCore` for one AES variant.
 *
 * The bodies are seed-parameterized: the underlying `build*BodyNative`
 * builders already accept an input source (defaulting to `$input` for the
 * single-block specs), so a mode can hand them the iterate's injected block
 * port instead. AES was the only cipher already shaped this way — which is
 * why it is the first core.
 */
export function aesCore(variant: AesVariant): BlockCipherCore {
  const rounds = ROUNDS_BY_VARIANT[variant];
  const keyByteLength = KEY_BYTES_BY_VARIANT[variant];

  return {
    id: variant,
    displayName: VARIANT_DISPLAY[variant],
    // Narration prose says "AES", not "AES-128" — the variant is irrelevant to
    // how a mode chains blocks.
    familyName: "AES",
    blockByteLength: AES_BLOCK_BYTES,
    keyByteLength,
    // Nk (key length in 32-bit words) is what the schedule builder wants.
    buildKeySchedule: () => buildAesKeyScheduleNative(rounds, keyByteLength / 4),
    buildEncryptBody: (seed: PortBinding): CipherBody => ({
      nodes: buildAesEncryptBodyNative(rounds, seed),
      output: aesNativeOutputFrom(rounds),
    }),
    buildDecryptBody: (seed: PortBinding): CipherBody => ({
      nodes: buildAesDecryptBodyNative(rounds, seed),
      // The inverse body's exit is the GROUP's published "out" port — the
      // helper knows it; don't reach for the inner leaf's "output".
      output: aesNativeDecryptOutputFrom(),
    }),
  };
}
