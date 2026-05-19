/**
 * Cipher-choice store. Holds which AES variant (128 / 192 / 256) is active.
 *
 * Session-only (2026-05-19): not persisted in localStorage. Refresh resets
 * to "aes-128" — the same posture the inputs (plaintext, key) already had,
 * and the same posture the Save dialog's `includeSession` checkbox defaults
 * to OFF. We deliberately do NOT persist the user's last selector picks so
 * that a tab refresh is equivalent to closing-and-reopening the app: a
 * clean slate. The earlier persistent design produced a confusing
 * asymmetry where the selector survived refresh but the input bytes (held
 * by App.tsx local signals) reset to defaults, leaving e.g. AES-128 + ECB
 * showing the 16-byte default plaintext instead of whatever the user had
 * typed pre-refresh.
 *
 * Why a separate store rather than baking into `spec.ts`: the cipher choice
 * is a UI preference that re-applies to whichever (mode, padding) the user
 * has selected. Encrypt↔decrypt and padding↔padding flips should NOT reset
 * the cipher; keeping it isolated makes that contract obvious.
 */

import { createSignal } from "solid-js";

export type AesCipher = "aes-128" | "aes-192" | "aes-256";
export type SpeckCipher = "speck-32-64-be" | "speck-32-64-le";
export type SerpentCipher = "serpent-128" | "serpent-192" | "serpent-256";
export type Cipher = AesCipher | SpeckCipher | SerpentCipher;

const ALL_CIPHERS: readonly Cipher[] = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "serpent-128",
  "serpent-192",
  "serpent-256",
];

/**
 * True for AES-family ciphers (the only ones that today support the
 * `load-block`/`store-block` overlay and PKCS#7/zero/ISO 7816-4 padding).
 * Type-predicate form so TS narrows `cipher` on each branch — important
 * for the exhaustiveness check in `paddingLimits`'s non-AES switch.
 */
export const isAesCipher = (c: Cipher): c is AesCipher => c.startsWith("aes-");

// Default to AES-128 so first-time / fresh-load users hit the canonical
// FIPS-197 Appendix C.1 vector. Session-only — see file header.
const [cipher, setCipherSignal] = createSignal<Cipher>("aes-128");

export const useCipher = () => cipher;

export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
};

/** Display labels for the selector. Keep in sync with `ALL_CIPHERS`. */
export const CIPHER_LABELS: Record<Cipher, string> = {
  "aes-128": "AES-128",
  "aes-192": "AES-192",
  "aes-256": "AES-256",
  "speck-32-64-be": "Speck 32/64 (BE, paper)",
  "speck-32-64-le": "Speck 32/64 (LE, NSA)",
  "serpent-128": "Serpent-128",
  "serpent-192": "Serpent-192",
  "serpent-256": "Serpent-256",
};

export const CIPHER_OPTIONS = ALL_CIPHERS;

/**
 * Canonical default key per cipher — FIPS-197 §A.1 / §A.2 / §A.3 expansion
 * examples. These match the keys used by the NIST AES Core PDFs that drive
 * our KAT tests, so the first Run on each cipher reproduces a textbook
 * ciphertext.
 *
 * The plaintext default does not vary by cipher: AES-128/192/256 all use a
 * 16-byte block, and the sequential FIPS-197 vector works as a plaintext
 * for any of them under `none` padding.
 *
 * App.tsx consults these to decide whether the user's current key field
 * holds a "known default" (in which case switching cipher auto-swaps to
 * the new cipher's default) or a user-typed value (in which case the field
 * is left alone, mirroring `changePadding`'s policy).
 */
export const DEFAULT_KEY_BYTES_BY_CIPHER: Record<Cipher, Uint8Array> = {
  "aes-128": new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]),
  "aes-192": new Uint8Array([
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
  ]),
  "aes-256": new Uint8Array([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
  ]),
  // Speck32/64 canonical key from Beaulieu et al. 2013 Table 4.1. Same
  // word-level key under both byte conventions; the bytes differ only in
  // serialisation. BE-paper: `1918 1110 0908 0100`; LE-NSA: bytes are
  // k_0-first low-byte-first.
  "speck-32-64-be": new Uint8Array([0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00]),
  "speck-32-64-le": new Uint8Array([0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19]),
  // Serpent default keys: the same sequential byte pattern as AES so the
  // first Run shows a non-trivial trace. Serpent doesn't have a single
  // canonical KAT key the way AES (FIPS-197 Appendix C) does — the NIST
  // submission's `ecb_vk.txt` walks variable-key positions instead — so
  // we reuse the AES key bytes for the 128 / 192 / 256 variants and let
  // the user replace with NESSIE test vectors if they want to verify.
  "serpent-128": new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  ]),
  "serpent-192": new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  ]),
  "serpent-256": new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ]),
};

/**
 * Canonical default plaintext per cipher.
 *
 * AES variants share the FIPS-197 sequential 16-byte vector. Speck32/64
 * uses the canonical Beaulieu et al. KAT plaintext under each byte
 * convention (paper-visual vs. NSA-reference byte order). The Speck
 * defaults are 4 bytes each — one block at the cipher's natural width —
 * so the first Run lands on the published ciphertext exactly.
 *
 * App.tsx consults this table when swapping ciphers: if the plaintext
 * field currently holds the previous cipher's known default, replace
 * with the new cipher's default. A user-typed value is left alone.
 */
export const DEFAULT_PT_BYTES_BY_CIPHER: Record<Cipher, Uint8Array> = {
  "aes-128": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
  "aes-192": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
  "aes-256": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
  "speck-32-64-be": new Uint8Array([0x65, 0x74, 0x69, 0x4c]), // "6574694c"
  "speck-32-64-le": new Uint8Array([0x4c, 0x69, 0x74, 0x65]), // "4c697465"
  // Serpent uses the same 16-byte plaintext as AES (also 128-bit block).
  "serpent-128": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
  "serpent-192": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
  "serpent-256": new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
};

/** Test-only reset; production code never calls this. */
export const __resetCipherForTests = (): void => {
  setCipherSignal("aes-128");
};
