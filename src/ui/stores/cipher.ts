/**
 * Cipher-choice store. Holds which AES variant (128 / 192 / 256) is active.
 * Persisted in localStorage so the user's pick survives a reload — mirrors
 * the byte-format and padding-scheme stores next door.
 *
 * Why a separate store rather than baking into `spec.ts`: the cipher choice
 * is a UI preference that re-applies to whichever (mode, padding) the user
 * has selected. Encrypt↔decrypt and padding↔padding flips should NOT reset
 * the cipher; keeping it isolated makes that contract obvious.
 */

import { createSignal } from "solid-js";

export type Cipher = "aes-128" | "aes-192" | "aes-256";

const STORAGE_KEY = "cryptographer.cipher";
const ALL_CIPHERS: readonly Cipher[] = ["aes-128", "aes-192", "aes-256"];

const loadInitial = (): Cipher => {
  // Defensive: localStorage may be absent (vitest node env) or denied
  // (private mode). Default to AES-128 so first-time / fresh-load users
  // hit the canonical FIPS-197 Appendix C.1 vector.
  try {
    if (typeof localStorage === "undefined") return "aes-128";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_CIPHERS as readonly string[]).includes(raw)) {
      return raw as Cipher;
    }
  } catch {
    // Storage denied. Fall through to default.
  }
  return "aes-128";
};

const [cipher, setCipherSignal] = createSignal<Cipher>(loadInitial());

export const useCipher = () => cipher;

export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, c);
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/** Display labels for the selector. Keep in sync with `ALL_CIPHERS`. */
export const CIPHER_LABELS: Record<Cipher, string> = {
  "aes-128": "AES-128",
  "aes-192": "AES-192",
  "aes-256": "AES-256",
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
};

/** Test-only reset; production code never calls this. */
export const __resetCipherForTests = (): void => {
  setCipherSignal("aes-128");
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
