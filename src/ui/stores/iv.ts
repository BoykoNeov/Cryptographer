/**
 * Initialization-vector (IV) store. One signal: the bytes the App seeds under
 * `aux["iv"]` when CBC mode is active. Persists in localStorage so the user's
 * choice survives a reload (same pedagogy as the byte-format store — resetting
 * the IV on reload would be surprising mid-experiment).
 *
 * Read from anywhere via `useIvBytes()`; write via `setIvBytes`. A
 * `randomizeIv()` helper fills from `crypto.getRandomValues` for the
 * "🎲 Randomize" button.
 *
 * ## The IV is exactly one cipher block wide
 *
 * That's a property of CBC/CFB/OFB/CTR, not of AES: the IV has to XOR with a
 * block, so it is as wide as the block. This store used to hardcode 16 and
 * *throw* on anything else, which silently meant "AES only" — an 8-byte-block
 * cipher in CBC could not have been fed a legal IV.
 *
 * The size is passed IN (`setIvBytes(bytes, blockByteLength)`) rather than read
 * from a store: this is a module-scope signal with no notion of which cipher is
 * active, and reaching for the cipher store from here would invert the
 * dependency (`spec.ts` already imports this module). The App knows both the
 * active cipher and its core, so it is the honest place to resolve the width.
 *
 * Callers that hold a size pass it; callers that legitimately don't (a
 * document restore, whose IV length was already schema-validated) pass
 * `undefined` to accept the bytes as-is.
 *
 * Why this lives separately from the existing IV plumbing (`aux-load`
 * + `iv-load`): the IV is a *user input*, not a spec param. The same
 * spec runs against different IVs across runs; we don't want it baked
 * into the saved spec, and the user wants the same "type once, run
 * many times" experience as they have for plaintext + key.
 */

import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.iv";

/**
 * The IV width the store boots at, and the fallback when a caller doesn't name
 * one. 16 because AES is the default cipher and the only family with a core
 * today — not because the store is AES-only.
 */
export const DEFAULT_IV_LENGTH = 16;

// Default IV: NIST SP 800-38A §F's standard test vector
// `000102030405060708090a0b0c0d0e0f`. Chosen so the first-impression
// run against the §F sample plaintext matches the published §F.2.1
// ciphertext byte-for-byte — same first-impression discipline as the
// FIPS-197 default key for AES-128.
const DEFAULT_IV = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

const loadInitial = (): Uint8Array => {
  try {
    if (typeof localStorage === "undefined") return new Uint8Array(DEFAULT_IV);
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === null) return new Uint8Array(DEFAULT_IV);
    // Stored as a hex string for stability across format changes. Any even
    // number of hex digits is a legal IV now (the width follows the active
    // cipher's block); odd length or a non-hex character means corrupt.
    if (raw.length === 0 || raw.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(raw)) {
      return new Uint8Array(DEFAULT_IV);
    }
    const bytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = Number.parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  } catch {
    return new Uint8Array(DEFAULT_IV);
  }
};

const [ivBytes, setIvBytesSignal] = createSignal<Uint8Array>(loadInitial());

export const useIvBytes = () => ivBytes;

const persist = (bytes: Uint8Array): void => {
  try {
    if (typeof localStorage === "undefined") return;
    // Hex serialization — stable regardless of the byte-format toggle's
    // current setting. The IV is a value, not a presentation; we want
    // it to round-trip identically across reloads.
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += (bytes[i] ?? 0).toString(16).padStart(2, "0");
    }
    localStorage.setItem(STORAGE_KEY, hex);
  } catch {
    // Storage denied; signal still updated.
  }
};

/**
 * Replace the IV.
 *
 * @param blockByteLength the active cipher's block width, which the IV must
 *   match exactly. Pass `undefined` only when the caller genuinely has no
 *   cipher context and the length is already trusted (a document restore, whose
 *   schema validated it) — the bytes are then accepted as-is.
 *
 * A mismatch throws rather than coercing: every caller (IvInput, randomizeIv,
 * applyDocument) produces a deliberate length, so a wrong one is a programmer
 * bug. Silently truncating or zero-extending would hand CBC a *different IV
 * than the user typed* and quietly produce the wrong ciphertext.
 */
export const setIvBytes = (bytes: Uint8Array, blockByteLength?: number): void => {
  if (blockByteLength !== undefined && bytes.length !== blockByteLength) {
    throw new Error(`setIvBytes: must be ${blockByteLength} bytes, got ${bytes.length}`);
  }
  // Defensive copy — the caller may mutate the array after this call.
  // Aux entries that survive across many frames must own their storage.
  const copy = new Uint8Array(bytes);
  setIvBytesSignal(copy);
  persist(copy);
};

/**
 * Fill the IV with cryptographically-random bytes, one block wide. Backed by
 * `crypto.getRandomValues`, present in every modern browser and
 * jsdom-with-the-Web-Crypto-shim. Tests that simulate environments
 * without it pass a polyfill into globalThis.crypto first.
 */
export const randomizeIv = (blockByteLength: number = DEFAULT_IV_LENGTH): void => {
  const fresh = new Uint8Array(blockByteLength);
  crypto.getRandomValues(fresh);
  setIvBytes(fresh, blockByteLength);
};

/** Test-only reset to the default IV; production code never calls it. */
export const __resetIvForTests = (): void => {
  setIvBytesSignal(new Uint8Array(DEFAULT_IV));
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
