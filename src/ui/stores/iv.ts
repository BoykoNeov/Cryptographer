/**
 * Initialization-vector (IV) store. One signal: the 16 bytes the App
 * seeds under `aux["iv"]` when CBC mode is active. Persists in
 * localStorage so the user's choice survives a reload (same pedagogy
 * as the byte-format store — resetting the IV on reload would be
 * surprising mid-experiment).
 *
 * Read from anywhere via `useIvBytes()`; write via `setIvBytes`. A
 * `randomizeIv()` helper fills from `crypto.getRandomValues` for the
 * "🎲 Randomize" button.
 *
 * The shape is always 16 bytes — the AES block size, which is the only
 * IV length CBC/CFB/OFB/CTR support. The store enforces the length on
 * write; callers don't need to defend against off-size inputs.
 *
 * Why this lives separately from the existing IV plumbing (`aux-load`
 * + `iv-load`): the IV is a *user input*, not a spec param. The same
 * spec runs against different IVs across runs; we don't want it baked
 * into the saved spec, and the user wants the same "type once, run
 * many times" experience as they have for plaintext + key.
 */

import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.iv";
const IV_LENGTH = 16;

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
    // Stored as a hex string for stability across format changes.
    // 32 hex chars = 16 bytes. Anything else is corrupt; fall back.
    if (raw.length !== 32 || !/^[0-9a-fA-F]+$/.test(raw)) {
      return new Uint8Array(DEFAULT_IV);
    }
    const bytes = new Uint8Array(IV_LENGTH);
    for (let i = 0; i < IV_LENGTH; i++) {
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
 * Replace the IV. Enforces a length of 16 bytes — anything else throws,
 * because the callers (IvInput, randomizeIv, applyDocument) all already
 * produce exactly 16 bytes. A wrong length is a programmer bug, not a
 * user input edge case.
 */
export const setIvBytes = (bytes: Uint8Array): void => {
  if (bytes.length !== IV_LENGTH) {
    throw new Error(`setIvBytes: must be ${IV_LENGTH} bytes, got ${bytes.length}`);
  }
  // Defensive copy — the caller may mutate the array after this call.
  // Aux entries that survive across many frames must own their storage.
  const copy = new Uint8Array(bytes);
  setIvBytesSignal(copy);
  persist(copy);
};

/**
 * Fill the IV with cryptographically-random bytes. Backed by
 * `crypto.getRandomValues`, present in every modern browser and
 * jsdom-with-the-Web-Crypto-shim. Tests that simulate environments
 * without it pass a polyfill into globalThis.crypto first.
 */
export const randomizeIv = (): void => {
  const fresh = new Uint8Array(IV_LENGTH);
  crypto.getRandomValues(fresh);
  setIvBytes(fresh);
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
