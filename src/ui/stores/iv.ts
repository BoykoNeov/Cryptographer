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
 * one. 16 because AES is the default cipher — not because the store is AES-only.
 */
export const DEFAULT_IV_LENGTH = 16;

/**
 * The canonical default IV at a given block width: the ascending byte run
 * `00 01 02 …`.
 *
 * At 16 bytes this IS NIST SP 800-38A §F's standard test vector
 * `000102030405060708090a0b0c0d0e0f` — chosen so the first-impression AES run
 * against the §F sample plaintext reproduces the published §F.2.1 ciphertext
 * byte-for-byte (the same first-impression discipline as the FIPS-197 default
 * key). Generating it rather than spelling it out extends that default to any
 * block width for free: Blowfish/DES get `0001020304050607`, Speck `00010203`.
 */
export const defaultIvOfWidth = (blockByteLength: number): Uint8Array =>
  Uint8Array.from({ length: blockByteLength }, (_, i) => i & 0xff);

const DEFAULT_IV = defaultIvOfWidth(DEFAULT_IV_LENGTH);

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
 * Reset the IV to the canonical default for `blockByteLength` when the stored
 * one is the wrong width. No-op when the width already agrees, so a user's
 * hand-typed IV survives everything except an actual change of block size.
 *
 * ## Why this has to exist
 *
 * The stored IV is persisted and module-scope; the active cipher is neither. So
 * the two drift the moment the cipher's block width changes, and the store has
 * no way to notice on its own. Before this, landing on Blowfish CBC showed the
 * 16-byte AES default in the IV field — a value `setIvBytes` itself would
 * REJECT if the user typed it back, since `IvInput` passes Blowfish's 8. The
 * field displayed something it would not accept. (The run still "worked": the
 * runtime's port-length coercion truncated 16→8 and emitted a coercion frame.
 * That is warn-and-run doing its job on a genuinely wrong input, not a reason to
 * hand it one.)
 *
 * It drifts BOTH ways — the IV persists across reloads while `cipher` and
 * `cipherMode` are session-only, so finishing a Blowfish session and reloading
 * onto AES + CBC would otherwise feed AES-128 an 8-byte IV.
 *
 * **Why reset rather than preserve, unlike the plaintext smart-swap in
 * `changeCipher`** (which keeps a custom value and swaps only a recognized
 * default): a plaintext of the "wrong" length is a legal thing to experiment
 * with, but an IV must be exactly one block wide — CBC XORs it with a block.
 * There is no correct way to carry a custom 16-byte IV over to an 8-byte
 * cipher, so the canonical default is the honest landing place.
 *
 * @param blockByteLength the active cipher's block width, or `undefined` when
 *   there is no block cipher (a hash, RSA, a coreless cipher) — then the IV is
 *   inert and left alone.
 */
/**
 * The IV a cipher should start life with: its registered canonical default if
 * it has one, else the generic ascending pattern at the given width.
 *
 * Exists so the App can compare "is the field still holding the PREVIOUS
 * cipher's default?" using the same rule that produced it — the sacred-input
 * policy the key and plaintext fields already follow. `reconcileIvWidth` alone
 * is not enough for that job: it short-circuits when the width is unchanged,
 * so switching between two 16-byte-IV ciphers would silently keep the old
 * bytes. Harmless when the IV is an opaque block; wrong for a stream cipher,
 * whose leading bytes are a block counter. Inheriting AES's `00 01 02 03`
 * starts ChaCha20 at 0x03020100 and quietly reproduces no published vector —
 * and since Salsa20 there is a second 16-byte-IV stream cipher with a
 * DIFFERENT split (8 counter bytes, not 4), so the two of them inherit each
 * other's counters as readily as they inherit AES's.
 */
export const canonicalIvFor = (byteLength: number, registeredDefault?: Uint8Array): Uint8Array =>
  registeredDefault ?? defaultIvOfWidth(byteLength);

export const reconcileIvWidth = (
  blockByteLength: number | undefined,
  canonicalDefault?: Uint8Array,
): void => {
  if (blockByteLength === undefined) return;
  if (ivBytes().length === blockByteLength) return;
  // `canonicalDefault` lets a caller override the generic ascending pattern for
  // a cipher whose IV has internal structure — the stream ciphers, whose
  // leading bytes are a block counter (ChaCha20's four, little-endian;
  // Salsa20's eight). The generic `00 01 02 03 …` would silently start
  // ChaCha20 at 0x03020100 — legal, consistent, and matching no published test
  // vector. The store still knows nothing about which cipher is active; the
  // caller supplies the bytes.
  //
  // Note what this does NOT cover, and why `canonicalIvFor` exists above: the
  // equal-width short-circuit two lines up. Both stream ciphers want a 16-byte
  // IV under different layouts, so switching between them never reaches this
  // line at all.
  setIvBytes(canonicalDefault ?? defaultIvOfWidth(blockByteLength), blockByteLength);
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
