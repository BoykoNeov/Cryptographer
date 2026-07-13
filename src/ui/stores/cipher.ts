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
/**
 * DES is its own family — single fixed key size (64 bits including 8 parity
 * bits) so no `-128` / `-192` / `-256` variants like AES/Serpent. Phase 4 of
 * `docs/plans/des-feistel.md` adds it to the selector; the cipher is the
 * first to use the `feistel-round` branching primitive.
 */
export type DesCipher = "des";
/**
 * Blowfish is its own family — Schneier's 1993 64-bit-block Feistel cipher, the
 * second Feistel after DES. Variable key length (4–56 bytes) in the standard,
 * but v1 here fixes it at 8 bytes (`inputs.key.byteLength` can't express a
 * range yet). Single fixed variant, so no `-128`/`-192`/`-256` suffixes.
 * `docs/plans/blowfish.md`.
 */
export type BlowfishCipher = "blowfish";
/**
 * Twofish is its own family — Schneier et al.'s 1998 AES finalist, the third
 * Feistel after DES and Blowfish. v1 fixes the key at 128 bits (the h-function
 * q-permutation stage count is key-size-dependent, so 192/256 are real added
 * work deferred to follow-ups). Single fixed variant, so no `-128`/`-192`/`-256`
 * suffixes. `docs/plans/twofish.md`.
 */
export type TwofishCipher = "twofish";
export type Cipher =
  | AesCipher
  | SpeckCipher
  | SerpentCipher
  | DesCipher
  | BlowfishCipher
  | TwofishCipher;

/**
 * Hash family — non-cipher cryptographic primitives that consume a message
 * and emit a fixed-length digest. SHA-256 is the first variant (Slice 2.6 of
 * the universal-port dataflow plan); SHA-3 / SHA-512 / MAC / KDF growth
 * extends this union when those variants land.
 *
 * Slice 2.10a (2026-05-25) introduced this type alongside `Algorithm` so the
 * cipher-selector UI can carry a top-level Cipher | Hash category split per
 * Open #N7 user pick. Slice 2.10c (2026-05-25) reaches it through the live
 * UI via the `hash` + `category` signals below.
 */
export type Hash = "sha-256" | "sha3-256" | "shake128" | "shake256";

/**
 * Asymmetric (public-key) family — algorithms with a public/private key pair
 * rather than a single symmetric key. RSA is the first (and only) member
 * (`docs/plans/shimmying-booping-moth.md`). Like a cipher it has encrypt /
 * decrypt directions, but UNLIKE a cipher it has no symmetric key field, no
 * block-cipher mode of operation, and no padding overlay — the public/private
 * key material is the editable `p, q, e` constants on the spec. The separate
 * family + category is what lets the UI hide those three symmetric-only
 * surfaces (presenting a "key" field for RSA would miseducate).
 */
export type Asymmetric = "rsa";

/**
 * Category discriminant for the algorithm selector (Slice 2.10c, 2026-05-25).
 * The UI surfaces a top-level toggle between "cipher" and "hash"; the
 * specific dropdown alongside renders cipher or hash options depending on
 * which is active. The active algorithm is then
 *   `category === "cipher" ? cipher() : hash()`
 * (the `useAlgorithm()` accessor below).
 *
 * Two independent signals (cipher + hash) rather than a single algorithm
 * signal: user picked "Remember last cipher" semantics so the cipher
 * dropdown's selection survives a cipher → hash → cipher detour. Same
 * shape extends cleanly when SHA-3 / SHA-512 land — each family's dropdown
 * remembers independently.
 */
export type Category = "cipher" | "hash" | "asymmetric";

/**
 * Public umbrella type — every cryptographic primitive the app supports.
 * Use this when the surface needs to accept any algorithm; use `Cipher` or
 * `Hash` directly when the caller's logic is specific to one family.
 *
 * Predicates `isCipher` / `isHash` below narrow `Algorithm` to either branch.
 * Implementing functions in terms of `Algorithm` and branching on category
 * is cheaper than maintaining parallel cipher-only and hash-only overloads.
 */
export type Algorithm = Cipher | Hash | Asymmetric;

const ALL_CIPHERS: readonly Cipher[] = [
  "aes-128",
  "aes-192",
  "aes-256",
  "speck-32-64-be",
  "speck-32-64-le",
  "serpent-128",
  "serpent-192",
  "serpent-256",
  "des",
  "blowfish",
  "twofish",
];

/**
 * True for AES-family ciphers (the only ones that today support the
 * `load-block`/`store-block` overlay and PKCS#7/zero/ISO 7816-4 padding).
 * Type-predicate form so TS narrows `cipher` on each branch — important
 * for the exhaustiveness check in `paddingLimits`'s non-AES switch.
 */
export const isAesCipher = (c: Cipher): c is AesCipher => c.startsWith("aes-");

/**
 * True when an algorithm is a hash (non-cipher cryptographic primitive).
 * Defined first so `isCipher` below can express itself as the negation —
 * the union shape guarantees `!isHash(a) ⟹ isCipher(a)`. When SHA-3 or
 * other hash variants land, only this predicate widens; `isCipher` stays
 * untouched by virtue of the structural definition.
 */
export const isHash = (a: Algorithm): a is Hash =>
  a === "sha-256" || a === "sha3-256" || a === "shake128" || a === "shake256";

/**
 * True when an algorithm is in the asymmetric (public-key) family. RSA today.
 * Defined alongside `isHash` so `isCipher` can exclude BOTH non-cipher
 * families explicitly.
 */
export const isAsymmetric = (a: Algorithm): a is Asymmetric => a === "rsa";

/**
 * True when an algorithm is a symmetric cipher (the keyed encrypt/decrypt
 * block primitives with cipher-mode + padding surfaces).
 *
 * **MUST be an explicit exclusion of every non-cipher family, NOT
 * `!isHash(a)`.** The naive negation worked while `Algorithm = Cipher | Hash`,
 * but once the asymmetric family widened the union, `!isHash("rsa")` is `true`,
 * and because this is a hand-written type predicate (`a is Cipher`) the
 * compiler would BELIEVE the lie and silently route RSA down the cipher path
 * (`setAlgorithm`, `setSpecFromDocument`, the `DEFAULT_*_BY_CIPHER` lookups).
 * The exhaustive-switch safety net does not catch a manual predicate. Every
 * new non-cipher family MUST be subtracted here.
 */
export const isCipher = (a: Algorithm): a is Cipher => !isHash(a) && !isAsymmetric(a);

// Default to AES-128 so first-time / fresh-load users hit the canonical
// FIPS-197 Appendix C.1 vector. Session-only — see file header.
const [cipher, setCipherSignal] = createSignal<Cipher>("aes-128");

export const useCipher = () => cipher;

export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
};

// ─── Hash + category signals (Slice 2.10c, 2026-05-25) ───────────────────
//
// Two-signal-plus-flag model: cipher (always holds a Cipher) and hash
// (always holds a Hash) each preserve their last value across category
// flips, so cipher → hash → cipher returns the user to the same cipher
// they were on. `category` is the discriminant for which of the two is
// live. `useAlgorithm()` derives the active Algorithm by reading both
// signals and the flag — Solid tracks each access, so consumers re-render
// when ANY of the three changes.
//
// Session-only, like `cipher` above. Fresh load defaults to category
// "cipher" + cipher "aes-128" so the first-impression FIPS-197 trace
// stays unchanged; users opting into a hash do so deliberately via the
// selector.

const [hash, setHashSignal] = createSignal<Hash>("sha-256");
const [asymmetric, setAsymmetricSignal] = createSignal<Asymmetric>("rsa");
const [category, setCategorySignal] = createSignal<Category>("cipher");

export const useHash = () => hash;
export const useAsymmetric = () => asymmetric;
export const useCategory = () => category;

/**
 * Set the active hash variant. Does NOT flip category — flipping into the
 * hash branch is a separate intent (`setCategory("hash")` or the
 * higher-level `setAlgorithm` in `stores/spec.ts` which composes both).
 * Today's hash union is a single member, so this setter is mostly
 * forward-compat for SHA-3 / SHA-512 landings.
 */
export const setHash = (h: Hash): void => {
  setHashSignal(h);
};

/** Set the active asymmetric variant. Does NOT flip category — mirrors
 *  `setHash`. Single-member union today; forward-compat for future
 *  public-key algorithms. */
export const setAsymmetric = (a: Asymmetric): void => {
  setAsymmetricSignal(a);
};

/** Flip the active category without changing the cipher / hash / asymmetric
 *  signals. */
export const setCategory = (c: Category): void => {
  setCategorySignal(c);
};

/**
 * Active algorithm — the source of truth for runtime dispatch and the
 * save-side `algorithm` field. Tracks the cipher OR hash signal depending
 * on category; the other signal stays inert but ready for the next flip.
 *
 * Returned as a plain accessor (call it to read) so consumers fit the
 * `useX()` / `useX()()` shape used everywhere else in this store. The
 * accessor closure reads both signals + the category flag so Solid sees
 * all three as dependencies.
 */
export const useAlgorithm = (): (() => Algorithm) => {
  return () => {
    const c = category();
    if (c === "cipher") return cipher();
    if (c === "hash") return hash();
    return asymmetric();
  };
};

/** Hash dropdown options + labels. Sized to one entry today; mirrors
 *  CIPHER_OPTIONS / CIPHER_LABELS so the UI can render either family with
 *  the same `<For each={options}>` shape. */
const ALL_HASHES: readonly Hash[] = ["sha-256", "sha3-256", "shake128", "shake256"];
export const HASH_OPTIONS = ALL_HASHES;
export const HASH_LABELS: Record<Hash, string> = {
  "sha-256": "SHA-256",
  "sha3-256": "SHA3-256",
  shake128: "SHAKE128",
  shake256: "SHAKE256",
};

/** Asymmetric dropdown options + labels. One entry today (RSA); mirrors the
 *  cipher / hash option shapes so the selector renders any family uniformly. */
const ALL_ASYMMETRICS: readonly Asymmetric[] = ["rsa"];
export const ASYMMETRIC_OPTIONS = ALL_ASYMMETRICS;
export const ASYMMETRIC_LABELS: Record<Asymmetric, string> = {
  rsa: "RSA (textbook)",
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
  des: "DES",
  blowfish: "Blowfish",
  twofish: "Twofish",
};

export const CIPHER_OPTIONS = ALL_CIPHERS;

// ─── One-liner descriptions (2026-07-11) ─────────────────────────────────────
//
// A short, plain-language "what is this primitive" line per algorithm, surfaced
// in TWO places by the UI: the selector caption (below the dropdown + as each
// `<option>`'s `title` tooltip) and the header, right after the cipher name
// next to "Cryptographer". Family variants (AES-128/192/256, the two Speck byte
// orders, Serpent-128/192/256) get their own line so the key-length / byte-order
// distinction is visible at a glance. Kept terse (~one clause of history + one
// of structure) so they fit on a single line without wrapping the header.

/** Per-cipher one-liner. Keep in sync with `ALL_CIPHERS` / `CIPHER_LABELS`. */
export const CIPHER_DESCRIPTIONS: Record<Cipher, string> = {
  "aes-128": "AES (Rijndael, FIPS-197) — 128-bit key, 10 rounds; SPN over a 16-byte block.",
  "aes-192": "AES (Rijndael, FIPS-197) — 192-bit key, 12 rounds; SPN over a 16-byte block.",
  "aes-256": "AES (Rijndael, FIPS-197) — 256-bit key, 14 rounds; SPN over a 16-byte block.",
  "speck-32-64-be":
    "Speck 32/64 (NSA, 2013) — lightweight ARX cipher, 22 rounds; big-endian (paper) byte order.",
  "speck-32-64-le":
    "Speck 32/64 (NSA, 2013) — lightweight ARX cipher, 22 rounds; little-endian (NSA ref) byte order.",
  "serpent-128":
    "Serpent (Anderson–Biham–Knudsen) — AES finalist; 32-round bitsliced SPN, 128-bit key.",
  "serpent-192":
    "Serpent (Anderson–Biham–Knudsen) — AES finalist; 32-round bitsliced SPN, 192-bit key.",
  "serpent-256":
    "Serpent (Anderson–Biham–Knudsen) — AES finalist; 32-round bitsliced SPN, 256-bit key.",
  des: "DES (FIPS 46-3, 1977) — 16-round Feistel; 64-bit block, 56-bit key. Foundational, now insecure.",
  blowfish:
    "Blowfish (Schneier, 1993) — 16-round Feistel; 64-bit block, key-derived S-boxes (8-byte key here).",
  twofish:
    "Twofish (Schneier et al., 1998) — 16-round Feistel; 128-bit block, key-dependent S-boxes, MDS + PHT.",
};

/** Per-hash one-liner. Mirrors `HASH_LABELS`. */
export const HASH_DESCRIPTIONS: Record<Hash, string> = {
  "sha-256":
    "SHA-256 (FIPS 180-4) — Merkle–Damgård hash; 256-bit digest from 512-bit blocks over 64 rounds.",
  "sha3-256":
    "SHA3-256 (FIPS 202) — Keccak sponge; 256-bit digest, absorbs 1088-bit blocks through Keccak-f[1600] (24 rounds θρπχι).",
  shake128:
    "SHAKE128 (FIPS 202) — Keccak XOF; arbitrary-length output, 168-byte rate (128-bit strength). Squeezes as many blocks as you ask for.",
  shake256:
    "SHAKE256 (FIPS 202) — Keccak XOF; arbitrary-length output, 136-byte rate (256-bit strength). Squeezes as many blocks as you ask for.",
};

/** Per-asymmetric one-liner. Mirrors `ASYMMETRIC_LABELS`. */
export const ASYMMETRIC_DESCRIPTIONS: Record<Asymmetric, string> = {
  rsa: "Textbook RSA — public-key: key-gen (p, q, e → n, φ, d) + modular exponentiation. No padding.",
};

/**
 * Resolve the one-liner for any algorithm, routing by family. Used by the
 * header caption and the selector caption so the two surfaces stay in sync
 * (same single source of truth, like `CIPHER_LABELS` drives both the dropdown
 * and the "Custom (was …)" indicator).
 */
export const describeAlgorithm = (a: Algorithm): string =>
  isHash(a)
    ? HASH_DESCRIPTIONS[a]
    : isAsymmetric(a)
      ? ASYMMETRIC_DESCRIPTIONS[a]
      : CIPHER_DESCRIPTIONS[a];

// ─── Historical one-liners (2026-07-12) ──────────────────────────────────────
//
// A second, DIFFERENT flavour of one-liner: instead of the structural "what is
// this primitive" line above (which stays in the header next to "Cryptographer"),
// these carry the *history* — who designed it, when, and its place in the
// lineage. Surfaced ONLY in the selector caption below the dropdown, so the two
// surfaces complement rather than duplicate each other (per user request
// 2026-07-12: header keeps the technical line, caption tells the story).
//
// History is a family property, not a key-length one, so the AES / Speck /
// Serpent variants deliberately share their family's sentence — the 128/192/256
// distinction is a structural detail already carried by the header line.

/** Per-cipher historical one-liner. Keep in sync with `ALL_CIPHERS`. */
export const CIPHER_HISTORY: Record<Cipher, string> = {
  "aes-128":
    "Belgian design 'Rijndael' (Daemen & Rijmen); won NIST's open 1997–2000 contest, standardised as FIPS-197 in 2001.",
  "aes-192":
    "Belgian design 'Rijndael' (Daemen & Rijmen); won NIST's open 1997–2000 contest, standardised as FIPS-197 in 2001.",
  "aes-256":
    "Belgian design 'Rijndael' (Daemen & Rijmen); won NIST's open 1997–2000 contest, standardised as FIPS-197 in 2001.",
  "speck-32-64-be":
    "Published by the U.S. NSA in 2013 for constrained IoT devices; its ISO standardisation push drew public controversy.",
  "speck-32-64-le":
    "Published by the U.S. NSA in 2013 for constrained IoT devices; its ISO standardisation push drew public controversy.",
  "serpent-128":
    "Anderson, Biham & Knudsen's AES finalist (1998); placed second to Rijndael, prized for a conservative security margin.",
  "serpent-192":
    "Anderson, Biham & Knudsen's AES finalist (1998); placed second to Rijndael, prized for a conservative security margin.",
  "serpent-256":
    "Anderson, Biham & Knudsen's AES finalist (1998); placed second to Rijndael, prized for a conservative security margin.",
  des: "IBM's Lucifer, tuned by the NSA and adopted as U.S. standard in 1977; brute-forced by the EFF's 'Deep Crack' in 1998.",
  blowfish:
    "Bruce Schneier's 1993 unpatented, royalty-free cipher; a popular DES replacement, later succeeded by his Twofish.",
  twofish:
    "Schneier, Kelsey, Whiting, Wagner, Hall & Ferguson's AES finalist (1998); Blowfish's successor, unpatented and a strong runner-up to Rijndael.",
};

/** Per-hash historical one-liner. Mirrors `HASH_DESCRIPTIONS`. */
export const HASH_HISTORY: Record<Hash, string> = {
  "sha-256":
    "NSA-designed, published by NIST in 2001 (FIPS 180-2); the SHA-2 workhorse behind TLS, Bitcoin, and Git.",
  "sha3-256":
    "Keccak (Bertoni, Daemen, Peeters, Van Assche) won NIST's SHA-3 competition in 2012; standardized as FIPS 202 in 2015. A sponge, structurally unlike SHA-2 — and the hash every NIST post-quantum standard builds on.",
  shake128:
    "The XOF face of Keccak, standardized alongside SHA-3 in FIPS 202 (2015); its extendable output is the workhorse inside ML-KEM, ML-DSA, and SLH-DSA.",
  shake256:
    "The higher-strength Keccak XOF from FIPS 202 (2015); a variable-length output built from the same sponge, used pervasively across the NIST post-quantum standards.",
};

/** Per-asymmetric historical one-liner. Mirrors `ASYMMETRIC_DESCRIPTIONS`. */
export const ASYMMETRIC_HISTORY: Record<Asymmetric, string> = {
  rsa: "Rivest, Shamir & Adleman, 1977 — the first practical public-key cryptosystem; secretly pre-discovered by GCHQ's Cocks in 1973.",
};

/**
 * Resolve the historical one-liner for any algorithm, routing by family.
 * Sibling of `describeAlgorithm` (which the header uses); this one feeds only
 * the selector caption.
 */
export const historyOfAlgorithm = (a: Algorithm): string =>
  isHash(a) ? HASH_HISTORY[a] : isAsymmetric(a) ? ASYMMETRIC_HISTORY[a] : CIPHER_HISTORY[a];

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
  // DES canonical KAT key from FIPS 46-3 Appendix B test vector. Bit 8 of
  // each byte is a parity bit — flipping any of those 8 bits produces an
  // identical key schedule (PC-1 in `des.key-schedule@1` drops them).
  des: new Uint8Array([0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1]),
  // Blowfish canonical key from the Eric-Young Blowfish-ECB vector set. 8 bytes
  // (v1 fixes the key length). Under key 0123456789abcdef + plaintext
  // 1111111111111111 the cipher produces 61f9c3802281b096 — a published vector,
  // so the first Run reproduces a textbook result (like AES's FIPS-197 default).
  blowfish: new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
  // Twofish canonical key — the sequential 16-byte pattern (AES/Serpent house
  // style). Under plaintext 00112233…ff it produces df8451d2…3203, verified
  // against Niels Ferguson's reference; the all-zero key/pt gives the published
  // 128-bit vector 9f589f5c…c35a. See `docs/plans/twofish.md`.
  twofish: new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
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
  // DES canonical KAT plaintext from FIPS 46-3 Appendix B
  // (`PT=0123456789abcdef → CT=85e813540f0ab405` under the key above).
  des: new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
  // Blowfish canonical plaintext (Eric-Young vector) — 8 bytes, one block.
  blowfish: new Uint8Array([0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]),
  // Twofish uses the same 16-byte AES-style plaintext (128-bit block).
  twofish: new Uint8Array([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  ]),
};

/**
 * Canonical default *ciphertext* per cipher — the exact output each cipher
 * produces from its `DEFAULT_PT_BYTES_BY_CIPHER` plaintext under its
 * `DEFAULT_KEY_BYTES_BY_CIPHER` key. This is the decrypt-mode analogue of the
 * plaintext table above: it is what the input field should hold when the user
 * lands in decrypt mode, so the first Run round-trips straight back to the
 * canonical plaintext (mirroring how encrypt's first Run lands on the
 * published vector).
 *
 * **Why a table rather than computing on the fly.** Deriving these would mean
 * running each encrypt spec through the runtime (needs the registry, the spec
 * map, and a full trace) every time the cipher selector changes — heavy for a
 * UI event handler. Baking constants in matches the existing PT/KEY-table
 * pattern. The bytes are NOT hand-derived (which would risk the Speck BE/LE
 * and Serpent byte-convention traps): they were computed by running each
 * canonical encrypt spec, and `tests/default-ciphertext-table.test.ts` pins
 * every entry to `encrypt(DEFAULT_PT, DEFAULT_KEY)` so the table can never
 * drift from the implementation. The AES-128 / Speck-BE / Speck-LE / DES
 * entries additionally match their published KAT vectors (FIPS-197 §C.1,
 * Beaulieu et al., FIPS 46-3 App B), which keeps the round-trip test
 * non-circular — a regression in the shared byte-flat engine would break the
 * literal-anchor assertions, not silently redefine "canonical."
 *
 * App.tsx's `changeCipher` consults this in decrypt mode: if the ciphertext
 * field currently holds the previous cipher's canonical ciphertext, it swaps
 * to the new cipher's. A user-typed ciphertext is left alone (same sacred-
 * input policy as the plaintext/key swaps).
 *
 * AES-192/256 use the FIPS-197 sequential plaintext under §A.2/§A.3's
 * sequential keys (NOT the NIST AES Core `6bc1…` vectors), so their
 * ciphertexts differ from the headline KAT constants — they ride on the
 * existing AES-192/256 KAT coverage transitively via the table test.
 */
export const DEFAULT_CT_BYTES_BY_CIPHER: Record<Cipher, Uint8Array> = {
  // FIPS-197 §C.1: PT 00112233…ff under key 000102…0f → 69c4e0d8…c55a.
  "aes-128": new Uint8Array([
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
  ]),
  "aes-192": new Uint8Array([
    0xeb, 0x1b, 0x03, 0xf2, 0xac, 0xb6, 0x4b, 0xcf, 0x28, 0xc9, 0x99, 0x1c, 0xc8, 0xa4, 0xfa, 0x50,
  ]),
  "aes-256": new Uint8Array([
    0xd8, 0x34, 0x14, 0x22, 0x3d, 0x20, 0xa0, 0xc9, 0x28, 0xb1, 0x36, 0xc8, 0x84, 0xd0, 0x7e, 0xa2,
  ]),
  // Beaulieu et al. Speck32/64 KAT under each byte convention.
  "speck-32-64-be": new Uint8Array([0xa8, 0x68, 0x42, 0xf2]), // "a86842f2"
  "speck-32-64-le": new Uint8Array([0xf2, 0x42, 0x68, 0xa8]), // "f24268a8"
  "serpent-128": new Uint8Array([
    0x56, 0x3e, 0x2c, 0xf8, 0x74, 0x0a, 0x27, 0xc1, 0x64, 0x80, 0x45, 0x60, 0x39, 0x1e, 0x9b, 0x27,
  ]),
  "serpent-192": new Uint8Array([
    0x6a, 0xb8, 0x16, 0xc8, 0x2d, 0xe5, 0x3b, 0x93, 0x00, 0x50, 0x08, 0xaf, 0xa2, 0x24, 0x6a, 0x02,
  ]),
  "serpent-256": new Uint8Array([
    0x28, 0x68, 0xb7, 0xa2, 0xd2, 0x8e, 0xcd, 0x5e, 0x4f, 0xde, 0xfa, 0xc3, 0xc4, 0x33, 0x00, 0x74,
  ]),
  // FIPS 46-3 Appendix B: PT 0123456789abcdef under key 133457799bbcdff1.
  des: new Uint8Array([0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05]),
  // Eric-Young Blowfish-ECB vector: PT 1111111111111111 under key
  // 0123456789abcdef → 61f9c3802281b096.
  blowfish: new Uint8Array([0x61, 0xf9, 0xc3, 0x80, 0x22, 0x81, 0xb0, 0x96]),
  // Twofish: PT 00112233…ff under key 000102…0f → df8451d2…3203 (Ferguson ref).
  twofish: new Uint8Array([
    0xdf, 0x84, 0x51, 0xd2, 0x6e, 0x05, 0x04, 0xbc, 0x19, 0xb0, 0xa9, 0x3b, 0x04, 0x9e, 0x32, 0x03,
  ]),
};

// ─── Hash defaults ───────────────────────────────────────────────────────
//
// Slice 2.10b (2026-05-25) — canonical input bytes per Hash variant. The
// store wiring in `stores/spec.ts` consults these when constructing a
// `kind: "hash"` SpecsByMode (today reachable only via tests; 2.10c wires
// the user-facing entry point). They live alongside the cipher tables so
// `App.tsx`'s smart-swap on document load can route to the right table
// after checking `isCipher` vs `isHash`.
//
// **Key bytes**: hashes have no key (SHA-256's `inputs.key.byteLength`
// is 0), so the default is an empty `Uint8Array`. App.tsx's
// `parseBytesWithLength` accepts a zero-length expectation and renders
// the field as empty; the user can ignore it.
//
// **Plaintext bytes**: SHA-256's first KAT in FIPS 180-4 §A.1 is the
// 3-byte message "abc" (`[0x61, 0x62, 0x63]`), producing the digest
// `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
// First-time users hitting Run with this default reproduce that
// textbook vector exactly, mirroring how AES's default lands on
// FIPS-197 Appendix C.

/**
 * Canonical default key bytes per hash variant. Hashes are keyless so
 * the value is an empty `Uint8Array`; the structure mirrors the cipher
 * tables so callers can route `Algorithm` values to a unified lookup
 * via `isCipher` / `isHash`.
 */
export const DEFAULT_KEY_BYTES_BY_HASH: Record<Hash, Uint8Array> = {
  "sha-256": new Uint8Array(0),
  "sha3-256": new Uint8Array(0),
  shake128: new Uint8Array(0),
  shake256: new Uint8Array(0),
};

/**
 * Canonical default plaintext bytes per hash variant. SHA-256 lands on
 * "abc" — the FIPS 180-4 §A.1 single-block KAT — so the first Run
 * reproduces the textbook digest exactly.
 */
export const DEFAULT_PT_BYTES_BY_HASH: Record<Hash, Uint8Array> = {
  "sha-256": new Uint8Array([0x61, 0x62, 0x63]),
  // "abc" — the FIPS 202 §A.1 example, digest 3a985da7...31532.
  "sha3-256": new Uint8Array([0x61, 0x62, 0x63]),
  // "abc" — SHAKE128("abc") @ 32 = 5881092d…; the first Run reproduces the KAT.
  shake128: new Uint8Array([0x61, 0x62, 0x63]),
  // "abc" — SHAKE256("abc") @ 32 = 48336660…
  shake256: new Uint8Array([0x61, 0x62, 0x63]),
};

// ─── Asymmetric defaults ───────────────────────────────────────────────────
//
// RSA is keyless in the symmetric sense — the public/private material is the
// editable `p, q, e` constants on the spec — so the key default is empty
// (`inputs.key.byteLength` is 0; the key field is hidden for the asymmetric
// category). The message / ciphertext are W=2-byte big-endian integers; the
// defaults are the classic textbook vector m=65 ⇒ c=2790 (n=3233) so the first
// Run reproduces it and decrypt round-trips straight back. Kept in sync with
// `RSA_DEFAULT_MESSAGE` / the KAT in `src/ciphers/rsa.ts` +
// `tests/rsa-vectors.test.ts`.

/** Empty key per asymmetric variant — RSA has no symmetric key field. */
export const DEFAULT_KEY_BYTES_BY_ASYMMETRIC: Record<Asymmetric, Uint8Array> = {
  rsa: new Uint8Array(0),
};

/** Default message m (encrypt input) — 65 as a 2-byte BE integer. */
export const DEFAULT_PT_BYTES_BY_ASYMMETRIC: Record<Asymmetric, Uint8Array> = {
  rsa: new Uint8Array([0x00, 0x41]),
};

/** Default ciphertext c (decrypt input) — 2790 (= 65¹⁷ mod 3233) as 2-byte BE. */
export const DEFAULT_CT_BYTES_BY_ASYMMETRIC: Record<Asymmetric, Uint8Array> = {
  rsa: new Uint8Array([0x0a, 0xe6]),
};

/** Test-only reset; production code never calls this. */
export const __resetCipherForTests = (): void => {
  setCipherSignal("aes-128");
  setHashSignal("sha-256");
  setAsymmetricSignal("rsa");
  setCategorySignal("cipher");
};
