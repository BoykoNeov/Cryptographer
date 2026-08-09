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
import { POLY_BYTES } from "../../ciphers/mlkem-constants";
import { DEFAULT_NTT_INPUT, DEFAULT_NTT_OUTPUT } from "../../ciphers/ntt-3329-256";

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
/**
 * ChaCha20 (RFC 8439) — the app's first STREAM cipher, and the first cipher
 * with no `BlockCipherCore` at all.
 *
 * Every other member of this union is a block cipher: a keyed permutation on a
 * fixed-width block, which a mode of operation then repeats over a long
 * message. ChaCha20 is a different kind of object. It generates a keystream
 * from (key, nonce, counter) and the message meets that keystream exactly once,
 * at an XOR — so it needs no mode wrapped around it, contains its own counter,
 * accepts any message length ≥ 1, and never pads.
 *
 * Consequences worth knowing before touching anything cipher-keyed: it is the
 * first cipher for which `hasBlockCipherCore` is false, the first whose
 * supported-mode list does NOT include `"single-block"`, and the first whose IV
 * width is not its block width (16-byte counter‖nonce vs a 64-byte block).
 * `docs/plans/fluffy-orbiting-shannon.md`.
 */
export type ChaChaCipher = "chacha20";

/**
 * Salsa20 — the SECOND stream cipher, and ChaCha20's direct ancestor.
 *
 * Everything the ChaCha20 note above says about stream ciphers applies here
 * unchanged, which is the point: Salsa20 is the evidence that `"stream"` was
 * correctly modelled as a sixth `CipherMode` rather than a per-cipher
 * predicate. It costs exactly one row in `SUPPORTED_CIPHER_MODES_BY_CIPHER`
 * and ZERO new arms on `isStreamCipher` / `isStreamCipherMode` /
 * `cipherModeUsesIv` / `defaultCipherModeFor` — all of which already derive
 * from that row.
 *
 * Where it differs from ChaCha20: its state is assembled on the DIAGONAL from
 * eight runs rather than four contiguous regions, its nonce is 8 bytes rather
 * than 12, and its counter is 64 bits rather than 32 (so the IV is still 16
 * bytes, but split 8/8 instead of 4/12). `docs/plans/shiny-wandering-conway.md`.
 */
export type SalsaCipher = "salsa20";
export type Cipher =
  | AesCipher
  | SpeckCipher
  | SerpentCipher
  | DesCipher
  | BlowfishCipher
  | TwofishCipher
  | ChaChaCipher
  | SalsaCipher;

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
export type Hash =
  | "sha-256"
  | "sha3-256"
  | "shake128"
  | "shake256"
  | "cshake128"
  | "cshake256"
  | "kmac128"
  | "kmac256"
  | "kmacxof128"
  | "kmacxof256";

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
 * Pseudo-random generator family — algorithms that consume a seed and emit a
 * reproducible stream of bytes. MINSTD's two published multipliers are the first
 * members (`docs/plans/iterative-dancing-ocean.md`).
 *
 * **Why a fourth family rather than a cipher with a stream mode.** A PRNG has no
 * message. It has a seed (which sequence) and a requested length (how much of
 * it) — and nothing to encrypt. Modelling one as a `Cipher` would make
 * `isCipher` true, which drags in `SUPPORTED_CIPHER_MODES_BY_CIPHER`,
 * `defaultCipherModeFor`, `paddingLimits` and `ivByteLengthFor`: precisely the
 * surface a separate category costs nothing on. It would also present a
 * plaintext field for something that has no plaintext, which is the sort of
 * category lie the family split exists to prevent.
 *
 * Like a hash, a generator is **direction-less** — there is no inverse, so no
 * encrypt/decrypt toggle — which is why `PrngSpecsByMode` in `stores/spec.ts`
 * copies the single-slot hash shape rather than the two-slot cipher shape.
 *
 * The family spans both halves of the subject deliberately: three linear
 * congruential generators whose output is trivially predictable, and one
 * (`chacha20-csprng`) that is not. The comparison is the point — see
 * `ciphers/chacha20-csprng.ts` on the single step that separates them.
 */
export type Prng = "minstd-rand0" | "minstd-rand" | "ansi-c-lcg" | "mt19937" | "chacha20-csprng";

/**
 * Lattice family — arithmetic over the polynomial ring
 * `R_q = Z_q[X]/(X²⁵⁶+1)` with `q = 3329`, the setting the NIST post-quantum
 * standards are built in. The number-theoretic transform is the first (and, at
 * P1, only) member: `docs/plans/unified-stargazing-quasar.md`.
 *
 * **Why a fifth family rather than a cipher or a hash.** The NTT is a change of
 * representation, not an encryption and not a digest:
 *
 * - It is **not a cipher**. There is no key, and `isCipher` returning true would
 *   drag in `SUPPORTED_CIPHER_MODES_BY_CIPHER`, `defaultCipherModeFor`,
 *   `paddingLimits` and `ivByteLengthFor` — presenting a key field, a mode
 *   selector and a padding scheme for something that has none of them.
 * - It is **not a hash**: it is invertible, exactly.
 * - It is **not a PRNG**: it has a message (the polynomial).
 * - It is **not public-key**: no key pair.
 *
 * Unlike the hash and PRNG families it IS direction-ful — forward and inverse
 * are a genuine pair — so `LatticeSpecsByMode` in `stores/spec.ts` copies the
 * two-slot `AsymmetricSpecsByMode` shape rather than the single-slot hash one.
 * RSA is the precedent that matters here: a non-cipher family with two
 * directions was already a solved surface.
 */
export type Lattice = "ntt-3329-256";

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
export type Category = "cipher" | "hash" | "asymmetric" | "prng" | "lattice";

/**
 * Public umbrella type — every cryptographic primitive the app supports.
 * Use this when the surface needs to accept any algorithm; use `Cipher` or
 * `Hash` directly when the caller's logic is specific to one family.
 *
 * Predicates `isCipher` / `isHash` below narrow `Algorithm` to either branch.
 * Implementing functions in terms of `Algorithm` and branching on category
 * is cheaper than maintaining parallel cipher-only and hash-only overloads.
 */
export type Algorithm = Cipher | Hash | Asymmetric | Prng | Lattice;

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
  "chacha20",
  "salsa20",
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
  a === "sha-256" ||
  a === "sha3-256" ||
  a === "shake128" ||
  a === "shake256" ||
  a === "cshake128" ||
  a === "cshake256" ||
  a === "kmac128" ||
  a === "kmac256" ||
  a === "kmacxof128" ||
  a === "kmacxof256";

/**
 * True when an algorithm is in the asymmetric (public-key) family. RSA today.
 * Defined alongside `isHash` so `isCipher` can exclude BOTH non-cipher
 * families explicitly.
 */
export const isAsymmetric = (a: Algorithm): a is Asymmetric => a === "rsa";

/**
 * The generator variants, hoisted above `isPrng` so the predicate can be
 * expressed as membership rather than a hand-written disjunction. `PRNG_OPTIONS`
 * re-exports it further down, beside the other families' option lists.
 *
 * **Membership, not `a === … || a === …`, is deliberate.** The disjunction form
 * re-arms the `isCipher` landmine on every new *variant*, not just every new
 * family: widen the `Prng` union, forget the extra arm, and `isPrng` returns
 * false, so `isCipher` returns true and the compiler believes it — the
 * generator silently acquires a mode selector, padding and a key field. Reading
 * the list means the union and the predicate cannot disagree.
 */
const ALL_PRNGS: readonly Prng[] = [
  "minstd-rand0",
  "minstd-rand",
  "ansi-c-lcg",
  "mt19937",
  "chacha20-csprng",
];

/**
 * True when an algorithm is a pseudo-random generator. Defined alongside
 * `isHash` / `isAsymmetric` so `isCipher` below can exclude all three
 * non-cipher families explicitly.
 */
export const isPrng = (a: Algorithm): a is Prng => (ALL_PRNGS as readonly string[]).includes(a);

/**
 * The lattice variants. Membership, for the reason spelled out on `ALL_PRNGS`
 * above — a hand-written disjunction re-arms the `isCipher` landmine on every
 * new *variant*, and the compiler believes a type predicate whatever it says.
 * P2's additions land here and nowhere else.
 */
const ALL_LATTICE: readonly Lattice[] = ["ntt-3329-256"];

/**
 * True when an algorithm is in the lattice family. Defined alongside `isHash` /
 * `isAsymmetric` / `isPrng` so `isCipher` below can exclude all four non-cipher
 * families explicitly.
 */
export const isLattice = (a: Algorithm): a is Lattice =>
  (ALL_LATTICE as readonly string[]).includes(a);

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
export const isCipher = (a: Algorithm): a is Cipher =>
  !isHash(a) && !isAsymmetric(a) && !isPrng(a) && !isLattice(a);

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
const [prng, setPrngSignal] = createSignal<Prng>("minstd-rand0");
const [lattice, setLatticeSignal] = createSignal<Lattice>("ntt-3329-256");
const [category, setCategorySignal] = createSignal<Category>("cipher");

export const useHash = () => hash;
export const useAsymmetric = () => asymmetric;
export const usePrng = () => prng;
export const useLattice = () => lattice;
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

/** Set the active PRNG variant. Does NOT flip category — mirrors `setHash` /
 *  `setAsymmetric`; the category-flipping setter of the same name lives in
 *  `stores/spec.ts` and composes both. */
export const setPrng = (p: Prng): void => {
  setPrngSignal(p);
};

/** Set the active lattice variant. Does NOT flip category — mirrors `setHash` /
 *  `setAsymmetric` / `setPrng`; the category-flipping setter of the same name
 *  lives in `stores/spec.ts` and composes both. */
export const setLattice = (l: Lattice): void => {
  setLatticeSignal(l);
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
    if (c === "prng") return prng();
    if (c === "lattice") return lattice();
    return asymmetric();
  };
};

/** Hash dropdown options + labels. Sized to one entry today; mirrors
 *  CIPHER_OPTIONS / CIPHER_LABELS so the UI can render either family with
 *  the same `<For each={options}>` shape. */
const ALL_HASHES: readonly Hash[] = [
  "sha-256",
  "sha3-256",
  "shake128",
  "shake256",
  "cshake128",
  "cshake256",
  "kmac128",
  "kmac256",
  "kmacxof128",
  "kmacxof256",
];
export const HASH_OPTIONS = ALL_HASHES;
export const HASH_LABELS: Record<Hash, string> = {
  "sha-256": "SHA-256",
  "sha3-256": "SHA3-256",
  shake128: "SHAKE128",
  shake256: "SHAKE256",
  cshake128: "cSHAKE128",
  cshake256: "cSHAKE256",
  kmac128: "KMAC128",
  kmac256: "KMAC256",
  kmacxof128: "KMACXOF128",
  kmacxof256: "KMACXOF256",
};

/** Asymmetric dropdown options + labels. One entry today (RSA); mirrors the
 *  cipher / hash option shapes so the selector renders any family uniformly. */
const ALL_ASYMMETRICS: readonly Asymmetric[] = ["rsa"];
export const ASYMMETRIC_OPTIONS = ALL_ASYMMETRICS;
export const ASYMMETRIC_LABELS: Record<Asymmetric, string> = {
  rsa: "RSA (textbook)",
};

/** Lattice dropdown options + labels. One entry today (the NTT); mirrors the
 *  other families' option shapes so the selector renders any family uniformly. */
export const LATTICE_OPTIONS = ALL_LATTICE;
export const LATTICE_LABELS: Record<Lattice, string> = {
  "ntt-3329-256": "NTT over Z₃₃₂₉[X]/(X²⁵⁶+1)",
};

/** PRNG dropdown options + labels. The variants differ in a handful of
 *  constants — which is the point: the label names the standard identifier a
 *  learner will meet in C++, in C, or in the literature. */
export const PRNG_OPTIONS = ALL_PRNGS;
export const PRNG_LABELS: Record<Prng, string> = {
  "minstd-rand0": "MINSTD (a = 16807)",
  "minstd-rand": "MINSTD (a = 48271)",
  // NOT "glibc rand()" — glibc's default is a TYPE_3 additive-feedback
  // generator, not this LCG. The C standard's own §7.22.2.2 example and
  // POSIX `rand_r` are what this recurrence actually is.
  "ansi-c-lcg": "ANSI C LCG (rand_r)",
  // Named after the algorithm rather than its constants: unlike the three
  // above, MT19937 is not summarised by a multiplier.
  mt19937: "MT19937 (Mersenne Twister)",
  // The odd one out, and labelled as such: the other three are named after
  // their constants because their constants are all they are. This one is named
  // after a cipher, because it IS one.
  "chacha20-csprng": "ChaCha20 CSPRNG (secure)",
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
  chacha20: "ChaCha20",
  salsa20: "Salsa20",
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
  chacha20:
    "ChaCha20 (Bernstein, 2008; RFC 8439) — stream cipher; 20 ARX rounds over a 4×4 word state, no S-box, no padding.",
  salsa20:
    "Salsa20/20 (Bernstein, 2005) — stream cipher; ChaCha20's ancestor, 20 ARX rounds over a diagonally-assembled 4×4 word state.",
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
  cshake128:
    "cSHAKE128 (SP 800-185) — customizable SHAKE128; a customization string S domain-separates the XOF. Empty S ⇒ plain SHAKE128.",
  cshake256:
    "cSHAKE256 (SP 800-185) — customizable SHAKE256; a customization string S domain-separates the XOF. Empty S ⇒ plain SHAKE256.",
  kmac128:
    "KMAC128 (SP 800-185) — Keccak keyed MAC on cSHAKE128; the first keyed hash. 128-bit strength, fixed-length tag.",
  kmac256:
    "KMAC256 (SP 800-185) — Keccak keyed MAC on cSHAKE256; 256-bit strength, fixed-length tag.",
  kmacxof128:
    "KMACXOF128 (SP 800-185) — the XOF variant of KMAC128; arbitrary-length tag (appends right_encode(0)).",
  kmacxof256: "KMACXOF256 (SP 800-185) — the XOF variant of KMAC256; arbitrary-length tag.",
};

/** Per-asymmetric one-liner. Mirrors `ASYMMETRIC_LABELS`. */
export const ASYMMETRIC_DESCRIPTIONS: Record<Asymmetric, string> = {
  rsa: "Textbook RSA — public-key: key-gen (p, q, e → n, φ, d) + modular exponentiation. No padding.",
};

/** Per-PRNG one-liner. Mirrors `PRNG_LABELS`. */
export const PRNG_DESCRIPTIONS: Record<Prng, string> = {
  "minstd-rand0":
    "MINSTD (Lehmer 1951 / Park–Miller 1988) — x ← 16807·x mod 2³¹−1. One multiply, one remainder; predictable, not secure.",
  "minstd-rand":
    "MINSTD revised (Park–Miller–Stockmeyer 1993) — x ← 48271·x mod 2³¹−1. Same structure, better spectral behaviour.",
  "ansi-c-lcg":
    "ANSI C LCG (rand_r) — x ← (1103515245·x + 12345) mod 2³¹. A power-of-two modulus: the low bits are almost pure structure.",
  mt19937:
    "Mersenne Twister — period 2¹⁹⁹³⁷−1, passes the statistical batteries the LCGs fail, and is still fully predictable: 624 outputs recover the whole state.",
  "chacha20-csprng":
    "ChaCha20 as a generator — the stream cipher with the message removed. Twenty rounds per 64 bytes, and unlike the LCGs its output does not reveal its state.",
};

/** Per-lattice one-liner. Mirrors `LATTICE_LABELS`. */
export const LATTICE_DESCRIPTIONS: Record<Lattice, string> = {
  "ntt-3329-256":
    "Number-theoretic transform — the FFT done in integers mod the prime 3329; makes polynomial multiplication in ML-KEM's ring cheap and exact.",
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
      : isPrng(a)
        ? PRNG_DESCRIPTIONS[a]
        : isLattice(a)
          ? LATTICE_DESCRIPTIONS[a]
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
  chacha20:
    "Daniel J. Bernstein's 2008 refinement of his Salsa20; standardized as RFC 8439 and paired with Poly1305 in TLS 1.3, WireGuard and OpenSSH — the fast, constant-time answer to AES on hardware without AES instructions.",
  salsa20:
    "Bernstein's 2005 submission to the eSTREAM project, which selected it for its final software portfolio in 2008; the design ChaCha20 refines, and still the reference for the ARX stream-cipher family.",
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
  cshake128:
    "The customizable SHAKE from NIST SP 800-185 (2016); adds a domain-separation string so an application can carve out its own independent instance of the XOF. The base construction under KMAC.",
  cshake256:
    "The 256-bit-strength customizable SHAKE from NIST SP 800-185 (2016); the same domain-separation idea on the higher-security sponge, and the base of KMAC256.",
  kmac128:
    "The Keccak keyed MAC from NIST SP 800-185 (2016); built on cSHAKE, it is the SHA-3 family's native alternative to HMAC — a keyed, length-committing tag.",
  kmac256:
    "The 256-bit-strength Keccak MAC from NIST SP 800-185 (2016); cSHAKE256 with a key block and an output-length commitment.",
  kmacxof128:
    "The extendable-output variant of KMAC128 (SP 800-185, 2016); drops the length commitment so the tag can be squeezed to any length.",
  kmacxof256:
    "The extendable-output variant of KMAC256 (SP 800-185, 2016); an arbitrary-length keyed output.",
};

/** Per-asymmetric historical one-liner. Mirrors `ASYMMETRIC_DESCRIPTIONS`. */
export const ASYMMETRIC_HISTORY: Record<Asymmetric, string> = {
  rsa: "Rivest, Shamir & Adleman, 1977 — the first practical public-key cryptosystem; secretly pre-discovered by GCHQ's Cocks in 1973.",
};

/** Per-PRNG historical one-liner. Mirrors `PRNG_DESCRIPTIONS`. */
export const PRNG_HISTORY: Record<Prng, string> = {
  "minstd-rand0":
    "D. H. Lehmer's 1951 generator, which Park & Miller proposed in 1988 as a 'minimal standard' any generator should at least match; it became the default in countless libraries, and the source of countless flawed simulations.",
  "minstd-rand":
    "Park, Miller & Stockmeyer's 1993 revision after correspondence over the original's spectral flaws; both multipliers are named in the C++ standard, which is unusual — few algorithms have their constants fixed by an ISO document.",
  mt19937:
    "Matsumoto & Nishimura, 1998 — the default generator in Python, C++, MATLAB, Ruby and PHP, and the one a learner is most likely to have already used. It was a genuine advance over the LCGs on every statistical measure, and was never intended to be unpredictable; a 2000s generation of web applications used it for session tokens and password resets anyway.",
  "ansi-c-lcg":
    "The sample rand() published in the 1989 ANSI C standard (and carried into POSIX rand_r) — an implementation illustration that a generation of programs shipped verbatim. Its power-of-two modulus makes the low bits worthless, which is exactly why the sample discards the bottom 16 before returning a number.",
  "chacha20-csprng":
    "Daniel J. Bernstein's 2008 stream cipher, run as a generator — the configuration Linux's getrandom() and BSD's arc4random() actually use. It is the answer to the defect the three LCGs above demonstrate: their output hands over their state, and a CSPRNG's does not.",
};

/** Per-lattice historical one-liner. Mirrors `LATTICE_DESCRIPTIONS`. */
export const LATTICE_HISTORY: Record<Lattice, string> = {
  "ntt-3329-256":
    "Gauss described the algorithm in 1805, two years before Fourier's own work; Cooley & Tukey rediscovered it in 1965 and Pollard moved it into modular arithmetic in 1971. NIST's 2024 post-quantum standard ML-KEM (FIPS 203) does not merely use it for speed — it stores keys and ciphertexts in the transformed domain, making this transform part of the data format itself.",
};

/**
 * Resolve the historical one-liner for any algorithm, routing by family.
 * Sibling of `describeAlgorithm` (which the header uses); this one feeds only
 * the selector caption.
 */
export const historyOfAlgorithm = (a: Algorithm): string =>
  isHash(a)
    ? HASH_HISTORY[a]
    : isAsymmetric(a)
      ? ASYMMETRIC_HISTORY[a]
      : isPrng(a)
        ? PRNG_HISTORY[a]
        : isLattice(a)
          ? LATTICE_HISTORY[a]
          : CIPHER_HISTORY[a];

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
  // ChaCha20's 256-bit key, from RFC 8439 §2.4.2's worked example. The default
  // key, nonce, counter and plaintext together reproduce that section's
  // published ciphertext exactly — the same choice AES-128 makes with
  // FIPS-197 §C.1, so the app's first impression IS a published test vector.
  chacha20: new Uint8Array([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ]),
  // Salsa20's 256-bit key, from the eSTREAM/ECRYPT verified test vectors
  // (Set 6, vector 0). Paired with that vector's nonce in
  // DEFAULT_IV_BYTES_BY_CIPHER, so the keystream the app generates on its first
  // Run is a published one — the same "first impression IS a test vector"
  // choice AES-128 makes with FIPS-197 §C.1 and ChaCha20 with RFC 8439 §2.4.2.
  salsa20: new Uint8Array([
    0x00, 0x53, 0xa6, 0xf9, 0x4c, 0x9f, 0xf2, 0x45, 0x98, 0xeb, 0x3e, 0x91, 0xe4, 0x37, 0x8a, 0xdd,
    0x30, 0x83, 0xd6, 0x29, 0x7c, 0xcf, 0x22, 0x75, 0xc8, 0x1b, 0x6e, 0xc1, 0x14, 0x67, 0xba, 0x0d,
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
  // RFC 8439 §2.4.2's plaintext, verbatim. 114 bytes — deliberately NOT a
  // multiple of the 64-byte block, so the default view demonstrates the
  // property that distinguishes a stream cipher: the last block is short, the
  // keystream is trimmed to match it, and the ciphertext comes out exactly as
  // long as the plaintext with no padding anywhere.
  chacha20: new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  ),
  // 108 bytes — deliberately NOT a multiple of the 64-byte block, for the same
  // reason ChaCha20's default is 114: the default view should demonstrate the
  // property that distinguishes a stream cipher, with a short final block whose
  // keystream is trimmed to match and no padding anywhere.
  salsa20: new TextEncoder().encode(
    "Salsa20 builds a keystream from the key, the nonce and a counter; the message meets it just once, at an XOR.",
  ),
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
  // ChaCha20: RFC 8439 §2.4.2's published ciphertext, under that section's key,
  // its nonce 00:00:00:00:00:00:00:4a:00:00:00:00 and its initial counter of 1
  // (see DEFAULT_IV_BYTES_BY_CIPHER — the counter is 1, NOT 0). Cross-checked
  // against node:crypto's `chacha20` before being written down.
  chacha20: new Uint8Array([
    0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
    0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
    0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
    0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
    0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
    0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
    0x87, 0x4d,
  ]),
  // Salsa20: the default plaintext under the eSTREAM Set 6 vector-0 key and
  // nonce, counter starting at 0. Generated offline from pycryptodome's
  // `Crypto.Cipher.Salsa20` — `node:crypto` has no `salsa20`, so unlike every
  // other row in this table there is no live reference to check it against at
  // run time. See `tests/salsa20-kat.test.ts` for the pinned vectors.
  salsa20: new Uint8Array([
    0xa6, 0x9b, 0xb9, 0x4c, 0x18, 0xcb, 0xef, 0x78, 0xa6, 0xdb, 0xc9, 0xbc, 0x89, 0xe9, 0xb6, 0x60,
    0xd2, 0x13, 0x74, 0x55, 0xd4, 0x6c, 0x7f, 0x33, 0x3a, 0x2f, 0x2a, 0x2e, 0x73, 0xf9, 0x1d, 0xca,
    0x86, 0x24, 0x81, 0xb3, 0xc3, 0x07, 0x1a, 0xda, 0x57, 0xc0, 0x02, 0xab, 0x39, 0x4a, 0x18, 0x53,
    0x48, 0xd7, 0x75, 0x10, 0x8f, 0xce, 0xa5, 0xf2, 0x55, 0xec, 0xac, 0xf7, 0xdf, 0x5c, 0x6e, 0x03,
    0xbd, 0x98, 0x8a, 0x4f, 0x23, 0x63, 0xc7, 0x7b, 0x6d, 0x27, 0xd3, 0x9a, 0x52, 0x42, 0x66, 0x47,
    0xe1, 0x9f, 0xcd, 0x9c, 0x3a, 0x96, 0xf6, 0x78, 0x32, 0xce, 0xb2, 0xb8, 0xce, 0xe1, 0xfa, 0x43,
    0x17, 0xfe, 0xb0, 0x2b, 0x99, 0x9d, 0x7c, 0x38, 0x69, 0x0b, 0x34, 0x69,
  ]),
};

/**
 * Per-cipher canonical default IV, for the ciphers whose IV has internal
 * structure that the generic `defaultIvOfWidth` ascending pattern would get
 * wrong.
 *
 * `Partial` on purpose: **absence is the normal case.** For CBC, CFB and OFB
 * the IV is an opaque block with no meaningful interior, so
 * `defaultIvOfWidth(n)`'s `00 01 02 …` is as good as any value and the store
 * needs no per-cipher knowledge.
 *
 * ChaCha20 is the exception, and the reason this table exists. Its 16 IV bytes
 * are a 32-bit LITTLE-ENDIAN block counter followed by a 12-byte nonce, so the
 * generic default would set the counter to `0x03020100` — a legal value that
 * encrypts and decrypts perfectly consistently, and reproduces no published
 * test vector at all. RFC 8439's worked examples all start the counter at 1,
 * and an initial-counter off-by-one is the classic ChaCha bug precisely
 * because nothing about the output looks wrong.
 */
export const DEFAULT_IV_BYTES_BY_CIPHER: Partial<Record<Cipher, Uint8Array>> = {
  // RFC 8439 §2.4.2: counter = 1 (little-endian), nonce = 00…00 4a 00 00 00 00.
  chacha20: new Uint8Array([
    // counter = 1, little-endian
    0x01, 0x00, 0x00, 0x00,
    // 96-bit nonce
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
  ]),
  // Salsa20's 16 IV bytes are also a counter followed by a nonce, but split
  // 8/8 rather than ChaCha20's 4/12 — so the generic `defaultIvOfWidth` would
  // start the counter at 0x0706050403020100 and reproduce no published vector.
  //
  // The counter starts at 0 here, NOT at 1. That is the opposite of ChaCha20's
  // row directly above, and it is deliberate: RFC 8439's worked examples start
  // at 1, but standard Salsa20 implementations — including the pycryptodome
  // that generated every vector in `tests/salsa20-kat.test.ts` — start at 0 and
  // offer no API to start elsewhere. Carrying ChaCha20's convention across
  // would silently decouple this cipher from its only oracle.
  salsa20: new Uint8Array([
    // counter = 0, little-endian, 64 bits wide
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 64-bit nonce — eSTREAM Set 6, vector 0
    0x0d, 0x74, 0xdb, 0x42, 0xa9, 0x10, 0x77, 0xde,
  ]),
};

/**
 * Caption naming the internal split of a structured IV, for the ciphers that
 * have one.
 *
 * Both stream ciphers pack a counter and a nonce into the same 16-byte IV
 * field, and **they disagree about where the boundary is** — ChaCha20 splits
 * 4/12 with the counter starting at 1, Salsa20 splits 8/8 starting at 0. The
 * counter is precisely the part whose value silently changes the answer while
 * looking perfectly plausible, so a caption that named the wrong bytes would be
 * worse than none at all.
 *
 * This table exists because the caption was originally hardcoded to ChaCha20's
 * split behind a generic `isStreamCipher` gate — correct while there was one
 * stream cipher, and wrong in every particular the moment Salsa20 landed.
 */
export const IV_LAYOUT_CAPTION_BY_CIPHER: Partial<Record<Cipher, string>> = {
  chacha20: "bytes 0–3 = block counter (little-endian, starts at 1) · bytes 4–15 = 96-bit nonce",
  salsa20: "bytes 0–7 = block counter (little-endian, starts at 0) · bytes 8–15 = 64-bit nonce",
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
  cshake128: new Uint8Array(0), // cSHAKE is unkeyed (customization is spec data)
  cshake256: new Uint8Array(0),
  // KMAC is the FIRST keyed hash. Default = the NIST SP 800-185 sample key
  // (bytes 0x40..0x5F, 32 bytes) so the first Run reproduces a published tag.
  kmac128: new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i)),
  kmac256: new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i)),
  kmacxof128: new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i)),
  kmacxof256: new Uint8Array(Array.from({ length: 32 }, (_, i) => 0x40 + i)),
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
  // 00 01 02 03 — the NIST SP 800-185 cSHAKE sample data (with the default
  // S = "Email Signature" and output 32, the first Run reproduces Sample #1).
  cshake128: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
  cshake256: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
  // 00 01 02 03 — the NIST SP 800-185 KMAC sample message.
  kmac128: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
  kmac256: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
  kmacxof128: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
  kmacxof256: new Uint8Array([0x00, 0x01, 0x02, 0x03]),
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

// ─── PRNG defaults ─────────────────────────────────────────────────────────
//
// A generator is keyless in the symmetric sense — the seed is its only input,
// and it arrives through the plaintext field — so the key default is empty and
// the UI hides that field, exactly as it does for hashes and RSA.

/** Empty key per PRNG — generators have no symmetric key field. */
export const DEFAULT_KEY_BYTES_BY_PRNG: Record<Prng, Uint8Array> = {
  "minstd-rand0": new Uint8Array(0),
  "minstd-rand": new Uint8Array(0),
  "ansi-c-lcg": new Uint8Array(0),
  mt19937: new Uint8Array(0),
  "chacha20-csprng": new Uint8Array(0),
};

/**
 * Seed width in bytes, per generator.
 *
 * A generator's seed width is **not negotiable** the way a message length is:
 * the seed is bound straight into the generator's state, so bytes of the wrong
 * width do not produce an error, they produce a valid-looking stream from the
 * wrong starting point. `App.tsx` validates against this table at the input
 * boundary, where the problem can be named; the runtime would silently coerce.
 *
 * The three LCGs take one 32-bit word. The CSPRNG takes 32 bytes, because its
 * seed occupies ChaCha20's 256-bit key region — which is why this is a table
 * rather than the single `LCG_WORD_BYTES` constant the family shipped with.
 */
export const SEED_BYTES_BY_PRNG: Record<Prng, number> = {
  "minstd-rand0": 4,
  "minstd-rand": 4,
  "ansi-c-lcg": 4,
  // init_genrand takes a 32-bit seed, like the LCGs — the STATE is 624 words,
  // but the seed that selects it is one.
  mt19937: 4,
  "chacha20-csprng": 32,
};

/**
 * How much output one pass of a generator's loop produces — the `iterate`'s
 * `blockByteLength`, and therefore what the requested length is divided by to
 * get the iteration count.
 *
 * An LCG emits one 32-bit word per pass; the CSPRNG emits a whole 64-byte
 * ChaCha20 block. The output-length caption reads this so it can say "4 blocks
 * × 64 bytes" rather than mislabelling blocks as words.
 */
export const PRNG_UNIT_BYTES_BY_PRNG: Record<Prng, number> = {
  "minstd-rand0": 4,
  "minstd-rand": 4,
  "ansi-c-lcg": 4,
  mt19937: 4,
  "chacha20-csprng": 64,
};

/** What one pass of the loop is CALLED, for the same caption. */
export const PRNG_UNIT_NOUN_BY_PRNG: Record<Prng, string> = {
  "minstd-rand0": "word",
  "minstd-rand": "word",
  "ansi-c-lcg": "word",
  mt19937: "word",
  "chacha20-csprng": "block",
};

/**
 * Default seed per PRNG — **1**, as a 4-byte big-endian word.
 *
 * Not an arbitrary choice: 1 is `std::minstd_rand`'s `default_seed`, and it is
 * the seed under which ISO/IEC 14882 §rand.predef states the conformance value
 * both variants must produce. So the app's first Run on a generator reproduces a
 * published sequence — the same "first impression IS a test vector" property
 * AES-128 gets from FIPS-197 §C.1 and ChaCha20 from RFC 8439 §2.4.2.
 *
 * From this seed `minstd-rand0` opens 16807, 282475249, 1622650073, … — the most
 * widely republished fingerprint of the generator, and recognisable on sight to
 * anyone who has met it before.
 *
 * Seed 1 is the right default for the ANSI C variant too, and for the same
 * reason: `srand(1)` is what C guarantees an unseeded `rand()` behaves as, so
 * the opening states 1103527590, 377401575, 662824084, … are the ones a learner
 * will find quoted everywhere the sample generator is discussed.
 *
 * **MT19937 is the exception, and for the same underlying reason.** Its default
 * is 5489 rather than 1, because 5489 is `std::mt19937`'s `default_seed` — the
 * seed under which ISO/IEC 14882 §rand.predef states its conformance value. The
 * rule is "the seed that has a published vector", not "the number 1"; for three
 * of these generators those coincide, and for this one they do not.
 */
export const DEFAULT_PT_BYTES_BY_PRNG: Record<Prng, Uint8Array> = {
  "minstd-rand0": new Uint8Array([0x00, 0x00, 0x00, 0x01]),
  "minstd-rand": new Uint8Array([0x00, 0x00, 0x00, 0x01]),
  "ansi-c-lcg": new Uint8Array([0x00, 0x00, 0x00, 0x01]),
  // 5489 = 0x1571 — `std::mt19937`'s default_seed. The app's first paint
  // therefore opens `d0 91 bb 5c 22 ae 9e f6 …`, which is the published
  // sequence anyone who has printed MT19937's first outputs will recognise.
  mt19937: new Uint8Array([0x00, 0x00, 0x15, 0x71]),
  // All-zero, and for the same reason seed 1 is right for the LCGs: it is the
  // seed under which a published vector exists. With a zero seed (and this
  // generator's zero nonce and counter 0) the stream opens
  // `76 b8 e0 ad a0 f1 3d 90 …` — RFC 8439 Appendix A.1's first ChaCha20
  // block-function test vector. The app's first Run reproduces a standard.
  "chacha20-csprng": new Uint8Array(32),
};

// ─── Lattice defaults ──────────────────────────────────────────────────────
//
// The transform is keyless — it is a change of representation, not an
// encryption — so the key default is empty and the UI hides the field, the same
// posture the hash, RSA and PRNG families take.

/** Empty key per lattice variant — the transform has no key. */
export const DEFAULT_KEY_BYTES_BY_LATTICE: Record<Lattice, Uint8Array> = {
  "ntt-3329-256": new Uint8Array(0),
};

/**
 * Default polynomial: `f(X) = 0 + 1·X + 2·X² + … + 255·X²⁵⁵`, the sequential
 * house pattern AES and Serpent open on, and every coefficient safely below q.
 * It transforms into something with no visible structure, which is what makes
 * it worth looking at.
 *
 * **The input width is not negotiable here**, unlike a cipher's message. A ring
 * element is exactly 256 coefficients, so the polynomial is exactly 512 bytes;
 * anything else makes the first layer's block split meaningless and the runtime
 * throws. Same posture as `SEED_BYTES_BY_PRNG`.
 */
export const DEFAULT_PT_BYTES_BY_LATTICE: Record<Lattice, Uint8Array> = {
  "ntt-3329-256": DEFAULT_NTT_INPUT,
};

/**
 * Default *transformed* polynomial — the inverse direction's input, i.e. the
 * forward transform of the polynomial above. So landing in "inverse" mode and
 * running gives back the sequential coefficients, mirroring how a cipher's
 * decrypt default round-trips to its canonical plaintext.
 *
 * Computed by running the shipped forward spec rather than hand-derived, and
 * pinned by `tests/ntt-3329-256-kat.test.ts` so it cannot drift from the
 * implementation.
 */
export const DEFAULT_CT_BYTES_BY_LATTICE: Record<Lattice, Uint8Array> = {
  "ntt-3329-256": DEFAULT_NTT_OUTPUT,
};

/**
 * The input the field should hold when a lattice variant becomes active, given
 * the direction. Forward wants the polynomial; inverse wants its transform, so
 * the first run in that direction returns the polynomial rather than
 * transforming an already-untransformed value into 512 bytes of garbage.
 *
 * **Exported rather than inlined in `App.tsx` so a test can drive the real
 * rule.** `DEFAULT_CT_BYTES_BY_LATTICE` shipped for a few hours with no reader
 * at all, and the surface test asserted only its CONTENTS — which stays green
 * whether or not anything consumes it. RSA still has that hole
 * (`DEFAULT_CT_BYTES_BY_ASYMMETRIC` has no consumer); it matters less there
 * because its message is two bytes, and more here because nobody retypes 512
 * bytes of hex.
 *
 * The mode literal is spelled out rather than imported as `Mode` from
 * `stores/spec.ts`, which imports THIS module.
 */
export const latticeDefaultInput = (l: Lattice, mode: "encrypt" | "decrypt"): Uint8Array =>
  mode === "decrypt" ? DEFAULT_CT_BYTES_BY_LATTICE[l] : DEFAULT_PT_BYTES_BY_LATTICE[l];

/** Polynomial width in bytes, per lattice variant — the analogue of
 *  `SEED_BYTES_BY_PRNG`. A ring element is 256 coefficients × 2 bytes. */
export const INPUT_BYTES_BY_LATTICE: Record<Lattice, number> = {
  "ntt-3329-256": POLY_BYTES,
};

/** Test-only reset; production code never calls this. */
export const __resetCipherForTests = (): void => {
  setCipherSignal("aes-128");
  setHashSignal("sha-256");
  setAsymmetricSignal("rsa");
  setPrngSignal("minstd-rand0");
  setLatticeSignal("ntt-3329-256");
  setCategorySignal("cipher");
};
