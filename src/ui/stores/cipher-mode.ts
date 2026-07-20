/**
 * Cipher-mode store. Holds which block-cipher mode of operation the active
 * AES spec runs in:
 *
 *   "single-block" — today's path; the input is exactly one 16-byte block
 *                    and the canonical FIPS-197 spec runs as-is. Selected
 *                    by default on fresh load so the first impression
 *                    remains the FIPS-197 Appendix C.1 round-by-round demo.
 *   "ecb"          — multi-block, no chaining. Each block encrypts
 *                    independently. The "what NOT to do" baseline.
 *   "cbc"          — multi-block with IV-driven block chaining. Phase 2.
 *   "ctr"          — keystream from encrypting a counter block, XORed with
 *                    the message. Runs the FORWARD cipher in both
 *                    directions (XOR is its own inverse), so decrypt never
 *                    invokes the inverse body. A stream mode: it accepts any
 *                    message length ≥ 1 and engages no padding at all.
 *   "cfb"          — keystream from encrypting a feedback register that holds
 *                    the previous CIPHERTEXT block. Half CTR (forward cipher
 *                    only, XOR, no padding), half CBC (serially dependent
 *                    blocks) — see `src/ciphers/modes/cfb.ts`.
 *   "ofb"          — CFB's shape with CTR's symmetry: the register is refilled
 *                    from the cipher's OWN OUTPUT, so the keystream depends
 *                    only on key + IV. Precomputable, not seekable, and the
 *                    only mode with zero error propagation — see
 *                    `src/ciphers/modes/ofb.ts`.
 *
 * Orthogonal to:
 *   - direction ("encrypt"/"decrypt"), held by stores/spec.ts
 *   - cipher variant ("aes-128"/etc.), held by stores/cipher.ts
 *   - padding scheme, held by stores/padding.ts
 *   - IV bytes (Phase 2), held by stores/iv.ts
 *
 * The mode + cipher + direction triple selects one canonical spec from
 * the table in stores/spec.ts; padding overlay layers on top of that.
 *
 * Every block cipher in the app now has a `BlockCipherCore` and therefore runs
 * every mode. A cipher without one would support "single-block" only (the
 * cipher-mode <select> greys out), which is why the check still exists — it is
 * the gate the next cipher added will meet.
 *
 * Session-only (2026-05-19): not persisted in localStorage. Refresh resets
 * to "single-block". See the matching note in cipher.ts — both selectors
 * were demoted to session-scope together so refresh equals a clean slate
 * (matching the inputs, which were never persisted either) instead of
 * leaving a half-persistent UI state on reload.
 */

import { createSignal } from "solid-js";
import type { Cipher } from "./cipher";

export type CipherMode = "single-block" | "ecb" | "cbc" | "ctr" | "cfb" | "ofb" | "stream";

// All four SP 800-38A confidentiality modes ship, alongside single-block. ECB
// and CBC arrived with the cipher-agnostic mode machine; CTR followed, built
// from the same `BlockCipherCore` contract with no changes to it — the contract
// was designed against CTR precisely so that third mode would cost one file.
// CFB was cheaper still: it needed no new step type at all, reusing CTR's
// keystream leaves and CBC's feedback asymmetry. OFB is cheaper again — CFB's
// wiring with one wire moved and the direction branch DELETED, and it needed no
// new predicate either, only a fifth arm on the two CFB extracted.
// "stream" is the odd one out and deliberately so. The other six are modes of
// OPERATION — rules for repeating a block cipher over a long message, any of
// which can be applied to any core. "stream" is not a rule applied to a cipher;
// it is what a cipher that generates its own keystream (ChaCha20) already is.
// It exists as a `CipherMode` rather than as a per-cipher predicate because
// every downstream question — does this pad? does it use an IV? — is already
// asked of the MODE at seven call sites. Adding an arm to two predicates is
// zero new sites; a parallel `isStreamCipher(cipher)` OR'd in at all seven is
// seven chances to wire six of them and have the seventh fail silently.
export const SUPPORTED_CIPHER_MODES: readonly CipherMode[] = [
  "single-block",
  "ecb",
  "cbc",
  "ctr",
  "cfb",
  "ofb",
  "stream",
];

/**
 * Which (cipher, cipherMode) combinations have a concrete spec in
 * `stores/spec.ts`'s defaults table.
 *
 * Used both by the App's dropdown (to disable unsupported (cipher, mode)
 * options so the user can't pick a combo that silently falls back to
 * single-block) and by `setCipher` in spec.ts (to reset cipherMode when
 * the user switches to a cipher that doesn't support the active mode).
 *
 * If this drifts from the actual defaults table, the dropdown will lie —
 * keep them in sync when registering a new mode factory.
 * `tests/cipher-mode-fallback.test.ts` is the canary.
 */
export const SUPPORTED_CIPHER_MODES_BY_CIPHER: Readonly<Record<Cipher, readonly CipherMode[]>> = {
  // The AES variants: every one has a `BlockCipherCore`, and the generic mode
  // builders generate their ECB/CBC specs from it (`stores/spec.ts`).
  "aes-128": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  "aes-192": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  "aes-256": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // Blowfish — the first non-AES cipher with a core (Phase C), and the first
  // whose block is 8 bytes rather than 16.
  blowfish: ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // Serpent — an AES-shaped core (16-byte block, flat round groups between IP
  // and FP), three cores for one cipher's seed-threading work
  // (`src/ciphers/serpent-core.ts`).
  "serpent-128": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  "serpent-192": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  "serpent-256": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // Speck32/64 — the first core whose block is smaller than 8 bytes (4-byte
  // block, two byte conventions). `src/ciphers/speck-32-64-core.ts` — the
  // seed-threading was one binding (round 1's `state`), the rest of the round
  // chain and every param already flowed through the shared body builder.
  "speck-32-64-be": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  "speck-32-64-le": ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // DES — the first Feistel cipher, and the first core whose body nests a
  // port-mode group (the outer `rounds` group) inside the mode's iterate. Its
  // 8-byte block is Blowfish's, so this is breadth, not new block-size
  // coverage. `src/ciphers/des-core.ts` — the seed-threading was one binding
  // (the Initial Permutation leaf), the Serpent story rather than the Blowfish
  // one: B4 had already given every round a port-chained seed.
  des: ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // Twofish — the last cipher to gain modes, closing the `N + M` story: every
  // block cipher in the app now runs every mode. Its 16-byte block is AES's, so
  // this is breadth rather than block-size coverage; what it does add is the
  // mode machine over the app's most structurally unusual body (the 4-rail
  // round), nested a scope deeper inside the iterate. The seed-threading was one
  // binding — the input-whitening head — because every subkey already reached
  // its round through aux rather than a port edge into key setup.
  twofish: ["single-block", "ecb", "cbc", "ctr", "cfb", "ofb"],
  // ChaCha20 — the first cipher whose list does NOT include "single-block",
  // and the first with exactly one entry. It has no `BlockCipherCore`, so none
  // of the six modes of operation apply to it; and "single-block" would be a
  // lie in the persisted document, since a stream cipher has no block the
  // message must fit into. Anything that resolves a cipher's default mode must
  // therefore read this list rather than assume "single-block" exists.
  chacha20: ["stream"],
};

/**
 * Is this mode a **stream** mode — one that encrypts something other than the
 * message and XORs the result with it?
 *
 * CTR (encrypts a counter), CFB (encrypts a register holding the previous
 * ciphertext) and OFB (encrypts its own previous output). In all three, the
 * message meets only an XOR, so it never has to reach a block boundary: any
 * length ≥ 1 is legal, the ciphertext is exactly as long as the plaintext, and
 * **no padding overlay is spliced in at all**.
 *
 * That last consequence is why this is a shared predicate rather than an inline
 * check. A stream mode that padded would silently re-fill its final block, the
 * partial-block path would never run, and the mode would behave exactly like
 * the block modes it exists to contrast with — a bug that produces plausible
 * output and no error. The disengagement has to hold at every site that asks
 * about padding: `overlayBlockBytes` (stores/spec.ts), `paddingLimits`
 * (stores/padding.ts), and the App's padding selector.
 */
export const isStreamCipherMode = (mode: CipherMode): boolean =>
  mode === "ctr" || mode === "cfb" || mode === "ofb" || mode === "stream";

/**
 * Does this mode read `aux["iv"]`?
 *
 * True for every mode with a per-message starting value, whatever that value
 * *means*: CBC's chain bootstrap, CTR's initial counter block, CFB's initial
 * feedback register, OFB's initial output-feedback register. One aux slot and
 * one input field serve all four — the field's label and the mode's narration
 * carry the distinction.
 *
 * A predicate rather than three inline comparisons because the App checks this
 * in three places (seeding aux before a run, deciding whether a saved session
 * should carry an IV, and showing the IV input), and a mode added to two of the
 * three fails in ways no type check catches.
 */
export const cipherModeUsesIv = (mode: CipherMode): boolean =>
  mode === "cbc" ||
  mode === "ctr" ||
  mode === "cfb" ||
  mode === "ofb" ||
  // ChaCha20's IV is the only one with internal structure: a 32-bit
  // little-endian block counter followed by a 96-bit nonce. One aux slot and
  // one field still serve, as with the other four — the label carries the
  // distinction. See `DEFAULT_IV_BYTES_BY_CIPHER` in stores/cipher.ts.
  mode === "stream";

export const isCipherModeSupported = (cipher: Cipher, mode: CipherMode): boolean =>
  (SUPPORTED_CIPHER_MODES_BY_CIPHER[cipher] as readonly string[]).includes(mode);

/**
 * Is this cipher a stream cipher — one that generates a keystream itself and
 * therefore has no `BlockCipherCore` and no modes of operation?
 *
 * The ONE question that genuinely has to be asked of the cipher rather than the
 * mode, because it is asked *before* a mode is known: which mode should a
 * newly-selected cipher land in, and should the mode selector be enabled at
 * all. Everything downstream of "we are in mode X" is answered by
 * `isStreamCipherMode` instead — do not add call sites here that could ask that
 * one.
 */
export const isStreamCipher = (cipher: Cipher): boolean =>
  SUPPORTED_CIPHER_MODES_BY_CIPHER[cipher].includes("stream");

/**
 * The mode a cipher lands in when the active one isn't available to it — its
 * first supported mode.
 *
 * Every block cipher's list starts with "single-block", so this returns exactly
 * what the previously-hardcoded constant did for all eleven of them. ChaCha20
 * is the first cipher for which that constant would have been wrong: it has no
 * "single-block" entry, so a hardcoded fallback resolves to a spec that does
 * not exist and throws.
 */
export const defaultCipherModeFor = (cipher: Cipher): CipherMode =>
  SUPPORTED_CIPHER_MODES_BY_CIPHER[cipher][0] ?? "single-block";

/**
 * Is there actually a mode CHOICE to make for this cipher — i.e. should the
 * mode selector be interactive?
 *
 * Phrased as "more than one option" rather than "has a core", which is what
 * the App asked before ChaCha20 existed. The two agreed while every cipher was
 * a block cipher, and they disagree now in the right direction: ChaCha20's
 * selector still DISPLAYS "stream" (a disabled `<select>` shows its value), so
 * the user can see what the cipher is doing, but there is genuinely nothing to
 * pick and the control says so. The tooltip carries the reason.
 */
export const hasCipherModeChoice = (cipher: Cipher): boolean =>
  SUPPORTED_CIPHER_MODES_BY_CIPHER[cipher].length > 1;

// Default to single-block so the first impression remains the FIPS-197
// Appendix C.1 round-by-round demo. Session-only — see file header.
const [cipherMode, setCipherModeSignal] = createSignal<CipherMode>("single-block");

export const useCipherMode = () => cipherMode;

export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
};

/** Human-readable labels for the cipher-mode <select>. */
export const CIPHER_MODE_LABELS: Record<CipherMode, string> = {
  "single-block": "single block",
  ecb: "ECB",
  cbc: "CBC",
  ctr: "CTR",
  cfb: "CFB",
  ofb: "OFB",
  stream: "stream",
};

/** Test-only reset; production code uses setCipherMode. */
export const __resetCipherModeForTests = (): void => {
  setCipherModeSignal("single-block");
};
