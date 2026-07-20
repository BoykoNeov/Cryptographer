/**
 * Spec store. Holds the currently-displayed CipherSpec plus the UI
 * dimensions that select among the available canonical specs:
 *   • mode        — "encrypt" | "decrypt"
 *   • cipher      — "aes-128" | "aes-192" | "aes-256" | "speck-*"  (stores/cipher.ts)
 *   • cipherMode  — "single-block" | "ecb" | "cbc" | "ctr"          (stores/cipher-mode.ts)
 *
 * Together they pick from `defaults[cipher][cipherMode][mode]`. The padding
 * store is a fourth, orthogonal preference layered on TOP of the chosen
 * spec via `applyPaddingScheme`.
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 *
 * The coreless ciphers (DES, Twofish today) only support "single-block". The
 * defaults table records this with a partial inner record, and
 * `resolveDefault` falls back to single-block if a requested mode is
 * missing for the active cipher. That fallback lets the user pick "ECB"
 * for AES-128, then flip cipher to a coreless one without crashing — they
 * just land back in single-block on that side.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128CbcSpec } from "@/ciphers/aes-128-cbc";
import { aes128CbcDecryptSpec } from "@/ciphers/aes-128-cbc-decrypt";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { aesCore } from "@/ciphers/aes-core";
import type { BlockCipherCore } from "@/ciphers/block-cipher-core";
import { blowfishSpec } from "@/ciphers/blowfish";
import { blowfishCore } from "@/ciphers/blowfish-core";
import { blowfishDecryptSpec } from "@/ciphers/blowfish-decrypt";
import { chacha20DecryptSpec, chacha20EncryptSpec } from "@/ciphers/chacha20";
import { buildCshakeSpec, readCshakeCustomization } from "@/ciphers/cshake";
import { desSpec } from "@/ciphers/des";
import { desCore } from "@/ciphers/des-core";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import {
  type KmacVariant,
  buildKmacSpec,
  readKmacCustomization,
  readKmacKeyLength,
} from "@/ciphers/kmac";
import { buildCbcSpec } from "@/ciphers/modes/cbc";
import { buildCfbSpec } from "@/ciphers/modes/cfb";
import { buildCtrSpec } from "@/ciphers/modes/ctr";
import { buildEcbSpec } from "@/ciphers/modes/ecb";
import { buildOfbSpec } from "@/ciphers/modes/ofb";
import { rsaDecryptSpec, rsaEncryptSpec } from "@/ciphers/rsa";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { serpentCore } from "@/ciphers/serpent-core";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { buildSha3256Spec } from "@/ciphers/sha3-256";
import { buildShakeSpec, readShakeOutputLength } from "@/ciphers/shake";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64Core } from "@/ciphers/speck-32-64-core";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import { twofishSpec } from "@/ciphers/twofish";
import { twofishCore } from "@/ciphers/twofish-core";
import { twofishDecryptSpec } from "@/ciphers/twofish-decrypt";
import type { CipherDocument } from "@/core/document";
import { resolvePortMap } from "@/core/port-projection";
import {
  type CompositeInsertAnchor,
  type PaddingScheme,
  applyPaddingScheme,
  cloneGroupWithFreshIds,
  collectSpecIds,
  duplicateRoundGroup,
  findStepAndParent,
  insertStepAfter,
  insertStepBefore,
  pickSeedBinding,
  prependChildToContainer,
  removeStep,
  setPortBinding,
  updateAllStepsByType,
  updateCipherConstant,
  updateStepParams,
} from "@/core/spec-mutations";
import type { CipherSpec, Json, PortBinding, StepGroup, StepLeaf, StepNode } from "@/core/types";
import { batch, createSignal } from "solid-js";
import { blockByteLengthFor } from "./block-cipher-cores";
import {
  type Algorithm,
  type Asymmetric,
  type Cipher,
  type Hash,
  isAsymmetric,
  isCipher,
  isHash,
  setAsymmetric as setAsymmetricSignal,
  setCategory as setCategorySignal,
  setCipher as setCipherSignal,
  setHash as setHashSignal,
  useCipher,
  useHash,
} from "./cipher";
import {
  type CipherMode,
  defaultCipherModeFor,
  isCipherModeSupported,
  isStreamCipherMode,
  setCipherMode as setCipherModeSignal,
  useCipherMode,
} from "./cipher-mode";
import { setByteFormat } from "./format";
import { setIvBytes } from "./iv";
import { renameSpecLayoutIds } from "./layout";
import { setPaddingScheme, usePaddingScheme } from "./padding";
import { registry } from "./registry";

// ─── Mode ────────────────────────────────────────────────────────────────

export type Mode = "encrypt" | "decrypt";

/**
 * Generate the ECB + CBC entries for a cipher from its `BlockCipherCore`.
 *
 * Every (cipher × mode × direction) combination is one call to a generic mode
 * builder, so a variant that already has a core costs a single line here. The
 * alternative — a `<cipher>-<mode>[-decrypt].ts` file per combination, the
 * pattern AES-128 predates this machine with — is 4 files per cipher per mode:
 * the N×M explosion `docs/plans/foamy-prancing-wren.md` exists to remove.
 *
 * AES-128 deliberately keeps its file constants below: ~35 modules import them
 * by name, and those tests compare against the table's spec by REFERENCE, so
 * regenerating it here would hand them a byte-identical but non-identical
 * object.
 */
const modesFromCore = (
  core: BlockCipherCore,
): Partial<Record<CipherMode, Record<Mode, CipherSpec>>> => ({
  ecb: { encrypt: buildEcbSpec(core, "encrypt"), decrypt: buildEcbSpec(core, "decrypt") },
  cbc: { encrypt: buildCbcSpec(core, "encrypt"), decrypt: buildCbcSpec(core, "decrypt") },
  ...ctrFromCore(core),
  ...cfbFromCore(core),
  ...ofbFromCore(core),
});

/**
 * CTR alone, split out of `modesFromCore` for AES-128's sake.
 *
 * AES-128 keeps hand-authored ECB/CBC spec constants (see `modesFromCore`'s
 * note on reference equality), so it cannot spread `modesFromCore` — that
 * would regenerate and replace them. But AES-128 has no hand-authored CTR and
 * never will: CTR shipped after the mode machine, so there is no legacy file
 * to preserve. This helper lets AES-128 take the generic CTR while keeping its
 * grandfathered ECB/CBC constants intact.
 *
 * Both directions are structurally identical specs (CTR runs the forward
 * cipher either way) — they differ only in id, name, and narration prose.
 */
const ctrFromCore = (
  core: BlockCipherCore,
): Partial<Record<CipherMode, Record<Mode, CipherSpec>>> => ({
  ctr: { encrypt: buildCtrSpec(core, "encrypt"), decrypt: buildCtrSpec(core, "decrypt") },
});

/**
 * CFB alone, split out for the same reason as `ctrFromCore` — AES-128 must be
 * able to take it without regenerating its grandfathered ECB/CBC constants.
 *
 * Unlike CTR, the two directions are NOT structurally identical specs: both run
 * the forward cipher, but they differ in which port refills the feedback
 * register (see `src/ciphers/modes/cfb.ts`).
 */
const cfbFromCore = (
  core: BlockCipherCore,
): Partial<Record<CipherMode, Record<Mode, CipherSpec>>> => ({
  cfb: { encrypt: buildCfbSpec(core, "encrypt"), decrypt: buildCfbSpec(core, "decrypt") },
});

/**
 * OFB alone, split out for the same reason as `ctrFromCore` / `cfbFromCore` —
 * AES-128 must be able to take it without regenerating its grandfathered
 * ECB/CBC constants.
 *
 * Like CTR (and unlike CFB), the two directions are structurally IDENTICAL
 * specs: OFB's register is refilled from the cipher's own output, which is
 * message-independent, so nothing about the wiring flips with direction. Both
 * are still built, because they carry different ids, names, and prose.
 */
const ofbFromCore = (
  core: BlockCipherCore,
): Partial<Record<CipherMode, Record<Mode, CipherSpec>>> => ({
  ofb: { encrypt: buildOfbSpec(core, "encrypt"), decrypt: buildOfbSpec(core, "decrypt") },
});

// 3D table of canonical specs: defaults[cipher][cipherMode][mode]. The inner
// per-cipherMode record is partial — only ciphers with a `BlockCipherCore`
// carry ECB/CBC entries; the rest are single-block only.
const defaults: Record<Cipher, Partial<Record<CipherMode, Record<Mode, CipherSpec>>>> = {
  "aes-128": {
    "single-block": { encrypt: aes128Spec, decrypt: aes128DecryptSpec },
    ecb: { encrypt: aes128EcbSpec, decrypt: aes128EcbDecryptSpec },
    cbc: { encrypt: aes128CbcSpec, decrypt: aes128CbcDecryptSpec },
    // CTR postdates the mode machine, so there is no hand-authored AES-128 CTR
    // file to grandfather — it comes from the generic builder like every other
    // core's. See `ctrFromCore` on why this isn't a full `modesFromCore`.
    ...ctrFromCore(aesCore("aes-128")),
    // CFB likewise postdates the mode machine — same reasoning.
    ...cfbFromCore(aesCore("aes-128")),
    // OFB likewise postdates the mode machine — same reasoning.
    ...ofbFromCore(aesCore("aes-128")),
  },
  "aes-192": {
    "single-block": { encrypt: aes192Spec, decrypt: aes192DecryptSpec },
    ...modesFromCore(aesCore("aes-192")),
  },
  "aes-256": {
    "single-block": { encrypt: aes256Spec, decrypt: aes256DecryptSpec },
    ...modesFromCore(aesCore("aes-256")),
  },
  // Speck32/64 — the first core whose block is smaller than 8 bytes. Both byte
  // conventions gain ECB/CBC from `speck-32-64-core.ts` the same way AES-192/256
  // do: one `modesFromCore` line each, carrying the byte order.
  "speck-32-64-be": {
    "single-block": { encrypt: speck32_64BeSpec, decrypt: speck32_64BeDecryptSpec },
    ...modesFromCore(speck32_64Core("be-paper")),
  },
  "speck-32-64-le": {
    "single-block": { encrypt: speck32_64LeSpec, decrypt: speck32_64LeDecryptSpec },
    ...modesFromCore(speck32_64Core("le-nsa")),
  },
  // Serpent — an AES-shaped core (16-byte block, flat round groups between IP
  // and FP). The three variants gain ECB/CBC from `serpent-core.ts` the same
  // way AES-192/256 do: one `modesFromCore` line each.
  "serpent-128": {
    "single-block": { encrypt: serpent128Spec, decrypt: serpent128DecryptSpec },
    ...modesFromCore(serpentCore(16)),
  },
  "serpent-192": {
    "single-block": { encrypt: serpent192Spec, decrypt: serpent192DecryptSpec },
    ...modesFromCore(serpentCore(24)),
  },
  "serpent-256": {
    "single-block": { encrypt: serpent256Spec, decrypt: serpent256DecryptSpec },
    ...modesFromCore(serpentCore(32)),
  },
  // DES — first Feistel cipher (Phase 4 of `docs/plans/des-feistel.md`), and
  // the first core whose body nests a port-mode group (the outer `rounds`
  // group) inside the mode's iterate. Its 8-byte block is Blowfish's, so the
  // modes gain breadth here rather than new block-size coverage.
  des: {
    "single-block": { encrypt: desSpec, decrypt: desDecryptSpec },
    ...modesFromCore(desCore()),
  },
  // Blowfish — second Feistel cipher (`docs/plans/blowfish.md`); decrypt is the
  // same network with the P-array reversed. The first NON-AES cipher to gain
  // ECB/CBC, and the first whose 8-byte block exercises the block-size-generic
  // mode machine for real (Phase C of `docs/plans/foamy-prancing-wren.md`).
  blowfish: {
    "single-block": { encrypt: blowfishSpec, decrypt: blowfishDecryptSpec },
    ...modesFromCore(blowfishCore()),
  },
  // Twofish — third Feistel cipher (`docs/plans/twofish.md`), and the LAST
  // cipher to gain modes: with this row every block cipher in the app runs every
  // mode. Decrypt runs the same network with inverted rotations, reversed subkey
  // order, and swapped whitening.
  twofish: {
    "single-block": { encrypt: twofishSpec, decrypt: twofishDecryptSpec },
    ...modesFromCore(twofishCore),
  },
  // ChaCha20 — the only row with no "single-block" entry and no
  // `modesFromCore` spread, because there is no core. Its single "stream"
  // entry is the whole cipher: the block-repetition rule the other rows get
  // from a mode builder is already inside ChaCha20's own spec.
  chacha20: {
    stream: { encrypt: chacha20EncryptSpec, decrypt: chacha20DecryptSpec },
  },
};

/**
 * Pick the right canonical spec for the active (cipher, cipherMode, mode)
 * triple, falling back to single-block when the requested cipherMode isn't
 * registered for the cipher. The fallback keeps the UI from crashing when
 * the user switches cipher to one that doesn't support the active mode
 * (e.g. AES-128/ECB → Speck/ECB).
 */
const resolveDefault = (cipher: Cipher, cipherMode: CipherMode, mode: Mode): CipherSpec => {
  const byMode = defaults[cipher];
  // The fallback is the cipher's FIRST supported mode, not a hardcoded
  // "single-block". For all eleven block ciphers those are the same thing.
  // ChaCha20 is the first cipher for which they differ — it has no
  // single-block entry at all, and the old constant resolved to `undefined`
  // and threw the moment the user selected it while another mode was active.
  const forCipherMode = byMode[cipherMode] ?? byMode[defaultCipherModeFor(cipher)];
  if (!forCipherMode) {
    throw new Error(`No spec registered for cipher=${cipher}`);
  }
  return forCipherMode[mode];
};

/**
 * Canonical-spec table for hashes — sibling of `defaults` above. Slice 2.10b
 * of `docs/plans/universal-port-dataflow.md` introduces this table; today
 * SHA-256 is the only entry. Hash specs have no encrypt/decrypt direction
 * and no cipher-mode dimension (no block-cipher modes of operation), so
 * the table is keyed by `Hash` directly — flat compared to the cipher
 * `defaults` table's three-axis structure.
 *
 * Specs are built eagerly at module load (one call per registered hash),
 * matching the cipher tables. SHA-256's builder constructs ~1800+ leaves;
 * the cost is one-shot, paid before first paint.
 */
// ─── SHAKE output length (editable XOF digest length) ─────────────────────
//
// SHAKE is a variable-length XOF: its output length is spec DATA (it changes
// how many squeeze blocks run and the digest bytes, and travels via Save /
// Share), so it is captured structurally in the built spec. This signal is the
// "currently desired length" input the store rebuilds SHAKE specs from —
// exactly analogous to how the `cipherMode` signal parameterizes
// `buildCanonicalPair`. Fixed-digest hashes (SHA-256 / SHA3-256) ignore it.

/** Legibility ceiling on the SHAKE output length: 512 bytes ⇒ up to 4 squeeze
 *  blocks (3 extra Keccak-f permutations) — headroom above the default to show
 *  the loop growing, well under SHA-256's leaf count. */
export const MAX_SHAKE_OUTPUT = 512;
/** Default SHAKE output length: 200 bytes ⇒ 2 squeeze blocks for BOTH variants
 *  (rate 168 and 136), so the squeeze loop is visible on first paint. */
export const DEFAULT_SHAKE_OUTPUT = 200;

const [shakeOutputLength, setShakeOutputLengthSignal] = createSignal(DEFAULT_SHAKE_OUTPUT);
/** Accessor for the current SHAKE output length (the UI stepper reads this).
 *  Shared by every XOF variant — SHAKE and cSHAKE. */
export const useShakeOutputLength = (): (() => number) => shakeOutputLength;

// ─── cSHAKE customization strings (editable spec DATA) ────────────────────
//
// cSHAKE binds two byte strings — a function-name N (reserved for NIST-defined
// functions; empty for direct use) and a user customization string S — into the
// sponge prefix. Like the SHAKE output length, these are spec DATA (they change
// the encode_string/bytepad prefix bytes and the digest, and travel via Save /
// Share as constant-load params), so the store rebuilds the cSHAKE spec from
// these "currently desired" signals. Held as text; UTF-8-encoded at build.

/** Default cSHAKE customization: N empty (direct use), S the NIST sample string
 *  — so the first Run at output 32 reproduces SP 800-185 cSHAKE Sample #1. */
export const DEFAULT_CSHAKE_N = "";
export const DEFAULT_CSHAKE_S = "Email Signature";

const [cshakeN, setCshakeNSignal] = createSignal(DEFAULT_CSHAKE_N);
const [cshakeS, setCshakeSSignal] = createSignal(DEFAULT_CSHAKE_S);
/** Accessors for the current cSHAKE customization strings (the UI reads these). */
export const useCshakeN = (): (() => string) => cshakeN;
export const useCshakeS = (): (() => string) => cshakeS;

/** Default KMAC customization: empty S (the NIST sample #1 case). Only S is the
 *  user's — KMAC's function name N is the fixed "KMAC". */
export const DEFAULT_KMAC_S = "";
const [kmacS, setKmacSSignal] = createSignal(DEFAULT_KMAC_S);
/** Accessor for the current KMAC customization string (the UI reads this). */
export const useKmacS = (): (() => string) => kmacS;

// ─── KMAC key length (variable; DERIVED from the key field) ────────────────
//
// Unlike SHAKE's output length, KMAC's key length is not an independent knob —
// it is DERIVED from the key the user types (Option A: the key is the source of
// truth). But the store still needs a mirror signal, because `resolveHashDefault`
// / `buildCanonicalHash` build the KMAC spec (declaring `inputs.key.byteLength`,
// the `key.load` aux-read width, and `encode_string(K)`'s bit-length prefix)
// WITHOUT visibility into the App-local key field. The App keeps this signal in
// lockstep with the key field: it commits a new length on the field's blur, and
// the Run path resyncs defensively so an uncommitted edit can't run a
// stale-length spec (which the runtime would silently coerce into a WRONG MAC).

/** Default KMAC key length in bytes — the NIST SP 800-185 sample key size. */
export const DEFAULT_KMAC_KEY_LENGTH = 32;
/** Upper bound on the KMAC key length, for trace legibility (SP 800-185 itself
 *  places no bound). Mirrors `MAX_SHAKE_OUTPUT`'s role. */
export const MAX_KMAC_KEY_LENGTH = 512;
const [kmacKeyLength, setKmacKeyLengthSignal] = createSignal(DEFAULT_KMAC_KEY_LENGTH);
/** Accessor for the current KMAC key length (the store's mirror of the key
 *  field's byte length; consumed by `resolveHashDefault`). */
export const useKmacKeyLength = (): (() => number) => kmacKeyLength;
/** Clamp a proposed key length into `[1, MAX_KMAC_KEY_LENGTH]`. Min 1 because
 *  `aux-load-bytes@1` rejects `byteLength < 1` and the key field only shows when
 *  `inputs.key.byteLength > 0`. */
const clampKmacKeyLength = (n: number): number =>
  Math.max(1, Math.min(MAX_KMAC_KEY_LENGTH, Math.floor(n)));

const hashDefaults: Record<
  Exclude<
    Hash,
    | "shake128"
    | "shake256"
    | "cshake128"
    | "cshake256"
    | "kmac128"
    | "kmac256"
    | "kmacxof128"
    | "kmacxof256"
  >,
  CipherSpec
> = {
  "sha-256": buildSha256Spec(),
  "sha3-256": buildSha3256Spec(),
};

/**
 * Pick the canonical hash spec for a `Hash` variant. Mirrors
 * `resolveDefault` for ciphers — kept separate because the (mode,
 * cipherMode, padding) axes don't apply to hashes.
 *
 * SHAKE variants are built ON DEMAND at the current `shakeOutputLength()`
 * rather than cached in `hashDefaults`, because their canonical shape depends
 * on the editable output length. Reading the signal here makes every consumer
 * that calls `resolveHashDefault` (`isCustomSpec`, `resetSpec`) reactive to
 * length changes, and keeps the signal + the active spec in lockstep so a pure
 * length change reads "not custom".
 */
const resolveHashDefault = (hash: Hash): CipherSpec => {
  if (hash === "shake128" || hash === "shake256") {
    return buildShakeSpec(hash, shakeOutputLength());
  }
  if (hash === "cshake128" || hash === "cshake256") {
    const utf8 = new TextEncoder();
    return buildCshakeSpec(
      hash,
      utf8.encode(cshakeN()),
      utf8.encode(cshakeS()),
      shakeOutputLength(),
    );
  }
  if (isKmacHash(hash)) {
    return buildKmacSpec(
      hash,
      new TextEncoder().encode(kmacS()),
      shakeOutputLength(),
      kmacKeyLength(),
    );
  }
  return hashDefaults[hash];
};

/** True when a `Hash` is a KMAC variant (keyed; editable S; output length is the
 *  committed tag length — or arbitrary for the XOF variants). Type predicate so
 *  `resolveHashDefault` can narrow the hash to `KmacVariant`. */
export const isKmacHash = (h: Hash): h is KmacVariant =>
  h === "kmac128" || h === "kmac256" || h === "kmacxof128" || h === "kmacxof256";

/** True when a `Hash`'s output length is editable via the shared
 *  `shakeOutputLength` signal — every XOF-length variant (SHAKE, cSHAKE, and
 *  KMAC, whose output length is the committed tag length). */
export const isXofHash = (h: Hash): boolean =>
  h === "shake128" || h === "shake256" || h === "cshake128" || h === "cshake256" || isKmacHash(h);

/** True when a `Hash` is a cSHAKE variant (has editable customization strings). */
export const isCshakeHash = (h: Hash): boolean => h === "cshake128" || h === "cshake256";

/**
 * Canonical-spec table for asymmetric (public-key) algorithms — sibling of
 * `defaults` / `hashDefaults`. RSA is the only entry today
 * (`docs/plans/shimmying-booping-moth.md`). Asymmetric algorithms have
 * encrypt/decrypt directions (so the inner shape mirrors a cipher's mode pair)
 * but NO cipher-mode or padding axes — those are symmetric-block concepts — so
 * the table is keyed by `Asymmetric` × `Mode` directly, flat compared to the
 * cipher `defaults` table's three-axis structure.
 */
const asymmetricDefaults: Record<Asymmetric, Record<Mode, CipherSpec>> = {
  rsa: { encrypt: rsaEncryptSpec, decrypt: rsaDecryptSpec },
};

/** Pick the canonical asymmetric spec for an `(asymmetric, mode)` pair.
 *  Mirrors `resolveDefault` / `resolveHashDefault`; no cipherMode/padding. */
const resolveAsymmetricDefault = (a: Asymmetric, mode: Mode): CipherSpec =>
  asymmetricDefaults[a][mode];

// ─── Signals ─────────────────────────────────────────────────────────────
//
// Two-spec store: encrypt and decrypt are held simultaneously, in
// independent slots. Phase 4 of docs/plans/duplicate-round.md introduced
// this shape so the auto-mirror feature can write to both slots in one
// shot (`duplicateRoundInSpec` below) and so flipping mode preserves
// each side's customizations.
//
// Public surface stays compatible: `useSpec()` still returns an accessor
// for the currently active mode's spec. Behavior change worth noting:
// `setMode` no longer resets the spec to canonical — it just flips the
// active slot. `setCipher` / `setCipherMode` rebuild BOTH slots from
// canonical (a cipher swap is a clean break).

/**
 * Slice 2.10a (2026-05-25) widened `SpecsByMode` from
 * `{encrypt, decrypt}` to a discriminated union so the store can carry a
 * hash-shaped spec (single, direction-agnostic) alongside cipher-shaped
 * specs (encrypt + decrypt slots). The widening lands in 2.10a as type
 * scaffolding only — `buildCanonicalPair` always constructs the `cipher`
 * variant; the `hash` branch is exercised only in 2.10b once
 * `hashDefaults` lands. Every consumer (`activeSpec`, `updateActive`,
 * `updateBoth`, cross-mode mirror setters, `isCustomSpec`, `resetSpec`,
 * `setSpecFromDocument`) pattern-matches on `.kind` so the type system
 * forces them to consciously handle both shapes.
 *
 * Why two-variant rather than `{encrypt: T, decrypt?: T}`: the optional-
 * decrypt shape conflates "cipher whose decrypt hasn't been built yet"
 * (transient, never shipped) with "hash that has no decrypt by design"
 * (the actual semantic). The discriminated union names the distinction.
 */
type CipherSpecsByMode = {
  readonly kind: "cipher";
  readonly encrypt: CipherSpec;
  readonly decrypt: CipherSpec;
};

/**
 * Hash-shape SpecsByMode. The `hash: Hash` field is the load-bearing
 * discriminant for `resetSpec` and `isCustomSpec`: those operations need
 * to know WHICH hash variant the active spec is so they can look up the
 * canonical default from `hashDefaults`. Without it, the only other
 * way to recover the identity would be string-matching `single.id` —
 * fragile and indirect. The variant is intrinsic to the discriminated
 * union, just like `kind`.
 *
 * 2.10c will wire an `algorithm` signal that the UI selector reads/writes;
 * this field is the bridge that keeps store reads honest in the meantime.
 */
type HashSpecsByMode = {
  readonly kind: "hash";
  readonly hash: Hash;
  readonly single: CipherSpec;
};

/**
 * Asymmetric-shape SpecsByMode (RSA). Like the cipher shape it carries
 * encrypt + decrypt slots (asymmetric algorithms have a direction), and like
 * the hash shape it carries an `asymmetric: Asymmetric` discriminant so
 * `resetSpec` / `isCustomSpec` / `setSpecFromDocument` can recover WHICH
 * variant the active spec is for the canonical-default lookup. No cipherMode /
 * padding axes apply.
 *
 * Kept a DISTINCT kind from `cipher` (rather than reusing it) because every
 * `cipher`-branch consumer calls `resolveDefault(useCipher()(), …)`, a
 * `Cipher`-keyed lookup that an asymmetric variant would crash. The separate
 * kind makes the type system force each `.kind` site to handle RSA
 * consciously; the cross-mode-mirror guards (`kind !== "cipher"`) already
 * throw for it, exactly like the hash guards.
 */
type AsymmetricSpecsByMode = {
  readonly kind: "asymmetric";
  readonly asymmetric: Asymmetric;
  readonly encrypt: CipherSpec;
  readonly decrypt: CipherSpec;
};

export type SpecsByMode = CipherSpecsByMode | HashSpecsByMode | AsymmetricSpecsByMode;

/**
 * The block width to hand `applyPaddingScheme` — i.e. "should the padding
 * overlay engage here, and at what width?". **Every** call site that builds or
 * rebuilds a cipher spec must route through this rather than calling
 * `blockByteLengthFor` directly, because there are two independent reasons the
 * answer is "don't engage":
 *
 *  1. **No `BlockCipherCore`** (Twofish today) — the overlay has no width to
 *     wire itself in at. This is the original reason the parameter is optional.
 *  2. **CTR or CFB, whatever the cipher** — both are stream modes and need no
 *     padding at all. A pad step spliced into such a spec would re-fill the
 *     final block, so the partial-block path would silently never run and the
 *     mode would behave exactly like the block modes it differs from.
 *
 * Both are expressed as "no block width", which reuses `overlayApplies`'s
 * existing "no width ⇒ no overlay" semantics rather than adding a second gate
 * inside `applyPaddingScheme`.
 *
 * **This helper exists because the five call sites are easy to miss.** The CTR
 * rule originally landed in `buildCanonicalPair` alone, and browser smoke
 * immediately found the gap: `setPadding` recomputed the width independently,
 * so selecting a scheme while CTR was active still padded the message. The
 * other three (`setSpecFromDocument`, `resetSpec`, `isCustomSpec`) had the same
 * shape. Funnelling them through one function is what stops the next such rule
 * from having to be remembered five times.
 */
const overlayBlockBytes = (cipher: Cipher, cipherMode: CipherMode): number | undefined =>
  isStreamCipherMode(cipherMode) ? undefined : blockByteLengthFor(cipher);

const buildCanonicalPair = (
  cipher: Cipher,
  cipherMode: CipherMode,
  scheme: PaddingScheme,
): SpecsByMode => {
  const blockBytes = overlayBlockBytes(cipher, cipherMode);
  return {
    kind: "cipher",
    encrypt: applyPaddingScheme(
      resolveDefault(cipher, cipherMode, "encrypt"),
      "encrypt",
      scheme,
      blockBytes,
    ),
    decrypt: applyPaddingScheme(
      resolveDefault(cipher, cipherMode, "decrypt"),
      "decrypt",
      scheme,
      blockBytes,
    ),
  };
};

/**
 * Sibling of `buildCanonicalPair` for hash variants. Slice 2.10b
 * (2026-05-25) introduces this; today only reachable via tests (the
 * production setters `setCipher` / `setCipherMode` / `setPadding`
 * always go through `buildCanonicalPair`). Slice 2.10c wires the
 * algorithm-selector path so the user can flip into a hash via the
 * dropdown.
 *
 * No (mode, cipherMode, padding) parameters — none apply to hashes.
 * The result carries the `hash` discriminant so downstream consumers
 * can identify the variant for `resetSpec` / `isCustomSpec` lookups.
 *
 * Exported so the planned 2.10c selector setter (and current
 * test helpers) can construct a hash-kind SpecsByMode without
 * reaching into private helpers.
 */
export const buildCanonicalHash = (hash: Hash): SpecsByMode => ({
  kind: "hash",
  hash,
  single: resolveHashDefault(hash),
});

/**
 * Sibling of `buildCanonicalPair` / `buildCanonicalHash` for asymmetric
 * variants. Builds both encrypt + decrypt slots from the canonical table; no
 * (cipherMode, padding) parameters apply. Carries the `asymmetric` discriminant
 * so downstream `.kind` consumers can identify the variant.
 */
export const buildCanonicalAsymmetric = (a: Asymmetric): SpecsByMode => ({
  kind: "asymmetric",
  asymmetric: a,
  encrypt: resolveAsymmetricDefault(a, "encrypt"),
  decrypt: resolveAsymmetricDefault(a, "decrypt"),
});

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
const [specs, setSpecs] = createSignal<SpecsByMode>(
  buildCanonicalPair(useCipher()(), useCipherMode()(), usePaddingScheme()()),
);

// Active-spec accessor — reads both signals so consumers tracking
// `useSpec()` re-render on mode flips AND on per-slot edits. For hash
// specs the mode signal is semantically meaningless (hashes have no
// direction) so we return the single slot regardless of `mode()`.
const activeSpec = (): CipherSpec => {
  const s = specs();
  if (s.kind === "hash") return s.single;
  // cipher + asymmetric both carry encrypt/decrypt slots indexed by mode.
  return s[mode()];
};

export const useMode = () => mode;
export const useSpec = () => activeSpec;

/**
 * Read-only access to both slots. Used by the Save/Load surface so a
 * future "save both modes' specs" flow has a clean read boundary; today
 * only the active slot ships in the document, but the two-slot store
 * makes a richer save trivial later.
 *
 * Returns the discriminated union — consumers pattern-match on `.kind`.
 * Test helpers that need a guaranteed cipher-shape can call
 * `useCipherSpecsByMode()` instead, which throws if the active spec is
 * a hash.
 */
export const useSpecsByMode = () => specs;

/**
 * Narrowed accessor — guarantees the cipher-kind shape, throws otherwise.
 * Cross-mode mirror tests + duplicate-round tests use this so they can
 * read `.encrypt` / `.decrypt` directly without per-call kind narrowing.
 *
 * Throws at call time (not at construction) so the accessor itself stays
 * cheap when the cipher kind is active; consumers that genuinely need
 * polymorphic handling should call `useSpecsByMode()` instead.
 */
export const useCipherSpecsByMode = (): (() => CipherSpecsByMode) => {
  return () => {
    const s = specs();
    if (s.kind !== "cipher") {
      throw new Error(
        "useCipherSpecsByMode: active spec is a hash; use useSpecsByMode for polymorphic access",
      );
    }
    return s;
  };
};

// Internal: replace only the active mode's slot. Used by edit helpers
// (params, palette inserts, deletes) so changes to one mode never leak
// into the other. For hash specs the single slot is the only target;
// `mode()` is ignored.
const updateActive = (updater: (s: CipherSpec) => CipherSpec): void => {
  const current = specs();
  if (current.kind === "hash") {
    const updated = updater(current.single);
    if (updated === current.single) return;
    // Preserve the hash discriminant — without it, `resetSpec` and
    // `isCustomSpec` would lose track of WHICH hash variant the active
    // spec is when the user customizes (e.g. edits a leaf's params).
    setSpecs({ kind: "hash", hash: current.hash, single: updated });
    return;
  }
  const m = mode();
  const prev = current[m];
  const updated = updater(prev);
  if (updated === prev) return; // reference-equal → no-op write
  if (current.kind === "asymmetric") {
    setSpecs(
      m === "encrypt"
        ? { ...current, encrypt: updated, decrypt: current.decrypt }
        : { ...current, encrypt: current.encrypt, decrypt: updated },
    );
    return;
  }
  setSpecs(
    m === "encrypt"
      ? { kind: "cipher", encrypt: updated, decrypt: current.decrypt }
      : { kind: "cipher", encrypt: current.encrypt, decrypt: updated },
  );
};

// Internal: replace both slots in one signal write. Used by selector
// changes that rebuild canonical (cipher / cipherMode / padding) and by
// duplicate-round's auto-mirror. For hash specs the updater is invoked
// once on `single` with `"encrypt"` as the direction argument — the only
// call sites that reach here for hashes are `setPadding` (no-op for
// hashes; padding overlay doesn't apply) and `duplicateRoundInSpec` (no-
// op for hashes; defensive throw upstream).
const updateBoth = (updater: (s: CipherSpec, m: Mode) => CipherSpec): void => {
  const current = specs();
  if (current.kind === "hash") {
    const updated = updater(current.single, "encrypt");
    if (updated === current.single) return;
    setSpecs({ kind: "hash", hash: current.hash, single: updated });
    return;
  }
  if (current.kind === "asymmetric") {
    // The only caller that reaches here for asymmetric is `setPadding`
    // (`applyPaddingScheme` is inert for non-AES specs — RSA has no overlay);
    // `duplicateRoundInSpec` throws upstream for non-cipher kinds. Apply to
    // both slots preserving the discriminant.
    setSpecs({
      ...current,
      encrypt: updater(current.encrypt, "encrypt"),
      decrypt: updater(current.decrypt, "decrypt"),
    });
    return;
  }
  setSpecs({
    kind: "cipher",
    encrypt: updater(current.encrypt, "encrypt"),
    decrypt: updater(current.decrypt, "decrypt"),
  });
};

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. With the two-spec store this is a
 * pure index flip — the OTHER slot keeps whatever the user last left in
 * it (e.g. customizations from a prior session-in-this-mode). Cipher and
 * cipherMode swaps still rebuild both slots from canonical; this setter
 * doesn't.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
};

/**
 * Switch the active cipher. Both slots rebuild from canonical for the
 * new cipher × current cipherMode pair, then re-apply the active padding
 * overlay. If the new cipher doesn't support the current cipherMode,
 * the cipherMode signal RESETs to "single-block" first (same rationale
 * as the prior single-spec version: keeps `paddingLimits` consistent
 * with what the spec can actually accept).
 *
 * Slice 2.10c (2026-05-25): also flips the category signal to "cipher"
 * defensively. The cipher dropdown UI is gated behind category=cipher in
 * the App so a user-facing call here is reachable only from the cipher
 * branch, but a test or programmatic caller may have left category in
 * "hash" — keeping the two in sync prevents a state where the live spec
 * is a cipher but `useAlgorithm()` reads from `hash()`.
 */
export const setCipher = (c: Cipher): void => {
  setCategorySignal("cipher");
  setCipherSignal(c);
  if (!isCipherModeSupported(c, useCipherMode()())) {
    // The new cipher's own default, not a constant: selecting ChaCha20 must
    // land in "stream" (its only mode), and selecting a block cipher while
    // ChaCha20's "stream" is active must land back in "single-block". A
    // hardcoded fallback got the first of those wrong.
    setCipherModeSignal(defaultCipherModeFor(c));
  }
  setSpecs(buildCanonicalPair(c, useCipherMode()(), usePaddingScheme()()));
};

/**
 * Switch the active hash variant (Slice 2.10c, 2026-05-25). Mirrors
 * `setCipher`'s shape but lands a `kind: "hash"` SpecsByMode instead of
 * a cipher pair. Flips the category signal to "hash" so `useAlgorithm()`
 * resolves to the new hash value.
 *
 * No cipherMode / padding axes apply to hashes; the existing signals are
 * left at their current values (UI hides those selectors when the hash
 * category is active, so they stay inert without semantic effect).
 */
export const setHash = (h: Hash): void => {
  setCategorySignal("hash");
  setHashSignal(h);
  setSpecs(buildCanonicalHash(h));
};

/**
 * Set the SHAKE output length and, when a SHAKE is the active hash, rebuild the
 * spec at the new length. Clamps to `[1, MAX_SHAKE_OUTPUT]`.
 *
 * This is a STRUCTURAL rebuild (via `setSpecs(buildCanonicalHash(...))`), not a
 * param edit: the output length changes how many `squeeze.perm.{j}` groups the
 * spec contains, which `editStepParams` cannot express. The signal and the
 * active spec move in lockstep, so `isCustomSpec` (which compares against
 * `resolveHashDefault`, itself built at `shakeOutputLength()`) reads "not
 * custom" after a pure length change and "custom" only after a real edit.
 *
 * No-op for non-SHAKE hashes / ciphers: the signal still updates (cheap) but no
 * rebuild happens, so switching TO a SHAKE later picks up the chosen length.
 */
export const setShakeOutputLength = (n: number): void => {
  const clamped = Math.max(1, Math.min(MAX_SHAKE_OUTPUT, Math.floor(n)));
  setShakeOutputLengthSignal(clamped);
  const active = useHash()();
  // Every XOF variant (SHAKE and cSHAKE) is rebuilt at the new length.
  if (isXofHash(active)) {
    setSpecs(buildCanonicalHash(active));
  }
};

/**
 * Set a cSHAKE customization string (`N` or `S`) and, when a cSHAKE is the
 * active hash, rebuild the spec. Like the SHAKE output length this is a
 * STRUCTURAL rebuild: the string's length changes the `encode_string` / `bytepad`
 * prefix bytes (and emptying BOTH N and S flips the domain byte back to SHAKE's
 * 0x1F), which `editStepParams` cannot express. No-op for non-cSHAKE hashes.
 */
export const setCshakeCustomization = (which: "N" | "S", value: string): void => {
  if (which === "N") setCshakeNSignal(value);
  else setCshakeSSignal(value);
  const active = useHash()();
  if (isCshakeHash(active)) {
    setSpecs(buildCanonicalHash(active));
  }
};

/**
 * Set the KMAC customization string `S` and, when a KMAC is the active hash,
 * rebuild the spec. Structural rebuild (same rationale as cSHAKE). No-op for
 * non-KMAC hashes. KMAC's function name `N` is the fixed "KMAC" — not editable.
 */
export const setKmacCustomization = (value: string): void => {
  setKmacSSignal(value);
  const active = useHash()();
  if (isKmacHash(active)) {
    setSpecs(buildCanonicalHash(active));
  }
};

/**
 * Set the KMAC key length (in bytes) and, when a KMAC is the active hash,
 * rebuild the spec at that length. STRUCTURAL rebuild (same rationale as the S
 * string / output length): the length changes `encode_string(K)`'s bit-length
 * prefix, the key bytepad block size, the `key.load` aux-read width, and the
 * declared `inputs.key.byteLength` — none of which `editStepParams` can express.
 * Clamped to `[1, MAX_KMAC_KEY_LENGTH]`. No-op rebuild for non-KMAC hashes.
 *
 * KMAC's key length is DERIVED from the key field (Option A), so the App calls
 * this from the field's commit and defensively from the Run path; the store just
 * keeps the mirror signal + spec in lockstep so `isCustomSpec` reads "not custom"
 * after a pure length change (it compares against `resolveHashDefault`, itself
 * built at `kmacKeyLength()`).
 */
export const setKmacKeyLength = (n: number): void => {
  setKmacKeyLengthSignal(clampKmacKeyLength(n));
  const active = useHash()();
  if (isKmacHash(active)) {
    setSpecs(buildCanonicalHash(active));
  }
};

/**
 * Switch the active asymmetric variant (RSA). Mirrors `setHash`'s shape but
 * lands a `kind: "asymmetric"` SpecsByMode (encrypt + decrypt slots). Flips
 * the category signal to "asymmetric" so `useAlgorithm()` resolves to the new
 * value. No cipherMode / padding axes apply; the UI hides those selectors and
 * the symmetric key field when the asymmetric category is active.
 */
export const setAsymmetric = (a: Asymmetric): void => {
  setCategorySignal("asymmetric");
  setAsymmetricSignal(a);
  setSpecs(buildCanonicalAsymmetric(a));
};

/**
 * Algorithm-level setter that routes to `setCipher` or `setHash`
 * depending on the category of the passed value. The single boundary
 * the App's algorithm-selector UI calls into so cross-category flips
 * (cipher ↔ hash) go through one place and the corresponding canonical
 * default lands in the spec store.
 *
 * Returns `void`; callers reading the post-call algorithm signal need to
 * use `useAlgorithm()`. Side effects: cipher/hash + category signals
 * updated, `specs` signal replaced with the new canonical, cipherMode
 * possibly demoted to "single-block" (cipher branch only).
 */
export const setAlgorithm = (a: Algorithm): void => {
  if (isHash(a)) {
    setHash(a);
  } else if (isAsymmetric(a)) {
    setAsymmetric(a);
  } else {
    setCipher(a);
  }
};

/**
 * Switch the block-cipher mode of operation. Both slots rebuild from
 * canonical so encrypt/decrypt stay coherent (the multi-block factory
 * builds the matching pair).
 */
export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
  setSpecs(buildCanonicalPair(useCipher()(), m, usePaddingScheme()()));
};

/**
 * Switch the padding scheme. Re-applies the overlay to BOTH slots — the
 * encrypt slot gets pad+load-block prepended, the decrypt slot gets
 * store-block+unpad appended. `applyPaddingScheme` is idempotent (strips
 * existing overlay before re-applying) so user edits to round leaves
 * survive.
 */
export const setPadding = (scheme: PaddingScheme): void => {
  setPaddingScheme(scheme);
  // The block size has to be resolved HERE, not inside the callback:
  // `updateBoth` hands the updater only `(spec, mode)`, and the spec alone
  // can't say how wide its cipher's block is.
  //
  // Gate on the union's `kind` rather than on `useCipher()()` alone — the
  // cipher signal keeps its value while a hash or RSA is active ("remember
  // last cipher"), so reading it unconditionally would hand a 16 to an RSA
  // spec and splice a pad into it. Only a `cipher`-kind spec has a block.
  const current = specs();
  const blockBytes =
    current.kind === "cipher" ? overlayBlockBytes(useCipher()(), useCipherMode()()) : undefined;
  updateBoth((s, m) => applyPaddingScheme(s, m, scheme, blockBytes));
};

/**
 * Edit one specific step's params. Writes to the ACTIVE mode's slot
 * only — edits don't leak across modes. Two-spec semantics: encrypt's
 * S-box change does not propagate to decrypt's S-box, by design.
 */
export const editStepParams = (stepId: string, params: Json): void => {
  updateActive((s) => updateStepParams(s, stepId, params));
};

/**
 * Rewire one input port on a leaf to a new upstream source (or clear it with
 * `null`) — the store boundary for the port-wiring editor (Phase 4d-bis).
 * Writes to the ACTIVE mode's slot only, same two-spec semantics as
 * `editStepParams`: a rewire in encrypt does NOT leak into decrypt (the user
 * edits each side independently and learns what breaks). The caller is
 * responsible for only passing SCOPE-LEGAL bindings (the UI sources them from
 * `legalSourcesForInput`), so a cross-scope binding that would throw at runtime
 * can never reach `setPortBinding`. Flows through `updateActive`, so the
 * App-level debounced `createEffect(on(spec, …))` re-runs the cipher and the
 * trace updates — no new rerun path. A no-op rewire (rebinding to the same
 * target, or clearing an already-unbound port) returns the spec by reference,
 * so `updateActive` skips the redundant re-run.
 */
export const bindPortInSpec = (
  stepId: string,
  portName: string,
  binding: PortBinding | null,
): void => {
  updateActive((s) => setPortBinding(s, stepId, portName, binding));
};

/**
 * Edit one published cipher constant's bytes (scaffolding-suppression A1).
 * Writes to the ACTIVE slot — for hashes that's the single slot; for
 * ciphers, encrypt/decrypt hold their constants independently (the same
 * never-auto-sync rule as step params). Goes through `updateActive`, so the
 * App-level debounced `createEffect(on(spec, …))` re-runs the cipher and the
 * edited constant re-materializes into aux for every consumer.
 */
export const editCipherConstant = (name: string, bytes: Uint8Array): void => {
  updateActive((s) => updateCipherConstant(s, name, bytes));
};

/**
 * Apply an update to every step of a given type IN THE ACTIVE SPEC.
 * Used for "swap the S-box across all 10 round SubBytes steps in one
 * click." The decrypt slot's S-boxes are not touched (in fact, decrypt
 * uses the INVERSE S-box — propagating verbatim would be wrong).
 */
export const editAllStepsByType = (stepType: string, update: (params: Json) => Json): void => {
  updateActive((s) => updateAllStepsByType(s, stepType, update));
};

/**
 * Cross-slot inverse mirror — the *value-mirror* counterpart of
 * `duplicateRoundInSpec`'s structural mirror.
 *
 * Today only one step type is value-inverse-mirrored: AES's generic
 * `byte-substitution`. Encrypt holds the forward table, decrypt holds
 * its inverse. The two are algebraic inverses, not equal — see the
 * comment on `editAllStepsByType` above, and FIPS-197 §5.3.2.
 *
 * Writes `invertedSbox` to every step of `stepType` in the
 * COUNTERPART slot (encrypt edits → decrypt slot; decrypt edits →
 * encrypt slot). The caller computes the inverted array (so this
 * module stays purely a store boundary). Mirrors `updateAllStepsByType`
 * semantics: writes uniformly to every matching step in the
 * counterpart slot, regardless of any per-step customizations
 * already there — destructive by design, same as Apply-to-all.
 *
 * **Role-scoping (`idFilter`).** Since the key-schedule decomposition
 * (2026-06-01) `byte-substitute@1` is used in TWO roles: round-body
 * SubBytes (this inverse mirror) AND key-schedule SubWord (which holds the
 * FORWARD table on both sides — FIPS-197 §5.2, handled by
 * `syncSboxCopyToCounterpart`). A type-wide broadcast would overwrite the
 * decrypt key schedule's forward S-box with the inverse table and corrupt
 * decryption. The caller passes `idFilter` (`isRoundBodyLeafId`) so the
 * inverse only lands on round-body leaves; the key-schedule SubWord leaves
 * are left untouched.
 */
export const syncSboxInverseToCounterpart = (
  stepType: string,
  invertedSbox: readonly number[],
  idFilter?: (id: string) => boolean,
): void => {
  const current = specs();
  // Cross-mode mirror is only meaningful for ciphers with separate
  // encrypt/decrypt directions; hash specs have no counterpart slot.
  // UI gestures triggering this are gated upstream by the cross-mode
  // mirror registry (cipher-only), so reaching here for a hash kind
  // surfaces a programming error rather than silently mutating.
  if (current.kind !== "cipher") {
    throw new Error("syncSboxInverseToCounterpart not supported for hash spec");
  }
  const counterpartMode: Mode = mode() === "encrypt" ? "decrypt" : "encrypt";
  const updated = updateAllStepsByType(
    current[counterpartMode],
    stepType,
    (params) => ({
      ...(params as Record<string, Json>),
      sbox: [...invertedSbox],
    }),
    idFilter,
  );
  if (updated === current[counterpartMode]) return; // reference-equal → no-op
  setSpecs(
    counterpartMode === "encrypt"
      ? { kind: "cipher", encrypt: updated, decrypt: current.decrypt }
      : { kind: "cipher", encrypt: current.encrypt, decrypt: updated },
  );
};

/**
 * Per-S-box-index variant of `syncSboxInverseToCounterpart`. Required for
 * ciphers like Serpent that cycle through **multiple distinct S-boxes**
 * across the rounds (Serpent uses 8 different 4-bit S-boxes — `S_0`..`S_7` —
 * with round `r` using `S_{(r-1) mod 8}` for forward encryption). Every
 * leaf in the encrypt spec carries its own `sboxIndex` (0..7) AND its own
 * 16-entry `sbox` table; the decrypt spec mirrors the structure with the
 * inverse tables, same indices.
 *
 * **Why a second mutator instead of extending the first**: the AES case
 * has one S-box reused across all rounds — broadcasting one inverted
 * table to every `generic.byte-substitution@1` leaf in the counterpart
 * slot is correct. The Serpent case has 8 different S-boxes — broadcasting
 * one inverted table to every `serpent.sub-bytes@1` leaf would overwrite
 * 28 of the 32 decrypt-side rounds with the wrong inverse. The two
 * verbs read as parallel siblings: "AES has one S-box, Serpent has
 * eight, and the Sync semantics differ accordingly."
 *
 * Filters by `params.sboxIndex === sboxIndex` inside the updater so
 * decrypt-side leaves whose `sboxIndex` doesn't match the edited leaf's
 * are returned by reference (no spec rebuild). The user's "edit S_3 in
 * encrypt → click Sync → only the S_3 inverse leaves on the decrypt
 * side update" semantic is the pedagogical hook.
 *
 * **Not solved this slice (intentional, deferred):**
 *   - Within-encrypt S_x consistency. If the user edits `round.4.sub-bytes`
 *     (which uses S_3) and clicks Sync, encrypt rounds 12/20/28 (also S_3)
 *     stay un-edited and now diverge from their decrypt counterparts. This
 *     is the existing "each leaf owns its params" semantic — same as
 *     AddRoundKey. A future "Apply S_3 to all rounds using S_3" affordance
 *     would address it. Out of scope for cross-mode mirror Slice 2.
 *   - Slice 4's enumeration-test registry shape will need a `groupBy?:
 *     "sboxIndex"` field to handle this case cleanly. Today the test would
 *     pass as long as ANY Sync button is present for the step type; the
 *     per-index semantic is asserted by `tests/serpent-sync-inverse-store.test.ts`
 *     instead (including the non-regression "other sboxIndex leaves are
 *     unchanged" assertion).
 */
export const syncSboxInverseToCounterpartByIndex = (
  stepType: string,
  sboxIndex: number,
  invertedSbox: readonly number[],
): void => {
  const current = specs();
  if (current.kind !== "cipher") {
    throw new Error("syncSboxInverseToCounterpartByIndex not supported for hash spec");
  }
  const counterpartMode: Mode = mode() === "encrypt" ? "decrypt" : "encrypt";
  const updated = updateAllStepsByType(current[counterpartMode], stepType, (params) => {
    const p = params as { sboxIndex?: number };
    // Reference-equal return for non-matching index → updateAllStepsByType's
    // tree walker short-circuits the rebuild for this leaf, preserving
    // structural sharing across the unchanged 7/8ths of the rounds.
    if (p.sboxIndex !== sboxIndex) return params;
    return {
      ...(params as Record<string, Json>),
      sbox: [...invertedSbox],
    };
  });
  if (updated === current[counterpartMode]) return; // reference-equal → no-op
  setSpecs(
    counterpartMode === "encrypt"
      ? { kind: "cipher", encrypt: updated, decrypt: current.decrypt }
      : { kind: "cipher", encrypt: current.encrypt, decrypt: updated },
  );
};

/**
 * Cross-slot **identity** (copy) mirror — the value-mirror counterpart for
 * step types whose encrypt-side and decrypt-side params hold the **same**
 * value, not algebraic inverses.
 *
 * Today's user: AES key expansion (`aes.key-expansion@1` / `@2`). Per
 * FIPS-197 §5.2, the key schedule uses the FORWARD S-box even when
 * decrypting — the inverse cipher consumes the same round keys in
 * reverse order without re-deriving them with the inverse S-box. So a
 * user who edits the key-expansion S-box on the encrypt side will want
 * to propagate that **same** table to decrypt's key-expansion (not its
 * inverse — that's the SubBytes case, which `syncSboxInverseToCounterpart`
 * handles).
 *
 * Sibling to `syncSboxInverseToCounterpart`: same broadcast-to-every-
 * matching-step-in-counterpart shape, same "active slot untouched"
 * invariant, same direction inference from `useMode()`. The single
 * semantic difference is `sbox: [...sboxValue]` instead of
 * `sbox: [...invertedSbox]` — no algebraic inversion. The button
 * surfacing this mutator names the operation "Copy …" (not "Sync
 * inverse …") so users read the asymmetry between the two cases before
 * clicking.
 *
 * Caller passes the table verbatim — DO NOT compose `invertSbox` here or
 * on the caller side; that would re-introduce the AES-SubBytes semantic
 * by accident.
 *
 * **Today's user (since the key-schedule decomposition, 2026-06-01):** the
 * AES key-schedule SubWord leaves, which are `byte-substitute@1` (the same
 * type as round-body SubBytes). The caller passes `idFilter`
 * (`isKeyScheduleLeafId`) so the Copy lands ONLY on the key-schedule
 * SubWord leaves and not on the round-body SubBytes leaves (which take the
 * inverse mirror instead). Before decomposition this was keyed on the
 * monolithic `aes.key-expansion@1/@2` step type with no filter.
 */
export const syncSboxCopyToCounterpart = (
  stepType: string,
  sboxValue: readonly number[],
  idFilter?: (id: string) => boolean,
): void => {
  const current = specs();
  if (current.kind !== "cipher") {
    throw new Error("syncSboxCopyToCounterpart not supported for hash spec");
  }
  const counterpartMode: Mode = mode() === "encrypt" ? "decrypt" : "encrypt";
  const updated = updateAllStepsByType(
    current[counterpartMode],
    stepType,
    (params) => ({
      ...(params as Record<string, Json>),
      sbox: [...sboxValue],
    }),
    idFilter,
  );
  if (updated === current[counterpartMode]) return; // reference-equal → no-op
  setSpecs(
    counterpartMode === "encrypt"
      ? { kind: "cipher", encrypt: updated, decrypt: current.decrypt }
      : { kind: "cipher", encrypt: current.encrypt, decrypt: updated },
  );
};

/**
 * Cross-slot **inverse-matrix** mirror for MixColumns. The class-2
 * inverse-mirror counterpart to `syncSboxInverseToCounterpart` for the
 * `generic.mix-columns@1` step type — encrypt holds the forward mixing
 * matrix (canonically `AES_MIX_MATRIX`), decrypt holds its GF(2^8)
 * inverse (canonically `AES_INV_MIX_MATRIX`).
 *
 * Sibling to `syncSboxInverseToCounterpart`: same broadcast-to-every-
 * matching-step-in-counterpart shape, same "active slot untouched"
 * invariant, same direction inference from `useMode()`. The single
 * semantic difference is the param key — writes `matrix` instead of
 * `sbox`.
 *
 * The caller passes the inverted matrix verbatim (computed via
 * `gfMatInverse4x4` in `src/core/state/gf-matrix.ts`). The split keeps
 * this module a pure store boundary — no GF(2^8) arithmetic leaks into
 * the spec store. The caller is also responsible for the "throw =
 * singular = disable the button" gating logic.
 *
 * Unlike Serpent's per-S-box-index split, MixColumns broadcasts cleanly
 * because the AES round structure uses the SAME mixing matrix in every
 * round (rounds 1..Nr-1; the last round has no MixColumns). Every
 * `generic.mix-columns@1` leaf on the counterpart side gets the same
 * inverse, which matches the canonical AES_INV_MIX_MATRIX semantic.
 */
export const syncMixColumnsInverseToCounterpart = (
  stepType: string,
  invertedMatrix: readonly (readonly number[])[],
): void => {
  const current = specs();
  if (current.kind !== "cipher") {
    throw new Error("syncMixColumnsInverseToCounterpart not supported for hash spec");
  }
  const counterpartMode: Mode = mode() === "encrypt" ? "decrypt" : "encrypt";
  const updated = updateAllStepsByType(current[counterpartMode], stepType, (params) => ({
    ...(params as Record<string, Json>),
    matrix: invertedMatrix.map((row) => [...row]),
  }));
  if (updated === current[counterpartMode]) return; // reference-equal → no-op
  setSpecs(
    counterpartMode === "encrypt"
      ? { kind: "cipher", encrypt: updated, decrypt: current.decrypt }
      : { kind: "cipher", encrypt: current.encrypt, decrypt: updated },
  );
};

/**
 * Insert a brand-new step leaf into the live spec (Slice 8 of the 2D
 * editor plan). The palette + GraphView drop handler call this with a
 * `stepType` registered in the registry and an anchor that says WHERE
 * relative to the existing tree the new leaf should land.
 *
 * Four anchor flavors:
 *   • `{ kind: "after", stepId }` — uses `insertStepAfter` to place the
 *     new leaf immediately after that node, into its parent. The anchor
 *     can be a leaf id OR a container id (group/iterate) — `findStepAndParent`
 *     handles both since Slice 4.
 *   • `{ kind: "before", stepId }` — mirror of `after`. Routes through
 *     `insertStepBefore`. The drop-gutter UI surface (Slice 5 of the
 *     graph-narrative-and-zoom plan) uses this for "drop between two
 *     siblings" (gutter anchored at the slot's next sibling).
 *   • `{ kind: "into-start", containerId }` — inserts as the FIRST
 *     child of the named container's body. Used by the post-rescope
 *     header-drop semantic (2026-05-15 follow-up to Slice 5): dropping
 *     on a container's header band means "enter this container's body
 *     and land at position 0," NOT the original Slice 8 "insert after
 *     the container in its parent" — user feedback showed the after-in-
 *     parent semantic was actively confusing because the chip obscures
 *     the header and users couldn't tell their cursor was on the
 *     header. Falls back to root-append when the container has no
 *     children. Walks the spec tree to find the first child; works for
 *     groups and iterates uniformly.
 *   • `{ kind: "root-append" }` — appends to `spec.steps`. Used when the
 *     drop lands on the SVG canvas with no specific node target (today's
 *     ciphers always have at least one root node, so this is the empty-
 *     canvas / fallback path).
 *
 * The new leaf carries `params: {}` — the runtime will almost certainly
 * throw on first execution because most step types require parameters
 * (S-box, block size, …). That's deliberate per the Slice 8 plan: the
 * inserted leaf is a placeholder the user opens in the ParamEditor to
 * configure. The Run error surfaces in the existing error banner, telling
 * the user which step is missing what.
 *
 * Id generation: `<last-stepType-segment-without-@N>-<n>`. Example:
 * `generic.byte-substitution@1` → `byte-substitution-1`. n auto-increments
 * to dodge collisions with existing leaves of the same stepType.
 *
 * Returns the generated id so the caller (GraphView's drop handler) can
 * route the trace scrubber to the new step's frame once the auto-rerun
 * lands — even though that frame is likely an ERROR frame for a leaf with
 * empty params.
 */
/**
 * Remove a leaf, group, or iterate (and all its descendants) from the
 * live spec. Three UI affordances drive this:
 *   - the × button rendered on hover at the corner of each graph node;
 *   - the "Delete this step" button in the ParamEditor;
 *   - the Delete/Backspace keyboard shortcut while a graph node is
 *     focused.
 *
 * No-op + warn if the id doesn't resolve. Throwing on a stale id would
 * be hostile — the user clicks delete on a node, the spec re-runs
 * meanwhile and the leaf was already removed; we don't want a crash.
 * `removeStep` (core) throws on stale ids by design; we catch here to
 * make the boundary lenient.
 */
export const removeStepFromSpec = (stepId: string): void => {
  try {
    updateActive((s) => removeStep(s, stepId));
  } catch (err) {
    // Stale id or other failure — surface to the console for debugging
    // but don't crash the UI. Real users won't see this; the path lights
    // up only when delete races with another spec mutation.
    console.warn(`removeStepFromSpec(${stepId}) failed:`, err);
  }
};

export const insertStepIntoSpec = (
  stepType: string,
  anchor:
    | { kind: "after"; stepId: string }
    | { kind: "before"; stepId: string }
    | { kind: "into-start"; containerId: string }
    | { kind: "root-append" },
): string => {
  const currentSpec = activeSpec();
  const newId = generateUniqueStepId(currentSpec, stepType);
  const newLeaf: StepLeaf = {
    kind: "step",
    id: newId,
    type: stepType,
    params: {},
  };
  if (anchor.kind === "after") {
    updateActive((s) => insertStepAfter(s, anchor.stepId, newLeaf));
  } else if (anchor.kind === "before") {
    updateActive((s) => insertStepBefore(s, anchor.stepId, newLeaf));
  } else if (anchor.kind === "into-start") {
    // Land at position 0 of the targeted container's body. The dedicated
    // `prependChildToContainer` primitive handles BOTH the non-empty
    // case AND the previously-broken empty-container case in one path —
    // the old code path (find first child → insertStepBefore) had
    // nothing to anchor on when the container had zero children and
    // silently fell through to root-append, mis-scoping the drop to
    // the end of the top-level spec.
    try {
      updateActive((s) => prependChildToContainer(s, anchor.containerId, newLeaf));
    } catch (err) {
      // The drop handler only calls into-start when it has confirmed
      // the anchor id is a container (see `containersById().has(...)`
      // check in GraphView.handleDrop), so this throw really only
      // fires if the spec mutated out from under us mid-drop. Recover
      // by appending to root rather than crashing the UI.
      console.warn(`insertStepIntoSpec(into-start, ${anchor.containerId}) failed:`, err);
      updateActive((s) => ({ ...s, steps: [...s.steps, newLeaf] }));
    }
  } else {
    // root-append: rebuild the top-level array with the new leaf at the
    // end. `insertStepAfter` would also work if there's a last element,
    // but a direct append covers the empty-spec edge case uniformly.
    updateActive((s) => ({ ...s, steps: [...s.steps, newLeaf] }));
  }
  return newId;
};

/**
 * Registry-driven primary published output port of a node — the port a
 * downstream consumer reads by default. Leaves: the first declared output port
 * from the registered `PortContract` (falls back to `"output"`, the port-native
 * leaf convention, for an unregistered/contract-less type). Containers: their
 * first `outputPorts` entry, defaulting to `"out"`. Used to auto-wire a dropped
 * composite's seed into the flow (see `insertCompositeIntoSpec`).
 */
const primaryOutputPort = (node: StepNode): string => {
  if (node.kind !== "step") return node.outputPorts?.[0] ?? "out";
  const reg = registry.getRegistration(node.type);
  if (reg?.kind === "ported") {
    for (const portName of resolvePortMap(reg.shape.outputs, node.params).keys()) {
      return portName; // first declared output
    }
  }
  return "output";
};

/**
 * Slugify a composite's name into a spec-id-safe base (lowercase, non-alnum
 * runs → `-`, trimmed). `"AES Round"` → `"aes-round"`. Empty result (e.g. a
 * name with no alnum chars) lets the caller fall back to the template's id.
 */
const slugifyId = (s: string): string =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

/**
 * Drop a saved composite (a `StepGroup` template from the composites store)
 * into the live spec — the store boundary the GraphView composite-drop handler
 * calls (universal-port Phase 4f, compose-and-save). The COPY/INLINE semantics:
 * the template's children are cloned with fresh, collision-free ids
 * (`cloneGroupWithFreshIds`), inlined as a real group, and stay fully editable
 * + scrubbable — the saved/shared document is self-contained (it never
 * references the composite library).
 *
 * The clone's `seedInput` is auto-bound to the insertion-point predecessor
 * (`pickSeedBinding` + `primaryOutputPort`) so the dropped composite is wired
 * into the data flow by default — the 4d-bis port editor only rewires LEAF
 * ports, so a container seed left unbound would have no in-app fix. The user
 * can then rewire the composite's internal leaf ports via that editor as usual.
 *
 * Flows through `updateActive`, reusing the App-level debounced rerun (no new
 * rerun path). Returns the new group's id so the caller can route the scrubber.
 */
export const insertCompositeIntoSpec = (
  template: StepGroup,
  anchor: CompositeInsertAnchor,
): string => {
  const currentSpec = activeSpec();
  const existingIds = collectSpecIds(currentSpec);
  // Readable fresh root id from the composite's name (its label), else its id.
  const base = slugifyId(template.label) || template.id;
  const { group } = cloneGroupWithFreshIds(template, base, existingIds);
  // Wire the seed into the flow at the insertion point (registry-driven).
  const seed = pickSeedBinding(currentSpec, anchor, primaryOutputPort);
  const seeded: StepGroup = seed !== undefined ? { ...group, seedInput: seed } : group;

  if (anchor.kind === "after") {
    updateActive((s) => insertStepAfter(s, anchor.stepId, seeded));
  } else if (anchor.kind === "before") {
    updateActive((s) => insertStepBefore(s, anchor.stepId, seeded));
  } else if (anchor.kind === "into-start") {
    // Same recover-by-root-append fallback discipline as `insertStepIntoSpec`:
    // the drop handler only routes into-start to a confirmed container, so this
    // throw only fires if the spec mutated out from under us mid-drop.
    try {
      updateActive((s) => prependChildToContainer(s, anchor.containerId, seeded));
    } catch (err) {
      console.warn(`insertCompositeIntoSpec(into-start, ${anchor.containerId}) failed:`, err);
      updateActive((s) => ({ ...s, steps: [...s.steps, seeded] }));
    }
  } else {
    updateActive((s) => ({ ...s, steps: [...s.steps, seeded] }));
  }
  return seeded.id;
};

/**
 * Duplicate-round entry point for the graph-view toolbar (Phase 4 of
 * docs/plans/duplicate-round.md). Invariants:
 *
 *   - The CURRENT mode's spec is mutated via `duplicateRoundGroup` with
 *     the appropriate direction (forward for encrypt, reverse for
 *     decrypt).
 *   - The COUNTERPART mode's spec is also mutated, with the opposite
 *     direction and the source id translated by key index
 *     (round.N ↔ inv-round.N).
 *   - Both slots are written in one signal update.
 *   - Layout pins are migrated for BOTH spec.id's via
 *     `renameSpecLayoutIds`. Pins on un-renamed nodes stay.
 *   - Stacking duplicates: the second call applies the mutator to the
 *     LIVE (already-modified) counterpart slot, not to canonical. So
 *     two duplicates on encrypt produce a decrypt with two mirrored
 *     duplicates.
 *
 * Failure modes:
 *   - Active-side mutator throws → the entire call throws; nothing
 *     changes. (Bad source id, source isn't a group, etc.)
 *   - Counterpart mutator throws → active-side change still lands but
 *     counterpart is left unchanged. The user sees a console warning;
 *     they can manually adjust decrypt. This path is reachable if the
 *     counterpart spec has been customized in a way that lost the
 *     matching inv-round.N (e.g. user deleted it manually).
 *
 * The source id is restricted to non-final rounds by the UI layer
 * (Phase 5) — round.{rounds} / inv-round.0 have no clean auto-mirror
 * because the canonical decrypt has no inv-round.{rounds}.
 */
export const duplicateRoundInSpec = (sourceId: string): void => {
  const currentMode = mode();
  const current = specs();
  // Duplicate-round depends on the encrypt ↔ decrypt mirror by direction;
  // hash specs have no mirror counterpart. UI surfaces the duplicate
  // button only on cipher-shape round groups, so reaching here for a
  // hash kind surfaces a programming error.
  if (current.kind !== "cipher") {
    throw new Error("duplicateRoundInSpec not supported for hash spec");
  }
  const activeDirection: "forward" | "reverse" = currentMode === "encrypt" ? "forward" : "reverse";

  // Active-side: throws propagate to the caller (UI surfaces in the
  // existing error banner). Without this, a typo'd id would silently
  // no-op which would be a debugging puzzle.
  const { spec: newActive, renames: activeRenames } = duplicateRoundGroup(
    current[currentMode],
    sourceId,
    activeDirection,
  );

  // Counterpart-side: best-effort. The counterpart's source id swaps
  // by key index — round.N ↔ inv-round.N — preserving the "same key
  // index, mirrored direction" semantic.
  const counterpartMode: Mode = currentMode === "encrypt" ? "decrypt" : "encrypt";
  const counterpartDirection: "forward" | "reverse" =
    counterpartMode === "encrypt" ? "forward" : "reverse";
  const counterpartSourceId =
    activeDirection === "forward"
      ? sourceId.replace(/^round\./, "inv-round.")
      : sourceId.replace(/^inv-round\./, "round.");

  let newCounterpart: CipherSpec = current[counterpartMode];
  let counterpartRenames: ReadonlyMap<string, string> = new Map();
  try {
    const result = duplicateRoundGroup(
      current[counterpartMode],
      counterpartSourceId,
      counterpartDirection,
    );
    newCounterpart = result.spec;
    counterpartRenames = result.renames;
  } catch (err) {
    // Don't roll back active-side: the user explicitly clicked
    // duplicate, and partial success > total failure when the
    // counterpart is the only failed side.
    console.warn(
      `duplicateRoundInSpec: counterpart mirror failed for ${counterpartSourceId}:`,
      err,
    );
  }

  // One `batch()` so the three signal writes below (the spec union + both
  // layout-map renames) land as a SINGLE reactive transition. Subscribers see
  // one consistent (encrypt, decrypt, layout) update — and, load-bearing for
  // C2, the edit-history capture observer records exactly ONE undo entry for
  // the whole duplicate-round instead of one per intermediate write.
  batch(() => {
    // Both slots land atomically: subscribers see one consistent
    // (encrypt, decrypt) pair.
    setSpecs(
      currentMode === "encrypt"
        ? { kind: "cipher", encrypt: newActive, decrypt: newCounterpart }
        : { kind: "cipher", encrypt: newCounterpart, decrypt: newActive },
    );

    // Layout migration. Both specs have their own layout entry keyed by
    // spec.id; each gets the matching rename map applied.
    renameSpecLayoutIds(newActive.id, activeRenames);
    renameSpecLayoutIds(newCounterpart.id, counterpartRenames);
  });
};

/**
 * UI gate for the graph-view duplicate button. Returns true iff the
 * container at `containerId` is a round group whose auto-mirror has a
 * clean landing site on the counterpart side.
 *
 *   - `round.N`: needs a sibling `round.{N+1}` to exist. The final
 *     round (e.g. `round.{rounds}` in canonical AES) has no
 *     `round.{N+1}` sibling, so it would auto-mirror to a non-existent
 *     `inv-round.{rounds}` on the decrypt side. Suppress the button
 *     to avoid a half-mirrored state.
 *   - `inv-round.N`: needs `N > 0`. `inv-round.0` is the final inverse
 *     round; mirroring to encrypt's `round.0` (which doesn't exist —
 *     encrypt's `initial.add-round-key` is a LEAF, not a group) would
 *     fail.
 *   - Anything else (leaves, iterate body, non-round groups): false.
 *
 * Pure read of the active spec. Tracking is implicit (reads `specs()`
 * and `mode()` via `activeSpec()`), so consumers using this inside
 * `createMemo` automatically re-evaluate when the spec changes.
 */
export const isRoundDuplicatable = (containerId: string): boolean => {
  const m = containerId.match(/^(round|inv-round)\.(\d+)$/);
  if (!m || !m[1] || !m[2]) return false;
  const prefix = m[1];
  const n = Number.parseInt(m[2], 10);
  if (prefix === "inv-round") return n > 0;
  // prefix === "round": confirm a higher-numbered sibling exists.
  const loc = findStepAndParent(activeSpec(), containerId);
  if (!loc || loc.node.kind !== "group") return false;
  const siblings = loc.parent ? loc.parent.children : activeSpec().steps;
  return siblings.some((s) => s.kind === "group" && s.id === `round.${n + 1}`);
};

/**
 * Walk the spec collecting every existing step / group / iterate id, then
 * produce the smallest positive integer `n` for which
 * `<lastSegment>-<n>` is unused. The base segment is the last dot-separated
 * part of `stepType` with any trailing `@version` chopped off, so
 * `generic.byte-substitution@1` → base `byte-substitution`. Pure helper,
 * doesn't read or write the spec store — it just receives the live spec
 * as an argument.
 */
const generateUniqueStepId = (spec: CipherSpec, stepType: string): string => {
  const lastDot = stepType.lastIndexOf(".");
  const lastSegment = lastDot >= 0 ? stepType.slice(lastDot + 1) : stepType;
  const atIdx = lastSegment.indexOf("@");
  const base = atIdx >= 0 ? lastSegment.slice(0, atIdx) : lastSegment;
  // Collect every id in the spec — leaves AND groups AND iterates, because
  // ids share one namespace and a collision with a group id would be just
  // as bad as one with a leaf id. Cheap to walk on every insert; specs
  // top out at a few hundred nodes.
  const usedIds = new Set<string>();
  const visit = (nodes: readonly StepNode[]): void => {
    for (const node of nodes) {
      usedIds.add(node.id);
      if (node.kind === "step") continue;
      visit(node.children);
    }
  };
  visit(spec.steps);
  // Find the first free `<base>-<n>` starting at n=1. Linear scan is fine
  // because the worst case is hundreds of inserts of the same type in one
  // session — well below the threshold where a smarter algorithm pays off.
  let n = 1;
  while (usedIds.has(`${base}-${n}`)) n++;
  return `${base}-${n}`;
};

/**
 * Apply a loaded `CipherDocument` to the live stores (Slice 5 of the 2D
 * editor plan). This is the boundary that the Save/Load UI calls after
 * `parseDocument` succeeds — it routes around the public selector setters
 * (each of which would trigger its own spec rebuild) and lands the
 * document's literal `spec` value as the authoritative final state.
 *
 * Hydration order matters:
 *   1. byteFormat first — so a later App-level format of restored input/
 *      key bytes uses the freshly-applied format, not the previous one.
 *   2. cipher, cipherMode, padding — raw signal setters (from cipher.ts /
 *      cipher-mode.ts / padding.ts) that update the signal + localStorage
 *      WITHOUT rebuilding the spec. We bypass this module's own setCipher
 *      etc. on purpose: those would each rebuild spec from the canonical
 *      defaults table, then the next setter would overwrite it again, and
 *      the literal `doc.spec` would never land.
 *   3. mode — same idea via the local setModeSignal.
 *   4. spec — finally, set the document's spec verbatim. The
 *      createEffect(on(spec, ...)) in App.tsx picks this up; the Load
 *      handler also calls run() synchronously so the trace lands before
 *      the debounce.
 *
 * Cross-store consistency (e.g. a document with cipher=aes-192 +
 * cipherMode=ecb when AES-192-ECB doesn't ship yet) is NOT corrected —
 * the document's spec is what runs, regardless. If it's inconsistent with
 * the supported-modes matrix, the dropdown will show the unsupported
 * combo grayed out, but the loaded trace still works because we use the
 * literal spec rather than re-resolving the defaults table.
 *
 * Input + key bytes are NOT applied here — App.tsx owns those signals and
 * reads `doc.session.inputBytes` / `keyBytes` directly after this call.
 */
export const setSpecFromDocument = (doc: CipherDocument): void => {
  // Hash short-circuit (Slice 2.10b, 2026-05-25). When the document's
  // algorithm hint identifies a Hash variant, there is no encrypt/decrypt
  // counterpart to construct, and the existing `resolveDefault` call below
  // explicitly assumes a cipher universe (3-axis lookup keyed by Cipher).
  // The advisor flagged this as the load-bearing branch: the early return
  // here is what keeps the cipher-side construction honest. Session
  // restoration for a hash doc is also a degenerate case — there's no
  // `cipherMode` / `padding` / encrypt-decrypt distinction to apply, and
  // 2.10c is where the algorithm signal that would carry the hash
  // selector value lands. For now, we land the literal `doc.spec` into
  // the single slot and leave selector signals as-is.
  //
  // Implementation note on the discriminant: the document schema's
  // `algorithm: Algorithm` is the source of truth for WHICH hash variant
  // the spec is — `doc.spec.id` would be a fragile alternative ("sha-256@1"
  // string-match). When `algorithm` is absent on a hash document (a
  // historical doc authored before v3, but containing a hash spec — not
  // possible in practice since SHA-256 wasn't selectable pre-2.10c —
  // OR a future doc that omits the optional hint), we have no way to
  // identify the hash variant. Fall through to the cipher path in that
  // case; the unidentifiable doc.spec will simply land into the active
  // cipher slot and almost certainly fail at runtime, which is the
  // honest signal to the user that the document is malformed.
  if (doc.algorithm !== undefined && isHash(doc.algorithm)) {
    // Slice 2.10c (2026-05-25): sync the category + hash signals so the
    // selector UI lands on the right family + variant after a load. 2.10b
    // landed only `setSpecs(...)` here because the algorithm signal hadn't
    // been split yet; without these two extra writes, a hash document
    // loaded into a cipher-category recipient would leave the cipher
    // dropdown looking active even though the live spec is a hash.
    setCategorySignal("hash");
    setHashSignal(doc.algorithm);
    // For SHAKE, recover the output length from the loaded spec's truncate step
    // so the control shows it and a later resetSpec rebuilds at that length.
    // Set the RAW signal (not setShakeOutputLength) — we land doc.spec verbatim
    // below rather than a canonical rebuild, so no structural rebuild is wanted.
    if (isXofHash(doc.algorithm)) {
      const loadedLen = readShakeOutputLength(doc.spec);
      if (loadedLen !== undefined) {
        setShakeOutputLengthSignal(Math.max(1, Math.min(MAX_SHAKE_OUTPUT, loadedLen)));
      }
    }
    // cSHAKE: recover the customization strings so the controls show them and a
    // later resetSpec rebuilds the same customized spec.
    if (isCshakeHash(doc.algorithm)) {
      const { N, S } = readCshakeCustomization(doc.spec);
      const dec = new TextDecoder();
      setCshakeNSignal(dec.decode(N));
      setCshakeSSignal(dec.decode(S));
    }
    // KMAC: recover the customization string S (the key travels via session/aux,
    // not the spec; N is the fixed "KMAC") AND the declared key length, so a
    // later S edit rebuilds at the loaded key length rather than snapping back to
    // the 32-byte default. Signal-only (no rebuild): the doc's spec is applied
    // as-is by the setSpecs below and may be a customized/edited variant.
    if (isKmacHash(doc.algorithm)) {
      setKmacSSignal(new TextDecoder().decode(readKmacCustomization(doc.spec)));
      setKmacKeyLengthSignal(clampKmacKeyLength(readKmacKeyLength(doc.spec)));
    }
    setSpecs({ kind: "hash", hash: doc.algorithm, single: doc.spec });
    return;
  }
  // Asymmetric (RSA) document branch — sibling of the hash short-circuit.
  // Like the cipher branch it lands the doc's single spec in the matching
  // mode slot and rebuilds the counterpart from canonical, but there is no
  // cipherMode/padding to restore. byteFormat + mode come from the session
  // when present; otherwise the current values are kept.
  if (doc.algorithm !== undefined && isAsymmetric(doc.algorithm)) {
    setCategorySignal("asymmetric");
    setAsymmetricSignal(doc.algorithm);
    if (doc.session) {
      setByteFormat(doc.session.byteFormat);
      setModeSignal(doc.session.mode);
    }
    const docMode: Mode = doc.session?.mode ?? mode();
    const otherMode: Mode = docMode === "encrypt" ? "decrypt" : "encrypt";
    const otherCanonical = resolveAsymmetricDefault(doc.algorithm, otherMode);
    setSpecs(
      docMode === "encrypt"
        ? {
            kind: "asymmetric",
            asymmetric: doc.algorithm,
            encrypt: doc.spec,
            decrypt: otherCanonical,
          }
        : {
            kind: "asymmetric",
            asymmetric: doc.algorithm,
            encrypt: otherCanonical,
            decrypt: doc.spec,
          },
    );
    return;
  }
  // Slice 2.10c (2026-05-25): from here down is the cipher-document
  // branch. Land in category "cipher" defensively — a recipient previously
  // in "hash" category needs its selector flipped back so the cipher
  // dropdown is the live surface again. The hash short-circuit above
  // already handled the hash → hash case; this covers hash → cipher.
  setCategorySignal("cipher");
  if (doc.session) {
    setByteFormat(doc.session.byteFormat);
    setCipherSignal(doc.session.cipher);
    setCipherModeSignal(doc.session.cipherMode);
    setPaddingScheme(doc.session.padding);
    setModeSignal(doc.session.mode);
    // IV bytes — restored when the saved session carried them (CBC and
    // future feedback modes). The schema validates length=16 already, so
    // the cast to Uint8Array can't fail.
    if (doc.session.ivBytes !== undefined) {
      setIvBytes(new Uint8Array(doc.session.ivBytes));
    }
  } else if (doc.algorithm !== undefined && isCipher(doc.algorithm)) {
    // Spec-only path with the algorithm-hint field (Phase 6e of
    // `docs/plans/des-feistel.md`, renamed `cipher` → `algorithm` in
    // Slice 2.10b of the universal-port plan). Flip the cipher selector
    // to match the document's cipher so non-AES specs (DES, Speck,
    // Serpent) don't land into a recipient whose AES-128 default key
    // field (16 bytes) immediately errors with "expected 8 bytes"
    // against an 8-byte DES block.
    //
    // We also fall back `cipherMode` to "single-block" when the current
    // mode isn't supported for the loaded cipher (DES, Speck, Serpent
    // are all single-block today). Without this, switching from AES-128/ecb
    // to a DES document would leave the user in a (des, ecb) combo that
    // the canonical-defaults table doesn't have a spec for — the literal
    // `doc.spec` still runs, but selector flips after the load (like
    // switching mode and back) would pick up the wrong canonical default.
    //
    // mode/padding/byteFormat stay at the user's current values: there's
    // no hint for those in a spec-only document, and "DES has no
    // padding" is already enforced by the padding store's own
    // single-block fallback.
    setCipherSignal(doc.algorithm);
    if (!isCipherModeSupported(doc.algorithm, useCipherMode()())) {
      // As in `setCipher`: the loaded cipher's own default mode. Loading a
      // ChaCha20 document while a block-cipher mode is active must not try to
      // resolve a "single-block" ChaCha20 spec, which does not exist.
      setCipherModeSignal(defaultCipherModeFor(doc.algorithm));
    }
  }
  // Document carries one spec (for the document's mode). Land it in the
  // matching slot; rebuild the OTHER slot from canonical so the
  // unactive mode is consistent with the current selectors. A saved
  // document doesn't carry the counterpart, so this is the best we can
  // do without a richer document schema.
  const docMode: Mode = doc.session?.mode ?? mode();
  const otherMode: Mode = docMode === "encrypt" ? "decrypt" : "encrypt";
  const otherCanonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), otherMode),
    otherMode,
    usePaddingScheme()(),
    overlayBlockBytes(useCipher()(), useCipherMode()()),
  );
  setSpecs(
    docMode === "encrypt"
      ? { kind: "cipher", encrypt: doc.spec, decrypt: otherCanonical }
      : { kind: "cipher", encrypt: otherCanonical, decrypt: doc.spec },
  );
};

/**
 * History apply-path setter (Part C of the graph-legibility plan, undo/redo).
 * Replace the WHOLE dual-mode spec union wholesale from a snapshot the
 * edit-history store captured. Deliberately lean — a bare `setSpecs`, NOT
 * `setSpecFromDocument`: the selector signals (cipher, cipherMode, padding,
 * category/hash/asymmetric) are invariant within a single undo/redo stack
 * because any selector switch clears the history stacks (see the stack-
 * boundary rule), so restoring a snapshot never needs to re-sync them. The
 * snapshot was captured by reference off `useSpecsByMode()`, which the spec
 * store only ever replaces wholesale (structural sharing on untouched
 * branches), so the reference stays valid indefinitely.
 *
 * The caller (edit-history) wraps this + `replaceLayoutMap` in one Solid
 * `batch()` so subscribers see a single atomic (spec, layout) transition,
 * and sets its re-entrancy guard to this exact reference BEFORE calling so
 * the capture observer skips the restore's own write.
 */
export const restoreSpecsForHistory = (snapshot: SpecsByMode): void => {
  setSpecs(snapshot);
};

/**
 * Restore the default spec for the current (cipher, cipherMode, mode).
 * Affects the ACTIVE slot only — the counterpart slot keeps whatever
 * the user has there. Matches the existing single-spec semantic of
 * "reset the thing I'm looking at."
 */
export const resetSpec = (): void => {
  const current = specs();
  if (current.kind === "hash") {
    // Slice 2.10b: hash canonical lookup keyed by the variant discriminant
    // carried in the SpecsByMode itself. Hashes have no
    // (cipherMode, padding, mode) dimensions to apply, so the lookup is
    // a direct table read.
    const canonical = resolveHashDefault(current.hash);
    updateActive(() => canonical);
    return;
  }
  if (current.kind === "asymmetric") {
    // No (cipherMode, padding) overlay — direct table read by (variant, mode).
    const canonical = resolveAsymmetricDefault(current.asymmetric, mode());
    updateActive(() => canonical);
    return;
  }
  const canonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), mode()),
    mode(),
    usePaddingScheme()(),
    overlayBlockBytes(useCipher()(), useCipherMode()()),
  );
  updateActive(() => canonical);
};

/**
 * Structural deep equality for `Json`-typed values. Used by `isCustomSpec`
 * to compare the live spec to the canonical default without depending on
 * insertion-order stability — `JSON.stringify` would be order-sensitive, and
 * while today's spread-based mutations preserve key order, a future param
 * editor could round-trip a step's params through a differently-shaped
 * object and reorder keys. Recursive walk, ~15 lines, no allocation hot
 * path because it short-circuits on the first mismatch.
 */
const deepEqualJson = (a: unknown, b: unknown): boolean => {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqualJson(a[i], b[i])) return false;
    }
    return true;
  }
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  const bk = Object.keys(bo);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (!Object.prototype.hasOwnProperty.call(bo, k)) return false;
    if (!deepEqualJson(ao[k], bo[k])) return false;
  }
  return true;
};

/**
 * True when the live spec differs from the canonical default that the
 * current selectors (cipher, cipherMode, mode, padding) would produce.
 *
 * Used by the UI to render a "Custom (was AES-128)" indicator + a
 * "reset to canonical" affordance so the user can see when they've
 * diverged from the textbook spec and snap back to it in one click.
 *
 * Why selector flips don't trigger this: `setCipher` / `setCipherMode` /
 * `setMode` all replace the spec with the new canonical default, and
 * `setPadding` rebuilds via `applyPaddingScheme` from the live spec —
 * which, when the live spec was already canonical, produces the same
 * tree as a fresh canonical-then-padding build (verified by the padding
 * round-trip test below).
 *
 * Implementation reads every signal it needs so Solid's tracking sees
 * each dependency; the App-side caller can wrap this in `createMemo` for
 * caching when it's read multiple times per render.
 */
export const isCustomSpec = (): boolean => {
  const current = specs();
  if (current.kind === "hash") {
    // Slice 2.10b: compare the active hash spec against its canonical
    // table entry, identified by the variant discriminant carried in
    // the SpecsByMode. Same deep-equal walk used for ciphers — the
    // hash table has no padding overlay to compose first.
    const canonical = resolveHashDefault(current.hash);
    return !deepEqualJson(current.single, canonical);
  }
  if (current.kind === "asymmetric") {
    const canonical = resolveAsymmetricDefault(current.asymmetric, mode());
    return !deepEqualJson(activeSpec(), canonical);
  }
  const canonical = applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), mode()),
    mode(),
    usePaddingScheme()(),
    overlayBlockBytes(useCipher()(), useCipherMode()()),
  );
  return !deepEqualJson(activeSpec(), canonical);
};

/** Test-only reset; production code uses the setters above. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  const scheme = usePaddingScheme()();
  setSpecs({
    kind: "cipher",
    encrypt: applyPaddingScheme(aes128Spec, "encrypt", scheme, blockByteLengthFor("aes-128")),
    decrypt: applyPaddingScheme(
      aes128DecryptSpec,
      "decrypt",
      scheme,
      blockByteLengthFor("aes-128"),
    ),
  });
};

/**
 * Test-only: land an arbitrary spec into BOTH cipher slots so `useSpec()`
 * returns it regardless of mode. Used by the Feistel linear-mode component
 * tests (FeistelMiniDiagram / FeistelTrackContext / RejoinFrameView /
 * scrubber badges) to inject the `feistel-toy` fixture — `feistel-round`
 * is not in the cipher selector, so `setCipher` can't reach it, and after
 * the B4 DES rebuild no shipped cipher uses the primitive at all. The toy
 * is the only construct exercising those (Phase-5-doomed) components, and
 * this is the minimal injection path.
 */
export const __setSpecForTests = (spec: CipherSpec): void => {
  setSpecs({ kind: "cipher", encrypt: spec, decrypt: spec });
};
