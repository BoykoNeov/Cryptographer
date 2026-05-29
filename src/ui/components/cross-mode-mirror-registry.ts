/**
 * Registry of every (stepType, paramKey) pair whose ENCRYPT-side value
 * has a known mirror relationship to its DECRYPT-side counterpart. Drives
 * the enumeration coverage test (`tests/cross-mode-mirror-coverage.test.tsx`)
 * that asserts every entry here has a corresponding Sync/Copy button
 * rendered by `ParamEditor`.
 *
 * The architectural principle this registry locks in (see CLAUDE.md →
 * "Cross-mode mirror buttons"):
 *
 *   1. Encrypt and decrypt slots are held simultaneously but NEVER
 *      auto-synced. Edits stay where the user made them.
 *   2. Every step whose param has a known cross-mode relationship
 *      (class-1 identity-mirrored or class-2 inverse-mirrored) ships
 *      with a labelled, opt-in button below its editor.
 *   3. The button's label NAMES the operation specifically ("Copy …",
 *      "Sync inverse …") so the user reads the algebraic relationship
 *      before clicking.
 *
 * **Adding a new entry**: whenever a new step type ships whose params
 * fall in class 1 or 2, add it here AND wire its button in
 * `ParamEditor.tsx`. The enumeration test fails if you forget the
 * button — the registry is the canonical "this exists, where is the
 * UI for it?" list.
 *
 * The `groupBy` field handles ciphers like Serpent that cycle through
 * **multiple distinct S-boxes** across rounds. A Serpent leaf carries
 * `sboxIndex ∈ 0..7` and broadcasting one inverted table to every
 * `serpent.sub-bytes@1` leaf would corrupt 7/8ths of the decrypt
 * rounds. The Serpent Sync button is therefore per-leaf rather than
 * per-step-type, and the enumeration test only asserts SOME button
 * exists for the type (the per-index propagation contract is pinned
 * separately by `tests/sync-serpent-sbox-inverse.test.ts`).
 */

/** Class of cross-mode relationship — drives the button label verb. */
export type MirrorClass =
  /** Class-1: encrypt and decrypt hold the SAME value. Button verb: "Copy". */
  | "identity"
  /** Class-2: encrypt and decrypt hold algebraic inverses. Button verb: "Sync inverse". */
  | "inverse";

export type CrossModeMirrorEntry = {
  /** The step type whose params are mirrored. */
  readonly stepType: string;
  /** Which key inside `params` is the mirrored value. */
  readonly paramKey: string;
  /** Identity (copy) vs. inverse (algebraic). */
  readonly mirrorClass: MirrorClass;
  /**
   * When set, the button operates per-leaf grouped by this param key
   * rather than broadcasting across every leaf of the type. Today's
   * only user: Serpent SubBytes, grouped by `sboxIndex`.
   */
  readonly groupBy?: string;
  /**
   * For inverse-class types where the decrypt-side step type is a
   * DIFFERENT type from the encrypt-side (e.g. Serpent's
   * `serpent.sub-bytes@1` → `serpent.inv-sub-bytes@1`). Documentation
   * only — the actual write target is computed by the mutator from
   * `useMode()` and the registered counterpart spec.
   */
  readonly counterpartStepType?: string;
};

export const CROSS_MODE_MIRROR_ENTRIES: readonly CrossModeMirrorEntry[] = [
  // AES SubBytes — class-2 (inverse). Encrypt holds AES_SBOX; decrypt
  // holds AES_INV_SBOX. Mutator: `syncSboxInverseToCounterpart`.
  {
    stepType: "generic.byte-substitution@1",
    paramKey: "sbox",
    mirrorClass: "inverse",
  },

  // AES key-expansion v1 — class-1 (identity). FIPS-197 §5.2: the key
  // schedule uses the FORWARD S-box even when decrypting, so both
  // encrypt and decrypt hold AES_SBOX. Mutator:
  // `syncSboxCopyToCounterpart`.
  {
    stepType: "aes.key-expansion@1",
    paramKey: "sbox",
    mirrorClass: "identity",
  },

  // AES key-expansion v2 — same identity mirror as v1. v2 is the
  // renumber variant from the duplicate-round path (relaxed
  // `rounds === Nk + 6` assertion); shares the same `Match` arm in
  // `ParamEditor.tsx`'s `KeyExpansionBlock`, so the Copy button
  // surfaces identically.
  {
    stepType: "aes.key-expansion@2",
    paramKey: "sbox",
    mirrorClass: "identity",
  },

  // Serpent SubBytes — class-2 (inverse) with per-S-box-index grouping.
  // Serpent cycles 8 different 4-bit S-boxes (`S_0`..`S_7`) across 32
  // rounds. The button operates per-leaf, mirroring only the matching
  // sboxIndex on the counterpart side. Mutator:
  // `syncSboxInverseToCounterpartByIndex`.
  {
    stepType: "serpent.sub-bytes@1",
    paramKey: "sbox",
    mirrorClass: "inverse",
    groupBy: "sboxIndex",
    counterpartStepType: "serpent.inv-sub-bytes@1",
  },

  // AES MixColumns — class-2 (inverse). Encrypt holds `AES_MIX_MATRIX`;
  // decrypt holds its GF(2^8) inverse `AES_INV_MIX_MATRIX` (FIPS-197
  // §5.3.3). Same step type on both sides (unlike Serpent's
  // `sub-bytes@1` ↔ `inv-sub-bytes@1` split) — the round structure
  // differs between encrypt and decrypt but the executor for the matrix
  // multiplication is the same primitive. Mutator:
  // `syncMixColumnsInverseToCounterpart`; inverse computed by
  // `gfMatInverse4x4` (src/core/state/gf-matrix.ts).
  {
    stepType: "generic.mix-columns@1",
    paramKey: "matrix",
    mirrorClass: "inverse",
  },

  // Byte-native AES SubBytes (scaffolding-suppression Phase B, Slice B1.2) —
  // class-2 (inverse). The port-native rebuild of AES-128 single-block
  // (encrypt: Slice B1.1; decrypt: B1.2) carries SubBytes on the
  // `byte-substitute@1` primitive instead of the matrix
  // `generic.byte-substitution@1` lift. Encrypt holds AES_SBOX; decrypt holds
  // AES_INV_SBOX. Same `params.sbox` shape and same `syncSboxInverseToCounterpart`
  // mutator as the matrix entry — now that BOTH modes share the byte-native
  // type, the same-type broadcast lands on the decrypt counterpart (in B1 the
  // encrypt-only conversion would have made this a no-op sync button, so the
  // entry was deferred to B1.2). The matrix entry above stays for AES-192/256
  // (both modes) + ECB/CBC, which are still matrix until B1.3/B1.4.
  {
    stepType: "byte-substitute@1",
    paramKey: "sbox",
    mirrorClass: "inverse",
  },

  // Byte-native AES MixColumns (Slice B1.2) — class-2 (inverse). Encrypt holds
  // AES_MIX_MATRIX; decrypt holds its GF(2⁸) inverse AES_INV_MIX_MATRIX
  // (FIPS-197 §5.3.3). Same `params.matrix` shape and
  // `syncMixColumnsInverseToCounterpart` mutator as the matrix
  // `generic.mix-columns@1` entry above. Deferred from B1 for the same
  // both-modes-share-the-type reason as the SubBytes entry.
  {
    stepType: "gf-matrix-multiply@1",
    paramKey: "matrix",
    mirrorClass: "inverse",
  },

  // ─── Future entries land here ──────────────────────────────────────
  //
  // Speck has no entries by design — Speck is symmetric across modes by
  // construction (no S-box, no MixColumns). Hash / MAC / KDF / AEAD
  // step types that land later are sibling top types to encrypt/decrypt
  // ciphers and don't have mirror buttons; the principle degenerates to
  // "no mirror needed."
];
