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

  // ─── Future entries land here ──────────────────────────────────────
  //
  // Slice 5 adds `generic.mix-columns@1` (`matrix`, inverse-mirror) when
  // the GF(2^8) Gauss-Jordan inverter ships. Speck has no entries by
  // design — Speck is symmetric across modes by construction (no S-box,
  // no MixColumns). Hash / MAC / KDF / AEAD step types that land later
  // are sibling top types to encrypt/decrypt ciphers and don't have
  // mirror buttons; the principle degenerates to "no mirror needed."
];
