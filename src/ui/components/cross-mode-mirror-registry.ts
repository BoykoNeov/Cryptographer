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

/**
 * Role-scope for a step type used in TWO mirror roles. Since the
 * key-schedule decomposition (2026-06-01), `byte-substitute@1` is BOTH
 * round-body SubBytes (class-2 inverse) AND key-schedule SubWord (class-1
 * identity — the schedule uses the FORWARD S-box even when decrypting,
 * FIPS-197 §5.2). The two roles are distinguished purely by leaf id
 * (`key-schedule.*` vs everything else of that type). `matches` is BOTH
 * the predicate ParamEditor uses to decide which button to render AND the
 * `idFilter` it passes to the mutator so the broadcast lands only on this
 * role's leaves (a type-wide broadcast would corrupt the other role).
 * `sampleLeafId` is a stable leaf id the enumeration coverage test selects.
 */
export type MirrorLeafScope = {
  readonly description: string;
  readonly matches: (leafId: string) => boolean;
  readonly sampleLeafId: string;
};

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
  /**
   * When set, this entry applies to only the SUBSET of `stepType` leaves
   * matching `leafScope.matches` — used when one step type carries two
   * mirror roles (today: `byte-substitute@1`). Absent ⇒ the entry applies
   * to every leaf of the type (the common case).
   */
  readonly leafScope?: MirrorLeafScope;
};

// ─── Leaf-id role predicates (single source of truth) ──────────────────────
// The decomposed AES key schedule is a `key-schedule` group; every leaf
// inside it has an id prefixed `key-schedule.`. That prefix is the
// discriminator between the two `byte-substitute@1` roles.

/** Id prefix carried by every leaf inside the decomposed `key-schedule` group. */
export const KEY_SCHEDULE_LEAF_PREFIX = "key-schedule.";

/** True for a key-schedule SubWord leaf (class-1 identity Copy role). */
export const isKeyScheduleLeafId = (leafId: string): boolean =>
  leafId.startsWith(KEY_SCHEDULE_LEAF_PREFIX);

/**
 * True for a round-body leaf (class-2 inverse role). Defined as "not a
 * key-schedule leaf" — correct because it is only ever applied to
 * `byte-substitute@1` leaves, whose only two homes are round-body SubBytes
 * and key-schedule SubWord.
 */
export const isRoundBodyLeafId = (leafId: string): boolean => !isKeyScheduleLeafId(leafId);

export const CROSS_MODE_MIRROR_ENTRIES: readonly CrossModeMirrorEntry[] = [
  // NOTE: the matrix `generic.byte-substitution@1` + `generic.mix-columns@1`
  // entries were REMOVED in Slice B1.4b. They described the AES SubBytes /
  // MixColumns Sync buttons on the matrix `SbxBlock` / MixColumns editors —
  // but every shipped AES (single-block B1.1–B1.3, ECB B1.4a, CBC B1.4b) is
  // byte-native now, so no shipped spec renders those matrix editors and there
  // is no selectable leaf to assert a button on. The live AES mirror surfaces
  // are the byte-native `byte-substitute@1` / `gf-matrix-multiply@1` entries
  // below. (The matrix step types stay registered for test fixtures until
  // Phase C; ParamEditor still renders the matrix editors' Sync rows
  // unconditionally — that UI is just unreachable from any shipped spec.)

  // AES key-schedule SubWord — class-1 (identity). Since the key-schedule
  // decomposition (2026-06-01) the SubWord is a `byte-substitute@1` leaf
  // inside the `key-schedule` group (id prefix `key-schedule.`), NOT a
  // monolithic `aes.key-expansion@1/@2` step. Per FIPS-197 §5.2 the schedule
  // uses the FORWARD S-box even when decrypting, so both encrypt and decrypt
  // hold AES_SBOX here — the identity Copy mirror. `leafScope` confines this
  // role (and the Copy broadcast) to the key-schedule SubWord leaves, leaving
  // the round-body SubBytes entry below to own the inverse mirror. Mutator:
  // `syncSboxCopyToCounterpart` with the `isKeyScheduleLeafId` filter.
  // (Replaces the retired `aes.key-expansion@1` + `@2` identity entries.)
  {
    stepType: "byte-substitute@1",
    paramKey: "sbox",
    mirrorClass: "identity",
    leafScope: {
      description: "key-schedule SubWord leaves (forward S-box even when decrypting)",
      matches: isKeyScheduleLeafId,
      // g1.subword exists for every AES size (≥ 1 generated group). Stable id.
      sampleLeafId: "key-schedule.g1.subword",
    },
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

  // Byte-native AES SubBytes (scaffolding-suppression Phase B, Slice B1.2) —
  // class-2 (inverse). The port-native rebuild of AES-128 single-block
  // (encrypt: Slice B1.1; decrypt: B1.2) carries SubBytes on the
  // `byte-substitute@1` primitive instead of the matrix
  // `generic.byte-substitution@1` lift. Encrypt holds AES_SBOX; decrypt holds
  // AES_INV_SBOX. Same `params.sbox` shape and same `syncSboxInverseToCounterpart`
  // mutator as the former matrix entry — now that BOTH modes share the
  // byte-native type, the same-type broadcast lands on the decrypt counterpart
  // (in B1 the encrypt-only conversion would have made this a no-op sync
  // button, so the entry was deferred to B1.2). This is the round-body AES
  // SubBytes mirror entry — every shipped AES is byte-native (B1.4b).
  // `leafScope` confines the inverse to the round-body leaves so the
  // key-schedule SubWord leaves (identity entry above) are NOT overwritten
  // with the inverse table — that would corrupt the decrypt key schedule
  // (key-schedule-decomposition K1c, 2026-06-01).
  {
    stepType: "byte-substitute@1",
    paramKey: "sbox",
    mirrorClass: "inverse",
    leafScope: {
      description: "round-body SubBytes leaves (encrypt forward / decrypt inverse)",
      matches: isRoundBodyLeafId,
      // round.1.sub-bytes is the canonical round-body SubBytes leaf on AES-128.
      sampleLeafId: "round.1.sub-bytes",
    },
  },

  // Byte-native AES MixColumns (Slice B1.2) — class-2 (inverse). Encrypt holds
  // AES_MIX_MATRIX; decrypt holds its GF(2⁸) inverse AES_INV_MIX_MATRIX
  // (FIPS-197 §5.3.3). `params.matrix` shape + `syncMixColumnsInverseToCounterpart`
  // mutator (inverse via `gfMatInverse4x4`, src/core/state/gf-matrix.ts).
  // Now the ONLY AES MixColumns mirror entry (the matrix `generic.mix-columns@1`
  // entry was removed in B1.4b). Deferred from B1 for the same
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
