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
 * Non-AES ciphers (Speck32/64) only support "single-block" today. The
 * defaults table records this with a partial inner record, and
 * `resolveDefault` falls back to single-block if a requested mode is
 * missing for the active cipher. That fallback lets the user pick "ECB"
 * for AES-128, then flip cipher to Speck without crashing — they just
 * land back in single-block on the Speck side.
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
import { blowfishSpec } from "@/ciphers/blowfish";
import { blowfishDecryptSpec } from "@/ciphers/blowfish-decrypt";
import { desSpec } from "@/ciphers/des";
import { desDecryptSpec } from "@/ciphers/des-decrypt";
import { rsaDecryptSpec, rsaEncryptSpec } from "@/ciphers/rsa";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { serpent128DecryptSpec } from "@/ciphers/serpent-128-decrypt";
import { serpent192Spec } from "@/ciphers/serpent-192";
import { serpent192DecryptSpec } from "@/ciphers/serpent-192-decrypt";
import { serpent256Spec } from "@/ciphers/serpent-256";
import { serpent256DecryptSpec } from "@/ciphers/serpent-256-decrypt";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
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
} from "./cipher";
import {
  type CipherMode,
  isCipherModeSupported,
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

// 3D table of canonical specs: defaults[cipher][cipherMode][mode]. The
// inner per-cipherMode record is partial — Speck only supports
// single-block today; AES-128 ships single-block + ecb in Phase 1, with
// cbc/ctr arriving in later phases.
const defaults: Record<Cipher, Partial<Record<CipherMode, Record<Mode, CipherSpec>>>> = {
  "aes-128": {
    "single-block": { encrypt: aes128Spec, decrypt: aes128DecryptSpec },
    ecb: { encrypt: aes128EcbSpec, decrypt: aes128EcbDecryptSpec },
    cbc: { encrypt: aes128CbcSpec, decrypt: aes128CbcDecryptSpec },
  },
  "aes-192": {
    "single-block": { encrypt: aes192Spec, decrypt: aes192DecryptSpec },
  },
  "aes-256": {
    "single-block": { encrypt: aes256Spec, decrypt: aes256DecryptSpec },
  },
  "speck-32-64-be": {
    "single-block": { encrypt: speck32_64BeSpec, decrypt: speck32_64BeDecryptSpec },
  },
  "speck-32-64-le": {
    "single-block": { encrypt: speck32_64LeSpec, decrypt: speck32_64LeDecryptSpec },
  },
  "serpent-128": {
    "single-block": { encrypt: serpent128Spec, decrypt: serpent128DecryptSpec },
  },
  "serpent-192": {
    "single-block": { encrypt: serpent192Spec, decrypt: serpent192DecryptSpec },
  },
  "serpent-256": {
    "single-block": { encrypt: serpent256Spec, decrypt: serpent256DecryptSpec },
  },
  // DES — first Feistel cipher (Phase 4 of `docs/plans/des-feistel.md`).
  // Single-block only; multi-block modes need block-size-aware load/store.
  des: {
    "single-block": { encrypt: desSpec, decrypt: desDecryptSpec },
  },
  // Blowfish — second Feistel cipher (`docs/plans/blowfish.md`). Single-block
  // only; decrypt is the same network with the P-array reversed.
  blowfish: {
    "single-block": { encrypt: blowfishSpec, decrypt: blowfishDecryptSpec },
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
  const forCipherMode = byMode[cipherMode] ?? byMode["single-block"];
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
const hashDefaults: Record<Hash, CipherSpec> = {
  "sha-256": buildSha256Spec(),
};

/**
 * Pick the canonical hash spec for a `Hash` variant. Mirrors
 * `resolveDefault` for ciphers — kept separate because the (mode,
 * cipherMode, padding) axes don't apply to hashes.
 */
const resolveHashDefault = (hash: Hash): CipherSpec => hashDefaults[hash];

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

const buildCanonicalPair = (
  cipher: Cipher,
  cipherMode: CipherMode,
  scheme: PaddingScheme,
): SpecsByMode => ({
  kind: "cipher",
  encrypt: applyPaddingScheme(resolveDefault(cipher, cipherMode, "encrypt"), "encrypt", scheme),
  decrypt: applyPaddingScheme(resolveDefault(cipher, cipherMode, "decrypt"), "decrypt", scheme),
});

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
    setCipherModeSignal("single-block");
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
  updateBoth((s, m) => applyPaddingScheme(s, m, scheme));
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
      setCipherModeSignal("single-block");
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
  );
  return !deepEqualJson(activeSpec(), canonical);
};

/** Test-only reset; production code uses the setters above. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  const scheme = usePaddingScheme()();
  setSpecs({
    kind: "cipher",
    encrypt: applyPaddingScheme(aes128Spec, "encrypt", scheme),
    decrypt: applyPaddingScheme(aes128DecryptSpec, "decrypt", scheme),
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
