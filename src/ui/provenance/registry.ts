/**
 * Cell-level provenance registry. Phase 3 of the linear-mode pedagogy plan
 * (~/.claude/plans/immutable-doodling-quokka.md).
 *
 * Maps step types to per-step "where did THIS output cell come from?"
 * functions. The MatrixView's hover handler reads from this registry to
 * highlight the contributing cells in `before` (and / or in the round-key
 * panel) when the user hovers an `after` cell.
 *
 * Architectural decision (advisor-flagged): this is a *parallel* registry,
 * NOT a new field on `StepDocumentation`. The two registries answer
 * different questions:
 *
 *   - Step registry (`src/core/registry.ts`) — runtime: "how does this
 *     step execute? what does its doc panel say?"
 *   - This registry — navigation: "for visualization, which cells feed
 *     which output cell?"
 *
 * Keeping them separate means a runtime-only refactor doesn't reach into
 * pedagogy code (and vice versa). A new cipher with novel cell shapes
 * (e.g. bit-level) can register its own provenance fn without touching
 * the core step registration path.
 *
 * Coverage in initial slice:
 *   - AES: SubBytes, ShiftRows, MixColumns, AddRoundKey (forward AND
 *     inverse — the underlying generic.* step types are param-driven,
 *     so one provenance fn per step type handles both directions).
 *   - Serpent: AddRoundKey, SubBytes.
 *
 * Out of scope for v1: bit-level Serpent steps (linear-transform,
 * inv-linear-transform, bit-permutation). Byte-approximation is doable
 * but pedagogically muddled — each output bit derives from 6–7 input
 * bits, so byte-level highlights would say "everything contributes to
 * everything" which isn't useful. Flag in the no-provenance allowlist.
 *
 * A contract test (`tests/provenance-registry-contract.test.ts`) walks
 * the core registry and asserts every shipped matrix-shape AND
 * bytes-shape step type EITHER has a provenance fn here OR sits on the
 * explicit allowlist — so a future cipher addition can't silently slip
 * past with no hover support.
 */

import type { AuxValue, TraceFrame } from "@/core/types";

/**
 * One contributing source for one output cell. Discriminated union so the
 * UI can decide which surface to render the highlight on:
 *
 *   - `kind: "before-cell"` — highlight `before` cell at `index` in
 *      the same MatrixView (or BytesView).
 *   - `kind: "aux-cell"` — highlight cell at `index` of the named aux
 *      buffer in the RoundKeyPanel.
 *
 * `label` is an optional annotation (e.g. the GF(2^8) coefficient `0x02`
 * for a MixColumns contributor) the UI can show in a tooltip.
 */
export type ProvenanceSource =
  | {
      readonly kind: "before-cell";
      readonly index: number;
      readonly label?: string;
    }
  | {
      readonly kind: "aux-cell";
      readonly auxName: string;
      readonly index: number;
      readonly label?: string;
    };

/**
 * Per-step provenance function. Takes the trace frame and a 0-based
 * linear index into `stateAfter.bytes`, returns the list of cells that
 * contributed to it.
 *
 * Returns an empty array for indices outside the byte-range of the
 * state (defensive — callers shouldn't pass invalid indices but the
 * registry stays robust). Returning [] from any step type is also a
 * valid statement of "no provenance to surface here" without throwing.
 *
 * Frame is passed in full so the fn can read `frame.params` (ShiftRows
 * shift table, MixColumns matrix coefficients) and `frame.auxRead`
 * (AddRoundKey's consumed `roundKey.N` aux name).
 */
export type ProvenanceFn = (
  frame: TraceFrame,
  afterCellIndex: number,
) => readonly ProvenanceSource[];

const REGISTRY = new Map<string, ProvenanceFn>();

/**
 * Register a provenance function for a step type. Throws on duplicate
 * registration so the contract test catches accidental double-registers
 * (the same accident that would shadow one cipher's fn with another).
 */
export const registerProvenance = (stepType: string, fn: ProvenanceFn): void => {
  if (REGISTRY.has(stepType)) {
    throw new Error(`provenance: step type "${stepType}" is already registered`);
  }
  REGISTRY.set(stepType, fn);
};

/**
 * Look up a provenance function. Returns null when none is registered —
 * callers should treat that as "hover does nothing for this step."
 * Graceful absence is the v1 contract; the contract test enforces that
 * every shapeContract-matrix4x4 or shapeContract-bytes step has either
 * a fn here OR an entry on the allowlist.
 */
export const lookupProvenance = (stepType: string): ProvenanceFn | null =>
  REGISTRY.get(stepType) ?? null;

/**
 * Step types that *intentionally* have no provenance fn. Two categories:
 *
 *   1. Bit-level transformations where a byte-level highlight would be
 *      misleading (Serpent linear-transform / inv-linear-transform /
 *      bit-permutation — each output bit derives from 6–7 input bits;
 *      byte-level "everything contributes to everything" is noise).
 *   2. Boundary / shape-shifter steps (load-block, store-block,
 *      split-blocks, concat-blocks) whose before/after shapes differ
 *      and don't have a meaningful cell-to-cell correspondence.
 *   3. Padding step types (pkcs7/zero/iso7816-4 pad+unpad) where the
 *      provenance is "all input bytes pass through" — uninformative.
 *   4. Aux primitives (aux-load, aux-xor, aux-copy, iv-load,
 *      xor-aux-into-state, state-to-aux, compute-block-count) whose
 *      operations are aux-routed rather than per-cell.
 *
 * Adding an entry here is a deliberate "we considered it and it's not
 * worth a provenance fn" — NOT "we forgot to write one." The contract
 * test enforces that every step type in the core registry is either
 * provenance-registered or here.
 */
export const PROVENANCE_NO_OP_ALLOWLIST: ReadonlySet<string> = new Set([
  // Bit-level (byte-approximation too noisy)
  "serpent.linear-transform@1",
  "serpent.inv-linear-transform@1",
  "serpent.bit-permutation@1",
  // Aux primitives & boundary steps
  "generic.aux-load@1",
  "generic.aux-xor@1",
  "generic.aux-copy@1",
  "generic.iv-load@1",
  "generic.xor-aux-into-state@1",
  "generic.state-to-aux@1",
  "generic.load-block@1",
  "generic.store-block@1",
  "generic.split-blocks@1",
  "generic.concat-blocks@1",
  "generic.compute-block-count@1",
  // Padding family
  "generic.pkcs7-pad@1",
  "generic.pkcs7-unpad@1",
  "generic.zero-pad@1",
  "generic.zero-unpad@1",
  "generic.iso7816-4-pad@1",
  "generic.iso7816-4-unpad@1",
  // Key-expansion (state pass-through, doesn't make sense to hover an
  // unchanged "after" cell and ask where it came from)
  "aes.key-expansion@1",
  "aes.key-expansion@2",
  "serpent.key-expansion@1",
  "speck.key-schedule@1",
  // Speck round (ARX over a 4-byte word — byte-level provenance is
  // muddled by the modular arithmetic; revisit when we add cell-level
  // hover to BytesView for Speck)
  "speck.round@1",
  "speck.round-inverse@1",
  // Phase 2 of the DES + branching primitive plan — toy F used only by
  // `tests/feistel-primitive.test.ts`. Never user-visible (the toy spec
  // is not in the cipher selector), so no cell-hover provenance is
  // needed. Removed when the toy is decommissioned.
  "feistel.toy-add-k@1",
  // SHA-256 coarse-granularity helpers (universal-port plan Phase 2
  // Slice 2.6b, 2026-05-25). Each helper executes one mathematically
  // dense operation (W_t recurrence, 32-bit working-variable shuffle, or
  // per-word modular add) over a wide state buffer (4..288 bytes). A
  // per-byte provenance view would either:
  //   (a) be vacuous — every output byte technically depends on every
  //       input byte for σ0/σ1/Σ0/Σ1, defeating the "where did this
  //       come from" pedagogy; or
  //   (b) require cipher-specific bit-level provenance fns that don't
  //       fit the per-byte ProvenanceCell shape today.
  //
  // Cipher-specific provenance lands in Slice 2.6d (post-decomposition,
  // where each rotate/xor/and/not chip has clear cell-level provenance).
  // The Slice 2.5 sha256-helpers + sha256-message-schedule tests pin the
  // math at the right granularity for now; the live inspector falls back
  // to default doc/narration for these leaves.
  "sha2.message-schedule-step@1",
  "sha2.compression-round@1",
  "sha2.final-add@1",
]);

/**
 * Predicate variant of the lookup. Cheap O(1).
 */
export const hasProvenanceFn = (stepType: string): boolean => REGISTRY.has(stepType);

/**
 * Pick the aux name a frame consumed under a given naming convention.
 * Used by AddRoundKey's provenance fn: the frame's `auxRead` Map carries
 * the snapshot keyed by aux name (e.g. "roundKey.3"). The fn needs to
 * know WHICH aux name the executor consumed to surface the right
 * round-key panel cell.
 *
 * Defensive: returns null if auxRead has zero or more-than-one entries.
 * Forward/inverse AddRoundKey both read exactly one aux per frame so
 * this branch is the common case.
 */
export const singleAuxNameFromFrame = (frame: TraceFrame): string | null => {
  const keys = Array.from(frame.auxRead.keys());
  return keys.length === 1 ? (keys[0] ?? null) : null;
};

/**
 * Resolve the byte length of a frame's named aux entry. Used by
 * AddRoundKey to validate the aux Uint8Array is shape-compatible
 * before emitting a same-position provenance source.
 */
export const auxLengthFromFrame = (frame: TraceFrame, auxName: string): number | null => {
  const v: AuxValue | undefined = frame.auxRead.get(auxName);
  if (!(v instanceof Uint8Array)) return null;
  return v.length;
};

/** Internal: clear the registry. Test-only. */
export const __resetProvenanceForTests = (): void => {
  REGISTRY.clear();
};
