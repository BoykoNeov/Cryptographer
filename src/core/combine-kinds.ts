/**
 * Combine-kind metadata for the Feistel branching primitive (Phase 2 of
 * `docs/plans/des-feistel.md`).
 *
 * `CombineKind` is declared as a string-literal union in `core/types.ts`;
 * this file carries the per-kind metadata the runtime + UI need:
 *
 *   - `apply(L_in, L_out, R_in, R_out) → { new_L, new_R }`. The 4-arg shape
 *     is documented on `CombineKind` itself. The runtime calls this once
 *     per `feistel-round` to compute the round's combined output.
 *   - `inspectorRowOrder`: ordering for the 4 snapshots in the rejoin
 *     inspector. Matches the kind's formula left-to-right for reading-
 *     order readability (per Phase 2 plan, "Layer 0 — inspector row order").
 *   - `formulaText`: human-readable formula shown at the top of the rejoin
 *     inspector / narration. Driven from data so a new kind doesn't need a
 *     UI patch beyond an entry here.
 *
 * Today's kinds support `tracks.length === 2` only (L, R). N-way variants
 * (Twofish 4-way) would add their own `CombineKind` entries with N-tuple
 * outputs; the runtime's `applyCombine` signature widens accordingly when
 * that lands. Out of scope for Phase 2.
 *
 * Why this lives in core, not ui/: the runtime calls `apply` to produce
 * the combined state for the rejoin frame. The inspector + narration
 * read the metadata for display. Keeping it next to the executor contract
 * matches `core/registry.ts`'s pattern of co-locating executor + doc.
 */

import type { CombineKind } from "./types";

/** Bytes from one track's input/output snapshot. */
export type TrackSnapshot = Uint8Array;

/** Result of applying a combine over 2-track inputs. */
export type CombineResult = {
  /** New bytes for track 0 (the L track by DES convention). */
  readonly new_L: Uint8Array;
  /** New bytes for track 1 (the R track by DES convention). */
  readonly new_R: Uint8Array;
};

/** Ordering for the 4 snapshots in the rejoin inspector. */
export type SnapshotKey = "L_in" | "L_out" | "R_in" | "R_out";

export type CombineKindMetadata = {
  /** Runtime apply: combine the 4 snapshots into the round's output state. */
  readonly apply: (
    L_in: TrackSnapshot,
    L_out: TrackSnapshot,
    R_in: TrackSnapshot,
    R_out: TrackSnapshot,
  ) => CombineResult;
  /**
   * Snapshot ordering for the rejoin inspector. Reading-order, not track-
   * name-order — for `feistel-standard` the formula `new_L = R_in,
   * new_R = L_in XOR R_out` reads R_in first, then L_in + R_out (in pair),
   * then L_out at the end as the "unused" slot.
   */
  readonly inspectorRowOrder: readonly [SnapshotKey, SnapshotKey, SnapshotKey, SnapshotKey];
  /** Formula text shown in inspector + narration. */
  readonly formulaText: string;
  /**
   * Whether the kind reads `L_out` (the post-track-body L value) when
   * combining. Used by the inspector to render unused snapshots in muted
   * style ("the L track ran its body; the output is available but this
   * combine doesn't use it"). True for the `add-into-right` kind (which
   * adds L_out into R); false for the other three.
   */
  readonly usesLOut: boolean;
  /**
   * Whether the kind reads `R_out` (the post-F R value). True for
   * `feistel-standard`, `feistel-no-swap`, and `feistel-add-into-left`;
   * false for `feistel-add-into-right`. (Symmetry of the muted-style
   * "unused" indicator.)
   */
  readonly usesROut: boolean;
};

const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  // a + b must be equal length; the runtime guarantees this via
  // BranchTrack.inputBytes declaration consistency.
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    // Non-null assertions on .at() are safer than [i] here under
    // noUncheckedIndexedAccess; both paths require an existence check.
    // Direct indexing is fine since we just allocated `a.length` and
    // loop within it.
    out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return out;
};

const addModulo256 = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = ((a[i] ?? 0) + (b[i] ?? 0)) & 0xff;
  }
  return out;
};

export const COMBINE_KINDS: { readonly [K in CombineKind]: CombineKindMetadata } = {
  // new_L = R_in
  // new_R = L_in XOR R_out
  // Used by classic Feistel rounds 1..N-1 (DES rounds 1..15, TEA cycles
  // when expressed as two half-rounds).
  "feistel-standard": {
    apply: (L_in, _L_out, R_in, R_out) => ({
      new_L: new Uint8Array(R_in),
      new_R: xor(L_in, R_out),
    }),
    inspectorRowOrder: ["R_in", "L_in", "R_out", "L_out"],
    formulaText: "new_L = R_in,  new_R = L_in ⊕ R_out",
    usesLOut: false,
    usesROut: true,
  },
  // new_L = L_in XOR R_out
  // new_R = R_in
  // The textbook "no swap on last round" exception. DES round 16; makes
  // the cipher its own inverse under key-reversal.
  "feistel-no-swap": {
    apply: (L_in, _L_out, R_in, R_out) => ({
      new_L: xor(L_in, R_out),
      new_R: new Uint8Array(R_in),
    }),
    inspectorRowOrder: ["L_in", "R_out", "R_in", "L_out"],
    formulaText: "new_L = L_in ⊕ R_out,  new_R = R_in",
    usesLOut: false,
    usesROut: true,
  },
  // new_L = L_in + R_out (per-byte mod 256)
  // new_R = R_in
  // TEA's "add into left" half-cycle.
  "feistel-add-into-left": {
    apply: (L_in, _L_out, R_in, R_out) => ({
      new_L: addModulo256(L_in, R_out),
      new_R: new Uint8Array(R_in),
    }),
    inspectorRowOrder: ["L_in", "R_out", "R_in", "L_out"],
    formulaText: "new_L = L_in + R_out (mod 256),  new_R = R_in",
    usesLOut: false,
    usesROut: true,
  },
  // new_L = L_in
  // new_R = R_in + L_out (per-byte mod 256)
  // TEA's "add into right" half-cycle.
  "feistel-add-into-right": {
    apply: (_L_in, L_out, R_in, _R_out) => ({
      new_L: new Uint8Array(_L_in),
      new_R: addModulo256(R_in, L_out),
    }),
    inspectorRowOrder: ["R_in", "L_out", "L_in", "R_out"],
    formulaText: "new_L = L_in,  new_R = R_in + L_out (mod 256)",
    usesLOut: true,
    usesROut: false,
  },
};

/** Synthetic stepType used on rejoin frames. Analog of `__endpoint__`
 *  in `core/graph.ts` — never registered with an executor; renderers
 *  + narration / provenance registries dispatch off the literal. */
export const REJOIN_STEP_TYPE = "__rejoin__";
