/**
 * Combine-kind narration — Phase 4 of `docs/plans/des-feistel.md`.
 *
 * Registers ONE narrator under the synthetic stepType `__rejoin__` (the
 * literal emitted by the runtime for every `feistel-round` rejoin frame
 * — see `src/core/runtime.ts` and `src/core/combine-kinds.ts`). The
 * narrator inspects `frame.params.combineKind` and emits per-kind prose.
 *
 * The 4-arg combine formula reads `(L_in, L_out, R_in, R_out) → (new_L,
 * new_R)`. Each kind has a different formula; the narrator displays the
 * formula, names which of the four snapshots it consumes, and explains
 * why (e.g. `feistel-standard`'s `new_L = R_in` is the textbook Feistel
 * swap, which is what makes the cipher invertible).
 *
 * **Why one narrator dispatching on `combineKind`, not one per kind**:
 * the narration registry keys on stepType (a single string). The
 * runtime emits `stepType = "__rejoin__"` for every kind, with the
 * variant carried in `params.combineKind`. Keeping the dispatch inside
 * the narrator matches the runtime's emission shape without forcing a
 * registry-shape extension; the trade-off is one slightly bigger fn
 * instead of four small ones.
 *
 * **One-sentence cross-row callout (per plan Phase 4)**: when the
 * combine kind moves bytes across tracks (anything other than the
 * trivial "L stays in L" case), the prose includes a sentence noting
 * that the next cell-hover provenance overlay may light up cells on
 * the OPPOSITE half of the state. This pre-empts a real user confusion
 * ("why does my hover cross the row?") that's expected on every Feistel
 * round body's first scrub.
 */

import { COMBINE_KINDS } from "@/core/combine-kinds";
import type { BytesState, CombineKind, TraceFrame } from "@/core/types";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

const readBytesState = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "bytes") return null;
  return (state as BytesState).bytes;
};

const readCombineKind = (params: TraceFrame["params"]): CombineKind | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, unknown>).combineKind;
  if (typeof v !== "string") return null;
  if (v in COMBINE_KINDS) return v as CombineKind;
  return null;
};

/**
 * Rejoin narrator. Always produces a single unit since the combine is
 * one logical operation, not N parallel sub-units like SubBytes or
 * AddRoundKey. The Prose body explains the combine kind in full.
 */
export const rejoinNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  const after = readBytesState(frame.stateAfter);
  if (!before || !after) return null;
  if (before.length !== after.length || before.length % 2 !== 0) return null;
  const kind = readCombineKind(frame.params);
  if (!kind) return null;

  const kindMetadata = COMBINE_KINDS[kind];
  const half = before.length / 2;
  // Pre-combine bytes are L_out || R_out (the runtime sets
  // `rejoinStateBefore = L_out concat R_out` — see runtime.ts:340-342).
  // Post-combine bytes are new_L || new_R.
  const beforeFrozen = new Uint8Array(before);
  const afterFrozen = new Uint8Array(after);

  // Cross-row callout: every shipped combine kind moves bytes across
  // halves (feistel-standard / feistel-no-swap swap halves; the
  // add-into variants modify one half from the other's output). The
  // callout is unconditional today but kept as a per-kind switch in
  // case a future identity kind ships.
  const crossRowCallout =
    "Cell-hover provenance on the next frame's state will light up cells on the OPPOSITE half — that's the swap (or cross-half mix) showing up, not a bug.";

  const unit: NarrationUnit = {
    key: `rejoin:${kind}`,
    label: `rejoin (${kind})`,
    Prose: (props) => (
      <div>
        <p>
          The Feistel round body finished both tracks; this rejoin frame combines them per the
          <code> {kind} </code>
          formula:
        </p>
        <p>
          <code>{kindMetadata.formulaText}</code>
        </p>
        <p>
          Pre-combine ({formatBytes(beforeFrozen, props.fmt)}): the first {half} bytes are L_out
          (the L track's exit value — for DES, an empty passthrough so L_out = L_in); the next{" "}
          {half} bytes are R_out (the R track's exit value, after F = P(S(E(R) ⊕ K_i))).
        </p>
        <p>
          Post-combine ({formatBytes(afterFrozen, props.fmt)}): the first {half} bytes are new_L,
          the next {half} bytes are new_R. This becomes the input state of the next round (or, on
          the last round, feeds straight into FP).
        </p>
        <p>
          <em>{crossRowCallout}</em>
        </p>
        {kind === "feistel-no-swap" && (
          <p>
            This is the textbook "no swap on the last round" exception. It's what makes DES self-
            inverse under key-reversal: with the swap on rounds 1..15 and no-swap on round 16,
            running the same body backwards with reversed round keys recovers the plaintext.
          </p>
        )}
      </div>
    ),
  };

  return [unit];
};
