/**
 * Canonical "what bytes flow into / out of this frame as its primary payload?"
 * accessors — the port-first reading of a trace frame's primary dataflow,
 * used by every cipher-agnostic value surface (graph value inspector, step
 * strip thumbnails, RunExplorer tiles, per-cipher narration).
 *
 * **Why this exists (Phase 5 Slice 5.3c → finalized 5.3e Batch 4).** The
 * legacy `TraceFrame.stateBefore` / `stateAfter` State snapshots were retired
 * in Slice 5.3e Batch 4 (see `docs/plans/phase-5-legacy-retirement.md`). Every
 * value/narration consumer reads the port I/O through this single accessor, so
 * the field deletion only had to drop the State fallback rather than rewrite
 * every reader.
 *
 * **Port resolution (Slice 2.9c-e, the "honest close").** A port-flow leaf
 * carries its honest per-step bytes on `portInputs` / `portOutputs` (captured
 * by the runtime for any leaf whose registration has `legacy === undefined`).
 * The resolution order is:
 *
 *   1. The conventional `"state"` port — every hybrid-ported state-threading
 *      leaf (AES/Speck/Serpent/DES round bodies under `meta`, the padding
 *      family) names its primary payload `"state"`, so this branch keeps those
 *      surfaces byte-identical to the pre-5.3e `stateAfter` read. Zero risk.
 *   2. The SOLE port, when the leaf declares exactly one. Pure port-native
 *      primitives name their single output `"output"` (and single input
 *      `"input"`): `byte-substitute` / `permute` / `gf-matrix-multiply` /
 *      `xor-with-aux` / `rotate-bits-right` / `xor` / `add-mod-32` / `concat`
 *      all have one output; native-AES + SHA-256 leaves land here. This is the
 *      branch that repaired the Batch-4 "(no state)" regression: those leaves
 *      have no `"state"` port but an unambiguous single output.
 *   3. Otherwise `null` — the leaf is genuinely many-ported on this side, so
 *      there is no single representative payload. OUTPUT-side this is only
 *      `split-bytes` (output0..N); INPUT-side it is every fan-in leaf
 *      (`xor`/`add-mod-32`/`concat`/`xor-with-aux` read N operands). Call
 *      sites treat `null` as "no single value to show" — a `"missing"`
 *      inspector row / empty thumbnail / "(no state)" tile. The full per-port
 *      breakdown is always available in `PortFlowView` (which reads every port
 *      by name).
 *
 * **Failure mode is "missing", never a wrong value.** The `"state"`-first
 * branch is untouched, the sole-port branch is unambiguous, and everything
 * else returns `null` — so no surface can ever show a misattributed byte.
 *
 * The cell-level provenance HOVER that an earlier draft of Slice 2.9c-e
 * proposed was formally deferred (see the slice plan): the graph already
 * answers port-level provenance, and with these helpers honest the value
 * inspector does too.
 */

import type { TraceFrame } from "./types";

/** The conventional port name every state-threading (hybrid-ported) leaf uses
 *  for its primary in/out byte payload. Checked first so those surfaces stay
 *  byte-identical to the pre-5.3e `stateAfter`/`stateBefore` reads. */
const STATE_PORT = "state";

/** First (only) value of a single-entry map, or null when the map is absent
 *  or has 0 / ≥2 entries — the "exactly one port → unambiguous" rule. */
const soleValue = (m: ReadonlyMap<string, Uint8Array> | undefined): Uint8Array | null => {
  if (m === undefined || m.size !== 1) return null;
  for (const v of m.values()) return v;
  return null;
};

/**
 * Bytes flowing OUT as this frame's primary payload: the `"state"` output port
 * if present, else the sole output port when there's exactly one, else `null`.
 * This is "the value the step produced" for every cipher-agnostic value
 * surface. Returns `null` for multi-output leaves (`split-bytes`) — inspect
 * the individual ports in `PortFlowView`.
 */
export const framePrimaryOutBytes = (frame: TraceFrame): Uint8Array | null => {
  return frame.portOutputs?.get(STATE_PORT) ?? soleValue(frame.portOutputs);
};

/**
 * Bytes flowing IN as this frame's primary payload: the `"state"` input port
 * if present, else the sole input port when there's exactly one, else `null`.
 * Symmetric to {@link framePrimaryOutBytes}, but note the input side is
 * intrinsically less resolvable — every fan-in leaf (`xor`/`add-mod-32`/
 * `concat`/`xor-with-aux`) reads multiple operands and so returns `null` here.
 */
export const framePrimaryInBytes = (frame: TraceFrame): Uint8Array | null => {
  return frame.portInputs?.get(STATE_PORT) ?? soleValue(frame.portInputs);
};
