/**
 * Canonical "what bytes flow into / out of this frame's state thread?"
 * accessors — the port-first reading of a trace frame's primary dataflow.
 *
 * **Why this exists (Phase 5 Slice 5.3c).** The legacy `TraceFrame.stateBefore`
 * / `stateAfter` fields are scheduled for removal in Slice 5.3e (see
 * `docs/plans/phase-5-legacy-retirement.md`). Every value/narration consumer
 * that today reads those fields to surface "the state at this step" must read
 * the port I/O instead, so the deletion only has to drop a fallback rather
 * than rewrite every reader. This module is that single migration point.
 *
 * **The reading.** A port-flow leaf carries its honest per-step bytes on
 * `portInputs` / `portOutputs` (captured by the runtime for any leaf whose
 * registration has `legacy === undefined`). Every shipped cipher's
 * state-carrying leaf — AES / Speck / Serpent / DES round bodies, the padding
 * family — names that port `"state"`, so `portOutputs.get("state")` is
 * byte-identical to today's `stateAfter.bytes` (the runtime reconstructs the
 * threaded `state` FROM that same output port; see `runtime.ts:799-807`).
 *
 * **Why the fallback is still here.** Two frame kinds carry NO port I/O and
 * fall through to the legacy field:
 *   - SHA-256's pure port-native leaves leave `state` a passthrough (no
 *     `"state"` port at all) — `stateBefore === stateAfter`, the static seed.
 *   - the lifted-legacy `feistel.toy-add-k@1` toy frame (test-only).
 * Both are byte-identical to pre-5.3c behavior. The fallback retires in 5.3e
 * along with the fields and the toy; until then it keeps every reader
 * byte-stable and lets the migration land without a behavior change. (DES's
 * B4 rebuild shipped this exact pattern privately in `narration/des.tsx`;
 * 5.3c lifts it here so every consumer shares one definition.)
 *
 * Returns `null` when neither a `"state"` port nor a bytes state field is
 * available — call sites treat that as "no value to show" (a `"missing"`
 * inspector row / an empty thumbnail). Today that only happens for genuinely
 * port-less frames; after 5.3e it becomes the normal "this leaf has no state
 * port" answer.
 */

import type { TraceFrame } from "./types";

/** The conventional port name every state-threading leaf uses for its
 *  primary in/out byte payload. */
const STATE_PORT = "state";

/**
 * Bytes flowing INTO this frame's state thread: the `"state"` input port if
 * the frame captured one, else the legacy `stateBefore` field (retired 5.3e).
 */
export const frameStateInBytes = (frame: TraceFrame): Uint8Array | null => {
  const fromPort = frame.portInputs?.get(STATE_PORT);
  if (fromPort !== undefined) return fromPort;
  return frame.stateBefore.bytes;
};

/**
 * Bytes flowing OUT of this frame's state thread: the `"state"` output port
 * if the frame captured one, else the legacy `stateAfter` field (retired
 * 5.3e). This is "the state after the step ran" for every value/thumbnail
 * surface.
 */
export const frameStateOutBytes = (frame: TraceFrame): Uint8Array | null => {
  const fromPort = frame.portOutputs?.get(STATE_PORT);
  if (fromPort !== undefined) return fromPort;
  return frame.stateAfter.bytes;
};
