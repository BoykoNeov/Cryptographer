/**
 * Canonical "what bytes flow into / out of this frame's state thread?"
 * accessors — the port-first reading of a trace frame's primary dataflow.
 *
 * **Why this exists (Phase 5 Slice 5.3c → finalized 5.3e Batch 4).** The
 * legacy `TraceFrame.stateBefore` / `stateAfter` State snapshots were retired
 * in Slice 5.3e Batch 4 (see `docs/plans/phase-5-legacy-retirement.md`). Every
 * value/narration consumer reads the port I/O through this single accessor, so
 * the field deletion only had to drop the fallback below rather than rewrite
 * every reader.
 *
 * **The reading.** A port-flow leaf carries its honest per-step bytes on
 * `portInputs` / `portOutputs` (captured by the runtime for any leaf whose
 * registration has `legacy === undefined`). Every shipped cipher's
 * state-carrying leaf — AES / Speck / Serpent / DES round bodies, the padding
 * family — names that port `"state"`, so `portOutputs.get("state")` is the
 * honest "state after the step ran."
 *
 * **No state port → no reading.** Leaves with no `"state"` port return `null`:
 * SHA-256's pure port-native primitives (their payloads ride `output`/`input`/
 * `a`/… ports the cipher-agnostic surfaces don't know to name), native-AES
 * `xor`/`byte-substitute`, DES `split-bytes`/`xor`/`concat`. Call sites treat
 * `null` as "no value to show" — a `"missing"` inspector row / an empty
 * thumbnail / "(no state)" on the step strip. This is the user-accepted
 * Batch-4 regression: those bytes are still visible in `PortFlowView` (which
 * reads the real ports by name), just not on the `"state"`-keyed shortcut
 * surfaces. The deferred port-aware inspector (Slice 2.9c-e) resolves each
 * leaf's real output port by name and removes the gap.
 */

import type { TraceFrame } from "./types";

/** The conventional port name every state-threading leaf uses for its
 *  primary in/out byte payload. */
const STATE_PORT = "state";

/**
 * Bytes flowing INTO this frame's state thread: the `"state"` input port if
 * the frame captured one, else `null` (the leaf has no state-keyed input).
 */
export const frameStateInBytes = (frame: TraceFrame): Uint8Array | null => {
  return frame.portInputs?.get(STATE_PORT) ?? null;
};

/**
 * Bytes flowing OUT of this frame's state thread: the `"state"` output port if
 * the frame captured one, else `null` (the leaf has no state-keyed output).
 * This is "the state after the step ran" for every value/thumbnail surface.
 */
export const frameStateOutBytes = (frame: TraceFrame): Uint8Array | null => {
  return frame.portOutputs?.get(STATE_PORT) ?? null;
};
