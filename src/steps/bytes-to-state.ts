/**
 * bytes-to-state — port-native bridge that materializes its `input` port's
 * bytes into the runtime `state` variable (universal-port plan Phase 2
 * Slice 2.6b, 2026-05-25).
 *
 * **Why this primitive exists.** Phase 1 — Slice 2.6a's port-edge wiring
 * lets port-native leaves read each other's outputs via `portInputs`, but
 * pure port-native leaves (no `meta`) never touch the runtime's `state`
 * variable. That means a port-native chain (constant-load → pad →
 * length-append → …) can compute arbitrary bytes but those bytes only live
 * in scope-local `nodeOutputs`. The trace's `finalState` — which is what
 * KAT tests read AND what the UI's bottom pane displays as the cipher
 * output — never sees them.
 *
 * SHA-256 is the forcing case: the cipher's product is a 32-byte hash, but
 * under a pure port-native authoring style nothing in the spec would
 * update `state`. Without a terminator, `finalState` would be whatever the
 * LAST state-writing step produced (most likely the message-schedule
 * FES-with-history's 256-byte W array — not the hash).
 *
 * **How it works.** The primitive is a 1-input / 1-output identity
 * passthrough on the port layer. The load-bearing piece is
 * `ProjectionMetadata.stateOutputPort = "output"`: the runtime sees this
 * metadata on a `kind: "ported"` registration and, AFTER the executor
 * runs, copies the bytes from the named output port into `state` via
 * `portBytesToState(outBytes, "bytes")`. State becomes a fresh BytesState
 * carrying the leaf's input bytes.
 *
 * **Why expose the output port** (Slice 2.6b user pick 2026-05-25). The
 * primitive could have been registered terminal-only (sink the bytes into
 * state, emit nothing on the port layer). Exposing `output` is free —
 * the executor returns the bytes anyway — and supports a future
 * "materialize-then-keep-using" pattern where downstream leaves wire to
 * this leaf's output AND state inherits the same bytes. No 2.6b consumer
 * uses the chainable form, but the cost is zero and the extension is
 * obvious.
 *
 * **What the spec author writes.**
 *
 * ```json
 * {
 *   "kind": "step",
 *   "id": "seed-schedule",
 *   "type": "bytes-to-state@1",
 *   "params": {},
 *   "portInputs": {
 *     "input": { "node": "length-append", "port": "output" }
 *   }
 * }
 * ```
 *
 * After this leaf runs, `state` = the 64-byte padded block produced by
 * `length-append` — which is what the downstream `for-each-subgraph-with-
 * history` (message schedule) reads as its parent-scope state for seeding.
 *
 * **Port-native + meta — the hybrid registration shape.** Slice 2.1a
 * widened `StepRegistration.kind: "ported"` so `meta` AND `legacy` are
 * both optional. `bytes-to-state@1` exercises the path where `legacy` is
 * absent but `meta` is present: off-flag dispatch throws (port-native;
 * requires portedDispatchEnabled: true) and on-flag dispatch uses
 * `meta.stateOutputPort` to drive the state update. No legacy executor
 * underneath because there's no `(state, params, ctx) → result` shape
 * that maps naturally to "pure port-native + state-write hint."
 *
 * **Pairs with `state-to-bytes@1`** (this slice's sibling). state-to-
 * bytes is the inverse direction: reads parent state into an output port
 * via `meta.stateInputPort`. The two together close the loop —
 * port-native chains can both source from initial state and terminate
 * into final state.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────
// Zero params today. Reserved as `Record<string, never>` for future
// extension (e.g., a target `stateLayout` override if we ever need to
// materialize as matrix4x4-bytes — defer until a real consumer surfaces).

const readParams = (params: Json): void => {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("bytes-to-state: params must be an object (use {} for the no-op default)");
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * One polymorphic input port `input` and one polymorphic output port
 * `output`. Both `byteLength` absent — the bytes flow through unchanged,
 * length determined by the upstream wiring per the universal-port plan's
 * "polymorphic means wiring-determined" rule (Slice 1.2 user pick).
 *
 * Layout `"raw"` on both — these are byte-flat values without structural
 * interpretation. A future consumer needing matrix layout would either
 * wrap with a separate reshape step or extend this primitive's params.
 */
export const bytesToStatePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const bytesToState: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error(
      "bytes-to-state: input port 'input' is not wired (declare it in the spec node's `portInputs` map)",
    );
  }
  // Fresh Uint8Array so the runtime's state assignment doesn't alias the
  // upstream's nodeOutputs buffer (paranoia — the runtime would clone
  // again on stateBefore/stateAfter snapshots, but keeping the executor's
  // contract "every output is a fresh buffer" matches the convention every
  // other port-native primitive follows).
  const out = new Uint8Array(input.length);
  out.set(input);
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────
//
// The load-bearing field: `stateOutputPort = "output"` tells the runtime
// to copy the bytes emitted on the `output` port into `state` after the
// executor returns. Combined with `stateLayout = "bytes"`, the runtime
// constructs a fresh `BytesState` of the right length.
//
// `stateInputPort` is undefined — no parent-scope state projection. The
// executor sources its bytes entirely from the wired `input` port.
// No aux ports — this primitive doesn't read or write aux.

export const bytesToStateMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateOutputPort: "output",
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const bytesToStateDoc: StepDocumentation = {
  name: "Bytes To State",
  summary:
    "The exit point: takes the finished result and hands it back out as the cipher's output.",
  detail: `# Bytes To State

The end point of a cipher's dataflow. It takes the finished result — the
ciphertext, or a hash's digest — and hands it back out as the cipher's
output, so it shows up as the final value. It doesn't change the bytes; it
just marks them as the result.

Its partner is **State To Bytes**, which does the reverse at the start: it
brings the input data in. A dataflow typically begins with one and ends with
the other. The same step is also used to hand a computed value on to the next
stage (for example, feeding a prepared block into the rounds that follow).`,
  params: new Map([["(no params)", "This step takes no settings."]]),
};
