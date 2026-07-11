/**
 * state-to-bytes — port-native bridge that exposes the runtime `state`
 * variable as bytes on an output port (universal-port plan Phase 2
 * Slice 2.6b, 2026-05-25).
 *
 * **Why this primitive exists.** Symmetric counterpart to
 * `bytes-to-state@1`. A port-native chain that wants to operate on the
 * cipher's initial plaintext (which the runtime delivers via
 * `RuntimeInput.initialState`) needs an entry point — pure port-native
 * leaves can't read from `state` because they don't have meta-driven
 * state projection. Without an entry bridge, the FIRST leaf in a SHA-256
 * spec (`pad-with-byte@1`) would have no way to source its input.
 *
 * **How it works.** The primitive is a 1-input / 1-output identity
 * passthrough on the port layer. The load-bearing piece is
 * `ProjectionMetadata.stateInputPort = "state"`: the runtime sees this
 * metadata on a `kind: "ported"` registration and, BEFORE the executor
 * runs, projects parent-scope state bytes into the "state" input port
 * via `stateToPortBytes(state, "bytes")`. The executor then sees an
 * `inputs` map with key `"state"` containing the state bytes, and emits
 * those bytes verbatim on the `output` port for downstream consumers.
 *
 * Q-edges-3 user pick allows portInputs to OVERRIDE the state projection
 * on a per-port basis: a spec author who wanted to reuse this leaf in
 * a non-initial-state context could wire the `state` input port via
 * portInputs and bypass the projection entirely. Today's only consumer
 * uses the natural projection.
 *
 * **What the spec author writes.**
 *
 * ```json
 * {
 *   "kind": "step",
 *   "id": "src",
 *   "type": "state-to-bytes@1",
 *   "params": {}
 * }
 * ```
 *
 * No `portInputs` map — the runtime projects parent state into the
 * `state` input port automatically. After the leaf runs, `state` is
 * unchanged (no `meta.stateOutputPort`) and downstream consumers can
 * wire `{ node: "src", port: "output" }`.
 *
 * **Port-native + meta — the hybrid registration shape.** Same shape as
 * `bytes-to-state@1`'s sibling. `meta` present, `legacy` absent. Off-flag
 * dispatch throws; on-flag dispatch uses `meta.stateInputPort` to drive
 * the state read.
 *
 * **Trade with naming.** The input port is named "state" (matching the
 * existing lifted-legacy convention for state-thread input ports in
 * `aux-load`, `byte-substitution`, etc.). The output port is named
 * "output" (matching the port-native convention for single-output
 * primitives in `rotate-bits-right`, `xor`, `constant-load`). Asymmetric
 * but each side matches its own family's convention.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

const readParams = (params: Json): void => {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("state-to-bytes: params must be an object (use {} for the no-op default)");
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * One polymorphic input port `state` (sourced via meta.stateInputPort)
 * and one polymorphic output port `output`. Length flows through —
 * `output.byteLength === state.byteLength`. Layout `"raw"` on both.
 *
 * Why "state" not "input" as the input port name: matches the existing
 * lifted-legacy convention where the state-projecting port is named
 * "state" (see `aux-load.ts`, `byte-substitution.ts`, every shipped
 * lifted-legacy step). The runtime's projection mechanism inspects
 * `meta.stateInputPort` to find which port to fill from state, so the
 * name is purely convention — but uniformity helps readers.
 */
export const stateToBytesPortContract: PortContract = {
  inputs: new Map([["state", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const stateToBytes: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const stateBytes = inputs.get("state");
  if (stateBytes === undefined) {
    throw new Error(
      "state-to-bytes: input port 'state' is not wired (it should be auto-projected from parent-scope state by the runtime — check meta.stateInputPort)",
    );
  }
  // Fresh Uint8Array — match `bytes-to-state` and every port-native
  // primitive's "outputs own their buffers" convention.
  const out = new Uint8Array(stateBytes.length);
  out.set(stateBytes);
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────
//
// The load-bearing field: `stateInputPort = "state"` tells the runtime
// to project parent-scope state bytes into the `state` input port before
// the executor runs. Combined with `stateLayout = "bytes"`, the runtime
// uses `stateToPortBytes(state, "bytes")` which (post-Slice-2.0b-ii
// option C) accepts any non-bigint State variant by reading `.bytes`
// directly.
//
// `stateOutputPort` is undefined — no state write. The leaf is a pure
// reader from state's perspective.

export const stateToBytesMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const stateToBytesDoc: StepDocumentation = {
  name: "State To Bytes",
  summary:
    "The entry point: takes the incoming data (plaintext or message) and hands it to the first step.",
  detail: `# State To Bytes

The starting point of a cipher's dataflow. It takes the data being processed
— the plaintext or message you entered — and makes it available for the first
real step to read. It doesn't change anything; it just hands the input over so
the chain of steps has somewhere to begin.

Its partner is **Bytes To State**, which does the reverse at the end: it
takes the final result and hands it back out as the cipher's output. One
brings the data in, the other sends it out.`,
  params: new Map([["(no params)", "This step takes no settings."]]),
};
