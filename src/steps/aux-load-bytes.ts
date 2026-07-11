/**
 * aux-load-bytes — port-native bridge that exposes an aux key's bytes on
 * an output port (universal-port plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * **Why this primitive exists.** Phase 2's port-native chain can read from
 * parent-scope `state` via `state-to-bytes@1`, but there's no parallel
 * mechanism for reading from the aux map. SHA-256's decomposed
 * compression rounds need to read `aux["K"]` (round constants) and
 * `aux["W"]` (message schedule) per round; the final-add step needs to
 * read `aux["H"]` (initial hash values). Without an aux→port bridge,
 * those values can only be reached by lifted-legacy steps with their own
 * `auxReadPorts` metadata — which forces every cipher that needs aux to
 * ship a one-off helper step.
 *
 * **How it works.** Hybrid registration shape: `kind: "ported"` with
 * `meta.auxReadPorts` present and NO `legacy` executor — the same shape
 * `state-to-bytes@1` and `bytes-to-state@1` set the precedent for in
 * Slice 2.6b. The runtime sees the metadata's aux-read binding and,
 * BEFORE the executor runs, projects `aux[params.auxName]` into the
 * "input" port via `auxValueToPortBytes`. The executor itself is an
 * identity-on-port: it copies the "input" port bytes to the "output"
 * port. State is passthrough — no `stateInputPort` / `stateOutputPort`
 * in the meta.
 *
 * **Authoring shape.** Spec leaf carries `params: { auxName: "K",
 * byteLength: 256 }`; downstream consumers wire `portInputs.X: { node:
 * "fetch-K", port: "output" }`. The aux value at `aux["K"]` must be a
 * `Uint8Array` (or a State variant that decodes to bytes via the
 * existing port-projection contract — the runtime's coercion handles
 * length mismatches by padding or truncating and emitting a synthetic
 * `__coerce__` frame).
 *
 * **Why declare `byteLength` in params (not derive at run-time).** The
 * output port's byteLength is known at spec-edit time, which lets the
 * editor's coercion-warning glyph surface mismatches before run. Same
 * reasoning as `constant-load@1` (Slice 2.4): pre-known output lengths
 * let the visual editor reason about wiring statically. The aux value's
 * actual length is checked at run-time against this declared length by
 * the runtime's port-length coercion (Slice 1.12).
 *
 * **Parallel naming with `constant-load@1`.** Both primitives are
 * "sources" that emit bytes on an output port:
 *   - `constant-load@1` — source bytes are a compile-time literal.
 *   - `aux-load-bytes@1` — source bytes come from the run-time aux map.
 *
 * User pick Q-2.6c-3 (2026-05-25): `aux-load-bytes` was preferred over
 * `aux-to-bytes` (which reads as a transformation, like `state-to-bytes`)
 * and `aux-fetch` (terse but family-orphan). The `*-load-*` family
 * signals "source" to spec authors scanning the palette.
 *
 * **Fresh palette drop semantics.** Authoring-state: when a user drops
 * this leaf without configuring `auxName` (default `""`), the binding is
 * still emitted to the runtime. `aux.get("")` returns undefined, the
 * runtime records the miss in `frame.auxReadMissing`, and the editor
 * surfaces an orphan-read warning glyph. The executor receives an empty
 * `inputs` map and throws — matching `state-to-bytes@1`'s posture for
 * its own missing-input case. The pre-Run orphan glyph is the first
 * line of defense; the executor throw is the second. (Future relaxation
 * to "emit zero-filled output for graceful incremental authoring" is on
 * the table if practical use shows the strict throw is too aggressive.)
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly auxName: string;
  readonly byteLength: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aux-load-bytes: params must be an object");
  }
  const p = params as Record<string, Json>;
  const auxName = p.auxName;
  if (typeof auxName !== "string") {
    throw new Error("aux-load-bytes: params.auxName must be a string");
  }
  const byteLength = p.byteLength;
  if (typeof byteLength !== "number" || !Number.isInteger(byteLength) || byteLength < 1) {
    throw new Error(
      `aux-load-bytes: params.byteLength must be a positive integer (≥ 1), got ${String(byteLength)}`,
    );
  }
  return { auxName, byteLength };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * One input port `input` (sourced via meta.auxReadPorts → aux[auxName])
 * and one output port `output`. Both declare exact `byteLength` from
 * `params.byteLength` — pre-known output lengths let the editor's
 * coercion-warning glyph surface mismatches at spec-edit time. Layout
 * `"raw"` on both ports — this primitive is byte-flat by design.
 *
 * Function-form on both sides because `byteLength` depends on params (the
 * port COUNT is fixed at 1, but per the project's "function form when
 * varies on THIS side" rule from Slice 2.1b, the varying byteLength on a
 * single port still uses function form to declare it honestly).
 */
export const auxLoadBytesPortContract: PortContract = {
  inputs: (params: Json) => {
    const { byteLength } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength };
    return new Map([["input", shape]]);
  },
  outputs: (params: Json) => {
    const { byteLength } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength };
    return new Map([["output", shape]]);
  },
};

export const auxLoadBytes: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error(
      "aux-load-bytes: input port 'input' is not wired (the runtime should auto-project aux[params.auxName] via meta.auxReadPorts — check that aux[auxName] is populated by an earlier spec leaf, or that params.auxName is set)",
    );
  }
  // Fresh Uint8Array — every port-native primitive's "outputs own their
  // buffers" convention. The runtime's port-length coercion (Slice 1.12)
  // has already aligned inputBytes.length to params.byteLength when they
  // differed, so a defensive copy here is a constant-cost guard against
  // downstream mutation leaking into the upstream aux value.
  const out = new Uint8Array(inputBytes.length);
  out.set(inputBytes);
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────
//
// `auxReadPorts` is what makes this primitive load-bearing: the runtime
// reads the binding `Map([["input", params.auxName]])` and fills
// `inputs.get("input")` with the bytes encoding of `aux[params.auxName]`
// BEFORE the executor runs. The binding is emitted UNCONDITIONALLY —
// even when `auxName === ""` (the fresh-palette-drop default) — so the
// runtime records `frame.auxReadMissing[""]` and the editor surfaces an
// orphan-read warning glyph on the half-wired leaf.
//
// `stateLayout: "bytes"` is a defensive default. State is passthrough —
// no `stateInputPort` / `stateOutputPort` declared — but the layout tag
// is required by the runtime's projection contract for any `kind:
// "ported"` registration with `meta` present.
//
// **No `auxWritePorts`** — aux-load-bytes is read-only on aux. Writes
// would defeat the "bridge from aux to port" framing.

export const auxLoadBytesMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { auxName } = readParams(params);
    return new Map([["input", auxName]]);
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const auxLoadBytesDoc: StepDocumentation = {
  name: "Aux Load Bytes",
  summary:
    "Fetches a value that an earlier step stored under a name, and makes it available to read.",
  detail: `# Aux Load Bytes

Fetches a value that an earlier step stored away under a name (a "slot") and
makes it available for later steps to read. Ciphers use named slots for
values that are computed once and then read many times — most often the round
keys or tables produced by the key schedule.

## Where it fits

- **Reading key-schedule output** — a key schedule computes the round keys
  and stores them in named slots; steps that need a round key fetch it back
  with this.
- **Reading shared tables** — where a hash keeps a table of round constants
  in one slot, this fetches the whole table so a later step can pick out the
  part it needs.

If instead you want a fixed value that you type in directly (rather than one
produced by an earlier step), use **Load constant** — its value is written
right into the cipher and needs no earlier step to fill it in.`,
  params: new Map([
    [
      "auxName",
      "The name of the slot to read. Left blank on a freshly added step, and the editor flags it until you point it at a slot some earlier step fills in.",
    ],
    ["byteLength", "How many bytes the fetched value is expected to be."],
  ]),
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
