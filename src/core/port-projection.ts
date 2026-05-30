/**
 * Port-projection helpers for the universal port-based dataflow spike
 * (Phase 0 of `docs/plans/universal-port-dataflow.md`). Lives ALONGSIDE
 * the legacy runtime; nothing in `runtime.ts` or `registry.ts` imports
 * from here yet. Phase 0 validates the round-trip:
 *
 *   deepEqual(reconstruct(project(legacyFrame, meta).frame,
 *                          project(legacyFrame, meta).tags),
 *             legacyFrame)
 *
 * for the three target step types: `generic.byte-substitution@1` (pure
 * state-only), `generic.add-round-key@1` (aux-reading), and the same
 * two when emitted inside an `iterate` body (frame metadata: `blockIndex`,
 * `:b{i}` stepId suffix). If the round-trip holds byte-by-byte for all
 * three, the load-bearing claim that "every frame's state/aux split is
 * one projection of unified ports" is empirically supported — and Phase 0
 * can proceed to runtime dual-dispatch.
 *
 * Anti-trivial discipline: `LayoutTags` MUST carry only what's needed to
 * reinterpret raw byte arrays back into the legacy variant — the State
 * enum tag and the port-name ↔ aux-key bindings. It MUST NOT carry the
 * legacy `State`
 * object verbatim. A trivial round-trip that just stashes the original
 * State in the sidecar would not test the flatten-to-Uint8Array claim
 * the entire migration rests on.
 */

import { cloneState } from "./state/clone";
import type {
  AuxValue,
  Json,
  LayoutTags,
  PortShape,
  PortShapeMap,
  PortedExecutor,
  PortedFrame,
  ProjectionMetadata,
  State,
  StateShape,
  StepExecutor,
  StepInputs,
  StepOutputs,
  TraceFrame,
} from "./types";

/**
 * Resolve a `PortShapeMap` to a static `ReadonlyMap<string, PortShape>`.
 *
 * `PortContract.inputs` and `PortContract.outputs` are unioned with a
 * function form (`(params) => Map`) so dynamic-N steps — AES / Speck /
 * Serpent / DES key-schedules — can declare per-leaf port counts sized
 * by `params.rounds`. Callers MUST funnel through this helper instead
 * of touching `.get(...)` directly: the function form needs `params` to
 * materialize and the static form is identity.
 *
 * Cheap for the static case (`typeof !== "function"` returns the map
 * unchanged). The runtime resolves once per ported frame and reads
 * from the returned map repeatedly. User pick 2026-05-23 over the
 * templated-name "keyN" lie and a `dynamicOutputs?` sibling field.
 */
export const resolvePortMap = (spec: PortShapeMap, params: Json): ReadonlyMap<string, PortShape> =>
  typeof spec === "function" ? spec(params) : spec;

// `ProjectionMetadata` moved to `core/types.ts` in Slice 1.2 so the
// `StepRegistration` discriminated union can carry it as the `meta` field
// on the `kind: "ported"` variant without forcing a circular import. The
// lift logic below still lives here; only the type definition relocated.
// Re-exported for callers that imported it from this module's old
// surface. (The throw-away Phase-0 `PROJECTION_METADATA` side-map that
// also lived here was deleted in Slice 1.9.)
export type { ProjectionMetadata };

/**
 * Result of `project`. Bundling the frame and tags into one return
 * value keeps the round-trip test ergonomic and signals that the two
 * outputs are NOT independently meaningful — each is half of the
 * lossless pair that round-trips to the legacy frame.
 */
export type Projection = {
  readonly frame: PortedFrame;
  readonly tags: LayoutTags;
};

/**
 * Project a legacy `TraceFrame` to a `(PortedFrame, LayoutTags)` pair.
 *
 * State carries through the named port (default "state"). Aux reads
 * become input ports per the metadata's `auxReadPorts(params)` mapping;
 * aux writes become output ports per `auxWritePorts(params)`. Any frame
 * field that's already port-agnostic (index, path, stepId, stepType,
 * params, blockIndex, branchPath, auxReadMissing) is copied through.
 *
 * Throws if an aux value targeted by a port is NOT a `Uint8Array` —
 * the three Phase-0 targets only use `Uint8Array` aux values (round
 * keys); other AuxValue variants (`State`, `number`, `bigint`, `State[]`)
 * are not exercised in Phase 0 and would need their own encoding rules
 * before they can flow through a port. See TODOs below.
 */
export const project = (frame: TraceFrame, meta: ProjectionMetadata): Projection => {
  const inputs = new Map<string, Uint8Array>();
  const outputs = new Map<string, Uint8Array>();
  const auxInputBindings = new Map<string, string>();
  const auxOutputBindings = new Map<string, string>();

  // ── State → port ────────────────────────────────────────────────────────
  if (meta.stateInputPort !== undefined) {
    inputs.set(meta.stateInputPort, stateToBytes(frame.stateBefore, meta.stateLayout));
  }
  if (meta.stateOutputPort !== undefined) {
    outputs.set(meta.stateOutputPort, stateToBytes(frame.stateAfter, meta.stateLayout));
  }

  // ── Aux read → input port ───────────────────────────────────────────────
  if (meta.auxReadPorts !== undefined) {
    const readBindings = meta.auxReadPorts(frame.params);
    for (const [portName, auxKey] of readBindings) {
      const auxValue = frame.auxRead.get(auxKey);
      if (auxValue === undefined) {
        // The step's params name an aux key but the frame didn't record
        // a read for it. The legacy runtime separates SUCCESSFUL reads
        // (auxRead) from MISSING reads (auxReadMissing). A missing read
        // is fine — the binding stays for reconstruction; the port has
        // no input bytes this frame. This matches the legacy auxRead's
        // "key absent" semantics.
        continue;
      }
      inputs.set(portName, auxValueToBytes(auxValue, auxKey));
      auxInputBindings.set(portName, auxKey);
    }
  }

  // ── Aux write → output port ─────────────────────────────────────────────
  if (meta.auxWritePorts !== undefined) {
    const writeBindings = meta.auxWritePorts(frame.params);
    for (const [portName, auxKey] of writeBindings) {
      const auxValue = frame.auxWritten.get(auxKey);
      if (auxValue === undefined) continue;
      outputs.set(portName, auxValueToBytes(auxValue, auxKey));
      auxOutputBindings.set(portName, auxKey);
    }
  }

  const tags: LayoutTags = {
    stateLayout: meta.stateLayout,
    ...(auxInputBindings.size > 0 ? { auxInputBindings } : {}),
    ...(auxOutputBindings.size > 0 ? { auxOutputBindings } : {}),
  };

  const portedFrame: PortedFrame = {
    index: frame.index,
    path: frame.path,
    stepId: frame.stepId,
    stepType: frame.stepType,
    params: frame.params,
    inputs,
    outputs,
    ...(frame.auxReadMissing !== undefined ? { auxReadMissing: frame.auxReadMissing } : {}),
    ...(frame.blockIndex !== undefined ? { blockIndex: frame.blockIndex } : {}),
    ...(frame.branchPath !== undefined ? { branchPath: frame.branchPath } : {}),
  };

  return { frame: portedFrame, tags };
};

/**
 * Reconstruct a legacy `TraceFrame` from a `(PortedFrame, LayoutTags)`
 * pair. The inverse of `project`. The round-trip
 * `reconstruct(project(f).frame, project(f).tags)` must byte-equal `f`
 * for Phase 0's three target step types.
 *
 * Throws when the tags claim a state port that the ported frame doesn't
 * provide — that would indicate metadata inconsistency, not a missing
 * legitimate read.
 */
export const reconstruct = (ported: PortedFrame, tags: LayoutTags): TraceFrame => {
  // ── Reconstruct stateBefore / stateAfter ───────────────────────────────
  // Phase-0 design simplification: the convention is that if a step has
  // a stateInputPort, it's named "state" in the inputs map. The same
  // assumption holds for the output side. Real Phase 1+ would consult
  // the contract here; Phase 0 hard-codes the convention because all
  // three lifted steps follow it.
  const stateBefore = bytesToState(
    requirePortBytes(ported.inputs, "state", ported.stepType, "input"),
    tags,
  );
  const stateAfter = bytesToState(
    requirePortBytes(ported.outputs, "state", ported.stepType, "output"),
    tags,
  );

  // ── Rebuild auxRead from input-port → aux-key bindings ─────────────────
  const auxRead = new Map<string, AuxValue>();
  if (tags.auxInputBindings !== undefined) {
    for (const [portName, auxKey] of tags.auxInputBindings) {
      const bytes = ported.inputs.get(portName);
      if (bytes === undefined) {
        // Binding declared but no port bytes present. Legacy contract
        // never produces this: auxRead only carries SUCCESSFUL reads,
        // and the binding is added in `project` only when the aux value
        // was present. Treat as a defensive throw — silent skipping
        // would let a buggy projection round-trip to a "looks-fine"
        // frame that's actually missing data.
        throw new Error(
          `port-projection: aux binding "${portName}" → "${auxKey}" has no input bytes (stepType=${ported.stepType})`,
        );
      }
      // Aux values came in as Uint8Array (the only AuxValue variant
      // Phase 0 projects); rebuild as such. cloneState-like copy keeps
      // reference inequality with the port bytes — preserves the
      // legacy frame's immutability convention.
      auxRead.set(auxKey, new Uint8Array(bytes));
    }
  }

  // ── Rebuild auxWritten symmetrically ───────────────────────────────────
  const auxWritten = new Map<string, AuxValue>();
  if (tags.auxOutputBindings !== undefined) {
    for (const [portName, auxKey] of tags.auxOutputBindings) {
      const bytes = ported.outputs.get(portName);
      if (bytes === undefined) {
        throw new Error(
          `port-projection: aux binding "${portName}" → "${auxKey}" has no output bytes (stepType=${ported.stepType})`,
        );
      }
      auxWritten.set(auxKey, new Uint8Array(bytes));
    }
  }

  const recovered: TraceFrame = {
    index: ported.index,
    path: ported.path,
    stepId: ported.stepId,
    stepType: ported.stepType,
    params: ported.params,
    stateBefore,
    stateAfter,
    auxRead,
    auxWritten,
    ...(ported.auxReadMissing !== undefined ? { auxReadMissing: ported.auxReadMissing } : {}),
    ...(ported.blockIndex !== undefined ? { blockIndex: ported.blockIndex } : {}),
    ...(ported.branchPath !== undefined ? { branchPath: ported.branchPath } : {}),
  };
  return recovered;
};

// ─── State ↔ bytes ──────────────────────────────────────────────────────

/**
 * Convert a legacy `State` variant to a raw `Uint8Array` for a port
 * payload. Exposed (along with `bytesToState`) so the runtime's
 * Phase-0 dual-dispatch path can construct ported inputs / disassemble
 * ported outputs without re-implementing the variant-specific encoding.
 *
 * `expected` is asserted against `state.shape` so a metadata mismatch
 * surfaces at the boundary instead of silently producing wrong bytes.
 */
export const stateToPortBytes = (state: State, expected: StateShape): Uint8Array => {
  return stateToBytes(state, expected);
};

/**
 * Inverse of `stateToPortBytes`. Reconstructs a `State` from raw bytes
 * plus the layout tag. Both surviving layouts (`bytes`, `matrix4x4-bytes`)
 * reconstruct directly from the `Uint8Array`.
 */
export const portBytesToState = (bytes: Uint8Array, layout: StateShape): State => {
  // Reuse `bytesToState` with a minimal LayoutTags carrying only the layout.
  return bytesToState(bytes, { stateLayout: layout });
};

const stateToBytes = (state: TraceFrame["stateBefore"], expected: StateShape): Uint8Array => {
  // Slice 2.0b-ii (universal-port Phase 2) relaxation, user pick option C
  // (2026-05-24): when `expected === "bytes"`, accept the other State
  // variant (`matrix4x4-bytes`) and read `.bytes` directly. The relaxation
  // unblocks lifting shape-transforming steps whose input state's variant
  // doesn't matter to the executor (concat-blocks: matrix-in/bytes-out,
  // `_state` ignored) without forcing every such step to ship asymmetric
  // stateInput/stateOutput layout meta. Trade-off: a meta author who
  // mis-declares `stateLayout: "bytes"` against a state-reading executor no
  // longer surfaces at the encode boundary — they surface inside the
  // executor's own shape check.
  //
  // Untouched: `expected === "matrix4x4-bytes"` still enforces shape
  // equality. "bytes" is the universal sink because every State variant
  // carries a `.bytes` Uint8Array internally.
  if (expected === "bytes" && state.shape !== "bytes") {
    // The union narrows to `matrix4x4-bytes` here; it carries `.bytes`.
    return new Uint8Array(state.bytes);
  }
  if (state.shape !== expected) {
    throw new Error(
      `port-projection: state shape ${state.shape} does not match expected ${expected}`,
    );
  }
  switch (state.shape) {
    case "bytes":
    case "matrix4x4-bytes":
      // Defensive copy: the runtime's `cloneState` already produces
      // a fresh Uint8Array for each frame, but `project` must not
      // alias the caller's bytes either — the PortedFrame is a
      // separate value owned by the ported pipeline.
      return new Uint8Array(state.bytes);
  }
};

const bytesToState = (bytes: Uint8Array, tags: LayoutTags): TraceFrame["stateBefore"] => {
  switch (tags.stateLayout) {
    case "bytes":
      // bytes layout is wiring-determined — any length is legal. The
      // consumer's own length assertions (if any) gate beyond this.
      return cloneState({ shape: "bytes", bytes });
    case "matrix4x4-bytes":
      // Slice 1.12 caveat 1 defensive throw — a coerced byte stream
      // whose length doesn't match the layout's fixed expected size
      // would otherwise produce a malformed MatrixState that downstream
      // consumers silently misinterpret (treating wrong-length bytes as
      // a column-major 4×4 matrix smears values into the wrong cells).
      // Loud throw with clear attribution lets a fixture error surface
      // at the projection boundary, not three frames later.
      if (bytes.length !== 16) {
        throw new Error(
          `port-projection: bytesToState layout "matrix4x4-bytes" expected 16 bytes, got ${bytes.length}. This usually means a ported-dispatch input port's coerced bytes don't fit the declared state-port layout. See Slice 1.12 caveat 1 in docs/plans/universal-port-phase-1-slices.md.`,
        );
      }
      return cloneState({ shape: "matrix4x4-bytes", bytes });
  }
};

// ─── Aux value ↔ bytes ──────────────────────────────────────────────────

/**
 * Convert an AuxValue to a Uint8Array port payload. Phase 0 only handled
 * the `Uint8Array` variant; subsequent slices widen as their step types
 * lift.
 *
 * Slice 2.0b-ii (universal-port Phase 2) — widens to accept
 * `readonly State[]` for `split-blocks@1`. Each element must be a State
 * variant carrying `.bytes: Uint8Array`; all bytes are concatenated end
 * to end. The decoder side (`auxPortBytesToValue` with layout
 * `"matrix-cm-4x4-array"`) re-slices using a fixed 16-byte element width;
 * this encoder is element-width-agnostic by design (a future
 * `bytes-array` layout for `BytesState[]` would reuse the same encode
 * branch).
 *
 * Other AuxValue shapes (`number`, `bigint`) still get a descriptive
 * throw so a fixture mistake surfaces immediately. Those variants are
 * exercised by `compute-block-count` (number) and would-be RSA / EC
 * (bigint); their projection rules need design as their step types lift.
 */
const auxValueToBytes = (value: AuxValue, auxKey: string): Uint8Array => {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  if (Array.isArray(value)) {
    return encodeStateArrayToBytes(value, auxKey);
  }
  throw new Error(
    `port-projection: aux key "${auxKey}" has unsupported value (type=${typeof value}); only Uint8Array and State[] aux are projected so far`,
  );
};

/**
 * Encode a `readonly State[]` aux value as concatenated bytes for a port
 * payload. Used by both `auxValueToBytes` (the file-private encoder
 * `project` uses) and `auxValueToPortBytes` (the exported encoder the
 * runtime + lift adapter use). Centralised so the per-element validation
 * and the concat logic only live in one place.
 *
 * Per-element validation throws on the first non-State entry — silent
 * skipping would produce length-mismatched output bytes that
 * `auxPortBytesToValue` then either accepts (wrong element count) or
 * rejects (divisibility throw) several frames downstream, attributing
 * the bug to the wrong site. Loud throw at the encoding boundary keeps
 * authoring errors local.
 */
const encodeStateArrayToBytes = (value: readonly unknown[], auxKey: string): Uint8Array => {
  let totalLen = 0;
  for (let i = 0; i < value.length; i++) {
    const el = value[i];
    if (
      !(
        typeof el === "object" &&
        el !== null &&
        "shape" in el &&
        "bytes" in el &&
        (el as { bytes: unknown }).bytes instanceof Uint8Array
      )
    ) {
      throw new Error(
        `port-projection: aux key "${auxKey}"[${i}] is not a State variant with .bytes (got ${typeof el === "object" && el !== null ? "object missing shape/bytes" : typeof el})`,
      );
    }
    totalLen += (el as { bytes: Uint8Array }).bytes.length;
  }
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const el of value) {
    const b = (el as { bytes: Uint8Array }).bytes;
    out.set(b, offset);
    offset += b.length;
  }
  return out;
};

// ─── Helpers ────────────────────────────────────────────────────────────

const requirePortBytes = (
  ports: StepInputs | StepOutputs,
  portName: string,
  stepType: string,
  side: "input" | "output",
): Uint8Array => {
  const bytes = ports.get(portName);
  if (bytes === undefined) {
    throw new Error(`port-projection: ${side} port "${portName}" missing for stepType=${stepType}`);
  }
  return bytes;
};

// ═══════════════════════════════════════════════════════════════════════════
// Slice 2.9a — frame port-value lookup helper
// ═══════════════════════════════════════════════════════════════════════════
//
// Reads a TraceFrame's captured port I/O — the input/output Uint8Array a
// pure-port-native step saw at frame-emit time. Returns null when the frame
// is on the legacy path (no port fields populated) OR when the named port
// is absent on the chosen side. Single boundary so 2.9b's PortFlowView and
// 2.9d's provenance fns don't each re-implement the optional-chain.
//
// Side discriminator is a string literal rather than two separate functions
// because the caller often picks dynamically (one per row label in the
// vertical stack renderer).

/**
 * Look up a port's bytes on a TraceFrame.
 *
 * @returns `null` for legacy/lifted-legacy frames (port fields undefined)
 *          or when the named port doesn't exist on the chosen side.
 */
export const framePortBytes = (
  frame: TraceFrame,
  portName: string,
  side: "input" | "output",
): Uint8Array | null => {
  const map = side === "input" ? frame.portInputs : frame.portOutputs;
  if (map === undefined) return null;
  return map.get(portName) ?? null;
};

// ═══════════════════════════════════════════════════════════════════════════
// Port-length coercion — Q2 of the universal-port-dataflow plan
// (Slice 1.12, closes Phase 1)
// ═══════════════════════════════════════════════════════════════════════════
//
// Parent plan Q2: "Warn-and-run, deterministic coercion. Right-pad with zeros
// to target length when source is shorter; truncate from the right when
// source is longer. Coercion appears as a visible trace step."
//
// Surfacing mechanism (user pick 2026-05-24 over `coercionApplied` metadata
// field): synthetic `__coerce__` trace frame per affected input port, emitted
// BEFORE the consumer leaf. Frame carries the byte morph as
// (stateBefore → stateAfter), with params identifying the port + mode +
// lengths. Same pattern as `__rejoin__` (`combine-kinds.ts`) — runtime-
// synthesized stepType not registered with an executor; renderers + narration
// dispatch off the literal.
//
// Scope: input ports only (state + aux input ports both flow through the
// same `inputs` map at `runtime.ts`'s ported-dispatch path). Output ports
// don't coerce — a producer that emits wrong-length bytes is a meta
// authoring bug (executor lying about its output) that should surface
// loudly downstream when the next consumer's input contract bites,
// not be silently smoothed over at production time.
//
// Polymorphic ports (PortShape with `byteLength` absent) skip coercion —
// "absent" means "wiring-determined" per the Slice-1.2 user pick (over
// sentinel-0 and contract-optional alternatives). Coercion only fires when
// the target byteLength is EXPLICITLY declared.

/** Synthetic stepType used on coercion frames. Same convention as
 *  `__rejoin__` in `combine-kinds.ts` and `__endpoint__` in `graph.ts` —
 *  never registered with an executor; renderers + narration dispatch off
 *  the literal. */
export const COERCE_STEP_TYPE = "__coerce__";

/** Deterministic coercion modes per Q2 of the parent plan. */
export type CoercionMode = "right-pad" | "truncate-right" | "exact";

/** Result of a single port-length coercion. `mode === "exact"` means
 *  bytes already matched targetLen — runtime skips synthetic frame
 *  emission in that case (the bytes object is returned as-is, no copy). */
export type CoercionResult = {
  readonly bytes: Uint8Array;
  readonly mode: CoercionMode;
  readonly sourceLen: number;
  readonly targetLen: number;
};

/**
 * Coerce a source byte payload to a target length per Q2's deterministic
 * rule. Returns a CoercionResult carrying the (possibly fresh) byte buffer
 * + mode descriptor. The runtime's ported-dispatch path calls this once
 * per declared input port whose byteLength is set, then emits a synthetic
 * `__coerce__` frame iff `mode !== "exact"`.
 *
 * Three cases:
 *   - `source.length === targetLen` → `mode: "exact"`, bytes returned
 *     unchanged (reference-equal to caller's buffer). The runtime skips
 *     frame emission for the no-op case so a shipped spec with matched
 *     declarations adds zero frames to its trace.
 *   - `source.length < targetLen`  → `mode: "right-pad"`, returns a fresh
 *     `Uint8Array(targetLen)` with `source` at offset 0 and zeros after.
 *   - `source.length > targetLen`  → `mode: "truncate-right"`, returns a
 *     fresh `source.slice(0, targetLen)` — the FIRST targetLen bytes, i.e.,
 *     the leftmost prefix. "Truncate from the right" is the discard side,
 *     not the keep side — read Q2's prose carefully.
 *
 * Always returns a fresh buffer in the non-exact branches so the runtime
 * can hand both the original-length bytes (stateBefore) and the coerced
 * bytes (stateAfter) to the synthetic frame without aliasing.
 */
export const coerceToByteLength = (source: Uint8Array, targetLen: number): CoercionResult => {
  const sourceLen = source.length;
  if (sourceLen === targetLen) {
    return { bytes: source, mode: "exact", sourceLen, targetLen };
  }
  if (sourceLen < targetLen) {
    // Right-pad with zeros. Uint8Array's constructor zero-initializes,
    // so we only need to copy source bytes into the [0, sourceLen) prefix.
    const padded = new Uint8Array(targetLen);
    padded.set(source, 0);
    return { bytes: padded, mode: "right-pad", sourceLen, targetLen };
  }
  // sourceLen > targetLen — truncate from the right (discard the trailing
  // sourceLen - targetLen bytes; keep the leftmost targetLen). `.slice`
  // produces a fresh buffer, satisfying the no-alias invariant.
  return {
    bytes: source.slice(0, targetLen),
    mode: "truncate-right",
    sourceLen,
    targetLen,
  };
};

// ═══════════════════════════════════════════════════════════════════════════
// `liftLegacyExecutor` — wraps a legacy `StepExecutor` as a `PortedExecutor`
// ═══════════════════════════════════════════════════════════════════════════
//
// `liftLegacyExecutor(legacy, meta)` produces a `PortedExecutor` that the
// runtime's ported-dispatch path calls when the leaf's registration is
// `kind: "ported"` AND the per-call `RuntimeInput.portedDispatchEnabled`
// flag is on.
//
// What the lift does:
//   1. Reads the state bytes from `inputs.get(meta.stateInputPort)` and
//      reconstructs the legacy `State` variant via `bytesToState`. Aux-only
//      step types (no state ports declared) get a zero-length `bytes`
//      sentinel; the runtime preserves the caller's real state across the
//      ported call.
//   2. Calls the legacy executor with that State + the leaf's `params` +
//      the runtime's `ctx`. Since Slice 1.9 (Decision A), `ctx.aux` is a
//      SYNTHETIC map populated only from the step's `auxReadPorts`
//      bindings — the live aux map no longer reaches the legacy executor
//      through this channel. A legacy executor that reads an undeclared
//      aux key gets `undefined` and surfaces the meta-authoring bug.
//   3. Packs `result.state` into `outputs.get(meta.stateOutputPort)` (when
//      declared) and `result.auxWrites` entries into the output ports
//      named by `meta.auxWritePorts(params)`. Throws if the legacy
//      executor wrote aux but the meta declared no `auxWritePorts` —
//      that's a real metadata mismatch.
//
// What the lift does NOT do:
//   • It does NOT propagate `result.auxReads` — the runtime builds
//     `TraceFrame.auxRead` from the metadata's `auxReadPorts(params)` map
//     directly. This is the load-bearing claim: the trace can be expressed
//     purely in port projections + tags, with NO smuggled structured
//     auxReads piggybacking off the legacy contract.
//   • It does NOT mutate `ctx.aux` — only the legacy executor's own
//     side-effects on aux (none in any shipped step) reach the runtime,
//     and post-Slice-1.9 those would land on the runtime's synthetic
//     per-call map, which is discarded after the call returns.
//
// Half-declared state ports (one of `stateInputPort` / `stateOutputPort`
// declared but not the other) is a meta-authoring bug — the lift throws
// loudly rather than silently producing a half-valid round-trip.
export const liftLegacyExecutor = (
  legacy: StepExecutor,
  meta: ProjectionMetadata,
): PortedExecutor => {
  return (inputs, params, ctx) => {
    const inPort = meta.stateInputPort;
    const outPort = meta.stateOutputPort;

    // Half-declared state ports are a meta-authoring bug. The runtime's
    // ported path matches: it builds inputs for `stateInputPort` and
    // reconstructs state from `stateOutputPort` independently, so a meta
    // with one but not the other would silently corrupt one half of the
    // round-trip. Better to surface the inconsistency here.
    if ((inPort === undefined) !== (outPort === undefined)) {
      throw new Error(
        `liftLegacyExecutor: meta must declare BOTH stateInputPort and stateOutputPort, or NEITHER (got inPort=${String(inPort)}, outPort=${String(outPort)}, stepId=${ctx.stepId})`,
      );
    }

    // ── Reconstruct stateBefore from the state input port (if any) ─────
    let stateBefore: State;
    if (inPort !== undefined) {
      const stateBytes = inputs.get(inPort);
      if (stateBytes === undefined) {
        throw new Error(
          `liftLegacyExecutor: input port "${inPort}" missing (stepId=${ctx.stepId})`,
        );
      }
      // Build a minimal LayoutTags carrier so we can reuse `bytesToState`.
      const reconstructionTags: LayoutTags = { stateLayout: meta.stateLayout };
      stateBefore = bytesToState(stateBytes, reconstructionTags);
    } else {
      // Aux-only step — the legacy executor's state arg is ceremonial.
      // Pick a `bytes`-shape zero-length sentinel. `cloneState` in the
      // runtime preserves the caller's real state across the ported call;
      // the legacy executor's `return { state }` passthrough lands on the
      // sentinel, which the runtime then discards (no `stateOutputPort`).
      stateBefore = { shape: "bytes", bytes: new Uint8Array(0) };
    }

    const result = legacy(stateBefore, params, ctx);

    // ── Pack outputs: state output (if declared) + aux writes (if declared) ─
    const outputs = new Map<string, Uint8Array>();
    if (outPort !== undefined) {
      outputs.set(outPort, stateToBytes(result.state, meta.stateLayout));
    }

    if (result.auxWrites !== undefined && result.auxWrites.size > 0) {
      if (meta.auxWritePorts === undefined) {
        // The legacy executor wrote aux but meta doesn't know how to
        // route it. This is a real authoring mismatch — surface loudly.
        throw new Error(
          `liftLegacyExecutor: legacy executor returned auxWrites (size=${result.auxWrites.size}) but meta.auxWritePorts is undefined. Widen the metadata before lifting an aux-writing step. (stepId=${ctx.stepId})`,
        );
      }
      const writeBindings = meta.auxWritePorts(params);
      for (const [portName, auxKey] of writeBindings) {
        const auxValue = result.auxWrites.get(auxKey);
        if (auxValue === undefined) {
          // The metadata declares a binding for this aux key but the
          // executor produced none. Two legitimate causes:
          //   - The executor branched into a no-write path (e.g.,
          //     `aux-xor` returning passthrough on a missing read), in
          //     which case `meta.auxWritePorts(params)` should ideally
          //     have returned an empty Map for those params. But making
          //     the metadata's write-binding depend on a runtime read
          //     decision pushes too much logic into the meta.
          //   - The metadata's binding rule is stricter than necessary.
          //
          // Either way, the safest behavior is "no output bytes for this
          // port" — the runtime's auxWritten reconstruction skips ports
          // that aren't in the outputs map. No throw, no silent loss.
          continue;
        }
        outputs.set(portName, auxValueToPortBytes(auxValue, auxKey));
      }
    }

    return outputs;
  };
};

/**
 * Encode an AuxValue for a port payload. Exported so the runtime's
 * dispatch path can write to / read from the same byte representation
 * the lift adapter uses on its own auxWrites pass.
 *
 * Slice 1.2 handles two AuxValue variants:
 *   - `Uint8Array` — copied into a fresh buffer (the common case;
 *     `aux-load`, `aux-xor`, `aux-copy`).
 *   - `State` (any shape with `.bytes: Uint8Array`) — the contained bytes
 *     are extracted. `iv-load` writes a `MatrixState` to aux; the runtime
 *     decodes back via `auxPortBytesToValue` using the PortContract's
 *     layout tag.
 *
 * Other AuxValue shapes (State[], number, bigint) throw with a
 * descriptive message so a future mis-lifted step type surfaces
 * immediately rather than coercing wrong bytes. Future slices that lift
 * `split-blocks` (State[]) will widen this with the chosen encoding.
 *
 * **Slice 1.5 (universal port-dataflow Phase 1)** — promoted from
 * file-private to exported so the runtime's ported-dispatch input-side
 * (`runtime.ts`) can encode State-variant aux values into input-port
 * bytes. This is the input-side mirror of the existing output-side path
 * already used by the lift adapter; the unified helper keeps encode
 * semantics symmetric (Uint8Array → copy; State → bytes-extract; other
 * variants → throw). The previous input-side `if (!(v instanceof
 * Uint8Array)) throw` at `runtime.ts:254` (Slice-1.2 deferral) becomes
 * unnecessary — chaining primitives (`xor-aux-into-state`,
 * `state-to-aux`) read/write MatrixState aux, and aux-copy's already-
 * lifted-in-Slice-1.2 entry can now legitimately propagate them.
 */
export const auxValueToPortBytes = (value: AuxValue, auxKey: string): Uint8Array => {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  // State variant: any object with `shape` + `bytes`. Read the bytes
  // straight off. Reconstruction at decode time uses the PortContract's
  // layout tag (see `auxPortBytesToValue`).
  if (
    typeof value === "object" &&
    value !== null &&
    "shape" in value &&
    "bytes" in value &&
    (value as { bytes: unknown }).bytes instanceof Uint8Array
  ) {
    return new Uint8Array((value as { bytes: Uint8Array }).bytes);
  }
  // Slice 2.0b-ii — `readonly State[]` widening. split-blocks writes
  // `MatrixState[]` to its declared output port; the runtime's auxWrites
  // pass funnels through this helper. Concat all elements' `.bytes` into
  // one buffer; decode-side `auxPortBytesToValue` rebuilds the array
  // given the port's `"matrix-cm-4x4-array"` layout tag.
  if (Array.isArray(value)) {
    return encodeStateArrayToBytes(value, auxKey);
  }
  throw new Error(
    `liftLegacyExecutor: aux key "${auxKey}" has unsupported value (type=${typeof value}); Slice 1.2+2.0b-ii project Uint8Array, State, and State[] aux through ports`,
  );
};

/**
 * Decode a port's output bytes back into the original AuxValue shape,
 * using the PortContract's layout tag. Used by the runtime's ported-
 * dispatch path when populating the live aux map + frame's auxWritten.
 *
 * Defaults to `Uint8Array` (raw bytes) when no layout is declared or the
 * layout is `"raw"`. The current decode targets are:
 *
 *   - `"raw"` or undefined        → `Uint8Array`
 *   - `"matrix-cm-4x4"`           → `MatrixState` ({shape:"matrix4x4-bytes", bytes})
 *   - `"preserve-input-variant"`  → variant cloned from `sourceVariantHint`
 *
 * Other layouts (`"be-word"`, `"le-word"`, custom strings) are not yet
 * exercised by a shipped ported step; they throw so a future user surfaces
 * the gap loudly instead of getting silently coerced to `Uint8Array`.
 *
 * ## `"preserve-input-variant"` — variant-preserving aux passthrough (Slice 1.5b)
 *
 * Slice 1.2 lifted `generic.aux-copy@1` with a static `"raw"` layout,
 * sized correctly for the Uint8Array case (the only flag-on path
 * exercising it at the time). Slice 1.5's lift of `state-to-aux` made
 * the gap reachable: CBC decrypt advances its chain via
 * `aux-copy(next-chain → chain)` where `aux[next-chain]` is a
 * MatrixState, and the static `"raw"` layout dropped the variant on
 * decode. The next iteration's `xor-aux-into-state` then read
 * `aux["chain"]` as Uint8Array and the legacy executor threw on shape
 * validation.
 *
 * `"preserve-input-variant"` opts the output port into runtime-side
 * variant lookup: the runtime captures the source AuxValue from the
 * step's first `auxReadPorts` binding (recorded in `portedAuxRead` at
 * read time) and passes it as `sourceVariantHint`. The decoded value
 * gets the source's variant shape with a fresh-bytes copy of the
 * output bytes — by-reference variant copy with by-value bytes copy.
 *
 * Single-source convention: the sentinel's source is the FIRST entry
 * in `auxReadPorts(params)`. aux-copy has exactly one read port so
 * this is unambiguous. A hypothetical future multi-port-input
 * variant-preserving step would need a struct sentinel form
 * (`{ kind: "preserve-input-variant", source: "<portName>" }`)
 * naming the donor port explicitly — defer until a real cipher needs it.
 *
 * Supported source variants:
 *   - `Uint8Array`            → fresh `Uint8Array` copy
 *   - `{ shape: "bytes", … }` → fresh `BytesState`
 *   - `{ shape: "matrix4x4-bytes", … }` → fresh `MatrixState`
 *
 * Throws on State[]/number/bigint sources or on missing hint —
 * a future cipher's variant-preserving passthrough that needs one of
 * those should widen this branch loudly rather than coercing silently.
 */
export const auxPortBytesToValue = (
  bytes: Uint8Array,
  layout?: string,
  sourceVariantHint?: AuxValue,
): AuxValue => {
  if (layout === undefined || layout === "raw") {
    return new Uint8Array(bytes);
  }
  if (layout === "matrix-cm-4x4") {
    // Slice 1.12 caveat 1 defensive throw — aux-side mirror of the
    // bytesToState matrix4x4-bytes check. A coerced byte stream of
    // wrong length would produce a malformed MatrixState that
    // downstream consumers silently misinterpret.
    if (bytes.length !== 16) {
      throw new Error(
        `auxPortBytesToValue: layout "matrix-cm-4x4" expected 16 bytes, got ${bytes.length}. This usually means a ported-dispatch aux port's coerced bytes don't fit the declared layout. See Slice 1.12 caveat 1 in docs/plans/universal-port-phase-1-slices.md.`,
      );
    }
    return { shape: "matrix4x4-bytes", bytes: new Uint8Array(bytes) };
  }
  if (layout === "matrix-cm-4x4-array") {
    // Slice 2.0b-ii — decode the concatenated bytes back into a
    // `MatrixState[]`. Element width is implied by the layout
    // (`matrix-cm-4x4` = 16 bytes per element); count is derived from
    // `bytes.length / 16` with a divisibility throw. A non-multiple
    // length signals either a producer that wrote unaligned bytes or a
    // port-coercion that truncated mid-element — either is a meta /
    // wiring authoring bug worth surfacing loudly.
    //
    // A future `bytes-array` sibling layout will mirror this branch for
    // non-matrix block ciphers; element width then needs an explicit
    // param (no implied width from the tag), at which point this
    // helper's signature widens to take params.
    if (bytes.length % 16 !== 0) {
      throw new Error(
        `auxPortBytesToValue: layout "matrix-cm-4x4-array" expected bytes.length divisible by 16, got ${bytes.length}.`,
      );
    }
    const count = bytes.length / 16;
    const result: { shape: "matrix4x4-bytes"; bytes: Uint8Array }[] = [];
    for (let i = 0; i < count; i++) {
      // `slice` (not `subarray`) — produce an independent buffer per
      // element so consumers can't mutate one element and accidentally
      // touch another. Mirrors the per-element copy `split-blocks`'s
      // legacy executor performs via `matrixFromBytes`.
      result.push({ shape: "matrix4x4-bytes", bytes: bytes.slice(i * 16, (i + 1) * 16) });
    }
    return result;
  }
  if (layout === "preserve-input-variant") {
    if (sourceVariantHint === undefined) {
      throw new Error(
        'auxPortBytesToValue: layout "preserve-input-variant" requires sourceVariantHint (runtime contract: pass the source aux value from the step\'s first auxReadPorts binding)',
      );
    }
    if (sourceVariantHint instanceof Uint8Array) {
      // Same as the "raw" branch — fresh-bytes copy. Listed explicitly
      // so the call site doesn't need to special-case the
      // hint-is-Uint8Array case before calling.
      return new Uint8Array(bytes);
    }
    if (
      typeof sourceVariantHint === "object" &&
      sourceVariantHint !== null &&
      "shape" in sourceVariantHint
    ) {
      const shape = (sourceVariantHint as { shape: string }).shape;
      if (shape === "bytes" || shape === "matrix4x4-bytes") {
        // Slice 1.12 caveat 1 defensive throw — when the source
        // variant is matrix4x4-bytes, the output bytes MUST be 16
        // long for the reconstructed MatrixState to be well-formed.
        // The "bytes" variant remains length-agnostic (any length
        // legal) — same posture as bytesToState case "bytes".
        if (shape === "matrix4x4-bytes" && bytes.length !== 16) {
          throw new Error(
            `auxPortBytesToValue: layout "preserve-input-variant" with source variant "matrix4x4-bytes" expected 16 bytes, got ${bytes.length}. This usually means a ported-dispatch aux port's coerced bytes don't fit the source variant's layout. See Slice 1.12 caveat 1 in docs/plans/universal-port-phase-1-slices.md.`,
          );
        }
        // Construct a fresh State of the same variant. Type narrows via
        // the literal-string check above; the cast satisfies the union
        // discriminator (BytesState / MatrixState) without runtime cost.
        return { shape, bytes: new Uint8Array(bytes) } as AuxValue;
      }
      throw new Error(
        `auxPortBytesToValue: layout "preserve-input-variant" doesn't yet support source variant "${shape}" (only Uint8Array, bytes, matrix4x4-bytes); widen this branch when a cipher needs it`,
      );
    }
    throw new Error(
      `auxPortBytesToValue: layout "preserve-input-variant" requires source to be Uint8Array or State; got typeof=${typeof sourceVariantHint}`,
    );
  }
  throw new Error(
    `auxPortBytesToValue: layout "${layout}" has no decode target yet; widen this helper when the first shipped step needs it`,
  );
};

// ─── Side-map projection-metadata registry ──────────────────────────────
//
// Deleted in Slice 1.9 (universal-port-dataflow Phase 1) per Decision A.
// The two Phase-0 entries (`generic.byte-substitution@1`,
// `generic.add-round-key@1`) lifted to `kind: "ported"` registrations
// with colocated metadata in Slice 1.4 (Decision C); the side-map's
// runtime fallback branch in `runtime.ts` shadowed them as dead code
// through Slices 1.4–1.8, and this slice removes the dead code outright.
// The historical rationale ("Phase 0 spike used a throw-away side-map
// because projection metadata is the lift function's INPUT, not a
// permanent registration field") is preserved in
// `project_universal_port_dataflow_proposal.md`.
