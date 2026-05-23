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
 * enum tag, optional bit-length / bigint-encoding metadata, and the
 * port-name ↔ aux-key bindings. It MUST NOT carry the legacy `State`
 * object verbatim. A trivial round-trip that just stashes the original
 * State in the sidecar would not test the flatten-to-Uint8Array claim
 * the entire migration rests on.
 */

import { cloneState } from "./state/clone";
import type {
  AuxValue,
  Json,
  LayoutTags,
  PortedExecutor,
  PortedFrame,
  State,
  StateShape,
  StepExecutor,
  StepInputs,
  StepOutputs,
  TraceFrame,
} from "./types";

/**
 * Per-step-type metadata needed to project a legacy TraceFrame into the
 * port-based shape. Static at the contract layer; passed to `project`
 * by the caller (Phase-0 test fixture today; the registry in Phase 1+).
 *
 * `stateInputPort` / `stateOutputPort` may be undefined for aux-only
 * steps (none of Phase 0's three targets, but possible for future
 * `aux-load` / `aux-copy` primitives once they're ported).
 */
export type ProjectionMetadata = {
  /**
   * The State variant the legacy executor accepts/produces. Recorded in
   * `LayoutTags.stateLayout` so reconstruction can rebuild the right
   * variant from the port bytes.
   */
  readonly stateLayout: StateShape;
  /**
   * Name of the input port that carries `stateBefore`. Convention: "state".
   * Undefined for aux-only steps (state is passthrough; no port projection).
   */
  readonly stateInputPort?: string;
  /** Name of the output port that carries `stateAfter`. Convention: "state". */
  readonly stateOutputPort?: string;
  /**
   * Function mapping the step's `params` to a `portName → auxKey` map.
   * Why a function rather than a static map: aux key names are typically
   * spec-leaf-specific (e.g., `params.auxName === "roundKey.0"` vs
   * `"roundKey.1"`), so the binding can only be resolved after the
   * params are in hand. Returns an empty map when the step reads no aux.
   */
  readonly auxReadPorts?: (params: Json) => ReadonlyMap<string, string>;
  /** Symmetric to `auxReadPorts`, for outputs that go to aux. */
  readonly auxWritePorts?: (params: Json) => ReadonlyMap<string, string>;
};

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
    // bitLength / bigintEndian / bigintByteLength only populated for
    // their respective variants — Phase 0's matrix4x4-bytes targets
    // never set them.
    ...readBitLength(frame),
    ...readBigintEncoding(frame),
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
 * Inverse of `stateToPortBytes` (with the `LayoutTags`-rich variants
 * suppressed for Phase-0 simplicity — `bitvec` requires bitLength
 * separately and `bigint` is deferred). Throws if asked to reconstruct
 * a shape that needs more than `Uint8Array` bytes.
 */
export const portBytesToState = (bytes: Uint8Array, layout: StateShape): State => {
  // Build a minimal LayoutTags so we can reuse `bytesToState`. bitvec
  // and bigint paths require additional metadata and are out of scope
  // for Phase 0; `bytesToState` throws if either is requested without
  // its companion field.
  return bytesToState(bytes, { stateLayout: layout });
};

const stateToBytes = (state: TraceFrame["stateBefore"], expected: StateShape): Uint8Array => {
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
    case "bitvec":
      // Bits are already packed; copy for safety. The bitLength rides
      // in LayoutTags.bitLength (see readBitLength below).
      // TODO(Phase 1, bitvec): exercise round-trip with a real bitvec
      // frame to confirm bitLength survives.
      return new Uint8Array(state.bits);
    case "bigint": {
      // TODO(Phase 1, bigint): this is a placeholder. The first cipher
      // to ship with BigIntState (RSA / elliptic curves) must pick a
      // canonical encoding (BE vs LE, length convention) and the
      // round-trip test must cover it. Throwing here keeps Phase 0
      // honest — if someone wires a bigint step into the Phase-0
      // fixture by mistake, the failure is loud.
      throw new Error(
        "port-projection: BigIntState projection deferred to Phase 1 (no shipped cipher exercises it yet)",
      );
    }
  }
};

const bytesToState = (bytes: Uint8Array, tags: LayoutTags): TraceFrame["stateBefore"] => {
  switch (tags.stateLayout) {
    case "bytes":
      return cloneState({ shape: "bytes", bytes });
    case "matrix4x4-bytes":
      return cloneState({ shape: "matrix4x4-bytes", bytes });
    case "bitvec": {
      if (tags.bitLength === undefined) {
        throw new Error("port-projection: bitvec reconstruction requires LayoutTags.bitLength");
      }
      return cloneState({ shape: "bitvec", bits: bytes, bitLength: tags.bitLength });
    }
    case "bigint":
      // TODO(Phase 1, bigint): pair with the encoding decision in
      // stateToBytes. Throws today so a misconfigured fixture surfaces
      // immediately.
      throw new Error("port-projection: BigIntState reconstruction deferred to Phase 1");
  }
};

// ─── Aux value ↔ bytes ──────────────────────────────────────────────────

/**
 * Convert an AuxValue to a Uint8Array port payload. Phase 0 only handles
 * the `Uint8Array` variant; other AuxValue shapes (`State`, `number`,
 * `bigint`, `readonly State[]`) get a descriptive throw so a fixture
 * mistake surfaces immediately. These variants are exercised by the
 * iterate construct (count + blocks + outBlocks) and by some legacy aux
 * primitives; their projection rules need design as their step types
 * lift in Phase 1.
 */
const auxValueToBytes = (value: AuxValue, auxKey: string): Uint8Array => {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  throw new Error(
    `port-projection: aux key "${auxKey}" has non-Uint8Array value (type=${typeof value}); only Uint8Array aux is projected in Phase 0`,
  );
};

// ─── Layout-tag accessors ───────────────────────────────────────────────

/**
 * Pull `bitLength` from a bitvec stateBefore if applicable. Returns an
 * empty object so the spread in `project` produces no key when the
 * variant isn't bitvec — keeps LayoutTags slim for the common case.
 */
const readBitLength = (frame: TraceFrame): { bitLength?: number } => {
  if (frame.stateBefore.shape === "bitvec") {
    return { bitLength: frame.stateBefore.bitLength };
  }
  return {};
};

/**
 * Symmetric placeholder for bigint encoding metadata. Returns empty
 * today because Phase 0 doesn't exercise bigint frames — and the
 * encoding rule itself is deferred to Phase 1.
 */
const readBigintEncoding = (
  _frame: TraceFrame,
): { bigintEndian?: "be" | "le"; bigintByteLength?: number } => {
  // TODO(Phase 1, bigint): once an encoding is picked, populate this
  // from the BigIntState — and stateToBytes / bytesToState above need
  // matching changes.
  return {};
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
// Phase-0 task 4 — `liftLegacyExecutor` + side-map projection registry
// ═══════════════════════════════════════════════════════════════════════════
//
// `liftLegacyExecutor(legacy, meta)` produces a `PortedExecutor` that the
// runtime's dual-dispatch path (Phase-0 task 5) can call when its side-map
// has a matching `ProjectionMetadata` for the leaf's step type AND the
// per-call `RuntimeInput.portedDispatchEnabled` flag is on.
//
// What the lift does:
//   1. Reads the state bytes from `inputs.get(meta.stateInputPort)`,
//      reconstructs the legacy `State` variant via `bytesToState`.
//   2. Calls the legacy executor with that State + the leaf's `params` +
//      the runtime's `ctx`. The `ctx.aux` channel is unchanged — the legacy
//      add-round-key executor's `ctx.aux.get(params.auxName)` keeps working
//      as-is. (Phase 1 cuts the ctx.aux channel; until then, dual aux read
//      paths coexist — the runtime ALSO projects the same bytes into
//      `inputs.get("key")` via `meta.auxReadPorts`. By construction both
//      paths see the same map.)
//   3. **Phase-0 strictness:** throws if the legacy result includes
//      `auxWrites` with any entries. Neither Phase-0 target step
//      (`generic.byte-substitution@1`, `generic.add-round-key@1`) writes
//      aux. A throw here surfaces drift — if a future lifted step starts
//      writing aux, the adapter needs widening (carry `auxWrites` →
//      `outputs` via metadata's `auxWritePorts`) before we silently lose
//      the write.
//   4. Returns `outputs` with the new state bytes at `meta.stateOutputPort`.
//
// What the lift does NOT do:
//   • It does NOT propagate `result.auxReads` — the runtime builds
//     `TraceFrame.auxRead` from the metadata's `auxReadPorts(params)` map
//     directly. This is the load-bearing claim: the trace can be expressed
//     purely in port projections + tags, with NO smuggled structured
//     auxReads piggybacking off the legacy contract.
//   • It does NOT mutate `ctx.aux` — only the legacy executor's own
//     side-effects on aux (none in Phase-0 targets) reach the runtime.
//
// **Verified by inspection (advisor consult 2026-05-23):** for the two
// Phase-0 targets, `result.auxReads` is exactly what `meta.auxReadPorts(
// params)` yields: byte-substitution returns no auxReads; add-round-key
// returns `[params.auxName]` matching the single `"key" → params.auxName`
// binding. So the runtime's "rebuild auxRead from metadata" path produces
// byte-identical `TraceFrame.auxRead` to the legacy path.
export const liftLegacyExecutor = (
  legacy: StepExecutor,
  meta: ProjectionMetadata,
): PortedExecutor => {
  return (inputs, params, ctx) => {
    const inPort = meta.stateInputPort;
    const outPort = meta.stateOutputPort;
    if (inPort === undefined || outPort === undefined) {
      // Phase-0 only lifts state-carrying steps. Aux-only primitives
      // (`aux-load`, `aux-copy`) would lift with no state port set;
      // they're out of scope for this spike. The throw makes that
      // explicit instead of silently producing empty outputs.
      throw new Error(
        `liftLegacyExecutor: Phase-0 lift requires both stateInputPort and stateOutputPort (stepId=${ctx.stepId})`,
      );
    }
    const stateBytes = inputs.get(inPort);
    if (stateBytes === undefined) {
      throw new Error(`liftLegacyExecutor: input port "${inPort}" missing (stepId=${ctx.stepId})`);
    }
    // Build a minimal LayoutTags carrier so we can reuse `bytesToState`.
    // Phase-0 targets are all matrix4x4-bytes; bitLength/bigint encoding
    // fields stay undefined.
    const reconstructionTags: LayoutTags = { stateLayout: meta.stateLayout };
    const stateBefore = bytesToState(stateBytes, reconstructionTags);

    const result = legacy(stateBefore, params, ctx);

    if (result.auxWrites !== undefined && result.auxWrites.size > 0) {
      throw new Error(
        `liftLegacyExecutor: Phase-0 strictness — legacy executor returned auxWrites (size=${result.auxWrites.size}) but the lift adapter does not yet propagate aux writes to output ports. ` +
          `Widen the adapter via meta.auxWritePorts before lifting an aux-writing step. (stepId=${ctx.stepId})`,
      );
    }

    const outputs = new Map<string, Uint8Array>();
    outputs.set(outPort, stateToBytes(result.state, meta.stateLayout));
    return outputs;
  };
};

// ─── Side-map projection-metadata registry ──────────────────────────────
//
// Per advisor consult 2026-05-23: projection metadata lives in a SEPARATE
// side-map keyed by step-type string — NOT as an optional field on
// `StepDefinition`. Rationale (preserved in `project_universal_port_
// dataflow_proposal.md`): projection metadata is the lift function's
// INPUT, not a permanent registration field. Phase 1's eventual
// `StepRegistration` discriminated union will hold `{executor:
// PortedExecutor, shape: PortContract}` as the OUTPUT of lifting; if we
// put `projectionMetadata?` on the legacy `StepDefinition` now, that
// metadata would live on the wrong end of the pipe and force two
// migrations (Phase 0 adds optional field → Phase 1 restructures).
// A throw-away side-map is cheaper and honestly signals "this is a spike."
//
// Phase 0 registers exactly two entries (the targets named in the plan).
// Phase 1 will replace this map entirely with a real registry of
// `PortContract` + `PortedExecutor` pairs.

const META_BYTE_SUBSTITUTION: ProjectionMetadata = {
  // `generic.byte-substitution@1` accepts a 4×4 column-major matrix on
  // its "state" input, returns the same shape on "state" output, reads
  // no aux.
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

const META_ADD_ROUND_KEY: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  // The leaf's `params.auxName` (e.g., "roundKey.0") becomes the single
  // aux-key bound to the "key" input port. Function shape (not static
  // map) because every leaf has a different round-key name; the binding
  // can only be resolved with `params` in hand.
  auxReadPorts: (params: Json) => {
    if (
      typeof params !== "object" ||
      params === null ||
      Array.isArray(params) ||
      !("auxName" in params) ||
      typeof (params as { auxName: unknown }).auxName !== "string"
    ) {
      throw new Error(
        "META_ADD_ROUND_KEY.auxReadPorts: params.auxName: string required (matches add-round-key executor's own validation)",
      );
    }
    return new Map([["key", (params as { auxName: string }).auxName]]);
  },
};

/**
 * The side-map registry consumed by the runtime's dual-dispatch path.
 * `has(stepType)` is the gate: present + `portedDispatchEnabled` →
 * ported path; absent → legacy path (unchanged).
 *
 * Frozen at module load so the runtime's `walk` can `Map.get` directly
 * without needing the registry instance threaded through. Phase 1's
 * `StepRegistration` discriminated union supersedes this entirely.
 */
export const PROJECTION_METADATA: ReadonlyMap<string, ProjectionMetadata> = new Map([
  ["generic.byte-substitution@1", META_BYTE_SUBSTITUTION],
  ["generic.add-round-key@1", META_ADD_ROUND_KEY],
]);
