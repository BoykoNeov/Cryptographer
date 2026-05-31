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
  ProjectionMetadata,
  State,
  StateShape,
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

const stateToBytes = (state: TraceFrame["stateBefore"], _expected: StateShape): Uint8Array => {
  // Post-Slice-5.1 the only State shape is "bytes" (and `_expected` is
  // likewise always "bytes"), so there's nothing to assert — just take a
  // defensive copy. `cloneState` already produces a fresh Uint8Array per
  // frame, but `project` must not alias the caller's bytes either: the
  // PortedFrame is a separate value owned by the ported pipeline.
  return new Uint8Array(state.bytes);
};

const bytesToState = (bytes: Uint8Array, _tags: LayoutTags): TraceFrame["stateBefore"] => {
  // Post-Slice-5.1 the only State shape is "bytes" — wiring-determined
  // length, any length is legal. The consumer's own length assertions
  // (if any) gate beyond this.
  return cloneState({ shape: "bytes", bytes });
};

// ─── Aux value ↔ bytes ──────────────────────────────────────────────────

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
  // The `"matrix-cm-4x4"` (single MatrixState) and `"matrix-cm-4x4-array"`
  // (MatrixState[]) decode targets were retired in Phase 5 Slice 5.1
  // (2026-05-30) with the `MatrixState` shape. Their only producers were
  // the now-deleted `iv-load@1` and `split-blocks@1`. The advisory
  // `PortLayout "matrix-cm-4x4"` rendering tag survives, but no aux value
  // decodes to a matrix variant any more.
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
      if (shape === "bytes") {
        // Post-Slice-5.1 the only State variant is `bytes` (length-agnostic,
        // any length legal — same posture as the `bytesToState` "bytes"
        // case). Construct a fresh State so the decoded value owns its
        // buffer.
        return { shape, bytes: new Uint8Array(bytes) } as AuxValue;
      }
      throw new Error(
        `auxPortBytesToValue: layout "preserve-input-variant" doesn't support source variant "${shape}" (only Uint8Array and bytes survive after Slice 5.1); widen this branch when a cipher needs it`,
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
