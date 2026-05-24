import { COMBINE_KINDS, REJOIN_STEP_TYPE } from "./combine-kinds";
import {
  COERCE_STEP_TYPE,
  auxPortBytesToValue,
  auxValueToPortBytes,
  coerceToByteLength,
  portBytesToState,
  resolvePortMap,
  stateToPortBytes,
} from "./port-projection";
import type { StepRegistry } from "./registry";
import { cloneState } from "./state/clone";
import type {
  Aux,
  AuxValue,
  BytesState,
  CipherSpec,
  FeistelRoundGroup,
  ForEachSubgraphNode,
  State,
  StepNode,
  Trace,
  TraceFrame,
} from "./types";

export type RuntimeInput = {
  readonly initialState: State;
  /** Aux values that should be present before any step runs (e.g. the key). */
  readonly initialAux?: ReadonlyMap<string, AuxValue>;
  /**
   * Dual-dispatch flag (universal-port-dataflow plan). When true AND a
   * leaf's registration is `kind: "ported"` (colocated metadata + lifted
   * executor — every shipped step type ported through Slice 1.8), the
   * runtime routes that leaf through the ported execution path:
   *
   *   1. Project state + aux reads into per-port `Uint8Array` inputs via
   *      the ported registration's `meta` bindings.
   *   2. Call the ported `PortedExecutor` with a SYNTHETIC `ctx.aux`
   *      populated only from declared `auxReadPorts` bindings (Slice 1.9
   *      — Decision A; the live aux map no longer reaches lifted
   *      executors).
   *   3. Reconstruct `State` from the output port; build the emitted
   *      `TraceFrame.auxRead` from the metadata's input-port-to-aux-key
   *      bindings (NOT from the legacy executor's `result.auxReads`).
   *
   * Frames produced under either flag value are byte-equal across every
   * shipped cipher family — pinned by the per-cipher
   * `tests/runtime-ported-dispatch-{aes-core,chaining,speck,serpent,des}.test.ts`
   * via frame-by-frame deep equality.
   *
   * Default: `false`. Existing callers (UI, cipher specs, every shipped
   * test) keep the legacy path until a follow-on slice flips the default.
   * The flag lives on `RuntimeInput` (per-call) rather than a module-
   * level global so legacy and ported runs can stand side by side in
   * the same test file.
   */
  readonly portedDispatchEnabled?: boolean;
};

/**
 * Walks a CipherSpec, dispatches each leaf to its executor via the registry,
 * and emits one immutable TraceFrame per leaf.
 *
 * Steps are pure `(state, params, ctx) -> { state, auxWrites?, auxReads? }`.
 * The runtime is the only place that knows about tracing, mutation of the
 * aux map, or frame indexing.
 *
 * `iterate` nodes are expanded inline: the walker reads
 * `aux[countFromAux]` and `aux[blocksFromAux]`, runs the children body
 * once per index with `state = blocks[i]`, suffixes per-iteration step ids
 * with `:b{i}` so the flat trace stays uniquely keyed, stamps each frame
 * with `blockIndex: i`, and appends each iteration's final state into
 * `aux[outBlocksAux]`. See `IterateGroup` in `types.ts` for the contract.
 *
 * `feistel-round` nodes are expanded inline too (Phase 2 of
 * `docs/plans/des-feistel.md`): the walker slices the round's input bytes
 * by each track's `inputBytes`, runs each track's children sequentially
 * with `branchPath` stamped on every emitted frame, then emits one
 * synthetic rejoin frame (`stepType = "__rejoin__"`, `stepId =
 * "{roundId}:rejoin"`) carrying the combined output. See `FeistelRoundGroup`
 * + `CombineKind` in `types.ts`, and `COMBINE_KINDS` in `combine-kinds.ts`,
 * for the contract.
 *
 * `for-each-subgraph` nodes (Slice 2.0a of
 * `docs/plans/universal-port-phase-2-slices.md`) are also expanded inline
 * but **thread state across iterations** — iteration `i+1`'s body input is
 * iteration `i`'s body output, no clone-from-aux per iteration. Each body
 * frame gets a `:r{i}` suffix. See `ForEachSubgraphNode` in `types.ts`.
 *
 * Suffix application on per-iteration / per-track stepIds follows a
 * **fixed type order** (`:t` < `:b` < `:r`) with **outer-first walk order
 * within a type**. So a leaf inside Feistel-A wrapping Feistel-B inside an
 * iterate inside a for-each-subgraph emits `node.id:tA:tB:b3:r7`. The
 * earlier doc claim "innermost-first" was a coincidence of the one shipped
 * nested case (Feistel-in-iterate, where Feistel happens to be `:t` and
 * iterate happens to be `:b`); type-order + walk-order is the real rule.
 * The walker threads `branchPath` + `blockIndex` + `roundPath` through
 * recursion; the suffix string is assembled at frame-construction time.
 * Canonicalization (used by `setTrace` stepId-matching) lives in
 * `@/core/step-id` and strips all suffixes back to the spec-leaf id.
 */
export const runSpec = (spec: CipherSpec, registry: StepRegistry, input: RuntimeInput): Trace => {
  const frames: TraceFrame[] = [];
  let state: State = cloneState(input.initialState);
  const aux = new Map<string, AuxValue>(input.initialAux ?? []);

  let frameIndex = 0;

  // Dual-dispatch flag (universal-port-dataflow plan). Captured once at
  // the call boundary so the per-leaf check in `walk` is a simple
  // `if (portedDispatch && registration.kind === "ported")`. Defaults
  // to false → every leaf runs the legacy path; no behavior change for
  // any caller that doesn't opt in.
  const portedDispatch = input.portedDispatchEnabled === true;

  /** Compose the per-emit stepId suffix from runtime context. Fixed type
   *  order `:t` < `:b` < `:r`; within a type, outer-first walk order.
   *  So a leaf inside Feistel-A wrapping Feistel-B inside an iterate inside
   *  a for-each-subgraph emits `node.id:tA:tB:b3:r7`. See
   *  `core/step-id.ts` for the canonicalization counterpart. */
  const composeStepId = (
    baseId: string,
    branchPath: readonly string[],
    blockIndex: number | undefined,
    roundPath: readonly number[],
  ): string => {
    let id = baseId;
    for (const name of branchPath) id += `:t${name}`;
    if (blockIndex !== undefined) id += `:b${blockIndex}`;
    for (const r of roundPath) id += `:r${r}`;
    return id;
  };

  // `blockIndex` is threaded through recursive walks: undefined at the
  // top level; set to the current iteration index when inside an iterate's
  // children. Used to suffix emitted step ids and stamp frame metadata.
  // `branchPath` is the analogous thread for Feistel tracks: empty at
  // the top level; appended with the track's name (or stringified index)
  // when inside a `feistel-round`'s track body. Outer-first ordering.
  // `roundPath` is the analogous thread for `for-each-subgraph` iterations:
  // empty at the top level; appended with the current round index when
  // inside a for-each-subgraph's body. Outer-first ordering (a nested
  // for-each-subgraph emits `roundPath = [outerRound, innerRound]`).
  const walk = (
    nodes: readonly StepNode[],
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
    roundPath: readonly number[],
  ): void => {
    for (const node of nodes) {
      if (node.kind === "group") {
        walk(node.children, [...path, node.id], blockIndex, branchPath, roundPath);
        continue;
      }

      if (node.kind === "iterate") {
        const rawCount = aux.get(node.countFromAux);
        if (typeof rawCount !== "number" || !Number.isInteger(rawCount) || rawCount < 0) {
          throw new Error(
            `iterate '${node.id}': aux["${node.countFromAux}"] must be a non-negative integer, got ${String(rawCount)}`,
          );
        }
        const rawBlocks = aux.get(node.blocksFromAux);
        if (!Array.isArray(rawBlocks)) {
          throw new Error(
            `iterate '${node.id}': aux["${node.blocksFromAux}"] must be an array of State, got ${typeof rawBlocks}`,
          );
        }
        if (rawBlocks.length !== rawCount) {
          throw new Error(
            `iterate '${node.id}': aux["${node.blocksFromAux}"].length (${rawBlocks.length}) does not match aux["${node.countFromAux}"] (${rawCount})`,
          );
        }

        // Accumulate each iteration's final state into a local mutable
        // array, then publish to aux at the end so partial state isn't
        // visible to executors mid-loop. (If a future step needs to see
        // partial output, expose it via aux["blockIndex"] instead.)
        const outBlocks: State[] = [];
        const iteratePath = [...path, node.id];

        for (let i = 0; i < rawCount; i++) {
          aux.set("blockIndex", i);
          const block = rawBlocks[i];
          if (block === undefined) {
            throw new Error(
              `iterate '${node.id}': aux["${node.blocksFromAux}"][${i}] is undefined`,
            );
          }
          state = cloneState(block);
          walk(node.children, iteratePath, i, branchPath, roundPath);
          outBlocks.push(cloneState(state));
        }

        aux.set(node.outBlocksAux, outBlocks);
        continue;
      }

      if (node.kind === "feistel-round") {
        runFeistelRound(node, path, blockIndex, branchPath, roundPath);
        continue;
      }

      if (node.kind === "for-each-subgraph") {
        runForEachSubgraph(node, path, blockIndex, branchPath, roundPath);
        continue;
      }

      // Leaf step.
      const stateBefore = cloneState(state);

      // ─── Ported dispatch (universal-port-dataflow plan) ────────────────
      // When `portedDispatch` is on AND the registration is `kind: "ported"`
      // (colocated metadata + lifted executor — the long-term home per
      // Decision C), route through the ported execution path:
      //   1. Build `inputs` (state port + aux ports per `auxReadPorts`).
      //   2. Call the ported `executor` with a SYNTHETIC `ctx.aux`
      //      populated only from the step's declared `auxReadPorts`
      //      bindings (Decision A — Slice 1.9 cut the live-aux channel).
      //      A legacy executor inside the lift that tries to read an
      //      undeclared aux key gets `undefined` and surfaces the bug.
      //   3. Reconstruct `State` from the output port (if declared) OR
      //      leave state untouched (aux-only primitives — Slice 1.2).
      //   4. Build the TraceFrame's `auxRead` from the metadata's input-
      //      port-to-aux-key bindings — NOT from the legacy executor's
      //      `result.auxReads`. This is the load-bearing claim: the
      //      trace can be expressed purely in port projections + tags.
      //   5. Build `auxWritten` from output-port-to-aux-key bindings.
      //      The runtime also writes back into the live `aux` map so
      //      downstream legacy / ported steps see the same Aux state.
      //
      // Otherwise (the default for every shipped caller, and every
      // step type still registered as `kind: "legacy"`): the legacy
      // path below runs unchanged.
      const registration = registry.getRegistration(node.type);
      if (!registration) throw new Error(`unknown step type: ${node.type}`);
      let auxRead: Map<string, AuxValue>;
      let auxReadMissing: string[] | undefined;
      let auxWritten: Map<string, AuxValue>;

      if (portedDispatch && registration.kind === "ported") {
        const meta = registration.meta;
        // ── Ported execution path ─────────────────────────────────────
        const inputs = new Map<string, Uint8Array>();
        if (meta.stateInputPort !== undefined) {
          inputs.set(meta.stateInputPort, stateToPortBytes(state, meta.stateLayout));
        }
        // Aux reads: project each (portName, auxKey) binding from the live
        // aux map into the inputs map. Missing values record as orphaned
        // reads (mirrors the legacy path's `auxReadMissing` semantics).
        //
        // **Iteration order matters** — see ProjectionMetadata's contract.
        // The metadata's `auxReadPorts(params)` Map must iterate in the
        // same order the legacy executor declares `auxReads`, or
        // `auxReadMissing` arrays diverge between the two paths.
        const readBindings = meta.auxReadPorts?.(node.params) ?? new Map<string, string>();
        const portedAuxRead = new Map<string, AuxValue>();
        for (const [portName, auxKey] of readBindings) {
          const v = aux.get(auxKey);
          if (v === undefined) {
            if (auxReadMissing === undefined) auxReadMissing = [];
            auxReadMissing.push(auxKey);
            continue;
          }
          // Slice 1.5 input-side widening — encode the live AuxValue into
          // port bytes via `auxValueToPortBytes`, the same helper the lift
          // adapter uses on its auxWrites pass. Handles both Uint8Array
          // and State-variant aux values (chaining primitives —
          // `xor-aux-into-state` reads a MatrixState chain; already-lifted
          // `aux-copy` may now legitimately propagate one). The previous
          // hard throw on non-Uint8Array was a Slice-1.2 deferral; this is
          // the slice where MatrixState-in-aux actually exercises both
          // sides of the input port.
          inputs.set(portName, auxValueToPortBytes(v, auxKey));
          // For `frame.auxRead`, alias the live aux value rather than
          // cloning. Matches the legacy path's `auxRead.set(k, v)` at the
          // line below — symmetry across paths is the parity-preserving
          // choice. (Practically `toEqual` deep-equals either way; aliasing
          // is the cleaner mental model and matches the legacy contract.)
          portedAuxRead.set(auxKey, v);
        }

        // ─── Port-length coercion (Slice 1.12 — Q2 of universal-port plan) ─
        // Walk the registration's declared input ports; for each port that
        // (a) has bytes in the inputs map (state input + any aux read that
        // succeeded), (b) declares a fixed `byteLength` (polymorphic ports
        // — `byteLength` absent — opt out of coercion per the Slice 1.2
        // user pick "absent means wiring-determined"), and (c) the source
        // byte count doesn't match the declared length: coerce the bytes
        // (right-pad with zeros or truncate from the right per Q2) and
        // emit ONE synthetic `__coerce__` frame per affected port BEFORE
        // the consumer's leaf frame. The frame surfaces the morph via its
        // stateBefore/stateAfter pair so the linear scrubber reads it
        // for free (precedent: `__rejoin__`). Frames are flag-on-only;
        // no shipped spec triggers coercion today (every shipped port's
        // declared byteLength matches its actual source — pinned by the
        // Slice 1.11 frame-parity matrix).
        const inputShapes = resolvePortMap(registration.shape.inputs, node.params);
        for (const [portName, shape] of inputShapes) {
          if (shape.byteLength === undefined) continue;
          const sourceBytes = inputs.get(portName);
          if (sourceBytes === undefined) continue;
          if (sourceBytes.length === shape.byteLength) continue;
          const coerced = coerceToByteLength(sourceBytes, shape.byteLength);
          // mode "exact" is filtered above by the length-equality short-
          // circuit; the remaining modes both produced a fresh buffer.
          inputs.set(portName, coerced.bytes);
          // Synthetic frame uses the same path as the consumer leaf so it
          // nests at the same depth in the linear/graph views. stepId
          // disambiguates by portName so multiple coerced ports on the
          // same leaf emit distinct frames in declaration order. Suffixes
          // (`:b{i}`, `:t{name}`) ride along via composeStepId — same
          // contract as the consumer leaf and the rejoin frame.
          const coerceBaseId = `${node.id}:coerce:${portName}`;
          const coerceStepId = composeStepId(coerceBaseId, branchPath, blockIndex, roundPath);
          const beforeBytes: BytesState = {
            shape: "bytes",
            bytes: new Uint8Array(sourceBytes),
          };
          const afterBytes: BytesState = {
            shape: "bytes",
            bytes: new Uint8Array(coerced.bytes),
          };
          const coerceFrame: TraceFrame = {
            index: frameIndex++,
            path,
            stepId: coerceStepId,
            stepType: COERCE_STEP_TYPE,
            params: {
              portName,
              mode: coerced.mode,
              sourceLen: coerced.sourceLen,
              targetLen: coerced.targetLen,
            },
            stateBefore: beforeBytes,
            stateAfter: afterBytes,
            auxRead: new Map(),
            auxWritten: new Map(),
            ...(blockIndex !== undefined ? { blockIndex } : {}),
            ...(branchPath.length > 0 ? { branchPath: [...branchPath] } : {}),
          };
          frames.push(coerceFrame);
        }

        // Call the ported executor with a SYNTHETIC `ctx.aux` populated
        // ONLY from this step's declared `auxReadPorts` bindings (Slice
        // 1.9 — Decision A). `portedAuxRead` is keyed by aux-key and
        // already aliases the live AuxValue (variants preserved —
        // MatrixState chain stays MatrixState), so the lifted executor's
        // `ctx.aux.get(params.auxName)` lookups hit identical values.
        //
        // The cut surfaces a "lifted executor reads undeclared aux" bug
        // as a single failure mode: the synthetic map only contains
        // declared keys; any other key yields `undefined` and the legacy
        // executor inside the lift fails on its own shape check. The
        // live aux map (`aux`) reaches NEITHER the lifted nor the ported
        // executor anymore.
        const outputs = registration.executor(inputs, node.params, {
          stepId: node.id,
          path,
          aux: portedAuxRead,
        });

        // Reconstruct state from the output port if one is declared.
        // Aux-only steps (`generic.aux-load@1` et al.) leave state
        // untouched — the runtime's `state` variable is preserved across
        // the ported call so the caller's shape (matrix4x4-bytes, bytes,
        // etc.) survives.
        if (meta.stateOutputPort !== undefined) {
          const outBytes = outputs.get(meta.stateOutputPort);
          if (outBytes === undefined) {
            throw new Error(
              `ported dispatch: output port "${meta.stateOutputPort}" missing (stepId=${node.id}, stepType=${node.type})`,
            );
          }
          state = portBytesToState(outBytes, meta.stateLayout);
        }

        auxRead = portedAuxRead;

        // Aux writes (Slice 1.2). When meta declares `auxWritePorts`,
        // walk the binding map, read each port's bytes from outputs,
        // decode back to AuxValue, write into BOTH the live aux map AND
        // the frame's auxWritten. Missing port bytes are fine — they
        // mean the executor took a no-write branch (e.g., aux-xor's
        // graceful passthrough on a missing read).
        //
        // Decode layout: the registration's PortContract drives
        // reconstruction. The declared output port's `layout` selects
        // the decode target (`"matrix-cm-4x4"` → MatrixState,
        // `"raw"`/undefined → Uint8Array, `"preserve-input-variant"`
        // → variant-matched copy of the source aux value).
        auxWritten = new Map<string, AuxValue>();
        if (meta.auxWritePorts !== undefined) {
          const writeBindings = meta.auxWritePorts(node.params);
          // Resolve the contract's outputs map ONCE per frame. For
          // dynamic-N ported steps (key-expansion's per-round-key ports
          // sized by `params.rounds`) the outputs field is a function;
          // for the common fixed-arity case (byte-substitution et al.)
          // it's already a static Map and `resolvePortMap` returns it
          // unchanged. See `PortShapeMap` in `core/types.ts`.
          const outputsMap = resolvePortMap(registration.shape.outputs, node.params);

          // Slice 1.5b — source-variant cache for `"preserve-input-variant"`
          // outputs. Computed LAZILY: only allocated if at least one
          // output port declares the sentinel layout. The donor is the
          // FIRST entry of the step's auxReadPorts bindings (today's
          // single-source convention; aux-copy has exactly one read port).
          // We pull from `portedAuxRead` so we get the pre-executor
          // snapshot — defensive against a self-modifying step (aux-copy
          // doesn't do this today, but the contract should not depend on
          // it). `portedAuxRead` is keyed by aux-key, matching the value
          // side of the auxReadPorts binding.
          let preserveVariantHint: AuxValue | undefined;
          let preserveVariantHintComputed = false;
          const resolvePreserveVariantHint = (): AuxValue | undefined => {
            if (preserveVariantHintComputed) return preserveVariantHint;
            preserveVariantHintComputed = true;
            const readBindings = meta.auxReadPorts?.(node.params);
            if (readBindings === undefined) return undefined;
            const firstAuxKey = readBindings.values().next().value;
            if (typeof firstAuxKey !== "string") return undefined;
            preserveVariantHint = portedAuxRead.get(firstAuxKey);
            return preserveVariantHint;
          };

          for (const [portName, auxKey] of writeBindings) {
            const outBytes = outputs.get(portName);
            if (outBytes === undefined) continue;
            const layout = outputsMap.get(portName)?.layout;
            const hint =
              layout === "preserve-input-variant" ? resolvePreserveVariantHint() : undefined;
            const value = auxPortBytesToValue(outBytes, layout, hint);
            aux.set(auxKey, value);
            auxWritten.set(auxKey, value);
          }
        }
      } else {
        // ── Legacy execution path ─────────────────────────────────────
        // Pull the legacy-shape executor out of the registration. For
        // `kind:"legacy"` this is `registration.executor` directly; for
        // `kind:"ported"` it's the preserved `legacy` field that the
        // ported registration carries during the Phase 1 migration
        // window. Frame-parity tests run a ported-registered step type
        // under BOTH dispatch flag values; this is the path the off-flag
        // half takes.
        const executor =
          registration.kind === "ported" ? registration.legacy : registration.executor;
        const result = executor(state, node.params, {
          stepId: node.id,
          path,
          aux,
        });

        auxRead = new Map<string, AuxValue>();
        // Track requested-but-unfulfilled aux reads separately so Slice 9's
        // `validateGraph` can surface them as orphaned-read warnings. The
        // happy-path produces no missing reads, so we lazily allocate the
        // array only on the first miss to keep frame allocation light.
        for (const k of result.auxReads ?? []) {
          const v = aux.get(k);
          if (v !== undefined) {
            auxRead.set(k, v);
          } else {
            if (auxReadMissing === undefined) auxReadMissing = [];
            auxReadMissing.push(k);
          }
        }

        auxWritten = new Map<string, AuxValue>();
        if (result.auxWrites) {
          for (const [k, v] of result.auxWrites) {
            aux.set(k, v);
            auxWritten.set(k, v);
          }
        }

        state = result.state;
      }

      // Per-iteration / per-track / per-round stepId suffix: ensures every
      // frame in the flat trace has a unique stepId even when the same
      // children run N times (iterate, for-each-subgraph) or in parallel
      // tracks (Feistel). The trace store's `setTrace` preserves the
      // scrubber by canonical stepId across re-runs — the suffixes make
      // that work for multi-block AND multi-track AND multi-round.
      // Canonicalization lives in `@/core/step-id`.
      const emittedStepId = composeStepId(node.id, branchPath, blockIndex, roundPath);

      const frame: TraceFrame = {
        index: frameIndex++,
        path,
        stepId: emittedStepId,
        stepType: node.type,
        params: node.params,
        stateBefore,
        stateAfter: cloneState(state),
        auxRead,
        auxWritten,
        ...(auxReadMissing !== undefined ? { auxReadMissing } : {}),
        ...(blockIndex !== undefined ? { blockIndex } : {}),
        ...(branchPath.length > 0 ? { branchPath: [...branchPath] } : {}),
      };
      frames.push(frame);
    }
  };

  /**
   * Expand one `feistel-round` node. Slices the round's input bytes by
   * each track's `inputBytes`, walks each track's children in declaration
   * order with `branchPath` stamped, applies the combine, and emits the
   * synthetic rejoin frame.
   *
   * Pre-conditions enforced at runtime:
   *   - parent-scope `state.shape === "bytes"` (Feistel is bytes-shape today;
   *     a future bitvec-shape Feistel would relax this and re-slice via
   *     bit indices).
   *   - tracks declare disjoint byte ranges within the input. Overlap or
   *     out-of-range indices throw with a descriptive message — easier to
   *     catch at the spec edit boundary than via a confusing combine result.
   *   - `tracks.length === 2`. Today's combine ops assume binary Feistel.
   *
   * Failure modes are noisy by design: a malformed `feistel-round` should
   * be caught immediately when the user clicks Run, not silently produce
   * a misshapen trace.
   */
  const runFeistelRound = (
    node: FeistelRoundGroup,
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
    roundPath: readonly number[],
  ): void => {
    if (node.tracks.length !== 2) {
      throw new Error(
        `feistel-round '${node.id}': exactly 2 tracks supported today, got ${node.tracks.length}`,
      );
    }
    if (state.shape !== "bytes") {
      throw new Error(`feistel-round '${node.id}': requires bytes-shape state, got ${state.shape}`);
    }
    const inputBytes = state.bytes;
    const feistelPath = [...path, node.id];

    // Slice each track's input and validate index coverage.
    const trackInputs: Uint8Array[] = [];
    const seenIndices = new Set<number>();
    for (let t = 0; t < node.tracks.length; t++) {
      const track = node.tracks[t];
      if (!track) throw new Error(`feistel-round '${node.id}': track ${t} is undefined`);
      const sliced = new Uint8Array(track.inputBytes.length);
      for (let i = 0; i < track.inputBytes.length; i++) {
        const idx = track.inputBytes[i];
        if (idx === undefined || idx < 0 || idx >= inputBytes.length) {
          throw new Error(
            `feistel-round '${node.id}': track ${t} inputBytes[${i}]=${String(idx)} out of range [0, ${inputBytes.length})`,
          );
        }
        if (seenIndices.has(idx)) {
          throw new Error(
            `feistel-round '${node.id}': track ${t} reuses byte index ${idx} declared by an earlier track`,
          );
        }
        seenIndices.add(idx);
        sliced[i] = inputBytes[idx] ?? 0;
      }
      trackInputs.push(sliced);
    }

    // Walk each track's children with state set to that track's input.
    // The track's name (defaulting to its stringified index) gets pushed
    // onto branchPath so emitted frames carry track membership.
    const trackOutputs: Uint8Array[] = [];
    for (let t = 0; t < node.tracks.length; t++) {
      const track = node.tracks[t];
      if (!track) throw new Error(`feistel-round '${node.id}': track ${t} is undefined`);
      const trackName = track.name ?? String(t);
      const trackInput = trackInputs[t];
      if (!trackInput) throw new Error(`feistel-round '${node.id}': missing input for track ${t}`);

      // Empty-track passthrough: zero frames emitted; output = input.
      // This is the COMMON case for the L track in textbook Feistel.
      if (track.children.length === 0) {
        trackOutputs.push(new Uint8Array(trackInput));
        continue;
      }

      // Set state to the track's sliced input and walk its children.
      // Using `cloneState` here keeps state's TypeScript type as the full
      // `State` union — a direct `state = { shape: "bytes", ... }` would
      // narrow state to BytesState locally, then TS can't see that
      // `walk()` may reassign it through closure to any other variant,
      // making the shape-check below appear unreachable.
      state = cloneState({ shape: "bytes", bytes: new Uint8Array(trackInput) });
      walk(track.children, feistelPath, blockIndex, [...branchPath, trackName], roundPath);

      // Track exit: snapshot the final state's bytes as the track output.
      const exitState: State = state;
      if (exitState.shape !== "bytes") {
        throw new Error(
          `feistel-round '${node.id}': track '${trackName}' ended with state shape ${exitState.shape}; only bytes is supported`,
        );
      }
      trackOutputs.push(new Uint8Array(exitState.bytes));
    }

    // Apply the combine. By convention track 0 is L, track 1 is R.
    const L_in = trackInputs[0];
    const R_in = trackInputs[1];
    const L_out = trackOutputs[0];
    const R_out = trackOutputs[1];
    if (!L_in || !R_in || !L_out || !R_out) {
      throw new Error(`feistel-round '${node.id}': internal slicing inconsistency`);
    }
    const combineMeta = COMBINE_KINDS[node.combineKind];
    const combined = combineMeta.apply(L_in, L_out, R_in, R_out);

    // Reconstruct the round's output bytes by writing each track's new
    // bytes back to its declared inputBytes positions. This is the inverse
    // of the slicing step — preserves the user's byte ordering even for
    // non-contiguous track ranges (a future "split by parity" cipher would
    // care; DES doesn't because L = [0..3], R = [4..7]).
    const outputBytes = new Uint8Array(inputBytes);
    const writeTrack = (track: { readonly inputBytes: readonly number[] }, bytes: Uint8Array) => {
      for (let i = 0; i < track.inputBytes.length; i++) {
        const idx = track.inputBytes[i];
        if (idx === undefined) continue;
        outputBytes[idx] = bytes[i] ?? 0;
      }
    };
    const lTrack = node.tracks[0];
    const rTrack = node.tracks[1];
    if (!lTrack || !rTrack) {
      throw new Error(`feistel-round '${node.id}': internal track-write inconsistency`);
    }
    writeTrack(lTrack, combined.new_L);
    writeTrack(rTrack, combined.new_R);

    // The stateBefore for the rejoin frame is the concatenation of track
    // outputs in declaration order — that's the value the combine actually
    // observes. stateAfter is the combined output. Together they make the
    // rejoin frame self-describing: the inspector reads (stateBefore,
    // stateAfter) and the L_in/L_out/R_in/R_out 4-arg view is rebuilt by
    // `edge-value-lookup` from the trackOutputs + trackInputs context.
    const preCombineBytes = new Uint8Array(L_out.length + R_out.length);
    preCombineBytes.set(L_out, 0);
    preCombineBytes.set(R_out, L_out.length);
    const rejoinStateBefore: BytesState = { shape: "bytes", bytes: preCombineBytes };
    const rejoinStateAfter: BytesState = { shape: "bytes", bytes: new Uint8Array(outputBytes) };

    // Resume parent-scope state from the combined output. The rejoin
    // frame's stateAfter == this value; the next sibling in the parent
    // scope sees the round's output as its incoming state.
    state = { shape: "bytes", bytes: outputBytes };

    // Stash all 4 track snapshots into the rejoin frame's params so the
    // inspector (`<RejoinFrameView />`) can render the 4-arg combine
    // formula's inputs without reconstructing them from the trace.
    //
    // Why params, not a new TraceFrame field: a new field would ripple
    // through every TraceFrame consumer (graph derivation, frame-format
    // helpers, document schema if we ever serialized frames). The
    // 4 snapshots are combine-specific data, semantically equivalent to
    // any other "what this frame was given to operate on" payload that
    // params carries for ordinary leaves. Uint8Array → number[] for the
    // Json contract; the view re-wraps as Uint8Array at read time.
    //
    // Note on redundancy: stateBefore already encodes (L_out || R_out)
    // as a single concat, and stateAfter encodes (new_L || new_R). Two
    // of the four params duplicate that data — kept anyway for the
    // inspector's symmetry and to make the rejoin frame self-describing
    // (a stale narrator looking at just `frame.params` can render the
    // full 4-arg formula). The arrays are small (8 bytes each for DES).
    const rejoinStepId = composeStepId(`${node.id}:rejoin`, branchPath, blockIndex, roundPath);
    const rejoinFrame: TraceFrame = {
      index: frameIndex++,
      path,
      stepId: rejoinStepId,
      stepType: REJOIN_STEP_TYPE,
      params: {
        combineKind: node.combineKind,
        L_in: Array.from(L_in),
        L_out: Array.from(L_out),
        R_in: Array.from(R_in),
        R_out: Array.from(R_out),
      },
      stateBefore: rejoinStateBefore,
      stateAfter: rejoinStateAfter,
      auxRead: new Map(),
      auxWritten: new Map(),
      ...(blockIndex !== undefined ? { blockIndex } : {}),
      ...(branchPath.length > 0 ? { branchPath: [...branchPath] } : {}),
    };
    frames.push(rejoinFrame);
  };

  /**
   * Expand one `for-each-subgraph` node (Slice 2.0a). Threads state across
   * iterations — iteration `i+1`'s body input is iteration `i`'s body
   * output, no clone-from-aux per iteration. Each emitted body frame's
   * stepId is appended with `:r{i}` (the new round-suffix); composition
   * with any enclosing `:b{i}` (iterate) / `:t{name}` (Feistel) follows the
   * type-order rule documented on `composeStepId`.
   *
   * Pre-conditions:
   *   - `node.iterationCount` is either a literal `number ≥ 0` OR
   *     `{ fromParam }`. Slice 2.0a only resolves the number form; the
   *     `fromParam` resolution mechanism settles at the first consumer
   *     that needs it (per plan: SHA-256 compression uses literal 64).
   *     Hitting the unimplemented branch throws a noisy error.
   *
   * Side effects: pushes one body frame per (child × iteration) and
   * advances the parent-scope `state` to the final iteration's body
   * output.
   */
  const runForEachSubgraph = (
    node: ForEachSubgraphNode,
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
    roundPath: readonly number[],
  ): void => {
    let count: number;
    if (typeof node.iterationCount === "number") {
      count = node.iterationCount;
    } else {
      // `{ fromParam }` resolution mechanism is deferred to the first
      // consumer that needs it — SHA-256 compression uses literal 64,
      // so Slice 2.0a's toy fixture exercises only the number form.
      // Mirror `iterate`'s noisy failure mode rather than silently
      // defaulting to 0.
      throw new Error(
        `for-each-subgraph '${node.id}': iterationCount.fromParam resolution is not implemented in Slice 2.0a — first consumer with param-form picks up the lookup mechanism`,
      );
    }
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(
        `for-each-subgraph '${node.id}': iterationCount must be a non-negative integer, got ${String(count)}`,
      );
    }

    const childPath = [...path, node.id];
    for (let i = 0; i < count; i++) {
      // State threads across iterations: NO clone-from-aux, NO reset.
      // The body walks with the parent-scope `state` (which equals
      // iteration `i-1`'s body output on iteration `i > 0`). Iteration 0
      // sees whatever state existed before the for-each-subgraph node.
      walk(node.children, childPath, blockIndex, branchPath, [...roundPath, i]);
    }
  };

  walk(spec.steps, [], undefined, [], []);

  return {
    frames,
    finalState: state,
    finalAux: aux as Aux,
  };
};
