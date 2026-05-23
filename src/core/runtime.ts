import { COMBINE_KINDS, REJOIN_STEP_TYPE } from "./combine-kinds";
import {
  PROJECTION_METADATA,
  auxPortBytesToValue,
  liftLegacyExecutor,
  portBytesToState,
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
   * Phase-0 dual-dispatch flag (universal-port-dataflow plan, task 5).
   * When true AND a leaf's step type is in `PROJECTION_METADATA`, the
   * runtime routes that leaf through the ported execution path:
   *
   *   1. Project state + aux reads into per-port `Uint8Array` inputs via
   *      metadata bindings.
   *   2. Call the lifted `PortedExecutor` (which wraps the legacy executor
   *      via `liftLegacyExecutor`).
   *   3. Reconstruct `State` from the output port; build the emitted
   *      `TraceFrame.auxRead` from the metadata's input-port-to-aux-key
   *      bindings (NOT from the legacy executor's `result.auxReads`).
   *
   * Frames produced under either path are byte-equal for the two
   * Phase-0 targets — pinned by `tests/runtime-ported-dispatch.test.ts`
   * (task 6) via frame-by-frame deep equality.
   *
   * Default: `false`. Existing callers (UI, cipher specs, every shipped
   * test) keep the legacy path until Phase 1 widens the lift to every
   * step type. The flag lives on `RuntimeInput` (per-call) rather than
   * a module-level global so legacy and ported runs can stand side by
   * side in the same test file.
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
 * Suffix application order on per-iteration / per-track stepIds is
 * INNERMOST-FIRST: a leaf inside a feistel-round inside an iterate emits
 * `node.id:t{name}:b{i}` (track suffix first, then block suffix). The
 * walker threads `branchPath` + `blockIndex` through recursion; the
 * suffix string is assembled at frame-construction time. Canonicalization
 * (used by `setTrace` stepId-matching) lives in `@/core/step-id` and
 * strips all suffixes back to the spec-leaf id.
 */
export const runSpec = (spec: CipherSpec, registry: StepRegistry, input: RuntimeInput): Trace => {
  const frames: TraceFrame[] = [];
  let state: State = cloneState(input.initialState);
  const aux = new Map<string, AuxValue>(input.initialAux ?? []);

  let frameIndex = 0;

  // Phase-0 dual-dispatch flag (universal-port-dataflow plan, task 5).
  // Captured once at the call boundary so the per-leaf check in `walk` is
  // a simple `if (portedDispatch && PROJECTION_METADATA.has(node.type))`.
  // Defaults to false → every leaf runs the legacy path; no behavior change
  // for any caller that doesn't opt in.
  const portedDispatch = input.portedDispatchEnabled === true;

  /** Compose the per-emit stepId suffix from runtime context. Innermost-
   *  first: `:t{name}` for track membership goes before `:b{i}` for block
   *  index, so a leaf inside a Feistel inside an iterate emits
   *  `node.id:t{name}:b{i}`. */
  const composeStepId = (
    baseId: string,
    branchPath: readonly string[],
    blockIndex: number | undefined,
  ): string => {
    let id = baseId;
    for (const name of branchPath) id += `:t${name}`;
    if (blockIndex !== undefined) id += `:b${blockIndex}`;
    return id;
  };

  // `blockIndex` is threaded through recursive walks: undefined at the
  // top level; set to the current iteration index when inside an iterate's
  // children. Used to suffix emitted step ids and stamp frame metadata.
  // `branchPath` is the analogous thread for Feistel tracks: empty at
  // the top level; appended with the track's name (or stringified index)
  // when inside a `feistel-round`'s track body. Outer-first ordering.
  const walk = (
    nodes: readonly StepNode[],
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
  ): void => {
    for (const node of nodes) {
      if (node.kind === "group") {
        walk(node.children, [...path, node.id], blockIndex, branchPath);
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
          walk(node.children, iteratePath, i, branchPath);
          outBlocks.push(cloneState(state));
        }

        aux.set(node.outBlocksAux, outBlocks);
        continue;
      }

      if (node.kind === "feistel-round") {
        runFeistelRound(node, path, blockIndex, branchPath);
        continue;
      }

      // Leaf step.
      const stateBefore = cloneState(state);

      // ─── Ported dispatch (universal-port-dataflow plan) ────────────────
      // When `portedDispatch` is on AND the leaf's step type has
      // projection metadata available, route through the ported execution
      // path:
      //   1. Build `inputs` (state port + aux ports per `auxReadPorts`).
      //   2. Call the lifted `PortedExecutor`.
      //   3. Reconstruct `State` from the output port (if declared) OR
      //      leave state untouched (aux-only primitives — Slice 1.2).
      //   4. Build the TraceFrame's `auxRead` from the metadata's input-
      //      port-to-aux-key bindings — NOT from the legacy executor's
      //      `result.auxReads`. This is the load-bearing claim: the
      //      trace can be expressed purely in port projections + tags.
      //   5. Build `auxWritten` from output-port-to-aux-key bindings
      //      (Slice 1.2). The runtime also writes back into the live
      //      `aux` map so downstream legacy / ported steps see the same
      //      Aux state.
      //
      // **Metadata source (Slice 1.2)** — two routes coexist through
      // Slice 1.8:
      //   (a) `registry.getRegistration(node.type)?.kind === "ported"` →
      //       the ported variant carries `meta: ProjectionMetadata`. This
      //       is the long-term home (Decision C — colocated meta).
      //   (b) `PROJECTION_METADATA.get(node.type)` side-map → the
      //       Phase-0 entries (`generic.byte-substitution@1`,
      //       `generic.add-round-key@1`) still register as `kind:"legacy"`
      //       in Slice 1.2 because their colocation lands in Slice 1.4.
      //       The side-map is the bridge.
      // Slice 1.9 deletes the side-map (Decision A); until then, the
      // registry has priority and the side-map is the fallback.
      //
      // Otherwise (the default for every shipped caller): the legacy path
      // below runs unchanged.
      const registration = registry.getRegistration(node.type);
      if (!registration) throw new Error(`unknown step type: ${node.type}`);
      const meta = portedDispatch
        ? registration.kind === "ported"
          ? registration.meta
          : PROJECTION_METADATA.get(node.type)
        : undefined;
      let auxRead: Map<string, AuxValue>;
      let auxReadMissing: string[] | undefined;
      let auxWritten: Map<string, AuxValue>;

      if (meta !== undefined) {
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
          // Strictness: the bound aux key MUST hold a Uint8Array. The
          // Phase-0 + Slice-1.2 targets only bind Uint8Array aux. A
          // non-Uint8Array here means a metadata mismatch — surface
          // loudly instead of silently coercing.
          if (!(v instanceof Uint8Array)) {
            throw new Error(
              `ported dispatch: aux "${auxKey}" bound to input port "${portName}" must be Uint8Array, got ${typeof v} (stepId=${node.id}, stepType=${node.type})`,
            );
          }
          inputs.set(portName, new Uint8Array(v));
          portedAuxRead.set(auxKey, new Uint8Array(v));
        }

        // Call the ported executor. For Slice 1.2 every ported entry is
        // a lifted legacy executor; we either pull the pre-lifted closure
        // off the registration OR build one on the fly from the side-map
        // metadata (Phase-0 fallback). `ctx.aux` still carries the live
        // aux map — the legacy executor inside the lift reads via
        // `ctx.aux.get(...)`. Phase 1's Slice 1.9 cuts this channel; until
        // then the dual aux read paths see the same map by construction.
        const ported =
          registration.kind === "ported"
            ? registration.executor
            : liftLegacyExecutor(registration.executor, meta);
        const outputs = ported(inputs, node.params, {
          stepId: node.id,
          path,
          aux,
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
        // Decode layout: when the registration carries a PortContract,
        // the declared output port's `layout` drives reconstruction
        // (`"matrix-cm-4x4"` → MatrixState, `"raw"`/undefined → Uint8Array).
        // Side-map fallback entries (Phase-0 byte-substitution / add-
        // round-key) don't have a contract; they default to raw bytes,
        // which matches their existing aux shape.
        auxWritten = new Map<string, AuxValue>();
        if (meta.auxWritePorts !== undefined) {
          const writeBindings = meta.auxWritePorts(node.params);
          for (const [portName, auxKey] of writeBindings) {
            const outBytes = outputs.get(portName);
            if (outBytes === undefined) continue;
            const layout =
              registration.kind === "ported"
                ? registration.shape.outputs.get(portName)?.layout
                : undefined;
            const value = auxPortBytesToValue(outBytes, layout);
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

      // Per-iteration / per-track stepId suffix: ensures every frame in
      // the flat trace has a unique stepId even when the same children
      // run N times (iterate) or in parallel tracks (Feistel). The trace
      // store's `setTrace` preserves the scrubber by canonical stepId
      // across re-runs — the suffixes make that work for multi-block AND
      // multi-track. Canonicalization lives in `@/core/step-id`.
      const emittedStepId = composeStepId(node.id, branchPath, blockIndex);

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
    const roundPath = [...path, node.id];

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
      walk(track.children, roundPath, blockIndex, [...branchPath, trackName]);

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
    const rejoinStepId = composeStepId(`${node.id}:rejoin`, branchPath, blockIndex);
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

  walk(spec.steps, [], undefined, []);

  return {
    frames,
    finalState: state,
    finalAux: aux as Aux,
  };
};
