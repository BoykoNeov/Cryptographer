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
  ForEachSubgraphWithHistoryNode,
  State,
  StepExecutor,
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
    // ─── Scope-local node-output map (Slice 2.6a) ──────────────────────
    // Records each leaf's emitted output-port bytes so downstream siblings
    // can resolve declared `portInputs` references. Per `Q-edges-2` user
    // pick: scope is one walk-frame (siblings within the same `walk` call
    // share the map; nested scopes — group bodies, iterate iterations,
    // for-each-subgraph iterations — start fresh). Cross-scope wiring is
    // deferred to Slice 2.6b (SHA-256's constant chips need to feed
    // compression-body leaves across the for-each-subgraph boundary; the
    // scoping rule will be reconsidered then).
    //
    // Key = upstream node id (leaf OR container) — NOT the suffixed
    // `stepId` — portInputs references the design-time spec id, not
    // the runtime emit id. Value = map of output-port-name → bytes.
    const nodeOutputs = new Map<string, Map<string, Uint8Array>>();

    /**
     * Publish a container's exit-state bytes to `nodeOutputs` under each
     * of its declared output ports (Slice 2.6a — Q-edges-4 user pick
     * "Author-declared per node, defaulting to `out`"). Called after
     * each container's case body, with `state` holding the container's
     * exit value:
     *   - group: last child's output state.
     *   - iterate: last iteration's matrix (matrix4x4-bytes).
     *   - for-each-subgraph state-thread: body's final state.
     *   - for-each-subgraph item-array: concatenated per-iteration bytes.
     *   - for-each-subgraph-with-history: full concatenated history bytes.
     *   - feistel-round: rejoin combined output bytes.
     *
     * All shipped exit shapes (bytes, matrix4x4-bytes, bitvec) are
     * `stateToPortBytes`-encodable; bigint throws inside that helper if
     * a future container produces one. Multi-output containers (e.g.,
     * one with both "out" = concat AND "history" = per-iteration bytes
     * exposed separately) all receive the SAME bytes today — sufficient
     * for SHA-256's message-schedule-into-compression handoff in 2.6b.
     */
    const publishContainerOutputs = (
      containerId: string,
      outputPorts: readonly string[] | undefined,
    ): void => {
      const ports = outputPorts ?? ["out"];
      const bytes = stateToPortBytes(state, state.shape);
      const outMap = new Map<string, Uint8Array>();
      for (const port of ports) outMap.set(port, bytes);
      nodeOutputs.set(containerId, outMap);
    };

    for (const node of nodes) {
      if (node.kind === "group") {
        walk(node.children, [...path, node.id], blockIndex, branchPath, roundPath);
        publishContainerOutputs(node.id, node.outputPorts);
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
        publishContainerOutputs(node.id, node.outputPorts);
        continue;
      }

      if (node.kind === "feistel-round") {
        runFeistelRound(node, path, blockIndex, branchPath, roundPath);
        publishContainerOutputs(node.id, node.outputPorts);
        continue;
      }

      if (node.kind === "for-each-subgraph") {
        runForEachSubgraph(node, path, blockIndex, branchPath, roundPath);
        publishContainerOutputs(node.id, node.outputPorts);
        continue;
      }

      if (node.kind === "for-each-subgraph-with-history") {
        runForEachSubgraphWithHistory(node, path, blockIndex, branchPath, roundPath);
        publishContainerOutputs(node.id, node.outputPorts);
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
        // ── Ported execution path ─────────────────────────────────────
        // Two registration shapes coexist post-Slice-2.6a:
        //   (1) Lifted-legacy ported — `meta` present. Inputs come from a
        //       State + Aux projection driven by `meta.stateInputPort` /
        //       `meta.auxReadPorts`. Per Q-edges-3 user pick, portInputs
        //       (if any) OVERRIDE the projection on a per-port basis;
        //       unbound ports fall back to the projection (the Slice 1.x
        //       contract, preserved here byte-equal).
        //   (2) Pure port-native — `meta` absent. ALL inputs must come
        //       from `node.portInputs` resolved against `nodeOutputs`
        //       (the scope-local map built up by prior siblings). An
        //       unbound port throws.
        //
        // The inputs map is built once and consumed by the executor; the
        // resolution-vs-projection ordering above keeps existing lifted-
        // legacy specs byte-equal to their Slice 1.11 parity matrix.
        const meta = registration.meta;
        const inputs = new Map<string, Uint8Array>();

        // Step A — portInputs (universal-port Slice 2.6a). Resolve each
        // declared sink-side edge against `nodeOutputs`. Same-scope only
        // in 2.6a; a reference to a node outside the current walk frame
        // is "node not found" and throws. Cross-scope wiring is deferred
        // to 2.6b when SHA-256 surfaces the first real consumer.
        if (node.portInputs !== undefined) {
          for (const [portName, binding] of Object.entries(node.portInputs)) {
            const upstreamOutputs = nodeOutputs.get(binding.node);
            if (upstreamOutputs === undefined) {
              throw new Error(
                `port-input resolution: leaf '${node.id}' input port '${portName}' references upstream node '${binding.node}' which has no recorded outputs in this scope (universal-port plan Phase 2 Slice 2.6a — same-scope wiring only)`,
              );
            }
            const upstreamBytes = upstreamOutputs.get(binding.port);
            if (upstreamBytes === undefined) {
              throw new Error(
                `port-input resolution: leaf '${node.id}' input port '${portName}' references upstream node '${binding.node}' port '${binding.port}' but that port was not emitted`,
              );
            }
            inputs.set(portName, upstreamBytes);
          }
        }

        // Step B — state input from meta (if lifted-legacy). Skipped
        // when portInputs already wired this port; preserves Q-edges-3
        // "portInputs override projection on a per-port basis".
        if (meta?.stateInputPort !== undefined && !inputs.has(meta.stateInputPort)) {
          inputs.set(meta.stateInputPort, stateToPortBytes(state, meta.stateLayout));
        }

        // Step C — aux reads from meta (if lifted-legacy). Skipped per
        // port when portInputs already wired it (same precedence rule).
        // `portedAuxRead` is built ONLY from successful aux projections —
        // a port wired via portInputs contributes no `frame.auxRead`
        // entry (it's a state edge, not an aux read), preserving the
        // Slice 1.x contract for unwired ports.
        //
        // **Iteration order matters** — see ProjectionMetadata's contract.
        // The metadata's `auxReadPorts(params)` Map must iterate in the
        // same order the legacy executor declares `auxReads`, or
        // `auxReadMissing` arrays diverge between the two paths.
        const readBindings = meta?.auxReadPorts?.(node.params) ?? new Map<string, string>();
        const portedAuxRead = new Map<string, AuxValue>();
        for (const [portName, auxKey] of readBindings) {
          if (inputs.has(portName)) continue; // portInputs already wired it
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

        // Step D — pure port-native guard. With no `meta`, every declared
        // input port MUST have been wired via portInputs. An unbound
        // port surfaces here with a sharper message than the post-
        // executor "input port X missing" thrown deep in the executor.
        if (meta === undefined) {
          const inputShapes = resolvePortMap(registration.shape.inputs, node.params);
          for (const [portName] of inputShapes) {
            if (!inputs.has(portName)) {
              throw new Error(
                `port-native step '${node.id}' (type '${node.type}'): input port '${portName}' is not wired (declare it in spec node's \`portInputs\` map — universal-port plan Phase 2 Slice 2.6a)`,
              );
            }
          }
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

        // ─── Save outputs to scope-local nodeOutputs (Slice 2.6a) ──────
        // Every ported leaf's outputs are recorded so downstream siblings
        // can resolve declared `portInputs` references. Pure port-native
        // leaves use this as their ONLY way to publish results;
        // lifted-legacy leaves publish via this map AND via state/aux
        // reconstruction below (the dual surfaces coexist — a downstream
        // port-native consumer reads via portInputs, while a downstream
        // legacy consumer reads via state/aux as before).
        //
        // Stored by spec-time `node.id` (NOT the suffixed runtime
        // `emittedStepId`), matching how portInputs references its
        // upstream (the spec author writes `{ node: "round.1.shift" }`,
        // not a per-iteration emit id). Map values clone-on-write would
        // be wasted — the executor's outputs are already a fresh Map of
        // Uint8Arrays per `PortedExecutor`'s contract.
        const recorded = new Map<string, Uint8Array>();
        for (const [portName, bytes] of outputs) {
          recorded.set(portName, bytes);
        }
        nodeOutputs.set(node.id, recorded);

        // Reconstruct state from the output port if one is declared.
        // Aux-only steps (`generic.aux-load@1` et al.) leave state
        // untouched — the runtime's `state` variable is preserved across
        // the ported call so the caller's shape (matrix4x4-bytes, bytes,
        // etc.) survives. Pure port-native steps (no meta) also leave
        // state untouched — same preservation rule.
        if (meta?.stateOutputPort !== undefined) {
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
        //
        // Pure port-native leaves (no meta) skip this entire block —
        // their outputs reach downstream consumers ONLY via portInputs
        // resolution against `nodeOutputs` above, never through aux.
        auxWritten = new Map<string, AuxValue>();
        if (meta?.auxWritePorts !== undefined) {
          const auxWritePortsFn = meta.auxWritePorts;
          const writeBindings = auxWritePortsFn(node.params);
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
            const readBindings = meta?.auxReadPorts?.(node.params);
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
        //
        // Slice 2.1a (universal-port plan): port-native registrations
        // omit `legacy` entirely — they have no single-thread shape
        // executor to fall back to. Hitting one of these here means a
        // spec wired a port-native step but the caller forgot to enable
        // `portedDispatchEnabled: true`. Surface it with the exact
        // message the slice's test pins.
        // Resolve the legacy-shape executor up-front so the narrowing is
        // obvious to TS: the compound `kind === "ported" && legacy ===
        // undefined` guard above doesn't propagate through the ternary.
        let executor: StepExecutor;
        if (registration.kind === "ported") {
          if (registration.legacy === undefined) {
            throw new Error(
              `step type "${node.type}" is port-native; requires portedDispatchEnabled: true`,
            );
          }
          executor = registration.legacy;
        } else {
          executor = registration.executor;
        }
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
   * Expand one `for-each-subgraph` node (Slice 2.0a + 2.0b). Two modes
   * share the same node kind:
   *
   *  - **State-thread mode** (Slice 2.0a): `iterationCount` set, the four
   *    item-array fields absent. Body inherits parent-scope `state` on
   *    iteration 0; iteration `i+1`'s body input is iteration `i`'s body
   *    output. No per-iteration reset.
   *  - **Item-array mode** (Slice 2.0b): item-array fields all set,
   *    `iterationCount` absent. Parent-scope `state.bytes` is sliced into
   *    `blockByteLength`-sized chunks; each chunk decodes via
   *    `portBytesToState(slice, blockLayout)` and seeds the body's
   *    `state` for one iteration; each iteration's body-exit state
   *    encodes via `stateToPortBytes(state, blockLayout)` and accumulates;
   *    on node exit, the accumulator concatenates back into parent-scope
   *    `state` as a BytesState. `iterationCount` auto-derives as
   *    `state.bytes.length / blockByteLength`.
   *
   * Each body frame's stepId appends `:r{i}` (the round-suffix);
   * composition with any enclosing `:b{i}` (iterate) / `:t{name}`
   * (Feistel) follows the type-order rule documented on `composeStepId`.
   *
   * Pre-conditions enforced loudly (mirrors `iterate`'s noisy failure
   * posture):
   *   - Mode-exclusivity: exactly one of {iterationCount only, all four
   *     item-array fields} is set. Both-modes / partial-fields throw.
   *   - State-thread: `iterationCount` is either a literal `number ≥ 0`
   *     OR `{ fromParam }`. The number form runs; `{ fromParam }` throws
   *     until SHA-256-variant or similar spec lands its lookup mechanism.
   *   - Item-array: parent-scope `state.shape === "bytes"`;
   *     `blockByteLength` divides `state.bytes.length` evenly.
   *
   * Side effects: pushes one frame per (child × iteration) and advances
   * the parent-scope `state` (to body's final-iteration state in
   * state-thread mode; to concatenated BytesState in item-array mode).
   */
  const runForEachSubgraph = (
    node: ForEachSubgraphNode,
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
    roundPath: readonly number[],
  ): void => {
    // Mode discriminator: presence of ANY item-array field selects
    // item-array mode; the runtime then enforces that ALL four are
    // present AND iterationCount is absent (partial-field configs are
    // authoring bugs that throw before any iteration runs).
    const hasItemArrayMode =
      node.inputArrayPort !== undefined ||
      node.outputsPort !== undefined ||
      node.blockByteLength !== undefined ||
      node.blockLayout !== undefined;

    if (hasItemArrayMode) {
      // Mode-exclusivity invariant 1: all four item-array fields present.
      if (
        node.inputArrayPort === undefined ||
        node.outputsPort === undefined ||
        node.blockByteLength === undefined ||
        node.blockLayout === undefined
      ) {
        throw new Error(
          `for-each-subgraph '${node.id}': item-array mode requires ALL of inputArrayPort + outputsPort + blockByteLength + blockLayout to be set (got inputArrayPort=${String(node.inputArrayPort)}, outputsPort=${String(node.outputsPort)}, blockByteLength=${String(node.blockByteLength)}, blockLayout=${String(node.blockLayout)})`,
        );
      }
      // Mode-exclusivity invariant 2: iterationCount must be absent in
      // item-array mode. It auto-derives from input bytes / blockByteLength.
      if (node.iterationCount !== undefined) {
        throw new Error(
          `for-each-subgraph '${node.id}': item-array mode forbids iterationCount (auto-derives from inputArrayPort byte length / blockByteLength); got iterationCount=${JSON.stringify(node.iterationCount)}`,
        );
      }

      const blockSize = node.blockByteLength;
      if (!Number.isInteger(blockSize) || blockSize <= 0) {
        throw new Error(
          `for-each-subgraph '${node.id}': blockByteLength must be a positive integer, got ${String(blockSize)}`,
        );
      }

      // Source: parent-scope state.bytes. Slice 2.0b ships the
      // "read from parent state" mechanism; Phase 4+ adds explicit
      // port-edge wiring (semantic `inputArrayPort` name is the anchor).
      if (state.shape !== "bytes") {
        throw new Error(
          `for-each-subgraph '${node.id}': item-array mode requires parent-scope state.shape === "bytes" (got "${state.shape}")`,
        );
      }
      const inputBytes = state.bytes;
      if (inputBytes.length % blockSize !== 0) {
        throw new Error(
          `for-each-subgraph '${node.id}': inputArrayPort byte length ${inputBytes.length} is not a multiple of blockByteLength ${blockSize}`,
        );
      }
      const count = inputBytes.length / blockSize;

      const childPath = [...path, node.id];
      const outputBytes = new Uint8Array(inputBytes.length);

      for (let i = 0; i < count; i++) {
        // Slice + decode: per-block bytes → State variant per blockLayout.
        // `subarray` aliases inputBytes; `portBytesToState` constructs the
        // State via `bytesToState` which copies the underlying buffer
        // (cloneState fresh-Uint8Array per case), so no caller-owned
        // bytes leak into the body's state.
        const slice = inputBytes.subarray(i * blockSize, (i + 1) * blockSize);
        state = portBytesToState(slice, node.blockLayout);

        // Body walks with the per-block state. The :r{i} suffix on
        // emitted frames comes from `roundPath.push(i)` via composeStepId.
        walk(node.children, childPath, blockIndex, branchPath, [...roundPath, i]);

        // Encode + accumulate: body's exit state → port bytes.
        // `stateToPortBytes` asserts shape match against blockLayout, so a
        // body that emits a wrong-shape state surfaces here, not silently.
        const outSlice = stateToPortBytes(state, node.blockLayout);
        if (outSlice.length !== blockSize) {
          throw new Error(
            `for-each-subgraph '${node.id}': iteration ${i} body produced ${outSlice.length} bytes; expected blockByteLength=${blockSize}`,
          );
        }
        outputBytes.set(outSlice, i * blockSize);
      }

      // Node exit: concatenated bytes become parent-scope state. Mirrors
      // legacy `concat-blocks` semantics; concat-blocks downstream of an
      // item-array for-each-subgraph becomes redundant in port-native
      // specs but still works under the legacy aux contract.
      state = { shape: "bytes", bytes: outputBytes };
      return;
    }

    // ── State-thread mode (Slice 2.0a) ──────────────────────────────────
    // No item-array fields set, so iterationCount must be present.
    if (node.iterationCount === undefined) {
      throw new Error(
        `for-each-subgraph '${node.id}': state-thread mode requires iterationCount (set the four item-array fields for item-array mode instead)`,
      );
    }
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

  /**
   * Expand one `for-each-subgraph-with-history` node (Slice 2.0c).
   * Per-iteration lookback primitive: body reads named priors from a
   * runtime-maintained history buffer via `aux["prior-{N}"]` for each `N`
   * in `lookbackOffsets`.
   *
   * Lifecycle per invocation:
   *   1. **Seed** — slice parent-scope `state.bytes` into
   *      `historyEntryByteLength` chunks; copy each into the local
   *      `history` array. Seed count = `bytes.length / entryLen`. Must be
   *      ≥ `max(lookbackOffsets)` so iteration 0 has something to read.
   *   2. **Per iteration** — for each `N` in offsets, snapshot the
   *      previous `aux["prior-{N}"]` (so a pre-existing key isn't
   *      clobbered), then `aux.set("prior-{N}", history[absIndex - N])`.
   *      Reset state to `Uint8Array(entryLen)` (blank slate the body
   *      writes into via lookback reads + computation). Walk children
   *      with `:r{t}` suffix. Validate body's exit state shape/length;
   *      push a fresh copy into history.
   *   3. **Restore** — after the loop, restore aux keys from the
   *      snapshot map (delete if pre-state was absent, set otherwise).
   *   4. **Exit** — concatenate full history (seeds + outputs) into a
   *      flat `BytesState`; assign to parent-scope `state`.
   *
   * Per-outer-reset is trivial by construction: `history` is a local
   * variable scoped to this invocation. When this node sits inside an
   * outer loop (iterate / for-each-subgraph / a future
   * persistAcrossOuter-enabled FES-with-history), each outer iteration
   * triggers a fresh invocation, hence fresh history.
   *
   * Pre-conditions enforced loudly (noisy failure posture, matching
   * `iterate` / `for-each-subgraph` precedent):
   *   - `lookbackOffsets` non-empty.
   *   - Every offset ≥ 1 and an integer (offset 0 would read the not-
   *     yet-written current iteration's entry).
   *   - `historyEntryByteLength` ≥ 1 and an integer.
   *   - `state.shape === "bytes"`; `bytes.length` divisible by entry.
   *   - `seedCount ≥ max(offsets)`.
   *   - `iterationCount` resolves to a non-negative integer (param-form
   *     throws as deferred, mirroring `for-each-subgraph`).
   *   - Body exit state per iteration is bytes-shape AND length = entry.
   */
  const runForEachSubgraphWithHistory = (
    node: ForEachSubgraphWithHistoryNode,
    path: readonly string[],
    blockIndex: number | undefined,
    branchPath: readonly string[],
    roundPath: readonly number[],
  ): void => {
    // ── Static contract validation ──────────────────────────────────────
    if (node.lookbackOffsets.length === 0) {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': lookbackOffsets must be non-empty (declare at least one offset the body reads from)`,
      );
    }
    for (const offset of node.lookbackOffsets) {
      if (!Number.isInteger(offset) || offset < 1) {
        throw new Error(
          `for-each-subgraph-with-history '${node.id}': every lookbackOffsets entry must be a positive integer (got ${String(offset)}; offset 0 would read the not-yet-written current iteration's entry, negative offsets are not history reads)`,
        );
      }
    }
    const entryLen = node.historyEntryByteLength;
    if (!Number.isInteger(entryLen) || entryLen < 1) {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': historyEntryByteLength must be a positive integer, got ${String(entryLen)}`,
      );
    }

    // ── Parent-scope state contract ─────────────────────────────────────
    // Initial history seeds come from parent state.bytes (Slice 2.0c
    // sourcing pick). SHA-256 will arrange for the preceding spec leaves
    // to populate state with W[0..15]; the toy fixture passes seeds in
    // directly via runtime's initialState.
    if (state.shape !== "bytes") {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': parent-scope state.shape must be "bytes" to source initial history seeds (got "${state.shape}")`,
      );
    }
    if (state.bytes.length % entryLen !== 0) {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': parent state.bytes.length ${state.bytes.length} is not a multiple of historyEntryByteLength ${entryLen}`,
      );
    }
    const seedCount = state.bytes.length / entryLen;
    const maxOffset = Math.max(...node.lookbackOffsets);
    if (seedCount < maxOffset) {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': need at least max(lookbackOffsets)=${maxOffset} seeds in initial history (got ${seedCount} seeds from ${state.bytes.length} bytes / entry ${entryLen}); iteration 0 cannot satisfy a lookback deeper than seed count`,
      );
    }

    // ── Iteration count resolution (mirrors for-each-subgraph) ──────────
    let count: number;
    if (typeof node.iterationCount === "number") {
      count = node.iterationCount;
    } else {
      // `{ fromParam }` resolution is deferred to the first param-form
      // consumer per Slice 2.0a precedent. SHA-256's message schedule
      // uses literal 48, so the literal form is what shipped consumers
      // exercise.
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': iterationCount.fromParam resolution is not implemented in Slice 2.0c — first consumer with param-form picks up the lookup mechanism`,
      );
    }
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(
        `for-each-subgraph-with-history '${node.id}': iterationCount must be a non-negative integer, got ${String(count)}`,
      );
    }

    // ── Build initial history (defensive copies — caller bytes don't leak) ─
    const history: Uint8Array[] = [];
    for (let i = 0; i < seedCount; i++) {
      history.push(new Uint8Array(state.bytes.subarray(i * entryLen, (i + 1) * entryLen)));
    }

    // ── Snapshot aux keys we're about to set, so we can restore on exit ─
    // Map value `undefined` means "the key was absent — delete on restore."
    // A pre-existing key with any value is preserved verbatim.
    const auxKeyPrefix = "prior-";
    const snapshot = new Map<string, AuxValue | undefined>();
    for (const offset of node.lookbackOffsets) {
      const k = `${auxKeyPrefix}${offset}`;
      snapshot.set(k, aux.get(k));
    }

    const childPath = [...path, node.id];

    // ── Per-iteration loop ──────────────────────────────────────────────
    for (let t = 0; t < count; t++) {
      const absIndex = seedCount + t;

      // Seed aux["prior-N"] = history[absIndex - N] for each declared
      // offset. The validation above guarantees absIndex - offset ≥ 0
      // for every iteration (seedCount ≥ maxOffset; absIndex grows from
      // seedCount; offset ≤ maxOffset → absIndex - offset ≥ 0).
      for (const offset of node.lookbackOffsets) {
        const k = `${auxKeyPrefix}${offset}`;
        const priorEntry = history[absIndex - offset];
        if (priorEntry === undefined) {
          // Defensive — should be unreachable given the seedCount ≥
          // maxOffset check, but the type system requires the guard.
          throw new Error(
            `for-each-subgraph-with-history '${node.id}': iteration ${t}: history[${absIndex - offset}] missing for offset ${offset} (this is a runtime invariant violation — please file a bug)`,
          );
        }
        aux.set(k, priorEntry);
      }

      // Body's starting state per iteration: blank slate of entryLen
      // zero bytes. The body builds the new history entry from the
      // lookback aux reads + computation; it does NOT inherit running
      // state across iterations (unlike state-thread for-each-subgraph).
      state = { shape: "bytes", bytes: new Uint8Array(entryLen) };

      walk(node.children, childPath, blockIndex, branchPath, [...roundPath, t]);

      // Body exit contract: bytes-shape AND exactly entryLen bytes.
      // Wrong shape is a body authoring bug (using a state-shape that
      // doesn't match the history entry width); wrong length is either
      // a body bug or a mismatched historyEntryByteLength setting.
      //
      // TS narrowed `state` to `BytesState` after the iteration-entry
      // assignment `state = { shape: "bytes", ... }` and can't track
      // that the `walk()` callback may have widened it. Re-widen via
      // the union cast so the shape branch reads cleanly.
      const exitState = state as State;
      if (exitState.shape !== "bytes") {
        throw new Error(
          `for-each-subgraph-with-history '${node.id}': iteration ${t} body exit state.shape must be "bytes" (got "${exitState.shape}"); the body's last leaf must produce a bytes-shape state of historyEntryByteLength=${entryLen} bytes`,
        );
      }
      if (exitState.bytes.length !== entryLen) {
        throw new Error(
          `for-each-subgraph-with-history '${node.id}': iteration ${t} body exit state.bytes.length ${exitState.bytes.length} != historyEntryByteLength ${entryLen}`,
        );
      }

      // Append a defensive copy so subsequent iterations / aux sets
      // can't mutate this entry through their own aliased state buffer.
      history.push(new Uint8Array(exitState.bytes));
    }

    // ── Restore aux keys to pre-invocation values ───────────────────────
    // Delete keys that were absent before; restore prior values for keys
    // that were present. Keeps the surrounding scope's aux untouched
    // across this node's lifetime — friendly to nesting and to specs
    // that happen to use "prior-N"-shaped keys elsewhere.
    for (const [k, prev] of snapshot) {
      if (prev === undefined) {
        aux.delete(k);
      } else {
        aux.set(k, prev);
      }
    }

    // ── Exit state: full history concatenated as flat BytesState ────────
    // Length = (seedCount + count) × entryLen. SHA-256 message schedule:
    // 16 seeds + 48 iterations = 64 × 4 = 256 bytes (W[0..63]).
    const totalLen = history.length * entryLen;
    const totalBytes = new Uint8Array(totalLen);
    for (let i = 0; i < history.length; i++) {
      const entry = history[i];
      if (entry === undefined) {
        throw new Error(
          `for-each-subgraph-with-history '${node.id}': history[${i}] missing during exit concatenation (runtime invariant violation — please file a bug)`,
        );
      }
      totalBytes.set(entry, i * entryLen);
    }
    state = { shape: "bytes", bytes: totalBytes };
  };

  walk(spec.steps, [], undefined, [], []);

  return {
    frames,
    finalState: state,
    finalAux: aux as Aux,
  };
};
