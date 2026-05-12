import type { StepRegistry } from "./registry";
import { cloneState } from "./state/clone";
import type { Aux, AuxValue, CipherSpec, State, StepNode, Trace, TraceFrame } from "./types";

export type RuntimeInput = {
  readonly initialState: State;
  /** Aux values that should be present before any step runs (e.g. the key). */
  readonly initialAux?: ReadonlyMap<string, AuxValue>;
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
 */
export const runSpec = (spec: CipherSpec, registry: StepRegistry, input: RuntimeInput): Trace => {
  const frames: TraceFrame[] = [];
  let state: State = cloneState(input.initialState);
  const aux = new Map<string, AuxValue>(input.initialAux ?? []);

  let frameIndex = 0;

  // `blockIndex` is threaded through recursive walks: undefined at the
  // top level; set to the current iteration index when inside an iterate's
  // children. Used to suffix emitted step ids and stamp frame metadata.
  const walk = (
    nodes: readonly StepNode[],
    path: readonly string[],
    blockIndex: number | undefined,
  ): void => {
    for (const node of nodes) {
      if (node.kind === "group") {
        walk(node.children, [...path, node.id], blockIndex);
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
          walk(node.children, iteratePath, i);
          outBlocks.push(cloneState(state));
        }

        aux.set(node.outBlocksAux, outBlocks);
        continue;
      }

      // Leaf step.
      const executor = registry.get(node.type);
      const stateBefore = cloneState(state);
      const result = executor(state, node.params, {
        stepId: node.id,
        path,
        aux,
      });

      const auxRead = new Map<string, AuxValue>();
      for (const k of result.auxReads ?? []) {
        const v = aux.get(k);
        if (v !== undefined) auxRead.set(k, v);
      }

      const auxWritten = new Map<string, AuxValue>();
      if (result.auxWrites) {
        for (const [k, v] of result.auxWrites) {
          aux.set(k, v);
          auxWritten.set(k, v);
        }
      }

      state = result.state;

      // Per-iteration step-id suffix: ensures every frame in the flat
      // trace has a unique stepId even when the same children run N times.
      // The trace store's `setTrace` preserves the scrubber by stepId
      // across re-runs — the suffix makes that work for multi-block.
      const emittedStepId = blockIndex !== undefined ? `${node.id}:b${blockIndex}` : node.id;

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
        ...(blockIndex !== undefined ? { blockIndex } : {}),
      };
      frames.push(frame);
    }
  };

  walk(spec.steps, [], undefined);

  return {
    frames,
    finalState: state,
    finalAux: aux as Aux,
  };
};
