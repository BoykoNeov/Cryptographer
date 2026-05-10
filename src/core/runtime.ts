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
 */
export const runSpec = (spec: CipherSpec, registry: StepRegistry, input: RuntimeInput): Trace => {
  const frames: TraceFrame[] = [];
  let state: State = cloneState(input.initialState);
  const aux = new Map<string, AuxValue>(input.initialAux ?? []);

  let frameIndex = 0;

  const walk = (nodes: readonly StepNode[], path: readonly string[]): void => {
    for (const node of nodes) {
      if (node.kind === "group") {
        walk(node.children, [...path, node.id]);
        continue;
      }

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

      frames.push({
        index: frameIndex++,
        path,
        stepId: node.id,
        stepType: node.type,
        params: node.params,
        stateBefore,
        stateAfter: cloneState(state),
        auxRead,
        auxWritten,
      });
    }
  };

  walk(spec.steps, []);

  return {
    frames,
    finalState: state,
    finalAux: aux as Aux,
  };
};
