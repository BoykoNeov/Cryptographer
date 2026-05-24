/**
 * Static state-shape inference for a CipherSpec.
 *
 * Every step type can declare (via `StepDocumentation.shapeContract`) which
 * input state shape its executor accepts and what shape it produces. This
 * file walks the spec tree, threading the state shape forward through
 * groups + iterates + leaves, and produces two outputs:
 *
 *   - `inferShapesAtAnchors(spec, registry)` → a map from every node id
 *     (leaf stepId or container id) to the StateShape that exists
 *     immediately AFTER that node completes. The graph view uses this to
 *     decorate each drop anchor with `data-state-shape="..."`, which CSS
 *     then keys off of to grey incompatible anchors during a palette drag.
 *
 *   - `validateShapes(spec, registry)` → a list of `state-shape-mismatch`
 *     `GraphWarning`s for every leaf whose declared input shape doesn't
 *     match the shape arriving from upstream. Concatenated into the
 *     existing graph-warning pipeline in `GraphView.tsx`'s `rawWarnings`
 *     memo. Catches "compute-block-count expects bytes state" *before*
 *     the user clicks Run.
 *
 * Both share a single walker (`walk`) to keep the iterate-scope semantics
 * + the "preserveInput" output shorthand in one place.
 *
 * Iterate handling. The runtime sets `state = blocks[i]` (a MatrixState)
 * for each iteration, then leaves state as the last iteration's matrix on
 * exit (`core/runtime.ts:81–86`). The walker therefore:
 *   - enters the iterate body with shape = `matrix4x4-bytes`;
 *   - exits the iterate with shape = `matrix4x4-bytes`, regardless of the
 *     shape that surrounded the iterate node in the parent scope.
 * This matches what every shipped multi-block spec actually does. A future
 * iterate that carries `BytesState` blocks would need an explicit
 * `bodyInputShape` field on `IterateGroup` — flagged in the plan as out
 * of scope for today.
 *
 * "any" input contract. Steps declared with `input: "any"` (the aux
 * primitives + the various key-expansions) consume no state-shape
 * constraint — they pass shape through untouched. Validation skips them;
 * the palette renders an "any" chip; the drop-anchor greying never
 * activates for them.
 *
 * Steps with no `shapeContract` at all. Treated identically to `"any"`:
 * no validation, no chip, no greying. Keeps the field a soft addition —
 * existing executors that haven't been backfilled still work as before.
 */

import type { GraphWarning } from "./graph";
import type { StepRegistry } from "./registry";
import type { CipherSpec, StateShape, StepNode } from "./types";

/**
 * A read-only lookup from a node id (leaf stepId or container id) to the
 * StateShape that exists in the runtime immediately AFTER that node
 * completes. Used by the graph view's drop-anchor greying.
 */
export type ShapeAtAnchor = ReadonlyMap<string, StateShape>;

/** The shape the runtime always installs at the start of each iterate
 *  body iteration (per `runtime.ts:81`). Same shape on iterate exit. */
const ITERATE_BODY_SHAPE: StateShape = "matrix4x4-bytes";

type WalkContext = {
  readonly registry: StepRegistry;
  readonly shapeAt: Map<string, StateShape>;
  readonly warnings: GraphWarning[];
};

/**
 * Recursive worker that processes one scope's siblings + descends into
 * groups/iterates. Returns the shape that exists at the end of the scope
 * (i.e. after the last sibling finishes). The caller threads this back as
 * the starting shape for the next sibling at its own level.
 *
 * Side effects: writes the after-shape into `ctx.shapeAt` for every node
 * visited, and pushes a `state-shape-mismatch` warning whenever a leaf's
 * declared input disagrees with the current shape.
 */
const walk = (nodes: readonly StepNode[], current: StateShape, ctx: WalkContext): StateShape => {
  let shape = current;
  for (const node of nodes) {
    if (node.kind === "step") {
      const contract = ctx.registry.getDoc(node.type)?.shapeContract;
      if (contract && contract.input !== "any" && contract.input !== shape) {
        ctx.warnings.push({
          kind: "state-shape-mismatch",
          stepId: node.id,
          expected: contract.input,
          got: shape,
        });
      }
      // The leaf's output drives the next sibling's "current" shape. If
      // the contract specifies a concrete output, install it; otherwise
      // (preserveInput, or no contract at all), state shape carries on.
      if (contract && contract.output !== "preserveInput") {
        shape = contract.output;
      }
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    if (node.kind === "group") {
      // Groups are transparent — their child chain shares the parent's
      // current shape, and the group's after-shape is its last child's.
      shape = walk(node.children, shape, ctx);
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    if (node.kind === "feistel-round") {
      // Feistel-round runtime contract: the round operates on a
      // BytesState (parent-scope state.shape === "bytes") — see
      // `core/runtime.ts::runFeistelRound`. Each track gets a sliced
      // BytesState; track-internal shape changes are local to that track
      // (E-expand grows R from 4 to 6 bytes, S-boxes shrink back to 4;
      // the combine reassembles bytes at declared inputBytes positions).
      // Therefore:
      //   - Body input shape is "bytes" (regardless of parent shape).
      //   - Body exit shape is "bytes" (concatenation of track outputs
      //     placed at declared inputBytes positions).
      // Parent-scope shape entering / exiting the round is therefore
      // "bytes". We still walk each track so per-track contract checks
      // fire + shapeAt entries are populated for renderer use.
      for (const track of node.tracks) {
        walk(track.children, "bytes", ctx);
      }
      shape = "bytes";
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    if (node.kind === "for-each-subgraph") {
      // For-each-subgraph has two modes (Slice 2.0a + 2.0b). Discriminator:
      // item-array mode populates ALL four item-array fields; state-thread
      // mode populates iterationCount alone. Mode-exclusivity invariants
      // live in the runtime walker; this validator only routes its shape
      // analysis. A misconfigured node (e.g., both modes' fields present)
      // is left to surface at runtime — that's a noisier failure mode the
      // user wants attributed to the runtime contract, not the static
      // shape walk.
      if (
        node.inputArrayPort !== undefined &&
        node.outputsPort !== undefined &&
        node.blockByteLength !== undefined &&
        node.blockLayout !== undefined
      ) {
        // Item-array mode (Slice 2.0b). The body's INPUT shape per
        // iteration is `blockLayout` (the runtime decodes each byte slice
        // via `portBytesToState(slice, blockLayout)` at iteration entry);
        // the node's AFTER shape is `"bytes"` (the runtime concatenates
        // each iteration's exit bytes back into a flat BytesState).
        // Children still walk so per-child contracts fire + shapeAt
        // entries populate.
        walk(node.children, node.blockLayout, ctx);
        shape = "bytes";
        ctx.shapeAt.set(node.id, shape);
        continue;
      }
      // State-thread mode (Slice 2.0a) — shape-transparent. Unlike
      // iterate, it does NOT clobber state from an aux array between
      // iterations. State threads across iterations, so the body's input
      // shape on iteration 0 is the parent scope's current shape, and the
      // node's after-shape is the shape the body produces (which becomes
      // iteration N+1's input on subsequent iterations and the next
      // sibling's input on node exit).
      //
      // The static walk runs the body ONCE with the current shape: each
      // child contract still gets checked, and the after-shape is whatever
      // the body's last child emits. This is correct because every shipped
      // body produces the same after-shape regardless of iteration count
      // (a "MatrixState in, BytesState out" body would emit the same
      // mismatch every iteration; one walk surfaces it).
      shape = walk(node.children, shape, ctx);
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    if (node.kind === "for-each-subgraph-with-history") {
      // For-each-subgraph-with-history (Slice 2.0c) — body input shape is
      // always "bytes" (the runtime resets state to a zero Uint8Array of
      // historyEntryByteLength at iteration entry); node exit shape is
      // also "bytes" (full history concatenated). Children walk once with
      // the bytes input shape so per-child contracts fire + shapeAt entries
      // populate. Mode-exclusivity / lookbackOffsets validity / seed-count
      // adequacy are runtime contracts — surface at runtime walk, not here.
      walk(node.children, "bytes", ctx);
      shape = "bytes";
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    // Iterate is opaque to shape inference. The body always starts in
    // matrix4x4-bytes (the runtime substitutes state = blocks[i]); the
    // iterate exits leaving state in matrix4x4-bytes (the last iteration's
    // value). We still walk the body so child leaves inside the iterate
    // get their shapeAt entries + any contract checks.
    walk(node.children, ITERATE_BODY_SHAPE, ctx);
    shape = ITERATE_BODY_SHAPE;
    ctx.shapeAt.set(node.id, shape);
  }
  return shape;
};

/**
 * Walk the spec once and return the shape-at-anchor map. The caller passes
 * this map down to the SVG renderer; each `data-drop-anchor` element gets a
 * matching `data-state-shape` attribute so the CSS `.dragging-*` rules can
 * dim incompatible anchors.
 *
 * Pure function — same (spec, registry) → same map. Safe to memoize.
 */
export const inferShapesAtAnchors = (spec: CipherSpec, registry: StepRegistry): ShapeAtAnchor => {
  const ctx: WalkContext = {
    registry,
    shapeAt: new Map(),
    warnings: [],
  };
  walk(spec.steps, spec.inputs.plaintext.shape, ctx);
  return ctx.shapeAt;
};

/**
 * Walk the spec and emit `state-shape-mismatch` warnings for every leaf
 * whose declared `shapeContract.input` doesn't match the inferred upstream
 * shape. Trace-free — runs the moment a spec changes, even if the user
 * hasn't clicked Run.
 *
 * Pure function — same (spec, registry) → same list. The GraphView
 * concatenates this list with `validateGraph(graph, trace)`'s output;
 * orphaned-reads / unused-writes / cycles still come from the trace path.
 */
export const validateShapes = (spec: CipherSpec, registry: StepRegistry): GraphWarning[] => {
  const ctx: WalkContext = {
    registry,
    shapeAt: new Map(),
    warnings: [],
  };
  walk(spec.steps, spec.inputs.plaintext.shape, ctx);
  return ctx.warnings;
};
