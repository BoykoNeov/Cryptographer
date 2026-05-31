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
import { resolvePortMap } from "./port-projection";
import type { StepRegistry } from "./registry";
import type { CipherSpec, PortBinding, StateShape, StepNode } from "./types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "./types";

/**
 * A read-only lookup from a node id (leaf stepId or container id) to the
 * StateShape that exists in the runtime immediately AFTER that node
 * completes. Used by the graph view's drop-anchor greying.
 */
export type ShapeAtAnchor = ReadonlyMap<string, StateShape>;

/** The shape the runtime always installs at the start of each iterate
 *  body iteration. Post-Slice-5.1 the only State shape is `bytes` (the
 *  byte-native port-mode iterate; the aux-mode matrix iterate retired with
 *  the MatrixState shape). Same shape on iterate exit. */
const ITERATE_BODY_SHAPE: StateShape = "bytes";

type WalkContext = {
  readonly registry: StepRegistry;
  readonly shapeAt: Map<string, StateShape>;
  readonly warnings: GraphWarning[];
};

/**
 * Output-port names of the DIRECT children of a body scope, keyed by node
 * id. Used to resolve a looping container's `bodyOutput` `PortBinding`
 * (scaffolding-suppression A2) — the runtime reads the body's full
 * `nodeOutputs` map AFTER the body completes, so `bodyOutput` may name any
 * direct child (forward references are valid here, unlike sink-side
 * `portInputs` which only sees preceding siblings). Mirrors the
 * scope-output recording in `walk`. Ported leaves expose their
 * registration's output ports; containers expose `outputPorts ?? ["out"]`.
 */
const collectDirectChildOutputs = (
  nodes: readonly StepNode[],
  registry: StepRegistry,
): Map<string, ReadonlySet<string>> => {
  const out = new Map<string, ReadonlySet<string>>();
  for (const node of nodes) {
    if (node.kind === "step") {
      const registration = registry.getRegistration(node.type);
      if (registration !== undefined && registration.kind === "ported") {
        const names = new Set<string>();
        for (const [portName] of resolvePortMap(registration.shape.outputs, node.params)) {
          names.add(portName);
        }
        out.set(node.id, names);
      }
      continue;
    }
    out.set(node.id, new Set(node.outputPorts ?? ["out"]));
  }
  return out;
};

/**
 * Validate one container `PortBinding` field (`seedInput` / `bodyOutput`,
 * scaffolding-suppression A2) against a scope's output-port map, reusing
 * the `port-input-unresolvable` warning so no new warning kind / renderer
 * branch is needed. `fieldName` ("seedInput" | "bodyOutput") rides through
 * as the warning's `portName`.
 */
const validateContainerBinding = (
  containerId: string,
  fieldName: string,
  binding: PortBinding,
  scope: ReadonlyMap<string, ReadonlySet<string>>,
  ctx: WalkContext,
): void => {
  // A3b follow-up ⓐ: a container can never reference its OWN output. Its `out`
  // is published only on exit, so `seedInput`/`bodyOutput: port("<self>","out")`
  // is unresolvable at the point the runtime resolves the binding (it throws at
  // run). Guard explicitly because the caller records the container's own
  // output into `scope` (via `recordContainerOutputs`) BEFORE this validation
  // runs — without this check a self-reference would match that freshly-recorded
  // own output and slip silently, a validator-silent/runtime-loud divergence.
  // Covers both the `group` and the FES branches (they share this helper) and
  // both binding fields.
  if (binding.node === containerId) {
    ctx.warnings.push({
      kind: "port-input-unresolvable",
      stepId: containerId,
      portName: fieldName,
      targetNode: binding.node,
      targetPort: binding.port,
      reason: "missing-node",
    });
    return;
  }
  // Reserved `$input` source (A3a): the runtime seeds it into the top scope,
  // so a container `seedInput` pointing at it always resolves on its port.
  // (Byte-native ECB's port-mode iterate reads `port($input, out)` — B1.4.)
  if (binding.node === INPUT_SOURCE_ID) {
    if (binding.port !== INPUT_SOURCE_PORT) {
      ctx.warnings.push({
        kind: "port-input-unresolvable",
        stepId: containerId,
        portName: fieldName,
        targetNode: binding.node,
        targetPort: binding.port,
        reason: "missing-port",
      });
    }
    return;
  }
  const upstream = scope.get(binding.node);
  if (upstream === undefined) {
    ctx.warnings.push({
      kind: "port-input-unresolvable",
      stepId: containerId,
      portName: fieldName,
      targetNode: binding.node,
      targetPort: binding.port,
      reason: "missing-node",
    });
  } else if (!upstream.has(binding.port)) {
    ctx.warnings.push({
      kind: "port-input-unresolvable",
      stepId: containerId,
      portName: fieldName,
      targetNode: binding.node,
      targetPort: binding.port,
      reason: "missing-port",
    });
  }
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
const walk = (
  nodes: readonly StepNode[],
  current: StateShape,
  ctx: WalkContext,
  // Pre-seeded scope outputs visible to this scope's first leaf. Used by a
  // `group` with `seedInput` (A3b) to inject `port(groupId, "in")` so the
  // body's first leaf resolves — mirrors the runtime's `seedOutputs` arg.
  seedScopeOutputs?: ReadonlyMap<string, ReadonlySet<string>>,
): StateShape => {
  let shape = current;
  // Scope-local map of node-id → its declared output port names.
  // Mirrors the runtime's `nodeOutputs` scoping (universal-port plan
  // Phase 2 Slice 2.6a): siblings within one walk frame can wire to
  // each other; nested scopes start fresh. Used to resolve
  // `portInputs` references for `port-input-unresolvable` warnings.
  const scopeOutputs = new Map<string, ReadonlySet<string>>(seedScopeOutputs);
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
      // ─── Port-edge wiring validation (Slice 2.6a) ─────────────────
      // For port-native registrations (kind: "ported" with no `meta`)
      // ALL declared input ports must be wired via `portInputs`. For
      // lifted-legacy or pure-legacy registrations the wiring is
      // optional (state/aux fallback covers unbound ports).
      const registration = ctx.registry.getRegistration(node.type);
      if (registration !== undefined && registration.kind === "ported") {
        const isPureNative = registration.meta === undefined;
        const portInputs = node.portInputs;

        // Validate that every declared portInputs reference resolves.
        if (portInputs !== undefined) {
          for (const [portName, binding] of Object.entries(portInputs)) {
            // Reserved `$input` source (scaffolding-suppression A3a): the
            // runtime seeds it into the top scope, so it always resolves on
            // port INPUT_SOURCE_PORT. (No shipped spec wires `$input` from a
            // nested body, which the runtime would reject; if one ever does,
            // tighten this to a top-scope-only check.)
            if (binding.node === INPUT_SOURCE_ID) {
              if (binding.port !== INPUT_SOURCE_PORT) {
                ctx.warnings.push({
                  kind: "port-input-unresolvable",
                  stepId: node.id,
                  portName,
                  targetNode: binding.node,
                  targetPort: binding.port,
                  reason: "missing-port",
                });
              }
              continue;
            }
            const upstream = scopeOutputs.get(binding.node);
            if (upstream === undefined) {
              ctx.warnings.push({
                kind: "port-input-unresolvable",
                stepId: node.id,
                portName,
                targetNode: binding.node,
                targetPort: binding.port,
                reason: "missing-node",
              });
            } else if (!upstream.has(binding.port)) {
              ctx.warnings.push({
                kind: "port-input-unresolvable",
                stepId: node.id,
                portName,
                targetNode: binding.node,
                targetPort: binding.port,
                reason: "missing-port",
              });
            }
          }
        }

        // For pure port-native leaves, every declared input port must
        // be present in `portInputs` (else the runtime throws on Run).
        if (isPureNative) {
          const inputShapes = resolvePortMap(registration.shape.inputs, node.params);
          for (const [portName] of inputShapes) {
            if (portInputs === undefined || !(portName in portInputs)) {
              ctx.warnings.push({
                kind: "port-input-unwired",
                stepId: node.id,
                portName,
              });
            }
          }
        }

        // Record this leaf's output port names in the scope map so
        // downstream siblings can resolve against it.
        const outputShapes = resolvePortMap(registration.shape.outputs, node.params);
        const outPortNames = new Set<string>();
        for (const [portName] of outputShapes) outPortNames.add(portName);
        scopeOutputs.set(node.id, outPortNames);
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
    // Slice 2.6a — record this container's declared output port names
    // into the scope-local map BEFORE descending into its children, so
    // a downstream sibling can wire `{ node: containerId, port }`.
    // Default port set is `["out"]` per Q-edges-4 user pick. The
    // leaf-step branch above has already returned by this point, so
    // `node.kind` is one of the container kinds — all five have an
    // optional `outputPorts` field per the Slice 2.6a container-edge
    // mixin.
    const recordContainerOutputs = (): void => {
      const declared = node.outputPorts ?? ["out"];
      scopeOutputs.set(node.id, new Set(declared));
    };

    if (node.kind === "group") {
      // Groups are transparent — their child chain shares the parent's
      // current shape, and the group's after-shape is its last child's.
      recordContainerOutputs();
      // A3b group port contract: validate `seedInput` (same-scope preceding
      // sibling) + `bodyOutput` (direct body child), mirroring the FES branch
      // below, so an unresolvable reference surfaces as a pre-Run warning. And
      // when `seedInput` is present, seed the body scope with
      // `port(groupId, "in")` — the runtime injects the carried bytes there,
      // so the body's first leaf reads it and must resolve.
      let seedScope: ReadonlyMap<string, ReadonlySet<string>> | undefined;
      if (node.seedInput !== undefined) {
        validateContainerBinding(node.id, "seedInput", node.seedInput, scopeOutputs, ctx);
        seedScope = new Map([[node.id, new Set(["in"])]]);
      }
      if (node.bodyOutput !== undefined) {
        const bodyScope = collectDirectChildOutputs(node.children, ctx.registry);
        validateContainerBinding(node.id, "bodyOutput", node.bodyOutput, bodyScope, ctx);
      }
      shape = walk(node.children, shape, ctx, seedScope);
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
      recordContainerOutputs();
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
      recordContainerOutputs();
      // A2 container port contract: validate the `seedInput` (same-scope
      // preceding-sibling) and `bodyOutput` (direct body child) bindings so
      // an unresolvable reference surfaces as a pre-Run graph warning rather
      // than only a runtime throw. `scopeOutputs` already holds preceding
      // siblings at this point (incremental, same as `portInputs`); the body
      // scope is collected fresh.
      if (node.seedInput !== undefined) {
        validateContainerBinding(node.id, "seedInput", node.seedInput, scopeOutputs, ctx);
      }
      if (node.bodyOutput !== undefined) {
        const bodyScope = collectDirectChildOutputs(node.children, ctx.registry);
        validateContainerBinding(node.id, "bodyOutput", node.bodyOutput, bodyScope, ctx);
      }
      walk(node.children, "bytes", ctx);
      shape = "bytes";
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    // Iterate has two modes (B1.4).
    recordContainerOutputs();
    if (node.seedInput !== undefined) {
      // Port mode (byte-native ECB): a pure port-graph container like `group`.
      // The body reads the per-block bytes on `port(iterateId, "in")`; the
      // node's output bytes are the concatenated per-iteration `bodyOutput`.
      // Validate both bindings + seed the body scope with `port(iterateId,
      // "in")` so the body's head leaf's portInputs resolve pre-Run.
      validateContainerBinding(node.id, "seedInput", node.seedInput, scopeOutputs, ctx);
      if (node.bodyOutput !== undefined) {
        const bodyScope = collectDirectChildOutputs(node.children, ctx.registry);
        validateContainerBinding(node.id, "bodyOutput", node.bodyOutput, bodyScope, ctx);
      }
      // Seed the body scope with the ports the runtime injects: always
      // `port(iterateId, "in")` (the per-block bytes), and — for a chaining
      // iterate (byte-native CBC, B1.4b) — `port(iterateId, "chain")` (the
      // IV / previous-block value). Without seeding "chain", `cbc-xor`'s
      // `operand1 = port(iterateId, "chain")` read fails to resolve and the
      // validator emits a false-positive `port-input-unresolvable` even though
      // the runtime injects the port and the KAT passes (B1.5 Finding 5).
      // Gating on `chainInput` mirrors the runtime's own injection (chainInput
      // /chainFeedback are a pair, types.ts) and preserves the CORRECT warning
      // for a hypothetical iterate that reads "chain" without declaring it.
      const bodyPorts = new Set(["in"]);
      if (node.chainInput !== undefined) bodyPorts.add("chain");
      const seedScope = new Map([[node.id, bodyPorts]]);
      // Body operates on byte blocks; node exit is the concatenated bytes.
      walk(node.children, "bytes", ctx, seedScope);
      shape = "bytes";
      ctx.shapeAt.set(node.id, shape);
      continue;
    }
    // Aux mode (legacy matrix CBC/CTR) is opaque to shape inference. The body
    // always starts in matrix4x4-bytes (the runtime substitutes
    // state = blocks[i]); the iterate exits leaving state in matrix4x4-bytes
    // (the last iteration's value). We still walk the body so child leaves
    // inside the iterate get their shapeAt entries + any contract checks.
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
