/**
 * Legal-source enumeration + shape-compat classification for the port-wiring
 * editor (universal-port plan Phase 4d-bis).
 *
 * The wiring editor lets the user rebind ONE input port on a leaf to a
 * different upstream output port. The editor's whole correctness hinges on a
 * single question: **for input port P on leaf L, what is the set of sources
 * the user is allowed to pick?** Get that set right and the rest falls out —
 * the gesture is just a picker over the set, the "mismatch" glyph is just a
 * tag on a member of the set, and the worst failure (a binding that THROWS at
 * runtime) becomes unrepresentable by construction.
 *
 * **Two failure classes, kept separate** (conflating them ships specs that
 * crash on Run instead of coercing):
 *
 *   1. **Scope violation** — a binding the runtime cannot resolve (the target
 *      lives in a different walk-frame scope). The runtime THROWS
 *      (`resolveBinding` in `runtime.ts`). We prevent this BY CONSTRUCTION:
 *      `legalSourcesForInput` only ever returns scope-legal targets, so the
 *      editor cannot offer a cross-scope source. This is NOT a soft warning.
 *
 *   2. **byteLength mismatch** among scope-legal targets — the source emits a
 *      different number of bytes than the input port declares. The runtime
 *      COERCES (warn-and-run, a visible trace step). `classifyBinding` tags
 *      these `"coerce"` so the editor can paint a red glyph; the binding is
 *      still allowed. "Permissiveness IS the pedagogy."
 *
 * **The scope model** (verified against `runtime.ts:151-179` and the parallel
 * walk in `spec-shapes.ts`): scope = one walk-frame. Siblings within a `walk`
 * call share a `nodeOutputs` map; nested scopes (group bodies, iterate /
 * for-each iterations) start FRESH; the reserved `$input` source is seeded
 * ONLY at the top scope. So the legal-source set for an input port on leaf L
 * is exactly:
 *
 *   - every PRECEDING node in L's own scope (sibling leaf's declared output
 *     ports, or a sibling container's published `outputPorts`) — the runtime
 *     records each node's outputs only AFTER walking it, so forward / self
 *     references are unresolvable and excluded here;
 *   - PLUS, when L sits at the head of a seeded container body, the synthetic
 *     port the runtime injects at body entry: `port(<containerId>, "in")` for
 *     a seeded group / port-mode iterate (and `port(<containerId>, "chain")`
 *     for a chaining iterate);
 *   - PLUS, at the TOP scope only, `port($input, "out")`.
 *
 * **Drift guard.** These scope rules are mirrored from `spec-shapes.ts`'s
 * `walk` (the validator). The two MUST agree; `tests/port-sources.test.ts`
 * pins it from both sides: a SUPERSET test (every binding every shipped spec
 * already declares must appear in this enumerator's output — proving we agree
 * with the validator on all real data) and a STRICT-EXCLUSION test (a nested
 * leaf must NOT enumerate `$input` or a cross-scope sibling — the bound this
 * superset test can't catch). One divergence is deliberate: the validator is
 * lenient about `$input` from a nested scope (`spec-shapes.ts:229` — "tighten
 * this to a top-scope-only check"); this enumerator is STRICT, because the
 * runtime only seeds `$input` at the top scope and a nested `$input` binding
 * would throw. No shipped spec wires `$input` from a nested scope, so the
 * superset test stays green.
 */

import { resolvePortMap } from "./port-projection";
import type { StepRegistry } from "./registry";
import type { CipherSpec, PortShape, StepLeaf, StepNode } from "./types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "./types";

/** byteLength-compat verdict for a (target input, source output) pairing. */
export type BindingCompat = "ok" | "coerce";

/** One pickable upstream source for an input port. */
export type LegalSource = {
  /** Upstream node id (a sibling leaf/container, the container seed, or `$input`). */
  readonly node: string;
  /** Output port name on that node. */
  readonly port: string;
  /**
   * Declared `PortShape` of that output port, when known. `undefined` for
   * container outputs, container seeds, and `$input` — none of which declare a
   * byteLength, so they are polymorphic (coerce-free) sinks-of-bytes.
   */
  readonly sourceShape?: PortShape;
  /** `classifyBinding(<this input port's shape>, sourceShape)`. */
  readonly compat: BindingCompat;
};

/**
 * Classify whether wiring a source output into a target input would COERCE.
 *
 * `"coerce"` iff BOTH sides declare a concrete `byteLength` and they differ —
 * mirroring the runtime's coercion rule (`port-projection.ts:208-211`: a
 * polymorphic port, i.e. `byteLength` absent, skips coercion entirely). A
 * `layout` difference is advisory only (the runtime always passes raw bytes),
 * so it is NOT reported as `"coerce"` here.
 *
 * Pure + total: reused by the enumerator below, the canvas red glyph, and any
 * inspector line that wants to explain a wiring.
 */
export const classifyBinding = (
  targetInput: PortShape | undefined,
  sourceOutput: PortShape | undefined,
): BindingCompat => {
  if (
    targetInput?.byteLength !== undefined &&
    sourceOutput?.byteLength !== undefined &&
    targetInput.byteLength !== sourceOutput.byteLength
  ) {
    return "coerce";
  }
  return "ok";
};

/** A scope-local map: node id → (output port name → its declared shape, if any). */
type ScopeMap = Map<string, Map<string, PortShape | undefined>>;

type ScopeCapture = {
  /** The upstream sources visible to the target leaf at its processing point. */
  readonly scope: ScopeMap;
  /** True iff the target leaf lives directly at the top scope (where `$input` exists). */
  readonly isTopScope: boolean;
  /** The target leaf node itself (for reading its input-port shapes). */
  readonly targetLeaf: StepLeaf;
};

/**
 * The ports the runtime injects at the head of a seeded container body. Mirrors
 * the seed logic in `spec-shapes.ts`'s `walk` (the group + port-mode iterate
 * branches) and `runtime.ts`'s body-scope seeding. Returns `undefined` for any
 * container that does NOT seed its body (FES in either mode, aux-mode iterate).
 */
const bodySeedScope = (node: StepNode): ScopeMap | undefined => {
  if (node.kind === "group" && node.seedInput !== undefined) {
    return new Map([[node.id, new Map([["in", undefined]])]]);
  }
  if (node.kind === "iterate" && node.seedInput !== undefined) {
    const ports = new Map<string, PortShape | undefined>([["in", undefined]]);
    // A chaining iterate (byte-native CBC) also injects `port(id, "chain")`.
    if (node.chainInput !== undefined) ports.set("chain", undefined);
    return new Map([[node.id, ports]]);
  }
  return undefined;
};

/** This leaf's declared output ports → shapes (empty for non-ported leaves). */
const leafOutputPorts = (
  node: StepLeaf,
  registry: StepRegistry,
): Map<string, PortShape | undefined> => {
  const out = new Map<string, PortShape | undefined>();
  const registration = registry.getRegistration(node.type);
  if (registration?.kind === "ported") {
    for (const [portName, shape] of resolvePortMap(registration.shape.outputs, node.params)) {
      out.set(portName, shape);
    }
  }
  return out;
};

/**
 * Walk the spec to find `stepId` and capture the upstream scope visible to it.
 * Returns `null` when no LEAF with that id exists (a container id, or a typo).
 *
 * The walk mirrors `spec-shapes.ts`'s scope semantics exactly: leaf outputs are
 * recorded AFTER the leaf (preceding-sibling visibility), container outputs are
 * recorded BEFORE descent (a following sibling can wire to a finished
 * container), and each container body descends with a fresh scope plus its
 * `bodySeedScope`. Capture happens BEFORE the target's own outputs are recorded,
 * so a leaf never appears in its own legal-source set.
 */
const captureScope = (
  spec: CipherSpec,
  registry: StepRegistry,
  stepId: string,
): ScopeCapture | null => {
  let result: ScopeCapture | null = null;

  const walk = (nodes: readonly StepNode[], isTop: boolean, seed?: ScopeMap): void => {
    const scope: ScopeMap = new Map();
    if (seed) for (const [id, ports] of seed) scope.set(id, ports);

    for (const node of nodes) {
      if (result) return; // target already found in an earlier branch — unwind.

      if (node.kind === "step") {
        if (node.id === stepId) {
          // Snapshot the scope as it stands BEFORE this leaf records its own
          // outputs — exactly the preceding-sibling set the runtime resolves.
          result = { scope, isTopScope: isTop, targetLeaf: node };
          return;
        }
        scope.set(node.id, leafOutputPorts(node, registry));
        continue;
      }

      // Container: publish its outputs into THIS scope before descending, then
      // walk its body in a fresh (non-top) scope with the appropriate seed.
      const declared = node.outputPorts ?? ["out"];
      const cPorts = new Map<string, PortShape | undefined>();
      for (const portName of declared) cPorts.set(portName, undefined);
      scope.set(node.id, cPorts);

      walk(node.children, false, bodySeedScope(node));
    }
  };

  walk(spec.steps, true);
  return result;
};

/** This leaf's declared input-port shape for `portName`, when known. */
const inputShapeOf = (
  leaf: StepLeaf,
  portName: string,
  registry: StepRegistry,
): PortShape | undefined => {
  const registration = registry.getRegistration(leaf.type);
  if (registration?.kind !== "ported") return undefined;
  return resolvePortMap(registration.shape.inputs, leaf.params).get(portName);
};

/**
 * Enumerate every scope-legal source the user may bind to input port `portName`
 * on leaf `stepId`, each annotated with its `byteLength`-compat verdict against
 * that input port. Returns `[]` when `stepId` is not a leaf.
 *
 * The list is ordered: `$input` first (top scope only), then the visible scope
 * entries in spec order (a container seed, then preceding siblings) — a stable
 * order the dropdown and canvas highlight can rely on. The result deliberately
 * INCLUDES whatever the port is currently bound to (so the dropdown can show it
 * as the selected option); clearing a port is a separate "— unwired —" choice
 * the caller adds.
 *
 * `portName` only affects the per-source `compat` tag (the scope-legal SET is
 * the same for every input port on the leaf); it is taken as a parameter so a
 * caller asking about a specific port gets correctly-tagged results.
 */
export const legalSourcesForInput = (
  spec: CipherSpec,
  registry: StepRegistry,
  stepId: string,
  portName: string,
): LegalSource[] => {
  const capture = captureScope(spec, registry, stepId);
  if (capture === null) return [];

  const targetShape = inputShapeOf(capture.targetLeaf, portName, registry);
  const sources: LegalSource[] = [];

  // `$input` is reachable ONLY at the top scope (the runtime seeds it there
  // alone). A nested-scope binding to `$input` would throw at runtime, so it is
  // excluded by construction here.
  if (capture.isTopScope) {
    sources.push({
      node: INPUT_SOURCE_ID,
      port: INPUT_SOURCE_PORT,
      compat: classifyBinding(targetShape, undefined),
    });
  }

  for (const [nodeId, ports] of capture.scope) {
    if (nodeId === stepId) continue; // defensive — capture precedes self-record.
    for (const [port, shape] of ports) {
      sources.push({
        node: nodeId,
        port,
        ...(shape !== undefined ? { sourceShape: shape } : {}),
        compat: classifyBinding(targetShape, shape),
      });
    }
  }

  return sources;
};
