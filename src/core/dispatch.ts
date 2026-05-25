/**
 * Dispatch-mode derivation for a CipherSpec.
 *
 * Slice 2.7 of the universal-port dataflow plan
 * (`docs/plans/universal-port-dataflow.md`). The runtime's
 * `RuntimeInput.portedDispatchEnabled` flag selects between the legacy
 * single-thread executor path and the port-native dispatch path; this
 * module derives whether a given spec REQUIRES the latter.
 *
 * Why derive rather than carry an explicit field on `CipherSpec`?
 * User pick (b) at Slice 2.7 start: registry-derived. The registration's
 * `kind` discriminator is already the source of truth — adding a
 * redundant spec field would couple CipherSpec, document schemaVersion,
 * and runtime dispatch semantics into one bundle that has to evolve
 * together. Deriving keeps each layer independent: a port-native step
 * registration is the SOLE knob that flips a spec onto the ported path.
 *
 * The precise rule, matching the slice's pass/fail gate ("AES /
 * Speck32-64 / Serpent-128 / DES continue running under
 * `portedDispatchEnabled: false`"): a spec requires ported dispatch
 * IFF at least one leaf's registration is **pure port-native** —
 * `kind === "ported" && legacy === undefined`. Lifted-legacy
 * registrations (`kind: "ported"` WITH a `legacy` fallback) do NOT
 * trigger the flag, because the runtime's off-flag path can fall back
 * to the legacy executor and Phase 1's parity matrix pins byte-equality
 * across both dispatches. SHA-256 is the first cipher to declare any
 * pure port-native leaves (`generic.aux-load-bytes@1`,
 * `byte-slice@1`, etc.) so it is the first spec to derive `true`.
 *
 * Asymmetry note (per advisor): a false positive degrades gracefully —
 * the runtime branches per-step on `registration.kind`, so enabling
 * ported dispatch on a spec with only legacy steps is harmless and
 * already covered by the Phase 1 parity matrix. A false negative would
 * throw `step type "X" is port-native; requires portedDispatchEnabled:
 * true` at run time. Tests therefore enumerate every shipped spec to
 * pin both directions.
 */

import type { StepRegistry } from "./registry";
import type { CipherSpec, StepNode } from "./types";

/**
 * Walk the spec tree depth-first; for every leaf, look up its
 * registration and short-circuit on the first pure port-native one. All
 * five container kinds — `group`, `iterate`, `feistel-round` (with
 * `tracks[].children`), `for-each-subgraph`, and
 * `for-each-subgraph-with-history` — must be descended into so a
 * port-native leaf injected anywhere in the tree is detected. Missing
 * a container kind is the easy bug; the synthetic Feistel test in
 * `tests/requires-ported-dispatch.test.ts` catches it.
 *
 * Returns `false` for an empty spec (vacuously: no leaf requires
 * ported dispatch).
 */
export const requiresPortedDispatch = (spec: CipherSpec, registry: StepRegistry): boolean => {
  const visit = (nodes: readonly StepNode[]): boolean => {
    for (const node of nodes) {
      if (node.kind === "step") {
        const reg = registry.getRegistration(node.type);
        // Pure port-native registration: `kind: "ported"` AND no
        // `legacy` fallback executor. This is the exact condition the
        // runtime checks before throwing the "requires
        // portedDispatchEnabled: true" error (runtime.ts:607).
        if (reg !== undefined && reg.kind === "ported" && reg.legacy === undefined) {
          return true;
        }
        continue;
      }
      if (node.kind === "feistel-round") {
        // Feistel rounds branch into N parallel tracks, each carrying
        // its own children array. A port-native leaf can live inside
        // any track (e.g., a future DES rebuild's expansion or
        // S-box composition).
        for (const track of node.tracks) {
          if (visit(track.children)) return true;
        }
        continue;
      }
      // Remaining container kinds (group, iterate, for-each-subgraph,
      // for-each-subgraph-with-history) all carry a single
      // `children: readonly StepNode[]` field — exhaustive over the
      // current StepNode union (types.ts:522).
      if (visit(node.children)) return true;
    }
    return false;
  };
  return visit(spec.steps);
};
