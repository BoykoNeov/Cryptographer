/**
 * Slice S2(h) of `docs/plans/sha-256-density-polish.md` — 2026-05-26.
 *
 * Pins the asymmetric endpoint semantics of `dropAuxOnlyStateEdges`:
 * the FROM-side suppression keeps AES `key-expansion → first-state-
 * consumer` redundancy out of the graph, while the narrower TO-side set
 * preserves a legitimate state-thread handoff INTO an aux-only-root sink.
 *
 * **History note (scaffolding-suppression A3a).** The original TO-side
 * coverage used SHA-256's `msg-schedule → W-publish` handoff (W-publish
 * = `generic.state-to-aux-bytes@1`, in the WIDE aux-only set via
 * `shapeContract.input === "any"` but excluded from the NARROW sink set
 * because it declares `meta.stateInputPort`). A3a retired the `W-publish`
 * bridge — the message-schedule FES now publishes W into `aux["W"]`
 * directly via `outputAux`, and the schedule→rounds connection is drawn
 * by the `outputAux`-writer stamping in `deriveEdges`. With no
 * `state-to-aux-bytes@1` leaf left in any shipped spec, the TO-side
 * sink-preservation path is no longer exercised by a real cipher; those
 * two SHA-256 cases were removed. The AES from-side cases below still
 * pin the original filter intent + the legacy-spec regression budget.
 *
 * Surface tested:
 *   - `deriveAuxGraph` (real spec → graph w/ inferred edges)
 *   - The two-set memo computation (replicated locally to mirror
 *     `GraphView`'s pre-filter pipeline)
 *   - `dropAuxOnlyStateEdges` with both sets
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { deriveAuxGraph, dropAuxOnlyStateEdges } from "@/core/graph";
import type { StepRegistry } from "@/core/registry";
import type { CipherSpec, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

/**
 * Replicates GraphView's `auxOnlyRootIds` memo (Path 1 + Path 2). The
 * wider set used for from-side filtering AND layout-lift; tests pin
 * the registry-driven heuristic without dragging the UI tree in.
 */
const computeAuxOnlyRootIds = (spec: CipherSpec, registry: StepRegistry): Set<string> => {
  const out = new Set<string>();
  for (const n of spec.steps) {
    if (n.kind !== "step") continue;
    const contract = registry.getDoc(n.type)?.shapeContract;
    if (contract && contract.input === "any") {
      out.add(n.id);
      continue;
    }
    const reg = registry.getRegistration(n.type);
    const hasPortInputs = n.portInputs !== undefined && Object.keys(n.portInputs).length > 0;
    if (
      reg?.kind === "ported" &&
      reg.meta?.stateInputPort === undefined &&
      reg.meta?.stateOutputPort === undefined &&
      !hasPortInputs
    ) {
      out.add(n.id);
    }
  }
  return out;
};

/**
 * Replicates GraphView's `auxOnlyRootSinkIds` memo: the subset of
 * `auxOnlyRootIds` whose leaves lack `meta.stateInputPort` (so the
 * inferred consecutive-siblings spine edge INTO them is misleading).
 */
const computeAuxOnlyRootSinkIds = (
  spec: CipherSpec,
  registry: StepRegistry,
  wide: ReadonlySet<string>,
): Set<string> => {
  const out = new Set<string>();
  for (const n of spec.steps) {
    if (n.kind !== "step" || !wide.has(n.id)) continue;
    const reg = registry.getRegistration(n.type);
    // Same kind-narrow as `GraphView`'s `auxOnlyRootSinkIds` memo —
    // `meta` only exists on the `kind: "ported"` variant of the
    // StepRegistration discriminated union.
    const stateInputPort = reg?.kind === "ported" ? reg.meta?.stateInputPort : undefined;
    if (stateInputPort === undefined) out.add(n.id);
  }
  return out;
};

describe("dropAuxOnlyStateEdges — asymmetric endpoint sets (S2(h))", () => {
  it("SHA-256: a pure aux-reading root (`init.fetch-H`) belongs to BOTH the wide and narrow sets", () => {
    // The wide/narrow distinction only diverges for a leaf that lifts to
    // the preamble (wide) yet still reads the state thread (excluded from
    // narrow). Post scaffolding-suppression A3a, SHA-256 has no such leaf
    // (the `W-publish` state-to-aux-bytes bridge that used to is gone — W
    // now broadcasts via the FES `outputAux`). What remains is the
    // symmetric case: `init.fetch-H` (`aux-load-bytes@1`) reads the
    // materialized aux["H"], declares no `stateInputPort`, and so sits in
    // BOTH sets — the from-side filter applies to it uniformly.
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);
    expect(wide.has("init.fetch-H")).toBe(true);
    expect(narrow.has("init.fetch-H")).toBe(true);
  });

  it("AES-128: key-expansion has no outgoing state spine edge (from-side invariant)", () => {
    // The original filter intent — AES's leading aux-only root must not
    // carry an outgoing identity-passthrough spine edge, because the real
    // state lands at the first consumer via the `$input` source, not via
    // key-expansion's (aux-only) state passthrough.
    //
    // Retargeted to the byte-native `aes128Spec` in Phase 5 Slice 5.1
    // (2026-05-30) when the matrix ECB fixture retired. Byte-native AES is
    // structurally cleaner than the matrix era: key-expansion's first-sibling
    // consumer reads `$input` (a portInputs binding), so `inferStateEdges`
    // never emits a key-expansion → successor spine edge in the first place
    // — and `dropAuxOnlyStateEdges` is a no-op belt over it. Either way the
    // headline invariant holds: NO outgoing state spine edge from the
    // leading aux-only root in the final graph.
    const spec = aes128Spec;
    const registry = buildDefaultRegistry();
    const raw = deriveAuxGraph(emptyTrace(), spec, { registry });

    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);
    expect(wide.has("key-expansion")).toBe(true);
    // key-expansion has no stateInputPort → in BOTH sets.
    expect(narrow.has("key-expansion")).toBe(true);

    // The invariant, robust to whether suppression happens at inference time
    // or in the filter: after `dropAuxOnlyStateEdges` there is no outgoing
    // state spine edge from key-expansion.
    const filtered = dropAuxOnlyStateEdges(raw, wide, narrow);
    const postFilter = filtered.edges.filter(
      (e) => e.from === "key-expansion" && e.kind === "state" && e.auxKey === "state",
    );
    expect(postFilter).toEqual([]);
  });

  it("AES-128: NO change vs. the pre-S2(h) symmetric filter behavior (regression budget zero for legacy specs)", () => {
    // S2(h) is purely additive on these ciphers — every aux-only root in
    // an AES/Speck/Serpent spec has no `stateInputPort` (none of their
    // key-schedules read the state thread), so the narrower sink set
    // equals the wider source set, and the asymmetric filter collapses to
    // the original symmetric behavior. Pin byte-equal edge set between the
    // old (two-arg) and new (three-arg) calls.
    const spec = aes128Spec;
    const registry = buildDefaultRegistry();
    const raw = deriveAuxGraph(emptyTrace(), spec, { registry });

    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);

    const oldCall = dropAuxOnlyStateEdges(raw, wide);
    const newCall = dropAuxOnlyStateEdges(raw, wide, narrow);
    expect(newCall.edges).toEqual(oldCall.edges);
  });
});
