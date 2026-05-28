/**
 * Slice S2(h) of `docs/plans/sha-256-density-polish.md` — 2026-05-26.
 *
 * Pins the asymmetric endpoint semantics of `dropAuxOnlyStateEdges`:
 * the FROM-side suppression keeps AES `key-expansion → first-state-
 * consumer` redundancy out of the graph; the narrower TO-side
 * suppression keeps SHA-256's `msg-schedule → W-publish` legitimate
 * state-thread handoff visible.
 *
 * Why this test lives at the integration layer (real specs, real
 * registry) rather than as a unit-level synthetic vector: the
 * pedagogical bug ("message schedule has no outgoing arrows") was
 * surfaced by manual browser smoke on the actual SHA-256 graph view,
 * and a synthetic test wouldn't catch a future regression where the
 * `auxOnlyRootSinkIds` memo's `meta.stateInputPort` heuristic drifts
 * away from how the registry actually classifies `state-to-aux-bytes@1`.
 * Real specs + real registry = test agrees with what the user sees.
 *
 * Surface tested:
 *   - `deriveAuxGraph` (real spec → graph w/ inferred edges)
 *   - The two-set memo computation (replicated locally to mirror
 *     `GraphView`'s pre-filter pipeline)
 *   - `dropAuxOnlyStateEdges` with both sets
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
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
  it("SHA-256: `msg-schedule → W-publish` legacy state edge survives filtering", () => {
    // Pre-S2(h) regression: the symmetric filter saw W-publish in
    // auxOnlyRootIds (Path 1, shapeContract.input === "any") and
    // dropped the edge wholesale — the user saw the schedule as a
    // dead end. The narrower sink set excludes W-publish because
    // `generic.state-to-aux-bytes@1` has `meta.stateInputPort: "state"`
    // (it really does read the state thread to clone bytes into aux).
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const raw = deriveAuxGraph(emptyTrace(), spec, { registry });

    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);

    // Pre-condition: the legacy state edge IS emitted by inferStateEdges
    // (msg-schedule is a container — not in skipStateEdgeTo; W-publish
    // has stateInputPort defined, also not in skipStateEdgeTo).
    const preFilter = raw.edges.some(
      (e) =>
        e.from === "msg-schedule" &&
        e.to === "W-publish" &&
        e.kind === "state" &&
        e.auxKey === "state",
    );
    expect(preFilter).toBe(true);

    // The new asymmetric API must KEEP it.
    const filtered = dropAuxOnlyStateEdges(raw, wide, narrow);
    const postFilter = filtered.edges.some(
      (e) =>
        e.from === "msg-schedule" &&
        e.to === "W-publish" &&
        e.kind === "state" &&
        e.auxKey === "state",
    );
    expect(postFilter).toBe(true);
  });

  it("SHA-256: W-publish appears in the WIDER aux-only set (lifts to preamble row) but NOT the narrower sink set", () => {
    // Pins the registry-driven heuristic that gates the asymmetric
    // behavior. If `state-to-aux-bytes@1`'s registration ever loses
    // its `stateInputPort` declaration, this test fails alongside
    // the user-visible regression — the heuristic and the bug are
    // pinned together.
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);
    expect(wide.has("W-publish")).toBe(true);
    expect(narrow.has("W-publish")).toBe(false);
    // Sanity: a pure aux-reading root leaf DOESN'T read state (no
    // stateInputPort on its meta), so it belongs to BOTH sets — the
    // symmetric contrast to W-publish's asymmetry. Post scaffolding-
    // suppression A1 the standalone aux source is `init.fetch-H`
    // (`aux-load-bytes@1` reading the materialized aux["H"]); the old
    // `K-to-aux`/`H-to-aux` generic.aux-load@1 loaders were retired.
    expect(wide.has("init.fetch-H")).toBe(true);
    expect(narrow.has("init.fetch-H")).toBe(true);
  });

  it("AES-128: `key-expansion → split-blocks` outgoing spine edge is suppressed (from-side rule)", () => {
    // The original filter intent — AES's leading aux-only root drops
    // its outgoing identity-passthrough spine edge, because the
    // synthetic plaintext-input pill already shows the real state
    // landing at the first consumer. S2(h) must preserve this.
    //
    // AES-128 ECB's root-scope DFS chain is `[key-expansion, split-
    // blocks, compute-block-count, ecb-blocks (iterate), concat-blocks]`.
    // The iterate terminates the spine on both sides, so the only edge
    // touching key-expansion from inferStateEdges is `key-expansion →
    // split-blocks`.
    const spec = aes128EcbSpec;
    const registry = buildDefaultRegistry();
    const raw = deriveAuxGraph(emptyTrace(), spec, { registry });

    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);
    expect(wide.has("key-expansion")).toBe(true);
    // key-expansion has no stateInputPort → in BOTH sets.
    expect(narrow.has("key-expansion")).toBe(true);

    // Pre-condition: the legacy consecutive-siblings spine edge from
    // key-expansion to its DFS successor at root scope is emitted.
    const preFilter = raw.edges.some(
      (e) =>
        e.from === "key-expansion" &&
        e.to === "split-blocks" &&
        e.kind === "state" &&
        e.auxKey === "state",
    );
    expect(preFilter).toBe(true);

    // After filtering: no outgoing legacy spine edge from key-expansion.
    const filtered = dropAuxOnlyStateEdges(raw, wide, narrow);
    const postFilter = filtered.edges.filter(
      (e) => e.from === "key-expansion" && e.kind === "state" && e.auxKey === "state",
    );
    expect(postFilter).toEqual([]);
  });

  it("AES-128: NO change vs. the pre-S2(h) symmetric filter behavior (regression budget zero for legacy specs)", () => {
    // S2(h) is purely additive on legacy ciphers — every aux-only
    // root in an AES/Speck/Serpent spec has no `stateInputPort` (none
    // of their key-schedules read the state thread), so the narrower
    // sink set equals the wider source set, and the asymmetric filter
    // collapses to the original symmetric behavior. Pin byte-equal
    // edge set between the old (two-arg) and new (three-arg) calls.
    const spec = aes128EcbSpec;
    const registry = buildDefaultRegistry();
    const raw = deriveAuxGraph(emptyTrace(), spec, { registry });

    const wide = computeAuxOnlyRootIds(spec, registry);
    const narrow = computeAuxOnlyRootSinkIds(spec, registry, wide);

    const oldCall = dropAuxOnlyStateEdges(raw, wide);
    const newCall = dropAuxOnlyStateEdges(raw, wide, narrow);
    expect(newCall.edges).toEqual(oldCall.edges);
  });
});
