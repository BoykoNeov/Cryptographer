/**
 * `deriveAuxGraph` — port-flow edge derivation + legacy state-spine
 * suppression on port-native specs.
 *
 * Slices S2(e) + S2(f) of `docs/plans/sha-256-density-polish.md`,
 * 2026-05-26. Shipped together per advisor (a transitional commit
 * with only S2(e) would emit BOTH port-flow edges AND the legacy
 * consecutive-siblings state-spine for SHA-256's ~60+ port-native
 * top-level leaves — visibly unreadable). The pair is the load-
 * bearing fix for the misdiagnosed "S2 layout problem": the original
 * three smoke symptoms (`msg-schedule → W-publish` invisible, long
 * `H-to-aux → final.fetch-H` arrow, msg-schedule looks like a dead
 * end) were a derivation gap — `portInputs` wasn't being read by
 * `deriveAuxGraph`. This file pins both halves of the fix.
 *
 * Coverage:
 *   - SHA-256 (port-native): each `portInputs` declaration emits a
 *     `kind: "state"` edge from the upstream node's id to the
 *     consumer leaf. Specific consumer fan-in counts match the spec.
 *   - SHA-256: zero state edges from the legacy consecutive-siblings
 *     pass (S2(f) gate fires, the inferred spine is empty for the
 *     port-native top scope).
 *   - AES-128 ECB (legacy): byte-identical to today — `inferPortEdges`
 *     returns empty (no `portInputs` in any AES leaf) and
 *     `inferStateEdges` still owns the spine.
 *   - Legacy specs called without `opts.registry`: state-spine
 *     inference still fires (the backward-compat default for the
 *     ~110 existing callsites that don't pass a registry).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { collapseGraph, deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import type { Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
  initialState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

describe("deriveAuxGraph — port-flow edge derivation (S2(e))", () => {
  it("SHA-256: `final.s_0` has exactly two incoming port-flow edges (operand0, operand1)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    // No need to run — port edges come from the spec, not the trace.
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const incoming = graph.edges.filter((e) => e.to === "final.s0");
    // SHA-256 spec wires `final.s0.portInputs.operand0 ← split-wv.output0`
    // and `final.s0.portInputs.operand1 ← split-H.output0`. Both must
    // surface as edges.
    const sources = incoming.map((e) => e.from).sort();
    expect(sources).toEqual(["final.split-H", "final.split-wv"]);
  });

  it("SHA-256: `final.assemble` has eight incoming port-flow edges (one per word)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const incoming = graph.edges.filter((e) => e.to === "final.assemble");
    // Spec: `portInputs: Object.fromEntries(8 entries of (input{i}, port(`final.s${i}`, "output")))`
    const sources = incoming.map((e) => e.from).sort();
    expect(sources).toEqual([
      "final.s0",
      "final.s1",
      "final.s2",
      "final.s3",
      "final.s4",
      "final.s5",
      "final.s6",
      "final.s7",
    ]);
  });

  it("SHA-256: round 0 is seeded port-to-port from `init.fetch-H` (A3b)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Scaffolding-suppression A3b retired the `init-working-vars`
    // bytes-to-state bridge: round 0's `seedInput` is `port("init.fetch-H",
    // "output")`, and `round.0.split` reads `port("round.0", "in")`. The
    // port-edge derivation resolves that seed reference THROUGH the group's
    // seedInput, so the edge runs `init.fetch-H → round.0.split`.
    const match = graph.edges.some(
      (e) => e.from === "init.fetch-H" && e.to === "round.0.split" && e.kind === "state",
    );
    expect(match).toBe(true);
  });

  it("SHA-256: every port-flow edge has kind:'state' + auxKey:'port-flow' (distinguishes from legacy passthrough)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Port-flow edges are emitted with `kind: "state"` so the renderer
    // treats them as the cipher's primary dataflow, but with a
    // DISTINCT `auxKey: "port-flow"` so `dropAuxOnlyStateEdges`
    // doesn't filter them out from lifted aux-only roots. Spot-check
    // that the discriminator is consistently applied to every port-
    // flow edge from a known port-native source leaf (`init.fetch-H`
    // — an aux-load-bytes@1 leaf; since A3b it seeds round 0 via the
    // group seedInput, so its edge targets `round.0.split`).
    const portFlowFromInitFetchH = graph.edges.filter((e) => e.from === "init.fetch-H");
    expect(portFlowFromInitFetchH.length).toBeGreaterThan(0);
    for (const edge of portFlowFromInitFetchH) {
      expect(edge.kind).toBe("state");
      expect(edge.auxKey).toBe("port-flow");
    }
  });
});

describe("deriveAuxGraph — per-edge state-spine suppression on port-native consumers (S2(f))", () => {
  it("SHA-256: spurious chain through parallel `final.s_i` leaves is suppressed", () => {
    // Without the per-edge gate, the legacy consecutive-siblings rule
    // would emit `final.s0 → final.s1 → final.s2 → ... → final.s7` as
    // state edges (and similarly `split-wv → fetch-H`). The truth is
    // these leaves are PARALLEL: each `final.s_i` reads `split-wv.output_i`
    // and `split-H.output_i` via port-flow, with no sequential
    // relationship between them. Pin the suppression.
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const legacyStateEdges = graph.edges.filter((e) => e.kind === "state" && e.auxKey === "state");
    const hasEdge = (from: string, to: string): boolean =>
      legacyStateEdges.some((e) => e.from === from && e.to === to);
    // All these would be emitted by the unconditional inference pass.
    // The per-edge gate (consumer doesn't read state-thread) must
    // suppress every one.
    expect(hasEdge("final.split-wv", "final.fetch-H")).toBe(false);
    for (let i = 0; i < 7; i++) {
      expect(hasEdge(`final.s${i}`, `final.s${i + 1}`)).toBe(false);
    }
    expect(hasEdge("final.assemble", "final.out")).toBe(false);
  });

  it("SHA-256: round-to-round carry is port-to-port, not a state-thread (A3b)", () => {
    // Scaffolding-suppression A3b retired the `state-in`/`state-out` bridge
    // leaves. The working variables now carry port-to-port: round t+1's
    // `seedInput` reads round t's published `bodyOutput` (round 0 from
    // `init.fetch-H`), and the port-edge derivation resolves each
    // `port("round.{t}", "in")` seed reference THROUGH the group's seedInput.
    // So the round chain is connected by PORT-FLOW edges (auxKey "port-flow"),
    // and NO legacy consecutive-siblings state edge touches any round. (This
    // replaces the pre-A3b state-thread spine that threaded through the
    // now-deleted bridges; the connectivity is the same shape, in port edges.
    // The one surviving legacy state edge, `length-append → msg-schedule`, is
    // the preamble→schedule handoff and touches no round.)
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const portFlow = graph.edges.filter((e) => e.kind === "state" && e.auxKey === "port-flow");
    const hasPort = (from: string, to: string): boolean =>
      portFlow.some((e) => e.from === from && e.to === to);
    // Round 0 seeded from init.fetch-H (resolved through round.0.seedInput).
    expect(hasPort("init.fetch-H", "round.0.split")).toBe(true);
    // Inter-round carry: round t's published exit ("out") → round t+1's split.
    expect(hasPort("round.0", "round.1.split")).toBe(true);
    expect(hasPort("round.62", "round.63.split")).toBe(true);
    // Exit from the round chain into the final-add block.
    expect(hasPort("round.63", "final.split-wv")).toBe(true);
    // No legacy consecutive-siblings state edge touches any round — the
    // round-to-round carry is purely port-flow.
    const legacyStateEdges = graph.edges.filter((e) => e.kind === "state" && e.auxKey === "state");
    const roundTouching = legacyStateEdges.filter(
      (e) => e.from.startsWith("round.") || e.to.startsWith("round."),
    );
    expect(roundTouching).toEqual([]);
  });

  it("SHA-256: pure port-native leaves (aux-load-bytes@1, split-bytes@1) do NOT receive inferred state edges", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const legacyStateEdges = graph.edges.filter((e) => e.kind === "state" && e.auxKey === "state");
    // `init.fetch-H` is `aux-load-bytes@1` (reads aux["H"]; no state meta).
    // It's a root aux source — no inferred legacy state edge should target
    // it. (Was `H-constant` / constant-load@1 before A1 retired that leaf.)
    const initFetchHIncoming = legacyStateEdges.filter((e) => e.to === "init.fetch-H");
    expect(initFetchHIncoming).toEqual([]);
    // `final.split-H` is `split-bytes@1` (pure port-native). Same.
    const splitHIncoming = legacyStateEdges.filter((e) => e.to === "final.split-H");
    expect(splitHIncoming).toEqual([]);
  });

  // (The two "non-ported legacy spec" cases that pinned `inferStateEdges`'s
  // consecutive-siblings fallback + its registry-independence were removed in
  // Slice 5.3e Batch 3 with the inference itself — no shipped spec is
  // non-ported, and the legacy fallback no longer exists.)
});

describe("deriveAuxGraph — A3b follow-ups: collapsed round-carry parity + validateGraph clean", () => {
  // The uncollapsed round carry (init.fetch-H → round.0, round.{t-1} →
  // round.{t}, round.63 → final.split-wv) is pinned above on an empty trace.
  // These two tests close the A3b advisor follow-ups ⓑ + ⓓ:
  //   ⓑ — the carry survives `collapseGraph` over all 64 rounds (the user's
  //       stated biggest A3b risk: a collapse/layout refactor silently
  //       re-islanding the chain — previously verified only by a deleted probe).
  //   ⓓ — `validateGraph` is clean (orphaned-read / unused-write / cycle) on
  //       BOTH the uncollapsed and the collapsed graph.
  // A real "abc" trace is built so `validateGraph` has the recorded aux
  // reads/writes it inspects; the port-flow carry edges themselves are
  // spec-derived (`inferPortEdges`), so they're present regardless of trace.
  const buildSha256Graph = () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: new TextEncoder().encode("abc") },
    });
    return { spec, registry, trace, graph: deriveAuxGraph(trace, spec, { registry }) };
  };
  // The 64 compression-round group ids.
  const allRoundIds = (): ReadonlySet<string> =>
    new Set(Array.from({ length: 64 }, (_, t) => `round.${t}`));

  it("ⓑ: round-to-round carry survives collapsing all 64 rounds", () => {
    // After collapse, each `round.{t}.split` leaf remaps to its `round.{t}`
    // container; the carry source `round.{t-1}` (a group id) is a collapsed
    // container that stays itself. So the uncollapsed `round.{t-1} →
    // round.{t}.split` becomes `round.{t-1} → round.{t}`. `init.fetch-H` and
    // `final.split-wv` aren't rounds → they stay as visible leaves.
    const { graph } = buildSha256Graph();
    const collapsed = collapseGraph(graph, allRoundIds());
    const hasEdge = (from: string, to: string): boolean =>
      collapsed.edges.some((e) => e.from === from && e.to === to && e.kind === "state");
    // Preamble seed into round 0.
    expect(hasEdge("init.fetch-H", "round.0")).toBe(true);
    // Exit from the round chain into the final-add block.
    expect(hasEdge("round.63", "final.split-wv")).toBe(true);
    // Every inter-round boundary carries — no island anywhere in the chain.
    for (let t = 1; t < 64; t++) {
      expect(hasEdge(`round.${t - 1}`, `round.${t}`)).toBe(true);
    }
  });

  it("ⓓ: validateGraph emits zero warnings on SHA-256, uncollapsed AND collapsed", () => {
    // The plan claims a clean validateGraph post-A3b but committed no
    // assertion. GraphView validates the POST-collapse graph, so the collapsed
    // assertion is the load-bearing one: `validateGraph`'s unused-write check
    // reads uncollapsed `trace.frames` but looks them up in the collapsed
    // graph's edges. It stays clean because the rounds only READ K/W from aux
    // (they never write aux), so collapsing them can't orphan a consumed write.
    // If collapsed ever warns where uncollapsed doesn't, that's a real app bug,
    // not a test artifact.
    const { graph, trace } = buildSha256Graph();
    expect(validateGraph(graph, trace)).toEqual([]);
    const collapsed = collapseGraph(graph, allRoundIds());
    expect(validateGraph(collapsed, trace)).toEqual([]);
  });
});
