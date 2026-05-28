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

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { deriveAuxGraph } from "@/core/graph";
import type { Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
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

  it("SHA-256: `init.fetch-H → init-working-vars` port-flow edge exists", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Post scaffolding-suppression A1: `init-working-vars` declares
    // `portInputs: { input: port("init.fetch-H", "output") }` (was
    // `H-constant` before A1 retired the standalone constant-load leaf).
    const match = graph.edges.some(
      (e) => e.from === "init.fetch-H" && e.to === "init-working-vars" && e.kind === "state",
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
    // since A1 — an aux-load-bytes@1 leaf feeding init-working-vars).
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

  it("SHA-256: legitimate state-thread handoffs into round bodies are KEPT", () => {
    // Round groups are transparent in `inferStateEdges` — the chain
    // descends through `hasSpineContent`'s children rather than
    // pushing the group id as a chain element. So the spine through
    // rounds reads `init-working-vars → round.0.state-in →
    // (port-flow inside round.0) → round.0.state-out →
    // round.1.state-in → ...`. The state-thread handoff is between
    // the round's exit (bytes-to-state@1, writes state) and the next
    // round's entry (state-to-bytes@1, reads state).
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const legacyStateEdges = graph.edges.filter((e) => e.kind === "state" && e.auxKey === "state");
    const hasEdge = (from: string, to: string): boolean =>
      legacyStateEdges.some((e) => e.from === from && e.to === to);
    // Entry into the round body — init-working-vars (writes state)
    // feeds the first round's state-in.
    expect(hasEdge("init-working-vars", "round.0.state-in")).toBe(true);
    // Inter-round handoff via state-thread (each round's exit →
    // next round's entry).
    expect(hasEdge("round.0.state-out", "round.1.state-in")).toBe(true);
    expect(hasEdge("round.62.state-out", "round.63.state-in")).toBe(true);
    // Exit from the round chain into the final-add block.
    expect(hasEdge("round.63.state-out", "final.state-in")).toBe(true);
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

  it("AES-128 ECB (legacy): byte-identical edges with or without registry", () => {
    // AES has zero `portInputs` declarations, so `inferPortEdges`
    // returns []. With `requiresPortedDispatch(aes128EcbSpec) === false`,
    // `inferStateEdges` still fires regardless of whether registry is
    // passed. Pin byte-equality of the structural edges between the two
    // call signatures — using an empty trace avoids needing a fully
    // valid initialAux; the spine + container-mediated edges are
    // spec-derived, not trace-derived.
    const registry = buildDefaultRegistry();
    const withRegistry = deriveAuxGraph(emptyTrace(), aes128EcbSpec, { registry });
    const withoutRegistry = deriveAuxGraph(emptyTrace(), aes128EcbSpec);
    expect(withRegistry.edges.length).toBe(withoutRegistry.edges.length);
    expect(withRegistry.edges).toEqual(withoutRegistry.edges);
  });

  it("Legacy specs called without registry: state-spine inference still fires (backward compat)", () => {
    // The ~110 existing `deriveAuxGraph(trace, spec)` callsites in the
    // test suite don't pass a registry; they must continue to see the
    // pre-S2 behavior. Concretely: AES-128 ECB without registry still
    // emits the consecutive-siblings spine.
    const graph = deriveAuxGraph(emptyTrace(), aes128EcbSpec);
    const stateEdges = graph.edges.filter((e) => e.kind === "state");
    // Even on an empty trace, the spine is derived from spec structure
    // alone. AES-128 ECB has multiple consecutive-sibling pairs at root
    // and inside rounds; the count must be > 0.
    expect(stateEdges.length).toBeGreaterThan(0);
  });
});
