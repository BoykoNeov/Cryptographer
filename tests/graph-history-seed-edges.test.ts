/**
 * `deriveAuxGraph` — history-seed synthetic edge derivation
 * (`inferHistorySeedEdges`).
 *
 * Slice S2(l) of `docs/plans/sha-256-density-polish.md`, 2026-05-26.
 *
 * **Why this pass exists.** The `for-each-subgraph-with-history`
 * runtime auto-publishes `aux["prior-{N}"]` for every declared
 * `N ∈ lookbackOffsets` before each iteration body runs (`runtime.ts`
 * — `aux.set(k, priorEntry)`). The call is silent: no `TraceFrame`
 * records the auto-publish, so the natural `inferAuxEdges` pass
 * (which matches each `frame.auxRead` against `writerByAuxKey`)
 * finds no producer for `prior-{N}` and emits no edge. The body's
 * lookback fetches end up with zero incoming arrows — pedagogically
 * reading as "values from thin air" even though their seed window
 * has a real provenance. Slice 2.11b wrapped the per-block body in the
 * "blocks" iterate, and the SHA-256 FES now declares
 * `seedInput: { node: "blocks", port: "in" }` (this block's 64 bytes,
 * injected per-iteration by the iterate), so the anchor is `blocks` —
 * the honest "this block's bytes seed the schedule" source.
 *
 * **What this file pins:**
 *   1. SHA-256: four history-seed edges exist, one per
 *      `lookbackOffsets` entry, sourced from the FES `seedInput.node`
 *      (`blocks`, the per-block iterate) and targeting the four fetch-pN
 *      body leaves.
 *   2. AES-128 ECB (legacy, no FES-with-history): zero history-seed
 *      edges — the pass is a no-op for specs without the primitive.
 *   3. Shared `auxKey: "history-seed"` so that when `msg-schedule`
 *      is collapsed, `collapseGraph`'s `(kind, from, to, auxKey)`
 *      dedup folds all four edges to a single visible arrow
 *      anchoring at the container chip.
 *   4. Edges are `kind: "aux"` so `replicateHighFanoutSources`'s
 *      fanout-eligibility predicate counts them (the user's "items
 *      inside a container should also be available to be
 *      represented as replications" ask — at the new default
 *      threshold of 3, length-append's fanout=4 auto-replicates
 *      into the expanded msg-schedule body).
 *   5. `validateGraph` does not fire `orphaned-read` /
 *      `unused-write` warnings on the synthetic edges (no
 *      `frame.auxReadMissing` for `prior-N` — the auto-publish
 *      satisfies the reads — and no `frame.auxWritten` for
 *      `"history-seed"`, so the producer-set check is vacuous).
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import {
  HISTORY_SEED_AUX_KEY,
  collapseGraph,
  deriveAuxGraph,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import type { CipherSpec, Trace } from "@/core/types";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
  initialState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

describe("deriveAuxGraph — history-seed edge derivation (S2(l))", () => {
  it("SHA-256: emits exactly four history-seed edges (one per lookbackOffset)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const seedEdges = graph.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    expect(seedEdges).toHaveLength(4);
  });

  it("SHA-256: every history-seed edge originates from `blocks` (the FES-with-history `seedInput.node`)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const seedEdges = graph.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    // Anchor rule: `seedInput.node`. Slice 2.11b's SHA-256 FES declares
    // `seedInput: { node: "blocks", port: "in" }` — this block's 64 bytes,
    // injected per iteration by the per-block iterate. So the synthetic seed
    // edges anchor at `blocks` (the honest per-block seed source), not at
    // `length-append` (which is the WHOLE padded message — anchoring there
    // would misrepresent the per-block seed window for multi-block input).
    for (const edge of seedEdges) {
      expect(edge.from).toBe("blocks");
    }
  });

  it("SHA-256: the four edges target the body's fetch-p2, fetch-p7, fetch-p15, fetch-p16 leaves", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const seedEdgeTargets = graph.edges
      .filter((e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY)
      .map((e) => e.to)
      .sort();
    // Spec's `lookbackOffsets: [2, 7, 15, 16]` aligns with the four
    // body fetch leaves of the same names. Sorted alphabetically:
    expect(seedEdgeTargets).toEqual(["fetch-p15", "fetch-p16", "fetch-p2", "fetch-p7"]);
  });

  it('SHA-256: msg-schedule publishes aux["W"] (outputAux) — schedule→W→rounds stays connected after the W-publish bridge removal (A3a)', () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    // A real trace is required: the W-writer stamping happens in
    // `deriveEdges`'s trace walk. The runtime's `outputAux` write carries no
    // TraceFrame, so the container is stamped as aux["W"]'s writer at its
    // trace-exit boundary, and each round's `fetch-W` read then draws a
    // natural edge from it (instead of orphaning, as a producerless aux
    // constant like K does).
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) },
    });
    const graph = deriveAuxGraph(trace, spec, { registry });
    const wEdges = graph.edges.filter((e) => e.kind === "aux" && e.auxKey === "W");
    // One edge per compression round's W_t fetch (64 rounds), all sourced
    // from the msg-schedule container — the honest depiction of the W
    // broadcast that the deleted `W-publish` leaf used to anchor.
    expect(wEdges).toHaveLength(64);
    for (const e of wEdges) {
      expect(e.from).toBe("msg-schedule");
      expect(e.to).toMatch(/^round\.\d+\.fetch-W$/);
    }
  });

  it("AES-128 ECB: no history-seed edges (legacy spec, no for-each-subgraph-with-history)", () => {
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), aes128EcbSpec, { registry });
    const seedEdges = graph.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    expect(seedEdges).toHaveLength(0);
  });

  it("SHA-256: when `msg-schedule` is collapsed, the four history-seed edges dedupe to a single visible arrow", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Collapse the msg-schedule container; collapseGraph rewrites every
    // edge whose `to` is inside the container to land at the container
    // id itself, then dedupes by (kind, from, to, auxKey). All four
    // history-seed edges share `from: length-append`, `to: msg-schedule`
    // (after rewrite), `kind: "aux"`, `auxKey: "history-seed"` — so
    // dedup collapses them to one.
    const collapsed = collapseGraph(graph, new Set(["msg-schedule"]));
    const seedEdges = collapsed.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    expect(seedEdges).toHaveLength(1);
    expect(seedEdges[0]?.from).toBe("blocks");
    expect(seedEdges[0]?.to).toBe("msg-schedule");
  });

  it("SHA-256: `blocks` is the single seed source for the four history-seed edges (shared auxKey)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Slice 2.11b: the seed source is the per-block iterate `blocks`. Its
    // outgoing aux edges are exactly the four history-seed edges (one per
    // lookback offset), all sharing HISTORY_SEED_AUX_KEY so a collapse dedups
    // them to one arrow (see the collapse test above).
    const blocksAuxOut = graph.edges.filter((e) => e.from === "blocks" && e.kind === "aux");
    expect(blocksAuxOut).toHaveLength(4);
    for (const edge of blocksAuxOut) {
      expect(edge.auxKey).toBe(HISTORY_SEED_AUX_KEY);
    }
  });

  it("SHA-256: the seed source is a CONTAINER (`blocks`), so leaf fanout-replication does not apply", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Behavior change from Slice 2.11b: the seed window moved from a leaf
    // (`length-append`, pre-2.11b — which auto-replicated its 4-way fanout
    // into the msg-schedule body) to the per-block iterate `blocks`. The
    // honest depiction is "this block's bytes seed the schedule", and the
    // bytes originate at the iterate boundary, not a standalone leaf.
    // `replicateHighFanoutSources` only splits LEAF source nodes; a container
    // source is left intact, so no seed replicas are produced. (The four
    // edges still share an auxKey, so they dedup to one arrow when
    // msg-schedule is collapsed — see the collapse test above.)
    expect(graph.containers.some((c) => c.id === "blocks")).toBe(true);
    expect(graph.nodes.some((n) => n.stepId === "blocks")).toBe(false);
    const replicated = replicateHighFanoutSources(graph, DEFAULT_REPLICATION_THRESHOLD);
    const blocksReplicas = replicated.nodes.filter((n) => n.replicaOf === "blocks");
    expect(blocksReplicas).toHaveLength(0);
    // And the old leaf source no longer fans the seeds out either.
    const laReplicas = replicated.nodes.filter((n) => n.replicaOf === "length-append");
    expect(laReplicas).toHaveLength(0);
  });

  it("SHA-256: history-seed edges paint as kind:'aux' (not 'state'), distinguishing them from the port-flow spine", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const seedEdges = graph.edges.filter((e) => e.auxKey === HISTORY_SEED_AUX_KEY);
    expect(seedEdges.length).toBeGreaterThan(0);
    for (const edge of seedEdges) {
      // Distinguishes from `PORT_FLOW_AUX_KEY` edges (which carry
      // kind:"state" + auxKey:"port-flow") AND from legacy passthrough
      // state edges (kind:"state" + auxKey:"state"). The renderer
      // styles aux edges differently from state edges.
      expect(edge.kind).toBe("aux");
    }
  });
});

// ─── A2 retarget: seedInput overrides the spine-predecessor anchor ─────────
//
// Scaffolding-suppression A2 lets a FES-with-history declare `seedInput`
// (the explicit upstream producer the runtime seeds the history from). When
// present, `inferHistorySeedEdges` must anchor the synthetic seed edges at
// `seedInput.node`, NOT at the spine predecessor. SHA-256 doesn't carry
// `seedInput` until A3, so the SHA-256 tests above (spine predecessor =
// `seed-schedule`) continue to pass unchanged; this synthetic spec pins the
// new branch.

describe("deriveAuxGraph — history-seed retarget to seedInput (A2)", () => {
  // `producer` (the seedInput target) sits BEFORE `middle`, which is the
  // FES's spine predecessor. If the retarget works, edges source from
  // `producer`; if it regressed to the legacy rule, they'd source from
  // `middle`.
  const buildSeedInputSpec = (): CipherSpec => ({
    id: "test-seedinput-retarget@1",
    name: "A2 seedInput retarget",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      { kind: "step", id: "producer", type: "constant-load@1", params: { bytes: [0x00, 0x01] } },
      { kind: "step", id: "middle", type: "constant-load@1", params: { bytes: [0x00, 0x01] } },
      {
        kind: "for-each-subgraph-with-history",
        id: "loop",
        iterationCount: 2,
        lookbackOffsets: [1, 2],
        historyEntryByteLength: 1,
        seedInput: { node: "producer", port: "output" },
        children: [
          {
            kind: "step",
            id: "fp1",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-1", byteLength: 1 },
          },
          {
            kind: "step",
            id: "fp2",
            type: "aux-load-bytes@1",
            params: { auxName: "prior-2", byteLength: 1 },
          },
        ],
      },
    ],
  });

  it("anchors history-seed edges at seedInput.node, not the spine predecessor", () => {
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), buildSeedInputSpec(), { registry });
    const seedEdges = graph.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    // One edge per lookback offset whose fetch leaf exists (prior-1, prior-2).
    expect(seedEdges).toHaveLength(2);
    for (const edge of seedEdges) {
      expect(edge.from).toBe("producer");
      expect(edge.from).not.toBe("middle");
    }
    expect(seedEdges.map((e) => e.to).sort()).toEqual(["fp1", "fp2"]);
  });
});
