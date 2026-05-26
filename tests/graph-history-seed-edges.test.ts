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
 * has a real provenance: the container's spine predecessor (in
 * SHA-256: `seed-schedule`, the `bytes-to-state@1` that produces the
 * 64-byte padded block split into 16 four-byte seeds).
 *
 * **What this file pins:**
 *   1. SHA-256: four history-seed edges exist, one per
 *      `lookbackOffsets` entry, sourced from the spine predecessor
 *      (`seed-schedule`) and targeting the four fetch-pN body leaves.
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
 *      threshold of 3, seed-schedule's fanout=4 auto-replicates
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
import type { Trace } from "@/core/types";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

const emptyTrace = (): Trace => ({
  frames: [],
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

  it("SHA-256: every history-seed edge originates from `seed-schedule` (the FES-with-history spine predecessor)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    const seedEdges = graph.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    // Anchor rule: spine predecessor of the FES-with-history container
    // in spec order. In SHA-256, the immediate sibling before
    // `msg-schedule` is `seed-schedule` (the bytes-to-state@1 that
    // produces the 64-byte padded block split into 16 four-byte seeds).
    for (const edge of seedEdges) {
      expect(edge.from).toBe("seed-schedule");
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
    // history-seed edges share `from: seed-schedule`, `to: msg-schedule`
    // (after rewrite), `kind: "aux"`, `auxKey: "history-seed"` — so
    // dedup collapses them to one.
    const collapsed = collapseGraph(graph, new Set(["msg-schedule"]));
    const seedEdges = collapsed.edges.filter(
      (e) => e.kind === "aux" && e.auxKey === HISTORY_SEED_AUX_KEY,
    );
    expect(seedEdges).toHaveLength(1);
    expect(seedEdges[0]?.from).toBe("seed-schedule");
    expect(seedEdges[0]?.to).toBe("msg-schedule");
  });

  it("SHA-256: shared auxKey makes the edges fanout-eligible for replication (seed-schedule fanout = 4)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // Mirror `replicateHighFanoutSources`'s fanout-eligibility predicate
    // (graph.ts:2118: kind:"aux" OR kind:"state" + auxKey:PORT_FLOW_AUX_KEY).
    // `seed-schedule`'s outgoing edges should include the four aux edges;
    // the state edge to msg-schedule is auxKey:"state" (legacy passthrough)
    // and does NOT count.
    const seedScheduleOutgoing = graph.edges.filter((e) => e.from === "seed-schedule");
    const auxOnly = seedScheduleOutgoing.filter((e) => e.kind === "aux");
    expect(auxOnly).toHaveLength(4);
    for (const edge of auxOnly) {
      expect(edge.auxKey).toBe(HISTORY_SEED_AUX_KEY);
    }
  });

  it("SHA-256: at the default threshold, seed-schedule auto-replicates inside the expanded msg-schedule body (replicas land in consumer scope)", () => {
    const spec = buildSha256Spec();
    const registry = buildDefaultRegistry();
    const graph = deriveAuxGraph(emptyTrace(), spec, { registry });
    // No msg-schedule collapse: the four fetch-pN consumers remain
    // distinct, so each gets its own replica chip. Threshold 3 (strict
    // `>`) means "fanout ≥ 4 auto-replicates" — exactly what
    // seed-schedule's four history-seed edges trip. Without the user
    // touching the panel, the four arrows should fan out into the
    // msg-schedule body (one replica per consumer, sitting inside the
    // body alongside its fetch leaf).
    const replicated = replicateHighFanoutSources(graph, DEFAULT_REPLICATION_THRESHOLD);
    const seedReplicas = replicated.nodes.filter((n) => n.replicaOf === "seed-schedule");
    // Five total: 4 aux (history-seed) replicas inside msg-schedule + 1
    // spine replica at root scope for the state edge to msg-schedule
    // itself (different consumer, no shared replica per Slice 7b).
    expect(seedReplicas).toHaveLength(5);
    // The four IN-CONTAINER replicas (the user's add-on: "items inside
    // a container should also be available to be represented as
    // replications") land inside `msg-schedule`, alongside their
    // consumer fetch leaves.
    const insideMsgSchedule = seedReplicas.filter(
      (n) => n.containerPath.length === 1 && n.containerPath[0] === "msg-schedule",
    );
    expect(insideMsgSchedule).toHaveLength(4);
    // The spine replica lives at root scope (consumer = msg-schedule
    // container, sibling of seed-schedule).
    const atRoot = seedReplicas.filter((n) => n.containerPath.length === 0);
    expect(atRoot).toHaveLength(1);
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
