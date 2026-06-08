/**
 * `replicateHighFanoutSources` — REFERENCE replication of a collapsed
 * pure-aux iterate (2026-06-08).
 *
 * SHA-256's `msg-schedule` is a `for-each-subgraph-with-history` that
 * publishes `aux["W"]` (256 bytes) to all 64 compression rounds. Before this
 * change every iterate-family container was excluded from replication, so the
 * 64 `W` edges stayed as a long fan-out bundle crossing the whole round column
 * (rendered yellow by source-coloring). The fix gives a collapsed pure-aux
 * iterate (aux fanout, NO outgoing state edge) a NEW replication mode:
 *
 *   - FULL replication (leaves, collapsed groups): source DELETED, references
 *     scattered, incoming edges redirected to a spine replica.
 *   - REFERENCE replication (this case): source KEPT on the canvas, only its
 *     outgoing aux edges reroute to short per-consumer chips. The loop box
 *     survives — deleting it would erase the schedule from the main flow,
 *     which is the whole reason iterates were excluded in the first place.
 *
 * The guard catches ONLY `msg-schedule`: ECB/CBC `*-blocks` iterates have zero
 * outgoing edges (never enter the fanout map) and SHA-256's outer `blocks`
 * iterate has an outgoing port-flow edge (stays spine-ineligible). Verified by
 * a throwaway probe over all four shipped iterate-family containers.
 *
 * This test composes the real GraphView pipeline's pure transforms
 * (deriveAuxGraph → collapseGraph(defaultCollapsed) → replicate). The inner
 * `blocks` iterate is default-EXPANDED, so `expandCollapsedIterates` (which
 * GraphView runs between collapse and replicate) is a no-op for SHA-256
 * single-block and is safely omitted here.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { collapseGraph, deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import type { CipherGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { getDefaultCollapsedContainers } from "@/core/spec-defaults";
import { DEFAULT_REPLICATION_THRESHOLD } from "@/ui/stores/view-replication";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/** deriveAuxGraph → collapseGraph(defaultCollapsed) for a fresh SHA-256 run. */
const collapsedSha256Graph = (): CipherGraph => {
  const spec = buildSha256Spec();
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: new Uint8Array([0x61, 0x62, 0x63]) }, // "abc"
  });
  const raw = deriveAuxGraph(trace, spec, { registry });
  return collapseGraph(raw, getDefaultCollapsedContainers(spec));
};

const ROUND_COUNT = 64;

describe("replicateHighFanoutSources — reference replication of msg-schedule", () => {
  it("with replication OFF, msg-schedule keeps its 64 direct W edges and spawns no chips", () => {
    const collapsed = collapsedSha256Graph();
    // threshold 0 = global replication off → transform is a no-op.
    const out = replicateHighFanoutSources(collapsed, 0);
    const directW = out.edges.filter((e) => e.from === "msg-schedule" && e.auxKey === "W");
    expect(directW).toHaveLength(ROUND_COUNT);
    const chips = out.nodes.filter((n) => n.replicaOf === "msg-schedule");
    expect(chips).toHaveLength(0);
  });

  it("KEEPS the msg-schedule box (it is NOT deleted, unlike a fully-replicated source)", () => {
    const out = replicateHighFanoutSources(collapsedSha256Graph(), DEFAULT_REPLICATION_THRESHOLD);
    // The container record survives — reference replication does not strip it.
    expect(out.containers.some((c) => c.id === "msg-schedule")).toBe(true);
  });

  it("reroutes all 64 W edges off the box onto per-round reference chips", () => {
    const out = replicateHighFanoutSources(collapsedSha256Graph(), DEFAULT_REPLICATION_THRESHOLD);
    // No direct W edge leaves the box any more — the long fan-out is gone.
    const directW = out.edges.filter((e) => e.from === "msg-schedule" && e.auxKey === "W");
    expect(directW).toHaveLength(0);
    // Instead 64 reference chips each carry one short W edge to their round.
    const chips = out.nodes.filter((n) => n.replicaOf === "msg-schedule");
    expect(chips).toHaveLength(ROUND_COUNT);
    const chipEdges = out.edges.filter(
      (e) => e.auxKey === "W" && e.from.startsWith("msg-schedule@->"),
    );
    expect(chipEdges).toHaveLength(ROUND_COUNT);
    // Each chip edge targets the round it sits beside.
    for (const e of chipEdges) {
      expect(e.to).toMatch(/^round\.\d+$/);
    }
  });

  it("labels every reference chip with the short aux key 'W' (one buffer, sliced per round)", () => {
    const out = replicateHighFanoutSources(collapsedSha256Graph(), DEFAULT_REPLICATION_THRESHOLD);
    const chips = out.nodes.filter((n) => n.replicaOf === "msg-schedule");
    expect(chips).toHaveLength(ROUND_COUNT);
    for (const chip of chips) {
      // NOT the verbose "Message schedule W_0..W_63" — that would imply 64
      // distinct values; each round actually slices the same W buffer.
      expect(chip.label).toBe("W");
    }
  });

  it("preserves the box's INCOMING edges (the schedule still has provenance)", () => {
    const out = replicateHighFanoutSources(collapsedSha256Graph(), DEFAULT_REPLICATION_THRESHOLD);
    // The per-block `blocks` iterate seeds the schedule (history-seed +
    // seedInput edges fold into `blocks → msg-schedule` on collapse). Those
    // incoming arrows must survive — only the OUTGOING W fan-out was rerouted.
    const incoming = out.edges.filter((e) => e.to === "msg-schedule");
    expect(incoming.length).toBeGreaterThan(0);
    expect(incoming.some((e) => e.from === "blocks")).toBe(true);
  });

  it("does NOT promote any reference chip to a spine replica (box owns the spine slot)", () => {
    const out = replicateHighFanoutSources(collapsedSha256Graph(), DEFAULT_REPLICATION_THRESHOLD);
    // samePath is genuinely true (msg-schedule and round.N share `blocks`
    // scope post-collapse), so the isSpine gate on referenceReplicated is
    // load-bearing: without it round.0's chip would be mis-flagged.
    const chips = out.nodes.filter((n) => n.replicaOf === "msg-schedule");
    expect(chips.some((c) => c.isSpineReplica === true)).toBe(false);
  });
});
