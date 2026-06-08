/**
 * Tests for `replicateHighFanoutSources` (commit 4 of the graph-readability
 * sequence). Drives the pure transform directly against the AES-128 graph.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { CipherGraph } from "@/core/graph";
import { deriveAuxGraph, replicateHighFanoutSources } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f";
const PT = "00112233445566778899aabbccddeeff";

// Byte-native AES-128 (Slice B1; AddRoundKey merged in Finding F3): bytes
// state + ported dispatch. Round keys are read internally by the
// `xor-with-aux@1` AddRoundKey leaves (initial.add-round-key +
// round.N.add-round-key), so key-schedule.publish's 11 aux fan-out consumers are
// those AddRoundKey leaves.
const aes128Graph = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
  });
  return deriveAuxGraph(trace, aes128Spec);
};

describe("replicateHighFanoutSources", () => {
  it("threshold <= 0 returns the input graph by reference (off short-circuit)", () => {
    const g = aes128Graph();
    expect(replicateHighFanoutSources(g, 0)).toBe(g);
    expect(replicateHighFanoutSources(g, -5)).toBe(g);
  });

  it("no source above threshold returns the input by reference", () => {
    const g = aes128Graph();
    // AES-128 key-schedule.publish has 11 outgoing aux edges. A threshold of 50
    // is above every source's fanout, so the transform is identity.
    expect(replicateHighFanoutSources(g, 50)).toBe(g);
  });

  it("replicates key-schedule.publish (11 unique consumers) when threshold = 6", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);

    // 11 unique (source, consumer) pairs — the publish leaf is aux-only
    // (writes roundKey.0..10 via meta), so all 11 outgoing edges are the
    // round-key fan-out (one per AddRoundKey consumer).
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-schedule.publish");
    expect(replicas.length).toBe(11);
    // Each replica inherits the source's stepType + label.
    for (const rep of replicas) {
      expect(rep.stepType).toBe("aes.publish-round-keys@1");
      expect(rep.label).toBe("key-schedule.publish");
    }
    // Slice 7b — every outgoing edge (aux AND state) is rerouted; the
    // original `key-schedule.publish` is fully replicated and removed from the
    // graph. Linear-list sidebar click-to-scrub continues working via
    // the trace (not via this graph), and replica chips carry
    // `replicaOf` so click-to-scrub on a replica still reaches the
    // source frame.
    const remainingFromSource = r.edges.filter((e) => e.from === "key-schedule.publish");
    expect(remainingFromSource.length).toBe(0);
    expect(r.nodes.find((n) => n.stepId === "key-schedule.publish")).toBeUndefined();
    expect(r.rootIds).not.toContain("key-schedule.publish");
  });

  it('mode "always" replicates a low-fanout source that auto would skip', () => {
    const g = aes128Graph();
    // round.0.add-round-key is an aux CONSUMER of key-schedule.publish, not a
    // source. Pick an actual low-fanout source — the iterate doesn't
    // exist in single-block AES, and most leaves don't emit aux. Use
    // `key-schedule.publish` with a HIGH threshold so auto would skip, then
    // force replication via "always".
    const r = replicateHighFanoutSources(g, 50, { "key-schedule.publish": "always" });
    // High threshold alone would have left the graph alone; "always"
    // forces replication anyway.
    expect(r).not.toBe(g);
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-schedule.publish");
    expect(replicas.length).toBe(11);
  });

  it('mode "never" suppresses replication of a high-fanout source that auto would replicate', () => {
    const g = aes128Graph();
    // Threshold 6 would auto-replicate key-schedule.publish (fanout 11), but the
    // "never" override pins IT back. Note the decomposed schedule (K1c) also
    // has `key-schedule.word-stream` as a fanout-11 source (it feeds the 11
    // round-key byte-slices), so the graph is NOT globally identity at
    // threshold 6 — the override is per-source, so we assert publish
    // specifically produced no replicas.
    const r = replicateHighFanoutSources(g, 6, { "key-schedule.publish": "never" });
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-schedule.publish");
    expect(replicas.length).toBe(0);
  });

  it("threshold <= 0 with no 'always' overrides short-circuits (modes empty)", () => {
    const g = aes128Graph();
    expect(replicateHighFanoutSources(g, 0, {})).toBe(g);
    expect(replicateHighFanoutSources(g, -1, undefined)).toBe(g);
  });

  it("threshold <= 0 with an 'always' override still replicates that source", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 0, { "key-schedule.publish": "always" });
    expect(r).not.toBe(g);
    expect(r.nodes.filter((n) => n.replicaOf === "key-schedule.publish").length).toBe(11);
  });

  it("each replica sits in its consumer's parent container, before the consumer", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);
    // Pick an AUX-FAN-OUT replica (NOT the spine-replica). Since the source
    // `key-schedule.publish` lives inside the `key-schedule` group (K1c), the
    // spine-replica is placed in the SOURCE's scope (`["key-schedule"]`), not
    // its consumer's — so only the aux-fan-out replicas satisfy the
    // "sibling of its consumer" property this test pins. (`:b{i}` suffixes are
    // stripped during graph derivation, so consumer ids look like
    // `round.5.add-round-key`.)
    const sample = r.nodes.find((n) => n.replicaOf === "key-schedule.publish" && !n.isSpineReplica);
    if (!sample) throw new Error("no aux-fan-out replica produced");
    // The replica id encodes the consumer: `${source}@->${consumer}`.
    const consumerId = sample.stepId.split("@->")[1];
    expect(consumerId).toBeDefined();
    const consumer = r.nodes.find((n) => n.stepId === consumerId);
    expect(consumer).toBeDefined();
    // Same containerPath as the consumer (siblings).
    expect(sample.containerPath).toEqual(consumer?.containerPath);
    // Inside the consumer's parent container, the replica precedes the
    // consumer in the childIds order. (Use the last entry of the
    // consumer's containerPath as the parent; that's the direct parent
    // by construction.)
    const parentId = consumer?.containerPath[consumer.containerPath.length - 1];
    if (parentId) {
      const parent = r.containers.find((c) => c.id === parentId);
      expect(parent).toBeDefined();
      const ix = (parent?.childIds ?? []).indexOf(sample.stepId);
      const cIx = (parent?.childIds ?? []).indexOf(consumerId ?? "");
      expect(ix).toBeGreaterThanOrEqual(0);
      expect(cIx).toBeGreaterThanOrEqual(0);
      expect(ix).toBeLessThan(cIx);
    } else {
      // Root-level consumer (e.g. `initial.add-round-key`): replica
      // should be present in rootIds, immediately before the consumer.
      const rix = r.rootIds.indexOf(sample.stepId);
      const cix = r.rootIds.indexOf(consumerId ?? "");
      expect(rix).toBeGreaterThanOrEqual(0);
      expect(cix).toBeGreaterThanOrEqual(0);
      expect(rix).toBeLessThan(cix);
    }
  });

  // A FANOUT-1 iterate container stays un-replicated even when set to
  // "always". This pins the user-reported 2026-05-16 case: a collapsed iterate
  // left as a source with ONE outgoing aux edge to `concat-blocks`, toggled
  // "always", produced a duplicate arrow + label-overflowing chip. Reference
  // replication (2026-06-08) added a path for collapsed pure-aux iterates, but
  // it requires ≥2 consumers — a single rerouted edge has nothing to declutter
  // and just adds an indirection chip on the data path. So this fanout-1 case
  // is still protected. (HIGH-fanout pure-aux iterates DO reference-replicate
  // now — SHA-256's `msg-schedule`, fanout 64; see
  // `replicate-pure-aux-iterate.test.ts`. Collapsed GROUP containers are FULLY
  // replicated at any fanout — see the group cases below.)
  it("skips a fanout-1 iterate container source even when set to 'always' in modes", () => {
    const g = {
      nodes: [
        {
          stepId: "concat-blocks",
          stepType: "ct",
          label: "concat-blocks",
          containerPath: [],
        },
      ],
      containers: [
        {
          kind: "iterate" as const,
          id: "ecb-blocks",
          label: "ECB blocks (per-block AES)",
          containerPath: [],
          childIds: [],
          blockSpan: 2,
        },
      ],
      edges: [
        { from: "ecb-blocks", to: "concat-blocks", auxKey: "blocks-out", kind: "aux" as const },
      ],
      rootIds: ["ecb-blocks", "concat-blocks"],
    };
    const r = replicateHighFanoutSources(g, 0, { "ecb-blocks": "always" });
    // No replicas; "ecb-blocks" stays as the edge source.
    expect(r.nodes.find((n) => n.replicaOf === "ecb-blocks")).toBeUndefined();
    const edges = r.edges.filter((e) => e.kind === "aux");
    expect(edges).toHaveLength(1);
    expect(edges[0]?.from).toBe("ecb-blocks");
    expect(edges[0]?.to).toBe("concat-blocks");
  });

  // ─── Collapsed-GROUP container sources ARE eligible (2026-06-02) ──────────
  //
  // A collapsed group renders as a single leaf-like chip (collapseGraph
  // clears its childIds to []), so it can be replicated exactly like a leaf
  // source: one small chip per consumer, the long fan-out lines gone. The
  // motivating case is AES's default-collapsed "Key Expansion" group fanning
  // 11 round keys to every AddRoundKey. Before this change the container was
  // silently skipped and the 11 long lines stayed on the canvas.
  describe("collapsed group container sources", () => {
    // Build a fixture that mirrors the post-collapse shape: a `group`
    // container with childIds === [] is the source of N aux edges to N
    // distinct leaf consumers.
    const collapsedGroupFixture = (childIds: readonly string[]): CipherGraph => {
      const consumers = Array.from({ length: 5 }, (_, i) => `consumer-${i}`);
      return {
        nodes: consumers.map((id) => ({
          stepId: id,
          stepType: "add-round-key@1",
          label: id,
          containerPath: [],
        })),
        containers: [
          {
            kind: "group" as const,
            id: "key-schedule",
            label: "Key Expansion",
            containerPath: [],
            childIds,
          },
        ],
        edges: consumers.map((id, i) => ({
          from: "key-schedule",
          to: id,
          auxKey: `roundKey.${i}`,
          kind: "aux" as const,
        })),
        rootIds: ["key-schedule", ...consumers],
      };
    };

    it("auto-replicates a collapsed group above the threshold (one chip per consumer)", () => {
      const g = collapsedGroupFixture([]); // collapsed → childIds empty
      // Fanout 5 > threshold 3 → auto-replicate, no override needed.
      const r = replicateHighFanoutSources(g, 3);
      const replicas = r.nodes.filter((n) => n.replicaOf === "key-schedule");
      expect(replicas).toHaveLength(5);
      for (const rep of replicas) {
        // Replicas inherit the container's kind (as stepType) + label.
        expect(rep.stepType).toBe("group");
        expect(rep.label).toBe("Key Expansion");
      }
      // The original container is fully replaced: gone from nodes (never was),
      // gone from containers, gone from rootIds, and no edge emits from it.
      expect(r.containers.find((c) => c.id === "key-schedule")).toBeUndefined();
      expect(r.rootIds).not.toContain("key-schedule");
      expect(r.edges.filter((e) => e.from === "key-schedule")).toHaveLength(0);
    });

    it('honors "always" for a collapsed group even below the threshold', () => {
      const g = collapsedGroupFixture([]);
      const r = replicateHighFanoutSources(g, 50, { "key-schedule": "always" });
      expect(r).not.toBe(g);
      expect(r.nodes.filter((n) => n.replicaOf === "key-schedule")).toHaveLength(5);
      expect(r.containers.find((c) => c.id === "key-schedule")).toBeUndefined();
    });

    it("does NOT replicate an EXPANDED group (childIds non-empty)", () => {
      // An expanded group owns a body box; its real fan-out source is the
      // inner leaf, not the container. childIds non-empty → ineligible.
      const g = collapsedGroupFixture(["some-inner-leaf"]);
      const r = replicateHighFanoutSources(g, 3);
      // No replicas, container survives, edges still emit from it.
      expect(r.nodes.filter((n) => n.replicaOf === "key-schedule")).toHaveLength(0);
      expect(r.containers.find((c) => c.id === "key-schedule")).toBeDefined();
      expect(r.edges.filter((e) => e.from === "key-schedule")).toHaveLength(5);
    });
  });

  // ─── Slice 7b: state-edge replication + source removal ─────────────────

  describe("Slice 7b — state edges fan through replicas", () => {
    // ("replicates the source's state-out alongside its aux edges" was removed
    // in Slice 5.3e Batch 3: AES `key-schedule.publish` is aux-only and has no
    // state-out — the legacy identity-passthrough spine edge it once carried
    // retired with `inferStateEdges`. The general "a source's state-out fans
    // through replicas" invariant is still pinned by the synthetic-graph cases
    // below + the SHA-256 split-wv S2(i) port-flow tests.)

    it("spine successor falls back to first aux consumer when state-out is absent", () => {
      // Synthetic fixture mirroring an aux-only source's shape: a source with
      // NO outgoing state edges (e.g. a key-schedule, whose only outputs are
      // aux fan-out) but exactly one outgoing aux edge to the iterate.
      const g = {
        nodes: [
          { stepId: "split-blocks", stepType: "sb", label: "split-blocks", containerPath: [] },
          {
            stepId: "compute-block-count",
            stepType: "cbc",
            label: "compute-block-count",
            containerPath: [],
          },
        ],
        containers: [
          {
            kind: "iterate" as const,
            id: "ecb-blocks",
            label: "ECB blocks",
            containerPath: [],
            childIds: [],
            blockSpan: 2,
          },
        ],
        edges: [
          // Spine: split-blocks → compute-block-count (preserved).
          {
            from: "split-blocks",
            to: "compute-block-count",
            auxKey: "state",
            kind: "state" as const,
          },
          // The state edge `compute-block-count → ecb-blocks` is ABSENT — an
          // aux-only source has no state-out (this synthetic graph models that
          // shape directly; the fallback under test is registry-independent).
          // Aux: compute-block-count writes blockCount, the iterate reads.
          {
            from: "compute-block-count",
            to: "ecb-blocks",
            auxKey: "blockCount",
            kind: "aux" as const,
          },
        ],
        rootIds: ["split-blocks", "compute-block-count", "ecb-blocks"],
      };

      const r = replicateHighFanoutSources(g, 0, { "compute-block-count": "always" });

      // One replica created: compute-block-count@->ecb-blocks. Fallback
      // (option b) picked it as the spine successor when no state-out exists.
      const replicas = r.nodes.filter((n) => n.replicaOf === "compute-block-count");
      expect(replicas).toHaveLength(1);
      expect(replicas[0]?.stepId).toBe("compute-block-count@->ecb-blocks");

      // Original compute-block-count removed from nodes + rootIds.
      expect(r.nodes.find((n) => n.stepId === "compute-block-count")).toBeUndefined();
      expect(r.rootIds).not.toContain("compute-block-count");

      // Incoming spine edge (`split-blocks → compute-block-count`) redirected
      // to the replica — keeps spine continuity across the removed source.
      const incoming = r.edges.find((e) => e.kind === "state" && e.from === "split-blocks");
      expect(incoming?.to).toBe("compute-block-count@->ecb-blocks");
    });

    it("incoming state edge to a fully-replicated source redirects to first-replica", () => {
      // Synthetic fixture: two leaves with a state spine + aux fanout
      // making the second one eligible for replication. The first leaf's
      // state-out should redirect to the second leaf's first replica.
      const g = {
        nodes: [
          { stepId: "A", stepType: "ts", label: "A", containerPath: [] },
          { stepId: "B", stepType: "ts", label: "B", containerPath: [] },
          { stepId: "C1", stepType: "ts", label: "C1", containerPath: [] },
          { stepId: "C2", stepType: "ts", label: "C2", containerPath: [] },
        ],
        containers: [],
        edges: [
          // Spine: A → B → C1 (C1 happens to be B's first state-output).
          { from: "A", to: "B", auxKey: "state", kind: "state" as const },
          { from: "B", to: "C1", auxKey: "state", kind: "state" as const },
          // Aux fanout from B (forces it to qualify; not strictly needed
          // because we set "always", but matches realistic shape).
          { from: "B", to: "C1", auxKey: "k1", kind: "aux" as const },
          { from: "B", to: "C2", auxKey: "k2", kind: "aux" as const },
        ],
        rootIds: ["A", "B", "C1", "C2"],
      };

      const r = replicateHighFanoutSources(g, 0, { B: "always" });

      expect(r.nodes.find((n) => n.stepId === "B")).toBeUndefined();
      expect(r.rootIds).not.toContain("B");

      // A → B redirects to A → B@->C1 (state-out first wins over aux-out).
      const incoming = r.edges.find((e) => e.kind === "state" && e.from === "A");
      expect(incoming?.to).toBe("B@->C1");
    });

    it("removes the source from its parent container childIds AND splices replicas", () => {
      // Since the key-schedule decomposition (K1c), the high-fanout aux source
      // `key-schedule.publish` lives INSIDE the `key-schedule` group (not at
      // root). Its AddRoundKey consumers are at root (initial.add-round-key) and
      // inside round groups — a CROSS-SCOPE source. Per the DES-era `samePath`
      // rule, a cross-scope (source.parent ≠ consumer.parent) replica is NOT a
      // spine-replica: every publish replica is a regular consumer-scope chip.
      // So publish@->initial.add-round-key lands at root (initial's scope) and
      // publish@->round.5.add-round-key inside round.5.
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);

      // publish was never at root; it's removed from the key-schedule group.
      expect(r.rootIds).not.toContain("key-schedule.publish");
      const keySchedule = r.containers.find((c) => c.id === "key-schedule");
      expect(keySchedule).toBeDefined();
      expect(keySchedule?.childIds.includes("key-schedule.publish")).toBe(false);

      // The root consumer's replica lands in ROOT (consumer scope), spliced
      // before initial.add-round-key.
      const initialRepId = "key-schedule.publish@->initial.add-round-key";
      const initialRepIdx = r.rootIds.indexOf(initialRepId);
      const initialConsIdx = r.rootIds.indexOf("initial.add-round-key");
      expect(initialRepIdx).toBeGreaterThanOrEqual(0);
      expect(initialConsIdx).toBeGreaterThanOrEqual(0);
      expect(initialRepIdx).toBeLessThan(initialConsIdx);

      // Spot-check a round group: round.5 hosts `round.5.add-round-key`
      // plus its aux-fan-out replica, both inside the group's childIds.
      const round5 = r.containers.find((c) => c.id === "round.5");
      expect(round5).toBeDefined();
      const round5Replica = "key-schedule.publish@->round.5.add-round-key";
      expect(round5?.childIds).toContain(round5Replica);
      expect(round5?.childIds).toContain("round.5.add-round-key");
      // No fully-replicated source id (key-schedule.publish) slipped through.
      expect(round5?.childIds.includes("key-schedule.publish")).toBe(false);
    });

    // ("spine reaches the last root step through the replica chain" was removed
    // in Slice 5.3e Batch 3. Its premise — replicating key-schedule.publish must not
    // break the spine — is moot: key-schedule.publish is no longer ON the spine (it's
    // aux-only), so replicating it can't break it. And the test's flat-BFS over
    // state edges can't traverse the port-flow spine's container-sourced
    // round→round handoffs (`round.1 → round.2.sub-bytes`, where the `round.1`
    // container is never an edge `to`). End-to-end port-flow spine reachability
    // is pinned by the Serpent/Speck tests in `aux-graph-derivation.test.ts`
    // (complete count + all endpoints materialized + forward-only ⇒ no gap).)

    it("source below threshold with no override — graph passes through unchanged", () => {
      // Slice 7b dropped the kind filter; verify the no-replicate baseline
      // (no source qualifies) still produces identity output.
      const g = aes128Graph();
      // Threshold 50 above key-schedule.publish's fanout of 11, no overrides.
      const r = replicateHighFanoutSources(g, 50);
      expect(r).toBe(g);
    });
  });

  // ─── Replica scope-aware layout (narrow, 2026-05-17) ──────────────────────
  //
  // The structural side of the fix: `replicateHighFanoutSources` flags
  // the spine-replica (the single (source, spineSuccessor) replica per
  // fully-replicated source) with `isSpineReplica: true` AND places it
  // in SOURCE's parent scope rather than CONSUMER's parent scope.
  //
  // Layout-side consequences (spine-replica flows at source's old slot,
  // not lifted) are pinned by `tests/graph-view-replica-gutter.test.ts`.

  describe("replica-scope-aware layout (narrow) — spine-replica flag + scope", () => {
    it("flags exactly one replica per fully-replicated source as isSpineReplica", () => {
      // Byte-native AES-128 with the decomposed key schedule (K1c). The
      // SAME-SCOPE high-fanout source is `key-schedule.word-stream`: it feeds
      // the 11 round-key byte-slices (`key-schedule.rk0..rk10`) via port-flow,
      // and ALL of them live in the SAME `key-schedule` group. So exactly ONE
      // of word-stream's replicas is the spine-replica (targeting the first
      // state successor `key-schedule.rk0`); the other 10 are aux/port-fan-out
      // replicas. (publish, by contrast, is CROSS-SCOPE — its consumers live
      // outside key-schedule — so it gets NO spine-replica; see the "removes
      // source" test above.)
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);
      const wsReplicas = r.nodes.filter((n) => n.replicaOf === "key-schedule.word-stream");
      expect(wsReplicas).toHaveLength(11);
      const spineReplicas = wsReplicas.filter((n) => n.isSpineReplica === true);
      expect(spineReplicas).toHaveLength(1);
      expect(spineReplicas[0]?.stepId).toBe("key-schedule.word-stream@->key-schedule.rk0");
      // publish is cross-scope → no spine-replica.
      const publishReplicas = r.nodes.filter((n) => n.replicaOf === "key-schedule.publish");
      expect(publishReplicas.filter((n) => n.isSpineReplica === true)).toHaveLength(0);
    });

    it("spine-replica's containerPath matches the SOURCE's parent scope", () => {
      // word-stream and its rk0 successor both live in the `key-schedule`
      // group, so the spine-replica's containerPath is `["key-schedule"]` —
      // the source's parent scope. (The source-≠-consumer-scope distinction is
      // pinned by the scope-aware synthetic case below.)
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);
      const spine = r.nodes.find((n) => n.stepId === "key-schedule.word-stream@->key-schedule.rk0");
      const source = g.nodes.find((n) => n.stepId === "key-schedule.word-stream");
      if (!spine || !source) throw new Error("missing node");
      expect(spine.containerPath).toEqual(source.containerPath);
      expect(spine.containerPath).toEqual(["key-schedule"]);
      expect(spine.isSpineReplica).toBe(true);
    });

    it("scope-aware synthetic: source in different parent than consumer — spine-replica lives in SOURCE's parent", () => {
      // Synthetic fixture pinning the structural contract: when the
      // spineSuccessor lives in a DIFFERENT parent than the source, the
      // spine-replica's containerPath matches SOURCE's. Aux-fan-out
      // replicas continue to use the CONSUMER's containerPath.
      //
      // Source `src` is at root. Three outgoing edges:
      //   - state edge to `state-target` (also root) → spineSuccessor.
      //   - aux edge to `inner` (inside `wrap` group, different parent).
      //   - aux edge to `state-target` (just to push fanout ≥ 2 so the
      //     source qualifies under the default threshold rules).
      const g: CipherGraph = {
        nodes: [
          { stepId: "src", stepType: "test.src", label: "src", containerPath: [] },
          {
            stepId: "state-target",
            stepType: "test.consumer",
            label: "state-target",
            containerPath: [],
          },
          {
            stepId: "inner",
            stepType: "test.consumer",
            label: "inner",
            containerPath: ["wrap"],
          },
        ],
        containers: [
          {
            kind: "group",
            id: "wrap",
            label: "wrap",
            containerPath: [],
            childIds: ["inner"],
          },
        ],
        edges: [
          { from: "src", to: "state-target", auxKey: "state", kind: "state" },
          { from: "src", to: "state-target", auxKey: "aux-1", kind: "aux" },
          { from: "src", to: "inner", auxKey: "aux-2", kind: "aux" },
        ],
        rootIds: ["src", "state-target", "wrap"],
      };
      const r = replicateHighFanoutSources(g, 1);

      const spine = r.nodes.find((n) => n.stepId === "src@->state-target");
      const auxFanOut = r.nodes.find((n) => n.stepId === "src@->inner");
      if (!spine || !auxFanOut) {
        throw new Error(`missing replica node: spine=${!!spine} auxFanOut=${!!auxFanOut}`);
      }

      // Spine-replica: containerPath matches SOURCE's (root, []).
      expect(spine.isSpineReplica).toBe(true);
      expect(spine.containerPath).toEqual([]);

      // Aux-fan-out: containerPath matches CONSUMER's (["wrap"]).
      expect(auxFanOut.isSpineReplica).toBeUndefined();
      expect(auxFanOut.containerPath).toEqual(["wrap"]);

      // Insertion: spine-replica lands in rootIds (source's parent),
      // before state-target. Aux-fan-out lands in wrap.childIds, before
      // inner.
      expect(r.rootIds).toContain("src@->state-target");
      expect(r.rootIds).not.toContain("src@->inner");
      const wrap = r.containers.find((c) => c.id === "wrap");
      expect(wrap?.childIds).toContain("src@->inner");
      expect(wrap?.childIds).not.toContain("src@->state-target");
    });
  });

  // ─── Slice S2(i) — port-flow state edges count toward fanout ──────────
  // Before S2(i), `replicateHighFanoutSources` counted only `kind: "aux"`
  // edges, so SHA-256's `final.split-wv` / `final.split-H` (each with 8
  // outgoing port-flow edges to `final.s_0..s_7`) scored fanout = 0 and
  // never qualified for replication — the long lines overlapped through
  // the s-row. The new rule includes port-flow state edges
  // (`kind:"state"` + `auxKey === PORT_FLOW_AUX_KEY`) while leaving legacy
  // passthrough state edges (`auxKey === "state"`) excluded as before.
  describe("Slice S2(i) — port-flow fanout eligibility (SHA-256 split-wv / split-H)", () => {
    it("port-native source with 8 port-flow consumers replicates at threshold 6 (split-wv analog)", () => {
      // Synthetic vector mirroring SHA-256's `final.split-wv` topology:
      // one source emits 8 port-flow STATE edges (auxKey === "port-flow")
      // — one per output port — to 8 distinct downstream consumers. With
      // a default threshold of 6, all 8 consumers should pick up a local
      // replica and the original source should be removed.
      const consumers = Array.from({ length: 8 }, (_, i) => `final.s${i}`);
      const g: CipherGraph = {
        nodes: [
          {
            stepId: "final.split-wv",
            stepType: "split-bytes@1",
            label: "split-wv",
            containerPath: [],
          },
          ...consumers.map((id) => ({
            stepId: id,
            stepType: "add-mod-32@1",
            label: id,
            containerPath: [],
          })),
        ],
        containers: [],
        edges: consumers.map((id) => ({
          from: "final.split-wv",
          to: id,
          // The port-flow sentinel — what `inferPortEdges` stamps on
          // every binding it walks.
          auxKey: "port-flow",
          kind: "state" as const,
        })),
        rootIds: ["final.split-wv", ...consumers],
      };

      const r = replicateHighFanoutSources(g, 6);

      // One replica per consumer (`final.split-wv@->final.s_i`).
      const replicas = r.nodes.filter((n) => n.replicaOf === "final.split-wv");
      expect(replicas).toHaveLength(8);
      for (const rep of replicas) {
        expect(rep.stepType).toBe("split-bytes@1");
        expect(rep.label).toBe("split-wv");
      }
      // Original source is fully replicated → removed from nodes + rootIds.
      expect(r.nodes.find((n) => n.stepId === "final.split-wv")).toBeUndefined();
      expect(r.rootIds).not.toContain("final.split-wv");
      // No edge still emits from the dead source id.
      expect(r.edges.filter((e) => e.from === "final.split-wv")).toHaveLength(0);
    });

    it("legacy passthrough state spine does NOT count toward fanout (negation)", () => {
      // 8 consecutive legacy state spine edges from a single source — but
      // `auxKey === "state"` (the passthrough sentinel), NOT "port-flow".
      // These represent the implicit (state, params) → state thread, are
      // 1-to-1 by construction in the real spec, and must not inflate
      // the fanout count. Even at threshold 1 (the floor — replicate
      // anything above 1), this source MUST NOT replicate.
      const consumers = Array.from({ length: 8 }, (_, i) => `step${i}`);
      const g: CipherGraph = {
        nodes: [
          {
            stepId: "legacy-source",
            stepType: "ts",
            label: "legacy-source",
            containerPath: [],
          },
          ...consumers.map((id) => ({
            stepId: id,
            stepType: "ts",
            label: id,
            containerPath: [],
          })),
        ],
        containers: [],
        edges: consumers.map((id) => ({
          from: "legacy-source",
          to: id,
          // Legacy passthrough sentinel — the one the new rule still
          // excludes from fanout eligibility.
          auxKey: "state",
          kind: "state" as const,
        })),
        rootIds: ["legacy-source", ...consumers],
      };

      // Threshold 1 (the lowest non-trivial setting) — would replicate
      // anything with fanout > 1 if state edges were eligible. The
      // legacy spine must remain unreplicated.
      const r = replicateHighFanoutSources(g, 1);

      // Identity short-circuit by reference: no source qualified.
      expect(r).toBe(g);
      const replicas = r.nodes.filter((n) => n.replicaOf === "legacy-source");
      expect(replicas).toHaveLength(0);
    });
  });
});
