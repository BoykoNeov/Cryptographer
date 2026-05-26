/**
 * Tests for `replicateHighFanoutSources` (commit 4 of the graph-readability
 * sequence). Drives the pure transform directly against the AES-128 graph.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import type { CipherGraph } from "@/core/graph";
import {
  CIPHER_INPUT_ID,
  deriveAuxGraph,
  dropAuxOnlyStateEdges,
  replicateHighFanoutSources,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const KEY = "000102030405060708090a0b0c0d0e0f";
const PT = "00112233445566778899aabbccddeeff";

const aes128Graph = () => {
  const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(PT)),
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
    // AES-128 key-expansion has 11 outgoing aux edges. A threshold of 50
    // is above every source's fanout, so the transform is identity.
    expect(replicateHighFanoutSources(g, 50)).toBe(g);
  });

  it("replicates key-expansion (11 unique consumers) when threshold = 6", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);

    // 11 unique (source, consumer) pairs — the state edge from
    // key-expansion to initial.add-round-key shares its replica with
    // the corresponding aux edge (roundKey.0 to the same consumer).
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(11);
    // Each replica inherits the source's stepType + label.
    for (const rep of replicas) {
      expect(rep.stepType).toBe("aes.key-expansion@1");
      expect(rep.label).toBe("key-expansion");
    }
    // Slice 7b — every outgoing edge (aux AND state) is rerouted; the
    // original `key-expansion` is fully replicated and removed from the
    // graph. Linear-list sidebar click-to-scrub continues working via
    // the trace (not via this graph), and replica chips carry
    // `replicaOf` so click-to-scrub on a replica still reaches the
    // source frame.
    const remainingFromSource = r.edges.filter((e) => e.from === "key-expansion");
    expect(remainingFromSource.length).toBe(0);
    expect(r.nodes.find((n) => n.stepId === "key-expansion")).toBeUndefined();
    expect(r.rootIds).not.toContain("key-expansion");
  });

  it('mode "always" replicates a low-fanout source that auto would skip', () => {
    const g = aes128Graph();
    // round.0.add-round-key is an aux CONSUMER of key-expansion, not a
    // source. Pick an actual low-fanout source — the iterate doesn't
    // exist in single-block AES, and most leaves don't emit aux. Use
    // `key-expansion` with a HIGH threshold so auto would skip, then
    // force replication via "always".
    const r = replicateHighFanoutSources(g, 50, { "key-expansion": "always" });
    // High threshold alone would have left the graph alone; "always"
    // forces replication anyway.
    expect(r).not.toBe(g);
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(11);
  });

  it('mode "never" suppresses replication of a high-fanout source that auto would replicate', () => {
    const g = aes128Graph();
    // Threshold 6 would auto-replicate key-expansion (fanout 11), but the
    // "never" override pins it back.
    const r = replicateHighFanoutSources(g, 6, { "key-expansion": "never" });
    expect(r).toBe(g);
    const replicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
    expect(replicas.length).toBe(0);
  });

  it("threshold <= 0 with no 'always' overrides short-circuits (modes empty)", () => {
    const g = aes128Graph();
    expect(replicateHighFanoutSources(g, 0, {})).toBe(g);
    expect(replicateHighFanoutSources(g, -1, undefined)).toBe(g);
  });

  it("threshold <= 0 with an 'always' override still replicates that source", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 0, { "key-expansion": "always" });
    expect(r).not.toBe(g);
    expect(r.nodes.filter((n) => n.replicaOf === "key-expansion").length).toBe(11);
  });

  it("each replica sits in its consumer's parent container, before the consumer", () => {
    const g = aes128Graph();
    const r = replicateHighFanoutSources(g, 6);
    // Pick one replica's consumer (the `:b{i}` suffix is stripped during
    // graph derivation, so consumer ids look like `round.5.add-round-key`).
    const sample = r.nodes.find((n) => n.replicaOf === "key-expansion");
    if (!sample) throw new Error("no replica produced");
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

  // Container sources (iterate, group) are themselves visible decongestion
  // devices — replicating them produces a chip near the consumer that
  // duplicates the existing state-spine arrow AND overflows the chip
  // (container labels are typically long). The transform silently skips
  // them: the user's "always" panel toggle is preserved but no-ops for
  // container ids. Specific user-reported case (2026-05-16): post-Option-C
  // a collapsed iterate stayed as a source with one outgoing aux edge to
  // `concat-blocks`, and toggling it "always" produced a duplicate
  // arrow + label-overflowing chip.
  it("skips container sources even when set to 'always' in modes", () => {
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

  // ─── Slice 7b: state-edge replication + source removal ─────────────────

  describe("Slice 7b — state edges fan through replicas", () => {
    it("replicates the source's state-out alongside its aux edges", () => {
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);

      // The state edge `key-expansion → initial.add-round-key` (single-block
      // AES, no iterate suppression of the spine) must now flow from a
      // replica too. Same consumer's aux replica is reused.
      const stateFromRep = r.edges.find(
        (e) => e.kind === "state" && e.to === "initial.add-round-key",
      );
      expect(stateFromRep).toBeDefined();
      expect(stateFromRep?.from).toBe("key-expansion@->initial.add-round-key");
    });

    it("spine successor falls back to first aux consumer when state-out is suppressed", () => {
      // Synthetic fixture mirroring the post-suppression `compute-block-count`
      // shape: a source with NO outgoing state edges (the spine `→ iterate`
      // edge was suppressed by `inferStateEdges`) but exactly one outgoing
      // aux edge to the iterate.
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
          // The state edge `compute-block-count → ecb-blocks` is ABSENT —
          // suppressed by inferStateEdges' iterate-boundary rule.
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

    it("removes the source from rootIds AND parent container childIds", () => {
      // The AES-128 fixture has key-expansion at root + add-round-key
      // consumers inside `round.X` groups. After replication the original
      // key-expansion is gone from rootIds, and the round groups carry
      // replicas spliced before their add-round-key children.
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);

      expect(r.rootIds).not.toContain("key-expansion");
      // initial.add-round-key sits at root: its replica should precede it.
      const initialRepId = "key-expansion@->initial.add-round-key";
      const initialRepIdx = r.rootIds.indexOf(initialRepId);
      const initialConsIdx = r.rootIds.indexOf("initial.add-round-key");
      expect(initialRepIdx).toBeGreaterThanOrEqual(0);
      expect(initialConsIdx).toBeGreaterThanOrEqual(0);
      expect(initialRepIdx).toBeLessThan(initialConsIdx);

      // Spot-check a round group: round.5 hosts `round.5.add-round-key`
      // plus its key-expansion replica, both inside the group's childIds.
      const round5 = r.containers.find((c) => c.id === "round.5");
      expect(round5).toBeDefined();
      const round5Replica = "key-expansion@->round.5.add-round-key";
      expect(round5?.childIds).toContain(round5Replica);
      expect(round5?.childIds).toContain("round.5.add-round-key");
      // No fully-replicated source id (key-expansion) slipped through.
      expect(round5?.childIds.includes("key-expansion")).toBe(false);
    });

    it("spine reaches the last root step through the replica chain", () => {
      // After 7b removes the original key-expansion, walking state edges
      // from rootIds[0] (the input-side first leaf) must still reach the
      // last add-round-key via the replica. The spine isn't "broken" — it
      // detours through the spine-entry replica.
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);

      // Build a state-edge adjacency list and BFS from the first non-
      // replica root.
      const stateOut = new Map<string, Set<string>>();
      for (const e of r.edges) {
        if (e.kind !== "state") continue;
        let set = stateOut.get(e.from);
        if (!set) {
          set = new Set();
          stateOut.set(e.from, set);
        }
        set.add(e.to);
      }

      const start = r.rootIds[0];
      expect(start).toBeDefined();
      const reached = new Set<string>([start as string]);
      const queue = [start as string];
      while (queue.length > 0) {
        const cur = queue.shift();
        if (cur === undefined) break;
        const outs = stateOut.get(cur);
        if (!outs) continue;
        for (const next of outs) {
          if (reached.has(next)) continue;
          reached.add(next);
          queue.push(next);
        }
      }

      // The last AES round's add-round-key is the cipher's final state-
      // shaped output — must be reachable.
      expect(reached.has("round.10.add-round-key")).toBe(true);
    });

    it("source below threshold with no override — graph passes through unchanged", () => {
      // Slice 7b dropped the kind filter; verify the no-replicate baseline
      // (no source qualifies) still produces identity output.
      const g = aes128Graph();
      // Threshold 50 above key-expansion's fanout of 11, no overrides.
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
      // AES-128 single-block: key-expansion is fully replicated (11
      // consumers above threshold). Exactly ONE of its replicas is the
      // spine-replica (= the one targeting the spineSuccessor —
      // `initial.add-round-key`, the first state-target). The other 10
      // are aux-fan-out replicas without the flag.
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);
      const keReplicas = r.nodes.filter((n) => n.replicaOf === "key-expansion");
      expect(keReplicas).toHaveLength(11);
      const spineReplicas = keReplicas.filter((n) => n.isSpineReplica === true);
      expect(spineReplicas).toHaveLength(1);
      expect(spineReplicas[0]?.stepId).toBe("key-expansion@->initial.add-round-key");
    });

    it("spine-replica's containerPath matches the SOURCE's parent scope (not consumer's)", () => {
      // For AES-128 single-block, both source (key-expansion) and
      // spineSuccessor (initial.add-round-key) live at root, so their
      // containerPaths coincide → the spine-replica's containerPath is
      // also `[]`. The interesting structural case is the scope-aware
      // synthetic below where source and consumer differ.
      const g = aes128Graph();
      const r = replicateHighFanoutSources(g, 6);
      const spine = r.nodes.find((n) => n.stepId === "key-expansion@->initial.add-round-key");
      const source = g.nodes.find((n) => n.stepId === "key-expansion");
      if (!spine || !source) throw new Error("missing node");
      expect(spine.containerPath).toEqual(source.containerPath);
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

  // ─── Pipeline composition: aux-only filter BEFORE replication ──────────
  // Regression vector reported 2026-05-17: when `key-expansion` is
  // replicated (either via the global threshold or the per-source
  // "always" override), the spine state edge `key-expansion →
  // initial.add-round-key` was rerouted through the spine replica
  // (Slice 7b semantics) and rendered as a white arrow from the tiny
  // replica chip into `initial.add-round-key`. Pedagogically wrong:
  // key-expansion doesn't transform state, so the state value flowing
  // there is the (identity) plaintext, which the synthetic plaintext-pill
  // arrow already shows.
  //
  // Fix: run `dropAuxOnlyStateEdges` BEFORE `replicateHighFanoutSources`,
  // matching the GraphView pipeline order. This test pins the composition
  // so a future shuffle of pipeline stages doesn't silently regress
  // the spine into `initial.add-round-key`.
  describe("dropAuxOnlyStateEdges composes correctly with replication", () => {
    it("leaves exactly one state edge into initial.add-round-key — the plaintext pill's", () => {
      // Build the graph the way GraphView does: with endpoint pills.
      const trace = runSpec(aes128Spec, buildDefaultRegistry(), {
        initialState: matrixFromBytes(bytesFromHex(PT)),
        initialAux: new Map<string, AuxValue>([["key", bytesFromHex(KEY)]]),
      });
      const raw = deriveAuxGraph(trace, aes128Spec, {
        endpoints: {
          inputLabel: "plaintext",
          outputLabel: "ciphertext",
          inputAnchorId: "initial.add-round-key",
          outputAnchorId: "final.add-round-key",
        },
      });

      // GraphView's pipeline: filter aux-only state edges, THEN replicate.
      // `key-expansion` is the only aux-only root in single-block AES.
      const filtered = dropAuxOnlyStateEdges(raw, new Set(["key-expansion"]));
      const replicated = replicateHighFanoutSources(filtered, 0, {
        "key-expansion": "always",
      });

      // After the pipeline: only the synthetic plaintext pill should
      // contribute a state edge into `initial.add-round-key`. The
      // replica chip emits an AUX edge for roundKeys[0] (kept — that's
      // the round-key fan-out story we want visible), but NO state
      // edge from any replica.
      const stateIntoFirst = replicated.edges.filter(
        (e) => e.kind === "state" && e.to === "initial.add-round-key",
      );
      expect(stateIntoFirst).toHaveLength(1);
      expect(stateIntoFirst[0]?.from).toBe(CIPHER_INPUT_ID);

      // Sanity: 11 aux replicas still produced (the round-key fan-out
      // is unaffected by the spine filter).
      const replicas = replicated.nodes.filter((n) => n.replicaOf === "key-expansion");
      expect(replicas).toHaveLength(11);

      // Sanity: the spine-entry replica still exists and still has an
      // outgoing aux edge to `initial.add-round-key` (roundKeys[0]).
      const spineReplicaId = "key-expansion@->initial.add-round-key";
      expect(replicated.nodes.find((n) => n.stepId === spineReplicaId)).toBeDefined();
      const auxOutFromSpineReplica = replicated.edges.filter(
        (e) => e.kind === "aux" && e.from === spineReplicaId,
      );
      expect(auxOutFromSpineReplica.length).toBeGreaterThan(0);

      // And the killer: NO state edge from ANY replica into add-round-key.
      const stateFromAnyReplica = replicated.edges.filter(
        (e) => e.kind === "state" && e.from.includes("@->"),
      );
      expect(stateFromAnyReplica).toHaveLength(0);
    });

    it("identity short-circuit: empty aux-only set returns the input graph by reference", () => {
      const g = aes128Graph();
      expect(dropAuxOnlyStateEdges(g, new Set())).toBe(g);
    });

    it("identity short-circuit: no matching edges returns the input graph by reference", () => {
      const g = aes128Graph();
      // A bogus id that doesn't appear anywhere → nothing filtered.
      expect(dropAuxOnlyStateEdges(g, new Set(["this-id-does-not-exist"]))).toBe(g);
    });

    it("to-side: when terminal-aux is in BOTH source AND sink sets (non-reader), its incoming spine edge is dropped", () => {
      // Synthetic shape: A → B → terminal-aux. The "terminal-aux" leaf
      // is aux-only AND does not read the state thread (caller passes
      // it in both sets — the default sink-set fallback to the source
      // set models this case). Spine edge `B → terminal-aux` should be
      // suppressed.
      //
      // Slice S2(h), 2026-05-26: this used to be unconditional ("aux-
      // only at the END always drops incoming"), but SHA-256 surfaced
      // `W-publish` — an aux-only root that DOES read state via the
      // thread (meta.stateInputPort defined). Callers now pass a
      // narrower sink set when they want to preserve such edges; the
      // default-fallback path (this test) keeps the original
      // unconditional behavior for callers that don't differentiate.
      const g: CipherGraph = {
        nodes: [
          { stepId: "A", stepType: "ts", label: "A", containerPath: [] },
          { stepId: "B", stepType: "ts", label: "B", containerPath: [] },
          {
            stepId: "terminal-aux",
            stepType: "tx",
            label: "terminal-aux",
            containerPath: [],
          },
        ],
        containers: [],
        edges: [
          { from: "A", to: "B", auxKey: "state", kind: "state" },
          { from: "B", to: "terminal-aux", auxKey: "state", kind: "state" },
        ],
        rootIds: ["A", "B", "terminal-aux"],
      };
      const filtered = dropAuxOnlyStateEdges(g, new Set(["terminal-aux"]));
      // The B → terminal-aux edge is gone; A → B survives.
      expect(filtered.edges).toEqual([{ from: "A", to: "B", auxKey: "state", kind: "state" }]);
    });

    // ─── S2(h) — asymmetric endpoint sets ─────────────────────────────
    // Synthetic vector for the new asymmetric API: an aux-only root
    // that READS state via meta.stateInputPort (modelled here by
    // EXCLUDING it from the narrower sink-set) must keep its incoming
    // legacy spine edge. Mirrors SHA-256's `msg-schedule → W-publish`
    // arrow in graph.ts terms without dragging the full hash spec
    // into a synthetic test.
    it("to-side: an aux-only root EXCLUDED from the sink set keeps its incoming spine edge (W-publish analog)", () => {
      const g: CipherGraph = {
        nodes: [
          {
            stepId: "msg-schedule",
            stepType: "container-ish",
            label: "schedule",
            containerPath: [],
          },
          {
            stepId: "W-publish",
            stepType: "state-to-aux-bytes",
            label: "W-publish",
            containerPath: [],
          },
          { stepId: "next", stepType: "downstream", label: "next", containerPath: [] },
        ],
        containers: [],
        edges: [
          { from: "msg-schedule", to: "W-publish", auxKey: "state", kind: "state" },
          { from: "W-publish", to: "next", auxKey: "state", kind: "state" },
        ],
        rootIds: ["msg-schedule", "W-publish", "next"],
      };
      // W-publish is in the WIDE auxOnlyIds (gets lifted to preamble
      // row by layoutRoot) but is EXCLUDED from the narrower sink set
      // (has meta.stateInputPort at the registry — modelled here by
      // omission from the second arg). Result:
      //  - msg-schedule → W-publish: kept (W-publish not in sink set)
      //  - W-publish → next: dropped (W-publish IS in source set, so
      //    outgoing identity-passthrough edges still suppressed)
      const filtered = dropAuxOnlyStateEdges(
        g,
        new Set(["W-publish"]),
        new Set(), // narrower sink set excludes W-publish
      );
      expect(filtered.edges).toEqual([
        { from: "msg-schedule", to: "W-publish", auxKey: "state", kind: "state" },
      ]);
    });

    it("from-side rule unchanged: aux-only root at the START still drops outgoing spine edge (key-expansion analog)", () => {
      // Even with the narrower sink set, an aux-only root in the
      // SOURCE set drops its outgoing legacy spine edge. Pins the
      // AES key-expansion → first-state-consumer suppression that
      // S2(h) explicitly preserves.
      const g: CipherGraph = {
        nodes: [
          { stepId: "key-expansion", stepType: "aux-only", label: "kx", containerPath: [] },
          { stepId: "first-step", stepType: "downstream", label: "first", containerPath: [] },
          { stepId: "second-step", stepType: "downstream", label: "second", containerPath: [] },
        ],
        containers: [],
        edges: [
          { from: "key-expansion", to: "first-step", auxKey: "state", kind: "state" },
          { from: "first-step", to: "second-step", auxKey: "state", kind: "state" },
        ],
        rootIds: ["key-expansion", "first-step", "second-step"],
      };
      // key-expansion is in BOTH sets (no meta.stateInputPort, so it
      // belongs to the narrower sink set too — but the from-side rule
      // is what fires here).
      const filtered = dropAuxOnlyStateEdges(
        g,
        new Set(["key-expansion"]),
        new Set(["key-expansion"]),
      );
      expect(filtered.edges).toEqual([
        { from: "first-step", to: "second-step", auxKey: "state", kind: "state" },
      ]);
    });
  });
});
