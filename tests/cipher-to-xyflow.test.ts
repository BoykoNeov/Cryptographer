/**
 * Tests for `src/ui/graph/cipher-to-xyflow.ts`.
 *
 * Spike adapter for the experimental fourth view mode. Pinning the
 * adapter behavior (input shape → output shape) lets the wrapper
 * component stay confident that whatever xyflow renders, it's getting
 * well-formed data. NOT a substitute for the visual smoke check —
 * xyflow's own rendering still has to be verified in a browser.
 *
 * Coverage targets:
 *   - 3-level nesting flattens to xyflow nodes with correct parentId
 *     chain (AES-128-ECB: iterate → round-group → leaf)
 *   - Container nodes get `type: "group"` and explicit width/height
 *   - Leaf positions are relative-to-immediate-parent (not absolute)
 *   - Iterate label includes `×N` when blockSpan is known
 *   - Both edge kinds map to xyflow edges with distinct style hints
 *   - Empty container (post-collapse simulation) renders as small chip
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type CipherGraph, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, Trace } from "@/core/types";
import {
  BASE_XYFLOW_CONSTANTS,
  cipherGraphToXyflow,
  scaleXyflowConstants,
} from "@/ui/graph/cipher-to-xyflow";
import { describe, expect, it } from "vitest";

const ZERO_KEY = new Uint8Array(16);

const runAes128 = (): Trace =>
  runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(new Uint8Array(16)),
    initialAux: new Map<string, AuxValue>([["key", ZERO_KEY]]),
  });

const runAes128Ecb = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    // 2 blocks of zeros → ×2 iterations in the trace.
    initialState: makeBytesState(new Uint8Array(32)),
    initialAux: new Map<string, AuxValue>([["key", ZERO_KEY]]),
  });

describe("cipherGraphToXyflow — adapter shape", () => {
  it("emits one xyflow node per leaf + one per container", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const { nodes } = cipherGraphToXyflow(graph);
    expect(nodes.length).toBe(graph.nodes.length + graph.containers.length);
  });

  it("containers get type='group' and explicit width/height; leaves don't", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const { nodes } = cipherGraphToXyflow(graph);
    const containerIds = new Set(graph.containers.map((c) => c.id));
    for (const n of nodes) {
      if (containerIds.has(n.id)) {
        expect(n.type).toBe("group");
        expect(typeof n.width).toBe("number");
        expect(typeof n.height).toBe("number");
        expect((n.width ?? 0) > 0).toBe(true);
        expect((n.height ?? 0) > 0).toBe(true);
      } else {
        // Leaves don't set `type` — xyflow's default node component handles
        // them. They DO carry width/height (set by the adapter, not by
        // xyflow), to keep the layout math self-consistent.
        expect(n.type).toBeUndefined();
        expect(typeof n.width).toBe("number");
        expect(typeof n.height).toBe("number");
      }
    }
  });

  it("3-level nesting: leaf inside round-group inside iterate (AES-128-ECB)", () => {
    const trace = runAes128Ecb();
    const graph = deriveAuxGraph(trace, aes128EcbSpec);
    const { nodes } = cipherGraphToXyflow(graph);
    const byId = new Map(nodes.map((n) => [n.id, n]));

    // Find a leaf inside a round group inside the iterate.
    // AES-128-ECB structure: top-level iterate "ecb-blocks" → group
    // "round.1" → leaf "round.1.sub-bytes". The adapter should chain
    // parentIds correctly so xyflow's relative-position math works.
    const leaf = byId.get("round.1.sub-bytes");
    expect(leaf, "round.1.sub-bytes leaf must exist").toBeDefined();
    const roundGroup = leaf?.parentId ? byId.get(leaf.parentId) : undefined;
    expect(roundGroup, "leaf's parent (round-group) must exist").toBeDefined();
    const iterate = roundGroup?.parentId ? byId.get(roundGroup.parentId) : undefined;
    expect(iterate, "round-group's parent (iterate) must exist").toBeDefined();
    // Iterate is at the top level → its parentId is undefined.
    expect(iterate?.parentId).toBeUndefined();
    // Both intermediate containers are groups.
    expect(roundGroup?.type).toBe("group");
    expect(iterate?.type).toBe("group");
  });

  it("child position is relative-to-immediate-parent, not absolute", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const { nodes } = cipherGraphToXyflow(graph);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    // AES-128's `round.1` group is a container inside the spec root.
    // Its children (sub-bytes, shift-rows, mix-columns, add-round-key)
    // should have small positive `position.x` values — they're laid out
    // with cursor starting at PAD_LEFT inside the round group, NOT at
    // absolute canvas coordinates.
    const subBytes = byId.get("round.1.sub-bytes");
    expect(subBytes).toBeDefined();
    expect(subBytes?.parentId).toBe("round.1");
    // PAD_LEFT (20) is the first child's x; should be much smaller than
    // the absolute canvas position of any later sibling.
    expect(subBytes?.position.x).toBeLessThan(100);
    expect(subBytes?.position.x).toBeGreaterThanOrEqual(0);
  });

  it("iterate label includes ×N when blockSpan > 1", () => {
    const trace = runAes128Ecb();
    const graph = deriveAuxGraph(trace, aes128EcbSpec);
    const { nodes } = cipherGraphToXyflow(graph);
    const iterate = nodes.find((n) => n.id === "ecb-blocks");
    expect(iterate).toBeDefined();
    const label = (iterate?.data as { label?: string } | undefined)?.label;
    // 32 plaintext bytes / 16-byte block = 2 blocks → ×2 in the label.
    expect(label).toMatch(/×2/);
  });

  it("emits one xyflow edge per graph edge, with kind-distinguishing style", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const { edges } = cipherGraphToXyflow(graph);
    expect(edges.length).toBe(graph.edges.length);

    const auxEdges = edges.filter((_, i) => graph.edges[i]?.kind === "aux");
    const stateEdges = edges.filter((_, i) => graph.edges[i]?.kind === "state");
    expect(auxEdges.length).toBeGreaterThan(0);
    expect(stateEdges.length).toBeGreaterThan(0);

    // Aux edges animate; state edges don't (visual spine = static).
    for (const e of auxEdges) expect(e.animated).toBe(true);
    for (const e of stateEdges) expect(e.animated).toBe(false);

    // Aux edges carry the auxKey as a label; state edges don't (the
    // sentinel "state" key isn't user-facing).
    for (const e of auxEdges) expect(typeof e.label === "string").toBe(true);
    for (const e of stateEdges) expect(e.label).toBeUndefined();
  });

  it("empty-frames trace produces structure-only graph (no crash, all containers + leaves)", () => {
    // Pre-run state: graph should still render, just without edges.
    const emptyTrace = {
      frames: [],
      finalState: { shape: "bytes" as const, bytes: new Uint8Array(0) },
      finalAux: new Map(),
    };
    const graph = deriveAuxGraph(emptyTrace, aes128Spec);
    const { nodes, edges } = cipherGraphToXyflow(graph);
    expect(nodes.length).toBe(graph.nodes.length + graph.containers.length);
    // State edges come from the spec (always present); aux edges need a
    // trace. So edges array isn't empty — it just has only state edges.
    for (const e of edges) {
      // animated=true → kind="aux"; animated=false → kind="state"
      expect(e.animated).toBe(false);
    }
  });

  // Phase 2 of the spike adds three knobs to the adapter so the view
  // component can match what the SVG GraphView ships: density-scaled
  // layout constants, pinned positions for root-level nodes (drag-to-
  // pin source of truth), and per-node `draggable` so xyflow's drag
  // model only fires on root-level siblings — same Slice 6 container-
  // only-drag scope. These tests pin those properties at the adapter
  // boundary so the view component can trust them.

  it("density scaling: scaleXyflowConstants(0.75) shrinks every value vs. base", () => {
    const compact = scaleXyflowConstants(0.75);
    expect(compact.LEAF_W).toBeLessThan(BASE_XYFLOW_CONSTANTS.LEAF_W);
    expect(compact.LEAF_H).toBeLessThan(BASE_XYFLOW_CONSTANTS.LEAF_H);
    expect(compact.SIBLING_GAP_X).toBeLessThan(BASE_XYFLOW_CONSTANTS.SIBLING_GAP_X);
    expect(compact.PAD_LEFT).toBeLessThan(BASE_XYFLOW_CONSTANTS.PAD_LEFT);
  });

  it("density scaling: scale=1.0 reproduces BASE_XYFLOW_CONSTANTS byte-for-byte", () => {
    const normal = scaleXyflowConstants(1.0);
    expect(normal).toEqual(BASE_XYFLOW_CONSTANTS);
  });

  it("adapter uses scaled constants when constants option is passed", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const compactConsts = scaleXyflowConstants(0.75);
    const { nodes } = cipherGraphToXyflow(graph, { constants: compactConsts });
    // Find any leaf — its width should match the scaled LEAF_W, not the base.
    const leaf = nodes.find((n) => n.type !== "group");
    expect(leaf).toBeDefined();
    expect(leaf?.width).toBe(compactConsts.LEAF_W);
    expect(leaf?.height).toBe(compactConsts.LEAF_H);
  });

  it("pinned positions override root nodes' auto-computed position", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    // Pin the first root container to a specific position.
    const rootId = graph.rootIds[0];
    expect(rootId, "AES-128 should have at least one root").toBeDefined();
    const pinned = new Map<string, { x: number; y: number }>([
      [rootId as string, { x: 1234, y: 567 }],
    ]);
    const { nodes } = cipherGraphToXyflow(graph, { pinnedPositions: pinned });
    const pinnedNode = nodes.find((n) => n.id === rootId);
    expect(pinnedNode?.position).toEqual({ x: 1234, y: 567 });
  });

  it("pinned position on a non-root id is ignored (matches SVG view's root-only drag scope)", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    // round.1.sub-bytes is nested inside round.1; pin it to a bogus
    // absolute position. The adapter should keep it at its auto-laid
    // position (relative to round.1, small positive x).
    const pinned = new Map<string, { x: number; y: number }>([
      ["round.1.sub-bytes", { x: 9999, y: 9999 }],
    ]);
    const { nodes } = cipherGraphToXyflow(graph, { pinnedPositions: pinned });
    const nested = nodes.find((n) => n.id === "round.1.sub-bytes");
    expect(nested).toBeDefined();
    expect(nested?.position.x).toBeLessThan(100);
    expect(nested?.position.y).toBeLessThan(100);
  });

  it("pinning one root preserves x of un-pinned siblings (no reflow on pin)", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const baseline = cipherGraphToXyflow(graph);
    const rootIds = graph.rootIds;
    // Need at least 2 roots for the property to be testable.
    expect(rootIds.length).toBeGreaterThanOrEqual(2);
    const firstRoot = rootIds[0] as string;
    const secondRoot = rootIds[1] as string;
    const pinned = new Map<string, { x: number; y: number }>([[firstRoot, { x: -500, y: -500 }]]);
    const withPin = cipherGraphToXyflow(graph, { pinnedPositions: pinned });
    const findRoot = (
      nodes: readonly { id: string; position: { x: number; y: number } }[],
      id: string,
    ) => nodes.find((n) => n.id === id);
    const baselineSecond = findRoot(baseline.nodes, secondRoot);
    const pinnedSecond = findRoot(withPin.nodes, secondRoot);
    expect(baselineSecond?.position.x).toBe(pinnedSecond?.position.x);
  });

  it("root-level nodes are draggable; nested nodes are not", () => {
    const trace = runAes128();
    const graph = deriveAuxGraph(trace, aes128Spec);
    const { nodes } = cipherGraphToXyflow(graph);
    const rootSet = new Set(graph.rootIds);
    for (const n of nodes) {
      if (rootSet.has(n.id)) {
        expect(n.draggable, `${n.id} should be draggable (root)`).toBe(true);
      } else {
        expect(n.draggable, `${n.id} should NOT be draggable (nested)`).toBe(false);
      }
    }
  });

  it("collapsed container (childIds=[]) renders as small labeled chip, not a sized box", () => {
    // Simulate a post-collapse graph: clear a container's childIds.
    const trace = runAes128();
    const original = deriveAuxGraph(trace, aes128Spec);
    const collapsedGraph: CipherGraph = {
      ...original,
      containers: original.containers.map((c) =>
        c.id === "round.1" ? { ...c, childIds: [] as readonly string[] } : c,
      ),
      // Hide the children of the collapsed container so the adapter
      // doesn't see orphaned parentId references.
      nodes: original.nodes.filter((n) => !n.containerPath.includes("round.1")),
    };
    const { nodes } = cipherGraphToXyflow(collapsedGraph);
    const collapsed = nodes.find((n) => n.id === "round.1");
    expect(collapsed).toBeDefined();
    expect(collapsed?.type).toBe("group");
    // Collapsed chip uses leaf-sized dimensions (180×56) per the adapter.
    expect(collapsed?.width).toBe(180);
    expect(collapsed?.height).toBe(56);
  });
});
