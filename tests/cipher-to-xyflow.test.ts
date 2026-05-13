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
import { cipherGraphToXyflow } from "@/ui/graph/cipher-to-xyflow";
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
