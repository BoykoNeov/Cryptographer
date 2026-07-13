/**
 * SHAKE graph value-resolution guard, 2026-07-13.
 *
 * SHAKE's squeeze loop introduces a graph edge shape no shipped spec had before:
 * `squeeze.perm.1`'s group `seedInput` reads `port("sponge", "state")` — a
 * **container (group) seeding from an iterate's published output**. SHA3-256
 * reads that same `sponge.state` port, but from a LEAF (the squeeze byte-slice);
 * a GROUP reading it exercises `resolveSeedChain` on a fresh path. The project's
 * "no frame found" bugs (SEQUEL5) cluster exactly at container port-flow edges,
 * so this test pins that every SHAKE squeeze edge resolves to a real value —
 * the structural analogue of the browser smoke's "the first perm group's
 * value-dots resolve, not 'no frame found'."
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { type ShakeVariant, buildShakeSpec } from "@/ciphers/shake";
import { lookupEdgeValue } from "@/core/edge-value-lookup";
import { deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex } from "@/core/state/bytes";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/** Every edge whose value lookup fails to resolve (the "no frame found" class),
 *  formatted `from → to [reason]`. */
const unresolvedSqueezeEdges = (variant: ShakeVariant, outputLength: number): string[] => {
  const spec = buildShakeSpec(variant, outputLength);
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: bytesFromHex("616263") }, // "abc"
  });
  const graph = deriveAuxGraph(trace, spec, { registry });
  const failures: string[] = [];
  for (const edge of graph.edges) {
    // Focus on the squeeze subgraph — the new topology this slice adds.
    if (!edge.from.startsWith("squeeze") && !edge.to.startsWith("squeeze")) continue;
    const lookup = lookupEdgeValue(edge, spec, trace, 0);
    if (lookup.status === "missing") {
      failures.push(`${edge.from} → ${edge.to} [${lookup.reason}]`);
    }
  }
  return failures;
};

describe("SHAKE graph — every squeeze edge resolves to a value (no 'no frame found')", () => {
  for (const variant of ["shake128", "shake256"] as const) {
    it(`${variant} @ 200 bytes (2 squeeze blocks, one perm group) resolves fully`, () => {
      expect(unresolvedSqueezeEdges(variant, 200)).toEqual([]);
    });
    it(`${variant} @ 512 bytes (4 blocks, three perm groups) resolves fully`, () => {
      expect(unresolvedSqueezeEdges(variant, 512)).toEqual([]);
    });
  }

  it("the perm.1 group seed edge specifically resolves (the advisor watch-item)", () => {
    const spec = buildShakeSpec("shake256", 200);
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: bytesFromHex("616263") },
    });
    const graph = deriveAuxGraph(trace, spec, { registry });
    // The edge that feeds the first squeeze permutation group its carried state.
    const seedEdge = graph.edges.find(
      (e) => e.to === "squeeze.perm.1" || e.to.startsWith("squeeze.perm.1"),
    );
    expect(seedEdge).toBeDefined();
    if (seedEdge) {
      const lookup = lookupEdgeValue(seedEdge, spec, trace, 0);
      expect(lookup.status).not.toBe("missing");
    }
  });
});
