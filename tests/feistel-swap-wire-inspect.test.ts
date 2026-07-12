/**
 * Regression: the DES inter-round Feistel swap wires (`R` / `L⊕F`) are
 * INSPECTABLE, and each resolves to its OWN half (reported 2026-07-13).
 *
 * The swap-X overlay in `GraphView` replaces the suppressed `recombine → split`
 * carry edge with two per-half wires. Before this fix the wires had no click
 * target at all (no `data-edge-key`, no handler), so clicking them did nothing.
 * The fix keys each wire to the REAL internal round edge that produced its half:
 *   - the mixed wire (`L⊕F`) → `fxor → recombine` at input `mixedRecombineInput`;
 *   - the carry wire (`R`)   → `carryProducer → recombine` at the COMPLEMENT input.
 *
 * The load-bearing subtlety: `encodeEdgeKey` DROPS `fromPort`, so after the
 * click round-trips through the selection store the carry wire (whose DES
 * producer is the multi-output `split`) resolves SOLELY through
 * `lookupRegularState`'s port-specific `toPort` branch. If the complement port
 * is wrong the "R" wire would silently show `L⊕F` — no error. This test
 * reconstructs the wire keys EXACTLY as `GraphView.feistelSwaps` does and pins
 * that each resolves to the correct half.
 *
 * Oracle = the published Grabbe/FIPS 46-3 worked example
 * (PT=0123456789ABCDEF, K=133457799BBCDFF1): post-IP round-1 R0 = F0AAF0AA.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { analyzeFeistelRound } from "@/core/feistel-shape";
import { PORT_FLOW_AUX_KEY, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { findStepAndParent } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, StepGroup } from "@/core/types";
import { decodeEdgeKey, encodeEdgeKey } from "@/ui/stores/view-value-inspector";
import { describe, expect, it } from "vitest";

const trace = runSpec(desSpec, buildDefaultRegistry(), {
  initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
});
// Derive the graph so we're certain the internal round edges these keys name
// actually exist in the port-flow spine (the wires MATCH real edges byte-for-byte).
const graph = deriveAuxGraph(trace, desSpec);

const R0 = bytesFromHex("f0aaf0aa"); // published post-IP round-1 right half.

const roundGroup = (id: string): StepGroup => {
  const located = findStepAndParent(desSpec, id);
  if (!located || located.node.kind !== "group") throw new Error(`no group at ${id}`);
  return located.node;
};

/**
 * Rebuild the two swap-wire edge keys for a round EXACTLY as
 * `GraphView.feistelSwaps` does — so a divergence in that code path fails here.
 */
const swapWireKeys = (roundId: string): { mixed: string; carry: string } => {
  const shape = analyzeFeistelRound(roundGroup(roundId));
  if (!shape) throw new Error(`round ${roundId} is not a recognized Feistel round`);
  const carryProducer =
    shape.railNodeIds.length > 0
      ? (shape.railNodeIds[shape.railNodeIds.length - 1] as string)
      : shape.splitId;
  const carryRecombineInput = shape.mixedRecombineInput === "input0" ? "input1" : "input0";
  return {
    mixed: encodeEdgeKey({
      from: shape.fxorId,
      to: shape.recombineId,
      auxKey: PORT_FLOW_AUX_KEY,
      kind: "state",
      toPort: shape.mixedRecombineInput,
    }),
    carry: encodeEdgeKey({
      from: carryProducer,
      to: shape.recombineId,
      auxKey: PORT_FLOW_AUX_KEY,
      kind: "state",
      toPort: carryRecombineInput,
    }),
  };
};

describe("DES Feistel swap wires — each wire's key resolves to its own half", () => {
  it("both wire keys name real port-flow edges present in the derived graph", () => {
    const { mixed, carry } = swapWireKeys("round.1");
    for (const key of [mixed, carry]) {
      const edge = decodeEdgeKey(key);
      expect(edge).not.toBeNull();
      if (!edge) return;
      const found = graph.edges.some(
        (g) => g.from === edge.from && g.to === edge.to && g.toPort === edge.toPort,
      );
      expect(found, `edge ${edge.from} → ${edge.to} @${edge.toPort ?? ""}`).toBe(true);
    }
  });

  it("round-1 carry wire (R) resolves to R0 — via the toPort-only branch, fromPort dropped", () => {
    const { carry } = swapWireKeys("round.1");
    const edge = decodeEdgeKey(carry);
    expect(edge).not.toBeNull();
    if (!edge) return;
    // Assert the key really lost fromPort — the whole reason toPort is load-bearing.
    expect(edge.fromPort).toBeUndefined();
    const out = lookupEdgeValue(edge, desSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toEqual(makeBytesState(R0));
  });

  it("round-1 mixed wire (L⊕F) resolves to the fxor's output — the OTHER half", () => {
    const { mixed } = swapWireKeys("round.1");
    const edge = decodeEdgeKey(mixed);
    expect(edge).not.toBeNull();
    if (!edge) return;
    const out = lookupEdgeValue(edge, desSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    // Cross-check against clicking the fxor node itself (its own output bytes),
    // without hardcoding the round-1 intermediate.
    const fxorNode = lookupNodeValue("round.1.fxor", desSpec, trace, undefined);
    expect(fxorNode.status).toBe("value");
    if (fxorNode.status !== "value") return;
    expect(out.value).toEqual(fxorNode.value);
    // And it must NOT be R0 — the two wires carry DIFFERENT halves.
    expect(out.value).not.toEqual(makeBytesState(R0));
  });

  it("round-16 (no-swap) wires still resolve — carry to R via the complement port", () => {
    // Round 16 has swap=false; the complement logic still applies (the carried
    // half lands on whichever recombine input the mixed half does not occupy).
    const { mixed, carry } = swapWireKeys("round.16");
    for (const key of [mixed, carry]) {
      const edge = decodeEdgeKey(key);
      expect(edge).not.toBeNull();
      if (!edge) return;
      const out = lookupEdgeValue(edge, desSpec, trace, undefined);
      expect(out.status, `round.16 ${key}`).toBe("value");
    }
  });
});
