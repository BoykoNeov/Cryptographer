/**
 * Regression: value-inspector resolution for MULTI-PORT leaves in the
 * port-native DES graph (reported 2026-06-03).
 *
 * Clicking a DES round's `split` node, or either of its outgoing wires that
 * lands on a fan-in consumer, used to show "no resolvable state" / "no frame
 * found for either endpoint of state edge …". Root cause: `split-bytes` has
 * TWO outputs (`output0` = L, `output1` = R) and the fan-in consumers
 * (`xor`/`concat`) have TWO inputs, so the cipher-agnostic
 * `framePrimaryOut/InBytes` helpers return `null` for both endpoints — and
 * `GraphEdge` discarded WHICH port each edge represented, so the lookup had no
 * way to pick `output0` vs `output1`.
 *
 * The fix carries `fromPort`/`toPort` on each port-flow `GraphEdge` (set by
 * `inferPortEdges`) and teaches `lookupRegularState` to read the SPECIFIC port
 * as a fallback after the primary helpers; the node lookup falls back to the
 * leaf's primary INPUT (the one 8-byte block a split divides).
 *
 * Oracle = the published FIPS 46-3 / Grabbe DES worked example
 * (PT=0123456789ABCDEF, K=133457799BBCDFF1): after the Initial Permutation
 * the round-1 input is L0=CC00CCFF, R0=F0AAF0AA — so `round.1.split`'s input is
 * CC00CCFF F0AAF0AA, its `output0` (L) is CC00CCFF and its `output1` (R) is
 * F0AAF0AA. These intermediates are independent of the lookup code path.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { type GraphEdge, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

const trace = runSpec(desSpec, buildDefaultRegistry(), {
  initialState: { shape: "bytes" as const, bytes: bytesFromHex("0123456789abcdef") },
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
});
const graph = deriveAuxGraph(trace, desSpec);

/** The published post-IP halves for the Grabbe/FIPS worked example. */
const L0 = bytesFromHex("cc00ccff");
const R0 = bytesFromHex("f0aaf0aa");
const ROUND1_INPUT = bytesFromHex("cc00ccfff0aaf0aa");

/** Find the single port-flow edge between two leaves (throws if absent). */
const edgeBetween = (from: string, to: string): GraphEdge => {
  const e = graph.edges.find((g) => g.from === from && g.to === to && g.kind === "state");
  if (e === undefined) throw new Error(`no state edge ${from} → ${to} in derived graph`);
  return e;
};

describe("inferPortEdges — port-flow edges carry their port pairing", () => {
  it("tags split→fxor with fromPort=output0 (L) and toPort=operand0", () => {
    const e = edgeBetween("round.1.split", "round.1.fxor");
    expect(e.fromPort).toBe("output0");
    expect(e.toPort).toBe("operand0");
  });

  it("tags split→recombine with fromPort=output1 (R) and toPort=input0 (round 1 swaps)", () => {
    // Round 1 uses the swap, so recombine = concat(R, L⊕F): its input0 is
    // split.output1 (R). The toPort is the consumer's binding key.
    const e = edgeBetween("round.1.split", "round.1.recombine");
    expect(e.fromPort).toBe("output1");
    expect(e.toPort).toBe("input0");
  });
});

describe("lookupEdgeValue — multi-port DES split wires resolve to the right half", () => {
  it("split → fxor (operand0) resolves to L0 — the bug's first broken edge", () => {
    const out = lookupEdgeValue(
      edgeBetween("round.1.split", "round.1.fxor"),
      desSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toEqual(makeBytesState(L0));
  });

  it("split → recombine (input0) resolves to R0 — the bug's second broken edge", () => {
    const out = lookupEdgeValue(
      edgeBetween("round.1.split", "round.1.recombine"),
      desSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toEqual(makeBytesState(R0));
  });

  it("split → expand-R still resolves to R0 via the consumer's sole `state` input (unchanged)", () => {
    // expand-R has a single `state` input, so this edge already resolved
    // through `framePrimaryInBytes` before the fix — pin that it's unaffected.
    const out = lookupEdgeValue(
      edgeBetween("round.1.split", "round.1.expand-R"),
      desSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toEqual(makeBytesState(R0));
  });
});

describe("lookupNodeValue — clicking the split node shows the 8-byte block it divides", () => {
  it("round.1.split resolves to its 8-byte input (was 'no resolvable state')", () => {
    const out = lookupNodeValue("round.1.split", desSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    // A multi-output leaf has no single OUTPUT to show, so the node lookup
    // falls back to its primary INPUT — the one block being split.
    expect(out.value).toEqual(makeBytesState(ROUND1_INPUT));
  });
});
