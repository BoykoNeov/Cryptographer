/**
 * Tests for `core/edge-value-lookup.ts::lookupEdgeValue` (Slice 4 of the
 * graph-narrative-and-zoom plan).
 *
 * The function is the pure lookup behind the value-inspector panel — it
 * resolves "what value flows through this edge at the current scrubber
 * position?" against a real trace.
 *
 * **Phase 5 Slice 5.1 (2026-05-30).** The bulk of this file's coverage
 * exercised the aux-mode `iterate` block-chip resolution (`blocksFromAux` /
 * `outBlocksAux`, the synthetic block-chip ids, endpoint pills) against the
 * matrix AES-128 ECB fixture — all of which retired with the `MatrixState`
 * shape + the `split-blocks`/`concat-blocks`/`compute-block-count` boundary
 * steps (no shipped spec uses the aux-mode iterate any more; ECB/CBC are
 * port-mode). Those `it`s were removed with the fixture. The surviving
 * byte-native coverage is the toy-Feistel chip path below, which keeps
 * `lookupEdgeValue`'s core branch exercised against a runnable spec.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { FEISTEL_TOY_SPEC } from "@/ciphers/feistel-toy";
import { lookupEdgeValue } from "@/core/edge-value-lookup";
import type { GraphEdge } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { describe, expect, it } from "vitest";

// UX-D candidate (b) R-bypass chip. The chip sits at the head of the R
// column of a Feistel round; its outgoing arrow must surface R_in (the
// pre-F value the bypass carries to rejoin) rather than the post-F-leaf
// value the F-stack-head arrow would otherwise resolve to. Exercised
// against the runnable toy Feistel (R = bytes [2,3], so R_in is 2 bytes;
// first R-leaf is `add-k`).

describe("lookupEdgeValue — UX-D candidate (b) R-bypass chip (toy Feistel)", () => {
  const TOY_PT = "01020304";

  it("returns R_in (2 bytes) for the chip's outgoing edge to rejoin", () => {
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(TOY_PT)),
    });
    const chipOutgoingEdge: GraphEdge = {
      from: "round.1:passthrough-1",
      to: "round.1:rejoin",
      auxKey: "state",
      kind: "state",
    };
    const out = lookupEdgeValue(chipOutgoingEdge, FEISTEL_TOY_SPEC, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    // R_in is the 2-byte R half; the rejoin's combined L||R is 4 bytes.
    // The chip's outgoing arrow MUST surface the R_in form — that's the
    // WHOLE point of routing through a chip rather than starting the arrow
    // at the F-stack head (which would show the post-F-leaf value).
    expect(out.value).toMatchObject({ shape: "bytes" });
    expect((out.value as { bytes: Uint8Array }).bytes.length).toBe(2);
  });

  it("returns R_in (2 bytes) for the chip's outgoing edge into the F-stack head (add-k)", () => {
    // The chip sits at the head of the R-column, so the chain edge
    // chip → add-k runs in parallel with the bypass chip → rejoin. Both
    // outgoing edges resolve to the same R_in — two destinations of one value.
    const trace = runSpec(FEISTEL_TOY_SPEC, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex(TOY_PT)),
    });
    const chipChainEdge: GraphEdge = {
      from: "round.1:passthrough-1",
      to: "round.1.add-k",
      auxKey: "state",
      kind: "state",
    };
    const out = lookupEdgeValue(chipChainEdge, FEISTEL_TOY_SPEC, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toMatchObject({ shape: "bytes" });
    expect((out.value as { bytes: Uint8Array }).bytes.length).toBe(2);
  });
});
