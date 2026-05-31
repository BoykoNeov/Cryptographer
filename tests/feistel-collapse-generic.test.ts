/**
 * Phase 6 of the DES + branching primitive plan
 * (`docs/plans/des-feistel.md`).
 *
 * The plan §Phase 2 originally proposed adding a separate
 * `collapseFeistelRoundEdges` pure transform alongside `collapseGraph`
 * to handle edges touching a collapsed feistel-round. Advisor's Phase 6
 * review (2026-05-20) flagged that generic `collapseGraph` already
 * remaps any edge endpoint to its outermost collapsed-ancestor on
 * `containerPath`; this file proves (via the assertions below) that
 * generic collapse is sufficient, so the planned new transform was
 * never written.
 *
 * **Retargeted to a synthetic feistel spec in B4 (universal-port Phase 4d).**
 * After the DES rebuild, `desSpec` no longer uses `feistel-round`, so the
 * collapse-on-a-feistel-round behavior is exercised here against a LOCAL
 * synthetic 4-round Feistel spec built from the lifted `feistel.toy-add-k@1`
 * leaf. The `feistel-round` primitive + `collapseGraph` survive until Phase 5,
 * and these assertions are the generic collapse-machinery coverage. The
 * structural tests use an EMPTY trace (deriveAuxGraph only — no run), so the
 * synthetic spec is never executed. The one DES-only test (key-schedule aux
 * fan-out onto a collapsed round) is dropped — the toy F uses a param `k`,
 * not an aux round key, so there is no aux fan-out to assert.
 */

import { collapseGraph, deriveAuxGraph } from "@/core/graph";
import type { CipherSpec, FeistelRoundGroup } from "@/core/types";
import { describe, expect, it } from "vitest";

// Synthetic 4-round Feistel spec — 4 rounds so round.3 has BOTH a
// predecessor (round.2) and a successor (round.4), the configuration the
// spine-threading assertion needs. Each R track has ONE leaf (`add-k`); the
// L track is an empty passthrough (the textbook Feistel shape). Built from
// `feistel.toy-add-k@1` (lifted, runnable) but only ever DERIVED here.
const synthRound = (
  id: string,
  k: number,
  combineKind: FeistelRoundGroup["combineKind"],
): FeistelRoundGroup => ({
  kind: "feistel-round",
  id,
  label: id,
  tracks: [
    { name: "L", inputBytes: [0, 1], children: [] },
    {
      name: "R",
      inputBytes: [2, 3],
      children: [{ kind: "step", id: `${id}.add-k`, type: "feistel.toy-add-k@1", params: { k } }],
    },
  ],
  combineKind,
});

const SYNTH_SPEC: CipherSpec = {
  id: "synth-feistel-collapse@1",
  name: "Synthetic 4-round Feistel (collapse experiment)",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 2 } },
  steps: [
    synthRound("round.1", 0x11, "feistel-standard"),
    synthRound("round.2", 0x22, "feistel-standard"),
    synthRound("round.3", 0x33, "feistel-standard"),
    synthRound("round.4", 0x44, "feistel-no-swap"),
  ],
};

const emptyTrace = {
  frames: [],
  initialState: { shape: "bytes" as const, bytes: new Uint8Array(4) },
  finalState: { shape: "bytes" as const, bytes: new Uint8Array(4) },
  finalAux: new Map(),
};

describe("Phase 6 experiment — collapseGraph on a feistel-round", () => {
  it("remaps round.3's R-track-leaf endpoints to round.3 when round.3 is collapsed", () => {
    const raw = deriveAuxGraph(emptyTrace, SYNTH_SPEC);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));

    // No edge should reference round.3's R-track leaf post-collapse.
    const offending = collapsed.edges.filter(
      (e) => e.from === "round.3.add-k" || e.to === "round.3.add-k",
    );
    expect(
      offending.length,
      "Edge endpoint should have remapped from round.3.add-k to round.3",
    ).toBe(0);

    // The rejoin synthetic id sits inside round.3's containerPath so it
    // should also remap to round.3.
    const rejoinOffending = collapsed.edges.filter(
      (e) => e.from === "round.3:rejoin" || e.to === "round.3:rejoin",
    );
    expect(
      rejoinOffending.length,
      "Edge endpoint should have remapped from round.3:rejoin to round.3",
    ).toBe(0);
  });

  it("preserves the inter-round spine: predecessor → round.3 → round.4", () => {
    const raw = deriveAuxGraph(emptyTrace, SYNTH_SPEC);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));

    const stateEdges = collapsed.edges.filter((e) => e.kind === "state");
    // After collapse, the spine enters round.3 from round.2's rejoin.
    expect(
      stateEdges.some((e) => e.from === "round.2:rejoin" && e.to === "round.3"),
      "spine should enter collapsed round.3",
    ).toBe(true);
    // And exits round.3 onto a round.4 node (the exact entry node — a leaf or
    // a synthesized passthrough/bypass chip — is a graph-derivation detail we
    // don't pin here; assert only that the spine leaves the collapsed round
    // toward round 4).
    expect(
      stateEdges.some((e) => e.from === "round.3" && e.to.startsWith("round.4")),
      "spine should exit collapsed round.3 toward round.4",
    ).toBe(true);
  });

  it("drops self-loops created by collapse (round.3 → round.3 edges)", () => {
    const raw = deriveAuxGraph(emptyTrace, SYNTH_SPEC);
    const collapsed = collapseGraph(raw, new Set(["round.3"]));
    const selfLoops = collapsed.edges.filter((e) => e.from === "round.3" && e.to === "round.3");
    expect(selfLoops.length, "self-loops should be dropped by collapseGraph").toBe(0);
  });
});
