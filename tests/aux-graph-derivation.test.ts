/**
 * Tests for `src/core/graph.ts::deriveAuxGraph`.
 *
 * Slice 1 of the 2D editor plan. The graph derivation underpins every UI
 * slice that follows (Slice 2's read-only view, Slice 6's drag layout,
 * Slice 8's palette insertion, Slice 9's edge-aware validation), so these
 * tests pin the structural and edge-derivation behavior across all three
 * cipher families that ship today: AES (single-block + ECB iterate), Speck
 * (flat, no containers), Serpent (deeply nested round groups).
 *
 * Coverage targets:
 *   - Node / container counts per spec
 *   - rootIds ordering (top-level mix of leaves and containers)
 *   - Round-key fan-out edges (key-expansion → every consumer)
 *   - Iterate-mediated edges (split-blocks → iterate → concat-blocks)
 *   - `:b{i}` collapse (4 iterations → 1 edge per logical pair)
 *   - blockSpan annotation on iterate-body leaves and the iterate container
 *   - Trace-less derivation (structure only, no edges, no blockSpan)
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { collapseGraph, deriveAuxGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Shared test fixtures ──────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const SPECK_KEY = "1918111009080100";
const SPECK_PT = "6574694c"; // 4 bytes; same length as BE-paper test vector

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT128_PT = "00112233445566778899aabbccddeeff";

const runAes128 = (): Trace =>
  runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: matrixFromBytes(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
  });

// 4-block plaintext (NIST SP 800-38A §F.1.1) → 4 ECB iterations.
const ECB_PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const runAes128Ecb = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS)),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("2b7e151628aed2a6abf7158809cf4f3c")],
    ]),
  });

const runSpeck = (): Trace =>
  runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SPECK_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SPECK_KEY)]]),
  });

const runSerpent128 = (): Trace =>
  runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
  });

const emptyTrace = (): Trace => ({
  frames: [],
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

// ─── AES-128 (no iterate) ──────────────────────────────────────────────────

describe("deriveAuxGraph — AES-128 (single block, no iterate)", () => {
  it("emits one node per leaf in the spec", () => {
    const trace = runAes128();
    const g = deriveAuxGraph(trace, aes128Spec);

    // AES-128 leaves: 1 key-expansion + 1 initial.add-round-key
    //   + 9 normal rounds × 4 leaves = 36
    //   + 1 final round × 3 leaves = 3
    //   = 41 leaves.
    expect(g.nodes.length).toBe(41);
  });

  it("emits one container per group (round.1 .. round.10)", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    expect(g.containers.length).toBe(10);
    expect(g.containers.every((c) => c.kind === "group")).toBe(true);
    const ids = g.containers.map((c) => c.id).sort();
    expect(ids).toEqual(
      [
        "round.1",
        "round.2",
        "round.3",
        "round.4",
        "round.5",
        "round.6",
        "round.7",
        "round.8",
        "round.9",
        "round.10",
      ].sort(),
    );
  });

  it("rootIds interleaves the top-level leaf with each round group, in spec order", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Spec shape: [key-expansion, initial.add-round-key, round.1, ..., round.10]
    expect(g.rootIds[0]).toBe("key-expansion");
    expect(g.rootIds[1]).toBe("initial.add-round-key");
    expect(g.rootIds.slice(2)).toEqual([
      "round.1",
      "round.2",
      "round.3",
      "round.4",
      "round.5",
      "round.6",
      "round.7",
      "round.8",
      "round.9",
      "round.10",
    ]);
  });

  it("fans out an edge from key-expansion to every add-round-key consumer", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // 11 consumers: initial.add-round-key + round.{1..10}.add-round-key.
    const expectedConsumers = new Set<string>([
      "initial.add-round-key",
      ...Array.from({ length: 10 }, (_, i) => `round.${i + 1}.add-round-key`),
    ]);
    // Filter to aux edges — key-expansion is also the first leaf in DFS
    // order, so it carries an outgoing `kind: "state"` spine edge to
    // initial.add-round-key. That edge is correct but not what THIS test
    // pins (this is the round-key fan-out test, sequence commit 1).
    const keyExpEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion");
    expect(keyExpEdges.length).toBe(11);
    const actualConsumers = new Set(keyExpEdges.map((e) => e.to));
    expect(actualConsumers).toEqual(expectedConsumers);
    // Each edge carries the matching roundKey.<i> aux key.
    for (const e of keyExpEdges) {
      expect(e.auxKey).toMatch(/^roundKey\.\d+$/);
    }
  });

  // Sequence commits 1 + 2: trace-derived edges (round-key fan-out etc.)
  // carry `kind: "aux"`; spec-derived spine edges (consecutive-leaf state
  // thread) carry `kind: "state"`. The two populations are disjoint by
  // their auxKey sentinel: state edges all use the literal "state" key,
  // which never collides with a real `auxWrites` key.
  it("partitions edges into aux (trace) and state (spec) populations", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    expect(g.edges.length).toBeGreaterThan(0);
    const auxEdges = g.edges.filter((e) => e.kind === "aux");
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // Both populations must be non-empty for AES-128 — round-key fan-out
    // on the aux side, the 40-edge spine on the state side.
    expect(auxEdges.length).toBeGreaterThan(0);
    expect(stateEdges.length).toBeGreaterThan(0);
    // No edge is missing a kind.
    expect(auxEdges.length + stateEdges.length).toBe(g.edges.length);
    // State edges always carry the "state" sentinel auxKey; aux edges
    // never use it (they come from real `auxWrites` keys).
    for (const e of auxEdges) expect(e.auxKey).not.toBe("state");
    for (const e of stateEdges) expect(e.auxKey).toBe("state");
  });

  it("assigns no blockSpan to any node when no iterate is present", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    for (const node of g.nodes) expect(node.blockSpan).toBeUndefined();
    for (const c of g.containers) expect(c.blockSpan).toBeUndefined();
  });

  it("populates containerPath for leaves nested inside a round group", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const node = g.nodes.find((n) => n.stepId === "round.5.mix-columns");
    expect(node).toBeDefined();
    expect(node?.containerPath).toEqual(["round.5"]);
  });
});

// ─── AES-128-ECB (iterate) ─────────────────────────────────────────────────

describe("deriveAuxGraph — AES-128-ECB (multi-block iterate)", () => {
  it("collapses :b{i} suffixes — leaf count matches spec, not trace", () => {
    const trace = runAes128Ecb();
    const g = deriveAuxGraph(trace, aes128EcbSpec);

    // Spec leaves: key-expansion + split-blocks + compute-block-count +
    //   concat-blocks + (initial.add-round-key + 9 × 4 + 1 × 3 inside iterate)
    //   = 4 + 40 = 44.
    // Trace, by contrast, has 164 frames — the :b{i} suffix multiplies each
    // iterate-body leaf by 4. Confirm the graph collapses.
    expect(g.nodes.length).toBe(44);
    // Sanity: trace really has 164 frames, so the collapse is non-trivial.
    expect(trace.frames.length).toBe(164);
  });

  it("includes one iterate container plus the 10 round groups inside it", () => {
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    // 1 iterate container + 10 round groups (groups are also inside the iterate).
    expect(g.containers.length).toBe(11);
    const iterate = g.containers.find((c) => c.kind === "iterate");
    expect(iterate?.id).toBe("ecb-blocks");
    const groups = g.containers.filter((c) => c.kind === "group");
    expect(groups.length).toBe(10);
    // Every group sits inside the iterate.
    for (const grp of groups) {
      expect(grp.containerPath).toEqual(["ecb-blocks"]);
    }
  });

  it("synthesizes split-blocks → iterate → concat-blocks edges across the boundary", () => {
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);

    // Iterate consumes input-blocks (written by split-blocks) and blockCount
    // (written by compute-block-count). Both must show up as edges to
    // `ecb-blocks` even though no FRAME records the read.
    const inputEdge = g.edges.find((e) => e.to === "ecb-blocks" && e.auxKey === "input-blocks");
    expect(inputEdge?.from).toBe("split-blocks");

    const countEdge = g.edges.find((e) => e.to === "ecb-blocks" && e.auxKey === "blockCount");
    expect(countEdge?.from).toBe("compute-block-count");

    // The iterate produces output-blocks (written by the runtime, not by a
    // frame). concat-blocks reads it.
    const outputEdge = g.edges.find((e) => e.from === "ecb-blocks" && e.auxKey === "output-blocks");
    expect(outputEdge?.to).toBe("concat-blocks");
  });

  it("dedups iteration replicas — key-expansion → round.N.add-round-key shows ONE edge per N", () => {
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    // Filter to aux edges — key-expansion also carries a `kind: "state"`
    // spine edge to the next DFS-consecutive leaf (split-blocks at top
    // scope in ECB), which isn't what this dedup test pins.
    const keyExpEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion");
    // Each round's add-round-key consumes one roundKey.N regardless of which
    // block. After collapsing :b0..:b3 there must be exactly 11 fan-out
    // edges from key-expansion, the same as single-block AES-128.
    expect(keyExpEdges.length).toBe(11);
    // And every (from,to,auxKey) triple is unique — paranoia against dedup
    // regressions when iteration replicas multiplied.
    const triples = new Set(keyExpEdges.map((e) => `${e.from}|${e.to}|${e.auxKey}`));
    expect(triples.size).toBe(11);
  });

  it("annotates blockSpan = 4 on the iterate container and on every leaf inside it", () => {
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    const iterate = g.containers.find((c) => c.id === "ecb-blocks");
    expect(iterate?.blockSpan).toBe(4);
    // A leaf inside the iterate: round.1.sub-bytes.
    const insideNode = g.nodes.find((n) => n.stepId === "round.1.sub-bytes");
    expect(insideNode?.blockSpan).toBe(4);
    // A leaf outside the iterate: split-blocks. No blockSpan.
    const outsideNode = g.nodes.find((n) => n.stepId === "split-blocks");
    expect(outsideNode?.blockSpan).toBeUndefined();
  });
});

// ─── Speck32/64 (flat, no containers, ARX) ────────────────────────────────

describe("deriveAuxGraph — Speck32/64 BE (flat, no groups)", () => {
  it("emits 23 leaves (key-schedule + 22 rounds) and zero containers", () => {
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec);
    expect(g.nodes.length).toBe(23);
    expect(g.containers.length).toBe(0);
  });

  it("fans out 22 round-key edges from key-schedule to round.1..round.22", () => {
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec);
    // Filter to aux edges — key-schedule is also the first leaf in DFS
    // order, so it has an outgoing `kind: "state"` spine edge to round.1
    // (which this fan-out test deliberately ignores).
    const ksEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-schedule");
    expect(ksEdges.length).toBe(22);
    // Each round.i reads roundKey.{i-1}.
    for (let i = 1; i <= 22; i++) {
      const edge = ksEdges.find((e) => e.to === `round.${i}`);
      expect(edge?.auxKey).toBe(`roundKey.${i - 1}`);
    }
  });
});

// ─── Serpent-128 (deeply nested round groups, 32 rounds) ──────────────────

describe("deriveAuxGraph — Serpent-128 (SP-network, 32 round groups)", () => {
  it("emits 99 leaves and 32 round-group containers", () => {
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec);
    // Leaves: 1 key-expansion + 1 IP + 31×3 (normal rounds) +
    //         3 (final round) + 1 FP = 99.
    expect(g.nodes.length).toBe(99);
    // Containers: 32 round groups (round.1 .. round.32). IP and FP are leaves.
    expect(g.containers.length).toBe(32);
    expect(g.containers.every((c) => c.kind === "group")).toBe(true);
  });

  it("fans out 33 round-key edges from key-expansion (rounds 1..31 + round 32's two AKs)", () => {
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec);
    // Each normal round has 1 AddRoundKey (rounds 1..31 → 31 edges).
    // Final round (32) has 2 AddRoundKey leaves (.add-round-key + .add-final-round-key).
    // Total fan-out: 31 + 2 = 33.
    // Filter to aux edges — key-expansion is also the first leaf in DFS
    // order, so it has an outgoing `kind: "state"` spine edge to `ip`.
    const kEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion");
    expect(kEdges.length).toBe(33);
    // Each edge carries a distinct roundKey.N.
    const auxKeys = new Set(kEdges.map((e) => e.auxKey));
    expect(auxKeys.size).toBe(33);
  });
});

// ─── Edge dedup paranoia (no actual case today; structural guard) ────────

describe("deriveAuxGraph — edge deduplication", () => {
  it("collapses identical (from, to, auxKey) triples to a single edge", () => {
    // The natural case: 4-block ECB produces 4 copies of every iterate-body
    // edge before dedup. The graph must keep exactly one.
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    const seen = new Set<string>();
    for (const e of g.edges) {
      const k = `${e.from}|${e.to}|${e.auxKey}`;
      expect(seen.has(k)).toBe(false);
      seen.add(k);
    }
  });
});

// ─── Trace-less derivation (pre-run state) ────────────────────────────────

describe("deriveAuxGraph — empty trace", () => {
  it("returns spec-derived spine but no aux edges or blockSpan annotations", () => {
    const g = deriveAuxGraph(emptyTrace(), aes128EcbSpec);
    // Spec walk is independent of trace: still 44 nodes + 11 containers.
    expect(g.nodes.length).toBe(44);
    expect(g.containers.length).toBe(11);
    // No frames → no aux edges and no blockSpan annotations.
    const auxEdges = g.edges.filter((e) => e.kind === "aux");
    expect(auxEdges.length).toBe(0);
    for (const node of g.nodes) expect(node.blockSpan).toBeUndefined();
    for (const c of g.containers) expect(c.blockSpan).toBeUndefined();
    // Spec-derived state spine appears regardless of trace state — the
    // headline pedagogical benefit of commit 2 is that the spine is visible
    // BEFORE the first run, so the user sees what the cipher "does" up front.
    // AES-128-ECB spine count:
    //   - top-scope pre-iterate: 3 leaves → 2 state edges
    //   - iterate body (initial AK + 9 full rounds + 1 final round = 40 leaves)
    //     → 39 state edges
    //   - top-scope post-iterate: 1 leaf (concat-blocks) → 0 state edges
    //   - total: 2 + 39 + 0 = 41 state edges
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    expect(stateEdges.length).toBe(41);
  });
});

// ─── State-edge inference (round-to-round spine, commit 2) ────────────────

describe("deriveAuxGraph — state-edge inference (spec-derived spine)", () => {
  it("AES-128: produces 40 state edges, one per consecutive-leaf pair", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // 41 leaves in DFS order → 40 edges in a single chain (no iterate
    // boundary to break it).
    expect(stateEdges.length).toBe(40);
    // Every state edge is between two distinct nodes that exist in the graph.
    const nodeIds = new Set(g.nodes.map((n) => n.stepId));
    for (const e of stateEdges) {
      expect(e.from).not.toBe(e.to);
      expect(nodeIds.has(e.from)).toBe(true);
      expect(nodeIds.has(e.to)).toBe(true);
    }
  });

  it("AES-128: spine crosses round-group boundaries (round.1.add-round-key → round.2.sub-bytes)", () => {
    // The headline correctness check for the spine: groups are transparent,
    // so the spine threads through every leaf in DFS order regardless of
    // which round-group they live in.
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const bridge = g.edges.find(
      (e) =>
        e.kind === "state" && e.from === "round.1.add-round-key" && e.to === "round.2.sub-bytes",
    );
    expect(bridge).toBeDefined();
    // Same property at the front of the chain: key-expansion → initial.add-round-key.
    const firstPair = g.edges.find(
      (e) => e.kind === "state" && e.from === "key-expansion" && e.to === "initial.add-round-key",
    );
    expect(firstPair).toBeDefined();
    // Last edge: round.10.shift-rows → round.10.add-round-key (the final
    // round has no mix-columns, so the second-to-last leaf is shift-rows).
    const lastEdge = g.edges.find(
      (e) =>
        e.kind === "state" && e.from === "round.10.shift-rows" && e.to === "round.10.add-round-key",
    );
    expect(lastEdge).toBeDefined();
  });

  it("AES-128-ECB: spine breaks at the iterate boundary (no edge crosses in either direction)", () => {
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");

    // Top-scope pre-iterate: 3 leaves (key-expansion, split-blocks,
    // compute-block-count) → 2 state edges in one chain.
    expect(
      stateEdges.find((e) => e.from === "key-expansion" && e.to === "split-blocks"),
    ).toBeDefined();
    expect(
      stateEdges.find((e) => e.from === "split-blocks" && e.to === "compute-block-count"),
    ).toBeDefined();

    // Iterate-body scope: 40 leaves → 39 state edges. Spot-check the
    // expected endpoints inside the body.
    expect(
      stateEdges.find((e) => e.from === "initial.add-round-key" && e.to === "round.1.sub-bytes"),
    ).toBeDefined();
    expect(
      stateEdges.find((e) => e.from === "round.5.add-round-key" && e.to === "round.6.sub-bytes"),
    ).toBeDefined();

    // The headline boundary checks: NO state edge bridges the iterate
    // boundary in either direction. The iterate replaces `state` with
    // `blocks[i]` per iteration and accumulates output into
    // `aux[outBlocksAux]` — the aux edges already capture that handoff
    // honestly, so the state spine MUST NOT double them.
    const crossesIn = stateEdges.find(
      (e) => e.from === "compute-block-count" && e.to === "initial.add-round-key",
    );
    expect(crossesIn).toBeUndefined();
    const crossesOut = stateEdges.find(
      (e) => e.from === "round.10.add-round-key" && e.to === "concat-blocks",
    );
    expect(crossesOut).toBeUndefined();
    // Spine MUST NOT silently skip over the iterate either (compute-block-
    // count is the last pre-iterate leaf and concat-blocks the only post;
    // a naive impl that ignored iterates entirely would emit this edge).
    const skipsIterate = stateEdges.find(
      (e) => e.from === "compute-block-count" && e.to === "concat-blocks",
    );
    expect(skipsIterate).toBeUndefined();

    // Total: 2 (pre) + 39 (body) + 0 (post, concat-blocks is alone) = 41.
    expect(stateEdges.length).toBe(41);
  });

  it("Speck32/64 (flat, no groups, no iterates): 22 state edges across 23 leaves", () => {
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // 23 flat leaves → 22 spine edges. Sanity-check the obvious ones.
    expect(stateEdges.length).toBe(22);
    expect(stateEdges.find((e) => e.from === "key-schedule" && e.to === "round.1")).toBeDefined();
    expect(stateEdges.find((e) => e.from === "round.1" && e.to === "round.2")).toBeDefined();
  });

  it("Serpent-128 (32 round groups, IP/FP outside): spine threads through every leaf", () => {
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // Serpent-128 has 99 leaves → 98 spine edges (one continuous chain;
    // round groups are transparent).
    expect(stateEdges.length).toBe(98);
    // Each spine edge endpoint exists in the node set.
    const nodeIds = new Set(g.nodes.map((n) => n.stepId));
    for (const e of stateEdges) {
      expect(nodeIds.has(e.from)).toBe(true);
      expect(nodeIds.has(e.to)).toBe(true);
    }
  });

  it("never duplicates aux+state on the same (from, to, auxKey) triple", () => {
    // State edges' "state" sentinel auxKey can't collide with real aux
    // keys (those come from step `auxWrites`, all of which are domain-
    // specific). This pins the no-collision invariant explicitly so a
    // future aux-write of literal "state" doesn't silently merge with
    // the spine in collapseGraph's dedup.
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    const auxKeysOnAuxEdges = new Set(g.edges.filter((e) => e.kind === "aux").map((e) => e.auxKey));
    expect(auxKeysOnAuxEdges.has("state")).toBe(false);
  });
});

// ─── collapseGraph (Slice 6 view-time transform) ──────────────────────────

describe("collapseGraph — view-time transform", () => {
  it("is a no-op for an empty collapsedIds set (identity)", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set());
    // Object identity: when the early-return fires, we return the same ref.
    expect(out).toBe(g);
  });

  it("hides every leaf inside a collapsed container (AES-128 round.5 collapse)", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set(["round.5"]));
    // round.5 had 4 leaves (sub-bytes, shift-rows, mix-columns, add-round-key);
    // they vanish from the node list. Pre: 41, post: 41 - 4 = 37.
    expect(out.nodes.length).toBe(37);
    // The container itself stays — renderer draws it as a collapsed chip.
    expect(out.containers.find((c) => c.id === "round.5")).toBeDefined();
    // But its childIds is now empty so the layout walk treats it as leaf-sized.
    expect(out.containers.find((c) => c.id === "round.5")?.childIds.length).toBe(0);
  });

  it("re-routes round-key edges that entered a collapsed container to terminate at it", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Before collapse: 11 fan-out aux edges from key-expansion (initial +
    // round.1..10's add-round-key consumers). Filter to kind=aux because
    // key-expansion also has an outgoing spine edge — see commit 2.
    const before = g.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion").length;
    expect(before).toBe(11);

    const out = collapseGraph(g, new Set(["round.3"]));
    // After collapse: round.3.add-round-key is hidden, but the edge
    // key-expansion → round.3.add-round-key remaps to key-expansion → round.3.
    // No edge count change for this particular fan-out (the remap doesn't
    // collide with anything else).
    const after = out.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion").length;
    expect(after).toBe(11);
    // The specific re-routed edge exists.
    expect(
      out.edges.some(
        (e) => e.from === "key-expansion" && e.to === "round.3" && e.auxKey === "roundKey.3",
      ),
    ).toBe(true);
    // And the pre-collapse target is gone.
    expect(out.edges.some((e) => e.to === "round.3.add-round-key")).toBe(false);
  });

  it("drops self-loop edges produced by collapse (aux that lived entirely inside the container)", () => {
    // AES round groups don't produce internal aux edges (state flows
    // through `state`, not aux), so manufacture the case: collapse
    // round.1 AND every group between key-expansion and round.1's consumer.
    // Simpler proof: collapse round.1; any edge whose endpoints both
    // remap to round.1 disappears.
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Pre-count edges that go between round.1 internal leaves (none in
    // AES because state flows through `state`, not aux — but the property
    // is enforced regardless).
    const out = collapseGraph(g, new Set(["round.1"]));
    // No edge should be a self-loop at round.1.
    for (const e of out.edges) {
      expect(e.from === "round.1" && e.to === "round.1").toBe(false);
    }
  });

  it("collapses multiple containers at once (round.5 + round.6)", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set(["round.5", "round.6"]));
    // Two rounds × 4 leaves = 8 fewer nodes.
    expect(out.nodes.length).toBe(g.nodes.length - 8);
    // Both containers still present in the container list.
    expect(out.containers.some((c) => c.id === "round.5")).toBe(true);
    expect(out.containers.some((c) => c.id === "round.6")).toBe(true);
  });

  it("filters rootIds to only entries that still resolve to a visible node or container", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Collapse a round that's in rootIds — the container ITSELF stays in
    // rootIds (it's still visible as a collapsed chip).
    const out = collapseGraph(g, new Set(["round.7"]));
    expect(out.rootIds).toContain("round.7");
    // Sanity: no rootIds entry that points to a now-hidden leaf.
    const visible = new Set<string>([
      ...out.nodes.map((n) => n.stepId),
      ...out.containers.map((c) => c.id),
    ]);
    for (const id of out.rootIds) expect(visible.has(id)).toBe(true);
  });

  it("drops state edges that lived entirely inside a collapsed container (round.5)", () => {
    // The state spine threads through every leaf inside a round (sub-bytes
    // → shift-rows → mix-columns → add-round-key). Collapsing round.5
    // hides those 4 leaves; their internal state edges remap both
    // endpoints to round.5 and become self-loops, which the dedup pass
    // drops.
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const before = g.edges.filter((e) => e.kind === "state").length;
    expect(before).toBe(40);

    const out = collapseGraph(g, new Set(["round.5"]));
    const afterState = out.edges.filter((e) => e.kind === "state");
    // Inside round.5 there were 3 state edges (4 leaves → 3 internal edges).
    // Plus the two boundary edges (round.4.add-round-key → round.5.sub-bytes
    // and round.5.add-round-key → round.6.sub-bytes) which remap their
    // round.5-side endpoint to "round.5" and survive as cross-boundary
    // edges. Net: 40 - 3 internal = 37 surviving state edges.
    expect(afterState.length).toBe(37);
    // No state self-loop on round.5.
    for (const e of afterState) {
      expect(e.from === "round.5" && e.to === "round.5").toBe(false);
    }
  });

  it("re-routes state edges crossing a collapsed container's boundary to terminate at it", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set(["round.5"]));
    const stateEdges = out.edges.filter((e) => e.kind === "state");
    // The pre-collapse pair (round.4.add-round-key → round.5.sub-bytes)
    // remaps the consumer to the collapsed container chip.
    const entering = stateEdges.find(
      (e) => e.from === "round.4.add-round-key" && e.to === "round.5",
    );
    expect(entering).toBeDefined();
    // The exit edge (round.5.add-round-key → round.6.sub-bytes) remaps
    // the producer to the collapsed chip.
    const leaving = stateEdges.find((e) => e.from === "round.5" && e.to === "round.6.sub-bytes");
    expect(leaving).toBeDefined();
    // And the original-endpoint versions are gone (their internal
    // round.5.* endpoints don't exist anymore in the visible graph).
    expect(
      stateEdges.some((e) => e.from === "round.4.add-round-key" && e.to === "round.5.sub-bytes"),
    ).toBe(false);
    expect(
      stateEdges.some((e) => e.from === "round.5.add-round-key" && e.to === "round.6.sub-bytes"),
    ).toBe(false);
  });

  it("collapses an iterate container's state spine (AES-128-ECB → ecb-blocks)", () => {
    // Pre-collapse: AES-128-ECB has 41 state edges:
    //   - top scope pre-iterate: 2 (KE → split, split → count)
    //   - iterate body scope: 39 (40 leaves → 39 in one chain)
    //   - top scope post-iterate: 0 (concat-blocks alone)
    // Collapsing the iterate hides all 40 body leaves, so all 39 body
    // state edges remap both endpoints to "ecb-blocks" and become
    // self-loops → dropped. The 2 pre-iterate edges survive untouched
    // (their endpoints are outside the iterate). 41 − 39 = 2.
    const g = deriveAuxGraph(runAes128Ecb(), aes128EcbSpec);
    const stateBefore = g.edges.filter((e) => e.kind === "state");
    expect(stateBefore.length).toBe(41);

    const out = collapseGraph(g, new Set(["ecb-blocks"]));
    const stateAfter = out.edges.filter((e) => e.kind === "state");
    expect(stateAfter.length).toBe(2);
    // The two surviving spine edges are the pre-iterate pair.
    expect(
      stateAfter.find((e) => e.from === "key-expansion" && e.to === "split-blocks"),
    ).toBeDefined();
    expect(
      stateAfter.find((e) => e.from === "split-blocks" && e.to === "compute-block-count"),
    ).toBeDefined();
    // No state self-loop on the iterate container.
    for (const e of stateAfter) {
      expect(e.from === "ecb-blocks" && e.to === "ecb-blocks").toBe(false);
    }
  });

  it("collapses an iterate container (AES-128-ECB → ecb-blocks)", () => {
    const trace = runAes128Ecb();
    const g = deriveAuxGraph(trace, aes128EcbSpec);
    // Pre-collapse: 44 nodes total, of which 4 are top-level (key-expansion,
    // split-blocks, compute-block-count, concat-blocks) and 40 live inside
    // the iterate.
    expect(g.nodes.length).toBe(44);
    const out = collapseGraph(g, new Set(["ecb-blocks"]));
    // After collapse: only the 4 top-level leaves remain visible.
    expect(out.nodes.length).toBe(4);
    // The iterate container survives in the container list as a chip;
    // its childIds is cleared.
    const it = out.containers.find((c) => c.id === "ecb-blocks");
    expect(it).toBeDefined();
    expect(it?.childIds.length).toBe(0);
    // Round groups (round.1..round.10) live INSIDE the iterate; they're
    // hidden after collapse.
    expect(out.containers.some((c) => c.id === "round.1")).toBe(false);
  });
});
