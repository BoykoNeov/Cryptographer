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
import { deriveAuxGraph } from "@/core/graph";
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
    const keyExpEdges = g.edges.filter((e) => e.from === "key-expansion");
    expect(keyExpEdges.length).toBe(11);
    const actualConsumers = new Set(keyExpEdges.map((e) => e.to));
    expect(actualConsumers).toEqual(expectedConsumers);
    // Each edge carries the matching roundKey.<i> aux key.
    for (const e of keyExpEdges) {
      expect(e.auxKey).toMatch(/^roundKey\.\d+$/);
    }
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
    // Each round's add-round-key consumes one roundKey.N regardless of which
    // block. After collapsing :b0..:b3 there must be exactly 11 fan-out
    // edges from key-expansion, the same as single-block AES-128.
    const keyExpEdges = g.edges.filter((e) => e.from === "key-expansion");
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
    const ksEdges = g.edges.filter((e) => e.from === "key-schedule");
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
    const kEdges = g.edges.filter((e) => e.from === "key-expansion");
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
  it("returns the structural graph (nodes + containers + rootIds) with no edges or blockSpan", () => {
    const g = deriveAuxGraph(emptyTrace(), aes128EcbSpec);
    // Spec walk is independent of trace: still 44 nodes + 11 containers.
    expect(g.nodes.length).toBe(44);
    expect(g.containers.length).toBe(11);
    // No frames → no edges and no blockSpan annotations.
    expect(g.edges.length).toBe(0);
    for (const node of g.nodes) expect(node.blockSpan).toBeUndefined();
    for (const c of g.containers) expect(c.blockSpan).toBeUndefined();
  });
});
