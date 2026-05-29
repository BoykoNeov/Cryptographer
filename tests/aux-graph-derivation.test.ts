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
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import {
  CIPHER_INPUT_ID,
  CIPHER_OUTPUT_ID,
  buildIterateFeedbackPredicate,
  collapseGraph,
  deriveAuxGraph,
  isEndpointId,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { removeStep } from "@/core/spec-mutations";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { INPUT_SOURCE_ID } from "@/core/types";
import type { AuxValue, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";
import { matrixAes192Spec } from "./fixtures/matrix-aes-192";
import { matrixAesEcbSpec } from "./fixtures/matrix-aes-ecb";

// ─── Shared test fixtures ──────────────────────────────────────────────────

const AES128_KEY = "000102030405060708090a0b0c0d0e0f";
const AES128_PT = "00112233445566778899aabbccddeeff";

const SPECK_KEY = "1918111009080100";
const SPECK_PT = "6574694c"; // 4 bytes; same length as BE-paper test vector

const SERPENT128_KEY = "00112233445566778899aabbccddeeff";
const SERPENT128_PT = "00112233445566778899aabbccddeeff";

// Byte-native AES-128 (Slice B1): bytes state + ported dispatch (port-native
// primitives have no legacy executor).
const runAes128 = (): Trace =>
  runSpec(aes128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(AES128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(AES128_KEY)]]),
    portedDispatchEnabled: true,
  });

// 4-block plaintext (NIST SP 800-38A §F.1.1) → 4 ECB iterations.
const ECB_PLAINTEXT_4_BLOCKS =
  "6bc1bee22e409f96e93d7e117393172a" +
  "ae2d8a571e03ac9c9eb76fac45af8e51" +
  "30c81c46a35ce411e5fbc1191a0a52ef" +
  "f69f2445df4f9b17ad2b417be66c3710";

const runAes128Ecb = (): Trace =>
  runSpec(matrixAesEcbSpec, buildDefaultRegistry(), {
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

    // Byte-native AES-128 leaves: 1 key-expansion + 1 init.fetch-rk
    //   + 1 initial.add-round-key
    //   + 9 normal rounds × 5 leaves (sub-bytes, shift-rows, mix-columns,
    //     fetch-rk, add-round-key) = 45
    //   + 1 final round × 4 leaves (no mix-columns) = 4
    //   = 52 leaves.
    // The graph ALSO carries the reserved `$input` source node (A3a) — filter
    // it so "one node per leaf" stays honest. (SHA-256's graph has it too.)
    const leafNodes = g.nodes.filter((n) => n.stepId !== INPUT_SOURCE_ID);
    expect(leafNodes.length).toBe(52);
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
    // Byte-native top-scope shape: [$input source, key-expansion,
    // init.fetch-rk, initial.add-round-key, round.1, ..., round.10].
    expect(g.rootIds[0]).toBe(INPUT_SOURCE_ID);
    expect(g.rootIds[1]).toBe("key-expansion");
    expect(g.rootIds[2]).toBe("init.fetch-rk");
    expect(g.rootIds[3]).toBe("initial.add-round-key");
    expect(g.rootIds.slice(4)).toEqual([
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

  it("fans out an edge from key-expansion to every fetch-rk consumer", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Byte-native: round keys are consumed by `aux-load-bytes@1` fetch-rk
    // leaves (one per round + the initial one), not by add-round-key directly.
    // 11 consumers: init.fetch-rk + round.{1..10}.fetch-rk.
    const expectedConsumers = new Set<string>([
      "init.fetch-rk",
      ...Array.from({ length: 10 }, (_, i) => `round.${i + 1}.fetch-rk`),
    ]);
    // Filter to aux edges — key-expansion is also the first leaf in DFS
    // order, so it carries an outgoing `kind: "state"` spine edge. That edge
    // is correct but not what THIS test pins (the round-key fan-out).
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
    // on the aux side; on the state side, the byte-native spine carries BOTH
    // the spec-derived consecutive-leaf spine ("state" sentinel) AND the
    // port-flow edges ("port-flow" sentinel from inferPortEdges).
    expect(auxEdges.length).toBeGreaterThan(0);
    expect(stateEdges.length).toBeGreaterThan(0);
    // No edge is missing a kind.
    expect(auxEdges.length + stateEdges.length).toBe(g.edges.length);
    // State-kind edges carry a state-family sentinel auxKey ("state" or
    // "port-flow"); aux edges never use those (they come from real
    // `auxWrites` keys like roundKey.N).
    for (const e of auxEdges) {
      expect(e.auxKey).not.toBe("state");
      expect(e.auxKey).not.toBe("port-flow");
    }
    for (const e of stateEdges) expect(["state", "port-flow"]).toContain(e.auxKey);
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
    const g = deriveAuxGraph(trace, matrixAesEcbSpec);

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
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);

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
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    const g = deriveAuxGraph(emptyTrace(), matrixAesEcbSpec);
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
    // AES-128-ECB spine count after the 2026-05-17 iterate-boundary fix:
    //   - top-scope: 5 chain participants (key-expansion, split-blocks,
    //     compute-block-count, ecb-blocks (the iterate), concat-blocks).
    //     Only the two pre-iterate pairs emit state edges; the iterate's
    //     incoming + outgoing spine edges are SUPPRESSED because the
    //     runtime is aux-mediated (state at iter entry is overwritten
    //     from aux, state at iter exit is published into aux — the spine
    //     value never crosses the boundary). → 2 state edges.
    //   - iterate body (initial AK + 9 full rounds + 1 final round = 40 leaves)
    //     → 39 state edges (separate scope, recursed into the body).
    //   - total: 2 + 39 = 41 state edges.
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    expect(stateEdges.length).toBe(41);
  });
});

// ─── State-edge inference (round-to-round spine, commit 2) ────────────────

describe("deriveAuxGraph — state-edge inference (spec-derived spine)", () => {
  // Phase B/C: the two AES-128 single-block pure-spine tests ("produces 40
  // state edges, one per consecutive-leaf pair" and "spine crosses round-group
  // boundaries") were REMOVED for the byte-native rebuild. Byte-native AES has
  // 102 state edges — 51 spec-derived spine ("state") PLUS 51 port-flow
  // companions ("port-flow") from inferPortEdges — so the clean "one edge per
  // consecutive pair" count is dup-broken, and the matrix leaf order they
  // asserted (key-expansion → initial.add-round-key; round.N.shift-rows →
  // round.N.add-round-key) no longer holds (init.fetch-rk / fetch-rk leaves
  // are interposed). The clean spec-derived spine property — a single chain
  // threading every leaf with all endpoints present, transparent through round
  // groups — is pinned on a still-matrix cipher by the Serpent-128 spine test
  // below (98 edges across 32 round groups). Re-pin on AES if/when a port-flow
  // spine assertion is wanted (Phase C, once inferStateEdges retires).

  it("AES-128-ECB: the iterate TERMINATES the parent spine on both sides (no prev→iter, no iter→next, no bridging prev→next)", () => {
    // Headline pedagogical fix (2026-05-17): an aux-mediated iterate
    // doesn't carry the spine value across its boundary. The runtime
    // overwrites `state` from aux[blocksFromAux] at iteration entry and
    // publishes per-iteration output into aux[outBlocksAux] at exit, so
    // the predecessor's stateAfter never reaches body steps and the
    // body's stateAfter never reaches the successor. Drawing white
    // arrows there misled users (the previously-rendered `compute-
    // block-count → ecb-blocks` state edge resolved to the plaintext
    // bytes — confusing pedagogically). Suppressed.
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");

    // Pre-iterate pairs DO emit (both endpoints are non-iterate).
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

    // The headline invariant: NO state edge crosses the iterate
    // boundary in either direction, and NO bridging edge skips over it.
    expect(
      stateEdges.find((e) => e.from === "compute-block-count" && e.to === "ecb-blocks"),
    ).toBeUndefined();
    expect(
      stateEdges.find((e) => e.from === "ecb-blocks" && e.to === "concat-blocks"),
    ).toBeUndefined();
    expect(
      stateEdges.find((e) => e.from === "compute-block-count" && e.to === "concat-blocks"),
    ).toBeUndefined();

    // State edges that would naively imply state passes through the
    // iterate's INTERNAL runtime contract (state replaced by blocks[i])
    // MUST NOT exist either.
    expect(
      stateEdges.find((e) => e.from === "compute-block-count" && e.to === "initial.add-round-key"),
    ).toBeUndefined();
    expect(
      stateEdges.find((e) => e.from === "round.10.add-round-key" && e.to === "concat-blocks"),
    ).toBeUndefined();

    // Total: 2 (top scope, pre-iterate pairs only) + 39 (body) = 41.
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

  it("empty group participates in the spine via its own id (deleting all round body steps)", () => {
    // Regression for the "delete all steps in a round → round disconnects
    // from the chain" bug. With AES-128's round.5 emptied, the spine
    // should route `round.4.add-round-key → round.5 → round.6.sub-bytes`
    // rather than leapfrogging straight to round.6 (which would leave the
    // empty round.5 box stranded on the canvas with no edges).
    let emptiedSpec = aes128Spec;
    // Remove all FIVE children of byte-native round.5 in turn (fetch-rk is the
    // extra leaf vs the matrix round). Using the live mutation helpers keeps
    // the test honest about the editor's actual flow.
    for (const id of [
      "round.5.sub-bytes",
      "round.5.shift-rows",
      "round.5.mix-columns",
      "round.5.fetch-rk",
      "round.5.add-round-key",
    ]) {
      emptiedSpec = removeStep(emptiedSpec, id);
    }
    // Empty-spec derivation: no trace needed for state-edge inference.
    const g = deriveAuxGraph(emptyTrace(), emptiedSpec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");

    // The two headline edges the empty group is supposed to bridge.
    expect(
      stateEdges.find((e) => e.from === "round.4.add-round-key" && e.to === "round.5"),
    ).toBeDefined();
    expect(
      stateEdges.find((e) => e.from === "round.5" && e.to === "round.6.sub-bytes"),
    ).toBeDefined();
    // And critically: the spine MUST NOT skip over round.5 entirely (the
    // pre-fix behavior left round.5 disconnected).
    expect(
      stateEdges.find((e) => e.from === "round.4.add-round-key" && e.to === "round.6.sub-bytes"),
    ).toBeUndefined();
    // (No exact edge-count assertion: byte-native AES carries dup state edges
    // — spec-derived spine + port-flow companions — so a precise count is
    // dup-coupled. The existence bridges above fully pin the regression:
    // "delete all steps in a round → round disconnects from the chain".)
  });

  it("nested empty group inside an otherwise filled outer group still participates", () => {
    // Synthesize a spec with a populated outer group containing an empty
    // inner group sandwiched between two leaves. The inner group should
    // appear as a spine node between them.
    const synthSpec: typeof aes128Spec = {
      ...aes128Spec,
      id: "synth-empty-nested",
      steps: [
        { kind: "step", id: "leafA", type: "test.fixture@1", params: {} },
        {
          kind: "group",
          id: "outer",
          label: "Outer",
          children: [
            { kind: "step", id: "innerLeafA", type: "test.fixture@1", params: {} },
            { kind: "group", id: "inner-empty", label: "Empty", children: [] },
            { kind: "step", id: "innerLeafB", type: "test.fixture@1", params: {} },
          ],
        },
        { kind: "step", id: "leafB", type: "test.fixture@1", params: {} },
      ],
    };
    const g = deriveAuxGraph(emptyTrace(), synthSpec);
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // Single chain: leafA → innerLeafA → inner-empty → innerLeafB → leafB.
    expect(stateEdges.length).toBe(4);
    expect(stateEdges.find((e) => e.from === "innerLeafA" && e.to === "inner-empty")).toBeDefined();
    expect(stateEdges.find((e) => e.from === "inner-empty" && e.to === "innerLeafB")).toBeDefined();
  });

  it("never duplicates aux+state on the same (from, to, auxKey) triple", () => {
    // State edges' "state" sentinel auxKey can't collide with real aux
    // keys (those come from step `auxWrites`, all of which are domain-
    // specific). This pins the no-collision invariant explicitly so a
    // future aux-write of literal "state" doesn't silently merge with
    // the spine in collapseGraph's dedup.
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    // Byte-native round.5 has 5 leaves (sub-bytes, shift-rows, mix-columns,
    // fetch-rk, add-round-key); they vanish from the node list. Pre: 53
    // (52 leaves + $input source), post: 53 - 5 = 48.
    expect(out.nodes.length).toBe(48);
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
    // After collapse: round.3.fetch-rk (the byte-native roundKey.3 consumer)
    // is hidden, but the edge key-expansion → round.3.fetch-rk remaps to
    // key-expansion → round.3. No edge count change for this fan-out (the
    // remap doesn't collide with anything else).
    const after = out.edges.filter((e) => e.kind === "aux" && e.from === "key-expansion").length;
    expect(after).toBe(11);
    // The specific re-routed edge exists.
    expect(
      out.edges.some(
        (e) => e.from === "key-expansion" && e.to === "round.3" && e.auxKey === "roundKey.3",
      ),
    ).toBe(true);
    // And the pre-collapse target (the hidden fetch-rk leaf) is gone.
    expect(out.edges.some((e) => e.to === "round.3.fetch-rk")).toBe(false);
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
    // Two byte-native rounds × 5 leaves = 10 fewer nodes.
    expect(out.nodes.length).toBe(g.nodes.length - 10);
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
    // The state spine threads through every leaf inside a round. Collapsing
    // round.5 hides those leaves; their internal state edges remap both
    // endpoints to round.5 and become self-loops, which the dedup pass drops.
    // Byte-native AES carries dup state edges (spine + port-flow companions),
    // so this asserts the property by EXISTENCE rather than an exact count:
    // after collapse, no surviving state edge touches a hidden round.5.* leaf,
    // and there is no self-loop on round.5.
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set(["round.5"]));
    const afterState = out.edges.filter((e) => e.kind === "state");
    for (const e of afterState) {
      // No edge retains a round.5-internal endpoint (e.g. round.5.sub-bytes).
      expect(e.from.startsWith("round.5.")).toBe(false);
      expect(e.to.startsWith("round.5.")).toBe(false);
      // No self-loop on the collapsed container chip.
      expect(e.from === "round.5" && e.to === "round.5").toBe(false);
    }
    // Sanity: the collapse left the spine connected through the round.5 chip
    // (the cross-boundary edges survive — pinned in detail by the next test).
    expect(afterState.some((e) => e.from === "round.4.add-round-key" && e.to === "round.5")).toBe(
      true,
    );
    expect(afterState.some((e) => e.from === "round.5" && e.to === "round.6.sub-bytes")).toBe(true);
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
    // Pre-collapse: AES-128-ECB has 41 state edges (post-2026-05-17
    // iterate-boundary fix):
    //   - top scope: 2 pre-iterate pairs (KE → split, split → count)
    //     ONLY — the prev→iter and iter→next edges are suppressed
    //     because the iterate is aux-mediated (see inferStateEdges'
    //     iterateIds doc-block).
    //   - iterate body scope: 39 (40 leaves → 39 in one chain).
    // Collapsing the iterate hides all 40 body leaves, so all 39 body
    // state edges remap both endpoints to "ecb-blocks" and become
    // self-loops → dropped. The 2 top-scope edges survive untouched.
    // 41 − 39 = 2.
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec);
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
    // The previously-rendered phantom prev→iter and iter→next edges
    // are absent (suppressed in derivation, never produced).
    expect(
      stateAfter.find((e) => e.from === "compute-block-count" && e.to === "ecb-blocks"),
    ).toBeUndefined();
    expect(
      stateAfter.find((e) => e.from === "ecb-blocks" && e.to === "concat-blocks"),
    ).toBeUndefined();
    // No state self-loop on the iterate container.
    for (const e of stateAfter) {
      expect(e.from === "ecb-blocks" && e.to === "ecb-blocks").toBe(false);
    }
  });

  it("collapses an iterate container (AES-128-ECB → ecb-blocks)", () => {
    const trace = runAes128Ecb();
    const g = deriveAuxGraph(trace, matrixAesEcbSpec);
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

// ─── Slice 1 of graph-narrative plan — synthetic endpoint pills ──────────

describe("deriveAuxGraph — synthetic endpoint pills (Slice 1)", () => {
  // The pills are opt-in via `opts.endpoints`. Every test in the suites
  // above continues to call `deriveAuxGraph(trace, spec)` with no opts and
  // sees the same shape it always did — these tests opt in and check the
  // injected pieces.

  // Retargeted to the shared MATRIX AES-192 fixture (`tests/fixtures/
  // matrix-aes-192.ts`). Every shipped single-block AES is byte-native as of
  // Slice B1.3 and injects a `$input` port-flow source node that occupies
  // rootIds[0], colliding with the synthetic endpoint-pill placement these
  // tests pin. The matrix fixture (no `$input` source node) preserves the exact
  // pill semantics — a top-level aux-only `key-expansion` root, a standalone
  // `initial.add-round-key`, and `round.12` as the final round. The
  // `$input`-vs-endpoint-pill interaction for byte-native specs is the real
  // feature question deferred to the B1.4 follow-up (Slice 2.9c-e / universal
  // inspector), tracked in the scaffolding-suppression plan.
  const ENCRYPT_OPTS = {
    endpoints: {
      inputLabel: "plaintext",
      outputLabel: "ciphertext",
      // The renderer skips aux-only leaves (key-expansion). The unit
      // tests pass the desired anchor directly — they don't have the
      // registry handy and the fallback to rootIds[0] would point at
      // key-expansion, which is what Option B is designed to avoid.
      inputAnchorId: "initial.add-round-key",
      outputAnchorId: "round.12",
    },
  };

  it("injects two endpoint nodes when opts.endpoints is provided", () => {
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, ENCRYPT_OPTS);

    const input = g.nodes.find((n) => n.stepId === CIPHER_INPUT_ID);
    const output = g.nodes.find((n) => n.stepId === CIPHER_OUTPUT_ID);
    expect(input).toBeDefined();
    expect(output).toBeDefined();
    expect(input?.endpointSide).toBe("input");
    expect(output?.endpointSide).toBe("output");
    expect(input?.label).toBe("plaintext");
    expect(output?.label).toBe("ciphertext");
    // Endpoint pills are root-level (no container path).
    expect(input?.containerPath.length).toBe(0);
    expect(output?.containerPath.length).toBe(0);
  });

  it("omits endpoint nodes when opts is undefined (back-compat)", () => {
    // Every existing test in this file calls deriveAuxGraph with no opts.
    // This pins that contract: no opts ⇒ no pills, ever.
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec);
    expect(g.nodes.some((n) => isEndpointId(n.stepId))).toBe(false);
    expect(g.edges.some((e) => isEndpointId(e.from) || isEndpointId(e.to))).toBe(false);
  });

  it("prepends + appends pills to rootIds (canvas-extreme placement hook)", () => {
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, ENCRYPT_OPTS);
    expect(g.rootIds[0]).toBe(CIPHER_INPUT_ID);
    expect(g.rootIds[g.rootIds.length - 1]).toBe(CIPHER_OUTPUT_ID);
  });

  it("emits two state-kind edges connecting the pills to the anchors", () => {
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, ENCRYPT_OPTS);

    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    const outputEdge = g.edges.find((e) => e.to === CIPHER_OUTPUT_ID);
    expect(inputEdge).toBeDefined();
    expect(outputEdge).toBeDefined();
    expect(inputEdge?.kind).toBe("state");
    expect(outputEdge?.kind).toBe("state");
    expect(inputEdge?.to).toBe("initial.add-round-key");
    expect(outputEdge?.from).toBe("round.12");
  });

  it("falls back to rootIds[0] / rootIds[last] when anchors are omitted", () => {
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, {
      endpoints: { inputLabel: "plaintext", outputLabel: "ciphertext" },
    });

    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    const outputEdge = g.edges.find((e) => e.to === CIPHER_OUTPUT_ID);
    // Without anchor overrides, the function points at the spec's literal
    // top-level extremes. For matrix AES-192 that means key-expansion at the
    // input side and the final round (round.12) at the output side. The
    // renderer's job is to pass smarter anchors that skip aux-only leaves.
    expect(inputEdge?.to).toBe("key-expansion");
    expect(outputEdge?.from).toBe("round.12");
  });

  it("swaps labels on decrypt-style invocation", () => {
    // Decrypt mode: the caller's labels themselves swap. The function
    // doesn't introspect direction; it just renders what it's given.
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, {
      endpoints: {
        inputLabel: "ciphertext",
        outputLabel: "plaintext",
        inputAnchorId: "initial.add-round-key",
        outputAnchorId: "round.12",
      },
    });
    expect(g.nodes.find((n) => n.stepId === CIPHER_INPUT_ID)?.label).toBe("ciphertext");
    expect(g.nodes.find((n) => n.stepId === CIPHER_OUTPUT_ID)?.label).toBe("plaintext");
  });

  it("renderer's anchor heuristic skips aux-only leaves (regression pin)", () => {
    // The renderer (GraphView.tsx) walks rootIds forward to find the
    // first leaf whose shapeContract.input is NOT "any", skipping
    // key-expansion. This test validates the *intent* by exercising the
    // helper directly with the value the renderer would pass — pinning
    // that the function honors a non-rootIds[0] anchor when supplied.
    const g = deriveAuxGraph(emptyTrace(), matrixAes192Spec, ENCRYPT_OPTS);
    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    // initial.add-round-key, NOT key-expansion (which is the literal rootIds[0]).
    expect(inputEdge?.to).toBe("initial.add-round-key");
    // Visually: the plaintext-pill arrow lands at the leaf that actually
    // reads state, not at the key schedule.
  });

  it("endpoint edges are never classified as feedback", () => {
    // Defense in depth: buildIterateFeedbackPredicate's early-return for
    // endpoint ids means the renderer never dashes the spine edges into
    // the pills. State edges are already excluded from feedback by kind,
    // so this is belt-and-suspenders against a future re-classification.
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec, ENCRYPT_OPTS);
    const isFeedback = buildIterateFeedbackPredicate(g);
    for (const e of g.edges) {
      if (isEndpointId(e.from) || isEndpointId(e.to)) {
        expect(isFeedback(e)).toBe(false);
      }
    }
  });

  it("collapsing the entire iterate body still leaves the input pill visible", () => {
    // The pedagogical payoff of Slice 1: even when the user collapses
    // away the round body, "plaintext enters here" is still self-evident.
    const g = deriveAuxGraph(runAes128Ecb(), matrixAesEcbSpec, {
      endpoints: {
        inputLabel: "plaintext",
        outputLabel: "ciphertext",
        inputAnchorId: "split-blocks",
        outputAnchorId: "concat-blocks",
      },
    });
    const collapsed = collapseGraph(g, new Set(["ecb-blocks"]));
    // Both pills survive the collapse.
    expect(collapsed.nodes.some((n) => n.stepId === CIPHER_INPUT_ID)).toBe(true);
    expect(collapsed.nodes.some((n) => n.stepId === CIPHER_OUTPUT_ID)).toBe(true);
    // Both endpoint edges survive too (their anchors are outside the
    // iterate, so collapse's "remap inside-collapsed endpoints" pass
    // doesn't touch them).
    expect(collapsed.edges.some((e) => e.from === CIPHER_INPUT_ID)).toBe(true);
    expect(collapsed.edges.some((e) => e.to === CIPHER_OUTPUT_ID)).toBe(true);
  });

  it("suppresses pill injection when the spec is empty", () => {
    // No rootIds → no anchors possible → no pills. Cheaper than
    // rendering a floating "plaintext" arrow into nothing.
    const emptySpec = { ...aes128Spec, steps: [] };
    const g = deriveAuxGraph(emptyTrace(), emptySpec, ENCRYPT_OPTS);
    expect(g.nodes.some((n) => isEndpointId(n.stepId))).toBe(false);
    expect(g.edges.some((e) => isEndpointId(e.from) || isEndpointId(e.to))).toBe(false);
  });
});
