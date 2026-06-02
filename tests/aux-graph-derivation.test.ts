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
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { INPUT_SOURCE_ID } from "@/core/types";
import type { AuxValue, CipherSpec, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

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
  });

const runSpeck = (): Trace =>
  runSpec(speck32_64BeSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SPECK_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SPECK_KEY)]]),
    // Speck rounds are port-native since B2 → the spec requires ported dispatch.
    // Since Phase 5 Slice 5.3b the round leaves declare explicit `portInputs.state`
    // (round.1 ← `$input`, round.N ← round.{N-1}.state), so a `$input` source node
    // + port-flow spine edges now appear, and the S2(f) gate suppresses the legacy
    // state-thread spine for those leaves. The aux fan-out (key-schedule → round)
    // is unchanged.
  });

const runSerpent128 = (): Trace =>
  runSpec(serpent128Spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(SERPENT128_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(SERPENT128_KEY)]]),
    // Serpent's round body is port-native since B3 → ported dispatch required.
    // Since Slice 5.3b the IP/FP leaves + round groups declare explicit
    // `portInputs`/`seedInput`/`bodyOutput`, so a `$input` source node + a
    // port-flow-owned spine appear (the S2(f) gate suppresses the legacy
    // state-thread for the wired leaves).
  });

const emptyTrace = (): Trace => ({
  frames: [],
  initialState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalState: { shape: "bytes", bytes: new Uint8Array(0) },
  finalAux: new Map(),
});

// ─── AES-128 (no iterate) ──────────────────────────────────────────────────

describe("deriveAuxGraph — AES-128 (single block, no iterate)", () => {
  it("emits one node per leaf in the spec", () => {
    const trace = runAes128();
    const g = deriveAuxGraph(trace, aes128Spec);

    // Byte-native AES-128, decomposed key schedule (K1c). Round body
    // (AddRoundKey merged in F3): 1 initial.add-round-key + 9 normal rounds ×
    // 4 (36) + final round × 3 (3) = 40. The former single `key-expansion`
    // leaf is now the decomposed `key-schedule` GROUP — ~114 primitive leaves
    // (load-key, per-group split/rotword/subword/rcon/temp/wN, word-stream,
    // rk0..10, publish) — so deriveAuxGraph (which does NOT collapse) emits
    // 154 leaf nodes total. The graph ALSO carries the reserved `$input`
    // source node (A3a) — filter it so "one node per leaf" stays honest.
    const leafNodes = g.nodes.filter((n) => n.stepId !== INPUT_SOURCE_ID);
    expect(leafNodes.length).toBe(154);
  });

  it("emits one container per group (key-schedule + round.1 .. round.10)", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // 10 round groups + the decomposed `key-schedule` group (K1c) = 11.
    expect(g.containers.length).toBe(11);
    expect(g.containers.every((c) => c.kind === "group")).toBe(true);
    const ids = g.containers.map((c) => c.id).sort();
    expect(ids).toEqual(
      [
        "key-schedule",
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

  it("rootIds interleaves the top-level groups with each round group, in spec order", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Byte-native top-scope shape (K1c): [$input source, key-schedule (the
    // decomposed schedule group), initial.add-round-key, round.1, ...,
    // round.10].
    expect(g.rootIds[0]).toBe(INPUT_SOURCE_ID);
    expect(g.rootIds[1]).toBe("key-schedule");
    expect(g.rootIds[2]).toBe("initial.add-round-key");
    expect(g.rootIds.slice(3)).toEqual([
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

  it("fans out an edge from key-schedule.publish to every AddRoundKey consumer", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Byte-native (merged in F3): round keys are read internally by the
    // `xor-with-aux@1` AddRoundKey leaves (the recorded auxRead is what keeps
    // this fan-out edge). Since the key-schedule decomposition (K1c) the aux
    // writer is the `key-schedule.publish` tail leaf (the one surviving
    // meta-bearing step). 11 consumers: initial.add-round-key +
    // round.{1..10}.add-round-key.
    const expectedConsumers = new Set<string>([
      "initial.add-round-key",
      ...Array.from({ length: 10 }, (_, i) => `round.${i + 1}.add-round-key`),
    ]);
    // The publish leaf is aux-only (writes roundKey.N via meta), so all its
    // outgoing edges are the round-key fan-out.
    const keyExpEdges = g.edges.filter(
      (e) => e.kind === "aux" && e.from === "key-schedule.publish",
    );
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

// The "AES-128-ECB (multi-block iterate)" describe block tested the matrix
// aux-mode iterate graph (:b{i} collapse, split→iterate→concat aux-edge
// synthesis, blockSpan, replica dedup) against the matrix ECB fixture. It
// was retired in Phase 5 Slice 5.1 (2026-05-30) with the MatrixState shape +
// the split/concat/compute-block-count boundary steps — the shipped ECB spec
// runs the byte-native port-mode iterate now. The byte-native single-block /
// Speck / Serpent graph derivations below carry the surviving coverage.

// ─── Speck32/64 (flat, no containers, ARX) ────────────────────────────────

describe("deriveAuxGraph — Speck32/64 BE (key-schedule container + flat rounds)", () => {
  it("emits 130 decomposed-schedule leaves + 22 rounds + `$input` source + 1 schedule container", () => {
    // K2a (2026-06-01): the schedule decomposed from a monolithic leaf into
    // a `key-schedule` GROUP holding ~130 port-native primitive leaves
    // (load-key + input-codec + master-split + 21 iterations × 6 leaves +
    // publish = 130) for the BE-paper variant (LE-NSA adds output-codec
    // sub-pipeline, but this test stays on BE for round-key math sanity).
    // Plus 22 round leaves + the synthetic `$input` source.
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec);
    const cipherLeaves = g.nodes.filter((n) => n.stepId !== INPUT_SOURCE_ID);
    // 130 schedule leaves + 22 round leaves = 152.
    expect(cipherLeaves.length).toBe(152);
    expect(g.nodes.some((n) => n.stepId === INPUT_SOURCE_ID)).toBe(true);
    expect(g.nodes.length).toBe(153);
    // Now ONE container: the `key-schedule` group. Round leaves remain flat
    // (Speck has no per-round group; the round-body is a single port-native
    // step that doesn't decompose further in K2 scope).
    expect(g.containers.length).toBe(1);
    expect(g.containers[0]?.id).toBe("key-schedule");
  });

  it("fans out 22 round-key edges from key-schedule.publish to round.1..round.22", () => {
    // K2a: the round-key aux fan-out now originates from the schedule's
    // `publish` tail leaf, not the legacy monolithic `key-schedule` leaf.
    // (The collapsed view remaps these onto the container, per K1c's note;
    // the uncollapsed/raw view tested here keeps them on `key-schedule.publish`.)
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec);
    const ksEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-schedule.publish");
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
  it("emits 567 cipher leaves + the `$input` source and 33 containers (32 rounds + key-schedule)", () => {
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec);
    // K3a (2026-06-02): the single `key-expansion` leaf became the decomposed
    // `key-schedule` group — for Serpent-128 (16-byte key, padded) that is
    // 469 inner leaves (load-key + pad-const + pad + input-codec + master-split
    // + phi + 132×{round-const, xor, rotate} + 33×{concat, key-sbox} + publish).
    // Body unchanged: 1 IP + 31×3 + 3 + 1 FP = 98. So 469 + 98 = 567 cipher
    // leaves, plus the synthetic `$input` source pill → 568 nodes total.
    const cipherLeaves = g.nodes.filter((n) => n.stepId !== INPUT_SOURCE_ID);
    expect(cipherLeaves.length).toBe(567);
    expect(g.nodes.some((n) => n.stepId === INPUT_SOURCE_ID)).toBe(true);
    expect(g.nodes.length).toBe(568);
    // Containers: 32 round groups (round.1 .. round.32) + 1 `key-schedule`
    // group. IP and FP are leaves.
    expect(g.containers.length).toBe(33);
    expect(g.containers.some((c) => c.id === "key-schedule")).toBe(true);
    expect(g.containers.every((c) => c.kind === "group")).toBe(true);
  });

  it("fans out 33 round-key edges from the decomposed schedule's publish tail", () => {
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec);
    // K3a: the round-key fan-out moved from the monolithic `key-expansion`
    // leaf to the decomposed schedule's B-minimal publish tail
    // (`key-schedule.publish`). Each normal round has 1 AddRoundKey
    // (rounds 1..31 → 31 edges); the final round (32) has 2 AddRoundKey leaves
    // (.add-round-key + .add-final-round-key). Total fan-out: 31 + 2 = 33.
    const kEdges = g.edges.filter((e) => e.kind === "aux" && e.from === "key-schedule.publish");
    expect(kEdges.length).toBe(33);
    // Each edge carries a distinct roundKey.N.
    const auxKeys = new Set(kEdges.map((e) => e.auxKey));
    expect(auxKeys.size).toBe(33);
  });
});

// ─── Edge dedup paranoia (no actual case today; structural guard) ────────

describe("deriveAuxGraph — edge deduplication", () => {
  it("collapses identical (from, to, auxKey) triples to a single edge", () => {
    // Structural guard: deriveAuxGraph must never emit two edges with the
    // same (from, to, auxKey) triple. (The original 4-block matrix ECB
    // multi-replica case retired with the MatrixState shape in Slice 5.1;
    // single-block AES still exercises the dedup path across its fan-out.)
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const seen = new Set<string>();
    for (const e of g.edges) {
      const k = `${e.from}|${e.to}|${e.auxKey}`;
      expect(seen.has(k)).toBe(false);
      seen.add(k);
    }
  });
});

// The matrix-ECB "empty trace" describe (spec-derived spine without a trace,
// pinning matrix-ECB-specific node/container/state-edge counts) was retired
// in Phase 5 Slice 5.1 (2026-05-30) with the matrix ECB fixture. The
// trace-less spine-derivation behavior is covered by the state-edge-inference
// block below and by `graph-port-edge-derivation.test.ts`.

// ─── State-edge inference (round-to-round spine, commit 2) ────────────────

describe("deriveAuxGraph — state-edge inference (spec-derived spine)", () => {
  // Phase B/C: the two AES-128 single-block pure-spine tests ("produces 40
  // state edges, one per consecutive-leaf pair" and "spine crosses round-group
  // boundaries") were REMOVED for the byte-native rebuild. Byte-native AES has
  // dup state edges — a spec-derived spine ("state") PLUS port-flow companions
  // ("port-flow") from inferPortEdges — so the clean "one edge per consecutive
  // pair" count is dup-broken, and the matrix leaf order they asserted
  // (key-expansion → initial.add-round-key; round.N.shift-rows →
  // round.N.add-round-key) no longer holds for the byte-native body. Since
  // Slice 5.3b, Speck and Serpent are ALSO port-wired, so their spine tests
  // below pass the registry and assert the port-flow-owned spine directly
  // (the S2(f) gate suppresses the legacy state-thread): Speck as a flat 22-edge
  // chain, Serpent as a 98-edge mix of within-group leaf hops + container-sourced
  // round→round handoffs. Re-pin on AES if/when a port-flow spine assertion is
  // wanted there too. (`inferStateEdges` retired in Slice 5.3e — port-flow is
  // now the sole spine source for every shipped spec.)

  // The "AES-128-ECB: the iterate TERMINATES the parent spine on both sides"
  // test pinned the aux-mediated iterate boundary spine-suppression against
  // the matrix ECB fixture (the `compute-block-count → ecb-blocks` /
  // `ecb-blocks → concat-blocks` phantom edges). It was retired in Phase 5
  // Slice 5.1 (2026-05-30) with the matrix ECB fixture + the aux-mode iterate
  // boundary steps. The byte-native port-mode iterate carries its own
  // boundary semantics (covered by the runtime + graph-port-edge tests).

  it("Speck32/64 (flat): the spine is port-flow-owned (Slice 5.3b), the legacy state-thread suppressed", () => {
    // The round leaves declare `portInputs.state`, so `inferPortEdges` (S2(e))
    // owns the entire spine: `$input → round.1 → … → round.22`. Every state
    // edge is tagged `auxKey: "port-flow"`, with NO legacy state-thread edge.
    // (Pre-5.3e the legacy `inferStateEdges` would have layered phantom
    // edges on top; retired in 5.3e, so port-flow is the sole spine source.)
    //
    // K2a (2026-06-01): the decomposed schedule introduces ~70 additional
    // port-flow edges INSIDE the `key-schedule` group (load-key → input-codec
    // → master-split → 21 × {rot-l, sum, new-l, rol-k, new-k} chained, plus
    // each iteration's fan-in into publish). The round-spine claim is
    // unchanged; the count is no longer exactly 22.
    const g = deriveAuxGraph(runSpeck(), speck32_64BeSpec, {
      registry: buildDefaultRegistry(),
    });
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // Every state edge is a port-flow edge — none survive from the legacy
    // consecutive-siblings state-thread inference (which was retired in 5.3e).
    expect(stateEdges.every((e) => e.auxKey === "port-flow")).toBe(true);
    // The round-spine portion: 22 round-to-round (state via $input) edges
    // still resolve cleanly. Head of the spine is the true plaintext source,
    // NOT the aux-only schedule container.
    const roundSpineEdges = stateEdges.filter(
      (e) =>
        (e.from === INPUT_SOURCE_ID || /^round\.\d+$/.test(e.from)) && /^round\.\d+$/.test(e.to),
    );
    expect(roundSpineEdges.length).toBe(22);
    expect(stateEdges.find((e) => e.from === INPUT_SOURCE_ID && e.to === "round.1")).toBeDefined();
    expect(stateEdges.find((e) => e.from === "key-schedule" && e.to === "round.1")).toBeUndefined();
    expect(stateEdges.find((e) => e.from === "round.1" && e.to === "round.2")).toBeDefined();
    expect(stateEdges.find((e) => e.from === "round.21" && e.to === "round.22")).toBeDefined();
  });

  it("Serpent-128 (32 round groups): the spine is port-flow-owned (Slice 5.3b), round handoffs resolve to producing leaves", () => {
    // Post-5.3b the body is port-wired (each leaf declares `portInputs.state`,
    // each round group declares `seedInput`/`bodyOutput`), so `inferPortEdges`
    // owns the spine. (Pre-5.3e the legacy `inferStateEdges` consecutive-
    // siblings inference ran alongside, suppressed for wired leaves by its
    // S2(f) gate; both retired in 5.3e — port-flow is the sole spine source.) The
    // body spine STRUCTURE: the within-group hops are leaf→leaf, while each
    // round→round handoff resolves through the group's `seedInput` AND through
    // the source round's `bodyOutput` (the "out"-port resolution) to the
    // producing LEAF (`round.{n-1}.linear-transform` → round.n's first leaf),
    // plus `round.32.add-final-round-key → FP`.
    //
    // K3a (2026-06-02): the decomposed `key-schedule` group adds many internal
    // port-flow edges (load → codec → split → 132 recurrence chains → 33 S-box
    // groups → publish), so the total `state`-edge count is no longer the body's
    // 98 — we assert the body-spine structure directly (zero container-sourced
    // edges + the named leaf→leaf hops) rather than an exact total, mirroring
    // the Speck K2a retarget above.
    const g = deriveAuxGraph(runSerpent128(), serpent128Spec, {
      registry: buildDefaultRegistry(),
    });
    const stateEdges = g.edges.filter((e) => e.kind === "state");
    // Every spine edge is port-flow — none survive from the legacy state-thread.
    expect(stateEdges.every((e) => e.auxKey === "port-flow")).toBe(true);
    // Endpoints resolve to a real node OR container (no dangling edge). Round
    // groups appear as edge SOURCES now, so the check spans nodes ∪ containers.
    const nodeIds = new Set(g.nodes.map((n) => n.stepId));
    const containerIds = new Set(g.containers.map((c) => c.id));
    const materialized = new Set([...nodeIds, ...containerIds]);
    for (const e of stateEdges) {
      expect(materialized.has(e.from)).toBe(true);
      expect(materialized.has(e.to)).toBe(true);
    }
    // ZERO container-sourced edges: every round→round handoff originates at the
    // producing LEAF now. A `port("round.{n-1}", "out")` seed reference resolves
    // THROUGH round.{n-1}'s `bodyOutput` (= its linear-transform leaf) to that
    // leaf, so the carry no longer leaves the round.{n-1} container boundary
    // (the fix for "expanded round containers draw an outgoing edge from the
    // box"). `final-permutation` likewise resolves to round.32's last leaf.
    const containerSourced = stateEdges.filter((e) => containerIds.has(e.from));
    expect(containerSourced.length).toBe(0);
    // Head of the spine is the plaintext source feeding the initial permutation.
    expect(
      stateEdges.find((e) => e.from === INPUT_SOURCE_ID && e.to === "initial-permutation"),
    ).toBeDefined();
    // A within-group hop (leaf→leaf) and a between-group hop (producing leaf →
    // next round's first leaf, resolved through round 1's `bodyOutput`).
    expect(
      stateEdges.find((e) => e.from === "round.1.add-round-key" && e.to === "round.1.sub-bytes"),
    ).toBeDefined();
    expect(
      stateEdges.find(
        (e) => e.from === "round.1.linear-transform" && e.to === "round.2.add-round-key",
      ),
    ).toBeDefined();
    expect(
      stateEdges.find(
        (e) => e.from === "round.32.add-final-round-key" && e.to === "final-permutation",
      ),
    ).toBeDefined();
  });

  // The two "empty group participates in the spine via its own id" tests
  // (a cleared round + a nested empty group) were removed in Slice 5.3e
  // Batch 3 with `inferStateEdges`. That consecutive-siblings inference was
  // the only thing that pushed an empty group's own id onto the spine; the
  // port-flow spine (`inferPortEdges`) has no analogue, so a round whose body
  // the user clears in the editor disconnects from the chain. This is the
  // user-accepted editor-only regression recorded in
  // `docs/plans/phase-5-legacy-retirement.md` (Slice 5.3e risk note).

  it("never duplicates aux+state on the same (from, to, auxKey) triple", () => {
    // State edges' "state" sentinel auxKey can't collide with real aux
    // keys (those come from step `auxWrites`, all of which are domain-
    // specific). This pins the no-collision invariant explicitly so a
    // future aux-write of literal "state" doesn't silently merge with
    // the spine in collapseGraph's dedup.
    const g = deriveAuxGraph(runAes128(), aes128Spec);
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
    // Byte-native round.5 has 4 leaves (sub-bytes, shift-rows, mix-columns,
    // add-round-key — merged in F3); they vanish from the node list. Pre: 155
    // (154 leaves incl. the decomposed key-schedule's sub-steps + $input
    // source), post: 155 - 4 = 151. (This case collapses only round.5; the
    // key-schedule group is left expanded here.)
    expect(out.nodes.length).toBe(151);
    // The container itself stays — renderer draws it as a collapsed chip.
    expect(out.containers.find((c) => c.id === "round.5")).toBeDefined();
    // But its childIds is now empty so the layout walk treats it as leaf-sized.
    expect(out.containers.find((c) => c.id === "round.5")?.childIds.length).toBe(0);
  });

  it("re-routes round-key edges that entered a collapsed container to terminate at it", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    // Before collapse: 11 fan-out aux edges from key-schedule.publish (the
    // decomposed schedule's meta-bearing tail, K1c) — initial +
    // round.1..10's add-round-key consumers. The publish leaf is aux-only.
    const before = g.edges.filter(
      (e) => e.kind === "aux" && e.from === "key-schedule.publish",
    ).length;
    expect(before).toBe(11);

    const out = collapseGraph(g, new Set(["round.3"]));
    // After collapse: round.3.add-round-key (the byte-native roundKey.3
    // consumer since F3) is hidden, but the edge key-schedule.publish →
    // round.3.add-round-key remaps to key-schedule.publish → round.3. No edge
    // count change for this fan-out (the remap doesn't collide with anything).
    const after = out.edges.filter(
      (e) => e.kind === "aux" && e.from === "key-schedule.publish",
    ).length;
    expect(after).toBe(11);
    // The specific re-routed edge exists.
    expect(
      out.edges.some(
        (e) => e.from === "key-schedule.publish" && e.to === "round.3" && e.auxKey === "roundKey.3",
      ),
    ).toBe(true);
    // And the pre-collapse target (the hidden add-round-key leaf) is gone.
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
    // Two byte-native rounds × 4 leaves (merged in F3) = 8 fewer nodes.
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
    // The port-flow spine routes round→round from the producing LEAF (round
    // n's `bodyOutput`, resolved through the "out" port): the pre-collapse
    // entry edge is `round.4.add-round-key → round.5.sub-bytes`, so after
    // collapsing round.5 the entry edge is `round.4.add-round-key → round.5`
    // (producing leaf → collapsed chip).
    expect(afterState.some((e) => e.from === "round.4.add-round-key" && e.to === "round.5")).toBe(
      true,
    );
    expect(afterState.some((e) => e.from === "round.5" && e.to === "round.6.sub-bytes")).toBe(true);
  });

  it("re-routes state edges crossing a collapsed container's boundary to terminate at it", () => {
    const g = deriveAuxGraph(runAes128(), aes128Spec);
    const out = collapseGraph(g, new Set(["round.5"]));
    const stateEdges = out.edges.filter((e) => e.kind === "state");
    // The port-flow round→round handoff originates at the producing leaf: the
    // pre-collapse ENTRY edge is `round.4.add-round-key → round.5.sub-bytes`
    // (round.4's `bodyOutput` leaf → round.5's first leaf). Collapsing round.5
    // remaps the consumer leaf to the chip → `round.4.add-round-key → round.5`.
    const entering = stateEdges.find(
      (e) => e.from === "round.4.add-round-key" && e.to === "round.5",
    );
    expect(entering).toBeDefined();
    // The EXIT edge `round.5.add-round-key → round.6.sub-bytes` has its
    // producing leaf hidden by the collapse → remaps to `round.5 →
    // round.6.sub-bytes` (collapsed chip → next round's first leaf).
    const leaving = stateEdges.find((e) => e.from === "round.5" && e.to === "round.6.sub-bytes");
    expect(leaving).toBeDefined();
    // The pre-collapse entry edge's internal endpoint (round.5.sub-bytes) is
    // gone — it remapped to the chip.
    expect(stateEdges.some((e) => e.from === "round.4" && e.to === "round.5.sub-bytes")).toBe(
      false,
    );
    // No surviving state edge is produced by a hidden round.5-internal leaf.
    expect(stateEdges.some((e) => e.from.startsWith("round.5."))).toBe(false);
  });

  // The two "collapses an iterate container" tests (state-spine remap to
  // self-loops; node/container hiding) ran against the matrix ECB fixture's
  // aux-mode `ecb-blocks` iterate. They were retired in Phase 5 Slice 5.1
  // (2026-05-30) with the matrix ECB fixture. `collapseGraph`'s container
  // collapse is still covered by the AES-128 single-block group-collapse
  // tests above and the synthetic-container collapse in the endpoint-pills
  // block below.
});

// ─── Slice 1 of graph-narrative plan — synthetic endpoint pills ──────────

describe("deriveAuxGraph — synthetic endpoint pills (Slice 1)", () => {
  // The pills are opt-in via `opts.endpoints`. Every test in the suites
  // above continues to call `deriveAuxGraph(trace, spec)` with no opts and
  // sees the same shape it always did — these tests opt in and check the
  // injected pieces.

  // Phase 5 Slice 5.1 (2026-05-30): retargeted from the matrix AES-192/ECB
  // fixtures (retired with the MatrixState shape) to a synthetic
  // lifted-legacy spec. The pill-placement semantics need a spec WITHOUT a
  // `$input` port-flow source node (byte-native AES injects one at rootIds[0],
  // colliding with the pill — a deferred feature question per Slice 2.9c-e).
  // This `pillSpec` wires nothing to `$input`, so no source node is injected:
  // a leading aux-only root (`load-iv`, mirrors AES key-expansion), a real
  // state consumer (`transform`, the input anchor), and a trailing group
  // (`final-group`, the output anchor — collapsible like the old iterate).
  const pillSpec: CipherSpec = {
    id: "pill-spec@1",
    name: "Endpoint pill fixture (no $input source)",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      {
        kind: "step",
        id: "load-iv",
        type: "generic.aux-load@1",
        params: { auxName: "iv", value: [] },
      },
      { kind: "step", id: "transform", type: "feistel.toy-add-k@1", params: { k: 1 } },
      {
        kind: "group",
        id: "final-group",
        label: "Final",
        children: [
          { kind: "step", id: "final-group.x", type: "feistel.toy-add-k@1", params: { k: 2 } },
        ],
      },
    ],
  };
  const ENCRYPT_OPTS = {
    endpoints: {
      inputLabel: "plaintext",
      outputLabel: "ciphertext",
      // The renderer skips aux-only leaves (load-iv). The unit tests pass
      // the desired anchor directly — they don't have the registry handy
      // and the fallback to rootIds[0] would point at load-iv, which is
      // what Option B is designed to avoid.
      inputAnchorId: "transform",
      outputAnchorId: "final-group",
    },
  };

  it("injects two endpoint nodes when opts.endpoints is provided", () => {
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);

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
    const g = deriveAuxGraph(emptyTrace(), pillSpec);
    expect(g.nodes.some((n) => isEndpointId(n.stepId))).toBe(false);
    expect(g.edges.some((e) => isEndpointId(e.from) || isEndpointId(e.to))).toBe(false);
  });

  it("prepends + appends pills to rootIds (canvas-extreme placement hook)", () => {
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);
    expect(g.rootIds[0]).toBe(CIPHER_INPUT_ID);
    expect(g.rootIds[g.rootIds.length - 1]).toBe(CIPHER_OUTPUT_ID);
  });

  it("emits two state-kind edges connecting the pills to the anchors", () => {
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);

    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    const outputEdge = g.edges.find((e) => e.to === CIPHER_OUTPUT_ID);
    expect(inputEdge).toBeDefined();
    expect(outputEdge).toBeDefined();
    expect(inputEdge?.kind).toBe("state");
    expect(outputEdge?.kind).toBe("state");
    expect(inputEdge?.to).toBe("transform");
    expect(outputEdge?.from).toBe("final-group");
  });

  it("falls back to rootIds[0] / rootIds[last] when anchors are omitted", () => {
    const g = deriveAuxGraph(emptyTrace(), pillSpec, {
      endpoints: { inputLabel: "plaintext", outputLabel: "ciphertext" },
    });

    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    const outputEdge = g.edges.find((e) => e.to === CIPHER_OUTPUT_ID);
    // Without anchor overrides, the function points at the spec's literal
    // top-level extremes: the leading aux-only `load-iv` at the input side
    // and the final group at the output side. The renderer's job is to pass
    // smarter anchors that skip aux-only leaves.
    expect(inputEdge?.to).toBe("load-iv");
    expect(outputEdge?.from).toBe("final-group");
  });

  it("swaps labels on decrypt-style invocation", () => {
    // Decrypt mode: the caller's labels themselves swap. The function
    // doesn't introspect direction; it just renders what it's given.
    const g = deriveAuxGraph(emptyTrace(), pillSpec, {
      endpoints: {
        inputLabel: "ciphertext",
        outputLabel: "plaintext",
        inputAnchorId: "transform",
        outputAnchorId: "final-group",
      },
    });
    expect(g.nodes.find((n) => n.stepId === CIPHER_INPUT_ID)?.label).toBe("ciphertext");
    expect(g.nodes.find((n) => n.stepId === CIPHER_OUTPUT_ID)?.label).toBe("plaintext");
  });

  it("renderer's anchor heuristic skips aux-only leaves (regression pin)", () => {
    // The renderer (GraphView.tsx) walks rootIds forward to find the
    // first leaf whose shapeContract.input is NOT "any", skipping the
    // aux-only `load-iv`. This test validates the *intent* by exercising the
    // helper directly with the value the renderer would pass — pinning
    // that the function honors a non-rootIds[0] anchor when supplied.
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);
    const inputEdge = g.edges.find((e) => e.from === CIPHER_INPUT_ID);
    // transform, NOT load-iv (which is the literal aux-only rootIds[0]).
    expect(inputEdge?.to).toBe("transform");
    // Visually: the plaintext-pill arrow lands at the leaf that actually
    // reads state, not at the aux-only preamble.
  });

  it("endpoint edges are never classified as feedback", () => {
    // Defense in depth: buildIterateFeedbackPredicate's early-return for
    // endpoint ids means the renderer never dashes the spine edges into
    // the pills. State edges are already excluded from feedback by kind,
    // so this is belt-and-suspenders against a future re-classification.
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);
    const isFeedback = buildIterateFeedbackPredicate(g);
    for (const e of g.edges) {
      if (isEndpointId(e.from) || isEndpointId(e.to)) {
        expect(isFeedback(e)).toBe(false);
      }
    }
  });

  it("collapsing a container still leaves the pills visible", () => {
    // The pedagogical payoff of Slice 1: even when the user collapses
    // away a container, "plaintext enters here" is still self-evident.
    const g = deriveAuxGraph(emptyTrace(), pillSpec, ENCRYPT_OPTS);
    const collapsed = collapseGraph(g, new Set(["final-group"]));
    // Both pills survive the collapse.
    expect(collapsed.nodes.some((n) => n.stepId === CIPHER_INPUT_ID)).toBe(true);
    expect(collapsed.nodes.some((n) => n.stepId === CIPHER_OUTPUT_ID)).toBe(true);
    // Both endpoint edges survive too (the input anchor is outside the
    // collapsed container; the output anchor IS the container, which stays
    // as a collapsed chip).
    expect(collapsed.edges.some((e) => e.from === CIPHER_INPUT_ID)).toBe(true);
    expect(collapsed.edges.some((e) => e.to === CIPHER_OUTPUT_ID)).toBe(true);
  });

  it("suppresses pill injection when the spec is empty", () => {
    // No rootIds → no anchors possible → no pills. Cheaper than
    // rendering a floating "plaintext" arrow into nothing.
    const emptySpec = { ...pillSpec, steps: [] };
    const g = deriveAuxGraph(emptyTrace(), emptySpec, ENCRYPT_OPTS);
    expect(g.nodes.some((n) => isEndpointId(n.stepId))).toBe(false);
    expect(g.edges.some((e) => isEndpointId(e.from) || isEndpointId(e.to))).toBe(false);
  });
});
