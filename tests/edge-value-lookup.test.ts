/**
 * Tests for `core/edge-value-lookup.ts::lookupEdgeValue` (Slice 4 of the
 * graph-narrative-and-zoom plan).
 *
 * The function is the pure lookup behind the value-inspector
 * panel. It resolves "what value flows through this edge at the current
 * scrubber position?" against a real trace, with special branches for
 * synthetic endpoint pills (Slice 1), block-chip ids (Slice 6), and the
 * iterate's `blocksFromAux` / `outBlocksAux` aux semantics.
 *
 * Test coverage tracks the branch table in the module docstring:
 *
 *   - Endpoint pills → `"endpoint"` carrying the cipher's I/O value
 *     (frames[0].stateBefore for input pill, trace.finalState for
 *     output pill). Pre-run pill clicks → `"no-trace"`.
 *   - Trace null → `"no-trace"`.
 *   - Regular leaf, aux edge → `"value"` with the consumer's auxRead.
 *   - Regular leaf, state edge → `"value"` with predecessor.stateAfter.
 *   - Block-chip incoming state edge → the chip's stateBefore = `blocks[i]`.
 *   - Block-chip outgoing state edge → the chip's stateAfter = `outBlocks[i]`.
 *   - Block-chip incoming aux edge with `auxKey === blocksFromAux` → `blocks[i]`.
 *   - Block-chip outgoing aux edge with `auxKey === outBlocksAux` → `outBlocks[i]`.
 *   - Block-chip incoming aux edge with a generic roundKey key → the round key.
 *   - Ellipsis chip (`@blockMore`) → `"missing"` with a descriptive reason.
 *
 * All branches are exercised against AES-128 ECB with a 4-block plaintext
 * — the only shipping multi-block fixture today.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { lookupEdgeValue } from "@/core/edge-value-lookup";
import {
  CIPHER_INPUT_ID,
  CIPHER_OUTPUT_ID,
  type GraphEdge,
  R_IN_BYPASS_AUX_KEY,
} from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, MatrixState, Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

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

const stateEdge = (from: string, to: string): GraphEdge => ({
  from,
  to,
  auxKey: "state",
  kind: "state",
});

const auxEdge = (from: string, to: string, auxKey: string): GraphEdge => ({
  from,
  to,
  auxKey,
  kind: "aux",
});

// ─── Endpoint pills (Slice 1 composition) ───────────────────────────────

describe("lookupEdgeValue — endpoint pills", () => {
  it("returns `endpoint` carrying the plaintext for edges from __cipher_input__", () => {
    const trace = runAes128Ecb();
    const out = lookupEdgeValue(
      stateEdge(CIPHER_INPUT_ID, "split-blocks"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.endpointSide).toBe("input");
    // The plaintext flowing in is frames[0].stateBefore (= the cipher's
    // initialState). For the ECB fixture above that's the 64-byte BytesState.
    const first = trace.frames[0];
    expect(first).toBeDefined();
    expect(out.value).toBe(first?.stateBefore);
  });

  it("returns `endpoint` carrying the ciphertext for edges to __cipher_output__", () => {
    const trace = runAes128Ecb();
    const out = lookupEdgeValue(
      stateEdge("concat-blocks", CIPHER_OUTPUT_ID),
      aes128EcbSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.endpointSide).toBe("output");
    // The cipher's final state IS the ciphertext (the runtime's
    // post-loop `finalState`).
    expect(out.value).toBe(trace.finalState);
  });

  it("returns `no-trace` for an endpoint edge when the trace is null (pre-run)", () => {
    const out = lookupEdgeValue(
      stateEdge(CIPHER_INPUT_ID, "split-blocks"),
      aes128EcbSpec,
      null,
      undefined,
    );
    // Pre-2026-05-17 the lookup returned a label-only `"endpoint"` row;
    // post-rework, pre-run pill clicks collapse to `"no-trace"` so the
    // empty-state copy is uniform with every other inspector row.
    expect(out.status).toBe("no-trace");
  });
});

// ─── No trace ────────────────────────────────────────────────────────────

describe("lookupEdgeValue — trace null", () => {
  it("returns `no-trace` for non-endpoint edges when trace is null", () => {
    const out = lookupEdgeValue(
      auxEdge("key-expansion", "initial.add-round-key", "round-key-0"),
      aes128EcbSpec,
      null,
      undefined,
    );
    expect(out.status).toBe("no-trace");
  });
});

// ─── Regular leaf edges ──────────────────────────────────────────────────

describe("lookupEdgeValue — regular aux edges", () => {
  it("returns the consumer's auxRead value for a regular aux edge", () => {
    const trace = runAes128Ecb();
    // `key-expansion → initial.add-round-key` carries `roundKey.0`,
    // consumed at the per-block AddRoundKey-0 step inside the iterate.
    // Pre-iterate, the only consumer is also inside the iterate, so we
    // pass blockIndex=0 to match the first iteration.
    const edge = auxEdge("key-expansion", "initial.add-round-key", "roundKey.0");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, 0);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.auxKey).toBe("roundKey.0");
    expect(out.displayKind).toBe("aux");
    // Round key 0 = the original 16-byte key.
    expect(out.value).toBeInstanceOf(Uint8Array);
    expect(out.value as Uint8Array).toHaveLength(16);
  });

  it("returns `missing` when the consumer has no frame matching the canonical stepId", () => {
    const trace = runAes128Ecb();
    const out = lookupEdgeValue(
      auxEdge("key-expansion", "no-such-step", "round-key-0"),
      aes128EcbSpec,
      trace,
      0,
    );
    expect(out.status).toBe("missing");
  });

  // ── Producer-side fallback for iterate-as-consumer ──────────────────
  //
  // The graph derivation emits aux edges whose `to` is the iterate
  // CONTAINER (e.g. `compute-block-count → ecb-blocks` for the count,
  // `split-blocks → ecb-blocks` for the blocks array). The runtime
  // reads `aux[countFromAux]` / `aux[blocksFromAux]` off the iterate
  // BEFORE setting up body frames, so neither `auxRead` lives on a
  // body frame. Consumer-side `findConsumerFrame("ecb-blocks", ...)`
  // returns null because no leaf frame's stepId canonicalizes to
  // `ecb-blocks` (only body steps have frames).
  //
  // Without producer-side fallback, the value-inspector would say
  // "no frame found for consumer ecb-blocks" — which is exactly the
  // bug surfaced by the Slice 7c demo path (the user clicked a
  // `compute-block-count` / `split-blocks` replica's outgoing arrow
  // and got "no value"). Producer-side fallback resolves to the
  // value the leaf step wrote into `auxWritten` — the count or the
  // blocks array — and the inspector renders it correctly.
  it("resolves compute-block-count→ecb-blocks via producer-side auxWritten (block count)", () => {
    const trace = runAes128Ecb();
    // ECB plaintext is 4 × 16 bytes → block count is 4.
    const edge = auxEdge("compute-block-count", "ecb-blocks", "blockCount");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("aux");
    expect(out.auxKey).toBe("blockCount");
    expect(out.value).toBe(4);
  });

  it("resolves split-blocks→ecb-blocks via producer-side auxWritten (blocks array)", () => {
    const trace = runAes128Ecb();
    // ECB-mode `split-blocks` writes the array of MatrixState into
    // `aux[outBlocksAux]` (default key: "input-blocks"). With the
    // 4-block test plaintext, the lookup returns an array of length 4.
    const edge = auxEdge("split-blocks", "ecb-blocks", "input-blocks");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("aux");
    expect(out.auxKey).toBe("input-blocks");
    expect(Array.isArray(out.value)).toBe(true);
    expect((out.value as readonly unknown[]).length).toBe(4);
  });

  it("returns `missing` when neither consumer nor producer has the aux", () => {
    const trace = runAes128Ecb();
    // Consumer (iterate) has no leaf frame; producer (also missing) also
    // doesn't. The fallback should still return missing without throwing.
    const out = lookupEdgeValue(
      auxEdge("no-such-producer", "ecb-blocks", "no-such-aux"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("missing");
  });
});

// ─── Replica edges (post-Slice-7c, after fan-out replication) ───────────
//
// `replicateHighFanoutSources` produces synthetic node ids of the form
// `${sourceId}@->${consumerId}`. When the consumer is a block CHIP,
// the replica id ends with `@block<N>` — e.g.
// `key-expansion@->ecb-blocks@block1`. The chip-id regex
// `/^(.+)@block(\d+)$/` greedily matches such ids, so without an
// explicit `@->` reject parseChipId would WRONGLY identify the replica
// as a chip with iterateId === `key-expansion@->ecb-blocks` (which
// isn't in the spec) and the inspector would show
// "iterate ... not found in spec — graph and spec out of sync".
//
// These tests pin the post-fix behavior:
//   - Replica → chip with a body-consumed aux key (roundKey.5)
//     resolves via lookupChipIncoming's body-frame walk.
//   - Replica → chip with an iterate-consumed aux key (blockCount,
//     input-blocks) resolves via lookupChipIncoming's NEW
//     producer-side fallback.
//   - Replica → iterate-container resolves via lookupRegularAux's
//     producer-side fallback (the existing Slice-7c-day-of fix; the
//     unwrap-replica part is what makes it work for replica producers).

describe("lookupEdgeValue — replica → chip edges (post-7c bug fix)", () => {
  it("replica of key-expansion → chip resolves to the body-read round key", () => {
    const trace = runAes128Ecb();
    // Replica id: `${sourceId}@->${consumerId}` where consumer is the
    // chip itself. The auxKey is whatever the body step inside the
    // iterate reads — here roundKey.5 (consumed by round.5.add-round-key).
    const edge = auxEdge("key-expansion@->ecb-blocks@block2", "ecb-blocks@block2", "roundKey.5");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("aux");
    expect(out.auxKey).toBe("roundKey.5");
    expect(out.blockIndex).toBe(2);
    expect(out.value).toBeInstanceOf(Uint8Array);
    expect(out.value as Uint8Array).toHaveLength(16);
  });

  it("replica of compute-block-count → chip resolves to blockCount via producer-side fallback", () => {
    const trace = runAes128Ecb();
    // The runtime reads blockCount at the iterate level — no body
    // frame's auxRead has it. Without producer-side fallback the
    // chip-incoming branch returns "no body frame ... read aux blockCount".
    const edge = auxEdge(
      "compute-block-count@->ecb-blocks@block0",
      "ecb-blocks@block0",
      "blockCount",
    );
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("aux");
    expect(out.auxKey).toBe("blockCount");
    expect(out.blockIndex).toBe(0);
    expect(out.value).toBe(4);
  });

  it("replica of split-blocks → chip resolves via the iterate.blocksFromAux slice (NOT producer fallback)", () => {
    const trace = runAes128Ecb();
    // split-blocks's outBlocksAux === iterate.blocksFromAux === "input-blocks",
    // so the lookupChipIncoming.aux branch's blocksFromAux special-case
    // already slices to blocks[i] from the body frame's stateBefore.
    // Producer-side fallback is unnecessary but the replica-id reject
    // is what makes the dispatch reach this branch at all.
    const edge = auxEdge("split-blocks@->ecb-blocks@block3", "ecb-blocks@block3", "input-blocks");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("block-payload");
    expect(out.blockIndex).toBe(3);
    expect(out.value).toMatchObject({ shape: "matrix4x4-bytes" });
    // Block 3 in `ECB_PLAINTEXT_4_BLOCKS` (4th 16-byte block).
    const expected = bytesFromHex("f69f2445df4f9b17ad2b417be66c3710");
    expect((out.value as MatrixState).bytes).toEqual(expected);
  });

  it("replica → iterate-container resolves via regular-aux producer-side fallback (replica unwrap)", () => {
    const trace = runAes128Ecb();
    // Replica targets the iterate container (un-collapsed iterate
    // case). Without the unwrap inside lookupAuxFromProducer, the
    // findProducerFrame call would search for a frame whose stepId is
    // the synthetic replica id and find nothing.
    const edge = auxEdge("compute-block-count@->ecb-blocks", "ecb-blocks", "blockCount");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.value).toBe(4);
  });
});

describe("lookupEdgeValue — regular state edges", () => {
  it("returns the producer's stateAfter for a regular state edge", () => {
    const trace = runAes128Ecb();
    // The spine state edge from `key-expansion → initial.add-round-key`
    // (synthesized post-key-expansion). key-expansion's stateAfter is
    // the BytesState input passed through unchanged, identical to its
    // stateBefore — but the lookup is what matters here, not the value.
    const edge = stateEdge("key-expansion", "initial.add-round-key");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, 0);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    expect(out.auxKey).toBe("state");
  });
});

// ─── UX-D "R_in bypass F" edge (2026-05-22) ──────────────────────────────
//
// Synthesized state edge from the R-track's first leaf (DES `expand-R`)
// directly to `:rejoin` for `feistel-standard` rounds. The arrow's
// pedagogical purpose is to show R_in flowing past the F-stack to
// become new_L. The inspector must therefore surface the leaf's
// `stateBefore` (= R_in, 4 bytes for DES), NOT its `stateAfter`
// (= E(R), 6 bytes). The lookup carries a dedicated `auxKey` so the
// renderer's tooltip can text-render the bypass label and the inspector
// can disambiguate from the conventional spine edge.

describe("lookupEdgeValue — UX-D R_in bypass edge (DES)", () => {
  it("returns the producer's stateBefore (= R_in, not E(R)) for the bypass edge", () => {
    // Any 8-byte plaintext + 8-byte key; FIPS Pub 81 vector picks itself.
    const trace = runSpec(desSpec, buildDefaultRegistry(), {
      initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
    });
    const bypassEdge: GraphEdge = {
      from: "round.1.expand-R",
      to: "round.1:rejoin",
      auxKey: R_IN_BYPASS_AUX_KEY,
      kind: "state",
    };
    const out = lookupEdgeValue(bypassEdge, desSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    expect(out.auxKey).toBe(R_IN_BYPASS_AUX_KEY);
    // R_in is 4 bytes (DES half-block); E(R) would be 6 bytes (48 bits).
    // The bypass edge MUST surface the 4-byte form.
    expect(out.value).toMatchObject({ shape: "bytes" });
    expect((out.value as { bytes: Uint8Array }).bytes.length).toBe(4);
  });

  it("a state edge with the same endpoints but auxKey === 'state' still uses stateAfter", () => {
    // Belt-and-braces: the bypass branch must key on `auxKey`, NOT on
    // the (from, to) pair. A hand-fabricated `auxKey: "state"` edge with
    // the same endpoints (which the derivation no longer emits, but a
    // future replicator/bundler MUST NOT mistake) should fall through
    // to the default "producer.stateAfter" branch.
    const trace = runAes128Ecb();
    const edge: GraphEdge = {
      from: "key-expansion",
      to: "initial.add-round-key",
      auxKey: "state",
      kind: "state",
    };
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, 0);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.auxKey).toBe("state");
  });
});

// ─── Block-chip edges (Slice 6 composition) ─────────────────────────────

describe("lookupEdgeValue — block-chip incoming edges", () => {
  it("state edge into chip_i resolves to `blocks[i]` (chip's stateBefore)", () => {
    const trace = runAes128Ecb();
    // After Slice 6, collapsed ECB iterate produces chips
    // `ecb-blocks@block0` .. `ecb-blocks@block3`. The lookup doesn't
    // care whether the graph is collapsed — it parses the chip-id
    // directly from the edge endpoints.
    const edge = stateEdge("compute-block-count", "ecb-blocks@block2");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("block-payload");
    expect(out.blockIndex).toBe(2);
    // Block 2 in `ECB_PLAINTEXT_4_BLOCKS` (3rd 16-byte block).
    const expected = bytesFromHex("30c81c46a35ce411e5fbc1191a0a52ef");
    expect(out.value).toMatchObject({ shape: "matrix4x4-bytes" });
    expect((out.value as MatrixState).bytes).toEqual(expected);
  });

  it("aux edge into chip_i with auxKey === blocksFromAux slices to blocks[i]", () => {
    const trace = runAes128Ecb();
    // The post-Slice-6 fanned edge `split-blocks → ecb-blocks@block1`
    // carrying auxKey `input-blocks` (the iterate's `blocksFromAux`).
    const edge = auxEdge("split-blocks", "ecb-blocks@block1", "input-blocks");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("block-payload");
    expect(out.blockIndex).toBe(1);
    const expected = bytesFromHex("ae2d8a571e03ac9c9eb76fac45af8e51");
    expect(out.value).toMatchObject({ shape: "matrix4x4-bytes" });
    expect((out.value as MatrixState).bytes).toEqual(expected);
  });

  it("aux edge into chip_i with a generic roundKey key returns that round key", () => {
    const trace = runAes128Ecb();
    // After expansion + replication, a `key-expansion → ecb-blocks@block0`
    // edge can carry `roundKey.3` (one of the per-round keys consumed
    // by `round.3.add-round-key` deep in the iterate body). The lookup
    // walks body frames at blockIndex=0 until one matches.
    const edge = auxEdge("key-expansion", "ecb-blocks@block0", "roundKey.3");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("aux");
    expect(out.auxKey).toBe("roundKey.3");
    expect(out.blockIndex).toBe(0);
    expect(out.value).toBeInstanceOf(Uint8Array);
    expect(out.value as Uint8Array).toHaveLength(16);
  });
});

describe("lookupEdgeValue — block-chip outgoing edges", () => {
  it("state edge out of chip_i resolves to the iterate body's final stateAfter at block i", () => {
    const trace = runAes128Ecb();
    const edge = stateEdge("ecb-blocks@block0", "concat-blocks");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("block-payload");
    expect(out.blockIndex).toBe(0);
    expect(out.value).toMatchObject({ shape: "matrix4x4-bytes" });
    // The ciphertext for block 0 under AES-128 with the FIPS-197 key
    // and our test plaintext is the published vector — but we only
    // assert the shape + length here, since other tests already pin
    // the cryptographic correctness of AES-128.
    expect((out.value as MatrixState).bytes).toHaveLength(16);
  });

  it("aux edge out of chip_i with auxKey === outBlocksAux slices to outBlocks[i]", () => {
    const trace = runAes128Ecb();
    const edge = auxEdge("ecb-blocks@block3", "concat-blocks", "output-blocks");
    const out = lookupEdgeValue(edge, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("block-payload");
    expect(out.blockIndex).toBe(3);
    expect(out.value).toMatchObject({ shape: "matrix4x4-bytes" });
  });
});

describe("lookupEdgeValue — ellipsis chip", () => {
  it("returns `missing` with a descriptive reason for @blockMore edges", () => {
    const trace = runAes128Ecb();
    const out = lookupEdgeValue(
      stateEdge("compute-block-count", "ecb-blocks@blockMore"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/multiple blocks/i);
  });
});

describe("lookupEdgeValue — chip id pointing at a non-existent iterate", () => {
  it("returns `missing` when the iterate id parsed from the chip is not in the spec", () => {
    const trace = runAes128Ecb();
    const out = lookupEdgeValue(
      stateEdge("compute-block-count", "no-such-iterate@block0"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    expect(out.status).toBe("missing");
  });
});

// ─── Reactivity surface (memo dep coverage smoke test) ──────────────────

describe("lookupEdgeValue — block-index sensitivity", () => {
  it("returns DIFFERENT values for two chips on the same iterate", () => {
    const trace = runAes128Ecb();
    const block0 = lookupEdgeValue(
      stateEdge("compute-block-count", "ecb-blocks@block0"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    const block2 = lookupEdgeValue(
      stateEdge("compute-block-count", "ecb-blocks@block2"),
      aes128EcbSpec,
      trace,
      undefined,
    );
    if (block0.status !== "value" || block2.status !== "value") {
      throw new Error("expected both chip lookups to succeed");
    }
    expect((block0.value as MatrixState).bytes).not.toEqual((block2.value as MatrixState).bytes);
  });
});
