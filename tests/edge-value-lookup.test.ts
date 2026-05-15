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
 *   - Endpoint pills → `"endpoint"` with the literal label.
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
import { lookupEdgeValue } from "@/core/edge-value-lookup";
import { CIPHER_INPUT_ID, CIPHER_OUTPUT_ID, type GraphEdge } from "@/core/graph";
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
  it("returns `endpoint` with the input label for edges from __cipher_input__", () => {
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
    expect(out.label).toMatch(/plaintext/i);
  });

  it("returns `endpoint` with the output label for edges to __cipher_output__", () => {
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
    expect(out.label).toMatch(/ciphertext/i);
  });

  it("returns endpoint even when the trace is null (no Run needed for pills)", () => {
    const out = lookupEdgeValue(
      stateEdge(CIPHER_INPUT_ID, "split-blocks"),
      aes128EcbSpec,
      null,
      undefined,
    );
    expect(out.status).toBe("endpoint");
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
