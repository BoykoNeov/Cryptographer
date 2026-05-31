/**
 * `Trace.initialState` + input-pill resolution (Phase 5 Slice 5.3c).
 *
 * 5.3c moved the value-inspector's input pill / input-end edge OFF the old
 * `frames[0].stateBefore` read onto the new `trace.initialState` field — the
 * symmetric counterpart of `trace.finalState`. The motivating reason: 5.3e
 * deletes `stateBefore`/`stateAfter`, and `frames[0]`'s `"state"` INPUT port
 * is not always the plaintext (SHA-256's first frame is a constant-load with
 * no state input port), so the port-first helper can't answer the endpoint
 * either. `trace.initialState` is the field-independent honest source.
 *
 * This file pins, for two representative shipped ciphers spanning the two
 * extremes:
 *   - SHA-256 — pure port-native; the first frame has NO `"state"` input
 *     port (the case the migration exists for).
 *   - AES-128 ECB — hybrid-ported, multi-block; `initialState` is the full
 *     multi-block plaintext.
 *
 * What's pinned:
 *   1. `runSpec` populates `trace.initialState` byte-equal to the input
 *      `initialState` it was handed.
 *   2. `trace.initialState` is byte-equal to `frames[0].stateBefore` — the
 *      migration is provably value-preserving. (This assertion references the
 *      legacy field and is dropped in 5.3e along with the field; assertion 1
 *      keeps correctness covered.)
 *   3. The input pill resolves to `trace.initialState` through BOTH node
 *      selectors (`CIPHER_INPUT_ID` and the port-native `$input` source) and
 *      the input-end edge — reference-equal, so the renderer formats the same
 *      value as the seed.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { CIPHER_INPUT_ID, type GraphEdge } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { type AuxValue, INPUT_SOURCE_ID, type Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const SHA_INPUT = new Uint8Array([0x61, 0x62, 0x63]); // "abc"

const runSha256 = (): Trace =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: SHA_INPUT },
    portedDispatchEnabled: true,
  });

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
    portedDispatchEnabled: true,
  });

describe("Trace.initialState — runtime population", () => {
  it("SHA-256: initialState byte-equals the input message", () => {
    const trace = runSha256();
    expect(trace.initialState.shape).toBe("bytes");
    expect(Array.from(trace.initialState.bytes)).toEqual(Array.from(SHA_INPUT));
  });

  it("AES-128 ECB: initialState byte-equals the full multi-block plaintext", () => {
    const trace = runAes128Ecb();
    expect(Array.from(trace.initialState.bytes)).toEqual(
      Array.from(bytesFromHex(ECB_PLAINTEXT_4_BLOCKS)),
    );
  });

  // Migration-equivalence pin: the input pill's NEW source (initialState) is
  // byte-equal to its OLD source (frames[0].stateBefore). Dropped in 5.3e
  // when `stateBefore` is deleted; assertion above keeps correctness covered.
  it("initialState is byte-equal to frames[0].stateBefore (both ciphers)", () => {
    for (const trace of [runSha256(), runAes128Ecb()]) {
      const first = trace.frames[0];
      expect(first).toBeDefined();
      expect(Array.from(trace.initialState.bytes)).toEqual(
        Array.from((first as { stateBefore: { bytes: Uint8Array } }).stateBefore.bytes),
      );
    }
  });
});

describe("input pill resolves to trace.initialState", () => {
  // SHA-256 is the load-bearing case: its first frame has no `"state"` input
  // port, so a port-first read of frames[0] could not surface the plaintext —
  // only `trace.initialState` can.
  it("SHA-256: CIPHER_INPUT_ID and $input both resolve to trace.initialState", () => {
    const trace = runSha256();
    for (const id of [CIPHER_INPUT_ID, INPUT_SOURCE_ID]) {
      const out = lookupNodeValue(id, buildSha256Spec(), trace, undefined);
      expect(out.status).toBe("endpoint");
      if (out.status !== "endpoint") continue;
      expect(out.endpointSide).toBe("input");
      expect(out.value).toBe(trace.initialState);
    }
  });

  it("SHA-256: an input-end edge resolves to trace.initialState", () => {
    const trace = runSha256();
    const inputEdge: GraphEdge = {
      from: CIPHER_INPUT_ID,
      to: "anything",
      auxKey: "state",
      kind: "state",
    };
    const out = lookupEdgeValue(inputEdge, buildSha256Spec(), trace, undefined);
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.endpointSide).toBe("input");
    expect(out.value).toBe(trace.initialState);
  });

  it("AES-128 ECB: CIPHER_INPUT_ID resolves to trace.initialState", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue(CIPHER_INPUT_ID, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.value).toBe(trace.initialState);
  });
});
