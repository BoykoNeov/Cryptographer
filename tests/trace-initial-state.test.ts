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
 *   2. The input pill resolves to `trace.initialState` through BOTH node
 *      selectors (`CIPHER_INPUT_ID` and the port-native `$input` source) and
 *      the input-end edge — reference-equal, so the renderer formats the same
 *      value as the seed.
 *   3. Post-Batch-4 helper regime: with `stateBefore`/`stateAfter` gone, the
 *      `frameState*` helpers read ONLY the `"state"` port. SHA-256 (pure
 *      port-native, no `"state"` port) → null on every frame ("(no state)" on
 *      the cipher-agnostic surfaces); DES's F-leaves expose `"state"` → the
 *      helper returns the honest round-local bytes.
 *
 * (Slice 5.3c's `helper == stateBefore/stateAfter` characterization corpus was
 * pre-deletion safety scaffolding; it retired with the fields in Batch 4. The
 * Speck/Serpent helper reads are now pinned by the golden frame streams in
 * `runtime-ported-dispatch-{speck,serpent}.test.ts`.)
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { frameStateInBytes, frameStateOutBytes } from "@/core/frame-state";
import { CIPHER_INPUT_ID, type GraphEdge } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { type AuxValue, INPUT_SOURCE_ID, type Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const SHA_INPUT = new Uint8Array([0x61, 0x62, 0x63]); // "abc"

const runSha256 = (): Trace =>
  runSpec(buildSha256Spec(), buildDefaultRegistry(), {
    initialState: { shape: "bytes", bytes: SHA_INPUT },
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

// ─── frame-state helper regime (Batch 4: port-only, no State field) ─────────
//
// With `stateBefore`/`stateAfter` deleted, `frameStateInBytes` /
// `frameStateOutBytes` are purely `portInputs/portOutputs.get("state") ?? null`.
// Their answer therefore reduces to one question — does this leaf name its
// primary payload `"state"`? Two representative regimes pin that contract.
const REGISTRY = buildDefaultRegistry();

const desTrace: Trace = runSpec(desSpec, REGISTRY, {
  initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
});

describe("frame-state helper regime (Batch 4)", () => {
  // SHA-256 is the load-bearing "(no state)" case: every leaf is pure
  // port-native and names its payload `output`/`a`/`w`/… — never `"state"` —
  // so the helper returns null on EVERY frame. This is the user-accepted
  // cipher-agnostic regression (step strip / value inspector show "(no state)"
  // for SHA-256); the bytes stay visible in PortFlowView by real port name.
  it('SHA-256: helper returns null on every frame (no `"state"` port anywhere)', () => {
    const trace = runSha256();
    expect(trace.frames.length).toBeGreaterThan(0);
    for (const f of trace.frames) {
      expect(frameStateInBytes(f)).toBeNull();
      expect(frameStateOutBytes(f)).toBeNull();
    }
  });

  // DES is the mixed case: its F-leaves (IP/FP/expand-R/xor-with-K/s-boxes/
  // p-permutation) DO name their output port `"state"`, so the helper returns
  // the honest round-local bytes there; the generic round steps (split-bytes/
  // xor/concat/key-schedule) have no `"state"` port → null. Pre-Batch-4 those
  // F-leaves carried a STALE 8-byte plaintext on the now-deleted `stateBefore`
  // field while the honest 4-byte R rode the port — removing the field is what
  // makes the honest port the only reading.
  it('DES: helper reads the `"state"` port on the F-leaves, null elsewhere', () => {
    expect(desTrace.frames.length).toBeGreaterThan(0);
    let withStatePort = 0;
    for (const f of desTrace.frames) {
      const portIn = f.portInputs?.get("state") ?? null;
      const portOut = f.portOutputs?.get("state") ?? null;
      // The helper returns EXACTLY the captured port (reference-equal), or null.
      expect(frameStateInBytes(f)).toBe(portIn);
      expect(frameStateOutBytes(f)).toBe(portOut);
      if (portOut !== null) withStatePort++;
    }
    // ≥1 F-leaf names its output `"state"` — proving the helper surfaces honest
    // per-leaf bytes, not a fallback/no-op.
    expect(withStatePort).toBeGreaterThan(0);
  });
});
