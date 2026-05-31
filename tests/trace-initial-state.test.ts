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
 *   3. Slice 2.9c-e helper regime: `framePrimary{In,Out}Bytes` resolve the
 *      `"state"` port if present, else the SOLE port when a leaf has exactly
 *      one, else null. SHA-256's single-output primitives (the vast majority
 *      of frames) now surface their honest `output` bytes; multi-output
 *      `split-bytes` stays null. DES's F-leaves expose `"state"`; its generic
 *      single-output round steps (xor/concat) surface their sole output.
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
import { framePrimaryInBytes, framePrimaryOutBytes } from "@/core/frame-state";
import { CIPHER_INPUT_ID, type GraphEdge } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { type AuxValue, INPUT_SOURCE_ID, type Trace } from "@/core/types";
import { describe, expect, it } from "vitest";

const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

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
// With `stateBefore`/`stateAfter` deleted, `framePrimaryInBytes` /
// `framePrimaryOutBytes` are purely `portInputs/portOutputs.get("state") ?? null`.
// Their answer therefore reduces to one question — does this leaf name its
// primary payload `"state"`? Two representative regimes pin that contract.
const REGISTRY = buildDefaultRegistry();

const desTrace: Trace = runSpec(desSpec, REGISTRY, {
  initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
});

describe("frame-state helper regime (Batch 4)", () => {
  // SHA-256 is the load-bearing former "(no state)" case: every leaf is pure
  // port-native and names its payload `output`/`a`/`w`/… — never `"state"`.
  // The Slice 2.9c-e helper resolves the SOLE output port when a leaf has
  // exactly one, so the vast majority of SHA-256 frames (single-output prims:
  // xor/add-mod-32/rotate/byte-slice/concat/…) now surface their honest bytes;
  // only multi-output `split-bytes` stays null. Pre-2.9c-e the helper returned
  // null on EVERY frame (the accepted cipher-agnostic regression).
  it("SHA-256: helper surfaces single-output port bytes (Slice 2.9c-e regression fix)", () => {
    const trace = runSha256();
    expect(trace.frames.length).toBeGreaterThan(0);
    let nonNullOut = 0;
    for (const f of trace.frames) {
      const outs = f.portOutputs;
      const got = framePrimaryOutBytes(f);
      if (outs?.get("state") !== undefined) {
        expect(got).toBe(outs.get("state"));
      } else if (outs && outs.size === 1) {
        // sole output port → the helper surfaces the runtime's captured bytes.
        expect(got).toBe([...outs.values()][0]);
        if (got !== null) nonNullOut++;
      } else {
        // multi-output `split-bytes` (or no outputs): no single representative.
        expect(got).toBeNull();
      }
      // Input side follows the same rule, but is intrinsically less resolvable
      // — every fan-in prim (xor/add-mod-32/concat) reads N operands → null.
      const ins = f.portInputs;
      const gotIn = framePrimaryInBytes(f);
      if (ins?.get("state") !== undefined) expect(gotIn).toBe(ins.get("state"));
      else if (ins && ins.size === 1) expect(gotIn).toBe([...ins.values()][0]);
      else expect(gotIn).toBeNull();
    }
    // Most SHA-256 frames are single-output primitives — the helper now returns
    // honest bytes for the bulk of the trace (was null on every frame before).
    expect(nonNullOut).toBeGreaterThan(100);
    // Concrete anchor (non-tautological): the digest-producing concat leaf's
    // sole output equals the FIPS 180-4 §A.1 "abc" digest — proving the
    // surfaced bytes are the real value, not an arbitrary port.
    const DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect(toHex(trace.finalState.bytes)).toBe(DIGEST);
    const surfacesDigest = trace.frames.some((f) => {
      const b = framePrimaryOutBytes(f);
      return b !== null && toHex(b) === DIGEST;
    });
    expect(surfacesDigest).toBe(true);
  });

  // DES is the mixed case: its F-leaves (IP/FP/expand-R/xor-with-K/s-boxes/
  // p-permutation) name their output port `"state"` → honest round-local bytes;
  // its generic single-output round steps (xor/concat) surface their sole
  // `output` port; only multi-output `split-bytes` (and the aux-only
  // key-schedule) resolve to null.
  it("DES: helper resolves state-port F-leaves + sole-output generic leaves", () => {
    expect(desTrace.frames.length).toBeGreaterThan(0);
    let statePortFrames = 0;
    let soleOutputFrames = 0;
    for (const f of desTrace.frames) {
      const outs = f.portOutputs;
      const got = framePrimaryOutBytes(f);
      const statePort = outs?.get("state") ?? null;
      if (statePort !== null) {
        expect(got).toBe(statePort); // F-leaf — honest round-local bytes
        statePortFrames++;
      } else if (outs && outs.size === 1) {
        expect(got).toBe([...outs.values()][0]); // generic xor/concat sole output
        soleOutputFrames++;
      } else {
        expect(got).toBeNull(); // split-bytes (multi-output) / aux-only schedule
      }
    }
    expect(statePortFrames).toBeGreaterThan(0); // F-leaves present
    expect(soleOutputFrames).toBeGreaterThan(0); // xor/concat now surfaced
    // Concrete anchor: DES(0123456789abcdef, key 133457799bbcdff1) =
    // 85e813540f0ab405 (FIPS 46-3) — the final permutation's honest output.
    expect(toHex(desTrace.finalState.bytes)).toBe("85e813540f0ab405");
  });
});
