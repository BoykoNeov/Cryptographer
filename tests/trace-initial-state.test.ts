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

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { serpent128Spec } from "@/ciphers/serpent-128";
import { buildSha256Spec } from "@/ciphers/sha-256";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { lookupEdgeValue, lookupNodeValue } from "@/core/edge-value-lookup";
import { frameStateInBytes, frameStateOutBytes } from "@/core/frame-state";
import { CIPHER_INPUT_ID, type GraphEdge } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import { type AuxValue, type CipherSpec, INPUT_SOURCE_ID, type Trace } from "@/core/types";
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

// ─── frame-state helpers vs legacy fields (the 5.3e safety proof) ───────────
//
// The load-bearing check that 5.3e can safely delete `stateBefore`/`stateAfter`:
// characterize, across all frames of representative ciphers spanning both
// port-naming regimes, exactly where the new `frameStateInBytes` /
// `frameStateOutBytes` helpers equal the fields and where they DON'T.
//
// Two regimes:
//   - **Byte-identical** — SHA-256 + AES (pure-port-native primitives whose
//     ports are named `output`/`input`/`a`/… so the helper falls back to the
//     field) AND Speck + Serpent (hybrid-ported: the runtime reconstructs
//     `stateAfter` FROM `portOutputs.get("state")`, so port == field). For
//     these the helper is provably byte-identical, frame-for-frame.
//   - **Partial, incidental divergence (DES)** — the DES-specific F-leaves
//     (IP/FP/expand-R/xor-with-K/s-boxes/p-permutation) are pure-port-native
//     (B4) AND name their output port `"state"`, but the runtime never
//     reconstructs the threaded state from it, so `stateAfter` holds the STALE
//     initial plaintext while the `"state"` port carries the honest per-leaf
//     value. The helper reads the honest port for THOSE leaves (the B4
//     de-staling already relied on by `narration/des.tsx`, now incidentally
//     extended to the step strip + value inspector). The generic primitives in
//     the same round — `split-bytes` (output0/1), the chaining `xor` (output),
//     `concat` (output), `key-schedule` (keyN) — carry NO `"state"` port, so
//     they STILL fall back to the stale field (and will read null/"(no state)"
//     post-5.3e). So a DES round renders MIXED: honest on the F-leaves, stale
//     on split/xor/concat. This is no worse than the prior uniformly-stale
//     display and strictly better on the F-leaves; the uniform fix (resolve
//     each leaf's real output port by name) is the deferred port-aware
//     inspector, shared with the native-AES staleness. (Inputs are valid-sized,
//     not KAT vectors — we assert the helper↔field relationship, not the
//     ciphertext.)
const REGISTRY = buildDefaultRegistry();

const byteIdenticalCorpus: ReadonlyArray<readonly [string, CipherSpec, Trace]> = [
  ["SHA-256 (fallback regime — no state port)", buildSha256Spec(), runSha256()],
  [
    "AES-128 single-block (fallback regime)",
    aes128Spec,
    runSpec(aes128Spec, REGISTRY, {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
      ]),
      portedDispatchEnabled: true,
    }),
  ],
  [
    "Speck-32/64 BE (hybrid: port 'state' == reconstructed stateAfter)",
    speck32_64BeSpec,
    runSpec(speck32_64BeSpec, REGISTRY, {
      initialState: makeBytesState(bytesFromHex("6574694c")),
      initialAux: new Map<string, AuxValue>([["key", bytesFromHex("1918111009080100")]]),
      portedDispatchEnabled: true,
    }),
  ],
  [
    "Serpent-128 (hybrid: port 'state' == reconstructed stateAfter)",
    serpent128Spec,
    runSpec(serpent128Spec, REGISTRY, {
      initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
      initialAux: new Map<string, AuxValue>([
        ["key", bytesFromHex("00000000000000000000000000000000")],
      ]),
      portedDispatchEnabled: true,
    }),
  ],
];

const desTrace: Trace = runSpec(desSpec, REGISTRY, {
  initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
  initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
  portedDispatchEnabled: true,
});

describe("frame-state helpers ≡ stateBefore/stateAfter (byte-identical regime)", () => {
  for (const [name, , trace] of byteIdenticalCorpus) {
    it(`${name}: every frame's helper bytes equal the legacy field bytes`, () => {
      expect(trace.frames.length).toBeGreaterThan(0);
      for (const f of trace.frames) {
        expect(Array.from(frameStateInBytes(f) ?? [])).toEqual(Array.from(f.stateBefore.bytes));
        expect(Array.from(frameStateOutBytes(f) ?? [])).toEqual(Array.from(f.stateAfter.bytes));
      }
    });
  }
});

describe("frame-state helpers partially de-stale DES (port 'state' ≠ stale field)", () => {
  // Where a `"state"` port exists (the DES F-leaves), the helper MUST read it
  // (not the field); where it doesn't (split/xor/concat/key-schedule), it falls
  // back to the field. And the de-staling must be ACTIVE — at least one frame's
  // honest port value genuinely differs from the stale field, proving the
  // helper improved those leaves rather than no-op'd.
  it("reads the honest 'state' port and genuinely diverges from the stale field", () => {
    expect(desTrace.frames.length).toBeGreaterThan(0);
    let outDivergences = 0;
    for (const f of desTrace.frames) {
      const portIn = f.portInputs?.get("state");
      if (portIn !== undefined) expect(frameStateInBytes(f)).toBe(portIn);
      else expect(Array.from(frameStateInBytes(f) ?? [])).toEqual(Array.from(f.stateBefore.bytes));

      const portOut = f.portOutputs?.get("state");
      if (portOut !== undefined) {
        expect(frameStateOutBytes(f)).toBe(portOut);
        if (Array.from(portOut).join() !== Array.from(f.stateAfter.bytes).join()) {
          outDivergences++;
        }
      } else {
        expect(Array.from(frameStateOutBytes(f) ?? [])).toEqual(Array.from(f.stateAfter.bytes));
      }
    }
    // The whole point of the B4 port-read: DES round bodies show honest
    // per-leaf bytes, NOT the stale threaded plaintext.
    expect(outDivergences).toBeGreaterThan(0);
  });
});
