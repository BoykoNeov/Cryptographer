/**
 * Tests for `core/edge-value-lookup.ts::lookupNodeValue`.
 *
 * The node-side lookup is the partner of `lookupEdgeValue` and powers
 * the value-inspector panel when the user clicks a NODE — a leaf step,
 * an endpoint pill, or a block chip — rather than an edge. Same return
 * shape (`EdgeValueLookup`) so the renderer dispatches on `status`
 * without caring which surface was clicked.
 *
 * Branch coverage (mirrors the module-docstring branch table on the
 * lookup helper):
 *
 *   - Endpoint pills (CIPHER_INPUT_ID / CIPHER_OUTPUT_ID) → `"endpoint"`
 *     carrying trace.initialState (input) or trace.finalState (output) as
 *     the I/O value. Pre-run clicks → `"no-trace"`.
 *   - Trace null → `"no-trace"`.
 *   - Block chip with valid index → `"value"`, displayKind=block-payload,
 *     value = `outBlocks[i]` (= the iterate's last body frame stateAfter
 *     at blockIndex=i).
 *   - Ellipsis chip (`@blockMore`) → `"missing"` with pick-a-numbered-chip hint.
 *   - Block chip pointing at a non-existent iterate → `"missing"` with
 *     graph/spec out-of-sync reason.
 *   - Regular leaf → `"value"`, displayKind=state, value = frame.stateAfter.
 *     Uses the scrubber's `currentBlockIndex` to disambiguate when the
 *     leaf has multiple frames (inside an iterate).
 *   - Cross-block sanity: different block indices on the same leaf
 *     resolve to DIFFERENT values (i.e. the per-block discrimination
 *     actually works against the multi-block trace).
 *
 * Fixture: AES-128 ECB with a 4-block plaintext — the only shipping
 * multi-block fixture today.
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { lookupNodeValue } from "@/core/edge-value-lookup";
import { CIPHER_INPUT_ID, CIPHER_OUTPUT_ID } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace } from "@/core/types";
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
    // Byte-native ECB (B1.4) — port-mode iterate + port-native body.
    portedDispatchEnabled: true,
  });

// ─── Endpoint pills ─────────────────────────────────────────────────────

describe("lookupNodeValue — endpoint pills", () => {
  it("returns `endpoint` for the input pill carrying the plaintext bytes", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue(CIPHER_INPUT_ID, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.endpointSide).toBe("input");
    // Input pill resolves to `trace.initialState` (Slice 5.3c) — the cipher's
    // plaintext (the seed state the runtime cloned in). This replaced the old
    // `frames[0].stateBefore` read; the two are byte-equal, and we also pin
    // that equivalence so the migration is provably value-preserving.
    expect(out.value).toBe(trace.initialState);
    const first = trace.frames[0];
    expect(first).toBeDefined();
    expect((out.value as { bytes: Uint8Array }).bytes).toEqual(first?.stateBefore.bytes);
  });

  it("returns `endpoint` for the output pill carrying the ciphertext bytes", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue(CIPHER_OUTPUT_ID, aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("endpoint");
    if (out.status !== "endpoint") return;
    expect(out.endpointSide).toBe("output");
    // Output pill resolves to `trace.finalState` — the runtime's
    // post-loop state, byte-for-byte the cipher's ciphertext.
    expect(out.value).toBe(trace.finalState);
  });

  it("returns `no-trace` for an endpoint pill click when trace is null (pre-run)", () => {
    // Pre-2026-05-17 the endpoint branch returned `"endpoint"` even
    // with a null trace (descriptive label only). Post-rework, pre-run
    // pill clicks collapse to `"no-trace"` so the panel's empty-trace
    // copy matches every other inspector row.
    const inputOut = lookupNodeValue(CIPHER_INPUT_ID, aes128EcbSpec, null, undefined);
    expect(inputOut.status).toBe("no-trace");
    const outputOut = lookupNodeValue(CIPHER_OUTPUT_ID, aes128EcbSpec, null, undefined);
    expect(outputOut.status).toBe("no-trace");
  });
});

// ─── No-trace ──────────────────────────────────────────────────────────

describe("lookupNodeValue — trace null", () => {
  it("returns `no-trace` for a regular leaf when the user hasn't run yet", () => {
    const out = lookupNodeValue("key-expansion", aes128EcbSpec, null, undefined);
    expect(out.status).toBe("no-trace");
  });

  it("returns `no-trace` for a chip when the trace is null", () => {
    const out = lookupNodeValue("ecb-blocks@block0", aes128EcbSpec, null, undefined);
    expect(out.status).toBe("no-trace");
  });
});

// ─── Block chips ────────────────────────────────────────────────────────

describe("lookupNodeValue — block chips", () => {
  // PHASE C / B1.4b: block-chip PAYLOAD-value resolution is an aux/state-mode
  // feature — it reads the per-block ciphertext from the body's `stateAfter`
  // at `blockIndex === i` (equivalently `aux[outBlocksAux][i]`). Byte-native
  // ECB (B1.4) is a port-mode iterate: leaves never write `state`, and there
  // is no `outBlocksAux` — each block's result lives in the body's port
  // outputs. Resolving a chip's payload therefore needs a PORT-based path,
  // the same class as the deferred `$input`-vs-endpoint-pill question
  // (graph-narrative Slice 1) — scheduled with Slice 2.9c-e / Phase C, not
  // built in B1.4a (locked decision: flat bytes until C2; accept the temporary
  // block-chip-value regression). Both ECB (B1.4a) and CBC (B1.4b) are now
  // port-mode iterates, so NO shipped spec has the aux/state block-payload
  // path anymore. The two former payload-value tests (matrix4x4-bytes per-block
  // value + per-chip discrimination) were dropped rather than retargeted. The
  // MISSING-path chip tests below are index-driven and stay valid for the
  // byte-native iterate.

  it("returns missing for the ellipsis chip (`@blockMore`)", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("ecb-blocks@blockMore", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/multiple blocks|numbered/i);
  });

  it("returns missing for a chip pointing at a non-existent iterate id", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("does-not-exist@block0", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/not found|out of sync/i);
  });

  it("returns missing for a chip index past the iteration count", () => {
    const trace = runAes128Ecb();
    // ECB ran 4 blocks; block index 99 is out of range.
    const out = lookupNodeValue("ecb-blocks@block99", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no body frames found/i);
  });
});

// ─── Regular leaves ─────────────────────────────────────────────────────

describe("lookupNodeValue — regular leaves", () => {
  it("resolves a top-level leaf (`key-expansion`) to its frame.stateAfter", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("key-expansion", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    // key-expansion is outside any iterate; blockIndex is undefined.
    expect(out.blockIndex).toBeUndefined();
  });

  it("resolves a leaf INSIDE the iterate to its per-block stateAfter (block 0 by default)", () => {
    const trace = runAes128Ecb();
    // initial.add-round-key lives inside the iterate body; without a
    // scrubber preference, the lookup falls back to the first matching
    // frame — which is block 0's first iteration.
    const out = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    expect(out.blockIndex).toBe(0);
  });

  it("resolves the SAME leaf to different block-indices when the scrubber moves", () => {
    const trace = runAes128Ecb();
    const a = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 0);
    const b = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 2);
    if (a.status !== "value" || b.status !== "value") {
      expect.fail("expected both leaf lookups to be values");
      return;
    }
    // The scrubber-blockIndex preference is what this pins: the SAME leaf id
    // resolves to the frame at the requested block. (The per-block VALUE no
    // longer differs by block under byte-native ECB — port-native leaves leave
    // `state` untouched, so the resolved `stateAfter` is the same leftover for
    // every block. The honest per-block value lives in the leaf's port output;
    // surfacing it is the Phase-C port-based value path — see the block-chips
    // describe above.)
    expect(a.blockIndex).toBe(0);
    expect(b.blockIndex).toBe(2);
  });

  it("returns missing for a leaf id that has no frame in the trace", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("not-a-real-step", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no frame found/i);
  });
});
