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
 *   - Regular leaf → its `"state"` output port (port-first, Slice 5.3c; the
 *     `stateAfter` State field retired in Slice 5.3e Batch 4). A leaf with NO
 *     `"state"` port resolves to `"missing"` — every native-AES leaf is in
 *     this class (their payloads ride `output`/`a`/… ports), so the
 *     cipher-agnostic value inspector reports "(no state)" for them. This is
 *     the user-accepted deferred-port-aware-inspector gap; pre-Batch-4 the
 *     field read returned only the STALE leftover threaded state for these
 *     leaves, so "(no state)" is strictly more honest. The scrubber's
 *     `currentBlockIndex` still selects the right per-block FRAME via
 *     `findConsumerFrame` even when the value is missing.
 *
 * Fixture: AES-128 ECB with a 4-block plaintext — the only shipping
 * multi-block fixture today (and entirely native-port → no `"state"` leaves).
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
    // `frames[0].stateBefore` read (the State fields retired in Slice 5.3e
    // Batch 4); `initialState` is now the field-independent source of truth.
    expect(out.value).toBe(trace.initialState);
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
  it('resolves a top-level leaf (`key-expansion`) to missing — aux-only, no `"state"` port', () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("key-expansion", aes128EcbSpec, trace, undefined);
    // key-expansion writes its round keys to aux; it has no `"state"` output
    // port, so post-Batch-4 the cipher-agnostic value inspector reports no
    // resolvable state (the round keys surface via aux edges / PortFlowView).
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no resolvable state/i);
  });

  it("resolves a native-AES leaf inside the iterate (`initial.add-round-key`) to missing", () => {
    const trace = runAes128Ecb();
    // Native-AES round leaves name their payload `output`/`a`/… — not
    // `"state"` — so the value inspector resolves them to missing post-Batch-4.
    // (Pre-Batch-4 the field read returned only the stale leftover threaded
    // state here; "(no state)" is strictly more honest. The deferred
    // port-aware inspector will resolve each leaf's real output port by name.)
    const out = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no resolvable state/i);
  });

  it("selects a DIFFERENT per-block frame for the same leaf when the scrubber moves", () => {
    const trace = runAes128Ecb();
    const a = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 0);
    const b = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 2);
    // Both are "missing" (native-AES leaf, no `"state"` port), but the
    // scrubber-blockIndex preference still drives `findConsumerFrame` to a
    // DIFFERENT per-block frame — the "missing" reason names the resolved
    // frame index, which differs by block. This pins that block resolution
    // survives Batch 4 even though the per-block VALUE is no longer surfaced
    // here (the honest per-block bytes live in the leaf's port output → the
    // deferred port-aware inspector).
    expect(a.status).toBe("missing");
    expect(b.status).toBe("missing");
    if (a.status !== "missing" || b.status !== "missing") return;
    expect(a.reason).not.toBe(b.reason);
  });

  it("returns missing for a leaf id that has no frame in the trace", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("not-a-real-step", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no frame found/i);
  });
});
