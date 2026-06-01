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
 *   - Regular leaf → its primary output port (Slice 2.9c-e: the `"state"`
 *     port if present, else the SOLE output port when the leaf has exactly
 *     one). Native-AES round leaves are single-output port-native steps
 *     (`xor-with-aux`/`byte-substitute`/… → port `"output"`), so the value
 *     inspector now surfaces their honest per-block bytes. Only genuinely
 *     multi-output leaves (`split-bytes`) or aux-only leaves (`key-expansion`,
 *     no output port) resolve to `"missing"`. The scrubber's
 *     `currentBlockIndex` selects the right per-block FRAME via
 *     `findConsumerFrame`, so block 0 and block 2 surface different values.
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

/** Byte-wise XOR — used to compute the expected initial-AddRoundKey output
 *  (plaintext ⊕ roundKey.0) independently of the runtime's own port capture. */
const xorBytes = (a: Uint8Array, b: Uint8Array): Uint8Array =>
  Uint8Array.from(a, (byte, i) => byte ^ (b[i] ?? 0));

const ECB_KEY = "2b7e151628aed2a6abf7158809cf4f3c";

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
    const out = lookupNodeValue("initial.add-round-key", aes128EcbSpec, null, undefined);
    expect(out.status).toBe("no-trace");
  });

  it("returns `no-trace` for a chip when the trace is null", () => {
    const out = lookupNodeValue("ecb-blocks@block0", aes128EcbSpec, null, undefined);
    expect(out.status).toBe("no-trace");
  });
});

// ─── Block chips ────────────────────────────────────────────────────────

describe("lookupNodeValue — block chips", () => {
  // Block-chip PAYLOAD-value resolution: `lookupChipOutgoing` reads the per-block
  // result from the LAST body frame's primary output port at `blockIndex === i`.
  // Byte-native ECB (B1.4) is a port-mode iterate — leaves never write `state`,
  // and there is no `outBlocksAux`; each block's result lives in the body's port
  // outputs. The native-AES body's last leaf is `xor-with-aux` (port `"output"`,
  // no `"state"` port), so under the old `"state"`-only helper this was "missing"
  // (the B1.4a accepted block-chip-value regression). Slice 2.9c-e generalized
  // the helper to the SOLE output port, so chip-out now resolves — pinned below
  // against the NIST SP 800-38A ECB-AES128 ciphertext blocks. (Chip-IN stays
  // intrinsically unresolvable: the body's FIRST leaf is `xor-with-aux` with two
  // inputs — a fan-in, no single representative input port.)

  it("resolves a numbered block chip to its per-block ciphertext (chip-out, NIST SP 800-38A)", () => {
    const trace = runAes128Ecb();
    const out0 = lookupNodeValue("ecb-blocks@block0", aes128EcbSpec, trace, undefined);
    expect(out0.status).toBe("value");
    if (out0.status !== "value") return;
    expect(out0.displayKind).toBe("block-payload");
    expect(out0.blockIndex).toBe(0);
    expect(out0.value).toEqual(makeBytesState(bytesFromHex("3ad77bb40d7a3660a89ecaf32466ef97")));

    // block3 is 0-indexed → NIST block #4 (PT f69f2445…), CT 7b0c785e…
    const out3 = lookupNodeValue("ecb-blocks@block3", aes128EcbSpec, trace, undefined);
    expect(out3.status).toBe("value");
    if (out3.status !== "value") return;
    expect(out3.value).toEqual(makeBytesState(bytesFromHex("7b0c785e27e8ad3f8223207104725dd4")));
    // Distinct blocks → distinct per-block ciphertext.
    expect(out0.value).not.toEqual(out3.value);
  });

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
  it("resolves the schedule publish tail (`key-schedule.publish`) to missing — multi-output, no single resolvable state", () => {
    const trace = runAes128Ecb();
    // Since the key-schedule decomposition (K1c) the schedule's meta-bearing
    // tail `key-schedule.publish` is the aux writer for the round keys. It has
    // 11 output ports (key0..key10, identity-forwarded) and no `"state"` port,
    // so the cipher-agnostic value inspector (framePrimaryOutBytes: state →
    // sole-port → null) can't pick a single representative value → missing.
    // The round keys surface via the aux edges / PortFlowView instead.
    const out = lookupNodeValue("key-schedule.publish", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no resolvable state|single|output port/i);
  });

  it("resolves a native-AES leaf inside the iterate (`initial.add-round-key`) to its honest single-output value", () => {
    const trace = runAes128Ecb();
    // Native-AES AddRoundKey is `xor-with-aux@1` — a single-output port-native
    // leaf (port `"output"`, no `"state"` port). The Slice 2.9c-e helper
    // resolves the sole output port, so the value inspector now surfaces the
    // honest per-block bytes (pre-2.9c-e this was the accepted "(no state)"
    // regression). The INITIAL AddRoundKey XORs the plaintext block with
    // roundKey.0, which IS the master key (FIPS-197 §5.1.4 / §5.2) — so block
    // 0's output is plaintext_block0 ⊕ key, computed here from the fixture
    // inputs (independent of the runtime's own port capture).
    const out = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 0);
    expect(out.status).toBe("value");
    if (out.status !== "value") return;
    expect(out.displayKind).toBe("state");
    expect(out.blockIndex).toBe(0);
    const expected = xorBytes(
      bytesFromHex("6bc1bee22e409f96e93d7e117393172a"),
      bytesFromHex(ECB_KEY),
    );
    expect(out.value).toEqual(makeBytesState(expected));
  });

  it("surfaces a DIFFERENT per-block value for the same leaf when the scrubber moves", () => {
    const trace = runAes128Ecb();
    const a = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 0);
    const b = lookupNodeValue("initial.add-round-key", aes128EcbSpec, trace, 2);
    // The scrubber-blockIndex preference drives `findConsumerFrame` to the
    // per-block frame, so block 0 and block 2 surface DIFFERENT initial-
    // AddRoundKey outputs — plaintext_block0 ⊕ key vs plaintext_block2 ⊕ key
    // (the two plaintext blocks differ). This pins both per-block resolution
    // AND the honest per-block value now flowing through the inspector.
    expect(a.status).toBe("value");
    expect(b.status).toBe("value");
    if (a.status !== "value" || b.status !== "value") return;
    const key = bytesFromHex(ECB_KEY);
    expect(a.value).toEqual(
      makeBytesState(xorBytes(bytesFromHex("6bc1bee22e409f96e93d7e117393172a"), key)),
    );
    expect(b.value).toEqual(
      makeBytesState(xorBytes(bytesFromHex("30c81c46a35ce411e5fbc1191a0a52ef"), key)),
    );
    expect(a.value).not.toEqual(b.value);
  });

  it("returns missing for a leaf id that has no frame in the trace", () => {
    const trace = runAes128Ecb();
    const out = lookupNodeValue("not-a-real-step", aes128EcbSpec, trace, undefined);
    expect(out.status).toBe("missing");
    if (out.status !== "missing") return;
    expect(out.reason).toMatch(/no frame found/i);
  });
});
