/**
 * Tests for the three Slice 10 aux primitives in `src/steps/` — port-native
 * `PortedExecutor`s since Slice 5.2 (2026-05-31):
 *
 *   - `generic.aux-load@1` — publish a literal byte sequence (no inputs; emits
 *      the `value` output port, mapped to aux[auxName] by meta).
 *   - `generic.aux-xor@1`  — XOR the `from` and `into` input ports; emits the
 *      `result` output port (mapped to aux[into]).
 *   - `generic.aux-copy@1` — copy the `from` input port to the `result` output
 *      port (mapped to aux[to]).
 *
 * Three coverage axes:
 *
 *   1. **Per-primitive KAT** — direct executor calls with the port signature
 *      (`(inputs, params, ctx) -> Map`) assert the byte math on the output
 *      ports.
 *   2. **Graceful missing-aux** — now a RUNTIME behavior: when a read key
 *      isn't in aux, the runtime omits that input port (the executor returns
 *      no output) AND records the miss in `frame.auxReadMissing` from
 *      meta.auxReadPorts. The integration suite runs the specs flag-on and
 *      asserts both auxReadMissing and the Slice 9 orphan-read warnings.
 *   3. **End-to-end CBC-from-scratch composition** — a hand-built spec that
 *      uses only `aux-load` + `aux-xor` + `aux-copy` (no cipher core) to
 *      compute the CBC chaining math over a 2-block plaintext, run flag-on.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { deriveAuxGraph, validateGraph } from "@/core/graph";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, CipherSpec, StepContext } from "@/core/types";
import { auxCopy } from "@/steps/aux-copy";
import { auxLoad } from "@/steps/aux-load";
import { auxXor } from "@/steps/aux-xor";
import { describe, expect, it } from "vitest";

// Empty BytesState used everywhere — the aux primitives don't care about
// state shape, but the runtime needs something to seed with.
const emptyBytes = () => makeBytesState(new Uint8Array(0));

// The aux primitives are PortedExecutors since Slice 5.2: they read named
// input ports and return a named-output-port Map, ignoring ctx. A fixed ctx
// satisfies the signature; `ports({...})` builds the input map.
const ctx: StepContext = { stepId: "test", path: [], aux: new Map() };
const ports = (entries: Record<string, Uint8Array>) => new Map(Object.entries(entries));

// ─── aux-load ─────────────────────────────────────────────────────────────

describe("aux-load@1 (port-native)", () => {
  it("emits the literal value on the `value` output port as a fresh Uint8Array", () => {
    const out = auxLoad(new Map(), { auxName: "iv", value: [0xde, 0xad, 0xbe, 0xef] }, ctx);
    const written = out.get("value");
    expect(written).toBeInstanceOf(Uint8Array);
    expect(Array.from(written as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("allocates a fresh buffer (does not alias the params array)", () => {
    const value = [1, 2, 3, 4];
    const out = auxLoad(new Map(), { auxName: "x", value }, ctx);
    const written = out.get("value") as Uint8Array;
    written[0] = 0xff;
    expect(value[0]).toBe(1);
  });

  it("rejects out-of-range bytes in value", () => {
    expect(() => auxLoad(new Map(), { auxName: "x", value: [0, 256] }, ctx)).toThrow(
      /value\[1\] must be an integer in \[0, 255\]/,
    );
  });

  it("treats empty auxName as unset (no output port) — palette-drop authoring state", () => {
    const out = auxLoad(new Map(), { auxName: "", value: [1, 2, 3] }, ctx);
    expect(out.size).toBe(0);
  });

  it("treats missing auxName as unset (no output port)", () => {
    // Palette-dropped params start as `{}` — auxName is undefined. Must not
    // throw, must not emit an output port.
    const out = auxLoad(new Map(), {}, ctx);
    expect(out.size).toBe(0);
  });

  it("rejects non-string auxName (malformed JSON spec — not reachable from the UI)", () => {
    expect(() => auxLoad(new Map(), { auxName: 42, value: [] }, ctx)).toThrow(
      /auxName must be a string/,
    );
  });

  it("rejects non-array value", () => {
    expect(() => auxLoad(new Map(), { auxName: "x", value: "abc" }, ctx)).toThrow(
      /value must be an array of integers/,
    );
  });
});

// ─── aux-xor ──────────────────────────────────────────────────────────────

describe("aux-xor@1 (port-native)", () => {
  it("XORs the `from` and `into` ports, emitting the result on `result`", () => {
    const out = auxXor(
      ports({
        from: new Uint8Array([0xff, 0x0f, 0xaa]),
        into: new Uint8Array([0x0f, 0xff, 0x55]),
      }),
      {},
      ctx,
    );
    const result = out.get("result") as Uint8Array;
    expect(Array.from(result)).toEqual([0xf0, 0xf0, 0xff]);
  });

  it("is graceful (no output) when the `from` port is missing", () => {
    const out = auxXor(ports({ into: new Uint8Array([1, 2, 3]) }), {}, ctx);
    expect(out.size).toBe(0);
  });

  it("is graceful (no output) when the `into` port is missing", () => {
    const out = auxXor(ports({ from: new Uint8Array([1, 2, 3]) }), {}, ctx);
    expect(out.size).toBe(0);
  });

  it("is graceful (no output) when both ports are missing", () => {
    const out = auxXor(new Map(), {}, ctx);
    expect(out.size).toBe(0);
  });

  it("THROWS on a length mismatch between the two operands", () => {
    expect(() =>
      auxXor(ports({ from: new Uint8Array(4), into: new Uint8Array(8) }), {}, ctx),
    ).toThrow(/length mismatch.*4.*8/);
  });
});

// ─── aux-copy ─────────────────────────────────────────────────────────────

describe("aux-copy@1 (port-native)", () => {
  it("copies the `from` port to the `result` port", () => {
    const out = auxCopy(ports({ from: new Uint8Array([0x11, 0x22, 0x33]) }), {}, ctx);
    const result = out.get("result") as Uint8Array;
    expect(Array.from(result)).toEqual([0x11, 0x22, 0x33]);
  });

  it("makes a defensive copy (result doesn't alias the source bytes)", () => {
    const src = new Uint8Array([1, 2, 3]);
    const out = auxCopy(ports({ from: src }), {}, ctx);
    const result = out.get("result") as Uint8Array;
    result[0] = 0xff;
    expect(src[0]).toBe(1);
  });

  it("is graceful (no output) when the `from` port is missing", () => {
    const out = auxCopy(new Map(), {}, ctx);
    expect(out.size).toBe(0);
  });
});

// ─── Runtime integration: missing aux surfaces as auxReadMissing ──────────

describe("runtime integration — missing aux populates auxReadMissing on the frame", () => {
  // Build a tiny spec that uses aux-xor without ever loading either of its
  // operands. The runtime should still emit a frame (the step is graceful),
  // and that frame should carry auxReadMissing for BOTH keys. Run flag-on —
  // the aux primitives are port-native (no legacy path).
  const spec: CipherSpec = {
    id: "test-graceful-xor@1",
    name: "test graceful aux-xor",
    stateShape: "bytes",
    inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
    steps: [
      { kind: "step", id: "xor", type: "generic.aux-xor@1", params: { from: "a", into: "b" } },
    ],
  };

  it("aux-xor on missing keys emits a frame with auxReadMissing populated", () => {
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    expect(trace.frames.length).toBe(1);
    const frame = trace.frames[0];
    expect(frame).toBeDefined();
    if (!frame) return;
    expect(frame.auxReadMissing).toEqual(["a", "b"]);
    // No aux written (graceful skip).
    expect(frame.auxWritten.size).toBe(0);
  });

  it("validateGraph surfaces both as orphaned-read warnings", () => {
    // The cross-slice integration receipt: Slice 9's validateGraph reads
    // auxReadMissing off the trace and produces the warnings.
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const graph = deriveAuxGraph(trace, spec);
    const warnings = validateGraph(graph, trace);

    const orphans = warnings.filter((w) => w.kind === "orphaned-read");
    expect(orphans.length).toBe(2);
    const keys = orphans.map((w) => (w.kind === "orphaned-read" ? w.auxKey : "")).sort();
    expect(keys).toEqual(["a", "b"]);
    for (const w of orphans) {
      if (w.kind === "orphaned-read") expect(w.stepId).toBe("xor");
    }
  });

  it("freshly palette-dropped aux-xor (params={}) emits a frame and surfaces orphan warnings", () => {
    // Regression for the bug a user hit in browser-verification of Slice
    // 10: drop aux-xor onto the canvas → no warning glyph → can't click
    // through to params editor. Root cause was the executor throwing on
    // empty `from`/`into`, which prevented a frame from being emitted.
    const droppedSpec: CipherSpec = {
      id: "test-fresh-drop@1",
      name: "test fresh palette drop",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [{ kind: "step", id: "xor", type: "generic.aux-xor@1", params: {} }],
    };
    const trace = runSpec(droppedSpec, buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    // Frame emitted → graph click can land on it → param editor can
    // resolve the step.
    expect(trace.frames.length).toBe(1);
    const frame = trace.frames[0];
    expect(frame).toBeDefined();
    if (!frame) return;
    // Empty-string reads declared as missing → validator surfaces them.
    expect(frame.auxReadMissing).toEqual(["", ""]);
    const graph = deriveAuxGraph(trace, droppedSpec);
    const warnings = validateGraph(graph, trace);
    const orphans = warnings.filter((w) => w.kind === "orphaned-read");
    // Both reads use the same auxKey (""), and validateGraph dedups by
    // (stepId, auxKey) — so the two empty-string reads collapse to ONE
    // warning.
    expect(orphans.length).toBe(1);
    if (orphans[0]?.kind === "orphaned-read") {
      expect(orphans[0].stepId).toBe("xor");
      expect(orphans[0].auxKey).toBe("");
    }
  });

  it("aux-copy on missing from emits a frame with auxReadMissing=['src']", () => {
    const copySpec: CipherSpec = {
      id: "test-graceful-copy@1",
      name: "test graceful aux-copy",
      stateShape: "bytes",
      inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
      steps: [
        { kind: "step", id: "cp", type: "generic.aux-copy@1", params: { from: "src", to: "dst" } },
      ],
    };
    const trace = runSpec(copySpec, buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const frame = trace.frames[0];
    expect(frame).toBeDefined();
    if (!frame) return;
    expect(frame.auxReadMissing).toEqual(["src"]);
    expect(frame.auxWritten.size).toBe(0);
  });
});

// ─── End-to-end: CBC-from-scratch built from the three primitives ─────────

/**
 * Build a CBC encryption spec that uses ONLY aux-load + aux-xor + aux-copy
 * to compute the chaining math over 2 plaintext blocks, with the cipher
 * "core" being an identity (no aux-state bridge primitive ships in Slice 10,
 * so a real cipher core can't be wired through aux; the educational point
 * is that the primitives chain correctly).
 *
 * Reference computation:
 *   C0 = P0 ⊕ IV
 *   C1 = P1 ⊕ C0
 *
 * Spec wiring:
 *   aux-load IV     (the IV literal)
 *   aux-load P0     (block 0 plaintext literal)
 *   aux-load P1     (block 1 plaintext literal)
 *   aux-copy iv → feedback     (initialize the chain)
 *   aux-xor  P0 → feedback     (feedback now = P0⊕IV = C0)
 *   aux-copy feedback → C0
 *   aux-xor  P1 → feedback     (feedback now = P1⊕C0 = C1)
 *   aux-copy feedback → C1
 */
const cbcEncryptSpec = (blockSize: number): CipherSpec => ({
  id: "test-cbc-encrypt@1",
  name: "CBC encrypt (from primitives)",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    // Slot loaders.
    {
      kind: "step",
      id: "load-iv",
      type: "generic.aux-load@1",
      params: { auxName: "iv", value: Array.from({ length: blockSize }, (_, i) => i) },
    },
    {
      kind: "step",
      id: "load-p0",
      type: "generic.aux-load@1",
      params: { auxName: "p0", value: Array.from({ length: blockSize }, (_, i) => 0xa0 + i) },
    },
    {
      kind: "step",
      id: "load-p1",
      type: "generic.aux-load@1",
      params: { auxName: "p1", value: Array.from({ length: blockSize }, (_, i) => 0xb0 + i) },
    },
    // Initialize feedback from IV.
    {
      kind: "step",
      id: "init-feedback",
      type: "generic.aux-copy@1",
      params: { from: "iv", to: "feedback" },
    },
    // Block 0: feedback ← P0 ⊕ feedback; publish C0.
    {
      kind: "step",
      id: "mix-p0",
      type: "generic.aux-xor@1",
      params: { from: "p0", into: "feedback" },
    },
    {
      kind: "step",
      id: "emit-c0",
      type: "generic.aux-copy@1",
      params: { from: "feedback", to: "c0" },
    },
    // Block 1: feedback ← P1 ⊕ feedback; publish C1.
    {
      kind: "step",
      id: "mix-p1",
      type: "generic.aux-xor@1",
      params: { from: "p1", into: "feedback" },
    },
    {
      kind: "step",
      id: "emit-c1",
      type: "generic.aux-copy@1",
      params: { from: "feedback", to: "c1" },
    },
  ],
});

/** Decrypt is symmetric: C_i = P_i ⊕ prev → P_i = C_i ⊕ prev. */
const cbcDecryptSpec = (blockSize: number): CipherSpec => ({
  id: "test-cbc-decrypt@1",
  name: "CBC decrypt (from primitives)",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    // Load the IV and the two ciphertexts.
    {
      kind: "step",
      id: "load-iv",
      type: "generic.aux-load@1",
      params: { auxName: "iv", value: Array.from({ length: blockSize }, (_, i) => i) },
    },
    // (c0, c1 are computed below and passed in via initialAux — see test.)
    // Decrypt block 0: P0 = C0 ⊕ IV.
    //   We need a working copy of C0 so the XOR doesn't destroy it for
    //   block 1's chain reference. (CBC decrypt uses each ciphertext block
    //   as the chain input for the NEXT block.)
    {
      kind: "step",
      id: "p0-working",
      type: "generic.aux-copy@1",
      params: { from: "c0", to: "p0-work" },
    },
    {
      kind: "step",
      id: "p0-xor",
      type: "generic.aux-xor@1",
      params: { from: "iv", into: "p0-work" },
    },
    {
      kind: "step",
      id: "emit-p0",
      type: "generic.aux-copy@1",
      params: { from: "p0-work", to: "p0-out" },
    },
    // Decrypt block 1: P1 = C1 ⊕ C0.
    {
      kind: "step",
      id: "p1-working",
      type: "generic.aux-copy@1",
      params: { from: "c1", to: "p1-work" },
    },
    {
      kind: "step",
      id: "p1-xor",
      type: "generic.aux-xor@1",
      params: { from: "c0", into: "p1-work" },
    },
    {
      kind: "step",
      id: "emit-p1",
      type: "generic.aux-copy@1",
      params: { from: "p1-work", to: "p1-out" },
    },
  ],
});

const xorBytes = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  return out;
};

describe("CBC-from-scratch composition (acceptance test)", () => {
  it("encrypts a 2-block plaintext purely from aux primitives, matching a reference XOR", () => {
    const blockSize = 16;
    const trace = runSpec(cbcEncryptSpec(blockSize), buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });

    // Reference computation done outside the runtime.
    const iv = Uint8Array.from({ length: blockSize }, (_, i) => i);
    const p0 = Uint8Array.from({ length: blockSize }, (_, i) => 0xa0 + i);
    const p1 = Uint8Array.from({ length: blockSize }, (_, i) => 0xb0 + i);
    const refC0 = xorBytes(p0, iv);
    const refC1 = xorBytes(p1, refC0);

    const c0 = trace.finalAux.get("c0");
    const c1 = trace.finalAux.get("c1");
    expect(c0).toBeInstanceOf(Uint8Array);
    expect(c1).toBeInstanceOf(Uint8Array);
    expect(Array.from(c0 as Uint8Array)).toEqual(Array.from(refC0));
    expect(Array.from(c1 as Uint8Array)).toEqual(Array.from(refC1));
  });

  it("decrypts the resulting ciphertext back to the original plaintext", () => {
    const blockSize = 16;

    // First encrypt to obtain c0/c1.
    const encTrace = runSpec(cbcEncryptSpec(blockSize), buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const c0 = encTrace.finalAux.get("c0") as Uint8Array;
    const c1 = encTrace.finalAux.get("c1") as Uint8Array;

    // Now decrypt, seeding c0/c1 via initialAux (the decrypt spec doesn't
    // load them itself — they come from the encrypt side, like real CBC
    // decrypt receives ciphertext from its caller).
    const decTrace = runSpec(cbcDecryptSpec(blockSize), buildDefaultRegistry(), {
      initialState: emptyBytes(),
      initialAux: new Map<string, AuxValue>([
        ["c0", c0],
        ["c1", c1],
      ]),
    });

    const p0Out = decTrace.finalAux.get("p0-out") as Uint8Array;
    const p1Out = decTrace.finalAux.get("p1-out") as Uint8Array;

    const expectedP0 = Uint8Array.from({ length: blockSize }, (_, i) => 0xa0 + i);
    const expectedP1 = Uint8Array.from({ length: blockSize }, (_, i) => 0xb0 + i);

    expect(Array.from(p0Out)).toEqual(Array.from(expectedP0));
    expect(Array.from(p1Out)).toEqual(Array.from(expectedP1));
  });

  it("encrypt spec produces zero orphaned-read / cycle validateGraph warnings (fully wired)", () => {
    // The acceptance test is "this is a valid spec", so the validator should
    // be silent on the dangerous directions. emit-c0/emit-c1 write c0/c1 which
    // are FINAL outputs (no downstream reader in this spec), so those surface
    // as "unused-write" — the validator working correctly. We filter those and
    // assert no ORPHANED reads (uninitialized inputs) or cycles.
    const spec = cbcEncryptSpec(16);
    const trace = runSpec(spec, buildDefaultRegistry(), {
      initialState: emptyBytes(),
    });
    const graph = deriveAuxGraph(trace, spec);
    const warnings = validateGraph(graph, trace);

    const orphans = warnings.filter((w) => w.kind === "orphaned-read");
    expect(orphans).toEqual([]);
    const cycles = warnings.filter((w) => w.kind === "cycle");
    expect(cycles).toEqual([]);
  });
});
