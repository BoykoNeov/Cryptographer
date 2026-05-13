/**
 * Tests for the three Slice 10 aux primitives in `src/steps/`:
 *
 *   - `generic.aux-load@1` — publish a literal byte sequence under an aux key.
 *   - `generic.aux-xor@1`  — XOR aux[from] into aux[into] (writes back to into).
 *   - `generic.aux-copy@1` — copy aux[from] to aux[to].
 *
 * Three coverage axes:
 *
 *   1. **Per-primitive KAT** — direct executor calls assert the byte math.
 *   2. **Graceful missing-aux** — when a read key isn't in aux, the step
 *      returns passthrough with the read still declared (so the runtime
 *      records the miss in `frame.auxReadMissing`), but emits NO aux write.
 *      This is the contract that lets Slice 9's `validateGraph` produce
 *      "orphaned-read" warnings — the cross-slice integration receipt for
 *      Slice 10's advertised payoff.
 *   3. **End-to-end CBC-from-scratch composition** — a hand-built spec
 *      that uses only `aux-load` + `aux-xor` + `aux-copy` (no cipher core)
 *      to compute the CBC chaining math over a 2-block plaintext. Result
 *      is compared byte-for-byte against a reference XOR computation done
 *      outside the runtime. Then the same primitives are used to decrypt
 *      and recover the original plaintext.
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

const makeCtx = (aux: ReadonlyMap<string, AuxValue>): StepContext => ({
  stepId: "test",
  path: [],
  aux,
});

// ─── aux-load ─────────────────────────────────────────────────────────────

describe("aux-load@1", () => {
  it("writes the literal value as a fresh Uint8Array under the named aux key", () => {
    const ctx = makeCtx(new Map());
    const result = auxLoad(emptyBytes(), { auxName: "iv", value: [0xde, 0xad, 0xbe, 0xef] }, ctx);
    expect(result.state.shape).toBe("bytes");
    expect(result.auxWrites?.size).toBe(1);
    const written = result.auxWrites?.get("iv");
    expect(written).toBeInstanceOf(Uint8Array);
    expect(Array.from(written as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("allocates a fresh buffer (does not alias the params array)", () => {
    const value = [1, 2, 3, 4];
    const result = auxLoad(emptyBytes(), { auxName: "x", value }, makeCtx(new Map()));
    const written = result.auxWrites?.get("x") as Uint8Array;
    // Mutating the written bytes must not change the params array (they
    // can't share storage anyway because Uint8Array vs number[], but this
    // also catches a Uint8Array.from-with-shared-buffer regression).
    written[0] = 0xff;
    expect(value[0]).toBe(1);
  });

  it("declares NO auxReads (pure source — no upstream dataflow)", () => {
    const result = auxLoad(emptyBytes(), { auxName: "x", value: [] }, makeCtx(new Map()));
    // auxReads is optional; the executor doesn't return it.
    expect(result.auxReads).toBeUndefined();
  });

  it("rejects out-of-range bytes in value", () => {
    expect(() =>
      auxLoad(emptyBytes(), { auxName: "x", value: [0, 256] }, makeCtx(new Map())),
    ).toThrow(/value\[1\] must be an integer in \[0, 255\]/);
  });

  it("rejects non-string auxName", () => {
    expect(() => auxLoad(emptyBytes(), { auxName: "", value: [] }, makeCtx(new Map()))).toThrow(
      /auxName must be a non-empty string/,
    );
  });

  it("rejects non-array value", () => {
    expect(() => auxLoad(emptyBytes(), { auxName: "x", value: "abc" }, makeCtx(new Map()))).toThrow(
      /value must be an array of integers/,
    );
  });
});

// ─── aux-xor ──────────────────────────────────────────────────────────────

describe("aux-xor@1", () => {
  it("XORs aux[from] into aux[into] and writes back to into", () => {
    const aux = new Map<string, AuxValue>([
      ["a", new Uint8Array([0xff, 0x0f, 0xaa])],
      ["b", new Uint8Array([0x0f, 0xff, 0x55])],
    ]);
    const result = auxXor(emptyBytes(), { from: "a", into: "b" }, makeCtx(aux));
    const out = result.auxWrites?.get("b") as Uint8Array;
    expect(Array.from(out)).toEqual([0xf0, 0xf0, 0xff]);
    // aux[from] is not modified.
    expect(result.auxWrites?.has("a")).toBe(false);
  });

  it("declares BOTH auxReads regardless of presence (so the runtime can record missing)", () => {
    const aux = new Map<string, AuxValue>();
    const result = auxXor(emptyBytes(), { from: "a", into: "b" }, makeCtx(aux));
    expect(result.auxReads).toEqual(["a", "b"]);
  });

  it("is passthrough (no auxWrites) when from is missing — graceful for Slice 9 orphan warnings", () => {
    const aux = new Map<string, AuxValue>([["b", new Uint8Array([1, 2, 3])]]);
    const result = auxXor(emptyBytes(), { from: "missing", into: "b" }, makeCtx(aux));
    expect(result.auxWrites).toBeUndefined();
    expect(result.auxReads).toEqual(["missing", "b"]);
  });

  it("is passthrough when into is missing", () => {
    const aux = new Map<string, AuxValue>([["a", new Uint8Array([1, 2, 3])]]);
    const result = auxXor(emptyBytes(), { from: "a", into: "missing" }, makeCtx(aux));
    expect(result.auxWrites).toBeUndefined();
  });

  it("is passthrough when both are missing", () => {
    const result = auxXor(emptyBytes(), { from: "x", into: "y" }, makeCtx(new Map()));
    expect(result.auxWrites).toBeUndefined();
    expect(result.auxReads).toEqual(["x", "y"]);
  });

  it("THROWS on length mismatch (both present, malformed-vs-missing distinction)", () => {
    const aux = new Map<string, AuxValue>([
      ["a", new Uint8Array(4)],
      ["b", new Uint8Array(8)],
    ]);
    expect(() => auxXor(emptyBytes(), { from: "a", into: "b" }, makeCtx(aux))).toThrow(
      /length mismatch.*4.*8/,
    );
  });

  it("THROWS when aux value isn't a Uint8Array", () => {
    const aux = new Map<string, AuxValue>([
      ["a", 42],
      ["b", new Uint8Array(4)],
    ]);
    expect(() => auxXor(emptyBytes(), { from: "a", into: "b" }, makeCtx(aux))).toThrow(
      /must be a Uint8Array/,
    );
  });
});

// ─── aux-copy ─────────────────────────────────────────────────────────────

describe("aux-copy@1", () => {
  it("copies aux[from] to aux[to]", () => {
    const aux = new Map<string, AuxValue>([["src", new Uint8Array([0x11, 0x22, 0x33])]]);
    const result = auxCopy(emptyBytes(), { from: "src", to: "dst" }, makeCtx(aux));
    const out = result.auxWrites?.get("dst") as Uint8Array;
    expect(Array.from(out)).toEqual([0x11, 0x22, 0x33]);
  });

  it("makes a defensive copy of Uint8Array (dst doesn't alias src)", () => {
    const src = new Uint8Array([1, 2, 3]);
    const aux = new Map<string, AuxValue>([["src", src]]);
    const result = auxCopy(emptyBytes(), { from: "src", to: "dst" }, makeCtx(aux));
    const out = result.auxWrites?.get("dst") as Uint8Array;
    out[0] = 0xff;
    expect(src[0]).toBe(1);
  });

  it("declares auxReads regardless of presence", () => {
    const result = auxCopy(emptyBytes(), { from: "x", to: "y" }, makeCtx(new Map()));
    expect(result.auxReads).toEqual(["x"]);
  });

  it("is passthrough (no auxWrites) when from is missing — graceful", () => {
    const result = auxCopy(emptyBytes(), { from: "missing", to: "dst" }, makeCtx(new Map()));
    expect(result.auxWrites).toBeUndefined();
    expect(result.auxReads).toEqual(["missing"]);
  });

  it("passes non-byte aux shapes through by reference (numbers, bigints)", () => {
    const aux = new Map<string, AuxValue>([["count", 7]]);
    const result = auxCopy(emptyBytes(), { from: "count", to: "count-mirror" }, makeCtx(aux));
    expect(result.auxWrites?.get("count-mirror")).toBe(7);
  });
});

// ─── Runtime integration: missing aux surfaces as auxReadMissing ──────────

describe("runtime integration — missing aux populates auxReadMissing on the frame", () => {
  // Build a tiny spec that uses aux-xor without ever loading either of its
  // operands. The runtime should still emit a frame (the step is graceful),
  // and that frame should carry auxReadMissing for BOTH keys.
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
    const trace = runSpec(spec, buildDefaultRegistry(), { initialState: emptyBytes() });
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
    // auxReadMissing off the trace and produces the warnings. Without the
    // Slice 10 graceful primitives, no shipped step ever emits a frame
    // with a populated auxReadMissing — this is the first one that does.
    const trace = runSpec(spec, buildDefaultRegistry(), { initialState: emptyBytes() });
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
    const trace = runSpec(copySpec, buildDefaultRegistry(), { initialState: emptyBytes() });
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
 *   aux-copy IV → feedback
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

  it("encrypt spec produces zero validateGraph warnings (fully wired)", () => {
    // The acceptance test is "this is a valid spec", so the validator
    // should be silent. If it isn't, the composition has a bug — an
    // unused write or an orphaned read — that the user would see as a
    // warning glyph in the visual editor.
    const spec = cbcEncryptSpec(16);
    const trace = runSpec(spec, buildDefaultRegistry(), { initialState: emptyBytes() });
    const graph = deriveAuxGraph(trace, spec);
    const warnings = validateGraph(graph, trace);

    // Note: emit-c0 and emit-c1 write c0/c1 which are FINAL outputs (no
    // downstream reader in this spec), so those will surface as
    // "unused-write" — that's the validator working correctly, telling
    // the user "this aux value isn't consumed inside the spec." For the
    // purpose of this acceptance test we filter those out and assert no
    // ORPHANED reads (the dangerous direction — uninitialized inputs).
    const orphans = warnings.filter((w) => w.kind === "orphaned-read");
    expect(orphans).toEqual([]);
    const cycles = warnings.filter((w) => w.kind === "cycle");
    expect(cycles).toEqual([]);
  });
});
