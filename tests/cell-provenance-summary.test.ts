/**
 * Node tests for `summarizeCellProvenance` — the always-on cell-provenance
 * classifier behind the graph leaf inspector's "where each byte comes from"
 * expander (Tier B, 2026-07-13).
 *
 * These run the REAL AES-128 and DES pipelines and pull frames by step type, so
 * the classification is pinned against the actual port I/O the runtime captured
 * (not hand-built frames). The four shapes are each exercised by a primitive
 * where that shape is the honest reading:
 *
 *   - same-index → SubBytes (`byte-substitute@1`), AddRoundKey (`xor-with-aux@1`),
 *                  DES round XOR (`xor@1`)
 *   - offset     → an AES key-schedule word-repack slice (`byte-slice@1`)
 *   - per-cell   → ShiftRows (`permute@1`), MixColumns (`gf-matrix-multiply@1`,
 *                  with GF `×coeff` labels), DES `split-bytes@1` / `concat@1`
 *   - none       → a publish tail (no registered provenance fn / 0 outputs)
 */

import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { summarizeCellProvenance } from "@/core/cell-provenance-summary";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { describe, expect, it } from "vitest";

const runAes = (): Trace =>
  runSpec(aes128EcbSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
    ]),
  });

const runDes = (): Trace =>
  runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("0123456789abcdef")),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex("133457799bbcdff1")]]),
  });

/** All frames of a given bare step type (there are many across the rounds). */
const framesOfType = (trace: Trace, stepType: string): readonly TraceFrame[] =>
  trace.frames.filter((f) => f.stepType === stepType);

/** The first frame of a given step type, or throw (keeps the test honest — a
 *  missing type means the fixture changed and the assertion below is vacuous). */
const firstOfType = (trace: Trace, stepType: string): TraceFrame => {
  const f = framesOfType(trace, stepType)[0];
  if (f === undefined) throw new Error(`no ${stepType} frame in fixture`);
  return f;
};

describe("summarizeCellProvenance — uniform maps collapse", () => {
  it("SubBytes (byte-substitute@1) → same-index on the single `input` port", () => {
    // The first byte-substitute is the key-schedule SubWord (a 4-byte word);
    // round-body SubBytes is 16 bytes. Both are same-index — the position is
    // preserved and only the value changes — so we assert the shape, not the len.
    const s = summarizeCellProvenance(firstOfType(runAes(), "byte-substitute@1"));
    expect(s.kind).toBe("same-index");
    if (s.kind !== "same-index") return;
    expect(s.ports).toEqual(["input"]);
    expect(s.length).toBeGreaterThan(0);
  });

  it("AddRoundKey (xor-with-aux@1) → same-index across `input` + the round-key `operand`", () => {
    const s = summarizeCellProvenance(firstOfType(runAes(), "xor-with-aux@1"));
    expect(s.kind).toBe("same-index");
    if (s.kind !== "same-index") return;
    // The round key was projected onto `operand`, so BOTH ports feed each byte.
    expect(s.ports).toEqual(["input", "operand"]);
    expect(s.length).toBe(16);
  });

  it("DES round XOR (xor@1) → same-index across operand0/operand1", () => {
    const s = summarizeCellProvenance(firstOfType(runDes(), "xor@1"));
    expect(s.kind).toBe("same-index");
    if (s.kind !== "same-index") return;
    expect(s.ports).toEqual(["operand0", "operand1"]);
  });

  it("an AES key-schedule slice (byte-slice@1) is always uniform (offset ≥ 1 collapses to `offset`)", () => {
    const slices = framesOfType(runAes(), "byte-slice@1");
    expect(slices.length).toBeGreaterThan(0);
    // Every slice collapses — a contiguous window never enumerates per-cell.
    for (const f of slices) {
      const kind = summarizeCellProvenance(f).kind;
      expect(kind === "same-index" || kind === "offset").toBe(true);
    }
    // The word-repack slices at offsets 1/2/3 give the non-trivial `offset` form.
    const offsetForms = slices
      .map((f) => summarizeCellProvenance(f))
      .filter((s) => s.kind === "offset");
    expect(offsetForms.length).toBeGreaterThan(0);
    const first = offsetForms[0];
    if (first !== undefined && first.kind === "offset") {
      expect(first.port).toBe("input");
      expect(first.offset).toBeGreaterThanOrEqual(1);
    }
  });
});

describe("summarizeCellProvenance — non-uniform maps enumerate per-cell", () => {
  it("ShiftRows (permute@1) → per-cell, and at least one byte is gathered from a DIFFERENT index", () => {
    // The first permute is the key-schedule RotWord (4-byte rotate); round-body
    // ShiftRows is 16 bytes. Either way it MOVES bytes, so it never collapses.
    const s = summarizeCellProvenance(firstOfType(runAes(), "permute@1"));
    expect(s.kind).toBe("per-cell");
    if (s.kind !== "per-cell") return;
    expect(s.rows.length).toBeGreaterThan(0);
    // A pure permutation moves at least one byte — otherwise it would have
    // collapsed to same-index. Prove the gather is real.
    const moved = s.rows.some(
      (r) => r.sources.length === 1 && r.sources[0]?.cellIndex !== r.outIndex,
    );
    expect(moved).toBe(true);
  });

  it("MixColumns (gf-matrix-multiply@1) → per-cell with GF `×coeff` labels", () => {
    const s = summarizeCellProvenance(firstOfType(runAes(), "gf-matrix-multiply@1"));
    expect(s.kind).toBe("per-cell");
    if (s.kind !== "per-cell") return;
    // The MDS matrix mixes 3–4 same-column contributors per output byte, each
    // carrying its coefficient — the label channel is why this never collapses.
    const labelled = s.rows.some((r) => r.sources.some((src) => src.label !== undefined));
    expect(labelled).toBe(true);
    const multiSource = s.rows.some((r) => r.sources.length >= 2);
    expect(multiSource).toBe(true);
  });

  it("DES split-bytes@1 → per-cell across the two output ports", () => {
    const s = summarizeCellProvenance(firstOfType(runDes(), "split-bytes@1"));
    expect(s.kind).toBe("per-cell");
    if (s.kind !== "per-cell") return;
    const outPorts = new Set(s.rows.map((r) => r.outPort));
    expect(outPorts.size).toBeGreaterThanOrEqual(2); // output0 + output1
  });

  it("DES concat@1 → per-cell (global index resolves to different input ports)", () => {
    const s = summarizeCellProvenance(firstOfType(runDes(), "concat@1"));
    expect(s.kind).toBe("per-cell");
    if (s.kind !== "per-cell") return;
    const inPorts = new Set(s.rows.flatMap((r) => r.sources.map((src) => src.portName)));
    expect(inPorts.size).toBeGreaterThanOrEqual(2); // input0 + input1
  });
});

describe("summarizeCellProvenance — no fn / no outputs → none", () => {
  it("a publish tail (des.publish-round-keys@1) has no provenance fn → none", () => {
    // The key-schedule terminal leaf: 16 input ports, 0 output ports, aux fan-out.
    const publish = framesOfType(runDes(), "des.publish-round-keys@1")[0];
    expect(publish).toBeDefined();
    if (publish !== undefined) {
      expect(summarizeCellProvenance(publish).kind).toBe("none");
    }
  });
});
