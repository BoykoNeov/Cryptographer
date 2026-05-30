/**
 * Slice 2.0b-ii of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-2-slices.md`).
 *
 * Focused unit tests pinning the two new contract surfaces introduced by
 * lifting `split-blocks@1` and `concat-blocks@1` to `kind: "ported"`:
 *
 *   1. **`"matrix-cm-4x4-array"` layout round-trip.** The new aux-layout
 *      tag carries a `MatrixState[]` as concatenated bytes (16 per
 *      element). `auxValueToPortBytes(MatrixState[])` → bytes →
 *      `auxPortBytesToValue(bytes, "matrix-cm-4x4-array")` must produce a
 *      byte-equal `MatrixState[]`.
 *
 *   2. **`stateToBytes` "bytes" relaxation (user pick option C).** When
 *      the expected layout is `"bytes"`, any non-bigint State variant is
 *      accepted by reading `.bytes` (or `.bits` for bitvec) directly.
 *      Unblocks shape-transforming lifts like `concat-blocks` (matrix-in,
 *      bytes-out) without an asymmetric `stateInputLayout`/
 *      `stateOutputLayout` widening.
 *
 * Frame-parity coverage for the actual lifted step types lives in
 * `runtime-ported-dispatch-frame-parity.test.ts` (Slice 1.11 matrix —
 * AES-128 ECB encrypt/decrypt + AES-128 CBC encrypt/decrypt). After this
 * slice, those rows automatically exercise the new layout's encode/
 * decode round-trip end-to-end. This file is the **tight diagnostic** —
 * if a future change to the layout-tag rules breaks the matrix, these
 * focused tests narrow attribution to the helper layer.
 */

import {
  auxPortBytesToValue,
  auxValueToPortBytes,
  portBytesToState,
  stateToPortBytes,
} from "@/core/port-projection";
import type { AuxValue, MatrixState, State } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── Helper: build a MatrixState from 16 sequential bytes ───────────────
//
// `start` lets each fixture matrix carry distinct bytes so a concat-then-
// re-slice that fluffs alignment surfaces as a per-element value drift
// (not just length drift). Mirror of `matrixFromBytes` semantics minus
// the column-major reordering — for THIS test, we never interpret the
// bytes as a matrix; we just need 16-byte uniquely-distinguishable
// payloads that ride through the helpers.

const makeMatrix = (start: number): MatrixState => {
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = (start + i) & 0xff;
  return { shape: "matrix4x4-bytes", bytes };
};

describe('aux layout "matrix-cm-4x4-array" round-trip (Slice 2.0b-ii)', () => {
  it("encodes MatrixState[] as concatenated bytes preserving element order", () => {
    const blocks: MatrixState[] = [makeMatrix(0x00), makeMatrix(0x10), makeMatrix(0x20)];
    const encoded = auxValueToPortBytes(blocks, "test-blocks");
    expect(encoded.length).toBe(48);
    // First 16 bytes are block 0 (0x00..0x0f); next 16 are block 1
    // (0x10..0x1f); last 16 are block 2 (0x20..0x2f).
    for (let i = 0; i < 16; i++) expect(encoded[i]).toBe(0x00 + i);
    for (let i = 0; i < 16; i++) expect(encoded[16 + i]).toBe(0x10 + i);
    for (let i = 0; i < 16; i++) expect(encoded[32 + i]).toBe(0x20 + i);
  });

  it("decodes concatenated bytes back to a byte-equal MatrixState[]", () => {
    const blocks: MatrixState[] = [makeMatrix(0xa0), makeMatrix(0xb0)];
    const encoded = auxValueToPortBytes(blocks, "test-blocks");
    const decoded = auxPortBytesToValue(encoded, "matrix-cm-4x4-array");
    expect(Array.isArray(decoded)).toBe(true);
    const out = decoded as readonly State[];
    expect(out.length).toBe(2);
    for (let i = 0; i < 2; i++) {
      const original = blocks[i] as MatrixState;
      const recovered = out[i] as MatrixState;
      expect(recovered.shape).toBe("matrix4x4-bytes");
      expect(Array.from(recovered.bytes)).toEqual(Array.from(original.bytes));
    }
  });

  it("empty State[] round-trips as zero-byte payload + empty array", () => {
    // Empty multi-block input is degenerate but legal — split-blocks on a
    // zero-length state writes [] to aux; the lift's helpers must not
    // special-case the boundary.
    const encoded = auxValueToPortBytes([], "test-blocks");
    expect(encoded.length).toBe(0);
    const decoded = auxPortBytesToValue(encoded, "matrix-cm-4x4-array");
    expect(Array.isArray(decoded)).toBe(true);
    expect((decoded as readonly State[]).length).toBe(0);
  });

  it("produces independent buffers per decoded element (no aliasing)", () => {
    // The decoder must `slice` (not `subarray`) per-element so a mutation
    // on one decoded block can't reach into the encoded source buffer or
    // a sibling block's bytes. Mirrors the per-element copy
    // `split-blocks`'s legacy executor performs via `matrixFromBytes`.
    const blocks: MatrixState[] = [makeMatrix(0x00), makeMatrix(0x10)];
    const encoded = auxValueToPortBytes(blocks, "test-blocks");
    const decoded = auxPortBytesToValue(encoded, "matrix-cm-4x4-array") as readonly State[];
    const block0 = decoded[0] as MatrixState;
    const block1 = decoded[1] as MatrixState;
    // Mutate block0's bytes; block1 + encoded must stay untouched.
    (block0.bytes as Uint8Array)[0] = 0xff;
    expect(block1.bytes[0]).toBe(0x10);
    expect(encoded[0]).toBe(0x00);
    expect(encoded[16]).toBe(0x10);
  });

  it("decode throws on non-16-multiple length", () => {
    const bytes = new Uint8Array(17); // 17 is not divisible by 16
    expect(() => auxPortBytesToValue(bytes, "matrix-cm-4x4-array")).toThrow(/divisible by 16/);
  });

  it("encode throws on a non-State element (mid-array)", () => {
    // Per-element validation must surface at the encoding boundary, not
    // get silently coerced into wrong-length output bytes the decoder
    // would either accept (wrong element count) or reject several
    // frames downstream (mis-attributing the bug).
    const bad: unknown[] = [
      makeMatrix(0x00),
      { not: "a state" }, // missing shape + bytes
      makeMatrix(0x20),
    ];
    expect(() => auxValueToPortBytes(bad as AuxValue, "test-blocks")).toThrow(
      /\[1\] is not a State variant/,
    );
  });

  it("encode throws on a null element", () => {
    const bad: unknown[] = [makeMatrix(0x00), null];
    expect(() => auxValueToPortBytes(bad as AuxValue, "test-blocks")).toThrow(
      /\[1\] is not a State variant/,
    );
  });
});

// ─── stateToBytes "bytes" relaxation (option C, 2026-05-24) ─────────────

describe('stateToBytes relaxation: expected:"bytes" accepts the matrix4x4-bytes variant', () => {
  it("encodes a matrix4x4-bytes state as raw bytes when expected is bytes", () => {
    // concat-blocks's load-bearing case: iterate leaves a 16-byte
    // matrix4x4-bytes in the runtime's `state` variable; concatBlocksMeta
    // declares stateLayout:"bytes"; the encode must succeed.
    const state: MatrixState = makeMatrix(0x40);
    const bytes = stateToPortBytes(state, "bytes");
    expect(bytes.length).toBe(16);
    for (let i = 0; i < 16; i++) expect(bytes[i]).toBe(0x40 + i);
  });

  it("strict path still rejects matrix4x4-bytes when expected is matrix4x4-bytes... vs bytes", () => {
    // Sanity floor: the relaxation is one-directional. matrix4x4-bytes
    // can still be encoded under the matching matrix4x4-bytes expected;
    // and a BytesState that lies about its shape would still fail under
    // the strict matrix4x4-bytes expected. Asserting both anchors keeps
    // the relaxation's blast radius bounded.
    const matrix: MatrixState = makeMatrix(0x70);
    // Matching expected: works.
    const matched = stateToPortBytes(matrix, "matrix4x4-bytes");
    expect(matched.length).toBe(16);

    // Mismatched expected (BytesState ⇒ matrix4x4-bytes): still throws.
    const bytesState: State = {
      shape: "bytes",
      bytes: new Uint8Array(16),
    };
    expect(() => stateToPortBytes(bytesState, "matrix4x4-bytes")).toThrow(
      /state shape bytes does not match expected matrix4x4-bytes/,
    );
  });

  it("decode under bytes layout: any-length bytes reconstruct as BytesState", () => {
    // Symmetric anchor — the decode side (`portBytesToState` with
    // layout "bytes") was already length-agnostic per Slice 1.12
    // case "bytes"; assert it stays so. concat-blocks's variable-
    // length output relies on this.
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const recovered = portBytesToState(bytes, "bytes");
    expect(recovered.shape).toBe("bytes");
    if (recovered.shape === "bytes") {
      expect(Array.from(recovered.bytes)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05]);
    }
  });
});
