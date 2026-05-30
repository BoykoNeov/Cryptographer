/**
 * Slice 1.12 follow-up — caveat 1 ("state-port coercion path mechanically
 * reachable but uncovered by fixture") from
 * `docs/plans/universal-port-phase-1-slices.md`.
 *
 * The matrix-layout defensive throws this file originally pinned
 * (`bytesToState`'s `matrix4x4-bytes` length check + `auxPortBytesToValue`'s
 * `matrix-cm-4x4` checks) were retired in Phase 5 Slice 5.1 (2026-05-30)
 * with the `MatrixState` shape — there is no longer a fixed-length non-bytes
 * layout to mis-coerce into. What survives is the deliberate
 * length-AGNOSTIC posture of the `bytes` layout (wiring-determined per Slice
 * 1.2's polymorphic-port pick) and the `coerceToByteLength` helper contract.
 */

import {
  COERCE_STEP_TYPE,
  auxPortBytesToValue,
  coerceToByteLength,
  portBytesToState,
} from "@/core/port-projection";
import type { AuxValue } from "@/core/types";
import { describe, expect, it } from "vitest";

// ─── bytesToState (state-port reconstruction) ────────────────────────────

describe("bytesToState — bytes layout is intentionally length-agnostic", () => {
  // Negative pin: the `bytes` shape is wiring-determined per the Slice 1.2
  // polymorphic-port user pick. Any length is legal — a future refactor that
  // adds a length check here knows it's breaking a deliberate posture.
  it("accepts any input length (0, 8, 16, 100)", () => {
    for (const len of [0, 8, 16, 100]) {
      const bytes = new Uint8Array(len);
      expect(() => portBytesToState(bytes, "bytes")).not.toThrow();
    }
  });
});

// ─── auxPortBytesToValue (aux-port reconstruction) ───────────────────────

describe("auxPortBytesToValue — preserve-input-variant, bytes source", () => {
  it("accepts any length when source variant is bytes (intentionally length-agnostic)", () => {
    // The `bytes` variant carries variable-length info, so the
    // preserve-input-variant path stays length-agnostic for it. Mirror of
    // the bytesToState "bytes" posture.
    const hint: AuxValue = { shape: "bytes", bytes: new Uint8Array(0) };
    for (const len of [0, 4, 8, 100]) {
      const bytes = new Uint8Array(len);
      expect(() => auxPortBytesToValue(bytes, "preserve-input-variant", hint)).not.toThrow();
    }
  });
});

// ─── coerceToByteLength helper sanity ────────────────────────────────────

describe("coerceToByteLength — exposed for direct callers (Slice 1.12)", () => {
  // Light sanity coverage so the helper's contract is pinned outside the
  // runtime integration path. Re-uses the COERCE_STEP_TYPE import as a
  // smoke that the symbol exports cleanly.
  it("right-pads short input with zeros", () => {
    const result = coerceToByteLength(new Uint8Array([1, 2, 3]), 5);
    expect(result.mode).toBe("right-pad");
    expect(Array.from(result.bytes)).toEqual([1, 2, 3, 0, 0]);
  });

  it("truncates long input from the right (keeps leftmost N)", () => {
    const result = coerceToByteLength(new Uint8Array([1, 2, 3, 4, 5]), 3);
    expect(result.mode).toBe("truncate-right");
    expect(Array.from(result.bytes)).toEqual([1, 2, 3]);
  });

  it("exact match returns exact-mode result with reference-equal bytes", () => {
    const src = new Uint8Array([1, 2, 3]);
    const result = coerceToByteLength(src, 3);
    expect(result.mode).toBe("exact");
    expect(result.bytes).toBe(src);
  });

  it("COERCE_STEP_TYPE export is the sentinel literal __coerce__", () => {
    expect(COERCE_STEP_TYPE).toBe("__coerce__");
  });
});
