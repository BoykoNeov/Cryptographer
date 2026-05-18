/**
 * Per-step narration tests for the Phase-3 padding narrators.
 *
 * Six narrators (pkcs7/zero/iso7816-4 × pad/unpad). Each emits exactly
 * one conceptual unit; the test confirms unit count, label format, and
 * that the rendered prose names the right input/output lengths and the
 * right pad-byte value.
 *
 * `// @vitest-environment jsdom` — Prose components need a DOM to render.
 */

// @vitest-environment jsdom

import type { AuxValue, BytesState, TraceFrame } from "@/core/types";
import {
  iso78164PadNarration,
  iso78164UnpadNarration,
  pkcs7PadNarration,
  pkcs7UnpadNarration,
  zeroPadNarration,
  zeroUnpadNarration,
} from "@/ui/narration/padding";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const bytesState = (bytes: Uint8Array): BytesState => ({ shape: "bytes", bytes });

const makeFrame = (overrides: Partial<TraceFrame>): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: { blockSize: 16 },
  stateBefore: bytesState(new Uint8Array(0)),
  stateAfter: bytesState(new Uint8Array(0)),
  auxRead: new Map<string, AuxValue>(),
  auxWritten: new Map(),
  ...overrides,
});

const proseText = (Prose: (props: { fmt: "hex" }) => unknown): string => {
  const result = render(() => Prose({ fmt: "hex" }) as never);
  const text = result.container.textContent ?? "";
  result.unmount();
  return text;
};

// ─── PKCS#7 pad ──────────────────────────────────────────────────────

describe("pkcs7PadNarration", () => {
  it("emits 1 unit naming the pad-length byte for a 5→16 pad", () => {
    const before = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]); // "apple"
    const after = new Uint8Array(16);
    after.set(before, 0);
    after.fill(0x0b, 5); // 11 copies of 0x0b
    const units = pkcs7PadNarration(
      makeFrame({
        stepType: "generic.pkcs7-pad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("11 bytes");
    expect(units[0]?.label).toContain("0x0b");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("5 bytes");
    expect(text).toContain("16 byte"); // output length
    expect(text).toContain("11"); // pad length
  });

  it("returns null when stateBefore isn't BytesState", () => {
    const frame = makeFrame({
      stepType: "generic.pkcs7-pad@1",
      stateBefore: { shape: "matrix4x4-bytes", bytes: new Uint8Array(16) },
    } as never);
    expect(pkcs7PadNarration(frame)).toBeNull();
  });
});

// ─── PKCS#7 unpad ────────────────────────────────────────────────────

describe("pkcs7UnpadNarration", () => {
  it("emits 1 unit reading the trailing byte and reporting the strip count", () => {
    const before = new Uint8Array(16);
    before.set([0x61, 0x70, 0x70, 0x6c, 0x65], 0);
    before.fill(0x0b, 5);
    const after = new Uint8Array(before.subarray(0, 5));
    const units = pkcs7UnpadNarration(
      makeFrame({
        stepType: "generic.pkcs7-unpad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("11 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("trailing byte");
    expect(text).toContain("0b"); // trailing byte in hex (no 0x prefix from formatByte)
    expect(text).toContain("5 bytes"); // remaining length
  });
});

// ─── Zero pad ────────────────────────────────────────────────────────

describe("zeroPadNarration", () => {
  it("emits 1 unit naming the zero-fill length", () => {
    const before = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);
    const after = new Uint8Array(16);
    after.set(before, 0);
    const units = zeroPadNarration(
      makeFrame({
        stepType: "generic.zero-pad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("11 byte");
    expect(units[0]?.label).toContain("0x00");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("5 bytes");
    expect(text).toMatch(/Append 11/);
  });

  it("special-cases the N=0 no-op when input is already aligned", () => {
    const before = new Uint8Array(16);
    const after = new Uint8Array(16);
    const units = zeroPadNarration(
      makeFrame({
        stepType: "generic.zero-pad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units[0]?.label).toMatch(/already aligned/);
  });
});

// ─── Zero unpad ──────────────────────────────────────────────────────

describe("zeroUnpadNarration", () => {
  it("emits 1 unit reporting the number of trailing zeros stripped", () => {
    const before = new Uint8Array(16);
    before.set([0x61, 0x70, 0x70, 0x6c, 0x65], 0);
    // Remaining bytes are 0x00 by default.
    const after = new Uint8Array(before.subarray(0, 5));
    const units = zeroUnpadNarration(
      makeFrame({
        stepType: "generic.zero-unpad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("11 trailing 0x00 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toMatch(/Lossy/);
  });
});

// ─── ISO 7816-4 pad ──────────────────────────────────────────────────

describe("iso78164PadNarration", () => {
  it("emits 1 unit naming the 0x80 sentinel and trailing-zero count", () => {
    const before = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);
    const after = new Uint8Array(16);
    after.set(before, 0);
    after[5] = 0x80;
    // Remaining bytes are zero by default.
    const units = iso78164PadNarration(
      makeFrame({
        stepType: "generic.iso7816-4-pad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("0x80 sentinel");
    expect(units[0]?.label).toContain("10 zeros");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("80"); // sentinel in hex
    expect(text).toContain("5 bytes"); // input length
  });
});

// ─── ISO 7816-4 unpad ────────────────────────────────────────────────

describe("iso78164UnpadNarration", () => {
  it("emits 1 unit naming the sentinel offset and strip count", () => {
    const before = new Uint8Array(16);
    before.set([0x61, 0x70, 0x70, 0x6c, 0x65], 0);
    before[5] = 0x80;
    const after = new Uint8Array(before.subarray(0, 5));
    const units = iso78164UnpadNarration(
      makeFrame({
        stepType: "generic.iso7816-4-unpad@1",
        stateBefore: bytesState(before),
        stateAfter: bytesState(after),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("offset 5");
    expect(units[0]?.label).toContain("11 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("80"); // sentinel byte
    expect(text).toMatch(/offset 5/); // sentinel position
  });
});
