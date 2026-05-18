/**
 * Per-step narration tests for the Phase-3 boundary narrators.
 *
 * Five narrators that bridge between BytesState and MatrixState OR
 * write the iterate-loop scaffolding into aux. Each emits exactly one
 * conceptual unit; the test confirms unit count, the label text, and
 * that the prose names the right counts / shapes.
 */

// @vitest-environment jsdom

import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, BytesState, MatrixState, TraceFrame } from "@/core/types";
import {
  computeBlockCountNarration,
  concatBlocksNarration,
  loadBlockNarration,
  splitBlocksNarration,
  storeBlockNarration,
} from "@/ui/narration/boundary";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const bytesState = (bytes: Uint8Array): BytesState => ({ shape: "bytes", bytes });

const makeFrame = (overrides: Partial<TraceFrame>): TraceFrame => ({
  index: 0,
  path: [],
  stepId: "test.step",
  stepType: "test",
  params: {},
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

// ─── load-block ──────────────────────────────────────────────────────

describe("loadBlockNarration", () => {
  it("emits 1 unit explaining the column-major packing", () => {
    const before = new Uint8Array(16);
    for (let i = 0; i < 16; i++) before[i] = i;
    const after = matrixFromBytes(before);
    const units = loadBlockNarration(
      makeFrame({
        stepType: "generic.load-block@1",
        params: { blockSize: 16 },
        stateBefore: bytesState(before),
        stateAfter: after,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("4×4 column-major matrix");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toMatch(/column-major/);
    expect(text).toContain("FIPS-197");
  });

  it("returns null when stateBefore isn't BytesState", () => {
    const frame = makeFrame({
      stepType: "generic.load-block@1",
      stateBefore: matrixFromBytes(new Uint8Array(16)),
    } as never);
    expect(loadBlockNarration(frame)).toBeNull();
  });
});

// ─── store-block ─────────────────────────────────────────────────────

describe("storeBlockNarration", () => {
  it("emits 1 unit explaining the matrix-to-bytes relabel", () => {
    const before = matrixFromBytes(new Uint8Array(16));
    const after = bytesState(new Uint8Array(16));
    const units = storeBlockNarration(
      makeFrame({
        stepType: "generic.store-block@1",
        stateBefore: before,
        stateAfter: after,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("unpack");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toMatch(/structural relabel/);
  });
});

// ─── split-blocks ────────────────────────────────────────────────────

describe("splitBlocksNarration", () => {
  it("emits 1 unit reporting block count from auxWritten", () => {
    const before = new Uint8Array(32); // 2 blocks
    const blocks: MatrixState[] = [
      matrixFromBytes(new Uint8Array(16)),
      matrixFromBytes(new Uint8Array(16)),
    ];
    const auxWritten = new Map<string, AuxValue>([["ecb-blocks", blocks]]);
    const units = splitBlocksNarration(
      makeFrame({
        stepType: "generic.split-blocks@1",
        params: { blockSize: 16, outBlocksAux: "ecb-blocks" },
        stateBefore: bytesState(before),
        stateAfter: bytesState(before),
        auxWritten,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("2 blocks");
    expect(units[0]?.label).toContain("16 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("32-byte");
    expect(text).toContain("aux[ecb-blocks]");
  });

  it("falls back to length-derived count when auxWritten is missing", () => {
    const before = new Uint8Array(48); // 3 blocks
    const units = splitBlocksNarration(
      makeFrame({
        stepType: "generic.split-blocks@1",
        params: { blockSize: 16, outBlocksAux: "blocks" },
        stateBefore: bytesState(before),
        stateAfter: bytesState(before),
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units[0]?.label).toContain("3 blocks");
  });
});

// ─── concat-blocks ───────────────────────────────────────────────────

describe("concatBlocksNarration", () => {
  it("emits 1 unit reporting block count from auxRead", () => {
    const blocks: MatrixState[] = [
      matrixFromBytes(new Uint8Array(16)),
      matrixFromBytes(new Uint8Array(16)),
    ];
    const auxRead = new Map<string, AuxValue>([["ecb-out", blocks]]);
    const units = concatBlocksNarration(
      makeFrame({
        stepType: "generic.concat-blocks@1",
        params: { blocksAux: "ecb-out" },
        stateBefore: matrixFromBytes(new Uint8Array(16)),
        stateAfter: bytesState(new Uint8Array(32)),
        auxRead,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("2 blocks");
    expect(units[0]?.label).toContain("32 bytes");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("aux[ecb-out]");
  });
});

// ─── compute-block-count ─────────────────────────────────────────────

describe("computeBlockCountNarration", () => {
  it("emits 1 unit reporting the count from auxWritten", () => {
    const auxWritten = new Map<string, AuxValue>([["block-count", 2]]);
    const units = computeBlockCountNarration(
      makeFrame({
        stepType: "generic.compute-block-count@1",
        params: { blockSize: 16, countAux: "block-count" },
        stateBefore: bytesState(new Uint8Array(32)),
        stateAfter: bytesState(new Uint8Array(32)),
        auxWritten,
      }),
    );
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toBe("blockCount = 2");
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain("32 bytes");
    expect(text).toContain("aux[block-count]");
  });
});
