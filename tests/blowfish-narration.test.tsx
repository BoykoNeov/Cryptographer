/**
 * Per-frame value-prose narration tests for the two Blowfish-only narrators
 * (2026-07-11): `blowfish.sbox-lookup@1` and `blowfish.key-schedule@1`.
 *
 * Both are driven off REAL trace frames (the Blowfish spec run through the
 * runtime), not fabricated ones — so these tests double as the verification
 * that the 521-loop monolith frame actually publishes `blowfish.P.*` /
 * `blowfish.S*` into `auxWritten` (via `meta.auxWritePorts`), which is what
 * lets the disclosure rows show real values rather than static text.
 */

// @vitest-environment jsdom

import { blowfishSpec } from "@/ciphers/blowfish";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { formatBytes } from "@/ui/components/byte-row";
import { blowfishKeyScheduleNarration, blowfishSboxLookupNarration } from "@/ui/narration/blowfish";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const runBlowfish = (): Trace =>
  runSpec(blowfishSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("1111111111111111")),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex("0123456789abcdef")]]),
  });

const frameById = (trace: Trace, stepId: string): TraceFrame => {
  const f = trace.frames.find((fr) => fr.stepId === stepId);
  if (!f) throw new Error(`no frame with stepId "${stepId}" in trace`);
  return f;
};

const proseText = (Prose: (props: { fmt: "hex" }) => unknown): string => {
  const result = render(() => Prose({ fmt: "hex" }) as never);
  const text = result.container.textContent ?? "";
  result.unmount();
  return text;
};

// ─── blowfish.sbox-lookup@1 ────────────────────────────────────────────────

describe("blowfishSboxLookupNarration", () => {
  it("emits 1 unit naming the specific S-box and the resolved 32-bit word", () => {
    const trace = runBlowfish();
    const frame = frameById(trace, "round.1.s0");
    const units = blowfishSboxLookupNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    // Label names the box (S0) and reads as an entry lookup.
    expect(units[0]?.label).toContain("S0");
    expect(units[0]?.label).toContain("entry");
    // Prose shows the actual 4-byte output word (hex) the port produced.
    const out = frame.portOutputs?.get("output");
    expect(out).toBeInstanceOf(Uint8Array);
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain(formatBytes(out as Uint8Array, "hex"));
    expect(text).toContain("key-derived");
  });

  it("returns null for a frame whose ports aren't the 1-byte-in / 4-byte-out shape", () => {
    const trace = runBlowfish();
    // A split leaf has no `index`/`output` ports of that shape.
    const frame = frameById(trace, "round.1.split");
    expect(blowfishSboxLookupNarration(frame)).toBeNull();
  });
});

// ─── blowfish.key-schedule@1 (the monolith) ────────────────────────────────

describe("blowfishKeyScheduleNarration", () => {
  it("emits coarse disclosure rows (mix / P-fill / S-fill / result)", () => {
    const trace = runBlowfish();
    const frame = frameById(trace, "key-schedule.loop");
    const units = blowfishKeyScheduleNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    // Four coarse rows — NOT 521 per-encryption disclosures.
    expect(units.map((u) => u.key)).toEqual(["mix", "pfill", "sfill", "result"]);
  });

  it("verifies the monolith frame publishes P/S to auxWritten AND shows a real P word", () => {
    const trace = runBlowfish();
    const frame = frameById(trace, "key-schedule.loop");
    // The advisor's pre-build concern: the monolith frame must carry the
    // published key material for the rows to show real values.
    expect(frame.auxWritten.get("blowfish.P.0")).toBeInstanceOf(Uint8Array);
    expect(frame.auxWritten.get("blowfish.S3")).toBeInstanceOf(Uint8Array);
    const units = blowfishKeyScheduleNarration(frame);
    if (!units) throw new Error("expected units");
    const pfill = units.find((u) => u.key === "pfill");
    expect(pfill).toBeDefined();
    const p0 = frame.auxWritten.get("blowfish.P.0") as Uint8Array;
    const text = proseText(pfill?.Prose ?? (() => null));
    expect(text).toContain("P[0]");
    expect(text).toContain(formatBytes(p0, "hex"));
  });

  it("returns null when the frame published no P material (unwired monolith)", () => {
    const bare: TraceFrame = {
      index: 0,
      path: [],
      stepId: "key-schedule.loop",
      stepType: "blowfish.key-schedule@1",
      params: { outputPrefix: "blowfish" },
      auxRead: new Map<string, AuxValue>(),
      auxWritten: new Map<string, AuxValue>(),
    };
    expect(blowfishKeyScheduleNarration(bare)).toBeNull();
  });
});
