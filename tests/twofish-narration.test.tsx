/**
 * Per-frame value-prose narration tests for the two Twofish-only narrators
 * (2026-07-12): `twofish.sbox-lookup@1` and `twofish.h-expand@1`.
 *
 * Both are driven off REAL trace frames (the Twofish spec run through the
 * runtime), not fabricated ones — so these tests double as the verification
 * that the opaque h-expand frame actually publishes `twofish.A.*` /
 * `twofish.S*` into `auxWritten` (via `meta.auxWritePorts`) AND exposes the
 * S-vector / master-key words in `portOutputs` (the display-only ports), which
 * is what lets the disclosure rows show the run's REAL values rather than
 * static text (the user's explicit requirement for the opaque block).
 */

// @vitest-environment jsdom

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { twofishSpec } from "@/ciphers/twofish";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { formatBytes } from "@/ui/components/byte-row";
import { twofishHExpandNarration, twofishSboxLookupNarration } from "@/ui/narration/twofish";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, describe, expect, it } from "vitest";

afterEach(cleanup);

const runTwofish = (): Trace =>
  runSpec(twofishSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex("00112233445566778899aabbccddeeff")),
    initialAux: new Map<string, AuxValue>([
      ["key", bytesFromHex("000102030405060708090a0b0c0d0e0f")],
    ]),
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

// ─── twofish.sbox-lookup@1 ─────────────────────────────────────────────────

describe("twofishSboxLookupNarration", () => {
  it("emits 1 unit naming the specific S-box and the resolved byte", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "round.0.g0.s0");
    const units = twofishSboxLookupNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    expect(units.length).toBe(1);
    expect(units[0]?.label).toContain("S0");
    const out = frame.portOutputs?.get("output");
    expect(out).toBeInstanceOf(Uint8Array);
    const text = proseText(units[0]?.Prose ?? (() => null));
    expect(text).toContain(formatBytes(out as Uint8Array, "hex"));
    expect(text).toContain("key-dependent");
  });

  it("returns null for a frame whose ports aren't the 1-byte-in / 1-byte-out shape", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "round.0.split");
    expect(twofishSboxLookupNarration(frame)).toBeNull();
  });
});

// ─── twofish.h-expand@1 (the opaque monolith) ──────────────────────────────

describe("twofishHExpandNarration", () => {
  it("emits four coarse disclosure rows (decode / svector / sboxes / ab)", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "key-schedule.h-expand");
    const units = twofishHExpandNarration(frame);
    expect(units).not.toBeNull();
    if (!units) return;
    // Four coarse rows — NOT one row per hidden operation.
    expect(units.map((u) => u.key)).toEqual(["decode", "svector", "sboxes", "ab"]);
  });

  it("publishes A/B/S to auxWritten AND exposes the S-vector on display ports", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "key-schedule.h-expand");
    // The opaque frame must carry the published material for the rows to show
    // real values (the user's requirement for the pedagogy panel).
    expect(frame.auxWritten.get("twofish.A.0")).toBeInstanceOf(Uint8Array);
    expect(frame.auxWritten.get("twofish.S3")).toBeInstanceOf(Uint8Array);
    // Display-only ports ride in portOutputs (NOT in auxWritten).
    expect(frame.portOutputs?.get("svec0")).toBeInstanceOf(Uint8Array);
    expect(frame.auxWritten.get("twofish.svec0")).toBeUndefined();
  });

  it("the S-vector row shows the REAL S_0 value this run produced", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "key-schedule.h-expand");
    const units = twofishHExpandNarration(frame);
    if (!units) throw new Error("expected units");
    const svec = units.find((u) => u.key === "svector");
    expect(svec).toBeDefined();
    const s0 = frame.portOutputs?.get("svec0") as Uint8Array;
    const text = proseText(svec?.Prose ?? (() => null));
    // S_0 for key 000102…0f is d72a062f (pinned in twofish-vectors.test.ts).
    expect(Array.from(s0)).toEqual(Array.from(bytesFromHex("d72a062f")));
    expect(text).toContain(formatBytes(s0, "hex"));
    expect(text).toContain("0x14D"); // names the RS field
  });

  it("the S-box row shows a real S0 head (not static text)", () => {
    const trace = runTwofish();
    const frame = frameById(trace, "key-schedule.h-expand");
    const units = twofishHExpandNarration(frame);
    if (!units) throw new Error("expected units");
    const sboxes = units.find((u) => u.key === "sboxes");
    const s0 = frame.auxWritten.get("twofish.S0") as Uint8Array;
    const text = proseText(sboxes?.Prose ?? (() => null));
    expect(text).toContain(formatBytes(s0.slice(0, 16), "hex"));
  });

  it("returns null when the frame published no A material (unwired monolith)", () => {
    const bare: TraceFrame = {
      index: 0,
      path: [],
      stepId: "key-schedule.h-expand",
      stepType: "twofish.h-expand@1",
      params: { outputPrefix: "twofish" },
      auxRead: new Map<string, AuxValue>(),
      auxWritten: new Map<string, AuxValue>(),
    };
    expect(twofishHExpandNarration(bare)).toBeNull();
  });
});
