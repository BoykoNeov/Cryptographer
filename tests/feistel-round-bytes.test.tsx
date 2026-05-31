// @vitest-environment jsdom

/**
 * `FeistelRoundBytes` — port-native DES (Slice 5.3d).
 *
 * Pins the round-level byte panel against a real port-native DES trace: the
 * round-entry (L | R), F-mix (F, L⊕F), and round-output (L' | R') rows render
 * with the FIPS-KAT bytes resolved from the round's split / fxor / recombine
 * frame ports. (The byte-resolution itself is unit-pinned in
 * `feistel-shape.test.ts`; here we pin that the COMPONENT surfaces them.)
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { FeistelRoundBytes } from "@/ui/components/FeistelRoundBytes";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, __setSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const DES_PT = "0123456789abcdef";
const DES_KEY = "133457799bbcdff1";

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

const seed = (): Trace => {
  __setSpecForTests(desSpec);
  const trace = runSpec(desSpec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(DES_PT)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(DES_KEY)]]),
    portedDispatchEnabled: true,
  });
  setTrace(trace);
  return trace;
};

const frameById = (trace: Trace, id: string): TraceFrame => {
  const f = trace.frames.find((fr) => fr.stepId === id);
  if (!f) throw new Error(`expected a ${id} frame`);
  return f;
};

/** The concatenated hex of a labelled row's byte cells. */
const rowHex = (container: HTMLElement, label: string): string | null => {
  const rows = Array.from(container.querySelectorAll(".feistel-round-bytes-row"));
  const row = rows.find(
    (r) => r.querySelector(".feistel-round-bytes-label")?.textContent === label,
  );
  if (!row) return null;
  return Array.from(row.querySelectorAll(".key-schedule-byte-cell"))
    .map((c) => c.textContent ?? "")
    .join("");
};

describe("FeistelRoundBytes — port-native DES", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing outside a round", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRoundBytes frame={frameById(trace, "initial-permutation")} />
    ));
    expect(container.querySelector(".feistel-round-bytes")).toBeNull();
  });

  it("shows the round id and the round-entry / F-mix / output rows with KAT bytes", () => {
    const trace = seed();
    // Any frame inside round 1 surfaces the whole round's halves.
    const { container } = render(() => (
      <FeistelRoundBytes frame={frameById(trace, "round.1.s-boxes")} />
    ));
    expect(container.querySelector(".feistel-round-bytes-round")?.textContent).toBe("round.1");

    // FIPS 46-3 round 1 (des-kat.json vector): L=cc00ccff, R=f0aaf0aa,
    // F=234aa9bb, L⊕F=ef4a6544; swap → L'=R=f0aaf0aa, R'=L⊕F=ef4a6544.
    expect(rowHex(container, "L")).toBe("cc00ccff");
    expect(rowHex(container, "R")).toBe("f0aaf0aa");
    expect(rowHex(container, "F")).toBe("234aa9bb");
    expect(rowHex(container, "L⊕F")).toBe("ef4a6544");
    expect(rowHex(container, "L'")).toBe("f0aaf0aa");
    expect(rowHex(container, "R'")).toBe("ef4a6544");
  });

  it("the L⊕F row carries the accent class", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRoundBytes frame={frameById(trace, "round.1.s-boxes")} />
    ));
    const rows = Array.from(container.querySelectorAll(".feistel-round-bytes-row"));
    const mixRow = rows.find(
      (r) => r.querySelector(".feistel-round-bytes-label")?.textContent === "L⊕F",
    );
    expect(mixRow?.classList.contains("feistel-round-bytes-row-accent")).toBe(true);
  });
});
