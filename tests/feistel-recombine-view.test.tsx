// @vitest-environment jsdom

/**
 * `FeistelRecombineView` — port-native DES (Slice 5.3d).
 *
 * Pins the recombine/swap inspector: it renders ONLY on a round's `recombine`
 * (concat) frame, labels the two concat inputs by their Feistel role (R / L⊕F,
 * in wiring order), and explains swap vs no-swap — the round-16 self-inverse
 * exception being the point.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import { FeistelRecombineView } from "@/ui/components/FeistelRecombineView";
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

const inputLabels = (container: HTMLElement): string[] => {
  const section = container.querySelector(".feistel-recombine-section");
  if (!section) return [];
  return Array.from(section.querySelectorAll(".feistel-recombine-label")).map(
    (el) => el.textContent ?? "",
  );
};

describe("FeistelRecombineView — port-native DES", () => {
  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("renders nothing on a non-recombine round frame", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRecombineView frame={frameById(trace, "round.5.s-boxes")} />
    ));
    expect(container.querySelector(".feistel-recombine")).toBeNull();
  });

  it("renders on the recombine frame and labels inputs R, L⊕F for a swap round", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRecombineView frame={frameById(trace, "round.5.recombine")} />
    ));
    expect(container.querySelector(".feistel-recombine")).not.toBeNull();
    expect(container.querySelector(".feistel-recombine-kind")?.textContent).toBe("swap");
    // swap → concat(R, L⊕F): input0 labelled R, input1 labelled L⊕F.
    expect(inputLabels(container)).toEqual(["R", "L⊕F"]);
    expect(container.textContent ?? "").toContain("swap");
  });

  it("on round 16 (no-swap) the inputs flip to L⊕F, R and the note explains self-inverse", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRecombineView frame={frameById(trace, "round.16.recombine")} />
    ));
    expect(container.querySelector(".feistel-recombine-kind")?.textContent).toBe("no swap");
    // no-swap → concat(L⊕F, R): input0 labelled L⊕F, input1 labelled R.
    expect(inputLabels(container)).toEqual(["L⊕F", "R"]);
    const text = container.textContent ?? "";
    expect(text).toContain("no-swap");
    expect(text.toLowerCase()).toContain("reversed");
  });

  it("renders the round output halves L' / R'", () => {
    const trace = seed();
    const { container } = render(() => (
      <FeistelRecombineView frame={frameById(trace, "round.5.recombine")} />
    ));
    const labels = Array.from(container.querySelectorAll(".feistel-recombine-label")).map(
      (el) => el.textContent ?? "",
    );
    expect(labels).toContain("L'");
    expect(labels).toContain("R'");
  });
});
