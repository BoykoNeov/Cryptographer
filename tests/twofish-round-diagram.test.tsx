// @vitest-environment jsdom

/**
 * `TwofishRoundDiagram` — the linear view's abstract Twofish round.
 *
 * The two contracts worth pinning in jsdom. (The geometry is NOT among them —
 * whether a 4-rail picture reads correctly is only checkable by eye, in a real
 * browser; these tests would pass on a diagram that was visually nonsense.)
 *
 *  1. **It renders for a Twofish round and is INERT everywhere else.** The
 *     component sits in the shared linear view alongside the 2-way Feistel trio,
 *     so every cipher mounts it on every frame. If it ever mis-fired on DES,
 *     AES, or a Twofish frame outside a round, it would draw a 4-rail Twofish
 *     picture over some other cipher's bytes — the worst failure available to
 *     it. `analyzeFeistelRound` returning null for Twofish is what left this gap
 *     open; the inverse must not open a new one.
 *  2. **"You are here" tracks the scrubber, and clicking scrubs back.** That
 *     pairing is the diagram's whole use while stepping through a round.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { desSpec } from "@/ciphers/des";
import { twofishSpec } from "@/ciphers/twofish";
import { runSpec } from "@/core/runtime";
import { bytesFromHex, makeBytesState } from "@/core/state/bytes";
import type { AuxValue, Trace, TraceFrame } from "@/core/types";
import type { CipherSpec } from "@/core/types";
import { TwofishRoundDiagram } from "@/ui/components/TwofishRoundDiagram";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import { __resetCipherModeForTests } from "@/ui/stores/cipher-mode";
import { __resetByteFormatForTests } from "@/ui/stores/format";
import { __resetPaddingForTests } from "@/ui/stores/padding";
import { __resetSpecForTests, __setSpecForTests } from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace, useFrameIndex } from "@/ui/stores/trace";
import { cleanup, fireEvent, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const TWOFISH_PT = "00112233445566778899aabbccddeeff";
const TWOFISH_KEY = "000102030405060708090a0b0c0d0e0f";

const resetAll = (): void => {
  __resetByteFormatForTests();
  __resetSpecForTests();
  __resetTraceForTests();
  __resetCipherForTests();
  __resetCipherModeForTests();
  __resetPaddingForTests();
};

/** Install `spec` as the live spec and run it, seeding the trace store. */
const seed = (spec: CipherSpec, pt: string, key: string): Trace => {
  __setSpecForTests(spec);
  const trace = runSpec(spec, buildDefaultRegistry(), {
    initialState: makeBytesState(bytesFromHex(pt)),
    initialAux: new Map<string, AuxValue>([["key", bytesFromHex(key)]]),
  });
  setTrace(trace);
  return trace;
};

const seedTwofish = (): Trace => seed(twofishSpec, TWOFISH_PT, TWOFISH_KEY);

const frameById = (trace: Trace, id: string): TraceFrame => {
  const f = trace.frames.find((fr) => fr.stepId === id);
  if (!f) throw new Error(`expected a "${id}" frame`);
  return f;
};

beforeEach(resetAll);
afterEach(() => {
  cleanup();
  resetAll();
});

describe("TwofishRoundDiagram — when it renders", () => {
  it("renders the 4 rails and the swapped output words for a round-body frame", () => {
    const trace = seedTwofish();
    const frame = frameById(trace, "round.5.f0");
    const { getByLabelText, getByTestId } = render(() => <TwofishRoundDiagram frame={frame} />);

    expect(getByLabelText("twofish round diagram")).toBeTruthy();
    // Inputs R0..R3 in rail order.
    for (let i = 0; i < 4; i++) {
      expect(getByTestId(`twofish-round-diagram-input-${i}`).textContent).toBe(`R${i}`);
    }
    // Outputs in the SWAPPED order — the mixed pair first, the carried pair
    // last. This is the one fact the diagram exists to show.
    expect(getByTestId("twofish-round-diagram-output-0").textContent).toBe("R2′");
    expect(getByTestId("twofish-round-diagram-output-1").textContent).toBe("R3′");
    expect(getByTestId("twofish-round-diagram-output-2").textContent).toBe("R0");
    expect(getByTestId("twofish-round-diagram-output-3").textContent).toBe("R1");
  });

  it("keeps the 8-bit pre-rotation OUTSIDE the g box, named the way the paper names it", () => {
    const trace = seedTwofish();
    const { getByTestId } = render(() => (
      <TwofishRoundDiagram frame={frameById(trace, "round.5.f0")} />
    ));
    // g0 has no such rotation; drawing it inside g1's box would teach that g
    // includes an 8-bit turn. (`textContent` also carries the chip's <title>
    // tooltip, hence `toContain` rather than an exact match.)
    expect(getByTestId("twofish-round-diagram-rol").textContent).toContain("ROL 8");
    expect(getByTestId("twofish-round-diagram-g0")).toBeTruthy();
    expect(getByTestId("twofish-round-diagram-g1")).toBeTruthy();
  });
});

describe("TwofishRoundDiagram — when it must stay dark", () => {
  it("renders nothing for a DES frame (the 2-way Feistel form)", () => {
    const trace = seed(desSpec, "0123456789abcdef", "133457799bbcdff1");
    const { container } = render(() => (
      <TwofishRoundDiagram frame={frameById(trace, "round.5.s-boxes")} />
    ));
    expect(container.querySelector(".twofish-round-diagram")).toBeNull();
  });

  it("renders nothing for an AES frame", () => {
    const trace = seed(
      aes128Spec,
      "00112233445566778899aabbccddeeff",
      "000102030405060708090a0b0c0d0e0f",
    );
    const frame = trace.frames[trace.frames.length - 1];
    if (!frame) throw new Error("expected an AES frame");
    const { container } = render(() => <TwofishRoundDiagram frame={frame} />);
    expect(container.querySelector(".twofish-round-diagram")).toBeNull();
  });

  it("renders nothing for a Twofish frame OUTSIDE a round (the key schedule)", () => {
    const trace = seedTwofish();
    const frame = trace.frames.find((f) => f.stepId.includes("h-expand"));
    if (!frame) throw new Error("expected an h-expand frame");
    const { container } = render(() => <TwofishRoundDiagram frame={frame} />);
    expect(container.querySelector(".twofish-round-diagram")).toBeNull();
  });
});

describe("TwofishRoundDiagram — you are here, and click to go back", () => {
  it("accents the element holding the active frame's leaf, not its neighbours", () => {
    const trace = seedTwofish();
    // A leaf inside g0's stack: the g0 BOX should light, g1's must not.
    const g0Leaf = trace.frames.find((f) => f.stepId.startsWith("round.5.g0."));
    if (!g0Leaf) throw new Error("expected a round.5.g0 frame");
    const { getByTestId } = render(() => <TwofishRoundDiagram frame={g0Leaf} />);

    const g0 = getByTestId("twofish-round-diagram-g0");
    const g1 = getByTestId("twofish-round-diagram-g1");
    expect(g0.classList.contains("twofish-round-diagram-active")).toBe(true);
    expect(g1.classList.contains("twofish-round-diagram-active")).toBe(false);
  });

  it("accents the PHT on a PHT frame", () => {
    const trace = seedTwofish();
    const { getByTestId } = render(() => (
      <TwofishRoundDiagram frame={frameById(trace, "round.5.f1")} />
    ));
    expect(
      getByTestId("twofish-round-diagram-pht").classList.contains("twofish-round-diagram-active"),
    ).toBe(true);
    expect(
      getByTestId("twofish-round-diagram-g0").classList.contains("twofish-round-diagram-active"),
    ).toBe(false);
  });

  it("clicking the PHT scrubs the trace to a PHT frame", () => {
    const trace = seedTwofish();
    const start = frameById(trace, "round.5.split");
    const startIdx = trace.frames.indexOf(start);
    const { getByTestId } = render(() => <TwofishRoundDiagram frame={start} />);

    fireEvent.click(getByTestId("twofish-round-diagram-pht"));

    const landedIdx = useFrameIndex()();
    expect(landedIdx).not.toBe(startIdx);
    const landed = trace.frames[landedIdx];
    expect(landed).toBeTruthy();
    // It must land on a leaf the PHT box actually stands for.
    expect(landed?.stepId.startsWith("round.5.")).toBe(true);
    expect(["loadK0", "loadK1", "f0", "f1", "dbl2T1"].some((n) => landed?.stepId.endsWith(n))).toBe(
      true,
    );
  });
});
