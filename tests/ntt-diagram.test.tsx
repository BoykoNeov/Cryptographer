// @vitest-environment jsdom

/**
 * The two lattice linear-view diagrams — `<NttButterflyDiagram />` and
 * `<ZqBaseCaseMulDiagram />`.
 *
 * These are driven against REAL frames from real runs of the shipped specs
 * rather than hand-built ones, because the two properties most likely to break
 * quietly are both properties of the frames:
 *
 * 1. **Direction.** The forward and inverse butterflies are genuinely different
 *    shapes — multiply-then-combine versus combine-then-multiply — so the
 *    diagram must draw the twiddle box on the other side of the crossing. That
 *    is the difference from the two ARX diagrams, whose specs are structurally
 *    identical and which need no direction-awareness at all.
 * 2. **Group scoping.** The header names which of a layer's groups this frame
 *    is, and the NTT is the spec that broke every trace-wide `blockIndex`
 *    reading: its seven sibling iterates run 1, 2, 4 … 64 groups. A
 *    trace-wide maximum would label layer 1's only group "1 of 64". Asserting
 *    both ends of that range is the regression this file exists for.
 *
 * A diagram that rendered for the wrong algorithm would be nonsense and nothing
 * else in the app would fail, so inertness is asserted too.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import { DEFAULT_NTT_INPUT, DEFAULT_NTT_OUTPUT } from "@/ciphers/ntt-3329-256";
import { BASE_CASE_MUL_TYPE } from "@/core/ntt-diagram";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { TraceFrame } from "@/core/types";
import { NttButterflyDiagram } from "@/ui/components/NttButterflyDiagram";
import { ZqBaseCaseMulDiagram } from "@/ui/components/ZqBaseCaseMulDiagram";
import {
  __resetSpecForTests,
  setAsymmetric,
  setCipher,
  setLattice,
  setMode,
  useSpec,
} from "@/ui/stores/spec";
import { __resetTraceForTests, setTrace } from "@/ui/stores/trace";
import { cleanup, render } from "@solidjs/testing-library";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

/**
 * Point the STORE at one direction of the transform and run it.
 *
 * The components read the ACTIVE spec (`useSpec()`), not a spec passed in, so a
 * locally built one is invisible to them — the first version of this file
 * asserted against the forward diagram twice without noticing, because the
 * store was still on `encrypt`.
 */
const runNtt = (forward: boolean) => {
  setLattice("ntt-3329-256");
  setMode(forward ? "encrypt" : "decrypt");
  const spec = useSpec()();
  const trace = runSpec(spec, registry, {
    initialState: makeBytesState(forward ? DEFAULT_NTT_INPUT : DEFAULT_NTT_OUTPUT),
  });
  return { spec, trace };
};

/** The first frame of `layerN` whose leaf id ends in `suffix`, at `blockIndex`. */
const frameIn = (
  trace: ReturnType<typeof runSpec>,
  layerId: string,
  suffix: string,
  blockIndex: number,
): TraceFrame => {
  const found = trace.frames.find(
    (f) => f.path.includes(layerId) && f.stepId.includes(suffix) && f.blockIndex === blockIndex,
  );
  if (!found) throw new Error(`no ${layerId}${suffix} frame at block ${blockIndex}`);
  return found;
};

const resetAll = (): void => {
  __resetTraceForTests();
  __resetSpecForTests();
};

describe("<NttButterflyDiagram />", () => {
  beforeEach(() => {
    resetAll();
    // `__resetSpecForTests` does not reset the algorithm selector, and the
    // components read the ACTIVE spec — so `runNtt` sets it explicitly, or the
    // diagram looks for butterflies in whatever leaked in from another file.
    setLattice("ntt-3329-256");
    setMode("encrypt");
  });
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("names the FORWARD butterfly after Cooley and Tukey, and shows the twist first", () => {
    const { trace } = runNtt(true);
    setTrace(trace);
    const { container } = render(() => (
      <NttButterflyDiagram frame={frameIn(trace, "layer1", ".twist", 0)} />
    ));
    expect(container.querySelector(".ntt-butterfly-diagram-title")?.textContent).toContain(
      "Cooley–Tukey",
    );
    // The twiddle box precedes both combining boxes — the structural claim.
    const glyphs = [...container.querySelectorAll(".ntt-butterfly-diagram-box-label")].map(
      (n) => n.textContent,
    );
    expect(glyphs.indexOf("× ζ")).toBeLessThan(glyphs.indexOf("+"));
    expect(glyphs.indexOf("× ζ")).toBeLessThan(glyphs.indexOf("−"));
  });

  it("names the INVERSE butterfly after Gentleman and Sande, and shows the twist last", () => {
    const { trace } = runNtt(false);
    setTrace(trace);
    const { container } = render(() => (
      <NttButterflyDiagram frame={frameIn(trace, "layer1", ".hi", 0)} />
    ));
    expect(container.querySelector(".ntt-butterfly-diagram-title")?.textContent).toContain(
      "Gentleman–Sande",
    );
    // Combine first, twist afterwards — the mirror of the assertion above, and
    // the whole reason this diagram is direction-aware where the ARX ones are
    // not.
    const glyphs = [...container.querySelectorAll(".ntt-butterfly-diagram-box-label")].map(
      (n) => n.textContent,
    );
    expect(glyphs.indexOf("× ζ")).toBeGreaterThan(glyphs.indexOf("+"));
    expect(glyphs.indexOf("× ζ")).toBeGreaterThan(glyphs.indexOf("−"));
  });

  it("writes each direction's own output lines", () => {
    for (const [forward, expected] of [
      [true, ["lo′ = lo + t", "hi′ = lo − t"]],
      [false, ["lo′ = lo + hi", "hi′ = ζ · (hi − lo)"]],
    ] as const) {
      const { trace } = runNtt(forward);
      setTrace(trace);
      const { container, unmount } = render(() => (
        <NttButterflyDiagram frame={frameIn(trace, "layer1", ".lo", 0)} />
      ));
      const labels = [...container.querySelectorAll(".ntt-butterfly-diagram-out-label")].map(
        (n) => n.textContent,
      );
      expect(labels).toEqual([...expected]);
      unmount();
    }
  });

  it("counts groups WITHIN the layer, not across the trace", () => {
    // The regression. Forward layer 1 runs a single group of 256 coefficients;
    // forward layer 7 runs 64 groups of 4. A trace-wide maximum `blockIndex`
    // would label them both "of 64" — which is exactly what `iterateScopeKey`
    // was added for, and the NTT is the spec that broke it.
    const { trace } = runNtt(true);
    setTrace(trace);

    const first = render(() => (
      <NttButterflyDiagram frame={frameIn(trace, "layer1", ".twist", 0)} />
    ));
    expect(first.container.querySelector(".ntt-butterfly-diagram-kind")?.textContent).toBe(
      "pairs j with j + 128 · group 1 of 1",
    );
    first.unmount();

    const last = render(() => (
      <NttButterflyDiagram frame={frameIn(trace, "layer7", ".twist", 63)} />
    ));
    expect(last.container.querySelector(".ntt-butterfly-diagram-kind")?.textContent).toBe(
      "pairs j with j + 2 · group 64 of 64",
    );
  });

  it("is inert for a cipher with no butterflies", () => {
    resetAll();
    setCipher("aes-128");
    const frame = { stepId: "sub-bytes", path: ["round.1"] } as unknown as TraceFrame;
    const { container } = render(() => <NttButterflyDiagram frame={frame} />);
    expect(container.querySelector(".ntt-butterfly-diagram")).toBeNull();
  });
});

describe("<ZqBaseCaseMulDiagram />", () => {
  /**
   * K-PKE encryption's matrix-vector product in the transformed domain is where
   * `zq-base-case-mul@1` actually runs. It is not selectable on its own — it
   * reaches a browser through ML-KEM-768, which embeds it — so driving the
   * K-PKE spec directly is the closest a headless test gets to the real frame.
   */
  const mlKemFrame = (): { frame: TraceFrame } => {
    setAsymmetric("ml-kem-768");
    setMode("encrypt");
    const spec = useSpec()();
    const trace = runSpec(spec, registry, {
      initialState: makeBytesState(new Uint8Array(32)),
    });
    setTrace(trace);
    const frame = trace.frames.find((f) => f.stepType === BASE_CASE_MUL_TYPE);
    if (!frame) throw new Error("no base-case-multiply frame in ML-KEM encapsulation");
    return { frame };
  };

  beforeEach(resetAll);
  afterEach(() => {
    cleanup();
    resetAll();
  });

  it("draws the four products, with the γ term marked as folded", () => {
    const { frame } = mlKemFrame();
    const { container } = render(() => <ZqBaseCaseMulDiagram frame={frame} />);
    const terms = [...container.querySelectorAll(".zq-basecase-diagram-term")].map(
      (n) => n.textContent,
    );
    expect(terms).toEqual(["a₀·b₀", "a₁·b₁·γ", "a₀·b₁", "a₁·b₀"]);
    // Exactly one term came back from degree 2 — the whole content of the step.
    const folded = container.querySelectorAll(".zq-basecase-diagram-term-folded");
    expect(folded).toHaveLength(1);
    expect(folded[0]?.textContent).toBe("a₁·b₁·γ");
  });

  it("reports the pair count from the frame's own input width", () => {
    const { frame } = mlKemFrame();
    const { container } = render(() => <ZqBaseCaseMulDiagram frame={frame} />);
    // 256 coefficients arrive and pair up: 128 little polynomial products, not
    // 256 element-wise ones. That number IS the teaching point.
    expect(container.querySelector(".zq-basecase-diagram-kind")?.textContent).toContain(
      "128 pairs",
    );
  });

  it("is inert for every other step type", () => {
    const { trace } = runNtt(true);
    setTrace(trace);
    const { container } = render(() => (
      <ZqBaseCaseMulDiagram frame={frameIn(trace, "layer1", ".twist", 0)} />
    ));
    expect(container.querySelector(".zq-basecase-diagram")).toBeNull();
  });
});
