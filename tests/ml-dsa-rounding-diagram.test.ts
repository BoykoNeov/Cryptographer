/**
 * The rounding diagram's model — ML-DSA's Decompose / MakeHint / UseHint drawn
 * as a value on a bucket ruler (P5 of `docs/plans/refactored-petting-tide.md`).
 *
 * Runs the SHIPPED signing and verification specs, never a toy: the model reads
 * those specs' ports, and a toy would pass while the real wiring drifted.
 *
 * What is pinned, and why each one discriminates:
 *
 * 1. **Placement by the low part.** Every value lands inside its own bucket's
 *    drawn range, including the edges FIPS 204's wrap creates (r = q − γ2 goes
 *    to bucket 0 at offset −γ2, so bucket 0 is closed at both ends). Placing
 *    by raw residue would put a wrapped value far outside its box.
 * 2. **The arrows land where the cryptography says.** Two different runs agree:
 *    on the signer's side, MakeHint's `r + z` for every coefficient of the
 *    ACCEPTED attempt lands in the bucket the signer committed to (the high
 *    bits of `w`, read off that attempt's Decompose frame); on the verifier's
 *    side, UseHint's corrected bucket equals that same committed bucket. A
 *    model that swapped `r` and `r + z` draws a consistent picture that fails
 *    the first; a model that ignored the hint fails the second.
 * 3. **The step's outputs are the truth.** A frame whose output disagrees
 *    with the geometry draws nothing.
 * 4. **γ2 comes from the frame.** A synthetic Decompose at ML-DSA-65/87's
 *    γ2 = (q − 1)/32 gives 16 buckets, not 44.
 * 5. **The narrator and the picture describe the same coefficient.**
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_44_DEFAULT_MESSAGE,
  ML_DSA_44_DEFAULT_SIGNATURE,
  buildMlDsa44SignSpec,
  buildMlDsa44VerifySpec,
} from "@/ciphers/ml-dsa-44";
import { decompose, modPm } from "@/core/ml-dsa-arith";
import {
  DECOMPOSE_TYPE,
  MAKE_HINT_TYPE,
  USE_HINT_TYPE,
  offsetInBucket,
  placeValue,
  roundingDiagramModel,
} from "@/core/ml-dsa-diagram";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, Trace, TraceFrame } from "@/core/types";
import { readCoeff, readZqVecParams } from "@/core/zq-vector";
import { mlDsaDecompose } from "@/steps/ml-dsa-decompose";
import { mlDsaMakeHintNarration, mlDsaUseHintNarration } from "@/ui/narration/ml-dsa";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();

const run = (spec: CipherSpec, input: Uint8Array): Trace =>
  runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });

// Each run takes most of a second; run each once.
const lazy = <T>(f: () => T): (() => T) => {
  let v: T | undefined;
  return () => {
    if (v === undefined) v = f();
    return v;
  };
};
const signTrace = lazy(() => run(buildMlDsa44SignSpec(), ML_DSA_44_DEFAULT_MESSAGE));
const verifyTrace = lazy(() => run(buildMlDsa44VerifySpec(), ML_DSA_44_DEFAULT_SIGNATURE));

/** ML-DSA-44's constants, as FIPS 204 states them (used only to name edges). */
const Q = 8_380_417;
const G2 = (Q - 1) / 88;
const M = (Q - 1) / (2 * G2);

const framesOf = (t: Trace, type: string): TraceFrame[] =>
  t.frames.filter((f) => f.stepType === type);

/** A vector port's coefficients as numbers. */
const vecOf = (f: TraceFrame, ports: "in" | "out", name: string): number[] => {
  const p = readZqVecParams(f.params, f.stepType);
  const bytes = (ports === "in" ? f.portInputs : f.portOutputs)?.get(name);
  if (!(bytes instanceof Uint8Array)) throw new Error(`${f.stepId}: no port ${name}`);
  return Array.from({ length: bytes.length / p.coeffBytes }, (_, i) =>
    Number(readCoeff(bytes, i, p)),
  );
};

/** The signing loop's attempt that was kept (0-based block index). */
const acceptedBlock = (): number => {
  const v = signTrace().frames.find(
    (f) => f.stepType === "ml-dsa.attempt-verdict@1" && f.portOutputs?.get("accepted")?.[0] === 1,
  );
  if (v?.blockIndex === undefined) throw new Error("no accepted attempt");
  return v.blockIndex;
};

/** The committed high bits w1: Decompose of w on the accepted attempt. */
const committedW1 = (): number[] => {
  const f = framesOf(signTrace(), DECOMPOSE_TYPE).find(
    (x) => x.blockIndex === acceptedBlock() && x.stepId.includes("w.split"),
  );
  if (f === undefined) throw new Error("no w.split frame on the accepted attempt");
  return vecOf(f, "out", "high");
};

/** Replace one coefficient of one output port, keeping the rest of the frame. */
const tamper = (f: TraceFrame, port: string, i: number, value: number): TraceFrame => {
  const p = readZqVecParams(f.params, f.stepType);
  const bytes = new Uint8Array(f.portOutputs?.get(port) ?? []);
  // Big-endian, as the ML-DSA specs pack (`littleEndian: false`).
  for (let b = 0; b < p.coeffBytes; b++) {
    bytes[i * p.coeffBytes + b] = (value >>> (8 * (p.coeffBytes - 1 - b))) & 0xff;
  }
  const outputs = new Map(f.portOutputs ?? []);
  outputs.set(port, bytes);
  return { ...f, portOutputs: outputs };
};

describe("placeValue — every value sits inside its own bucket", () => {
  it("places the wrap edges exactly as FIPS 204 does", () => {
    expect(placeValue(G2, G2, Q)).toEqual({ bucket: 0, offset: G2, wrapped: false });
    expect(placeValue(G2 + 1, G2, Q)).toEqual({ bucket: 1, offset: -G2 + 1, wrapped: false });
    expect(placeValue(Q - 1 - G2, G2, Q)).toEqual({ bucket: M - 1, offset: G2, wrapped: false });
    // Within γ2 of q − 1: bucket 0, negative offset — and −γ2 itself is reachable.
    expect(placeValue(Q - G2, G2, Q)).toEqual({ bucket: 0, offset: -G2, wrapped: true });
    expect(placeValue(Q - 1, G2, Q)).toEqual({ bucket: 0, offset: -1, wrapped: true });
  });

  it("puts every value of 0 … q − 1 inside its bucket's drawn range, and back where it came from", () => {
    // Every value, counted rather than asserted one by one.
    let bad = 0;
    let first = "";
    for (let r = 0; r < Q; r++) {
      const { bucket, offset } = placeValue(r, G2, Q);
      const back = (((bucket * 2 * G2 + offset) % Q) + Q) % Q;
      if (!offsetInBucket(offset, bucket, G2) || back !== r) {
        if (bad === 0) first = `r=${r}: bucket ${bucket}, offset ${offset}`;
        bad++;
      }
    }
    expect(bad, first).toBe(0);
  });
});

describe("roundingDiagramModel — Decompose on the signing trace", () => {
  it("draws coefficient 0 of every Decompose frame, in the bucket the step output", () => {
    const frames = framesOf(signTrace(), DECOMPOSE_TYPE);
    expect(frames.length).toBeGreaterThan(0);
    for (const f of frames) {
      const model = roundingDiagramModel(f);
      expect(model?.kind).toBe("decompose");
      expect(model?.coefficient).toBe(0);
      expect(model?.home).toBe(vecOf(f, "out", "high")[0]);
      expect(model?.m).toBe(M);
    }
  });

  it("every coefficient of a frame is drawn inside its bucket, with the step's own low part", () => {
    const f = framesOf(signTrace(), DECOMPOSE_TYPE)[0] as TraceFrame;
    const high = vecOf(f, "out", "high");
    const low = vecOf(f, "out", "low");
    for (let i = 0; i < high.length; i++) {
      const model = roundingDiagramModel(f, i);
      const pt = model?.points[0];
      expect(model?.home).toBe(high[i]);
      expect(pt?.placement.offset).toBe(modPm(low[i] as number, Q));
      expect(pt?.slot).toBe(0);
      expect(offsetInBucket(pt?.x ?? Number.NaN, model?.home ?? -1, G2)).toBe(true);
    }
  });

  it("the close-up's neighbours wrap: bucket 0's left neighbour is the last bucket", () => {
    const f = framesOf(signTrace(), DECOMPOSE_TYPE)[0] as TraceFrame;
    const high = vecOf(f, "out", "high");
    const i0 = high.indexOf(0);
    const iLast = high.indexOf(M - 1);
    expect(i0).toBeGreaterThanOrEqual(0);
    expect(iLast).toBeGreaterThanOrEqual(0);
    expect(roundingDiagramModel(f, i0)?.buckets.map((b) => b.index)).toEqual([M - 1, 0, 1]);
    expect(roundingDiagramModel(f, iLast)?.buckets.map((b) => b.index)).toEqual([M - 2, M - 1, 0]);
  });
});

describe("roundingDiagramModel — the hints land where the cryptography says", () => {
  it("MakeHint: on the accepted attempt, r + z lands in the committed bucket for EVERY coefficient", () => {
    const f = framesOf(signTrace(), MAKE_HINT_TYPE).find((x) => x.blockIndex === acceptedBlock());
    if (f === undefined) throw new Error("no MakeHint frame on the accepted attempt");
    const w1 = committedW1();
    const h = vecOf(f, "out", "output");
    let hinted = 0;
    for (let i = 0; i < h.length; i++) {
      const model = roundingDiagramModel(f, i);
      expect(model?.target).toBe(w1[i]);
      expect(model?.hint).toBe(h[i]);
      const second = model?.points[1];
      // r + z is drawn inside the bucket it belongs to.
      expect(second?.placement.bucket).toBe(w1[i]);
      expect(
        offsetInBucket((second?.x ?? 0) - (second?.slot ?? 0) * 2 * G2, w1[i] as number, G2),
      ).toBe(true);
      if (h[i] === 1) {
        hinted++;
        expect(model?.home).not.toBe(w1[i]);
      } else {
        expect(model?.home).toBe(w1[i]);
      }
    }
    // The default pair's kept attempt needs 75 hints (the attempts table's number).
    expect(hinted).toBe(75);
  });

  it("MakeHint: every attempt's frame draws, featured on the first hinted coefficient", () => {
    for (const f of framesOf(signTrace(), MAKE_HINT_TYPE)) {
      const h = vecOf(f, "out", "output");
      const model = roundingDiagramModel(f);
      expect(model?.coefficient).toBe(h.indexOf(1));
      expect(model?.hint).toBe(1);
      expect(model?.hintedCount).toBe(h.filter((b) => b === 1).length);
    }
  });

  it("UseHint: the verifier's corrected bucket is the signer's committed bucket, coefficient by coefficient", () => {
    const [f] = framesOf(verifyTrace(), USE_HINT_TYPE);
    if (f === undefined) throw new Error("no UseHint frame");
    const w1 = committedW1();
    const out = vecOf(f, "out", "output");
    expect(out).toEqual(w1);
    for (let i = 0; i < out.length; i++) {
      const model = roundingDiagramModel(f, i);
      expect(model?.target).toBe(w1[i]);
      const pt = model?.points[0];
      if (model?.hint === 1) {
        // The low part's sign picks the neighbour: up when positive, else down.
        const up = (model.home + 1) % M;
        const down = (model.home - 1 + M) % M;
        expect(model.target).toBe((pt?.placement.offset ?? 0) > 0 ? up : down);
      } else {
        expect(model?.target).toBe(model?.home);
      }
    }
  });
});

describe("roundingDiagramModel — draws only what the step produced", () => {
  it("a Decompose frame whose high bits disagree with its input draws nothing", () => {
    const f = framesOf(signTrace(), DECOMPOSE_TYPE)[0] as TraceFrame;
    const high = vecOf(f, "out", "high");
    expect(roundingDiagramModel(tamper(f, "high", 0, ((high[0] as number) + 1) % M))).toBeNull();
  });

  it("a UseHint frame whose output is not the hinted neighbour draws nothing", () => {
    const [f] = framesOf(verifyTrace(), USE_HINT_TYPE);
    if (f === undefined) throw new Error("no UseHint frame");
    const model = roundingDiagramModel(f);
    if (model === null || model.hint !== 1)
      throw new Error("expected a hinted featured coefficient");
    // Output the value's OWN bucket, as if the hint had been ignored.
    expect(roundingDiagramModel(tamper(f, "output", model.coefficient, model.home))).toBeNull();
  });

  it("any other step draws nothing", () => {
    const other = signTrace().frames.find(
      (f) => ![DECOMPOSE_TYPE, MAKE_HINT_TYPE, USE_HINT_TYPE].includes(f.stepType),
    ) as TraceFrame;
    expect(roundingDiagramModel(other)).toBeNull();
  });
});

describe("roundingDiagramModel — γ2 is read off the frame", () => {
  it("at ML-DSA-65/87's γ2 = (q − 1)/32 there are 16 buckets, each 2.75× as wide", () => {
    const real = framesOf(signTrace(), DECOMPOSE_TYPE)[0] as TraceFrame;
    const g2 = (Q - 1) / 32;
    const gammaPort = real.portInputs?.get("gamma2") as Uint8Array;
    const g2Bytes = new Uint8Array(gammaPort.length);
    for (let b = 0; b < g2Bytes.length; b++) {
      g2Bytes[b] = Math.floor(g2 / 256 ** (g2Bytes.length - 1 - b)) & 0xff;
    }
    const inputs = new Map(real.portInputs ?? []);
    inputs.set("gamma2", g2Bytes);
    const outputs = mlDsaDecompose(inputs, real.params, {} as never);
    const frame: TraceFrame = { ...real, portInputs: inputs, portOutputs: outputs };
    const model = roundingDiagramModel(frame);
    expect(model?.gamma2).toBe(g2);
    expect(model?.m).toBe(16);
    const a0 = vecOf(real, "in", "a")[0] as number;
    expect(model?.home).toBe(decompose(a0, g2, Q).r1);
  });
});

describe("the narrator and the picture talk about the same coefficient", () => {
  it("MakeHint and UseHint narrators name the coefficient the diagram draws", () => {
    const mk = framesOf(signTrace(), MAKE_HINT_TYPE)[0] as TraceFrame;
    const use = framesOf(verifyTrace(), USE_HINT_TYPE)[0] as TraceFrame;
    for (const [f, narrate] of [
      [mk, mlDsaMakeHintNarration],
      [use, mlDsaUseHintNarration],
    ] as const) {
      const model = roundingDiagramModel(f);
      const units = narrate(f) ?? [];
      const example = units.find((u) => u.key === "example");
      expect(example?.label).toContain(`coefficient ${model?.coefficient}:`);
    }
  });
});
