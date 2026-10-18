// @vitest-environment jsdom
/**
 * ML-DSA narration — the per-frame narrators for the rounding, hint and norm
 * steps (P2 of `docs/plans/refactored-petting-tide.md`).
 *
 * These steps are palette-only until P3/P4 ship a spec that uses them, so the
 * frames here come from a purpose-built spec run through the REAL runtime —
 * never a hand-assembled `TraceFrame` — the precedent `tests/lattice-narration`
 * set for ML-KEM's H and J. And what is checked is that the prose reports the
 * frame's own values: the verdict, the margin, the count of wrapped
 * coefficients. A narrator printing constants would pass a render test.
 *
 * The narrators are IMPORTED, never re-created locally.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  ML_DSA_44_GAMMA2,
  ML_DSA_Q,
  ML_DSA_Q_BYTES,
  mlDsaCoeffBytes,
  packMlDsaPoly,
} from "@/ciphers/mldsa-constants";
import { decompose } from "@/core/ml-dsa-arith";
import { runSpec } from "@/core/runtime";
import {
  type AuxValue,
  type CipherSpec,
  INPUT_SOURCE_ID,
  INPUT_SOURCE_PORT,
  type StepNode,
  type TraceFrame,
} from "@/core/types";
import { render } from "@solidjs/testing-library";
import "@/ui/narration/index";
import {
  mlDsaDecomposeNarration,
  mlDsaHintCountNarration,
  mlDsaMakeHintNarration,
  mlDsaPower2RoundNarration,
  mlDsaUseHintNarration,
  zqInfNormBelowNarration,
} from "@/ui/narration/ml-dsa";
import { type NarrationFn, lookupNarration } from "@/ui/narration/registry";
import { describe, expect, it } from "vitest";

const registry = buildDefaultRegistry();
const q = ML_DSA_Q;
const g2 = ML_DSA_44_GAMMA2;
const P = { coeffBytes: 4, littleEndian: false };

const input = { node: INPUT_SOURCE_ID, port: INPUT_SOURCE_PORT };
const from = (node: string, port = "output") => ({ node, port });
const constant = (id: string, bytes: Uint8Array): StepNode => ({
  kind: "step",
  id,
  type: "constant-load@1",
  params: { bytes: [...bytes] },
});

/**
 * The input vector: ordinary values, three in the wrap-round region at the top
 * of the range (indices 3–5), and coefficient 5 = q − 95232 as the largest
 * distance from zero — BELOW zero — so the norm, its position and the wrap
 * count are all known in advance. Coefficient 1 sits two below bucket 0's upper
 * edge (95232), so a correction of 5 pushes it into bucket 1.
 */
const VALUES = [5, 95230, 50000, q - 40000, q - 3, q - 95232, 12345];
const NORM = 95232;
const WRAPPED = VALUES.filter((v) => decompose(v, g2, q).wrapped).length;

/** A correction that pushes coefficient 1 over bucket 0's upper edge. */
const Z = [0, 5, 0, 0, 0, 0, 0];

const spec: CipherSpec = {
  id: "ml-dsa-narration-fixture",
  name: "ML-DSA narration fixture",
  stateShape: "bytes",
  inputs: { plaintext: { shape: "bytes" }, key: { byteLength: 0 } },
  steps: [
    constant("q", ML_DSA_Q_BYTES),
    constant("g2", mlDsaCoeffBytes(g2)),
    constant("bound-pass", mlDsaCoeffBytes(NORM + 1)),
    constant("bound-edge", mlDsaCoeffBytes(NORM)),
    constant("z", packMlDsaPoly(Z)),
    constant("omega-full", new Uint8Array([1])),
    constant("omega-zero", new Uint8Array([0])),
    {
      kind: "step",
      id: "p2r",
      type: "ml-dsa.power2round@1",
      params: { ...P, d: 13 },
      portInputs: { a: input, modulus: from("q") },
    },
    {
      kind: "step",
      id: "dec",
      type: "ml-dsa.decompose@1",
      params: P,
      portInputs: { a: input, gamma2: from("g2"), modulus: from("q") },
    },
    {
      kind: "step",
      id: "mh",
      type: "ml-dsa.make-hint@1",
      params: P,
      portInputs: { z: from("z"), r: input, gamma2: from("g2"), modulus: from("q") },
    },
    {
      kind: "step",
      id: "uh",
      type: "ml-dsa.use-hint@1",
      params: P,
      portInputs: { h: from("mh"), r: input, gamma2: from("g2"), modulus: from("q") },
    },
    {
      kind: "step",
      id: "hc-full",
      type: "ml-dsa.hint-count@1",
      params: P,
      portInputs: { h: from("mh"), omega: from("omega-full") },
    },
    {
      kind: "step",
      id: "hc-over",
      type: "ml-dsa.hint-count@1",
      params: P,
      portInputs: { h: from("mh"), omega: from("omega-zero") },
    },
    {
      kind: "step",
      id: "norm-pass",
      type: "zq-inf-norm-below@1",
      params: P,
      portInputs: { a: input, bound: from("bound-pass"), modulus: from("q") },
    },
    {
      kind: "step",
      id: "norm-edge",
      type: "zq-inf-norm-below@1",
      params: P,
      portInputs: { a: input, bound: from("bound-edge"), modulus: from("q") },
    },
  ],
};

const frames: readonly TraceFrame[] = runSpec(spec, registry, {
  initialState: { shape: "bytes", bytes: packMlDsaPoly(VALUES) },
  initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
}).frames;

const frame = (id: string): TraceFrame => {
  const f = frames.find((x) => x.stepId === id);
  if (f === undefined) throw new Error(`no frame ${id}`);
  return f;
};

const proseText = (units: ReturnType<NarrationFn>): string => {
  if (units === null) throw new Error("narrator declined");
  return units
    .map((u) => {
      const { container } = render(() => <u.Prose fmt="hex" />);
      return `${u.label}\n${container.textContent ?? ""}`;
    })
    .join("\n");
};

describe("ML-DSA narration — dispatch", () => {
  it("routes each step type to the narrator this file imports", () => {
    const expected: [string, NarrationFn][] = [
      ["zq-inf-norm-below@1", zqInfNormBelowNarration],
      ["ml-dsa.power2round@1", mlDsaPower2RoundNarration],
      ["ml-dsa.decompose@1", mlDsaDecomposeNarration],
      ["ml-dsa.make-hint@1", mlDsaMakeHintNarration],
      ["ml-dsa.use-hint@1", mlDsaUseHintNarration],
      ["ml-dsa.hint-count@1", mlDsaHintCountNarration],
    ];
    for (const [stepType, fn] of expected) {
      expect(lookupNarration(stepType), stepType).toBe(fn);
    }
  });
});

describe("zq-inf-norm-below@1 — the verdict and its margin", () => {
  it("passes with the margin it actually had", () => {
    const text = proseText(zqInfNormBelowNarration(frame("norm-pass")));
    expect(text).toContain("‖a‖∞ = 95,232 < 95,233");
    expect(text).toContain("with 1 to spare");
  });

  it("fails ON the bound and says that is the case a ≤ would let through", () => {
    const text = proseText(zqInfNormBelowNarration(frame("norm-edge")));
    expect(text).toContain("too large: ‖a‖∞ = 95,232 ≥ 95,232");
    expect(text).toContain("exactly ON the bound");
  });

  it("names the coefficient responsible, in both its wire and signed forms", () => {
    const text = proseText(zqInfNormBelowNarration(frame("norm-pass")));
    // Coefficient 5 is q − 95232: the largest distance from zero, BELOW zero.
    expect(text).toContain("coefficient 5: −95,232");
    expect(text).toContain((q - 95232).toLocaleString("en-US"));
  });
});

describe("ml-dsa.decompose@1 — the wrap count is this frame's", () => {
  it("counts exactly the coefficients that wrapped", () => {
    expect(WRAPPED).toBe(3); // q − 40000, q − 3, q − 95232 — not vacuous
    const text = proseText(mlDsaDecomposeNarration(frame("dec")));
    expect(text).toContain(`${WRAPPED} coefficients wrapped round to bucket 0`);
    expect(text).toContain("coefficients 3, 4, 5");
  });

  it("works coefficient 0 through, with 44 buckets", () => {
    const text = proseText(mlDsaDecomposeNarration(frame("dec")));
    expect(text).toContain("coefficient 0 is in bucket 0 of 44, offset 5");
  });
});

describe("ml-dsa.power2round@1 — the worked example is real", () => {
  it("splits coefficient 0 and reports the bit budget", () => {
    const text = proseText(mlDsaPower2RoundNarration(frame("p2r")));
    expect(text).toContain("5 = 0 · 2^13 + 5");
    expect(text).toContain("10 of 23 bits kept");
    expect(text).toContain("2,976 bytes to 1,312");
  });
});

describe("hints — MakeHint, UseHint and the count", () => {
  it("MakeHint reports the coefficient the correction pushed over an edge", () => {
    const text = proseText(mlDsaMakeHintNarration(frame("mh")));
    expect(text).toContain("1 of 7 coefficients need a hint");
    expect(text).toContain("coefficient 1: bucket 0 → 1");
  });

  it("UseHint moves that coefficient up, because its offset is positive", () => {
    const text = proseText(mlDsaUseHintNarration(frame("uh")));
    expect(text).toContain("1 corrected: 1 up a bucket, 0 down");
    expect(text).toContain("coefficient 1: bucket 0 → 1");
  });

  it("hint-count says 'exactly full' at ω and rejects past it", () => {
    expect(proseText(mlDsaHintCountNarration(frame("hc-full")))).toContain(
      "exactly full is allowed",
    );
    expect(proseText(mlDsaHintCountNarration(frame("hc-over")))).toContain("too many: 1 > ω = 0");
  });
});
