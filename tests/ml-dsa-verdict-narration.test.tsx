// @vitest-environment jsdom

/**
 * The verification spec's narration, on REAL frames (P3 of
 * `docs/plans/refactored-petting-tide.md`).
 *
 * Two claims:
 *
 * 1. **The verdict's headline names the check that decided it** — for a valid
 *    signature, a flipped challenge, an over-norm z and a malformed hint. The
 *    malformed hint is the case worth having: its zeroed hint also breaks the
 *    challenge, so a headline that reported only the first failure it found
 *    would hide the reason that actually decided it.
 * 2. **Every narrated frame of the shipped spec narrates.** P2's narrators were
 *    only ever run on hand-built fixtures, because no spec used them. This is
 *    the first spec that does, so every frame whose type has a narrator must
 *    produce units and render them without throwing — the jsdom half of "read
 *    every P2 narrator on real frames" (the on-screen half is P5's).
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_VERDICT_ID,
  ML_DSA_44_DEFAULT_SIGNATURE,
  buildMlDsa44VerifySpec,
} from "@/ciphers/ml-dsa-44";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, TraceFrame } from "@/core/types";
import { render } from "@solidjs/testing-library";
import "@/ui/narration/index";
import { mlDsaVerdictNarration } from "@/ui/narration/ml-dsa";
import { type NarrationFn, lookupNarration } from "@/ui/narration/registry";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

const framesOf = (spec: CipherSpec, signature: Uint8Array): readonly TraceFrame[] =>
  runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: signature },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  }).frames;

const verdictFrame = (spec: CipherSpec, signature: Uint8Array): TraceFrame => {
  const f = framesOf(spec, signature).find((x) => x.stepId === MLDSA_VERDICT_ID);
  if (f === undefined) throw new Error("no verdict frame");
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

const headline = (f: TraceFrame): string => mlDsaVerdictNarration(f)?.[0]?.label ?? "";

describe("ml-dsa.verdict@1's headline names what decided it", () => {
  const spec = buildMlDsa44VerifySpec();

  it("is registered for the step type", () => {
    expect(lookupNarration("ml-dsa.verdict@1")).toBe(mlDsaVerdictNarration);
  });

  it("a valid signature: VALID, all three checks ticked", () => {
    const f = verdictFrame(spec, ML_DSA_44_DEFAULT_SIGNATURE);
    expect(headline(f)).toBe("1 — VALID: all three checks pass");
    expect(proseText(mlDsaVerdictNarration(f))).toContain("hint ✓ · ‖z‖∞ ✓ · challenge ✓");
  });

  it("a flipped challenge bit: the challenge alone, and where it first differs", () => {
    const sig = new Uint8Array(ML_DSA_44_DEFAULT_SIGNATURE);
    sig[5] = (sig[5] as number) ^ 1;
    const f = verdictFrame(spec, sig);
    expect(headline(f)).toBe("1 — INVALID: c̃′ ≠ c̃");
    expect(proseText(mlDsaVerdictNarration(f))).toMatch(/first differing at byte \d+/);
  });

  it("the over-norm signature: z alone — its challenge matches", () => {
    const f = verdictFrame(spec, unhex(FIXTURE.p3.overNorm.signature));
    expect(headline(f)).toBe("1 — INVALID: z is too large");
  });

  it("a malformed hint: the hint is named, even though the challenge broke too", () => {
    const k = FIXTURE.keys[FIXTURE.malformed.keyIndex];
    const s = k?.signatures[FIXTURE.malformed.signatureIndex];
    const bad = FIXTURE.malformed.cases.find((c) => c.name === "indices-not-increasing");
    if (k === undefined || s === undefined || bad === undefined) throw new Error("fixture shape");
    const own = buildMlDsa44VerifySpec({
      seed: unhex(k.seed),
      message: unhex(s.message),
      context: unhex(s.context),
    });
    const label = headline(verdictFrame(own, unhex(bad.signature)));
    expect(label.startsWith("1 — INVALID: the hint is malformed")).toBe(true);
    expect(label).toContain("c̃′ ≠ c̃");
  });
});

describe("every narrated frame of the shipped verification spec narrates", () => {
  it("no narrator declines a real frame, and every unit renders", () => {
    const frames = framesOf(buildMlDsa44VerifySpec(), ML_DSA_44_DEFAULT_SIGNATURE);
    const narrated = new Set<string>();
    for (const f of frames) {
      const fn = lookupNarration(f.stepType);
      if (fn === null) continue;
      const units = fn(f);
      expect(units, `${f.stepId} (${f.stepType}) declined its frame`).not.toBeNull();
      expect(proseText(units).length, f.stepId).toBeGreaterThan(0);
      narrated.add(f.stepType);
    }
    // The P2 steps this spec exercises, so the loop above cannot pass vacuously.
    for (const t of [
      "ml-dsa.hash-h@1",
      "ml-dsa.expand-a@1",
      "ml-dsa.expand-s@1",
      "ml-dsa.ntt@1",
      "ml-dsa.intt@1",
      "ml-dsa.power2round@1",
      "ml-dsa.bit-pack@1",
      "ml-dsa.bit-unpack@1",
      "ml-dsa.hint-unpack@1",
      "ml-dsa.sample-in-ball@1",
      "ml-dsa.use-hint@1",
      "ml-dsa.w1-encode@1",
      "ml-dsa.format-message@1",
      "zq-inf-norm-below@1",
      "ml-dsa.verdict@1",
    ]) {
      expect(narrated.has(t), t).toBe(true);
    }
  });
});
