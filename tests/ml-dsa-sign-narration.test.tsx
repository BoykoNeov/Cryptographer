// @vitest-environment jsdom

/**
 * Signing's narration, on REAL frames (P4 of `docs/plans/refactored-petting-tide.md`).
 *
 * Three claims:
 *
 * 1. **Each attempt's headline is a verdict with the numbers in it**: "attempt
 *    1 rejected: ‖z‖∞ = … ≥ γ1 − β = 130,994". The values come off the attempt
 *    verdict's display ports, which is why those ports exist — a narrator sees
 *    only its own frame.
 * 2. **The release step says what happened**: signed on attempt N, with every
 *    rejected attempt's reason from the loop's log — or no signature at all,
 *    when the cap was reached.
 * 3. **Every narrated frame of the shipped signing spec narrates**, without
 *    throwing — the first spec that runs most of the P2 narrators inside a loop.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_ATTEMPT_PREFIX,
  MLDSA_ATTEMPT_VERDICT_ID,
  MLDSA_RELEASE_ID,
  ML_DSA_44_DEFAULT_MESSAGE,
  buildMlDsa44SignSpec,
} from "@/ciphers/ml-dsa-44";
import { ML_DSA_44_BETA, ML_DSA_44_GAMMA1 } from "@/ciphers/mldsa-constants";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, TraceFrame } from "@/core/types";
import { render } from "@solidjs/testing-library";
import "@/ui/narration/index";
import {
  mlDsaAttemptVerdictNarration,
  mlDsaReleaseSignatureNarration,
} from "@/ui/narration/ml-dsa";
import { type NarrationFn, lookupNarration } from "@/ui/narration/registry";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));
const VERDICT = `${MLDSA_ATTEMPT_PREFIX}${MLDSA_ATTEMPT_VERDICT_ID}`;

const memo = new Map<string, readonly TraceFrame[]>();
const framesOf = (spec: CipherSpec, key: string, message: Uint8Array): readonly TraceFrame[] => {
  const hit = memo.get(key);
  if (hit !== undefined) return hit;
  const frames = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: message },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  }).frames;
  memo.set(key, frames);
  return frames;
};
const defaultFrames = () => framesOf(buildMlDsa44SignSpec(), "default", ML_DSA_44_DEFAULT_MESSAGE);

const frame = (frames: readonly TraceFrame[], id: string): TraceFrame => {
  const f = frames.find((x) => x.stepId === id);
  if (f === undefined) throw new Error(`no frame ${id}`);
  return f;
};

const labels = (units: ReturnType<NarrationFn>): string[] => {
  if (units === null) throw new Error("narrator declined");
  return units.map((u) => u.label);
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

describe("the attempt verdict's headline", () => {
  it("attempt 1 of the default pair: rejected by z, with the measured norm and γ1 − β", () => {
    const head = labels(mlDsaAttemptVerdictNarration(frame(defaultFrames(), `${VERDICT}:b0`)))[0];
    expect(head).toMatch(/^1 — attempt 1 rejected: ‖z‖∞ = [\d,]+ ≥ γ1 − β = 130,994/);
    expect(ML_DSA_44_GAMMA1 - ML_DSA_44_BETA).toBe(130_994);
  });

  it("attempt 2: rejected by r0 (and, if z also failed, both are named)", () => {
    const head = labels(mlDsaAttemptVerdictNarration(frame(defaultFrames(), `${VERDICT}:b1`)))[0];
    expect(head).toMatch(/^1 — attempt 2 rejected: .*‖r0‖∞ = [\d,]+ ≥ γ2 − β = 95,154/);
  });

  it("attempt 3: accepted, and the detail row ticks all four", () => {
    const units = mlDsaAttemptVerdictNarration(frame(defaultFrames(), `${VERDICT}:b2`));
    expect(labels(units)).toEqual([
      "1 — attempt 3 ACCEPTED: all four checks pass",
      "2 — ‖z‖∞ ✓ · ‖r0‖∞ ✓ · ‖c·t0‖∞ ✓ · #h ✓",
    ]);
    expect(proseText(units)).toMatch(/to spare/);
  });

  it("the hint case's third attempt: '#h = 81 > ω = 80', the only check that failed", () => {
    const c = FIXTURE.p4.hint;
    const frames = framesOf(buildMlDsa44SignSpec(), "hint", unhex(c.message));
    const units = mlDsaAttemptVerdictNarration(frame(frames, `${VERDICT}:b2`));
    expect(labels(units)[0]).toBe("1 — attempt 3 rejected: #h = 81 > ω = 80");
    expect(proseText(units)).toMatch(/1 too many/);
  });
});

describe("the release step", () => {
  it("names the accepted attempt and every rejected one's reason", () => {
    const units = mlDsaReleaseSignatureNarration(frame(defaultFrames(), MLDSA_RELEASE_ID));
    expect(labels(units)).toEqual([
      "1 — SIGNED: accepted on attempt 3, 2,420 bytes",
      "2 — 2 rejected attempts",
    ]);
    const text = proseText(units);
    expect(text).toMatch(/attempt 1: rejected by [^\n]*‖z‖∞/);
    expect(text).toMatch(/attempt 2: rejected by [^\n]*‖r0‖∞/);
  });

  it("says there is no signature when the cap was reached", () => {
    const frames = framesOf(
      buildMlDsa44SignSpec({ attemptCap: 2 }),
      "cap2",
      ML_DSA_44_DEFAULT_MESSAGE,
    );
    const units = mlDsaReleaseSignatureNarration(frame(frames, MLDSA_RELEASE_ID));
    expect(labels(units)[0]).toBe("1 — NO SIGNATURE: all 2 attempts were rejected");
    expect(proseText(units)).toMatch(/output is empty/);
  });
});

describe("every narrated frame of the signing spec narrates", () => {
  it("produces units and renders them, for every frame with a registered narrator", () => {
    let narrated = 0;
    for (const f of defaultFrames()) {
      const fn = lookupNarration(f.stepType);
      if (fn === null) continue;
      const units = fn(f);
      expect(units, `${f.stepId} (${f.stepType}) declined`).not.toBeNull();
      proseText(units);
      narrated++;
    }
    expect(narrated).toBeGreaterThan(30);
  });
});
