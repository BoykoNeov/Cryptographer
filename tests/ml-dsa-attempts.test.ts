/**
 * The attempt log — ML-DSA signing's rejection loop read out of a trace, the
 * data behind the linear view's attempts panel and the verdict narrator (P5 of
 * `docs/plans/refactored-petting-tide.md`).
 *
 * Everything here runs the SHIPPED signing spec, never a toy: the reader exists
 * to read that spec's verdict frames, and a toy would pass while the real port
 * names drifted.
 *
 * What is pinned, and why each one discriminates:
 *
 * 1. **The default pair's numbers**, recorded in the plan from the trace: attempt
 *    1 fails z (131,029 vs 130,994) AND r0 (95,166 vs 95,154), attempt 2 fails
 *    r0 (95,190), attempt 3 is kept with z two under its bound (130,992). A
 *    reader that swapped two ports, or read the limit as the value, gets these
 *    wrong.
 * 2. **Agreement with the loop's own log.** The loop emits a one-byte bitmask
 *    per attempt; every row's failed set must equal it. Two independent
 *    channels out of the same run, so a reader that read a flag from the wrong
 *    port, or dropped a check, disagrees with the loop.
 *    What this does NOT catch: a reader that decided pass/fail by comparing
 *    value against limit. No real run puts a value exactly on its limit, so
 *    that reader agrees everywhere here. Section 6 pins it instead, on a
 *    hand-made frame whose flag contradicts its numbers.
 * 3. **The hint case** ("Hello, world! #17"): attempt 3 fails the hint count
 *    and NOTHING else, 81 ones against ω = 80. The only real-key case where the
 *    hint is the reason; it pins the `≤` column, not just the three norms.
 * 4. **The cap**: with one attempt allowed and the default message, the only
 *    attempt is rejected, so nothing is kept.
 * 5. **Scope.** Frames are grouped by the loop they came from; a frame outside
 *    the loop belongs to no attempt.
 * 6. **The flag decides.** The comparison rule lives in the check steps; the
 *    reader must report the flag even when value vs limit says otherwise.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_ATTEMPTS_ID,
  MLDSA_RELEASE_ID,
  ML_DSA_44_DEFAULT_MESSAGE,
  ML_DSA_44_DEFAULT_SIGNATURE,
  buildMlDsa44SignSpec,
  buildMlDsa44VerifySpec,
} from "@/ciphers/ml-dsa-44";
import { runSpec } from "@/core/runtime";
import type { AuxValue, CipherSpec, Trace, TraceFrame } from "@/core/types";
import { type AttemptCheck, failedChecks } from "@/steps/ml-dsa-attempt-verdict";
import {
  type AttemptLog,
  attemptLogFromFrames,
  attemptOfFrame,
  checkRelation,
  isAttemptLogRelevant,
  readAttemptChecks,
} from "@/ui/narration/ml-dsa-attempts";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

const run = (spec: CipherSpec, input: Uint8Array): Trace =>
  runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: input },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });

// Each signing run takes most of a second; run each case once.
const lazy = <T>(f: () => T): (() => T) => {
  let v: T | undefined;
  return () => {
    if (v === undefined) v = f();
    return v;
  };
};

const defaultTrace = lazy(() => run(buildMlDsa44SignSpec(), ML_DSA_44_DEFAULT_MESSAGE));
const hintTrace = lazy(() => {
  const c = FIXTURE.p4.hint as { message: string; context: string };
  return run(buildMlDsa44SignSpec({ context: unhex(c.context) }), unhex(c.message));
});
const cappedTrace = lazy(() =>
  run(buildMlDsa44SignSpec({ attemptCap: 1 }), ML_DSA_44_DEFAULT_MESSAGE),
);

const logOf = (t: Trace): AttemptLog => {
  const log = attemptLogFromFrames(t.frames);
  if (log === null) throw new Error("expected an attempt log");
  return log;
};

/** The loop's own per-attempt bitmask, as the release step received it. */
const loopLog = (t: Trace): Uint8Array => {
  const release = t.frames.find((f) => f.stepId === MLDSA_RELEASE_ID);
  const log = release?.portInputs?.get("log");
  if (!(log instanceof Uint8Array)) throw new Error("no release log");
  return log;
};

const failedOf = (log: AttemptLog, attempt: number): AttemptCheck[] =>
  (log.rows[attempt - 1]?.checks ?? []).filter((c) => !c.ok).map((c) => c.check);

const reading = (log: AttemptLog, attempt: number, check: AttemptCheck) => {
  const r = log.rows[attempt - 1]?.checks.find((c) => c.check === check);
  if (r === undefined) throw new Error(`no ${check} reading on attempt ${attempt}`);
  return r;
};

describe("attemptLogFromFrames — the default pair", () => {
  it("finds three attempts, keeps the third, and indexes each verdict frame", () => {
    const t = defaultTrace();
    const log = logOf(t);
    expect(log.rows.map((r) => r.attempt)).toEqual([1, 2, 3]);
    expect(log.rows.map((r) => r.accepted)).toEqual([false, false, true]);
    expect(log.acceptedAttempt).toBe(3);
    expect(log.loopPath).toEqual([MLDSA_ATTEMPTS_ID]);
    for (const row of log.rows) {
      const f = t.frames[row.frameIndex];
      expect(f?.stepType).toBe("ml-dsa.attempt-verdict@1");
      expect(f?.blockIndex).toBe(row.attempt - 1);
    }
  });

  it("reads the measured values and limits the plan recorded from this trace", () => {
    const log = logOf(defaultTrace());
    expect(failedOf(log, 1)).toEqual(["z", "r0"]);
    expect(reading(log, 1, "z")).toMatchObject({ value: 131_029, limit: 130_994, ok: false });
    expect(reading(log, 1, "r0")).toMatchObject({ value: 95_166, limit: 95_154, ok: false });
    expect(failedOf(log, 2)).toEqual(["r0"]);
    expect(reading(log, 2, "r0")).toMatchObject({ value: 95_190, ok: false });
    expect(failedOf(log, 3)).toEqual([]);
    expect(reading(log, 3, "z")).toMatchObject({ value: 130_992, limit: 130_994, ok: true });
  });

  it("agrees with the loop's own per-attempt log on every attempt", () => {
    const t = defaultTrace();
    const log = logOf(t);
    const bitmask = loopLog(t);
    expect(log.rows.length).toBe(bitmask.length);
    log.rows.forEach((row, i) => {
      expect(failedOf(log, row.attempt)).toEqual(failedChecks(bitmask[i] as number));
    });
  });
});

describe("attemptLogFromFrames — the hint and the cap", () => {
  it("the #17 case's third attempt fails the hint count and nothing else", () => {
    const t = hintTrace();
    const log = logOf(t);
    expect(failedOf(log, 3)).toEqual(["hint"]);
    const h = reading(log, 3, "hint");
    expect(h).toMatchObject({ value: 81, limit: 80, ok: false });
    // The hint's failing relation is ">" (the count may EQUAL ω), not "≥".
    expect(checkRelation("hint", h.ok)).toBe(">");
    const bitmask = loopLog(t);
    log.rows.forEach((row, i) => {
      expect(failedOf(log, row.attempt)).toEqual(failedChecks(bitmask[i] as number));
    });
  });

  it("with a cap of one, the only attempt is rejected and nothing is kept", () => {
    const log = logOf(cappedTrace());
    expect(log.rows.length).toBe(1);
    expect(log.rows[0]?.accepted).toBe(false);
    expect(log.acceptedAttempt).toBeNull();
  });
});

describe("attemptOfFrame / isAttemptLogRelevant — which frames the panel is about", () => {
  it("a body frame belongs to its attempt; key material and the precomputation to none", () => {
    const t = defaultTrace();
    const log = logOf(t);
    const inLoop = t.frames.filter((f) => attemptOfFrame(f, log) !== null);
    expect(inLoop.length).toBeGreaterThan(0);
    for (const f of inLoop) expect(attemptOfFrame(f, log)).toBe((f.blockIndex ?? -1) + 1);
    const first = t.frames[0] as TraceFrame;
    expect(attemptOfFrame(first, log)).toBeNull();
    expect(isAttemptLogRelevant(first, log)).toBe(false);
  });

  it("the release step, after the loop, is still about the attempts", () => {
    const t = defaultTrace();
    const log = logOf(t);
    const release = t.frames.find((f) => f.stepId === MLDSA_RELEASE_ID) as TraceFrame;
    expect(attemptOfFrame(release, log)).toBeNull();
    expect(isAttemptLogRelevant(release, log)).toBe(true);
  });

  it("groups by loop scope: verdicts from a second loop do not mix into the first", () => {
    const log = logOf(defaultTrace());
    const t = defaultTrace();
    // A synthetic second loop: the same verdict frames, re-homed under another path.
    const rehomed = t.frames.map((f) =>
      f.stepType === "ml-dsa.attempt-verdict@1" ? { ...f, path: ["other-loop"] } : f,
    );
    const both = [...t.frames, ...rehomed.filter((f) => f.path[0] === "other-loop")];
    expect(attemptLogFromFrames(both)?.rows.length).toBe(log.rows.length);
    const otherActive = rehomed.find((f) => f.path[0] === "other-loop") as TraceFrame;
    expect(attemptLogFromFrames(both, otherActive)?.loopPath).toEqual(["other-loop"]);
  });
});

describe("attemptLogFromFrames — every other trace", () => {
  it("ML-DSA verification has no attempt loop", () => {
    const t = run(buildMlDsa44VerifySpec(), ML_DSA_44_DEFAULT_SIGNATURE);
    expect(attemptLogFromFrames(t.frames)).toBeNull();
  });
});

describe("readAttemptChecks — the check step's flag decides, never value vs limit", () => {
  it("reports what the flags say even when the numbers would disagree", () => {
    // Taken from a real verdict frame, then edited: z's flag says PASS while
    // its value sits above its limit, and the hint's flag says FAIL at a count
    // equal to ω (which the real `≤` rule would pass). A reader that compared
    // numbers would flip both.
    const real = defaultTrace().frames.find(
      (f) => f.stepType === "ml-dsa.attempt-verdict@1",
    ) as TraceFrame;
    const inputs = new Map(real.portInputs ?? []);
    inputs.set("zOk", new Uint8Array([1]));
    inputs.set("zNorm", new Uint8Array([0, 2, 0, 0]));
    inputs.set("zBound", new Uint8Array([0, 1, 0, 0]));
    inputs.set("hintOk", new Uint8Array([0]));
    inputs.set("hintCount", new Uint8Array([80]));
    inputs.set("omega", new Uint8Array([80]));
    const checks = readAttemptChecks({ ...real, portInputs: inputs });
    expect(checks?.find((c) => c.check === "z")).toMatchObject({ ok: true, value: 131_072 });
    expect(checks?.find((c) => c.check === "hint")).toMatchObject({ ok: false, value: 80 });
  });

  it("declines a frame with a missing display port rather than guessing", () => {
    const real = defaultTrace().frames.find(
      (f) => f.stepType === "ml-dsa.attempt-verdict@1",
    ) as TraceFrame;
    const inputs = new Map(real.portInputs ?? []);
    inputs.delete("r0Norm");
    expect(readAttemptChecks({ ...real, portInputs: inputs })).toBeNull();
  });
});
