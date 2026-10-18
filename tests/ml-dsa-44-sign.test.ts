/**
 * ML-DSA-44 SIGNING as a shipped spec (P4 of `docs/plans/refactored-petting-tide.md`).
 *
 * Signing is FIPS 204's rejection loop: make a candidate, check four bounds,
 * throw it away and try again until one passes. The spec runs it as a
 * port-mode `iterate` with `stopWhen` (tests/runtime-iterate-stop-when.test.ts
 * proves that loop on a toy). This file proves the SIGNING spec, strongest
 * claim first:
 *
 * 1. **Byte-exact against noble's deterministic signatures**, which Node 24
 *    verifies (fixture `p3.defaultPair` and `p4.*`). A wrong rejection rule
 *    changes how many attempts run, hence the mask, hence every byte — so the
 *    attempt COUNT is pinned implicitly by the bytes.
 * 2. **Which checks rejected each attempt**, read off the attempt verdict's own
 *    input flags and the loop's per-attempt log. Noble records only the FIRST
 *    failed check in its order (z, then r0/ct0 row by row, then the hint count);
 *    the spec computes all four every attempt. So a recorded "z" is asserted as
 *    containment — z is AMONG the failures — while a recorded "hint" is exact:
 *    noble reaches the hint count only after every other check passed.
 * 3. **The output is verified by our own verification spec** (whose P3 tests
 *    hold it to Node), and the default signature equals the one P3 ships.
 * 4. **ct0 has no external case** (no real key reaches it: the plan records the
 *    measurement). A test-side copy tightens ONLY the ct0 check's bound and
 *    asserts the wiring: the flag, the log, the retry.
 * 5. **The cap**: a run that hits it emits NO signature, not 2,420 zero-ish
 *    bytes that would look real.
 */

import { buildDefaultRegistry } from "@/ciphers/default-registry";
import {
  MLDSA_ATTEMPTS_ID,
  MLDSA_ATTEMPT_PREFIX,
  MLDSA_ATTEMPT_VERDICT_ID,
  MLDSA_RELEASE_ID,
  MLDSA_SIGN_HARVEST_ID,
  MLDSA_VERDICT_ID,
  ML_DSA_44_DEFAULT_ATTEMPT_CAP,
  ML_DSA_44_DEFAULT_MESSAGE,
  ML_DSA_44_DEFAULT_SIGNATURE,
  ML_DSA_44_SIG_BYTES,
  type MlDsaSignOptions,
  buildMlDsa44SignSpec,
  buildMlDsa44VerifySpec,
} from "@/ciphers/ml-dsa-44";
import { runSpec } from "@/core/runtime";
import { validateShapes } from "@/core/spec-shapes";
import type { AuxValue, CipherSpec, StepNode, Trace, TraceFrame } from "@/core/types";
import { type AttemptCheck, failedChecks } from "@/steps/ml-dsa-attempt-verdict";
import { describe, expect, it } from "vitest";
import FIXTURE from "./fixtures/ml-dsa-44-vectors.json";

const registry = buildDefaultRegistry();

const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const unhex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

type Case = {
  readonly message: string;
  readonly context: string;
  readonly attempts: readonly string[];
  readonly deterministic: string;
  readonly hintCounts?: readonly number[];
};
const P4 = FIXTURE.p4 as unknown as {
  readonly hint: Case;
  readonly firstTry: Case;
  readonly withContext: Case;
};
const DEFAULT_PAIR = FIXTURE.p3.defaultPair as unknown as Case;
/** The cases only — the section also carries a `note`. */
const P4_CASES: Readonly<Record<string, Case>> = {
  hint: P4.hint,
  firstTry: P4.firstTry,
  withContext: P4.withContext,
};

const VERDICT = `${MLDSA_ATTEMPT_PREFIX}${MLDSA_ATTEMPT_VERDICT_ID}`;

// ─── Harness ───────────────────────────────────────────────────────────────

type SignRun = {
  readonly trace: Trace;
  /** The spec's output: the signature, or empty if the cap was reached. */
  readonly output: Uint8Array;
  /** Attempts that ran — the loop's per-attempt `failed` log. */
  readonly log: Uint8Array;
  /** The attempt verdict's frame for attempt i (0-based). */
  readonly verdict: (i: number) => TraceFrame;
  readonly ms: number;
};

/** Runs are memoized by spec object: a signature takes several attempts. */
const memo = new WeakMap<CipherSpec, Map<string, SignRun>>();
const sign = (spec: CipherSpec, message: Uint8Array): SignRun => {
  const byMsg = memo.get(spec) ?? new Map<string, SignRun>();
  memo.set(spec, byMsg);
  const hit = byMsg.get(hex(message));
  if (hit !== undefined) return hit;
  const t0 = performance.now();
  const trace = runSpec(spec, registry, {
    initialState: { shape: "bytes", bytes: message },
    initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
  });
  const ms = performance.now() - t0;
  if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
  const frames = new Map(trace.frames.map((f) => [f.stepId, f]));
  const release = frames.get(MLDSA_RELEASE_ID);
  const log = release?.portInputs?.get("log");
  if (!(log instanceof Uint8Array)) throw new Error("no release log");
  const fresh: SignRun = {
    trace,
    output: trace.finalState.bytes,
    log,
    verdict: (i) => {
      const f = frames.get(`${VERDICT}:b${i}`);
      if (f === undefined) throw new Error(`no verdict frame for attempt ${i + 1}`);
      return f;
    },
    ms,
  };
  byMsg.set(hex(message), fresh);
  return fresh;
};

const specs = new Map<string, CipherSpec>();
const specFor = (options: MlDsaSignOptions = {}): CipherSpec => {
  const key = JSON.stringify({
    c: options.context ? hex(options.context) : "",
    cap: options.attemptCap ?? null,
  });
  const hit = specs.get(key);
  if (hit !== undefined) return hit;
  const spec = buildMlDsa44SignSpec(options);
  specs.set(key, spec);
  return spec;
};

const signCase = (c: Case): SignRun =>
  sign(specFor({ context: unhex(c.context) }), unhex(c.message));

/** The checks an attempt verdict's INPUT flags say failed. */
const failedFromInputs = (f: TraceFrame): AttemptCheck[] => {
  const ok = (name: string) => f.portInputs?.get(name)?.[0] === 1;
  return (["z", "r0", "ct0", "hint"] as const).filter((c) => !ok(`${c}Ok`));
};

/** Assert a run's attempts against noble's FIRST-failure record. */
const expectAttempts = (run: SignRun, recorded: readonly string[]): void => {
  expect(run.log.length, "attempts run").toBe(recorded.length);
  recorded.forEach((reason, i) => {
    const fromInputs = failedFromInputs(run.verdict(i));
    // The log byte and the verdict's input flags must tell the same story.
    expect(failedChecks(run.log[i] as number), `attempt ${i + 1}: log vs flags`).toEqual(
      fromInputs,
    );
    if (reason === "accepted") {
      expect(fromInputs, `attempt ${i + 1}`).toEqual([]);
    } else if (reason === "hint") {
      // Noble reached the hint count, so every other check passed: exact.
      expect(fromInputs, `attempt ${i + 1}`).toEqual(["hint"]);
    } else {
      // Noble stopped at its first failure; others may have failed too.
      expect(fromInputs, `attempt ${i + 1}`).toContain(reason);
    }
  });
};

// ─── 1. Byte-exact against noble (which Node verifies) ─────────────────────

describe("ML-DSA-44 signing spec = noble's deterministic signatures, byte for byte", () => {
  it("the default pair: 2420 bytes, and P3's shipped default signature", () => {
    const run = sign(specFor(), ML_DSA_44_DEFAULT_MESSAGE);
    expect(run.output.length).toBe(ML_DSA_44_SIG_BYTES);
    expect(hex(run.output)).toBe(DEFAULT_PAIR.deterministic);
    expect(hex(run.output)).toBe(hex(ML_DSA_44_DEFAULT_SIGNATURE));
  });

  for (const [name, c] of Object.entries(P4_CASES)) {
    it(`p4.${name}: ${c.attempts.length} attempt(s), noble's bytes`, () => {
      expect(hex(signCase(c).output)).toBe(c.deterministic);
    });
  }
});

// ─── 2. Which checks rejected each attempt ─────────────────────────────────

describe("each attempt's verdict matches what rejected it", () => {
  it("the default pair: z, then r0, then accepted — the shape first paint shows", () => {
    expectAttempts(sign(specFor(), ML_DSA_44_DEFAULT_MESSAGE), DEFAULT_PAIR.attempts);
  });

  for (const [name, c] of Object.entries(P4_CASES)) {
    it(`p4.${name}: ${c.attempts.join(", ")}`, () => expectAttempts(signCase(c), c.attempts));
  }

  it("the hint case's third attempt: 81 ones against ω = 80, and nothing else wrong", () => {
    const run = signCase(P4.hint);
    const f = run.verdict(2);
    expect(failedFromInputs(f)).toEqual(["hint"]);
    const count = f.portInputs?.get("hintCount");
    expect(count && (count[0] as number) * 256 + (count[1] as number)).toBe(81);
    // The accepted attempt's count, from the same fixture record.
    const last = run.verdict(P4.hint.attempts.length - 1).portInputs?.get("hintCount");
    expect(last && (last[0] as number) * 256 + (last[1] as number)).toBe(
      P4.hint.hintCounts?.at(-1),
    );
  });

  it("the loop's output is a one-byte-per-attempt log, and the loop stops at acceptance", () => {
    const run = sign(specFor(), ML_DSA_44_DEFAULT_MESSAGE);
    expect(run.log.length).toBe(3);
    expect(run.trace.frames.some((f) => f.stepId === `${VERDICT}:b3`)).toBe(false);
  });
});

// ─── 3. Verified by the verification spec ──────────────────────────────────

describe("the signatures verify", () => {
  const verify = (message: Uint8Array, context: Uint8Array, sig: Uint8Array): number => {
    const spec = buildMlDsa44VerifySpec({ message, context });
    const trace = runSpec(spec, registry, {
      initialState: { shape: "bytes", bytes: sig },
      initialAux: new Map<string, AuxValue>([["key", new Uint8Array(0)]]),
    });
    if (trace.finalState.shape !== "bytes") throw new Error("expected bytes");
    return trace.finalState.bytes[0] as number;
  };

  it("with and without a context string", () => {
    const plain = signCase(P4.firstTry);
    expect(verify(unhex(P4.firstTry.message), new Uint8Array(0), plain.output)).toBe(1);
    const ctx = signCase(P4.withContext);
    expect(verify(unhex(P4.withContext.message), unhex(P4.withContext.context), ctx.output)).toBe(
      1,
    );
    // The context is bound into the signature: the same bytes under no context fail.
    expect(verify(unhex(P4.withContext.message), new Uint8Array(0), ctx.output)).toBe(0);
  });
});

// ─── 4. ct0: a wiring pin, since no real key reaches it ────────────────────

/** Rebind one input of one body leaf, everywhere it appears. */
const rebind = (
  spec: CipherSpec,
  leafId: string,
  portName: string,
  to: { node: string; port: string },
  extra: StepNode[] = [],
): CipherSpec => {
  const walk = (nodes: readonly StepNode[], inBody: boolean): StepNode[] => {
    const out = nodes.map((n): StepNode => {
      if (n.kind === "step") {
        return n.id === leafId ? { ...n, portInputs: { ...n.portInputs, [portName]: to } } : n;
      }
      const body = n.kind === "iterate" && n.id === MLDSA_ATTEMPTS_ID;
      return { ...n, children: walk(n.children, body) } as StepNode;
    });
    return inBody ? [...extra, ...out] : out;
  };
  return { ...spec, steps: walk(spec.steps, false) };
};

describe("the ct0 check is wired into the decision", () => {
  // A bound of 1 rejects any ct0 that is not all zeros — every attempt, since
  // c·t0 is never zero for a real key. Only the ct0 check's bound moves.
  // The verdict's display port is rebound too, so its narrator quotes the
  // limit that actually decided.
  const TIGHT = { node: `${MLDSA_ATTEMPT_PREFIX}tight`, port: "output" };
  const tight = rebind(
    rebind(
      buildMlDsa44SignSpec({ attemptCap: 3 }),
      `${MLDSA_ATTEMPT_PREFIX}check.ct0`,
      "bound",
      TIGHT,
      [
        {
          kind: "step",
          id: TIGHT.node,
          type: "constant-load@1",
          params: { bytes: [0, 0, 0, 1] },
        },
      ],
    ),
    VERDICT,
    "ct0Bound",
    TIGHT,
  );

  it("every attempt is rejected by ct0, the loop retries to its cap, and nothing is signed", () => {
    const run = sign(tight, ML_DSA_44_DEFAULT_MESSAGE);
    expect(run.log.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      expect(failedFromInputs(run.verdict(i))).toContain("ct0");
      expect(failedChecks(run.log[i] as number)).toContain("ct0");
    }
    expect(run.output.length).toBe(0);
  });

  it("the default bound (γ2) passes ct0 on every attempt of the default pair", () => {
    const run = sign(specFor(), ML_DSA_44_DEFAULT_MESSAGE);
    for (let i = 0; i < run.log.length; i++) {
      expect(failedFromInputs(run.verdict(i))).not.toContain("ct0");
    }
  });
});

// ─── 5. The cap ────────────────────────────────────────────────────────────

// ─── Perturbations, run not assumed ────────────────────────────────────────

describe("perturbations: each breaks the fixture in the way it should", () => {
  it("ω = 81 accepts the hint case's third attempt — 81 ones now fit — so it stops at 3", () => {
    // The fixture's one real edge case: that attempt had EXACTLY ω + 1 ones and
    // nothing else wrong. Editing ω by one flips it, which is the 'edit a bound,
    // watch the attempt count change' experiment the repeat-until loop exists for.
    const base = buildMlDsa44SignSpec();
    const spec: CipherSpec = {
      ...base,
      cipherConstants: { ...base.cipherConstants, omega: new Uint8Array([0, 0, 0, 81]) },
    };
    const run = sign(spec, unhex(P4.hint.message));
    expect(run.log.length).toBe(3);
    expect(failedFromInputs(run.verdict(2))).toEqual([]);
    expect(hex(run.output)).not.toBe(P4.hint.deterministic);
  });

  it("advancing κ by 1 instead of l reuses mask polynomials, and every later byte moves", () => {
    const spec = rebind(specFor(), `${MLDSA_ATTEMPT_PREFIX}kappa-next`, "operand1", {
      node: `${MLDSA_ATTEMPT_PREFIX}one`,
      port: "output",
    });
    const run = sign(spec, ML_DSA_44_DEFAULT_MESSAGE);
    expect(hex(run.output)).not.toBe(DEFAULT_PAIR.deterministic);
  });

  it("packing h WITHOUT the accept-bit select throws on the hint case's third attempt", () => {
    // Why the select exists: a rejected candidate need not FIT the packers,
    // which are strict on purpose (the P2 rule). That attempt's 81 ones cannot
    // go into ω = 80 slots. (A rejected z overshoots its packing range only
    // rarely — z exceeds γ1 − β far more often than γ1 itself, and the default
    // pair's rejected z fits, as P3's over-norm signature showed — so the hint
    // is the case that exercises the select.)
    const spec = rebind(specFor(), `${MLDSA_ATTEMPT_PREFIX}h.pack`, "h", {
      node: `${MLDSA_ATTEMPT_PREFIX}h`,
      port: "output",
    });
    expect(() => sign(spec, unhex(P4.hint.message))).toThrow(/ω|omega|81/);
  });
});

describe("the attempt cap", () => {
  it("reaching it emits no signature, and the harvested flag says why", () => {
    // The default pair needs three attempts; allow two.
    const run = sign(specFor({ attemptCap: 2 }), ML_DSA_44_DEFAULT_MESSAGE);
    expect(run.log.length).toBe(2);
    expect(run.output.length).toBe(0);
    const harvest = run.trace.frames.find((f) => f.stepId === MLDSA_SIGN_HARVEST_ID);
    expect(Array.from(harvest?.portOutputs?.get("output1") ?? [])).toEqual([0]);
  });

  it("defaults to 32 attempts (the measured budget — see the constant's comment)", () => {
    expect(ML_DSA_44_DEFAULT_ATTEMPT_CAP).toBe(32);
  });
});

// ─── Structure ─────────────────────────────────────────────────────────────

describe("the signing spec's structure", () => {
  it("passes the static checker with no warnings", () => {
    expect(validateShapes(specFor(), registry)).toEqual([]);
  });

  it("has unique node ids (the flat trace keys frames by id)", () => {
    const ids: string[] = [];
    const walk = (nodes: readonly StepNode[]) => {
      for (const n of nodes) {
        ids.push(n.id);
        if (n.kind !== "step") walk(n.children);
      }
    };
    walk(specFor().steps);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("does not reuse verification's verdict id for the attempt verdict", () => {
    expect(VERDICT).not.toBe(MLDSA_VERDICT_ID);
  });
});

// ─── Cost (logged, not asserted: the cap is set from it in the plan) ───────

describe("cost per attempt", () => {
  it("logs frames and milliseconds per attempt for the hint case (8 attempts)", () => {
    const run = signCase(P4.hint);
    const inLoop = run.trace.frames.filter((f) => f.path.includes(MLDSA_ATTEMPTS_ID)).length;
    const perAttempt = inLoop / run.log.length;
    console.log(
      `[ml-dsa sign cost] attempts=${run.log.length} frames=${run.trace.frames.length} inLoop=${inLoop} perAttempt=${perAttempt} ms=${run.ms.toFixed(0)}`,
    );
    expect(perAttempt).toBeGreaterThan(0);
    // Fresh (uncached) spec objects so neither run is a memo hit: the
    // difference between an 8-attempt and a 1-attempt signature is 7 attempts.
    const one = sign(buildMlDsa44SignSpec(), unhex(P4.firstTry.message));
    const eight = sign(buildMlDsa44SignSpec(), unhex(P4.hint.message));
    console.log(
      `[ml-dsa sign cost] 1 attempt ${one.ms.toFixed(0)} ms, 8 attempts ${eight.ms.toFixed(0)} ms ⇒ ${((eight.ms - one.ms) / 7).toFixed(0)} ms per attempt`,
    );
    // The default pair's measured values per attempt, for the docs' examples.
    const def = sign(specFor(), ML_DSA_44_DEFAULT_MESSAGE);
    const be = (b: Uint8Array | undefined) => (b ? b.reduce((v, x) => v * 256 + x, 0) : -1);
    for (let i = 0; i < def.log.length; i++) {
      const p = def.verdict(i).portInputs;
      console.log(
        `[ml-dsa sign default] attempt ${i + 1}: z=${be(p?.get("zNorm"))}/${be(p?.get("zBound"))} r0=${be(p?.get("r0Norm"))}/${be(p?.get("r0Bound"))} ct0=${be(p?.get("ct0Norm"))} h=${be(p?.get("hintCount"))}`,
      );
    }
  });
});
