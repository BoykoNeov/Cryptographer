/**
 * Reading ML-DSA signing's attempts out of a trace — the one parser shared by
 * the attempt verdict's narrator and the linear view's rejection-loop panel.
 *
 * ## Why this module exists
 *
 * Signing is a repeat-until loop (FIPS 204 Algorithm 7): each attempt builds a
 * candidate signature and `ml-dsa.attempt-verdict@1` keeps it only if four
 * bounds hold. That step receives, per check, a FLAG (which alone decides), the
 * measured VALUE and the LIMIT it was held to. Two surfaces read those ports:
 * the narrator (one attempt, in prose) and the panel (every attempt, as a
 * table). Kept as two hand-written readers they would drift — the endpoint-label
 * bug, where the sidebar and the graph pills disagreed, was exactly that — so
 * both import from here.
 *
 * ## Pass or fail comes from the flag, never from value vs limit
 *
 * The comparison rule (strict `<` for the three norms, `≤` for the hint count)
 * lives in the check steps and nowhere else. Re-comparing here would give the
 * UI a second opinion on an edge case — a value exactly AT its limit — that
 * could disagree with the step that actually decided. The relation glyph a
 * reader sees (`<` / `≥`, `≤` / `>`) is chosen FROM the flag.
 *
 * ## Why the log's numbers come from verdict frames, not the loop's output
 *
 * The loop's per-attempt output (`out`) is a one-byte bitmask: it says WHICH
 * checks failed, not by how much. The values and limits exist only on each
 * verdict frame's input ports, so the rows are built from those frames.
 *
 * No Solid components in this file: it is plain data in, plain data (and
 * strings) out. `num` is the lattice narrators' number format, shared so the
 * panel and the prose print a value the same way.
 */

import { iterateScopeKey } from "@/core/step-id";
import type { TraceFrame } from "@/core/types";
import {
  ATTEMPT_CHECKS,
  type AttemptCheck,
  attemptCheckPorts,
} from "@/steps/ml-dsa-attempt-verdict";
import { num } from "./lattice";

/** The step type whose frames close each attempt. */
export const ATTEMPT_VERDICT_TYPE = "ml-dsa.attempt-verdict@1";

/** The step type that hands out the signature (or nothing) after the loop. */
export const RELEASE_SIGNATURE_TYPE = "ml-dsa.release-signature@1";

/** Labels for the four checks, as a learner reads them. */
export const CHECK_LABEL: Record<AttemptCheck, { readonly value: string; readonly limit: string }> =
  {
    z: { value: "‖z‖∞", limit: "γ1 − β" },
    r0: { value: "‖r0‖∞", limit: "γ2 − β" },
    ct0: { value: "‖c·t0‖∞", limit: "γ2" },
    hint: { value: "#h", limit: "ω" },
  };

/**
 * The relation between value and limit, chosen from the flag. Norms must be
 * strictly below their bound (`<`, failing as `≥`); the hint count may equal ω
 * (`≤`, failing as `>`).
 */
export const checkRelation = (check: AttemptCheck, ok: boolean): string =>
  check === "hint" ? (ok ? "≤" : ">") : ok ? "<" : "≥";

/** One check's measured value against its limit, e.g. "‖z‖∞ = 131,029 ≥ γ1 − β = 130,994". */
export const checkLine = (
  check: AttemptCheck,
  value: number,
  limit: number,
  ok: boolean,
): string => {
  const { value: v, limit: l } = CHECK_LABEL[check];
  return `${v} = ${num(value)} ${checkRelation(check, ok)} ${l} = ${num(limit)}`;
};

/** The relation a check must SATISFY, for a column header: `<` or `≤`. */
export const passingRelation = (check: AttemptCheck): string => checkRelation(check, true);

/** A scalar input port (γ2, a bound, ω, a norm) as a number, or null. */
export const scalarOf = (frame: TraceFrame, name: string): number | null => {
  const bytes = frame.portInputs?.get(name);
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > 6) return null;
  let v = 0;
  for (const b of bytes) v = v * 256 + b;
  return v;
};

/** One check, as one attempt's verdict frame recorded it. */
export type CheckReading = {
  readonly check: AttemptCheck;
  /** The check step's own answer — the only thing that decides. */
  readonly ok: boolean;
  /** What was measured (a norm, or the hint's count of ones). */
  readonly value: number;
  /** What it was held to (γ1 − β, γ2 − β, γ2, or ω). */
  readonly limit: number;
};

/**
 * The four checks a verdict frame recorded, in FIPS 204's order, or null when
 * the frame is not a verdict or a port is missing (a learner's half-rewired
 * spec renders nothing rather than a guess).
 */
export const readAttemptChecks = (frame: TraceFrame): CheckReading[] | null => {
  if (frame.stepType !== ATTEMPT_VERDICT_TYPE) return null;
  const rows: CheckReading[] = [];
  for (const { name } of ATTEMPT_CHECKS) {
    const ports = attemptCheckPorts(name);
    const ok = frame.portInputs?.get(ports.ok);
    const value = scalarOf(frame, ports.value);
    const limit = scalarOf(frame, ports.limit);
    if (!(ok instanceof Uint8Array) || ok.length !== 1 || value === null || limit === null) {
      return null;
    }
    rows.push({ check: name, ok: ok[0] === 1, value, limit });
  }
  return rows;
};

/** One attempt of the loop, as the panel draws it. */
export type AttemptRow = {
  /** 1-based, as a learner counts. */
  readonly attempt: number;
  /** Index of this attempt's verdict frame in `trace.frames` — click-to-scrub. */
  readonly frameIndex: number;
  readonly checks: readonly CheckReading[];
  /** The verdict's own `accepted` output. */
  readonly accepted: boolean;
};

/** Every attempt one signing loop ran. */
export type AttemptLog = {
  /** The container path of the loop's body frames (scope key for "in the loop"). */
  readonly loopPath: readonly string[];
  readonly rows: readonly AttemptRow[];
  /** The attempt that was kept (1-based), or null if every attempt was rejected. */
  readonly acceptedAttempt: number | null;
};

/**
 * Build the attempt log from a trace's frames, or null if the trace holds no
 * signing loop (every other algorithm, and ML-DSA verification).
 *
 * Frames are grouped by the scope they were emitted in (`iterateScopeKey`),
 * never by a trace-wide `blockIndex` — the NTT's seven sibling loops are what
 * taught the app that lesson. Today's signing spec has exactly one loop; when
 * more than one scope holds verdicts, the one containing `active` wins, else
 * the first in trace order.
 */
export const attemptLogFromFrames = (
  frames: readonly TraceFrame[],
  active?: TraceFrame,
): AttemptLog | null => {
  const byScope = new Map<string, { path: readonly string[]; rows: AttemptRow[] }>();
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    if (f === undefined || f.stepType !== ATTEMPT_VERDICT_TYPE || f.blockIndex === undefined) {
      continue;
    }
    const checks = readAttemptChecks(f);
    const accepted = f.portOutputs?.get("accepted");
    if (checks === null || !(accepted instanceof Uint8Array)) continue;
    const key = iterateScopeKey(f.path);
    const scope = byScope.get(key) ?? { path: f.path, rows: [] };
    byScope.set(key, scope);
    scope.rows.push({
      attempt: f.blockIndex + 1,
      frameIndex: i,
      checks,
      accepted: accepted[0] === 1,
    });
  }
  if (byScope.size === 0) return null;
  const activeKey = active === undefined ? undefined : iterateScopeKey(active.path);
  const chosen =
    (activeKey !== undefined ? byScope.get(activeKey) : undefined) ?? byScope.values().next().value;
  if (chosen === undefined) return null;
  const rows = [...chosen.rows].sort((a, b) => a.attempt - b.attempt);
  const kept = rows.find((r) => r.accepted);
  return { loopPath: chosen.path, rows, acceptedAttempt: kept?.attempt ?? null };
};

/**
 * Which attempt `frame` belongs to (1-based), or null when it is outside the
 * loop. A frame is inside when it carries a block index and its path starts
 * with the loop's — so a leaf nested in a group inside the body still counts.
 */
export const attemptOfFrame = (frame: TraceFrame, log: AttemptLog): number | null => {
  if (frame.blockIndex === undefined) return null;
  if (frame.path.length < log.loopPath.length) return null;
  for (let i = 0; i < log.loopPath.length; i++) {
    if (frame.path[i] !== log.loopPath[i]) return null;
  }
  return frame.blockIndex + 1;
};

/**
 * Is the panel "about" this frame? Inside the loop, or the release step that
 * reads the loop's log. Everywhere else in signing (key material, the
 * precomputation) the panel starts collapsed so it does not crowd the step.
 */
export const isAttemptLogRelevant = (frame: TraceFrame, log: AttemptLog): boolean =>
  attemptOfFrame(frame, log) !== null || frame.stepType === RELEASE_SIGNATURE_TYPE;
