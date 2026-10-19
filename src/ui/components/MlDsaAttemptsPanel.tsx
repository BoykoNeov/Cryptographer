/**
 * ML-DSA signing's rejection loop, one row per attempt — the linear view's
 * picture of the thing that makes ML-DSA signing unlike every other algorithm
 * in the app: it does not know in advance how much work it will do.
 *
 * Self-detects a trace containing `ml-dsa.attempt-verdict@1` frames (only the
 * ML-DSA-44 signing spec has them) and renders nothing otherwise.
 *
 * **What a learner should take from it.** Each attempt signs the WHOLE message
 * again with a fresh mask, then holds the candidate to four bounds. A candidate
 * that fails any of them is thrown away, because publishing it could leak the
 * secret key (z, r0) or fail to verify (c·t0, the hint). Roughly one attempt in
 * four passes, so a signature usually takes several — and the narrator for one
 * attempt cannot show that, because it sees only its own frame. The table puts
 * every attempt's four measured values next to their limits, so the near
 * misses are visible: the default pair's third attempt keeps z just 2 under its
 * bound, while its first misses by 36.
 *
 * Data comes from `attemptLogFromFrames` (shared with the step's narrator);
 * pass/fail is each check step's own flag, never re-compared here.
 *
 * Collapsing follows `RoundKeyPanel`: expanded on frames the panel is about
 * (inside the loop, and the release step that reads its log), collapsed
 * elsewhere, and a click on the header overrides that until the spec changes.
 */

import type { TraceFrame } from "@/core/types";
import { ATTEMPT_CHECKS, type AttemptCheck } from "@/steps/ml-dsa-attempt-verdict";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { num } from "../narration/lattice";
import {
  type AttemptLog,
  type AttemptRow,
  CHECK_LABEL,
  attemptLogFromFrames,
  attemptOfFrame,
  checkLine,
  isAttemptLogRelevant,
  passingRelation,
} from "../narration/ml-dsa-attempts";
import { useSpec } from "../stores/spec";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";

type Props = {
  frame: TraceFrame;
};

/**
 * User override for collapsed/expanded. Module-scope so a click sticks across
 * scrubs; reset to `null` (follow the frame) when the spec changes.
 */
const [overrideExpanded, setOverrideExpanded] = createSignal<boolean | null>(null);

/** Test-only: clear the override so cases don't leak state. */
export const __resetMlDsaAttemptsPanelForTests = (): void => {
  setOverrideExpanded(null);
};

/** The limit a column is held to, read off the first attempt (it is a constant of the run). */
const limitOf = (log: AttemptLog, check: AttemptCheck): number | null =>
  log.rows[0]?.checks.find((c) => c.check === check)?.limit ?? null;

/** "‖z‖∞ < 130,994" — the column header. */
const columnHeader = (log: AttemptLog, check: AttemptCheck): string => {
  const limit = limitOf(log, check);
  const { value } = CHECK_LABEL[check];
  return limit === null ? value : `${value} ${passingRelation(check)} ${num(limit)}`;
};

/** One-line summary for the header, readable while collapsed. */
const summaryOf = (log: AttemptLog): string => {
  const n = log.rows.length;
  if (log.acceptedAttempt !== null) {
    return log.acceptedAttempt === 1
      ? "accepted on the first attempt"
      : `accepted on attempt ${log.acceptedAttempt} of ${n}`;
  }
  return `no signature — all ${n} attempt${n === 1 ? "" : "s"} rejected`;
};

export const MlDsaAttemptsPanel = (props: Props) => {
  const spec = useSpec();
  const version = useTraceVersion();

  // A new spec (another algorithm, or the learner's edit) forgets the click.
  createEffect(
    on(
      () => spec().id,
      () => setOverrideExpanded(null),
      { defer: true },
    ),
  );

  const log = createMemo<AttemptLog | null>(() => {
    void version();
    const t = getTrace();
    if (!t) return null;
    return attemptLogFromFrames(t.frames, props.frame);
  });

  const expanded = createMemo<boolean>(() => {
    const override = overrideExpanded();
    if (override !== null) return override;
    const l = log();
    return l !== null && isAttemptLogRelevant(props.frame, l);
  });

  /** The attempt the user is looking at, for the "you are here" accent. */
  const currentAttempt = createMemo<number | null>(() => {
    const l = log();
    return l === null ? null : attemptOfFrame(props.frame, l);
  });

  const scrubTo = (row: AttemptRow): void => setFrame(row.frameIndex);

  /**
   * Keyboard parity with the diagrams. The focusable thing is the button in
   * the row's first cell; a click anywhere on the row scrubs too. Enter/Space
   * on the focused button reaches the row as a keydown, and is handled once
   * here (the default is prevented, so the button's own click does not fire a
   * second scrub).
   */
  const onKey = (row: AttemptRow) => (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      scrubTo(row);
    }
  };

  const rowClass = (row: AttemptRow): string => {
    let cls = "ml-dsa-attempts-row";
    if (row.accepted) cls += " ml-dsa-attempts-row-accepted";
    if (row.attempt === currentAttempt()) cls += " ml-dsa-attempts-row-current";
    return cls;
  };

  return (
    <Show when={log()}>
      {(getLog) => (
        <section class="ml-dsa-attempts-panel" aria-label="signing attempts">
          <button
            type="button"
            class="round-key-panel-header"
            onClick={() => setOverrideExpanded(!expanded())}
            aria-expanded={expanded()}
          >
            <span class="round-key-panel-chevron">{expanded() ? "▼" : "▶"}</span>
            <span class="round-key-panel-title">signing attempts</span>
            <span class="ml-dsa-attempts-summary small">{summaryOf(getLog())}</span>
            <span class="round-key-panel-hint muted small">
              {expanded() ? "click to hide" : "click to show"}
            </span>
          </button>
          <Show when={expanded()}>
            <div class="ml-dsa-attempts-body">
              <table class="ml-dsa-attempts-table">
                <thead>
                  <tr>
                    <th scope="col">attempt</th>
                    <For each={ATTEMPT_CHECKS}>
                      {(c) => (
                        <th scope="col" class="ml-dsa-attempts-num">
                          {columnHeader(getLog(), c.name)}
                        </th>
                      )}
                    </For>
                    <th scope="col">result</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={getLog().rows}>
                    {(row) => (
                      <tr
                        class={rowClass(row)}
                        aria-current={row.attempt === currentAttempt() ? "step" : undefined}
                        onClick={() => scrubTo(row)}
                        onKeyDown={onKey(row)}
                      >
                        <th scope="row">
                          <button
                            type="button"
                            class="ml-dsa-attempts-go"
                            title={`go to attempt ${row.attempt}'s verdict`}
                          >
                            {row.attempt}
                          </button>
                        </th>
                        <For each={row.checks}>
                          {(c) => (
                            <td
                              class={
                                c.ok
                                  ? "ml-dsa-attempts-num ml-dsa-attempts-pass"
                                  : "ml-dsa-attempts-num ml-dsa-attempts-fail"
                              }
                              title={checkLine(c.check, c.value, c.limit, c.ok)}
                            >
                              {num(c.value)} {c.ok ? "✓" : "✗"}
                            </td>
                          )}
                        </For>
                        <td>{row.accepted ? "accepted" : "rejected"}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
              <p class="muted small ml-dsa-attempts-note">
                Every attempt signs the whole message again with a fresh mask, then checks the
                candidate against four limits. One failure is enough to throw it away: publishing it
                could reveal the secret key (z, r0) or fail to verify (c·t0, the hint). All four
                checks run on every attempt, so one attempt can fail several. About one attempt in
                four passes. Click a row to go to that attempt's verdict.
              </p>
            </div>
          </Show>
        </section>
      )}
    </Show>
  );
};
