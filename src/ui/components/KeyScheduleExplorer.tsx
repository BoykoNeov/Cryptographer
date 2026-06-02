/**
 * Key-Schedule Explorer — Phase 2 of the linear-mode pedagogy plan.
 *
 * Surfaces the hidden internal machinery of the still-monolithic DES
 * key-schedule executor. The standard `<FrameStateView />` for a
 * key-expansion frame renders the unchanged input state matrix on both
 * "before" and "after" sides (the executor only writes aux; state passes
 * through) — useless. This component takes the slot instead and renders the
 * algorithm's intermediate decomposition: the per-round PC-1/shift/PC-2
 * table for DES.
 *
 * **AES branch RETIRED (key-schedule-decomposition K1c, 2026-06-01) and
 * Serpent branch RETIRED (K3b, 2026-06-02).** Both schedules are now
 * decomposed into port-native primitives, so the stages they used to
 * simulate (RotWord/SubWord/Rcon/word-XOR for AES; prekey recurrence +
 * bitsliced S-box + IP for Serpent) are real scrubbable trace frames — each
 * swimlane was unreachable (no `aes.key-expansion@1` / `serpent.key-expansion@1`
 * frame ships from a builder-routed spec) and redundant. DES keeps its
 * simulator until K4 decomposes it.
 *
 * Dispatch:
 *   - Looks up the frame's stepType in the simulator registry
 *     (`src/ui/key-schedule-sim/registry.ts`).
 *   - For `kind: "des"`: needs the master key + PC-1/PC-2/shifts params;
 *     runs `simulateDesKeySchedule`, renders the per-round table.
 *
 * The parity test pins the simulator byte-for-byte against its executor, so
 * the values rendered here ARE the values the runtime computed — not an
 * independent calculation that could drift.
 *
 * Failure modes are graceful: missing/wrong-shape master key returns
 * `null` (the App falls back to the standard FrameStateView). Bad params
 * shape (sbox not an array, etc.) also returns null with a small inline
 * error stub. The explorer should never crash the linear-mode pane.
 */

import type { ByteFormat } from "@/core/format";
import type { Json, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import type { DesScheduleRound, DesScheduleTrace } from "../key-schedule-sim/des";
import { type ScheduleSimulator, lookupScheduleSimulator } from "../key-schedule-sim/registry";
import { useByteFormat } from "../stores/format";
import { getTrace, setFrame, useTraceVersion } from "../stores/trace";
import { ByteRow } from "./byte-row";

type Props = {
  frame: TraceFrame;
};

export const KeyScheduleExplorer = (props: Props) => {
  const fmt = useByteFormat();

  // Resolve the simulator for this frame's stepType. The component is
  // only mounted when App.tsx's `isKeyExpansionStepType` check passes, so
  // the null branch here is genuinely "shouldn't happen" — but the
  // explicit guard keeps the type-narrowing tidy and protects against a
  // registry/predicate mismatch in a future cipher addition.
  const simulator = createMemo<ScheduleSimulator | null>(() =>
    lookupScheduleSimulator(props.frame.stepType),
  );

  return (
    <section class="key-schedule-explorer" aria-label="key-schedule explorer">
      <Show
        when={simulator()}
        fallback={
          <div class="key-schedule-explorer-error muted">
            No simulator registered for step type "{props.frame.stepType}".
          </div>
        }
      >
        {(_sim) => (
          // DES is the only remaining simulator kind (AES retired in K1c,
          // Serpent in K3b — both now decompose into real trace frames).
          // The `ScheduleSimulator` union is single-member, so no per-kind
          // Switch is needed; a future cipher's monolithic schedule would
          // re-widen the union and reintroduce the dispatch here.
          <DesExplorer frame={props.frame} fmt={fmt()} />
        )}
      </Show>
    </section>
  );
};

/**
 * Pull the `keyAuxName` value out of a key-expansion step's params,
 * falling back to the canonical default `"key"` when the field is
 * missing or wrong shape. The DES executor uses the `keyAuxName` field
 * with a `"key"` default; the helper is kept standalone so a future
 * cipher addition reusing the same convention doesn't have to duplicate
 * the shape-guard.
 */
const readKeyAuxName = (params: Json): string => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return "key";
  const candidate = (params as Record<string, Json>).keyAuxName;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : "key";
};

// `<ByteRow>` lives in `./byte-row` so the StepNarration component
// renders byte sequences with the same visual rhythm as the
// key-schedule explorer's DES per-round table.

// ─── DES branch (Phase 5e of `docs/plans/des-feistel.md`) ────────────

/**
 * DES key-schedule explorer. Renders the per-round table that makes
 * the FIPS 46-3 §5 schedule legible:
 *
 *   | Round | Shift | C_i (28 bits) | D_i (28 bits) | K_i (48 bits = 6 bytes) |
 *
 * Each row is clickable — scrubs to that round's first body frame in
 * the trace (the round's `expand-R` step in DES; falls back to the
 * round container's first frame if expand-R isn't present, e.g. a
 * future cipher using the same primitive with a different leaf set).
 *
 * The header section shows the master key bytes + C_0 / D_0 (pre-shift
 * halves after PC-1) so the reader can see what "the schedule starts
 * from" before the per-round shifts kick in.
 *
 * Pattern from AES's per-word swimlane: simulator output drives the
 * render; click-to-scrub uses the round id (`round.{N}`) — same naming
 * the runtime emits.
 */
const DesExplorer = (props: { frame: TraceFrame; fmt: ByteFormat }) => {
  const keyAuxName = createMemo(() => readKeyAuxName(props.frame.params));
  const masterKey = createMemo<Uint8Array | null>(() => {
    const v = props.frame.auxRead.get(keyAuxName());
    if (!(v instanceof Uint8Array)) return null;
    if (v.length !== 8) return null;
    return v;
  });

  const params = createMemo(() => readDesParams(props.frame.params));

  const trace = createMemo<DesScheduleTrace | null>(() => {
    const key = masterKey();
    const p = params();
    if (!key || !p) return null;
    try {
      const sim = lookupScheduleSimulator(props.frame.stepType);
      if (!sim || sim.kind !== "des") return null;
      return sim.simulate(key, p);
    } catch {
      // Bad params shape — render the inline fallback rather than
      // crashing the linear pane.
      return null;
    }
  });

  return (
    <Show
      when={trace()}
      fallback={
        <div class="key-schedule-explorer-error muted">
          DES key-schedule simulator could not run — verify the master key is 8 bytes and the
          PC-1/PC-2/shifts params are present.
        </div>
      }
    >
      {(getTrace) => (
        <div class="key-schedule-des">
          <div class="key-schedule-des-header">
            <div class="key-schedule-des-label">master key (8 bytes)</div>
            <ByteRow bytes={masterKey() ?? new Uint8Array(0)} fmt={props.fmt} />
            <div class="key-schedule-des-half-pair">
              <div class="key-schedule-des-half">
                <div class="key-schedule-des-label">C_0 (28 bits)</div>
                <ByteRow bytes={packBitsForDisplay(getTrace().C0bits)} fmt={props.fmt} />
              </div>
              <div class="key-schedule-des-half">
                <div class="key-schedule-des-label">D_0 (28 bits)</div>
                <ByteRow bytes={packBitsForDisplay(getTrace().D0bits)} fmt={props.fmt} />
              </div>
            </div>
            <p class="muted small">
              PC-1 strips the 8 parity bits (positions 8, 16, …, 64) and shuffles the remaining 56
              into two 28-bit halves. Each round left-rotates both halves by 1 or 2 positions, then
              PC-2 selects 48 of the 56 bits as K_i.
            </p>
          </div>
          <table class="key-schedule-des-table">
            <thead>
              <tr>
                <th>round</th>
                <th>shift</th>
                <th>cumulative</th>
                <th>C_i</th>
                <th>D_i</th>
                <th>K_i (48 bits)</th>
              </tr>
            </thead>
            <tbody>
              <For each={getTrace().rounds}>
                {(round) => <DesRoundRow round={round} fmt={props.fmt} />}
              </For>
            </tbody>
          </table>
        </div>
      )}
    </Show>
  );
};

/**
 * Pull the DES key-schedule params (`pc1`, `pc2`, `shifts`) out of a
 * frame's params payload. All three are number-arrays of fixed length;
 * returns null on any shape miss so the explorer can render its inline
 * fallback rather than throwing.
 */
const readDesParams = (
  paramsJson: Json,
): { pc1: readonly number[]; pc2: readonly number[]; shifts: readonly number[] } | null => {
  if (typeof paramsJson !== "object" || paramsJson === null || Array.isArray(paramsJson)) {
    return null;
  }
  const p = paramsJson as Record<string, unknown>;
  const isNumArray = (v: unknown): v is number[] =>
    Array.isArray(v) && v.every((n) => typeof n === "number");
  if (!isNumArray(p.pc1) || !isNumArray(p.pc2) || !isNumArray(p.shifts)) return null;
  return { pc1: p.pc1, pc2: p.pc2, shifts: p.shifts };
};

/**
 * Pack a bit array (each entry 0 or 1) into bytes for ByteRow display.
 * MSB-first to match FIPS convention. Used for the C_0/D_0 header rows
 * and the per-round C_i/D_i ribbons.
 */
const packBitsForDisplay = (bits: readonly number[]): Uint8Array => {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]) {
      const idx = i >> 3;
      out[idx] = (out[idx] ?? 0) | (1 << (7 - (i & 7)));
    }
  }
  return out;
};

/**
 * One row in the DES key-schedule table. Renders the round number,
 * shift count, cumulative shifts, the two 28-bit halves, and K_i.
 * Clicking the row scrubs the trace to that round's `expand-R` frame
 * (the first body frame in DES's round). Falls back to the round
 * container's id if expand-R isn't found (future Feistel ciphers with
 * different leaf names won't have it).
 */
const DesRoundRow = (props: { round: DesScheduleRound; fmt: ByteFormat }) => {
  const version = useTraceVersion();
  const targetFrameIndex = createMemo<number | null>(() => {
    void version();
    const t = getTrace();
    if (!t) return null;
    // Prefer the round's first body frame for the click target. DES's
    // first body frame is the R-track's expand-R; round.{N}.expand-R:tR
    // is its full stepId.
    const r = props.round.round;
    const expandR = t.frames.findIndex((f) => f.stepId.startsWith(`round.${r}.expand-R`));
    if (expandR !== -1) return expandR;
    // Fallback: the rejoin frame (always exists for a feistel-round).
    const rejoin = t.frames.findIndex((f) => f.stepId === `round.${r}:rejoin`);
    return rejoin === -1 ? null : rejoin;
  });

  const handleClick = (): void => {
    const idx = targetFrameIndex();
    if (idx !== null) setFrame(idx);
  };
  // Keyboard accessibility — Enter / Space mirror the click.
  const handleKey = (e: KeyboardEvent): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleClick();
    }
  };

  return (
    <tr
      class="key-schedule-des-row"
      classList={{ "key-schedule-des-row-clickable": targetFrameIndex() !== null }}
      onClick={handleClick}
      onKeyDown={handleKey}
      tabindex={targetFrameIndex() !== null ? 0 : undefined}
      title={
        targetFrameIndex() !== null
          ? `scrub to round ${props.round.round}'s first body frame`
          : `round ${props.round.round} not in current trace`
      }
    >
      <td class="key-schedule-des-round-cell">{props.round.round}</td>
      <td class="key-schedule-des-shift-cell">{props.round.shift}</td>
      <td class="key-schedule-des-cumulative-cell">{props.round.cumulativeShift}</td>
      <td>
        <ByteRow bytes={props.round.Cbytes} fmt={props.fmt} />
      </td>
      <td>
        <ByteRow bytes={props.round.Dbytes} fmt={props.fmt} />
      </td>
      <td>
        <ByteRow bytes={props.round.K} fmt={props.fmt} />
      </td>
    </tr>
  );
};
