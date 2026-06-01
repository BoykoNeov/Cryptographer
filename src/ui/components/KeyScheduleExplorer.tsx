/**
 * Key-Schedule Explorer — Phase 2 of the linear-mode pedagogy plan.
 *
 * Surfaces the hidden internal machinery of the still-monolithic
 * key-expansion executors (Serpent, DES). The standard `<FrameStateView />`
 * for a key-expansion frame renders the unchanged input state matrix on
 * both "before" and "after" sides (the executor only writes aux; state
 * passes through) — useless. This component takes the slot instead and
 * renders the algorithm's intermediate decomposition: prekey recurrence +
 * bitsliced S-box + IP for Serpent; the per-round PC-1/shift/PC-2 table for
 * DES.
 *
 * **AES branch RETIRED (key-schedule-decomposition K1c, 2026-06-01).** AES's
 * key schedule is now decomposed into port-native primitives, so the
 * RotWord / SubWord / Rcon / word-XOR stages this used to simulate are real
 * scrubbable trace frames — the AES swimlane was unreachable (no
 * `aes.key-expansion@1` frame ships) and redundant. Serpent + DES keep their
 * simulators until K3/K4 decompose them.
 *
 * Dispatch:
 *   - Looks up the frame's stepType in the simulator registry
 *     (`src/ui/key-schedule-sim/registry.ts`).
 *   - For `kind: "serpent"`: just needs the master key; runs
 *     `simulateSerpentKeySchedule`, renders multi-stage pipeline.
 *   - For `kind: "des"`: needs the master key + PC-1/PC-2/shifts params;
 *     runs `simulateDesKeySchedule`, renders the per-round table.
 *
 * The parity tests pin both simulators byte-for-byte against their
 * executors, so the values rendered here ARE the values the runtime
 * computed — not an independent calculation that could drift.
 *
 * Failure modes are graceful: missing/wrong-shape master key returns
 * `null` (the App falls back to the standard FrameStateView). Bad params
 * shape (sbox not an array, etc.) also returns null with a small inline
 * error stub. The explorer should never crash the linear-mode pane.
 */

import type { ByteFormat } from "@/core/format";
import type { Json, TraceFrame } from "@/core/types";
import { For, Match, Show, Switch, createMemo } from "solid-js";
import type { DesScheduleRound, DesScheduleTrace } from "../key-schedule-sim/des";
import { type ScheduleSimulator, lookupScheduleSimulator } from "../key-schedule-sim/registry";
import type { SerpentScheduleTrace, SerpentStage } from "../key-schedule-sim/serpent";
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
        {(sim) => (
          // Per-kind dispatch. `Switch`/`Match` over `sim().kind` keeps
          // the three branches symmetric and makes adding a fourth
          // cipher's explorer mechanical (one Match arm). AES + Serpent
          // were a nested Show pair when only two kinds existed; the
          // pair couldn't extend cleanly when DES joined.
          <Switch fallback={<div class="muted small">unknown simulator kind: {sim().kind}</div>}>
            <Match when={sim().kind === "serpent"}>
              <SerpentExplorer frame={props.frame} fmt={fmt()} />
            </Match>
            <Match when={sim().kind === "des"}>
              <DesExplorer frame={props.frame} fmt={fmt()} />
            </Match>
          </Switch>
        )}
      </Show>
    </section>
  );
};

/**
 * Pull the `keyAuxName` value out of a key-expansion step's params,
 * falling back to the canonical default `"key"` when the field is
 * missing or wrong shape. Both the AES and Serpent executors use the
 * same `keyAuxName` field with the same `"key"` default — extracted
 * here as a single source of truth so a future cipher addition
 * (or a fix to one cipher's failure handling) doesn't have to be
 * applied to two parallel copies.
 */
const readKeyAuxName = (params: Json): string => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return "key";
  const candidate = (params as Record<string, Json>).keyAuxName;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : "key";
};

// ─── Serpent branch ──────────────────────────────────────────────────

const SerpentExplorer = (props: { frame: TraceFrame; fmt: ByteFormat }) => {
  const trace = createMemo<SerpentScheduleTrace | null>(() => {
    const masterKey = props.frame.auxRead.get(readKeyAuxName(props.frame.params));
    if (!(masterKey instanceof Uint8Array)) return null;
    try {
      const sim = lookupScheduleSimulator(props.frame.stepType);
      if (sim?.kind !== "serpent") return null;
      return sim.simulate(masterKey);
    } catch {
      return null;
    }
  });

  return (
    <Show
      when={trace()}
      fallback={
        <div class="key-schedule-explorer-error muted">
          Couldn't decompose this key-expansion frame (missing or wrong-shape master key).
        </div>
      }
    >
      {(t) => <SerpentScheduleView trace={t()} fmt={props.fmt} />}
    </Show>
  );
};

const SerpentScheduleView = (props: { trace: SerpentScheduleTrace; fmt: ByteFormat }) => {
  // Partition stages for distinct sections — readable rather than 200
  // homogeneous rows. The recurrence section is collapsed by default
  // (132 entries dominate the trace; the structurally interesting bits
  // are the pad + prekey-init + S-box-group + IP phases).
  const sections = createMemo(() => {
    const padStage = props.trace.stages.find((s) => s.kind === "pad");
    const initStage = props.trace.stages.find((s) => s.kind === "prekey-init");
    const recurrenceStages = props.trace.stages.filter((s) => s.kind === "prekey-recurrence");
    const sboxStages = props.trace.stages.filter((s) => s.kind === "sbox-group");
    const ipStages = props.trace.stages.filter((s) => s.kind === "ip");
    return { padStage, initStage, recurrenceStages, sboxStages, ipStages };
  });

  return (
    <div class="key-schedule-serpent">
      <div class="key-schedule-serpent-header">
        <span class="key-schedule-serpent-title">Serpent key expansion</span>
        <span class="muted small">
          {props.trace.keyByteLength}-byte key · {props.trace.roundKeys.length} round keys ·{" "}
          {props.trace.stages.length} stages
        </span>
      </div>

      {/* Section 1: padding */}
      <Show when={sections().padStage}>
        {(s) => (
          <details class="key-schedule-serpent-section" open>
            <summary>1. Pad to 256 bits</summary>
            <Show
              when={s().kind === "pad" && (s() as Extract<SerpentStage, { kind: "pad" }>)}
              fallback={null}
            >
              {(pad) => (
                <PadStageView
                  masterKey={pad().masterKey}
                  padded={pad().padded}
                  padByteIndex={pad().padByteIndex}
                  fmt={props.fmt}
                />
              )}
            </Show>
          </details>
        )}
      </Show>

      {/* Section 2: prekey-init (8 words from padded key) */}
      <Show when={sections().initStage}>
        {(s) => (
          <details class="key-schedule-serpent-section" open>
            <summary>2. Decode 8 prekey words (LE 32-bit)</summary>
            <Show
              when={
                s().kind === "prekey-init" &&
                (s() as Extract<SerpentStage, { kind: "prekey-init" }>)
              }
              fallback={null}
            >
              {(init) => (
                <ol class="key-schedule-serpent-prekey-init">
                  <For each={init().prekeys}>
                    {(w, idx) => (
                      <li>
                        <span class="muted">
                          w<sub>-{8 - idx()}</sub>
                        </span>{" "}
                        = 0x{(w >>> 0).toString(16).padStart(8, "0")}
                      </li>
                    )}
                  </For>
                </ol>
              )}
            </Show>
          </details>
        )}
      </Show>

      {/* Section 3: 132 prekey-recurrence (collapsed by default — dense) */}
      <details class="key-schedule-serpent-section">
        <summary>3. Generate w[0]…w[131] (132 × 5-input XOR + ROL11)</summary>
        <ol class="key-schedule-serpent-recurrence">
          <For each={sections().recurrenceStages}>
            {(stage) => (
              <Show
                when={
                  stage.kind === "prekey-recurrence" &&
                  (stage as Extract<SerpentStage, { kind: "prekey-recurrence" }>)
                }
                fallback={null}
              >
                {(r) => (
                  <li>
                    <span class="muted">
                      w<sub>{r().j}</sub>
                    </span>{" "}
                    = ROL<sub>11</sub>(0x{(r().xorResult >>> 0).toString(16).padStart(8, "0")}) = 0x
                    {(r().output >>> 0).toString(16).padStart(8, "0")}
                  </li>
                )}
              </Show>
            )}
          </For>
        </ol>
      </details>

      {/* Section 4: 33 sbox-group + IP pairs (interleaved per round key) */}
      <details class="key-schedule-serpent-section" open>
        <summary>4. Bitsliced S-box per group → IP → K_i (33 round keys)</summary>
        <ol class="key-schedule-serpent-sbox-groups">
          <For each={sections().sboxStages}>
            {(stage, i) => (
              <Show
                when={
                  stage.kind === "sbox-group" &&
                  (stage as Extract<SerpentStage, { kind: "sbox-group" }>)
                }
                fallback={null}
              >
                {(g) => (
                  <li>
                    <div class="key-schedule-serpent-sbox-group-header">
                      <span>
                        K<sub>{g().groupIndex}</sub>
                      </span>
                      <span class="muted small">
                        S<sub>{g().sboxIndex}</sub> (i={g().groupIndex} → (35-i) mod 8 ={" "}
                        {g().sboxIndex})
                      </span>
                    </div>
                    <Show
                      when={
                        sections().ipStages[i()] &&
                        sections().ipStages[i()]?.kind === "ip" &&
                        (sections().ipStages[i()] as Extract<SerpentStage, { kind: "ip" }>)
                      }
                      fallback={null}
                    >
                      {(ip) => (
                        <div class="key-schedule-serpent-roundkey">
                          <div class="muted small">raw (pre-IP):</div>
                          <ByteRow bytes={ip().rawRoundKey} fmt={props.fmt} />
                          <div class="muted small">permuted (final K_{g().groupIndex}):</div>
                          <ByteRow bytes={ip().permutedRoundKey} fmt={props.fmt} />
                        </div>
                      )}
                    </Show>
                  </li>
                )}
              </Show>
            )}
          </For>
        </ol>
      </details>
    </div>
  );
};

const PadStageView = (props: {
  masterKey: Uint8Array;
  padded: Uint8Array;
  padByteIndex: number;
  fmt: ByteFormat;
}) => (
  <div class="key-schedule-serpent-pad">
    <div class="muted small">master key ({props.masterKey.length} bytes):</div>
    <ByteRow bytes={props.masterKey} fmt={props.fmt} />
    <div class="muted small">
      padded (32 bytes
      <Show when={props.padByteIndex >= 0}>; 0x01 marker at byte {props.padByteIndex}</Show>
      <Show when={props.padByteIndex < 0}>; 256-bit key, no marker needed</Show>
      ):
    </div>
    <ByteRow bytes={props.padded} fmt={props.fmt} highlightIndex={props.padByteIndex} />
  </div>
);

// `<ByteRow>` lives in `./byte-row` so the StepNarration component
// renders byte sequences with the same visual rhythm as the
// key-schedule explorer's pad-stage / round-key views.

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
