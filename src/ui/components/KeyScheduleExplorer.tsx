/**
 * Key-Schedule Explorer — Phase 2 of the linear-mode pedagogy plan.
 *
 * Surfaces the hidden internal machinery of key-expansion executors. The
 * standard `<FrameStateView />` for a key-expansion frame renders the
 * unchanged input state matrix on both "before" and "after" sides (the
 * executor only writes aux; state passes through) — useless. This
 * component takes the slot instead and renders the algorithm's
 * intermediate decomposition: per-word `RotWord → SubWord → Rcon → XOR`
 * chain for AES, prekey recurrence + bitsliced S-box + IP for Serpent.
 *
 * Dispatch:
 *   - Looks up the frame's stepType in the simulator registry
 *     (`src/ui/key-schedule-sim/registry.ts`).
 *   - For `kind: "aes"` simulators: extracts sbox/rcon/rounds from
 *     `frame.params`, master key from `frame.auxRead`, runs
 *     `simulateAesKeySchedule`, renders per-word swimlane.
 *   - For `kind: "serpent"`: just needs the master key; runs
 *     `simulateSerpentKeySchedule`, renders multi-stage pipeline.
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

import { type ByteFormat, formatByte } from "@/core/format";
import type { Json, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import type { AesScheduleTrace, AesScheduleWord, AesStage } from "../key-schedule-sim/aes";
import {
  type AesSimParams,
  type ScheduleSimulator,
  lookupScheduleSimulator,
} from "../key-schedule-sim/registry";
import type { SerpentScheduleTrace, SerpentStage } from "../key-schedule-sim/serpent";
import { useByteFormat } from "../stores/format";

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
          <Show
            when={sim().kind === "aes"}
            fallback={<SerpentExplorer frame={props.frame} fmt={fmt()} />}
          >
            <AesExplorer frame={props.frame} fmt={fmt()} />
          </Show>
        )}
      </Show>
    </section>
  );
};

// ─── AES branch ──────────────────────────────────────────────────────

const AesExplorer = (props: { frame: TraceFrame; fmt: ByteFormat }) => {
  // Run the AES simulator from the frame's params + aux. Wrapped in a
  // memo so the heavy work re-runs only on frame swap (the simulator
  // walks 44/52/60 words and emits ~50/70/90 stages — cheap, but a
  // factor-of-N savings on scrub-and-format-toggle storms is free).
  const trace = createMemo<AesScheduleTrace | null>(() => {
    const params = extractAesParams(props.frame.params);
    if (!params) return null;
    // The executor reads `keyAuxName` (default "key") from aux. We
    // pull the same name out of params to find the master key in
    // the frame's auxRead snapshot.
    const keyAuxName =
      typeof props.frame.params === "object" &&
      props.frame.params !== null &&
      !Array.isArray(props.frame.params) &&
      typeof (props.frame.params as Record<string, Json>).keyAuxName === "string"
        ? ((props.frame.params as Record<string, Json>).keyAuxName as string)
        : "key";
    const masterKey = props.frame.auxRead.get(keyAuxName);
    if (!(masterKey instanceof Uint8Array)) return null;
    try {
      // Re-fetch the simulator (vs hoisting to the parent) so the memo
      // is independent and the parent can pass `frame` reactively.
      const sim = lookupScheduleSimulator(props.frame.stepType);
      if (sim?.kind !== "aes") return null;
      return sim.simulate(masterKey, params);
    } catch {
      // Simulator throws on shape mismatch (wrong sbox length, rounds<1,
      // etc.). Treat as "render the empty state" — the inline error
      // surface below tells the user the explorer couldn't decompose.
      return null;
    }
  });

  return (
    <Show
      when={trace()}
      fallback={
        <div class="key-schedule-explorer-error muted">
          Couldn't decompose this key-expansion frame (missing or wrong-shape params / master key).
        </div>
      }
    >
      {(t) => <AesScheduleView trace={t()} fmt={props.fmt} />}
    </Show>
  );
};

const AesScheduleView = (props: { trace: AesScheduleTrace; fmt: ByteFormat }) => (
  <div class="key-schedule-aes">
    <div class="key-schedule-aes-header">
      <span class="key-schedule-aes-title">AES key expansion</span>
      <span class="muted small">
        Nk = {props.trace.Nk} · Nr = {props.trace.Nr} · {props.trace.words.length} words →{" "}
        {props.trace.roundKeys.length} round keys
      </span>
    </div>
    <ol class="key-schedule-aes-words">
      <For each={props.trace.words}>{(word) => <AesWordRow word={word} fmt={props.fmt} />}</For>
    </ol>
  </div>
);

const AesWordRow = (props: { word: AesScheduleWord; fmt: ByteFormat }) => (
  <li
    class="key-schedule-aes-word"
    classList={{
      "key-schedule-aes-word-chain": props.word.isChainStart,
      "key-schedule-aes-word-nk8mid": props.word.isNk8Mid,
    }}
  >
    <div class="key-schedule-aes-word-header">
      <span class="key-schedule-aes-word-index">
        W<sub>{props.word.wordIndex}</sub>
      </span>
      <Show when={props.word.isChainStart}>
        <span
          class="key-schedule-aes-word-badge"
          title="i % Nk === 0 — RotWord + SubWord + Rcon XOR"
        >
          chain
        </span>
      </Show>
      <Show when={props.word.isNk8Mid}>
        <span
          class="key-schedule-aes-word-badge key-schedule-aes-word-badge-nk8mid"
          title="AES-256-only: extra SubWord at i % Nk === 4, no RotWord, no Rcon"
        >
          Nk&gt;6 mid
        </span>
      </Show>
    </div>
    <div class="key-schedule-aes-word-stages">
      <For each={props.word.stages}>{(stage) => <AesStageRow stage={stage} fmt={props.fmt} />}</For>
    </div>
  </li>
);

const AesStageRow = (props: { stage: AesStage; fmt: ByteFormat }) => (
  <div class="key-schedule-aes-stage" data-stage-kind={props.stage.kind}>
    <span class="key-schedule-aes-stage-label">{stageLabel(props.stage)}</span>
    <span class="key-schedule-aes-stage-arrow">→</span>
    <span class="key-schedule-aes-stage-value">
      <ByteRow bytes={stageOutput(props.stage)} fmt={props.fmt} />
    </span>
  </div>
);

const stageLabel = (stage: AesStage): string => {
  switch (stage.kind) {
    case "init":
      return "init";
    case "rotword":
      return "RotWord";
    case "subword":
      return "SubWord";
    case "rcon-xor":
      return `⊕ Rcon = 0x${stage.rconValue.toString(16).padStart(2, "0")}`;
    case "extra-subword":
      return "SubWord (extra, AES-256)";
    case "xor-prev":
      return `⊕ W[${stage.prevWordIndex}]`;
  }
};

const stageOutput = (stage: AesStage): Uint8Array => {
  switch (stage.kind) {
    case "init":
      return stage.word;
    default:
      return stage.output;
  }
};

const extractAesParams = (params: Json): AesSimParams | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const p = params as Record<string, Json>;
  const sbox = p.sbox;
  const rcon = p.rcon;
  const rounds = p.rounds;
  if (!Array.isArray(sbox) || sbox.length !== 256) return null;
  if (!Array.isArray(rcon)) return null;
  if (typeof rounds !== "number" || !Number.isInteger(rounds) || rounds < 1) return null;
  // Cast through Json → number[] is safe here because we just validated
  // the shape. The simulator does its own range checks.
  return {
    sbox: sbox as readonly number[],
    rcon: rcon as readonly number[],
    rounds,
  };
};

// ─── Serpent branch ──────────────────────────────────────────────────

const SerpentExplorer = (props: { frame: TraceFrame; fmt: ByteFormat }) => {
  const trace = createMemo<SerpentScheduleTrace | null>(() => {
    const keyAuxName =
      typeof props.frame.params === "object" &&
      props.frame.params !== null &&
      !Array.isArray(props.frame.params) &&
      typeof (props.frame.params as Record<string, Json>).keyAuxName === "string"
        ? ((props.frame.params as Record<string, Json>).keyAuxName as string)
        : "key";
    const masterKey = props.frame.auxRead.get(keyAuxName);
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

// ─── Shared byte-row renderer ────────────────────────────────────────

const ByteRow = (props: {
  bytes: Uint8Array;
  fmt: ByteFormat;
  /** Optional index to outline with .key-schedule-byte-highlight. */
  highlightIndex?: number;
}) => (
  <div class="key-schedule-byte-row">
    <For each={Array.from(props.bytes)}>
      {(b, i) => (
        <div
          class="key-schedule-byte-cell"
          classList={{
            "key-schedule-byte-highlight":
              props.highlightIndex !== undefined && i() === props.highlightIndex,
          }}
        >
          {formatByte(b, props.fmt)}
        </div>
      )}
    </For>
  </div>
);
