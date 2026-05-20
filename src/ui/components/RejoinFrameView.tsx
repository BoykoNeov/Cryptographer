/**
 * Rejoin-frame inspector — Phase 5c of `docs/plans/des-feistel.md`.
 *
 * Replaces `<FrameStateView />` when the scrubber lands on a synthetic
 * rejoin frame (`stepType === REJOIN_STEP_TYPE`). The default frame view
 * renders `before` (L_out || R_out concatenation) above `after`
 * (new_L || new_R concatenation), which is pedagogically meaningless
 * for a 4-arg combine: the user sees an 8-byte blob morph into another
 * 8-byte blob with no narrative about WHICH inputs produced WHICH
 * outputs.
 *
 * This component reads the 4 track snapshots stashed into `frame.params`
 * by the runtime's `runFeistelRound` (Phase 5c runtime change) and
 * displays them in the order declared by
 * `COMBINE_KINDS[kind].inspectorRowOrder` (formula-reading order, not
 * track-name order). Each snapshot's row labels its name (`R_in`, etc.)
 * and renders the bytes via the shared `<ByteRow>` helper so the visual
 * rhythm matches `<KeyScheduleExplorer />` and `<StepNarration />`.
 *
 * Snapshots that the combine doesn't read (e.g. `feistel-standard`
 * ignores `L_out` — the L track ran its body but the result wasn't
 * consumed) render with a "unused" muted style and an inline note,
 * making the asymmetry of each combine kind visible.
 *
 * The result block at the bottom splits `frame.stateAfter` into `new_L`
 * and `new_R` rows. The split offset is `L_in.length` (= half the round
 * state on 2-track Feistel; future n-track variants would need a richer
 * split rule).
 *
 * Prose narration is NOT this component's job — `<StepNarration />`
 * already owns the cross-row callout via `src/ui/narration/combine-kinds.tsx`
 * and renders the formula prose as a `<details>` directly below this
 * view. Keeping the split means the inspector can be terse and visual
 * while the narration carries the explanatory weight.
 */

import { COMBINE_KINDS, type SnapshotKey } from "@/core/combine-kinds";
import type { ByteFormat } from "@/core/format";
import type { CombineKind, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { ByteRow } from "./byte-row";

type Props = {
  frame: TraceFrame;
};

/**
 * Pull the 4 snapshots + combineKind out of a rejoin frame's params.
 * Returns null when the frame doesn't carry the expected shape — caller
 * falls back to the default frame view in that case.
 *
 * Defensive shape: the runtime always emits this shape today, but a
 * future schema migration or a test fixture with hand-rolled params
 * could be wrong. Null-on-bad-shape is friendlier than a hard crash.
 */
type ParsedRejoinParams = {
  readonly combineKind: CombineKind;
  readonly L_in: Uint8Array;
  readonly L_out: Uint8Array;
  readonly R_in: Uint8Array;
  readonly R_out: Uint8Array;
};

const isByteArray = (v: unknown): v is number[] =>
  Array.isArray(v) &&
  v.every((n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255);

const parseRejoinParams = (params: TraceFrame["params"]): ParsedRejoinParams | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const p = params as Record<string, unknown>;
  const combineKind = typeof p.combineKind === "string" ? p.combineKind : null;
  if (combineKind === null || !(combineKind in COMBINE_KINDS)) return null;
  if (
    !isByteArray(p.L_in) ||
    !isByteArray(p.L_out) ||
    !isByteArray(p.R_in) ||
    !isByteArray(p.R_out)
  ) {
    return null;
  }
  return {
    combineKind: combineKind as CombineKind,
    L_in: new Uint8Array(p.L_in),
    L_out: new Uint8Array(p.L_out),
    R_in: new Uint8Array(p.R_in),
    R_out: new Uint8Array(p.R_out),
  };
};

export const RejoinFrameView = (props: Props) => {
  const fmt = useByteFormat();
  const parsed = createMemo<ParsedRejoinParams | null>(() => parseRejoinParams(props.frame.params));

  // Split frame.stateAfter into new_L / new_R using L_in.length as the
  // pivot. Bytes-shape assertion is loose; the runtime guarantees it
  // for rejoin frames, but a malformed fixture falls back to null.
  const result = createMemo<{ new_L: Uint8Array; new_R: Uint8Array } | null>(() => {
    const after = props.frame.stateAfter;
    if (after.shape !== "bytes") return null;
    const p = parsed();
    if (!p) return null;
    const split = p.L_in.length;
    if (after.bytes.length < split) return null;
    return {
      new_L: after.bytes.slice(0, split),
      new_R: after.bytes.slice(split),
    };
  });

  return (
    <Show
      when={parsed()}
      fallback={
        <div class="rejoin-frame-error muted">
          rejoin frame is missing the expected 4-snapshot params; rerun the cipher.
        </div>
      }
    >
      {(getParsed) => (
        <section class="rejoin-frame-view" aria-label="feistel rejoin inspector">
          <RejoinHeader combineKind={getParsed().combineKind} />
          <div class="rejoin-snapshots">
            <For each={COMBINE_KINDS[getParsed().combineKind].inspectorRowOrder}>
              {(key) => (
                <SnapshotRow
                  snapshotKey={key}
                  bytes={getParsed()[key]}
                  used={isSnapshotUsed(key, getParsed().combineKind)}
                  fmt={fmt()}
                />
              )}
            </For>
          </div>
          <Show when={result()}>
            {(getResult) => (
              <div class="rejoin-result">
                <div class="rejoin-result-label">result</div>
                <div class="rejoin-result-rows">
                  <ResultRow label="new_L" bytes={getResult().new_L} fmt={fmt()} />
                  <ResultRow label="new_R" bytes={getResult().new_R} fmt={fmt()} />
                </div>
              </div>
            )}
          </Show>
        </section>
      )}
    </Show>
  );
};

/**
 * Whether a snapshot key is consumed by the named combine kind. Drives
 * the muted "unused" styling on rows whose value the formula doesn't
 * reference. Inputs (L_in, R_in) are always relevant — every shipped
 * combine uses at least one of them; outputs (L_out, R_out) are
 * variant-specific and the `usesLOut`/`usesROut` flags on the metadata
 * record which.
 */
const isSnapshotUsed = (key: SnapshotKey, combineKind: CombineKind): boolean => {
  const meta = COMBINE_KINDS[combineKind];
  if (key === "L_in") return true;
  if (key === "R_in") return true;
  if (key === "L_out") return meta.usesLOut;
  // key === "R_out"
  return meta.usesROut;
};

const RejoinHeader = (props: { combineKind: CombineKind }) => (
  <div class="rejoin-header">
    <div class="rejoin-header-row">
      <span class="rejoin-header-label">combine kind</span>
      <code class="rejoin-header-kind">{props.combineKind}</code>
    </div>
    <div class="rejoin-header-row">
      <span class="rejoin-header-label">formula</span>
      <code class="rejoin-header-formula">{COMBINE_KINDS[props.combineKind].formulaText}</code>
    </div>
  </div>
);

const SnapshotRow = (props: {
  snapshotKey: SnapshotKey;
  bytes: Uint8Array;
  used: boolean;
  fmt: ByteFormat;
}) => (
  <div
    class="rejoin-snapshot-row"
    classList={{ "rejoin-snapshot-unused": !props.used }}
    title={
      props.used
        ? props.snapshotKey
        : `${props.snapshotKey} — this snapshot exists but the combine kind does not read it`
    }
  >
    <span class="rejoin-snapshot-label">{props.snapshotKey}</span>
    <ByteRow bytes={props.bytes} fmt={props.fmt} />
    <Show when={!props.used}>
      <span class="rejoin-snapshot-unused-note muted small">(unused by this combine)</span>
    </Show>
  </div>
);

const ResultRow = (props: {
  label: string;
  bytes: Uint8Array;
  fmt: ByteFormat;
}) => (
  <div class="rejoin-result-row">
    <span class="rejoin-result-row-label">{props.label}</span>
    <ByteRow bytes={props.bytes} fmt={props.fmt} />
  </div>
);
