/**
 * Feistel round-bytes panel — Phase 5 Slice 5.3d (the obligatory port-native
 * rebuild of the old `FeistelTrackContext`).
 *
 * Renders the active Feistel round's *concrete* byte values, aggregated at the
 * round level: round entry (L_in | R_in), the mix (F = the F-function output,
 * L⊕F), and round output (new_L | new_R). The per-leaf `PortFlowView` shows one
 * step's ports; this panel shows the round as a whole, which is the unit the
 * swap operates on.
 *
 * All values come from `resolveFeistelRoundBytes` (`core/feistel-shape.ts`),
 * which reads the round's split / fxor / recombine frames' captured port I/O —
 * NOT the dead `branchPath` / rejoin-frame stash the old component used. Any
 * value that can't be resolved (a half-edited spec, a leaf that didn't run)
 * is simply omitted, so the panel degrades gracefully.
 *
 * Pairs side-by-side with `<FeistelSwapDiagram />`: the diagram shows the
 * abstract topology, this panel the bytes flowing through it for the same round.
 */

import {
  type FeistelRoundBytes as FeistelRoundBytesData,
  feistelValueLabels,
  findActiveFeistelRound,
  resolveFeistelRoundBytes,
} from "@/core/feistel-shape";
import type { ByteFormat } from "@/core/format";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useSpec } from "../stores/spec";
import { getTrace, useTraceVersion } from "../stores/trace";
import { ByteRow } from "./byte-row";

type Props = {
  frame: TraceFrame;
};

type Section = {
  readonly title: string;
  readonly rows: ReadonlyArray<{ label: string; bytes: Uint8Array; accent?: boolean }>;
};

/** Build the (title, rows) sections from the resolved bytes, dropping any row
 *  whose value is null. `mixedLabel` names the combined half ("L⊕F" for DES,
 *  "R⊕F" for the mirrored Blowfish form). A section with no resolvable rows is
 *  omitted. */
const buildSections = (b: FeistelRoundBytesData, mixedLabel: string): readonly Section[] => {
  const row = (label: string, bytes: Uint8Array | null, accent?: boolean) =>
    bytes ? [{ label, bytes, ...(accent ? { accent: true } : {}) }] : [];
  const sections: Section[] = [
    { title: "round entry", rows: [...row("L", b.L_in), ...row("R", b.R_in)] },
    { title: "F mix", rows: [...row("F", b.F), ...row(mixedLabel, b.LxorF, true)] },
    { title: "round output", rows: [...row("L'", b.new_L), ...row("R'", b.new_R)] },
  ];
  return sections.filter((s) => s.rows.length > 0);
};

export const FeistelRoundBytes = (props: Props) => {
  const fmt = useByteFormat();
  const spec = useSpec();
  const version = useTraceVersion();

  const active = createMemo(() => findActiveFeistelRound(props.frame, spec()));

  const sections = createMemo<readonly Section[]>(() => {
    void version();
    const a = active();
    if (!a) return [];
    const t = getTrace();
    if (!t) return [];
    const bytes = resolveFeistelRoundBytes(a.shape, t.frames, props.frame.blockIndex);
    return buildSections(bytes, feistelValueLabels(a.shape).mixed);
  });

  return (
    <Show when={active()}>
      {(getActive) => (
        <section class="feistel-round-bytes" aria-label="feistel round bytes">
          <div class="feistel-round-bytes-header">
            <span class="feistel-round-bytes-round">{getActive().shape.roundId}</span>
            <span class="feistel-round-bytes-hint muted small">round-level halves</span>
          </div>
          <div class="feistel-round-bytes-sections">
            <For each={sections()}>
              {(section) => <BytesSection section={section} fmt={fmt()} />}
            </For>
          </div>
        </section>
      )}
    </Show>
  );
};

const BytesSection = (props: { section: Section; fmt: ByteFormat }) => (
  <div class="feistel-round-bytes-section">
    <div class="feistel-round-bytes-section-title muted small">{props.section.title}</div>
    <For each={props.section.rows}>
      {(r) => (
        <div
          class="feistel-round-bytes-row"
          classList={{ "feistel-round-bytes-row-accent": !!r.accent }}
        >
          <span class="feistel-round-bytes-label">{r.label}</span>
          <ByteRow bytes={r.bytes} fmt={props.fmt} />
        </div>
      )}
    </For>
  </div>
);
