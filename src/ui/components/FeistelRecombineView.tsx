/**
 * Feistel recombine inspector — Phase 5 Slice 5.3d (the obligatory port-native
 * rebuild of the old `RejoinFrameView`).
 *
 * Renders ONLY when the active frame is the `recombine` (`concat@1`) leaf of a
 * port-native Feistel round. The generic `PortFlowView` shows that frame as
 * two opaque inputs (`input0`, `input1`) → `output`; this panel reframes it as
 * **the Feistel swap**: it names which input is R and which is L⊕F (read from
 * the round's derived `swap` flag), and splits the output into the new halves
 * (new_L | new_R), with a callout explaining the round-16 no-swap exception.
 *
 * It is an ADDITIVE panel (rendered alongside the raw `PortFlowView`, not
 * replacing it), so the `FrameStateView` / `RejoinFrameView` dispatch in App.tsx
 * stays untouched — keeping Slice 5.3d independent of 5.3e (which deletes the
 * `REJOIN_STEP_TYPE`-gated old view).
 *
 * Bytes are read straight off the active recombine frame's own port maps (it
 * IS the recombine frame), so no trace scan is needed.
 */

import { findActiveFeistelRound } from "@/core/feistel-shape";
import type { ByteFormat } from "@/core/format";
import { canonicalStepId } from "@/core/step-id";
import type { TraceFrame } from "@/core/types";
import { Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useSpec } from "../stores/spec";
import { ByteRow } from "./byte-row";

type Props = {
  frame: TraceFrame;
};

// The concat@1 input port names (fixed by the primitive contract; the same
// literals the DES round builder wires into `recombine.portInputs`).
const INPUT0 = "input0";
const INPUT1 = "input1";

type RecombineData = {
  readonly roundId: string;
  readonly swap: boolean;
  /** input0 / input1 bytes + their semantic label (R or L⊕F). */
  readonly input0: { label: string; bytes: Uint8Array };
  readonly input1: { label: string; bytes: Uint8Array };
  readonly new_L: Uint8Array;
  readonly new_R: Uint8Array;
};

export const FeistelRecombineView = (props: Props) => {
  const fmt = useByteFormat();
  const spec = useSpec();

  const data = createMemo<RecombineData | null>(() => {
    const a = findActiveFeistelRound(props.frame, spec());
    if (!a) return null;
    // Only on THE recombine leaf of this round.
    if (canonicalStepId(props.frame.stepId) !== a.shape.recombineId) return null;

    const in0 = props.frame.portInputs?.get(INPUT0);
    const in1 = props.frame.portInputs?.get(INPUT1);
    const out = props.frame.portOutputs?.get(a.shape.recombineOutPort);
    if (!in0 || !in1 || !out) return null;

    // The swap decides which concat argument is which half:
    //   swap   → input0 = R (passthrough), input1 = L⊕F (combined)
    //   no-swap→ input0 = L⊕F (combined),  input1 = R (passthrough)
    const label0 = a.shape.swap ? "R" : "L⊕F";
    const label1 = a.shape.swap ? "L⊕F" : "R";
    // The output's first half spans input0's length (balanced Feistel).
    const pivot = in0.length;
    if (out.length < pivot) return null;
    return {
      roundId: a.shape.roundId,
      swap: a.shape.swap,
      input0: { label: label0, bytes: in0 },
      input1: { label: label1, bytes: in1 },
      new_L: out.slice(0, pivot),
      new_R: out.slice(pivot),
    };
  });

  return (
    <Show when={data()}>
      {(getData) => (
        <section class="feistel-recombine" aria-label="feistel recombine inspector">
          <div class="feistel-recombine-header">
            <span class="feistel-recombine-round">{getData().roundId}</span>
            <span class="feistel-recombine-title">recombine = the Feistel swap</span>
            <code class="feistel-recombine-kind">{getData().swap ? "swap" : "no swap"}</code>
          </div>

          <div class="feistel-recombine-section">
            <div class="feistel-recombine-section-title muted small">
              concat inputs (in wiring order)
            </div>
            <RecombineRow
              label={getData().input0.label}
              bytes={getData().input0.bytes}
              fmt={fmt()}
            />
            <RecombineRow
              label={getData().input1.label}
              bytes={getData().input1.bytes}
              fmt={fmt()}
            />
          </div>

          <div class="feistel-recombine-section">
            <div class="feistel-recombine-section-title muted small">round output</div>
            <RecombineRow label="L'" bytes={getData().new_L} fmt={fmt()} />
            <RecombineRow label="R'" bytes={getData().new_R} fmt={fmt()} />
          </div>

          <p class="feistel-recombine-note muted small">
            <Show
              when={getData().swap}
              fallback={
                <>
                  This is the <strong>no-swap</strong> round: the halves stay put (
                  <code>output = L⊕F ‖ R</code>). DES's last round skips the swap — that is
                  precisely what makes the same body decrypt when the round keys are reversed.
                </>
              }
            >
              <>
                The halves <strong>swap</strong>: <code>output = R ‖ L⊕F</code>, so next round's
                left is this round's right. The order of the two arguments to <code>concat</code> IS
                the swap — flip them and the cipher stops round-tripping.
              </>
            </Show>
          </p>
        </section>
      )}
    </Show>
  );
};

const RecombineRow = (props: { label: string; bytes: Uint8Array; fmt: ByteFormat }) => (
  <div class="feistel-recombine-row">
    <span class="feistel-recombine-label">{props.label}</span>
    <ByteRow bytes={props.bytes} fmt={props.fmt} />
  </div>
);
