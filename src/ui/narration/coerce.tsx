/**
 * Coercion narrator — Slice 1.12 of the universal-port-dataflow plan
 * (`docs/plans/universal-port-phase-1-slices.md`).
 *
 * Registers ONE narrator under the synthetic stepType `__coerce__` (the
 * literal emitted by the runtime when a ported-dispatch input port's
 * declared `byteLength` doesn't match the source byte count — see
 * `src/core/runtime.ts`'s ported-dispatch coercion block and
 * `src/core/port-projection.ts`'s `coerceToByteLength`). The narrator
 * reads `params.{portName, mode, sourceLen, targetLen}` and explains the
 * byte morph in Q2's prose style.
 *
 * Why one narrator dispatching on `mode`: same shape rationale as
 * `combine-kinds.tsx`. The runtime emits `stepType = "__coerce__"` for
 * every coercion mode, with the variant carried in `params.mode`.
 *
 * Q2 of the parent plan (`docs/plans/universal-port-dataflow.md`)
 * specifies the example prose: "coerced 8 → 16 bytes by right-zero-
 * padding." This narrator delivers exactly that style of explanation,
 * plus pre/post byte rows so the learner sees the morph.
 *
 * Coercion is flag-on-only (`portedDispatchEnabled: true`) AND only
 * triggers when a port's source bytes don't match its declared
 * `byteLength` — no shipped cipher exercises it today. This narrator
 * exists so a future palette-dropped novice-authored spec that wires
 * mismatched ports sees a learner-friendly explanation rather than a
 * naked default frame view.
 */

import type { TraceFrame } from "@/core/types";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

type CoerceParams = {
  readonly portName: string;
  readonly mode: "right-pad" | "truncate-right" | "exact";
  readonly sourceLen: number;
  readonly targetLen: number;
};

const readCoerceParams = (params: TraceFrame["params"]): CoerceParams | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const p = params as Record<string, unknown>;
  const portName = p.portName;
  const mode = p.mode;
  const sourceLen = p.sourceLen;
  const targetLen = p.targetLen;
  if (typeof portName !== "string") return null;
  if (mode !== "right-pad" && mode !== "truncate-right" && mode !== "exact") return null;
  if (typeof sourceLen !== "number" || typeof targetLen !== "number") return null;
  return { portName, mode, sourceLen, targetLen };
};

const readBytesFromState = (state: TraceFrame["stateBefore"]): Uint8Array | null => {
  if (state.shape !== "bytes") return null;
  return state.bytes;
};

/**
 * Coercion narrator. One unit per frame — the morph is one logical
 * operation. The Prose body names the port, the mode, both lengths, and
 * renders the before/after byte rows under the chosen byte format.
 */
export const coerceNarration: NarrationFn = (frame) => {
  const params = readCoerceParams(frame.params);
  if (!params) return null;
  // The runtime never emits a `__coerce__` frame for mode "exact" — but
  // guard anyway so a stale fixture or future caller that passes one
  // through doesn't crash the narrator.
  if (params.mode === "exact") return null;

  const before = readBytesFromState(frame.stateBefore);
  const after = readBytesFromState(frame.stateAfter);
  if (!before || !after) return null;
  const beforeFrozen = new Uint8Array(before);
  const afterFrozen = new Uint8Array(after);

  const { portName, mode, sourceLen, targetLen } = params;

  // Mode-specific phrasing. The shorthand uses Q2's example wording
  // verbatim ("right-zero-padding") so anyone tracing the plan to the
  // running UI sees the same vocabulary.
  const modePhrase =
    mode === "right-pad"
      ? `right-zero-padding (source was shorter than the port's declared ${targetLen} bytes)`
      : `truncating from the right (source was longer than the port's declared ${targetLen} bytes; the trailing ${sourceLen - targetLen} bytes were discarded)`;

  const morphHeadline = `coerced ${sourceLen} → ${targetLen} bytes by ${mode === "right-pad" ? "right-zero-padding" : "right-truncation"}`;

  const unit: NarrationUnit = {
    key: `coerce:${portName}:${mode}`,
    label: `${morphHeadline} for input port "${portName}"`,
    Prose: (props) => (
      <div>
        <p>
          The downstream step declares input port <code>{portName}</code> at{" "}
          <strong>{targetLen} bytes</strong>; the upstream source produced{" "}
          <strong>{sourceLen} bytes</strong>. To keep the pipeline running, the runtime applied
          deterministic coercion: <em>{modePhrase}</em>.
        </p>
        <p>
          Before ({sourceLen} bytes): {formatBytes(beforeFrozen, props.fmt)}
        </p>
        <p>
          After ({targetLen} bytes): {formatBytes(afterFrozen, props.fmt)}
        </p>
        <p>
          This is the universal-port-dataflow plan's <strong>warn-and-run</strong> mismatch policy
          (Q2): mismatched wirings don't halt execution — they produce a deterministic, visible
          coercion frame so the learner sees exactly which bytes landed where. Editor warnings would
          additionally flag the mismatch as red at the wiring; the trace tells the runtime side of
          the story.
        </p>
      </div>
    ),
  };

  return [unit];
};
