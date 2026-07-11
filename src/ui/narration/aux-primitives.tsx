/**
 * Aux narrators — Phase 3 of the per-frame value-prose plan.
 *
 * Three user-composable aux primitives (state passthrough, work over the
 * aux map) used to hand-build block-cipher chaining modes:
 *
 *   - `generic.aux-load@1` → publish a literal byte sequence as aux.
 *   - `generic.aux-xor@1`  → aux[into] ⊕= aux[from] (single conceptual op).
 *   - `generic.aux-copy@1` → aux[to] := aux[from] (snapshot/rename).
 *
 * The matrix-shaped chaining narrators (`iv-load`, `xor-aux-into-state`,
 * `state-to-aux`) were retired in Phase 5 Slice 5.1 (2026-05-30) with their
 * step types + the `MatrixState` shape; shipped CBC chains in bytes through
 * the `iterate` port mode now.
 *
 * Half-wired authoring state: the aux primitives are graceful — they
 * produce frames even when wires aren't connected (no auxRead, no
 * auxWrites). Each narrator below returns `null` when the data needed
 * to narrate (the consumed aux, the produced aux, the operand pair) is
 * missing. The `<StepNarration>` component renders nothing in that case,
 * so a half-wired node just shows the inspector's `auxRead` / `auxWritten`
 * panels and the warning glyph from Slice 9.
 */

import type { AuxValue, Json, TraceFrame } from "@/core/types";
import { formatBytes } from "../components/byte-row";
import type { NarrationFn } from "./registry";

// ─── aux-load ────────────────────────────────────────────────────────

/**
 * `aux-load` publishes a literal byte sequence under an aux name. The
 * narrator reads the published value from `frame.auxWritten` (which is
 * what the runtime actually saw) — not from `params.value` directly,
 * because the executor short-circuits to passthrough when `auxName` is
 * empty, leaving no write to narrate.
 */
export const auxLoadNarration: NarrationFn = (frame) => {
  const written = singleAuxWrite(frame);
  if (!written) return null;
  const [auxName, value] = written;
  if (!(value instanceof Uint8Array)) return null;
  const valueLen = value.length;
  return [
    {
      key: "load",
      label: `aux[${auxName}] := ${valueLen}-byte literal`,
      Prose: (props) => (
        <div>
          <p>
            Store the fixed byte sequence {formatBytes(value, props.fmt)} ({valueLen} byte
            {valueLen === 1 ? "" : "s"}) in the slot <code>aux[{auxName}]</code>. The value is one
            you supply directly; the data being encrypted passes by untouched.
          </p>
          <p>
            Common uses: an initialization vector (CBC, OFB, CFB), a counter starting value (CTR),
            or any fixed value a hand-built mode of operation needs to bring in.
          </p>
        </div>
      ),
    },
  ];
};

// ─── aux-xor ─────────────────────────────────────────────────────────

/**
 * `aux-xor` reads two aux values, XORs them, and writes the result back
 * to one of the names (the `into` slot). The narrator reads both operands
 * from `frame.auxRead` and the result from `frame.auxWritten`.
 *
 * Returns null if either operand is missing (half-wired state) OR if the
 * shapes don't line up (defensive — the executor would have thrown).
 */
export const auxXorNarration: NarrationFn = (frame) => {
  const { from, into } = readFromIntoParams(frame.params);
  if (from === null || into === null) return null;
  const fromValue = frame.auxRead.get(from);
  const intoOldValue = frame.auxRead.get(into);
  const intoNewValue = frame.auxWritten.get(into);
  if (
    !(fromValue instanceof Uint8Array) ||
    !(intoOldValue instanceof Uint8Array) ||
    !(intoNewValue instanceof Uint8Array)
  ) {
    return null;
  }
  if (fromValue.length !== intoOldValue.length || intoOldValue.length !== intoNewValue.length) {
    return null;
  }
  const len = fromValue.length;
  return [
    {
      key: "xor",
      label: `aux[${into}] ⊕= aux[${from}] (${len} byte${len === 1 ? "" : "s"})`,
      Prose: (props) => (
        <div>
          <p>
            Read <code>aux[{from}]</code> = {formatBytes(fromValue, props.fmt)} and{" "}
            <code>aux[{into}]</code> = {formatBytes(intoOldValue, props.fmt)}, XOR them byte-wise,
            write the result back into <code>aux[{into}]</code> ={" "}
            {formatBytes(intoNewValue, props.fmt)}.
          </p>
          <p>
            <code>aux[{from}]</code> is left unchanged — this step accumulates into{" "}
            <code>{into}</code>. XOR is self-inverse (A ⊕ B ⊕ B = A), which is why CBC's
            encrypt/decrypt symmetry works: the same operand cancels out when applied a second time.
          </p>
        </div>
      ),
    },
  ];
};

// ─── aux-copy ────────────────────────────────────────────────────────

/**
 * `aux-copy` reads one aux value and writes it (deep-copied if Uint8Array)
 * under another name. The narrator reads from `frame.auxRead` and confirms
 * the write in `frame.auxWritten` — if either is missing, the wires aren't
 * fully connected and we decline to narrate.
 */
export const auxCopyNarration: NarrationFn = (frame) => {
  const { from, to } = readFromToParams(frame.params);
  if (from === null || to === null) return null;
  const fromValue = frame.auxRead.get(from);
  const toValue = frame.auxWritten.get(to);
  if (fromValue === undefined || toValue === undefined) return null;
  const len = uint8Length(fromValue);
  return [
    {
      key: "copy",
      label: `aux[${to}] := aux[${from}]${len !== null ? ` (${len} byte${len === 1 ? "" : "s"})` : ""}`,
      Prose: (props) => (
        <div>
          <p>
            Copy <code>aux[{from}]</code>
            {fromValue instanceof Uint8Array ? ` = ${formatBytes(fromValue, props.fmt)}` : ""} into{" "}
            <code>aux[{to}]</code>. The source slot is left unchanged.
          </p>
          <p>
            {fromValue instanceof Uint8Array
              ? "The destination is a fresh allocation — mutating one slot afterward does not affect the other."
              : "Non-byte aux shapes (State, State[], integers, bigints) pass through by reference; the architecture treats those as immutable once published."}{" "}
            Common uses: snapshot a feedback value before the next chain step clobbers it, or rename
            an upstream output to bridge it into a downstream step's input slot.
          </p>
        </div>
      ),
    },
  ];
};

// ─── Helpers ─────────────────────────────────────────────────────────

/**
 * Pull the single `(auxName, value)` write a frame published, returning
 * null if there are zero or more than one. Used by `aux-load` which by
 * construction writes exactly one aux entry per successful frame.
 */
const singleAuxWrite = (frame: TraceFrame): readonly [string, AuxValue] | null => {
  if (frame.auxWritten.size !== 1) return null;
  const entries = Array.from(frame.auxWritten.entries());
  const e = entries[0];
  if (!e) return null;
  return e;
};

const readFromIntoParams = (params: Json): { from: string | null; into: string | null } => {
  return { from: readStringParam(params, "from"), into: readStringParam(params, "into") };
};

const readFromToParams = (params: Json): { from: string | null; to: string | null } => {
  return { from: readStringParam(params, "from"), to: readStringParam(params, "to") };
};

const readStringParam = (params: Json, key: string): string | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>)[key];
  return typeof v === "string" && v.length > 0 ? v : null;
};

const uint8Length = (v: AuxValue | undefined): number | null =>
  v instanceof Uint8Array ? v.length : null;
