/**
 * Aux narrators — Phase 3 of the per-frame value-prose plan.
 *
 * Six step types that operate over the aux map (often with state
 * passthrough), used to compose block-cipher chaining modes:
 *
 *   - `generic.aux-load@1`           → publish a literal byte sequence as aux.
 *   - `generic.aux-xor@1`            → aux[into] ⊕= aux[from] (single conceptual op).
 *   - `generic.aux-copy@1`           → aux[to] := aux[from] (snapshot/rename).
 *   - `generic.iv-load@1`            → Uint8Array IV → MatrixState aux (shape bridge).
 *   - `generic.xor-aux-into-state@1` → state ⊕= aux (the CBC chain XOR). **1 unit**
 *                                       per plan — the chain XOR is one pedagogical
 *                                       beat, not 16 per-byte units.
 *   - `generic.state-to-aux@1`       → snapshot current state into aux.
 *
 * Half-wired authoring state: the aux primitives are graceful — they
 * produce frames even when wires aren't connected (no auxRead, no
 * auxWrites). Each narrator below returns `null` when the data needed
 * to narrate (the consumed aux, the produced aux, the operand pair) is
 * missing — matching the AES `aesAddRoundKeyNarration` convention from
 * Phase 1. The `<StepNarration>` component renders nothing in that case,
 * so a half-wired node just shows the inspector's `auxRead` / `auxWritten`
 * panels and the warning glyph from Slice 9.
 */

import type { AuxValue, Json, MatrixState, State, TraceFrame } from "@/core/types";
import { formatByteInline, formatBytes } from "../components/byte-row";
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
            Publish the literal byte sequence {formatBytes(value, props.fmt)} ({valueLen} byte
            {valueLen === 1 ? "" : "s"}) into <code>aux[{auxName}]</code>. State is passthrough —
            this step has no data inputs; the value is a constant baked into the spec.
          </p>
          <p>
            Common uses: an initialization vector (CBC, OFB, CFB), a counter starting value (CTR),
            or any per-mode constant a hand-built compound cipher needs to thread through aux.
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

// ─── iv-load ─────────────────────────────────────────────────────────

/**
 * `iv-load` reads a 16-byte Uint8Array aux value and republishes it under
 * another name as a MatrixState (column-major packing). The shape-bridge
 * between "the IV is just bytes the user typed" and "the chain wants
 * matrices."
 */
export const ivLoadNarration: NarrationFn = (frame) => {
  const { ivAuxName, outAuxName } = readIvLoadParams(frame.params);
  if (ivAuxName === null || outAuxName === null) return null;
  const inputBytes = frame.auxRead.get(ivAuxName);
  const outputMatrix = frame.auxWritten.get(outAuxName);
  if (!(inputBytes instanceof Uint8Array)) return null;
  if (!isMatrixState(outputMatrix)) return null;
  return [
    {
      key: "iv-bridge",
      label: `aux[${outAuxName}] := MatrixState(aux[${ivAuxName}])`,
      Prose: (props) => (
        <div>
          <p>
            Read the 16-byte IV from <code>aux[{ivAuxName}]</code> ={" "}
            {formatBytes(inputBytes, props.fmt)} and republish it under{" "}
            <code>aux[{outAuxName}]</code> in MatrixState shape (4×4 column-major, FIPS-197 §3.4) —
            the format the in-loop chaining XOR needs.
          </p>
          <p>
            The original byte-typed entry is preserved, so later frames can still display the
            literal IV separately from the running chain that block-by-block overwrites{" "}
            <code>aux[{outAuxName}]</code>. State is passthrough — this is a pure aux operation.
          </p>
        </div>
      ),
    },
  ];
};

// ─── xor-aux-into-state ──────────────────────────────────────────────

/**
 * `xor-aux-into-state`: state ⊕= aux. **One unit, not 16** (per the
 * Phase 3 plan). The XOR is one conceptual chaining step — CBC's P_i ⊕
 * C_{i-1} is a single pedagogical beat, not a 16-cell breakdown. Per-cell
 * detail is visible in the MatrixView the same frame renders alongside.
 *
 * If the user wants per-cell parity with AES AddRoundKey, revisit in a
 * follow-up — that would be a narration body change only.
 */
export const xorAuxIntoStateNarration: NarrationFn = (frame) => {
  const stateBefore = frame.stateBefore;
  const stateAfter = frame.stateAfter;
  if (stateBefore.shape !== "matrix4x4-bytes") return null;
  if (stateAfter.shape !== "matrix4x4-bytes") return null;
  const auxName = readStringParam(frame.params, "auxName");
  if (auxName === null) return null;
  const operand = frame.auxRead.get(auxName);
  if (!isMatrixState(operand)) return null;
  const beforeByte0 = stateBefore.bytes[0] ?? 0;
  const operandByte0 = operand.bytes[0] ?? 0;
  const afterByte0 = stateAfter.bytes[0] ?? 0;
  return [
    {
      key: "xor",
      label: `state ⊕= aux[${auxName}]`,
      Prose: (props) => (
        <div>
          <p>
            Byte-wise XOR of the current 4×4 state with <code>aux[{auxName}]</code>. In CBC encrypt
            this folds the previous ciphertext (or the IV for block 0) into the plaintext before
            AES; in CBC decrypt this folds it back out after the AES inverse. Per-cell values are
            visible in the matrix grid above — sample cell 0: state{" "}
            {formatByteInline(beforeByte0, props.fmt)} ⊕ aux{" "}
            {formatByteInline(operandByte0, props.fmt)} = {formatByteInline(afterByte0, props.fmt)}.
          </p>
          <p>
            <strong>Self-inverse property.</strong> A ⊕ B ⊕ B = A — applying the step twice with the
            same aux cancels out, which is why feedback modes (CBC, CFB, OFB) use XOR rather than
            addition. The encrypt and decrypt paths use this same step shape; only the
            chain-management plumbing around it differs.
          </p>
        </div>
      ),
    },
  ];
};

// ─── state-to-aux ────────────────────────────────────────────────────

/**
 * `state-to-aux` snapshots the current state into an aux name. The
 * narrator reads `frame.auxWritten` to confirm the snapshot and reports
 * its shape (typically MatrixState for CBC's chain update).
 */
export const stateToAuxNarration: NarrationFn = (frame) => {
  const auxName = readStringParam(frame.params, "auxName");
  if (auxName === null) return null;
  const snapshot = frame.auxWritten.get(auxName);
  if (snapshot === undefined) return null;
  // Most uses of state-to-aux save a MatrixState (CBC's chain). Decode
  // the shape for the prose so a future BytesState-based cipher's
  // snapshot reads sensibly too.
  const shape = isState(snapshot) ? snapshot.shape : "(unknown)";
  return [
    {
      key: "snapshot",
      label: `aux[${auxName}] := clone(state)`,
      Prose: () => (
        <div>
          <p>
            Deep-clone the current state and stash the snapshot into <code>aux[{auxName}]</code>{" "}
            (shape: <code>{shape}</code>). State itself is unchanged — this is a pure aux operation.
          </p>
          <p>
            Always allocates a fresh copy. The snapshot must survive across future state mutations
            (the next iterate iteration's state swap, the next in-place XOR) without aliasing the
            live buffer; sharing storage would let a later mutation silently corrupt the snapshot.
            Canonical use: CBC's chain update — the post-AES state is snapshotted into{" "}
            <code>aux[chain]</code> so the NEXT iteration's <code>xor-aux-into-state</code> has the
            freshly-produced ciphertext block.
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

const readIvLoadParams = (
  params: Json,
): { ivAuxName: string | null; outAuxName: string | null } => {
  return {
    ivAuxName: readStringParam(params, "ivAuxName"),
    outAuxName: readStringParam(params, "outAuxName"),
  };
};

const readStringParam = (params: Json, key: string): string | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>)[key];
  return typeof v === "string" && v.length > 0 ? v : null;
};

const uint8Length = (v: AuxValue | undefined): number | null =>
  v instanceof Uint8Array ? v.length : null;

const isMatrixState = (v: AuxValue | undefined): v is MatrixState =>
  typeof v === "object" && v !== null && "shape" in v && v.shape === "matrix4x4-bytes";

const isState = (v: AuxValue | undefined): v is State =>
  typeof v === "object" &&
  v !== null &&
  !Array.isArray(v) &&
  !(v instanceof Uint8Array) &&
  "shape" in v;
