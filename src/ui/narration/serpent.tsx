/**
 * Serpent narrators — Phase 2 of the per-frame value-prose plan.
 *
 * Three step types:
 *
 *   - `serpent.sub-bytes@1` → 16 byte units. Serpent's S-box is a 4-bit
 *     permutation applied independently to the LOW nibble and the HIGH
 *     nibble of each byte (standard form, paired with IP at the start
 *     of the cipher). Each unit shows BOTH nibble lookups, with the
 *     round-specific S-box index named.
 *
 *   - `serpent.add-round-key@1` → 16 cell units. Same byte-wise XOR
 *     shape as the AES AddRoundKey narrator (XOR with `roundKey.N` aux,
 *     byte at position `i`), but reading from a `BytesState` instead of
 *     a `MatrixState`.
 *
 *   - `serpent.bit-permutation@1` → 1 structural overview + 16 per-
 *     output-byte drill units = 17 units total. The structural unit
 *     orients the user (input vs output rendered in 8-bit binary side
 *     by side). Each drill unit shows the 8 source-bit lookups that
 *     assembled one output byte, with the taken bit highlighted in
 *     binary form. This is the most verbose narrator in Phase 2, but
 *     the only honest way to show a bit-permutation at byte granularity.
 *     Pattern documented in `feedback_bit_level_narration_pattern.md`.
 *
 * State shape: all three operate on a 16-byte `BytesState`. Cell index
 * is a linear byte index in `0..15` (no row/col), unlike AES which
 * threads through `MatrixState`.
 *
 * Bit numbering convention (per `src/steps/serpent-bit-ops.ts:16-18`):
 * state bit `b` is bit `(b%8)` of byte `(b>>3)`, **LSB-first** within
 * each byte. The bit-permutation narrator's structural prose names this
 * convention; the renderer uses MSB-on-left binary display (textbook
 * convention — `0xAB` reads as `10101011` with MSB leftmost), so the
 * highlighted-digit index inside the binary string is `7 - (b & 7)`.
 */

import type { BytesState, Json, TraceFrame } from "@/core/types";
import { For } from "solid-js";
import { formatByteInline, formatBytes } from "../components/byte-row";
import { type NarrationFn, type NarrationUnit, singleAuxNameFromFrame } from "./registry";

// ─── Serpent SubBytes ────────────────────────────────────────────────

/**
 * 16 byte units. Each byte holds two nibbles in the standard-form view:
 * the LOW nibble (bits 0..3, value `byte & 0x0f`) and the HIGH nibble
 * (bits 4..7, value `byte >> 4`). The S-box maps each independently.
 *
 * Prose names the round-specific S-box index (read from `params.sboxIndex`
 * — display-only annotation, but a critical pedagogical cue: Serpent
 * uses 8 different S-boxes and the round determines which one applies).
 *
 * Inverse direction: the executor receives the inverse table in
 * `params.sbox`; we don't try to distinguish forward vs inverse in prose
 * (the table contents are what the executor uses; we just narrate the
 * lookup the executor actually performed).
 */
export const serpentSubBytesNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  const after = readBytesState(frame.stateAfter);
  if (!before || !after || before.length !== 16 || after.length !== 16) return null;
  const sboxIndex = readSboxIndex(frame.params);
  const units: NarrationUnit[] = [];
  for (let i = 0; i < 16; i++) {
    const inByte = before[i] ?? 0;
    const outByte = after[i] ?? 0;
    const loIn = inByte & 0x0f;
    const hiIn = (inByte >> 4) & 0x0f;
    const loOut = outByte & 0x0f;
    const hiOut = (outByte >> 4) & 0x0f;
    const sboxName = sboxIndex !== null ? `S_${sboxIndex}` : "S-box";
    units.push({
      key: `byte:${i}`,
      label: `byte ${i}${sboxIndex !== null ? ` (uses S_${sboxIndex})` : ""}`,
      Prose: (props) => (
        <div>
          <p>
            Byte {i} = {formatByteInline(inByte, props.fmt)} → split into low nibble {hex4(loIn)}{" "}
            and high nibble {hex4(hiIn)}; apply 4-bit S-box to each independently.
          </p>
          <ul class="step-narration-mixcol-list">
            <li>
              low nibble: {sboxName}[{hex4(loIn)}] = {hex4(loOut)}
            </li>
            <li>
              high nibble: {sboxName}[{hex4(hiIn)}] = {hex4(hiOut)}
            </li>
            <li>
              reassembled byte: ({hex4(hiOut)} ≪ 4) | {hex4(loOut)} ={" "}
              {formatByteInline(outByte, props.fmt)}
            </li>
          </ul>
        </div>
      ),
    });
  }
  return units;
};

// ─── Serpent AddRoundKey ─────────────────────────────────────────────

/**
 * 16 cell units. Same shape as `aesAddRoundKeyNarration` but on flat
 * bytes — Serpent's state is `BytesState`, not `MatrixState`, so labels
 * drop the (row, col) annotation. Reads the single consumed aux name
 * (typically `roundKey.0`..`roundKey.32`) and renders
 * `before[i] ⊕ K[i] = after[i]` for each cell.
 *
 * If aux is missing or wrong-shape (defensive — shouldn't happen for a
 * frame that landed in the trace), return null and let the component
 * render nothing.
 */
export const serpentAddRoundKeyNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  const after = readBytesState(frame.stateAfter);
  if (!before || !after || before.length !== 16 || after.length !== 16) return null;
  const auxName = singleAuxNameFromFrame(frame);
  if (auxName === null) return null;
  const auxValue = frame.auxRead.get(auxName);
  if (!(auxValue instanceof Uint8Array) || auxValue.length < 16) return null;
  const units: NarrationUnit[] = [];
  for (let i = 0; i < 16; i++) {
    const b = before[i] ?? 0;
    const k = auxValue[i] ?? 0;
    const a = after[i] ?? 0;
    units.push({
      key: `cell:${i}`,
      label: `cell ${i}`,
      Prose: (props) => (
        <p>
          {formatByteInline(b, props.fmt)} ⊕ {auxName}[{i}] = {formatByteInline(k, props.fmt)} ={" "}
          {formatByteInline(a, props.fmt)}. XOR is self-inverse — decrypting consumes the same round
          keys in reverse order.
        </p>
      ),
    });
  }
  return units;
};

// ─── Serpent bit permutation (IP / FP) ───────────────────────────────

/**
 * 1 structural overview + 16 per-output-byte drill = 17 units.
 *
 * Structural overview: shows the 16-byte input and 16-byte output side
 * by side as 8-bit binary strings (MSB-on-left), naming the bit-numbering
 * convention. One disclosure at the top of the unit list — the user can
 * skip it once they've internalised the IP/FP layout.
 *
 * Per-output-byte drill: for output byte `j`, the 8 output bits live at
 * state-bits `8j..8j+7` (LSB at `8j`). Each output bit `o` reads from
 * input state-bit `table[o]`. The drill renders one row per output bit
 * showing the source state-bit address, the source byte's full 8-bit
 * binary with the taken bit highlighted (`<span class="bit-highlighted">`),
 * and the resulting bit value. After 8 rows, the assembled output byte
 * is shown in binary + hex form.
 *
 * The `params.label` (typically "IP" or "FP", display-only annotation
 * on the bit-permutation step) is named in the structural-overview
 * prose so users can tell which of the two permutations this frame
 * runs without leaving the narration.
 */
export const serpentBitPermutationNarration: NarrationFn = (frame) => {
  const before = readBytesState(frame.stateBefore);
  const after = readBytesState(frame.stateAfter);
  const table = readPermutationTable(frame.params);
  if (!before || !after || before.length !== 16 || after.length !== 16 || !table) return null;
  const label = readPermutationLabel(frame.params);
  const units: NarrationUnit[] = [];

  // Capture stable Uint8Array copies so the closures don't observe a
  // mutated state on subsequent frame swaps. The runtime already clones
  // around us, but a defensive snapshot keeps the prose deterministic
  // even if a future executor optimises the clone away.
  const beforeFrozen = new Uint8Array(before);
  const afterFrozen = new Uint8Array(after);

  // Unit 0: structural overview.
  units.push({
    key: "overview",
    label: `bit-permutation overview${label ? ` (${label})` : ""}`,
    Prose: (props) => (
      <div>
        <p>
          {label ? `This is the ${label} step — ` : "This is a bit-permutation step — "}a fixed bit
          shuffle: output_bit[i] = input_bit[table[i]], for i in 0..127. Each output bit is a copy
          of one input bit; no XOR, no S-box. Bit numbering: state bit b lives at bit (b mod 8) of
          byte (b ÷ 8), LSB-first within each byte. The 8-bit binary strings below show the MSB on
          the left (textbook convention — byte 0xAB renders as 10101011).
        </p>
        <p>
          input ({formatBytes(beforeFrozen, props.fmt)}):
          <code class="step-narration-bit-overview">{bytesToBinaryString(beforeFrozen)}</code>
        </p>
        <p>
          output ({formatBytes(afterFrozen, props.fmt)}):
          <code class="step-narration-bit-overview">{bytesToBinaryString(afterFrozen)}</code>
        </p>
      </div>
    ),
  });

  // Units 1..16: per-output-byte drill.
  for (let j = 0; j < 16; j++) {
    const outByte = afterFrozen[j] ?? 0;
    // For each output bit position p (0..7, LSB-first in the byte),
    // resolve which source state-bit, source byte, source bit-in-byte
    // it pulls from. Stash everything the Prose needs into a closure-
    // captured array so the render is just a `<For>` over fixed data.
    type BitLookup = {
      readonly outBitPos: number; // 0..7 (LSB-first within byte)
      readonly srcStateBit: number; // 0..127
      readonly srcByteIndex: number;
      readonly srcBitInByte: number; // 0..7 (LSB-first)
      readonly srcByteValue: number;
      readonly bitValue: 0 | 1;
    };
    const lookups: BitLookup[] = [];
    for (let p = 0; p < 8; p++) {
      const srcStateBit = table[8 * j + p] ?? 0;
      const srcByteIndex = srcStateBit >> 3;
      const srcBitInByte = srcStateBit & 7;
      const srcByteValue = beforeFrozen[srcByteIndex] ?? 0;
      const bitValue: 0 | 1 = ((srcByteValue >> srcBitInByte) & 1) === 1 ? 1 : 0;
      lookups.push({
        outBitPos: p,
        srcStateBit,
        srcByteIndex,
        srcBitInByte,
        srcByteValue,
        bitValue,
      });
    }
    units.push({
      key: `byte:${j}`,
      label: `byte ${j} of output`,
      Prose: (props) => (
        <div>
          <p>
            Output byte {j} occupies state bits {8 * j}..{8 * j + 7} (LSB-first). Each output bit is
            sourced from one input bit per the table:
          </p>
          <ul class="step-narration-bit-drill">
            <For each={lookups}>
              {(lk) => (
                <li>
                  <code>
                    out_bit {lk.outBitPos} ← state_bit {lk.srcStateBit} = byte {lk.srcByteIndex}
                    [bit {lk.srcBitInByte}] ={" "}
                    {byteToBinaryHighlighted(lk.srcByteValue, lk.srcBitInByte)} → {lk.bitValue}
                  </code>
                </li>
              )}
            </For>
          </ul>
          <p>
            Assembled output byte {j}: <code>{byteToBinary(outByte)}</code> ={" "}
            {formatByteInline(outByte, props.fmt)}.
          </p>
        </div>
      ),
    });
  }

  return units;
};

// ─── Helpers ─────────────────────────────────────────────────────────

/** Pull the bytes out of a `BytesState`; return null on shape mismatch. */
const readBytesState = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "bytes") return null;
  return (state as BytesState).bytes;
};

/**
 * Read the optional `sboxIndex` annotation (0..7) off a SubBytes frame's
 * params. Returns null when missing or out of range — the prose falls
 * back to a generic "S-box" name in that case.
 */
const readSboxIndex = (params: Json): number | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).sboxIndex;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > 7) return null;
  return v;
};

/** Read the 128-entry permutation table off a bit-permutation frame. */
const readPermutationTable = (params: Json): readonly number[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const t = (params as Record<string, Json>).table;
  if (!Array.isArray(t) || t.length !== 128) return null;
  if (!t.every((n) => typeof n === "number")) return null;
  return t as readonly number[];
};

/** Read the optional `label` annotation off a bit-permutation frame ("IP" / "FP"). */
const readPermutationLabel = (params: Json): string | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).label;
  return typeof v === "string" && v.length > 0 ? v : null;
};

/** Format a 4-bit nibble as 1 hex char with `0x` prefix (e.g. `0x5`). */
const hex4 = (n: number): string => `0x${(n & 0x0f).toString(16)}`;

/** Render a byte in 8-bit binary, MSB-on-left (e.g. `0xAB` → `"10101011"`). */
const byteToBinary = (b: number): string => (b & 0xff).toString(2).padStart(8, "0");

/**
 * Render a byte in 8-bit binary with the given bit position (LSB-first
 * index 0..7) highlighted via a `<span class="bit-highlighted">`. Because
 * the binary string is MSB-on-left, the *string* index of the bit at
 * LSB-position `p` is `7 - p`.
 */
const byteToBinaryHighlighted = (b: number, lsbBitPos: number) => {
  const bin = byteToBinary(b);
  const stringIndex = 7 - (lsbBitPos & 7);
  return (
    <>
      <span class="step-narration-binary-byte">
        {bin.slice(0, stringIndex)}
        <span class="bit-highlighted">{bin[stringIndex]}</span>
        {bin.slice(stringIndex + 1)}
      </span>
    </>
  );
};

/**
 * Render a 16-byte state as 16 space-separated 8-bit binary strings,
 * MSB-on-left. Used in the structural overview to show "before" and
 * "after" side by side without the per-bit highlighting.
 */
const bytesToBinaryString = (bytes: Uint8Array): string => {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(byteToBinary(bytes[i] ?? 0));
  }
  return parts.join(" ");
};
