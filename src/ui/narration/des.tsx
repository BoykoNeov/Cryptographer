/**
 * DES narrators — Phase 4 of `docs/plans/des-feistel.md`.
 *
 * Six step types ship with per-frame value-prose:
 *
 *   - `des.initial-permutation@1` / `des.final-permutation@1` — bit
 *     permutations on the 64-bit (8-byte) block. Structural overview +
 *     per-output-byte drill, mirroring the Serpent IP/FP narrator's two-
 *     tier `[[feedback-bit-level-narration-pattern]]`.
 *   - `des.expand-R@1` — bit permutation 4 bytes → 6 bytes (32 → 48
 *     bits). Output size differs from input size: 6 drill units (one per
 *     output byte) instead of 8.
 *   - `des.p-permutation@1` — bit permutation on the 32-bit S-box output.
 *     4 drill units.
 *   - `des.xor-with-K@1` — 6 cell units, one per byte. Mirrors AES /
 *     Serpent AddRoundKey narrators (XOR is self-inverse, reads one aux).
 *   - `des.s-boxes@1` — 8 units, one per S-box (S1..S8). Each unit shows
 *     the 6-bit input split into (row, col) per FIPS 46-3 Appendix A's
 *     `row = (b1 << 1) | b6, col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5`
 *     index extraction, the 4-bit lookup value, and how the result lands
 *     in the 4-bit output slot.
 *
 * **Bit numbering: FIPS 46-3 convention.** Bits are 1-indexed and
 * MSB-first within each byte. This is distinct from Serpent's
 * LSB-first numbering; the two ciphers share neither helpers nor
 * narration code. Display in the structural overview keeps MSB-on-left
 * (textbook convention — `0xAB` reads as `10101011`), so a highlighted-
 * digit at FIPS bit position `i` (within a byte, 1..8) lives at string
 * index `((i - 1) & 7)` — no flip needed since FIPS and display agree
 * on "MSB first".
 *
 * **Defensive null returns.** Each narrator returns `null` when the
 * frame's state shape, byte count, or params shape doesn't match
 * expectations. The component renders nothing in that case (the
 * contract test still requires either registration here or an
 * allowlist entry).
 */

import { framePrimaryInBytes, framePrimaryOutBytes } from "@/core/frame-state";
import type { Json } from "@/core/types";
import { For } from "solid-js";
import { formatByteInline, formatBytes } from "../components/byte-row";
import { type NarrationFn, type NarrationUnit, singleAuxNameFromFrame } from "./registry";

// ─── DES bit-permutation narrator (shared by IP / FP / E / P) ─────────

/**
 * Build the unit list for a DES bit-permutation step. Reused by IP, FP,
 * E-expand, and P-permute — they differ only in input length, output
 * length, label, and table.
 *
 * Args:
 *   - `inputBytes` / `outputBytes`: byte snapshots before / after.
 *   - `table`: FIPS 1-indexed source-bit indices.
 *   - `outBits`: total output bit count (8 × outputBytes.length is the
 *     usual case, but E's output uses all 48 bits of the 6-byte buffer
 *     while P uses all 32 of its 4-byte buffer — explicit so a future
 *     non-byte-aligned table doesn't trip on trailing zero bits).
 *   - `label`: human-readable step name ("IP", "FP", "E", "P") shown
 *     in the structural overview and unit labels.
 *
 * Returns `1 + outputBytes.length` units: one structural overview plus
 * one drill per output byte.
 */
const buildBitPermutationUnits = (
  inputBytes: Uint8Array,
  outputBytes: Uint8Array,
  table: readonly number[],
  outBits: number,
  label: string,
): readonly NarrationUnit[] => {
  if (table.length !== outBits) return [];
  const units: NarrationUnit[] = [];
  // Stable copies — defensive against future executors that might
  // mutate state. The runtime clones around us today, but the frozen
  // snapshot keeps closures deterministic.
  const beforeFrozen = new Uint8Array(inputBytes);
  const afterFrozen = new Uint8Array(outputBytes);

  // Unit 0: structural overview.
  units.push({
    key: "overview",
    label: `${label} overview`,
    Prose: (props) => (
      <div>
        <p>
          {label} is a fixed bit shuffle: output_bit[i] = input_bit[table[i]] for i = 1..
          {outBits}. Each output bit is a copy of one input bit; no XOR, no S-box. Bit numbering is
          FIPS 46-3: bits are 1-indexed and MSB-first within each byte (bit 1 = MSB of byte 0). The
          binary strings below show the MSB on the left (textbook convention — byte 0xAB renders as
          10101011).
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

  // Drill units: one per output byte. The last output byte may carry
  // fewer than 8 meaningful bits (only relevant when `outBits % 8 !== 0`
  // — not a case any DES table hits today, but kept honest).
  const numOutBytes = outputBytes.length;
  for (let j = 0; j < numOutBytes; j++) {
    const outByte = afterFrozen[j] ?? 0;
    const bitsInThisByte = Math.min(8, outBits - 8 * j);

    // Pre-compute per-bit lookups so the Prose body is just a `<For>`.
    type BitLookup = {
      readonly outBitPos: number; // 0..7 within the output byte (MSB-first display index)
      readonly fipsOutputBit: number; // 1..outBits (full state)
      readonly srcFipsBit: number; // 1..(8*input.length)
      readonly srcByteIndex: number; // 0..(input.length - 1)
      readonly srcBitInByte: number; // 0..7 (MSB-first display index)
      readonly srcByteValue: number;
      readonly bitValue: 0 | 1;
    };
    const lookups: BitLookup[] = [];
    for (let p = 0; p < bitsInThisByte; p++) {
      const fipsOutputBit = 8 * j + p + 1; // 1-indexed
      const srcFipsBit = table[fipsOutputBit - 1] ?? 0;
      const srcByteIndex = (srcFipsBit - 1) >> 3;
      const srcBitInByte = (srcFipsBit - 1) & 7; // MSB-first index within the byte
      const srcByteValue = beforeFrozen[srcByteIndex] ?? 0;
      // FIPS bit-read: bit = (byte >> (7 - bitInByte)) & 1.
      const bitValue: 0 | 1 = ((srcByteValue >> (7 - srcBitInByte)) & 1) === 1 ? 1 : 0;
      lookups.push({
        outBitPos: p,
        fipsOutputBit,
        srcFipsBit,
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
            Output byte {j} occupies state bits {8 * j + 1}..{8 * j + bitsInThisByte} (FIPS,
            MSB-first in the byte). Each output bit is sourced from one input bit per the table:
          </p>
          <ul class="step-narration-bit-drill">
            <For each={lookups}>
              {(lk) => (
                <li>
                  <code>
                    out_bit {lk.fipsOutputBit} ← state_bit {lk.srcFipsBit} = byte {lk.srcByteIndex}
                    [bit {lk.srcBitInByte + 1}] ={" "}
                    {byteToBinaryHighlightedMsbFirst(lk.srcByteValue, lk.srcBitInByte)} →{" "}
                    {lk.bitValue}
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

// ─── Concrete narrators per DES step type ─────────────────────────────

export const desInitialPermutationNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  const table = readPermutationTable(frame.params, 64);
  if (!before || !after || before.length !== 8 || after.length !== 8 || !table) return null;
  return buildBitPermutationUnits(before, after, table, 64, "Initial Permutation (IP)");
};

export const desFinalPermutationNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  const table = readPermutationTable(frame.params, 64);
  if (!before || !after || before.length !== 8 || after.length !== 8 || !table) return null;
  return buildBitPermutationUnits(before, after, table, 64, "Final Permutation (FP = IP⁻¹)");
};

/**
 * E-expand is the bit-permutation case where output length > input
 * length: 32 input bits flow into 48 output bits (12 bits are duplicated
 * — adjacent S-box groups share a bit at each boundary). The drill
 * units name the duplications implicitly via repeated source-bit
 * indices.
 */
export const desExpandRNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  const table = readPermutationTable(frame.params, 48);
  if (!before || !after || before.length !== 4 || after.length !== 6 || !table) return null;
  return buildBitPermutationUnits(before, after, table, 48, "Expansion (E)");
};

export const desPPermutationNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  const table = readPermutationTable(frame.params, 32);
  if (!before || !after || before.length !== 4 || after.length !== 4 || !table) return null;
  return buildBitPermutationUnits(before, after, table, 32, "P permutation");
};

// ─── DES xor-with-K ────────────────────────────────────────────────────

/**
 * 6 cell units (one per byte of the 48-bit S-box-input buffer). Mirrors
 * Serpent's AddRoundKey narrator shape, scaled to 6 bytes and with prose
 * tailored to the F-function context — the user reads this knowing the
 * result feeds the S-boxes, not the next state directly.
 */
export const desXorWithKNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  if (!before || !after || before.length !== 6 || after.length !== 6) return null;
  const auxName = singleAuxNameFromFrame(frame);
  if (auxName === null) return null;
  const auxValue = frame.auxRead.get(auxName);
  if (!(auxValue instanceof Uint8Array) || auxValue.length < 6) return null;
  const units: NarrationUnit[] = [];
  for (let i = 0; i < 6; i++) {
    const b = before[i] ?? 0;
    const k = auxValue[i] ?? 0;
    const a = after[i] ?? 0;
    units.push({
      key: `cell:${i}`,
      label: `byte ${i}`,
      Prose: (props) => (
        <p>
          {formatByteInline(b, props.fmt)} ⊕ {auxName}[{i}] = {formatByteInline(k, props.fmt)} ={" "}
          {formatByteInline(a, props.fmt)}. This XOR mixes the round subkey K_i (48 bits, 6 bytes)
          into the expanded R half; the result feeds the 8 S-boxes. Round 16 of encryption consumes
          K_16; decryption consumes the same schedule in reverse (K_16, K_15, …, K_1).
        </p>
      ),
    });
  }
  return units;
};

// ─── DES S-boxes ───────────────────────────────────────────────────────

/**
 * 8 units, one per S-box. Per FIPS 46-3 Appendix A: each 6-bit input
 * group b1..b6 indexes its S-box via
 *
 *   row = (b1 << 1) | b6
 *   col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5
 *
 * and the 4-bit value at `S_n[row][col]` writes MSB-first into bits
 * `4(n-1)..4n-1` of the 32-bit output (n = 1..8).
 *
 * Each narration unit names the 6 input bits' FIPS positions in the
 * 48-bit input (so the user can correlate with the xor-with-K frame
 * just before), shows the row/col extraction, and the 4-bit lookup
 * output.
 */
export const desSBoxesNarration: NarrationFn = (frame) => {
  const before = framePrimaryInBytes(frame);
  const after = framePrimaryOutBytes(frame);
  const sboxes = readSBoxes(frame.params);
  if (!before || !after || before.length !== 6 || after.length !== 4 || !sboxes) return null;

  const beforeFrozen = new Uint8Array(before);
  const afterFrozen = new Uint8Array(after);
  const units: NarrationUnit[] = [];

  for (let s = 0; s < 8; s++) {
    // The 6 input bits live at FIPS positions 6s+1..6s+6 of the 48-bit
    // input buffer.
    const inBits: number[] = [];
    for (let p = 0; p < 6; p++) {
      const fipsBit = 6 * s + p + 1;
      const byteIdx = (fipsBit - 1) >> 3;
      const bitInByte = (fipsBit - 1) & 7;
      const byteVal = beforeFrozen[byteIdx] ?? 0;
      inBits.push((byteVal >> (7 - bitInByte)) & 1);
    }
    const b1 = inBits[0] ?? 0;
    const b2 = inBits[1] ?? 0;
    const b3 = inBits[2] ?? 0;
    const b4 = inBits[3] ?? 0;
    const b5 = inBits[4] ?? 0;
    const b6 = inBits[5] ?? 0;
    const row = (b1 << 1) | b6;
    const col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5;
    const box = sboxes[s];
    const rowArr = box?.[row];
    const val = rowArr?.[col] ?? 0;

    // The 4-bit val sits at FIPS output positions 4s+1..4s+4.
    const fipsOutStart = 4 * s + 1;
    const fipsOutEnd = 4 * s + 4;

    units.push({
      key: `sbox:${s}`,
      label: `S${s + 1}`,
      Prose: (props) => (
        <div>
          <p>
            S-box S{s + 1} consumes the 6 bits at FIPS positions {6 * s + 1}..{6 * s + 6} of the
            48-bit input and produces 4 bits at FIPS output positions {fipsOutStart}..{fipsOutEnd}{" "}
            of the 32-bit pre-P state.
          </p>
          <ul class="step-narration-mixcol-list">
            <li>
              input bits b1..b6 = {b1} {b2} {b3} {b4} {b5} {b6}
            </li>
            <li>
              row = (b1 ≪ 1) | b6 = ({b1} ≪ 1) | {b6} = {row}
            </li>
            <li>col = (b2 ≪ 3) | (b3 ≪ 2) | (b4 ≪ 1) | b5 = {col}</li>
            <li>
              S{s + 1}[{row}][{col}] = {val} (binary {nibbleToBinary(val)})
            </li>
          </ul>
          <p>
            The 4-bit output lands MSB-first into pre-P bits {fipsOutStart}..{fipsOutEnd}. After all
            8 S-boxes complete in parallel, the 32-bit result is{" "}
            {formatBytes(afterFrozen, props.fmt)}.
          </p>
        </div>
      ),
    });
  }

  return units;
};

// ─── Helpers ───────────────────────────────────────────────────────────

/**
 * Source a DES leaf's input / output bytes for narration.
 *
 * **B4 (universal-port Phase 4d):** the port-native DES F-leaves dropped
 * `stateInputPort`/`stateOutputPort`, so the runtime never reconstructs the
 * threaded `state` through the rounds — every DES round frame's threaded
 * state holds the STALE initial plaintext. The honest per-leaf bytes live on
 * the port I/O instead (`frame.portInputs` / `frame.portOutputs`). DES B4
 * pioneered the port-first read; Slice 5.3c lifted it into the shared
 * `framePrimaryInBytes` / `framePrimaryOutBytes` helpers (read the `"state"`
 * port; the legacy State-field fallback retired in Slice 5.3e Batch 4, so a
 * leaf with no `"state"` port reads null), so every narrator now sources state
 * through one definition.
 */

/**
 * Read a FIPS permutation table off a frame's params. Returns null when
 * missing or wrong-sized (the executor would have thrown before
 * emitting the frame, but we double-check defensively).
 */
const readPermutationTable = (params: Json, expectedLength: number): readonly number[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const t = (params as Record<string, Json>).table;
  if (!Array.isArray(t) || t.length !== expectedLength) return null;
  if (!t.every((n) => typeof n === "number")) return null;
  return t as readonly number[];
};

/**
 * Read the 8 S-boxes off an `des.s-boxes@1` frame's params. Shape is
 * `number[8][4][16]`. Returns null on any structural mismatch.
 */
const readSBoxes = (params: Json): readonly (readonly (readonly number[])[])[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).sboxes;
  if (!Array.isArray(v) || v.length !== 8) return null;
  for (const box of v) {
    if (!Array.isArray(box) || box.length !== 4) return null;
    for (const row of box) {
      if (!Array.isArray(row) || row.length !== 16) return null;
    }
  }
  return v as readonly (readonly (readonly number[])[])[];
};

/** 8-bit binary, MSB-on-left. Matches Serpent's narrator's convention. */
const byteToBinary = (b: number): string => (b & 0xff).toString(2).padStart(8, "0");

/** 4-bit binary, MSB-on-left (used in S-box output display). */
const nibbleToBinary = (n: number): string => (n & 0x0f).toString(2).padStart(4, "0");

/**
 * Render a byte's 8-bit binary string with one bit highlighted. Bit
 * position is FIPS-style MSB-first index (0..7), matching `srcBitInByte`
 * computed in `buildBitPermutationUnits`. Since the display is also
 * MSB-on-left, the string index equals the bit position directly — no
 * flip (unlike Serpent's narrator, where LSB-first numbering needs the
 * `7 - p` flip).
 */
const byteToBinaryHighlightedMsbFirst = (b: number, msbBitPos: number) => {
  const bin = byteToBinary(b);
  const stringIndex = msbBitPos & 7;
  return (
    <span class="step-narration-binary-byte">
      {bin.slice(0, stringIndex)}
      <span class="bit-highlighted">{bin[stringIndex]}</span>
      {bin.slice(stringIndex + 1)}
    </span>
  );
};

const bytesToBinaryString = (bytes: Uint8Array): string => {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) parts.push(byteToBinary(bytes[i] ?? 0));
  return parts.join(" ");
};
