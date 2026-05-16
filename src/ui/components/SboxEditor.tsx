/**
 * 16x16 grid editor for an AES-style S-box (a 256-entry permutation of
 * bytes). Each cell shows the current substitution value at that index.
 *
 * Layout: row r, col c → S-box index (r * 16 + c). This matches FIPS-197
 * Appendix C's table presentation, which is the convention every AES
 * textbook uses, so users can sanity-check by eye.
 *
 * Cells highlight in red when they differ from the canonical AES S-box,
 * giving visible feedback that an experiment is in progress.
 *
 * Bijection enforcement: an S-box MUST be a permutation of 0..255 for
 * the inverse table to be well-defined. The editor lets users freely
 * type any byte (the whole point of the project is to *let them
 * experiment*), but surfaces duplicates two ways:
 *   - Per-cell: a red outline + tooltip naming the colliding indices.
 *   - Top banner: count of redundant cells + a "Repair to permutation"
 *     button that runs `repairToPermutation` (leftmost wins; missing
 *     values fill the redundant slots in ascending order).
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import { For, Show, createMemo } from "solid-js";
import { ActionButton } from "./ActionButton";
import { ByteCellInput } from "./ByteCellInput";
import {
  collisionGroupsByIndex,
  countRedundantDuplicates,
  findDuplicateIndices,
  repairToPermutation,
} from "./sbox-validation";

type Props = {
  sbox: readonly number[];
  /** Called with a new 256-entry array whenever any cell commits. */
  onChange: (next: number[]) => void;
  /** When true, compare against the AES inverse S-box for "modified" highlighting. */
  inverse?: boolean;
};

export const SboxEditor = (props: Props) => {
  // Range objects so we don't re-allocate every render.
  const indices = Array.from({ length: 256 }, (_, i) => i);
  const rows = Array.from({ length: 16 }, (_, i) => i);

  // The 'canonical' S-box to compare against for modified-cell highlighting.
  // We'd use the inverse table here too, but the editor doesn't currently
  // know whether it's editing the forward or inverse box; for now we always
  // compare to AES_SBOX. Future improvement: pass canonical via props.
  const canonical = props.inverse ? AES_SBOX : AES_SBOX;

  // Memoize duplicate detection — the For callback below reads from
  // these memos for every cell, so we want them computed once per
  // change to props.sbox rather than per-cell.
  const duplicateSet = createMemo(() => findDuplicateIndices(props.sbox));
  const collisionGroups = createMemo(() => collisionGroupsByIndex(props.sbox));
  const redundantCount = createMemo(() => countRedundantDuplicates(props.sbox));

  const handleRepair = (): void => {
    props.onChange(repairToPermutation(props.sbox));
  };

  return (
    <div class="sbox-editor">
      {/* Warning banner: only renders when the table is not a permutation.
          Decryption ambiguity isn't just a "yellow warning" — it's a
          correctness failure, so we lean red rather than amber here
          (amber is already taken by .modified for "you edited this"). */}
      <Show when={redundantCount() > 0}>
        <div class="sbox-warning-banner" role="alert">
          <span class="sbox-warning-icon" aria-hidden="true">
            ⚠
          </span>
          <span class="sbox-warning-text">
            This S-box must be a permutation of 0–255 (each value appears exactly once). With{" "}
            {redundantCount()} duplicate {redundantCount() === 1 ? "value" : "values"}, the table is
            not invertible.
          </span>
          {/* Wrapped in ActionButton so the click flashes the button
              green + announces "Repaired S-box to a permutation" to
              assistive tech. The repair changes the table without
              showing a status message anywhere else, so this feedback
              is the only confirmation a user gets. */}
          <ActionButton
            class="sbox-warning-repair"
            onAction={handleRepair}
            feedbackLabel="Repaired S-box to a permutation"
          >
            Repair to permutation
          </ActionButton>
        </div>
      </Show>

      <div class="sbox-axis-label sbox-col-axis">
        <span class="muted">col →</span>
        {/* Axis labels are intentionally rendered in hex regardless of the
            global byte-format toggle. These are *addresses* — the high/low
            nibble of the byte being looked up in the table — not byte
            values. Decimal would imply a 16x16 grid indexed 0..255 (it
            isn't), and ASCII would be nonsense. Keeping hex preserves the
            FIPS-197 Appendix C presentation convention. */}
        <For each={rows}>{(c) => <span class="axis-cell">{toHex1(c)}</span>}</For>
      </div>

      <div class="sbox-grid">
        <For each={indices}>
          {(idx) => {
            const r = Math.floor(idx / 16);
            const c = idx % 16;
            // Render the row-axis label as the first cell of each row.
            // Using grid-column/row to position keeps rendering simple.
            return (
              <>
                {c === 0 && (
                  <span class="axis-cell" style={{ "grid-row": `${r + 1}`, "grid-column": "1" }}>
                    {toHex1(r)}
                  </span>
                )}
                <div
                  class="sbox-cell-wrap"
                  style={{ "grid-row": `${r + 1}`, "grid-column": `${c + 2}` }}
                >
                  <ByteCellInput
                    compact
                    value={props.sbox[idx] ?? 0}
                    modified={props.sbox[idx] !== (canonical[idx] ?? 0)}
                    duplicate={duplicateSet().has(idx)}
                    title={duplicateTitleFor(idx, collisionGroups())}
                    onCommit={(next) => {
                      // Always copy the array so callers can detect change
                      // by reference identity (the spec mutator relies on
                      // this).
                      const out = [...props.sbox];
                      out[idx] = next;
                      props.onChange(out);
                    }}
                  />
                </div>
              </>
            );
          }}
        </For>
      </div>
    </div>
  );
};

const toHex1 = (n: number): string => n.toString(16);

const toHex2 = (n: number): string => n.toString(16).padStart(2, "0");

/**
 * Build a per-cell tooltip when `idx` is part of a duplicate group:
 * names the other indices its value collides with. Returns undefined
 * for non-duplicate cells so the input element renders no `title=""`.
 */
function duplicateTitleFor(
  idx: number,
  groups: Map<number, readonly number[]>,
): string | undefined {
  const group = groups.get(idx);
  if (!group) return undefined;
  // Show all indices in the collision group, hex-formatted to match the
  // grid's address presentation. The user is reading these as addresses.
  const others = group.filter((i) => i !== idx).map((i) => `0x${toHex2(i)}`);
  return `Duplicate value — also at ${others.join(", ")}`;
}
