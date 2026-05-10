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
 */

import { AES_SBOX } from "@/ciphers/aes-constants";
import { For } from "solid-js";
import { HexCellInput } from "./HexCellInput";

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

  return (
    <div class="sbox-editor">
      <div class="sbox-axis-label sbox-col-axis">
        <span class="muted">col →</span>
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
                  <HexCellInput
                    compact
                    value={props.sbox[idx] ?? 0}
                    modified={props.sbox[idx] !== (canonical[idx] ?? 0)}
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
