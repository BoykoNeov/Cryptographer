/**
 * Editor for the four ShiftRows row-shift counts. AES forward uses
 * [0, 1, 2, 3] (left-shift row r by r). Inverse uses [0, 3, 2, 1].
 *
 * Values are clamped to 0..3 because cyclic shifts mod 4 — anything else
 * is meaningless. (The shift-rows executor itself does the modulo, so
 * out-of-range values wouldn't crash, but they'd just confuse.)
 */

import { For } from "solid-js";

type Props = {
  shifts: readonly number[];
  onChange: (next: number[]) => void;
};

export const ShiftsEditor = (props: Props) => {
  const rows = [0, 1, 2, 3];

  return (
    <div class="shifts-editor">
      <For each={rows}>
        {(r) => (
          <label class="shift-row">
            <span class="shift-label">row {r}</span>
            <input
              type="number"
              min="0"
              max="3"
              value={props.shifts[r] ?? 0}
              onInput={(e) => {
                const raw = Number.parseInt(e.currentTarget.value, 10);
                if (Number.isNaN(raw)) return;
                // Clamp and propagate. We don't snap the input to the
                // clamped value visually because that would fight
                // mid-keystroke editing.
                const clamped = Math.max(0, Math.min(3, raw));
                const out = [...props.shifts];
                out[r] = clamped;
                props.onChange(out);
              }}
            />
          </label>
        )}
      </For>
    </div>
  );
};
