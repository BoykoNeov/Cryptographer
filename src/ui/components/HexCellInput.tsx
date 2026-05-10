/**
 * One editable hex byte cell, used by both SboxEditor (16x16 grid) and
 * MatrixEditor (4x4 grid). Self-contained — owns its own input element,
 * commits on blur/Enter, validates that the value is in 0..255.
 *
 * Why a dedicated component: 256 input elements on the S-box grid would
 * be unmanageable inline. Solid handles that count fine, but the
 * keyboard-and-validation logic should live in one place.
 */

import { createSignal } from "solid-js";

type Props = {
  value: number;
  onCommit: (next: number) => void;
  /** Show the value in red when it differs from the canonical default. */
  modified?: boolean;
  /** Compact rendering for the 16x16 S-box grid. */
  compact?: boolean;
};

export const HexCellInput = (props: Props) => {
  // Local edit-buffer state so the input stays under user control while
  // typing — we don't push every keystroke through the spec store.
  const [draft, setDraft] = createSignal(toHex(props.value));

  // Re-sync draft when the upstream value changes (e.g. Reset button).
  // Using an effect would be overkill; we just compare on render.
  let lastUpstream = props.value;
  const syncedDraft = () => {
    if (props.value !== lastUpstream) {
      lastUpstream = props.value;
      setDraft(toHex(props.value));
    }
    return draft();
  };

  const commit = () => {
    const parsed = Number.parseInt(draft(), 16);
    if (Number.isNaN(parsed) || parsed < 0 || parsed > 255) {
      // Invalid — snap back to the upstream value.
      setDraft(toHex(props.value));
      return;
    }
    if (parsed !== props.value) props.onCommit(parsed);
    setDraft(toHex(parsed)); // canonical 2-char form
  };

  return (
    <input
      class="hex-cell"
      classList={{ compact: props.compact, modified: props.modified }}
      type="text"
      maxLength={2}
      spellcheck={false}
      value={syncedDraft()}
      onInput={(e) => setDraft(e.currentTarget.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          commit();
          e.currentTarget.blur();
        } else if (e.key === "Escape") {
          // Cancel edit: revert draft, then blur without committing.
          setDraft(toHex(props.value));
          e.currentTarget.blur();
        }
      }}
    />
  );
};

const toHex = (b: number): string => b.toString(16).padStart(2, "0");
