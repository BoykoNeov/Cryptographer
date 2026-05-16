/**
 * One editable byte cell, used by both SboxEditor (16x16 grid) and
 * MatrixEditor (4x4 grid). Self-contained — owns its own input element,
 * commits on blur/Enter, validates against the *current byte format*
 * (hex / decimal / ASCII).
 *
 * Renamed from HexCellInput as part of Phase 3 (byte format toggle). The
 * width adapts to the format because decimal needs 3 chars per byte and
 * ASCII can need 4 (`\xNN`). The format itself is read from the format
 * store, not passed as a prop, so a toggle elsewhere in the app re-renders
 * every byte cell consistently.
 *
 * Why a dedicated component: 256 input elements on the S-box grid would
 * be unmanageable inline. Solid handles that count fine, but the
 * keyboard-and-validation logic should live in one place.
 */

import { type ByteFormat, byteDisplayWidth, formatByte, parseByte } from "@/core/format";
import { createSignal } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  value: number;
  onCommit: (next: number) => void;
  /** Show the value in red when it differs from the canonical default. */
  modified?: boolean;
  /** Compact rendering for the 16x16 S-box grid. */
  compact?: boolean;
  /**
   * Highlight this cell because its value collides with another cell's
   * value, breaking the S-box's permutation invariant. Styled with a
   * red outline so it stays distinct from the amber `modified` accent —
   * the two states can co-occur (a cell can be both edited and part of
   * a duplicate group), and duplicate is the more important signal.
   */
  duplicate?: boolean;
  /**
   * Tooltip — e.g. for SboxEditor to enumerate a cell's collision group.
   * Typed with explicit `| undefined` so callers can pass the result of
   * a conditional helper without exactOptionalPropertyTypes complaints.
   */
  title?: string | undefined;
};

export const ByteCellInput = (props: Props) => {
  const fmt = useByteFormat();

  // Local edit-buffer state so the input stays under user control while
  // typing — we don't push every keystroke through the spec store.
  const [draft, setDraft] = createSignal(formatByte(props.value, fmt()));

  // Re-sync draft when either the upstream value OR the byte format
  // changes (the latter is the Phase-3-specific case: switching format
  // mid-session must re-render every cell in the new format).
  let lastUpstream = props.value;
  let lastFmt: ByteFormat = fmt();
  const syncedDraft = () => {
    const currentFmt = fmt();
    if (props.value !== lastUpstream || currentFmt !== lastFmt) {
      lastUpstream = props.value;
      lastFmt = currentFmt;
      setDraft(formatByte(props.value, currentFmt));
    }
    return draft();
  };

  const commit = () => {
    const parsed = parseByte(draft(), fmt());
    if (parsed === null) {
      // Invalid in the current format — snap back to the upstream value.
      setDraft(formatByte(props.value, fmt()));
      return;
    }
    if (parsed !== props.value) props.onCommit(parsed);
    setDraft(formatByte(parsed, fmt())); // canonical re-render
  };

  return (
    <input
      class="byte-cell"
      classList={{
        compact: props.compact,
        modified: props.modified,
        duplicate: props.duplicate,
      }}
      title={props.title}
      type="text"
      // Cap input length to the format's max display width. Hex=2, dec=3,
      // ASCII=4 (\xNN). A literal printable char fits in 1; the cap is
      // for the worst-case escape representation.
      maxLength={byteDisplayWidth(fmt())}
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
          setDraft(formatByte(props.value, fmt()));
          e.currentTarget.blur();
        }
      }}
    />
  );
};
