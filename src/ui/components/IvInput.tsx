/**
 * IV input row. Renders a one-block-wide text field in the current byte format
 * alongside a 🎲 randomize button. Visible when CBC is the active
 * cipher-mode; the App owns the conditional render.
 *
 * Internal state is a local text signal — same pattern as the key
 * input next door. The text reflects the live IV from the store but
 * stays in the field as the user types so the byte parser doesn't
 * fight them mid-edit. On blur (or pressing Enter) the value is
 * parsed: if it's a clean block's worth of bytes in the current format,
 * commit to the store; otherwise revert to the store's current bytes so
 * the field never holds garbage between runs.
 *
 * The required width arrives as a prop rather than being read from a store:
 * the IV must match the active cipher's block, and the App is what knows which
 * cipher is active. Passing it down keeps this component cipher-agnostic — it
 * renders an 8-byte field for an 8-byte-block cipher without knowing one exists.
 *
 * Format awareness: the field re-renders on byte-format changes
 * because the upstream `props.format` flips, and the local effect
 * resets the draft from the store's bytes through the new format.
 * Same byte-format-toggle preservation the input + key fields already
 * have, just scoped here.
 */

import { type ByteFormat, formatBytes, parseBytes } from "@/core/format";
import { randomizeIv, setIvBytes, useIvBytes } from "@/ui/stores/iv";
import { createEffect, createSignal } from "solid-js";

type IvInputProps = {
  readonly format: ByteFormat;
  /** The active cipher's block width — the IV must be exactly this long. */
  readonly blockByteLength: number;
};

export const IvInput = (props: IvInputProps) => {
  const ivBytes = useIvBytes();
  // Local text mirror. Initialized from the live IV via the current
  // format. The `createEffect` below resyncs whenever the upstream
  // signal moves (randomize click, store-load-from-document) or the
  // format toggle flips.
  const [draft, setDraft] = createSignal(formatBytes(ivBytes(), props.format));

  let lastSyncedBytes = ivBytes();
  let lastSyncedFormat = props.format;

  createEffect(() => {
    const bytes = ivBytes();
    const fmt = props.format;
    // Resync the draft when the store's bytes change OR the byte
    // format changes. (Both cases want the field to show the canonical
    // representation; the user's draft is discarded.)
    if (bytes !== lastSyncedBytes || fmt !== lastSyncedFormat) {
      lastSyncedBytes = bytes;
      lastSyncedFormat = fmt;
      setDraft(formatBytes(bytes, fmt));
    }
  });

  const commit = (): void => {
    const text = draft();
    let parsed: Uint8Array;
    try {
      parsed = parseBytes(text, props.format);
    } catch {
      // Unparseable in this format. Revert the draft to the store's
      // current bytes — visible "your edit was discarded" feedback.
      setDraft(formatBytes(ivBytes(), props.format));
      return;
    }
    if (parsed.length !== props.blockByteLength) {
      // Wrong length. Same recovery — revert to store. We don't show a
      // separate error label because the field reverting is already the
      // signal that the input was wrong.
      setDraft(formatBytes(ivBytes(), props.format));
      return;
    }
    setIvBytes(parsed, props.blockByteLength);
  };

  return (
    <label>
      IV ({props.format})
      <div class="iv-row">
        <input
          class="iv-input"
          value={draft()}
          onInput={(e) => setDraft(e.currentTarget.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              commit();
              e.currentTarget.blur();
            } else if (e.key === "Escape") {
              setDraft(formatBytes(ivBytes(), props.format));
              e.currentTarget.blur();
            }
          }}
          spellcheck={false}
        />
        <button
          type="button"
          class="iv-randomize-button"
          onClick={() => randomizeIv(props.blockByteLength)}
          title={`Generate a cryptographically-random ${props.blockByteLength}-byte IV`}
          aria-label="Randomize IV"
        >
          🎲
        </button>
      </div>
    </label>
  );
};
