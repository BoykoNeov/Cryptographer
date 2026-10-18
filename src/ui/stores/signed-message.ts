/**
 * The last message ML-DSA-44 SIGNED — what Verify's "Use the message from Sign"
 * button copies (ML-DSA P4, `docs/plans/refactored-petting-tide.md`).
 *
 * Why this needs remembering at all: Sign's input field holds the message, and
 * flipping to Verify copies the signature INTO that field (the mode-flip
 * auto-swap in `App.tsx`), so the message is gone from the screen by the time
 * Verify wants it. Verify checks its own message — an editable step in its own
 * spec — and the two directions are never synced on their own (the project's
 * cross-mode rule), so the copy is an explicit, opt-in click.
 *
 * Session-only, deliberately: like the input fields themselves, it is not part
 * of a saved document.
 */

import { createSignal } from "solid-js";

const [signedMessage, setSignedMessage] = createSignal<Uint8Array | null>(null);

/** The message Sign last held, or null if ML-DSA-44 has not been signed with. */
export const useSignedMessage = () => signedMessage;

/** Record what Sign's input currently holds. A copy, so later edits cannot alias it. */
export const recordSignedMessage = (message: Uint8Array): void => {
  const prev = signedMessage();
  if (prev !== null && prev.length === message.length && prev.every((b, i) => b === message[i])) {
    return;
  }
  setSignedMessage(new Uint8Array(message));
};

export const __resetSignedMessageForTests = (): void => {
  setSignedMessage(null);
};
