/**
 * The last input each "one-way-back" public-key scheme ran FORWARD — the
 * message ML-DSA-44 signed, the random `m` ML-KEM-768 encapsulated.
 *
 * **Why this needs remembering at all.** Flipping encrypt ↔ decrypt copies the
 * current output into the input field (the mode-flip swap in `App.tsx`). For a
 * cipher that is exactly right in both directions: decrypt's output is the
 * plaintext encrypt takes. For these two schemes it is right only one way:
 *
 * - ML-DSA-44: Sign → Verify carries the signature across, correctly. Verify's
 *   output is a one-byte VERDICT, so Verify → Sign would put `01` where the
 *   message was.
 * - ML-KEM-768: encapsulate → decapsulate carries the ciphertext across,
 *   correctly. Decapsulation's output is the SHARED SECRET, so going back would
 *   put the secret in the "message m" field. It even works — any 32 bytes are a
 *   valid `m` — which is what makes it misleading: the learner sees a fresh,
 *   unrelated key exchange and no sign that their `m` was replaced.
 *
 * So going back restores what the forward direction last held instead. ML-DSA's
 * Verify additionally offers its recorded message through an opt-in button
 * ("Use the message from Sign") — the copy is never made on its own, per the
 * project's cross-mode rule.
 *
 * Keyed by algorithm so one scheme's record can never surface in the other's
 * field. Session-only, deliberately: like the input fields themselves, it is
 * not part of a saved document.
 */

import { createSignal, untrack } from "solid-js";
import type { Algorithm } from "./cipher";

/** The schemes whose inverse output is NOT something the forward direction takes. */
const RESTORES_ON_FLIP_BACK: readonly Algorithm[] = ["ml-dsa-44", "ml-kem-768"];

/**
 * True when flipping back to the forward direction should restore the recorded
 * forward input rather than copy the output. Membership over a list, so a new
 * scheme of this kind is one entry, not another `||` at every call site.
 */
export const restoresForwardInputOnFlipBack = (a: Algorithm): boolean =>
  RESTORES_ON_FLIP_BACK.includes(a);

const [inputs, setInputs] = createSignal<ReadonlyMap<Algorithm, Uint8Array>>(new Map());

/** The bytes the forward direction last held for `a`, or null if it has not run. */
export const forwardInputFor = (a: Algorithm): Uint8Array | null => inputs().get(a) ?? null;

/** The message ML-DSA-44 Sign last held — what Verify's copy button offers. */
export const useSignedMessage = () => () => forwardInputFor("ml-dsa-44");

/** Record what the forward direction's input currently holds. A copy, so later edits cannot alias it. */
export const recordForwardInput = (a: Algorithm, bytes: Uint8Array): void => {
  // Read untracked: this is called from an effect in `App.tsx`, and a tracked
  // read would subscribe that effect to the very store it writes — so every
  // write would re-run it.
  const current = untrack(inputs);
  const prev = current.get(a);
  if (prev !== undefined && prev.length === bytes.length && prev.every((b, i) => b === bytes[i])) {
    return;
  }
  const next = new Map(current);
  next.set(a, new Uint8Array(bytes));
  setInputs(next);
};

export const __resetForwardInputsForTests = (): void => {
  setInputs(new Map());
};
