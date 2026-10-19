/**
 * ML-DSA-44 Verify: which message is being checked, and the opt-in button that
 * copies in the message Sign last signed (ML-DSA P4,
 * `docs/plans/refactored-petting-tide.md`).
 *
 * Verification has two things to check against each other, the signature and
 * the message, but a spec has one input. The signature takes the input field
 * (it has a fixed width; flipping from Sign carries it over), and the message is
 * an editable `constant-load@1` step inside the verify spec. That step is easy
 * to miss in the graph, so this row puts it beside the input field.
 *
 * The button never fires on its own. Encrypt/decrypt specs are held separately
 * and never synced automatically — editing one side and seeing what breaks is
 * the point — so this is the same kind of labelled, opt-in copy as the app's
 * cross-mode mirror buttons. Verifying a signature against a DIFFERENT message
 * and watching it fail is a lesson too: a signature is bound to its message.
 */

import { MLDSA_MESSAGE_ID } from "@/ciphers/ml-dsa-44";
import { formatBytes } from "@/core/format";
import type { StepNode } from "@/core/types";
import { Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useSignedMessage } from "../stores/forward-input";
import { editStepParams, useSpec } from "../stores/spec";

/** The verify spec's message leaf bytes, or null if the step is gone or edited away. */
const messageOf = (steps: readonly StepNode[]): Uint8Array | null => {
  const leaf = steps.find((n) => n.kind === "step" && n.id === MLDSA_MESSAGE_ID);
  if (leaf === undefined || leaf.kind !== "step") return null;
  const bytes = (leaf.params as { bytes?: unknown }).bytes;
  if (!Array.isArray(bytes) || !bytes.every((b) => Number.isInteger(b) && b >= 0 && b < 256)) {
    return null;
  }
  return new Uint8Array(bytes as number[]);
};

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

export const MlDsaVerifyMessage = () => {
  const spec = useSpec();
  const fmt = useByteFormat();
  const signed = useSignedMessage();
  const current = createMemo(() => messageOf(spec().steps));
  const canCopy = createMemo(() => {
    const s = signed();
    const c = current();
    return s !== null && c !== null && !sameBytes(s, c);
  });
  const shown = (b: Uint8Array): string => (b.length === 0 ? "(empty)" : formatBytes(b, fmt()));

  return (
    <div class="data-field ml-dsa-verify-message" data-testid="ml-dsa-verify-message">
      <span>message being verified ({fmt()})</span>
      <Show
        when={current()}
        fallback={
          <span class="muted small">The message step has been removed from this spec.</span>
        }
      >
        {(m) => <code class="ml-dsa-verify-message-bytes">{shown(m())}</code>}
      </Show>
      <button
        type="button"
        disabled={!canCopy()}
        title="Copy the message Sign last signed into this spec's message step. FIPS 204 Algorithm 8: the signature is checked against μ = H(tr ‖ M′), so it verifies only for the exact message that was signed."
        onClick={() => {
          const s = signed();
          if (s !== null) editStepParams(MLDSA_MESSAGE_ID, { bytes: [...s] });
        }}
      >
        Use the message from Sign
      </button>
      <Show when={signed() === null}>
        <span class="muted small">Sign a message first to copy it here.</span>
      </Show>
    </div>
  );
};
