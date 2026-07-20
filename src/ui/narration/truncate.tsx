/**
 * Truncate-to-reference narrator — the per-frame value-prose for
 * `truncate-to-reference@1`, CTR's ragged-tail trim.
 *
 * **Why this needs a narrator at all, rather than a `narrationOverride`.**
 * The sentence this step exists to say is different on the last block than on
 * every other one:
 *
 *   - full-width block  → "nothing was discarded; the block passed through whole"
 *   - the ragged tail   → "kept the first N keystream bytes and discarded the
 *                          other B−N — this is why the ciphertext is exactly as
 *                          long as the plaintext"
 *
 * That branch depends on the *values in this frame* (specifically the two port
 * widths), and `narrationOverride` is static `StepDocumentation` markdown —
 * it cannot branch, and cannot interpolate the real N and B. So the payload
 * sentence of the whole partial-block feature is only expressible here.
 *
 * **Generic, not CTR-specific.** Narration is keyed by *stepType*, and
 * `truncate-to-reference@1` is a shared primitive — so the prose must describe
 * what the step did to these bytes, not assume a cipher (the lesson recorded
 * in `project_blowfish_plan.md`). CTR is named as the motivating context,
 * which is honest: it is the only shipped user, and the "why" only lands with
 * it. Nothing here reads a cipher, a block size constant, or a spec id.
 *
 * One unit per frame — a trim is one logical operation, and a per-byte
 * disclosure on a 16-byte block would bury the one sentence that matters.
 *
 * References: NIST SP 800-38A §6.5 (CTR mode — the final partial block).
 */

import { formatBytes } from "../components/byte-row";
import type { NarrationFn, NarrationUnit } from "./registry";

export const truncateToReferenceNarration: NarrationFn = (frame) => {
  const input = frame.portInputs?.get("input");
  const reference = frame.portInputs?.get("reference");
  const output = frame.portOutputs?.get("output");
  if (input === undefined || reference === undefined || output === undefined) return null;

  // Freeze the frame's bytes once, outside `Prose` — the closure is rebuilt
  // only when the frame changes, while `fmt` propagates reactively inside.
  const inputFrozen = new Uint8Array(input);
  const outputFrozen = new Uint8Array(output);
  const discardedFrozen = new Uint8Array(input.subarray(output.length));

  const kept = outputFrozen.length;
  const full = inputFrozen.length;
  const dropped = full - kept;

  // The branch the whole feature turns on. `dropped === 0` is every block but
  // the last (and every block of a message that divides evenly).
  const isPassthrough = dropped === 0;

  const unit: NarrationUnit = {
    key: `truncate:${kept}-of-${full}`,
    label: isPassthrough
      ? `Nothing discarded — all ${full} bytes passed through`
      : `Kept the first ${kept} of ${full} bytes, discarded ${dropped}`,
    Prose: (props) =>
      isPassthrough ? (
        <div>
          <p>
            This block is already the full <strong>{full} bytes</strong> wide, so nothing was
            trimmed — the value passed through unchanged.
          </p>
          <p>Bytes: {formatBytes(outputFrozen, props.fmt)}</p>
          <p>
            The trim only does something on the <em>last</em> block of a message that ends
            mid-block. Every other block reaches this step already the right width.
          </p>
        </div>
      ) : (
        <div>
          <p>
            The message has only <strong>{kept} bytes</strong> left, but the cipher produced a full{" "}
            <strong>{full} bytes</strong> of keystream — it knows no other size. So the first{" "}
            <strong>{kept}</strong> keystream bytes were kept and the other{" "}
            <strong>{dropped}</strong> were discarded.
          </p>
          <p>
            Full keystream ({full} bytes): {formatBytes(inputFrozen, props.fmt)}
          </p>
          <p>
            Kept ({kept} bytes): {formatBytes(outputFrozen, props.fmt)}
          </p>
          <p>
            Discarded ({dropped} bytes): {formatBytes(discardedFrozen, props.fmt)}
          </p>
          <p>
            <strong>This is why the ciphertext is exactly as long as the plaintext.</strong> The
            message is only ever XORed with the keystream, never fed through the cipher — so it
            never has to be topped up to a whole block. That is what it means to say counter mode
            needs no padding, and it is the difference between a stream mode and a block mode like
            ECB or CBC.
          </p>
        </div>
      ),
  };

  return [unit];
};
