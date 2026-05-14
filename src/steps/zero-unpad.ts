/**
 * Inverse of zero-pad. Strips trailing 0x00 bytes from the input.
 *
 * **Lossy by design.** Any 0x00 bytes at the end of the original plaintext
 * are indistinguishable from padding and will be stripped. Documented at
 * length in zero-pad.ts — this is the price of zero-pad's simplicity vs.
 * PKCS#7. For an educational tool, the lossiness is itself the lesson:
 * "see what happens when the user encodes 'apple\\x00\\x00' with zero-pad
 * and gets back 'apple'."
 *
 * Unlike pkcs7-unpad, this step does NOT throw on "malformed" padding —
 * there's no malformed state to detect. Empty trailing zeros are the
 * happy path. The only failure mode is a block that's all 0x00, which
 * unpads to an empty BytesState — odd but not invalid.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";

export const zeroUnpad: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("zero-unpad expects bytes state");
  }
  const blockSize = readBlockSize(params);
  const len = state.bytes.length;
  if (len === 0) {
    throw new Error("zero-unpad: input is empty");
  }
  if (len % blockSize !== 0) {
    throw new Error(`zero-unpad: input length ${len} is not a multiple of blockSize ${blockSize}`);
  }
  // Walk backwards from the end, dropping every 0x00 byte. If the entire
  // block is zeros, we end with `end == 0` (empty result) — that's
  // acceptable; the runtime will render it as a zero-byte BytesState and
  // the user can see the lossiness directly.
  let end = len;
  while (end > 0 && state.bytes[end - 1] === 0x00) {
    end--;
  }
  const out = new Uint8Array(end);
  out.set(state.bytes.subarray(0, end), 0);
  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const zeroUnpadDoc: StepDocumentation = {
  name: "Zero Unpad",
  summary: "Strip trailing 0x00 bytes. Lossy: original trailing zeros are also removed.",
  detail: `## Zero Unpad

The reverse of \`zero-pad\`. Walks the input from the end, dropping every
\`0x00\` byte until a non-zero byte is reached.

\`\`\`
padded:     61 70 70 6c 65 00 00 00 00 00 00 00 00 00 00 00
                           └── trailing zeros stripped ──┘
stripped:   61 70 70 6c 65   (← original "apple")
\`\`\`

**Lossy.** If your original plaintext ended in one or more \`0x00\` bytes,
they are indistinguishable from padding and will be stripped along with
the real padding. This is the canonical weakness of zero-pad: PKCS#7
encodes the pad length in the bytes themselves and so can be unambiguous;
zero-pad can't.

Educational worked example (blockSize = 16):

\`\`\`
original: "hi\\x00"       (3 bytes: h, i, NUL)
padded:   68 69 00 00 00 00 00 00 00 00 00 00 00 00 00 00
unpadded: 68 69           ← "hi"   ❗ trailing NUL was eaten
\`\`\`

**No malformed state to detect.** Unlike PKCS#7, zero-unpad has nothing to
validate — every trailing-zero sequence is by definition "valid" padding,
because that's all zero-pad emits. The trade-off is that we can't catch
ciphertext tampering at the unpad layer; that responsibility moves
entirely to a separate MAC or authenticated encryption mode (AES-GCM).

**Reference:** ISO/IEC 9797-1 padding method 1. See the \`zero-pad\` step
docs for the full lossiness discussion.`,
  params: new Map([
    ["blockSize", "Cipher block size in bytes. Must match the block size used by zero-pad."],
  ]),
  references: ["ISO/IEC 9797-1 §6.3.1 (padding method 1)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("zero-unpad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("zero-unpad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
