/**
 * Zero padding (ISO/IEC 9797-1 padding method 1, sometimes "null padding").
 * Appends N bytes of value 0x00 where N = (blockSize - input.length) mod blockSize.
 *
 * Distinguishing property vs. PKCS#7: zero-pad CAN be a no-op. When the
 * input is already a clean block multiple (length == blockSize in single-
 * block scope), N == 0 and we add nothing. That's the "lazy" form of zero-
 * pad you see in older systems — simpler than PKCS#7, but with two real
 * costs:
 *
 *   1. The inverse direction (zero-unpad) is **ambiguous and lossy**. If
 *      the original plaintext ended in 0x00 bytes, those are
 *      indistinguishable from padding and get stripped. PKCS#7 doesn't
 *      have this problem because the last byte is always the pad length.
 *
 *   2. When input is exactly blockSize bytes, the boundary between data
 *      and padding (zero bytes!) is invisible. Some implementations work
 *      around this by always adding a full block when aligned — that's a
 *      different convention; we don't follow it here. Stick to the
 *      canonical formula.
 *
 * Educational point: zero-pad is the "cheap" choice that bit you when your
 * data happens to end in 0x00. PKCS#7 fixes that by encoding the pad length
 * in the bytes themselves. ISO 7816-4 fixes it by marking the boundary with
 * a 0x80 sentinel.
 *
 * Generic over blockSize, same as PKCS#7 — drops into DES/3DES (8) or
 * Speck (variant-dependent) by parameter, not by code change.
 *
 * In single-block scope, the UI caps input at [1, blockSize]. We disallow
 * length 0 because the canonical formula gives N=0 there, producing a 0-
 * byte BytesState that fails load-block downstream. (Some implementations
 * special-case empty input to a full block of zeros; we don't, to keep the
 * formula uniform.)
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";

export const zeroPad: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("zero-pad expects bytes state");
  }
  const blockSize = readBlockSize(params);
  const inputLen = state.bytes.length;
  // Canonical zero-pad: N = (blockSize - len) mod blockSize. When input is
  // already aligned, N == 0 (no padding added). That's the property that
  // makes zero-pad ambiguous on inverse — different from PKCS#7's "always
  // adds at least one byte" guarantee.
  const padLen = (blockSize - (inputLen % blockSize)) % blockSize;
  const out = new Uint8Array(inputLen + padLen);
  out.set(state.bytes, 0);
  // Uint8Array is zero-initialized — explicit fill not needed, but doing
  // it makes the intent unmistakable to readers.
  out.fill(0x00, inputLen);
  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const zeroPadDoc: StepDocumentation = {
  name: "Zero Pad",
  summary:
    "Append 0x00 bytes until the input is a whole number of blocks. No-op when already aligned.",
  detail: `## Zero Padding

The simplest block-cipher padding scheme: append \`N\` bytes of \`0x00\`
where \`N = (blockSize - input.length) mod blockSize\`. If the input is
already a clean block multiple, \`N\` is **zero** — no bytes are added.

**Example** (blockSize = 16, input = \`apple\` = 5 bytes):

\`\`\`
input:    61 70 70 6c 65
padded:   61 70 70 6c 65 00 00 00 00 00 00 00 00 00 00 00
                          └── 11 copies of 0x00 ──┘
\`\`\`

**Costs vs. PKCS#7:**

1. **Lossy inverse.** \`zero-unpad\` strips trailing \`0x00\` bytes — if
   your original plaintext ended in \`0x00\`, those bytes are
   indistinguishable from padding and get eaten. PKCS#7 avoids this by
   making the last byte always equal the pad length.

2. **Ambiguous on aligned inputs.** When input is exactly \`blockSize\`
   bytes, no padding is added — so the inverse can't even tell whether
   *any* trailing zeros are padding or original data. Some implementations
   work around this by always appending a full block when aligned; that's
   a different convention and not followed here.

**When you'd see it in real code.** Mostly older protocols that predate
PKCS#7's wide adoption, or systems where the plaintext format is known
never to end in \`0x00\` (e.g. UTF-8 text without trailing nulls,
length-prefixed records). Modern code uses PKCS#7 or, better,
authenticated encryption (AES-GCM, ChaCha20-Poly1305) which sidesteps
padding entirely.

**Reusable across block ciphers.** Same generalization story as PKCS#7 —
parametrize on \`blockSize\` and the same step drops into DES/3DES, AES,
Twofish/Serpent, etc.

**Reference:** ISO/IEC 9797-1 padding method 1.`,
  params: new Map([
    ["blockSize", "Cipher block size in bytes. AES uses 16; DES/3DES use 8. Must be 1..255."],
  ]),
  references: ["ISO/IEC 9797-1 §6.3.1 (padding method 1)"],
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("zero-pad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("zero-pad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
