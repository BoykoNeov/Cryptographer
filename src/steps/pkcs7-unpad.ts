/**
 * Inverse of pkcs7-pad. Reads the final byte N, validates that the trailing
 * N bytes all equal N, then strips them. Throws (loudly) on malformed
 * padding — this is by design: when the user edits the ciphertext mid-trace
 * and breaks the padding, we WANT them to see the failure. That's a real
 * cryptographic property worth teaching, not a UX glitch to mask.
 *
 * Generic over blockSize, like pkcs7-pad. Same reusability story: works
 * for any block cipher, doesn't apply to stream/RSA.
 *
 * Subtle: a malicious validator could leak timing info via early-exit on
 * mismatch (this is the "padding oracle" attack family). Educational tool
 * — we don't bother with constant-time checks. Production crypto would
 * either avoid PKCS#7 (use authenticated modes like GCM) or carefully time
 * the validation.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";

export const pkcs7Unpad: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("pkcs7-unpad expects bytes state");
  }
  const blockSize = readBlockSize(params);
  const len = state.bytes.length;
  if (len === 0) {
    throw new Error("pkcs7-unpad: input is empty (cannot read pad length)");
  }
  if (len % blockSize !== 0) {
    throw new Error(`pkcs7-unpad: input length ${len} is not a multiple of blockSize ${blockSize}`);
  }
  const padLen = state.bytes[len - 1] ?? 0;
  if (padLen < 1 || padLen > blockSize) {
    throw new Error(
      `pkcs7-unpad: pad length ${padLen} out of range [1, ${blockSize}] — padding is malformed`,
    );
  }
  // Every one of the trailing padLen bytes must equal padLen, by construction
  // of pkcs7-pad. If any differs, the padding has been corrupted (or the
  // ciphertext is from a different scheme). Fail loudly so the user sees it.
  for (let i = len - padLen; i < len; i++) {
    if (state.bytes[i] !== padLen) {
      throw new Error(
        `pkcs7-unpad: padding byte at offset ${i} is ${state.bytes[i]}, expected ${padLen}`,
      );
    }
  }
  const out = new Uint8Array(len - padLen);
  out.set(state.bytes.subarray(0, len - padLen), 0);
  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const pkcs7UnpadDoc: StepDocumentation = {
  name: "PKCS#7 Unpad",
  summary: "Strip PKCS#7 padding from the end. Throws if the padding is malformed.",
  detail: `## PKCS#7 Unpad

The reverse of \`pkcs7-pad\`. Reads the last byte \`N\`, validates that the
trailing \`N\` bytes all equal \`N\`, then drops them. \`N\` must be in
\`[1, blockSize]\` — any other value, or a mismatch in the trailing bytes,
means the padding is corrupt (or never was PKCS#7 to begin with), and we
fail loudly.

**Example** (blockSize = 16):

\`\`\`
padded:    61 70 70 6c 65 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b
                         └── last byte is 0x0b (= 11) ──┘
verify:    trailing 11 bytes all == 0x0b ✓
stripped:  61 70 70 6c 65   (← original "apple")
\`\`\`

**Why it must throw on malformed padding.** Silently truncating to a
plausible prefix would hide bugs: a swapped block, an off-by-one in the
cipher, an attacker tampering with the ciphertext — all of these break the
padding before any other symptom shows up. Failing loudly turns the padding
into a (very weak) integrity check.

**Aside on padding oracles.** Real-world AES-CBC + PKCS#7 implementations
that distinguish "wrong padding" from "right padding but wrong plaintext"
leak that distinction to an attacker, who can recover plaintexts byte-by-
byte (Vaudenay 2002). The Cryptographer is an educational tool, not a
production cipher — our unpad throws the same error message regardless,
but a real implementation should use authenticated encryption (GCM, ChaCha20-
Poly1305) instead of bare PKCS#7.

**Reference:** RFC 5652 §6.3. Same scheme as pkcs7-pad — see that step's
docs for the full reusability story.`,
  params: new Map([
    [
      "blockSize",
      "Cipher block size in bytes. Must match the block size used by pkcs7-pad. AES = 16, DES/3DES = 8.",
    ],
  ]),
  references: ["RFC 5652 §6.3", "Vaudenay 2002 (padding oracle attacks on CBC)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("pkcs7-unpad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("pkcs7-unpad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
