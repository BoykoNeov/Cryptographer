/**
 * Inverse of iso7816-4-pad. Walks the input from the end, skipping 0x00
 * bytes, until it reaches the 0x80 sentinel. Drops the sentinel and the
 * trailing zeros; keeps everything before.
 *
 * Throws on malformed padding — same rationale as pkcs7-unpad: a user
 * editing ciphertext mid-trace should SEE the failure. The two failure
 * modes are:
 *
 *   1. No 0x80 found in the trailing zero-run (block is all zeros, or the
 *      first non-zero from the end is something other than 0x80). The
 *      padding is corrupt or the ciphertext was never ISO 7816-4 padded.
 *
 *   2. Input length isn't a multiple of blockSize. Same shape constraint
 *      as pkcs7-unpad.
 *
 * Unambiguous, unlike zero-unpad, and slightly cleaner than pkcs7-unpad
 * (no length-byte arithmetic to validate — just find the sentinel).
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";

export const iso78164Unpad: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("iso7816-4-unpad expects bytes state");
  }
  const blockSize = readBlockSize(params);
  const len = state.bytes.length;
  if (len === 0) {
    throw new Error("iso7816-4-unpad: input is empty (cannot find sentinel)");
  }
  if (len % blockSize !== 0) {
    throw new Error(
      `iso7816-4-unpad: input length ${len} is not a multiple of blockSize ${blockSize}`,
    );
  }
  // Walk back past 0x00 bytes. The sentinel-search range is bounded by
  // blockSize: by construction, the padding occupies at most one full
  // block, so we never need to scan further. If we hit the start of the
  // buffer or scan more than blockSize bytes without finding 0x80, the
  // padding is malformed.
  let i = len - 1;
  const minScan = Math.max(0, len - blockSize);
  while (i >= minScan && state.bytes[i] === 0x00) {
    i--;
  }
  if (i < minScan || state.bytes[i] !== 0x80) {
    throw new Error(
      "iso7816-4-unpad: no 0x80 sentinel found in the trailing block — padding is malformed",
    );
  }
  const out = new Uint8Array(i);
  out.set(state.bytes.subarray(0, i), 0);
  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const iso78164UnpadDoc: StepDocumentation = {
  name: "ISO 7816-4 Unpad",
  summary: "Find the trailing 0x80 sentinel, strip it and everything after. Throws if no sentinel.",
  detail: `## ISO/IEC 7816-4 Unpad

The reverse of \`iso7816-4-pad\`. Walks from the end of the input,
skipping over \`0x00\` bytes, until the \`0x80\` sentinel is reached.
Drops the sentinel and every zero byte after it; keeps everything before.

\`\`\`
padded:    61 70 70 6c 65 80 00 00 00 00 00 00 00 00 00 00
                          └── sentinel + trailing zeros ──┘
stripped:  61 70 70 6c 65   (← original "apple")
\`\`\`

**Failure modes** (both throw, by design):

1. No \`0x80\` found in the trailing block. Either the padding is corrupt,
   the ciphertext was never ISO 7816-4 padded, or someone tampered with
   the trailing bytes. Failing loudly is the educational choice: silently
   returning a plausible prefix would hide a real cryptographic event.

2. The last block is all zeros. Same shape, different cause — sometimes
   from a buggy pad implementation that forgot the sentinel.

**Why this is cleaner than PKCS#7 unpad.** No arithmetic to validate
(PKCS#7 has to check "trailing N bytes all equal N"); just one sentinel
byte to find. The downside is one byte of structural overhead **always**
(PKCS#7 averages roughly half a byte less per message, but with worse
worst-case behavior on aligned inputs).

**Aside on padding oracles.** The same caveat as pkcs7-unpad applies: a
real-world implementation that distinguishes "bad padding" from "good
padding but wrong plaintext" leaks information to an attacker who can
recover plaintext byte by byte. The Cryptographer is educational — we
throw a single error string regardless of failure mode — but production
code should use authenticated encryption (GCM, ChaCha20-Poly1305) instead
of bare ISO 7816-4 + CBC.

**Reference:** ISO/IEC 7816-4 §5.4.1.`,
  params: new Map([
    ["blockSize", "Cipher block size in bytes. Must match the block size used by iso7816-4-pad."],
  ]),
  references: ["ISO/IEC 7816-4 §5.4.1", "Vaudenay 2002 (padding oracle attacks)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("iso7816-4-unpad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("iso7816-4-unpad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
