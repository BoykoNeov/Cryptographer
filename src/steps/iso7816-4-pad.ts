/**
 * ISO/IEC 7816-4 padding. Appends a single 0x80 byte, then 0x00 bytes to
 * fill the remaining block:
 *
 *   pad = 0x80 followed by (N - 1) zero bytes
 *   where N = blockSize - (input.length % blockSize), so N ∈ [1, blockSize]
 *
 * Like PKCS#7, **always adds at least one byte** — the 0x80 sentinel. When
 * input is already a block multiple, N == blockSize and a full extra block
 * is appended (0x80 + (blockSize - 1) zeros). The UI's single-block scope
 * caps input at blockSize - 1 to avoid that case.
 *
 * The 0x80 sentinel (one '1' bit followed by zeros, viewed at the bit
 * level — originally a bit-padding scheme made byte-aligned) makes the
 * inverse unambiguous: find the last 0x80, everything after it is padding,
 * everything before is data. No length-byte trick is needed.
 *
 * **Educational contrast with the other schemes:**
 *   - PKCS#7: pad byte VALUE encodes the pad length. Unambiguous + redundant.
 *   - Zero-pad: pad byte VALUE is always 0x00. Ambiguous on inverse.
 *   - ISO 7816-4: pad byte VALUE is a SENTINEL (0x80) followed by zeros.
 *     Unambiguous, no redundancy — only one byte of "wasted" structural
 *     information per padded message.
 *
 * Originally from smart-card communication (ISO/IEC 7816-4 §5.4.1), which is
 * where "7816" comes from. The padding scheme is generic and reused widely
 * outside that context (TLS 1.0 MAC padding, some authenticated-encryption
 * constructions).
 *
 * Generic over blockSize, like the other padding steps.
 */

import type {
  BytesState,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const iso78164Pad: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("iso7816-4-pad expects bytes state");
  }
  const blockSize = readBlockSize(params);
  const inputLen = state.bytes.length;
  // ISO 7816-4 always adds at least one byte (the 0x80 sentinel). Same N
  // formula as PKCS#7: N ∈ [1, blockSize].
  const padLen = blockSize - (inputLen % blockSize);
  const out = new Uint8Array(inputLen + padLen);
  out.set(state.bytes, 0);
  out[inputLen] = 0x80; // sentinel byte
  // The remaining (padLen - 1) bytes stay at their default 0x00. No fill
  // needed (Uint8Array zero-initializes), but if the buffer were ever
  // changed to a SharedArrayBuffer this would be the line to revisit.
  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const iso78164PadDoc: StepDocumentation = {
  name: "ISO 7816-4 Pad",
  summary: "Append a 0x80 sentinel followed by 0x00 bytes to fill the block. Always adds ≥1 byte.",
  detail: `## ISO/IEC 7816-4 Padding

A "sentinel + zeros" scheme: append the byte \`0x80\` followed by enough
\`0x00\` bytes to reach the next block boundary. The pad length is
\`N = blockSize - (input.length mod blockSize)\`, always in \`[1, blockSize]\`
— like PKCS#7, this scheme **always adds at least one byte** (the
sentinel itself), even when the input is already block-aligned.

**Example** (blockSize = 16, input = \`apple\` = 5 bytes):

\`\`\`
input:    61 70 70 6c 65
padded:   61 70 70 6c 65 80 00 00 00 00 00 00 00 00 00 00
                          └── 0x80 sentinel + 10 zeros ──┘
\`\`\`

**Why 0x80?** Viewed at the bit level, this scheme is "append the bit
\`1\` followed by enough \`0\` bits to fill the block." On byte-aligned
data, \`10000000\` in binary is \`0x80\` in hex. The byte after the
sentinel down to the end of the block is all zeros, so the boundary
between original data and padding is unambiguous — the inverse just
walks from the end past zeros until it hits the \`0x80\`.

**Three padding schemes side-by-side**, encoding the same fact "where
does the original data end":

| Scheme       | How the boundary is marked              |
|--------------|------------------------------------------|
| PKCS#7       | Trailing bytes all equal the pad length |
| Zero-pad     | Not marked at all (lossy on inverse)    |
| ISO 7816-4   | A \`0x80\` byte followed by zero bytes  |

**Real-world use.** Originated in smart-card I/O (ISO/IEC 7816-4 §5.4.1)
for short APDU command padding. Also used by TLS 1.0/1.1 MAC padding,
the AES-CMAC subkey derivation, and some ZIP encryption variants. Drop-in
replacement for PKCS#7 in most contexts where determinism matters.

**Reusable across block ciphers** by parameter, same as the other schemes.

**Reference:** ISO/IEC 7816-4 §5.4.1 — Smart Card Padding.`,
  params: new Map([
    ["blockSize", "Cipher block size in bytes. AES uses 16; DES/3DES use 8. Must be 1..255."],
  ]),
  references: ["ISO/IEC 7816-4 §5.4.1", "ISO/IEC 9797-1 padding method 2"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.3) ───────────────
// ISO 7816-4 pad: pure bytes→bytes, no aux. Single state port each side,
// layout "raw", `byteLength` absent (input.length + N where N ∈ [1,
// blockSize] depending on input.length mod blockSize). Always adds at
// least one byte (the 0x80 sentinel) — never a passthrough no-op,
// unlike `zero-pad`.

export const iso78164PadMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const iso78164PadPortContract: PortContract = {
  inputs: new Map([["state", { layout: "raw" }]]),
  outputs: new Map([["state", { layout: "raw" }]]),
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("iso7816-4-pad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("iso7816-4-pad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
