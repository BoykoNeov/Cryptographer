/**
 * PKCS#7 padding (RFC 5652 §6.3). Generic block-cipher padding scheme:
 * appends N bytes of value N where N = blockSize - (input.length % blockSize).
 *
 * Property worth memorizing: PKCS#7 ALWAYS adds at least one byte. When the
 * raw input is already a clean block multiple, it appends a full extra block
 * of `blockSize` repeated. That makes the unpad direction unambiguous — the
 * last byte is always the pad length — at the cost of never being a no-op.
 *
 * Generic: parametrize on `blockSize` and this step drops into any block
 * cipher (DES/3DES → 8, AES → 16, Twofish/Serpent → 16, Speck → variant-
 * dependent). It does NOT apply to stream ciphers (XOR-keystream, no
 * blocks) or RSA (uses its own padding sized to the modulus — PKCS#1 v1.5
 * or OAEP).
 *
 * In the Cryptographer's single-block scope, the UI layer caps raw input at
 * `blockSize - 1` so the padded output stays in one block. Multi-block
 * support arrives with cipher modes (ECB/CBC/CTR/GCM) in a future change.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// Port-native `PortedExecutor` (Slice 5.2 — universal-port Phase 5): the bytes
// to pad arrive on the `state` input port and the padded bytes leave on the
// `state` output port. The runtime wires both via meta.stateInputPort /
// stateOutputPort, so the linear inspector still reads stateBefore/stateAfter
// from these ports. The frame renders in PortFlowView (it is a port-native
// frame), matching SHA-256's already-shipped pad rendering.
export const pkcs7Pad: PortedExecutor = (inputs, params, _ctx) => {
  const bytes = inputs.get("state");
  if (!(bytes instanceof Uint8Array)) {
    throw new Error("pkcs7-pad: 'state' input port must carry the bytes to pad");
  }
  const blockSize = readBlockSize(params);
  const inputLen = bytes.length;
  // PKCS#7: pad length N is in [1, blockSize]. When input is already a
  // block multiple, N == blockSize (a full extra block of `blockSize`).
  const padLen = blockSize - (inputLen % blockSize);
  const out = new Uint8Array(inputLen + padLen);
  out.set(bytes, 0);
  out.fill(padLen, inputLen);
  return new Map([["state", out]]);
};

export const pkcs7PadDoc: StepDocumentation = {
  name: "PKCS#7 Pad",
  summary: "Append N bytes of value N until the input is a whole number of blocks.",
  detail: `## PKCS#7 Padding

Block ciphers like AES operate on fixed-size blocks (16 bytes for AES). When
the message is shorter than a block, or not a whole number of blocks long,
we need to **pad** it before encryption. PKCS#7 is the canonical scheme.

**Algorithm:** compute \`N = blockSize - (input.length % blockSize)\`, then
append \`N\` copies of the byte \`N\` to the end of the input. \`N\` is
always in \`[1, blockSize]\` — even when the input is already a clean block
multiple, we add a full extra block of \`blockSize\`. That guarantee makes
the reverse direction unambiguous: the last byte of the padded message is
always the pad length, so unpad can strip it without ambiguity.

**Example** (blockSize = 16, input = \`apple\` = 5 bytes):

\`\`\`
input:    61 70 70 6c 65
padded:   61 70 70 6c 65 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b
                          └── 11 copies of 0x0b (= 11) ──┘
\`\`\`

**Reusable across block ciphers.** Parametrize on \`blockSize\` and the same
step drops into DES/3DES (8), AES (16), Twofish/Serpent (16), Speck (variable).
Does **not** apply to stream ciphers (no blocks) or RSA (uses PKCS#1 v1.5
or OAEP, sized to the modulus).

**Reference:** RFC 5652 §6.3 — Cryptographic Message Syntax, Content
Encryption Process. Originally specified in PKCS #7 (RSA Labs, 1993);
identical to PKCS #5 padding which is just PKCS#7 fixed at blockSize=8.`,
  params: new Map([
    [
      "blockSize",
      "Cipher block size in bytes. AES uses 16; DES/3DES use 8. Must be 1..255 so a single byte can encode the pad length.",
    ],
  ]),
  references: ["RFC 5652 §6.3", "PKCS #7 v1.5 (RSA Labs, 1993)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.3) ───────────────
// PKCS#7 pad is a pure bytes→bytes transform with no aux. The cleanest
// possible lift batch under the ported contract:
//   • One named state input port ("state") + one named state output port
//     ("state"). Both layout "raw" (the inspector renders as flat bytes,
//     not as a 4×4 matrix). byteLength ABSENT on both sides: pad output
//     is variable-length (input.length + N where N depends on input
//     length mod blockSize), so a fixed-length contract would be a lie.
//   • `auxReadPorts` / `auxWritePorts` undefined — no aux traffic at all.
//
// Slice 1.3 also defers `load-block`, `store-block`, `split-blocks`,
// `concat-blocks`, and `compute-block-count` for two separate reasons —
// see `docs/plans/universal-port-phase-1-slices.md` Slice 1.3 section.

export const pkcs7PadMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

/**
 * Declared port surface. Single `state` port in + single `state` port out,
 * `byteLength` absent on both (padding output length is a function of
 * input length mod blockSize, not a fixed contract value).
 */
export const pkcs7PadPortContract: PortContract = {
  inputs: new Map([["state", { layout: "raw" }]]),
  outputs: new Map([["state", { layout: "raw" }]]),
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("pkcs7-pad requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1 || bs > 255) {
    throw new Error("pkcs7-pad: blockSize must be an integer in [1, 255]");
  }
  return bs;
};
