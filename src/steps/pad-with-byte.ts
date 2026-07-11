/**
 * Pad-with-byte — port-native padding primitive (universal-port plan
 * Phase 2 Slice 2.4, 2026-05-24).
 *
 * Generic "sentinel byte + zeros" padding scheme. Appends a single
 * `padByte` sentinel followed by enough `0x00` bytes so the output
 * length reaches `padTarget` modulo `blockSize`. The minimum amount of
 * padding is 1 byte (the sentinel itself); the maximum is `blockSize`
 * bytes when the input already sits at `padTarget`.
 *
 * **Why decomposed (not a monolithic `sha2.pad@1`).** User pick at
 * Slice 2.4 start (2026-05-24) per advisor framing: the Slice 2.3
 * Open #N3 "(b) Compositions" precedent applies — SHA-256 padding
 * decomposes into a generic byte-fill step + a length-suffix step
 * (`append-be64-length@1`). The generic primitive is reusable across
 * every Merkle–Damgård hash (SHA-224/256/384/512, MD5, RIPEMD) and
 * many older padding schemes (ISO 7816-4 with `padTarget=0`,
 * Merkle–Damgård-strengthening variants).
 *
 * **Parameterization captures the variants:**
 *
 * | Scheme                  | padByte | blockSize | padTarget |
 * | ----------------------- | ------- | --------- | --------- |
 * | SHA-256 / SHA-224 / MD5 | 0x80    | 64        | 56        |
 * | SHA-512 / SHA-384       | 0x80    | 128       | 112       |
 * | ISO 7816-4 (full-block) | 0x80    | N         | 0         |
 *
 * (Note: SHA-256's full padding pipeline = `pad-with-byte@1` THEN
 * `append-be64-length@1`. This step does the sentinel + zero fill ONLY;
 * the length suffix is a separate primitive.)
 *
 * **Math (the padding-length formula):**
 *
 * ```
 *   pos     = inputLen % blockSize
 *   padLen  = ((padTarget - pos - 1) mod blockSize) + 1
 *   outLen  = inputLen + padLen
 * ```
 *
 * The `+ 1` accounts for the sentinel byte itself; the modular
 * subtraction picks the smallest non-negative zero-count that lands the
 * output at `padTarget` modulo `blockSize`. JavaScript's `%` returns
 * negative for negative operands, so the formula uses
 * `((x % n) + n) % n` to compute the true mathematical modulus.
 *
 * **Verification for SHA-256 padding** (`padByte=0x80, blockSize=64,
 * padTarget=56`):
 *
 * | inputLen | padLen | outLen | notes                          |
 * | -------- | ------ | ------ | ------------------------------ |
 * |        0 |     56 |     56 | sentinel + 55 zeros            |
 * |        3 |     53 |     56 | "abc" KAT, FIPS 180-4 §A.1     |
 * |       55 |      1 |     56 | sentinel only, no zero padding |
 * |       56 |     64 |    120 | sentinel + 63 zeros, full block|
 * |      120 |     64 |    184 | wraps at next block boundary   |
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. Same posture as `rotate-bits-right.ts` (Slice
 * 2.1a) and the rest of the port-native vocabulary. PortContract uses
 * polymorphic `byteLength` on both ports because output length depends
 * on run-time input length, not on params alone (the formula is
 * computable in advance only if input length is also known — which it
 * isn't at spec-edit time).
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly padByte: number;
  readonly blockSize: number;
  readonly padTarget: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("pad-with-byte: params must be an object");
  }
  const p = params as Record<string, Json>;
  const padByte = p.padByte;
  const blockSize = p.blockSize;
  const padTarget = p.padTarget;
  if (typeof padByte !== "number" || !Number.isInteger(padByte) || padByte < 0 || padByte > 0xff) {
    throw new Error("pad-with-byte: params.padByte must be an integer in [0, 255]");
  }
  if (typeof blockSize !== "number" || !Number.isInteger(blockSize) || blockSize < 1) {
    throw new Error("pad-with-byte: params.blockSize must be a positive integer");
  }
  if (
    typeof padTarget !== "number" ||
    !Number.isInteger(padTarget) ||
    padTarget < 0 ||
    padTarget >= blockSize
  ) {
    throw new Error(
      `pad-with-byte: params.padTarget must be an integer in [0, blockSize) (got ${String(padTarget)}, blockSize=${String(blockSize)})`,
    );
  }
  return { padByte, blockSize, padTarget };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Polymorphic byteLength on both ports — input length is run-time data;
 * output length depends on it via the padding-length formula. The
 * consumer's wiring determines the actual input length, and the
 * executor computes the corresponding output length each call.
 */
export const padWithBytePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const padWithByte: PortedExecutor = (inputs, params, _ctx) => {
  const { padByte, blockSize, padTarget } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("pad-with-byte: missing required input port 'input'");
  }

  const inputLen = inputBytes.length;
  const pos = inputLen % blockSize;
  // True mathematical modulo: JavaScript's `%` returns a negative value
  // when the dividend is negative (e.g., `-3 % 5 === -3`), but we need
  // the math result in `[0, blockSize)`. The `((x % n) + n) % n` idiom
  // is the standard JS workaround.
  const zerosAfterSentinel = (((padTarget - pos - 1) % blockSize) + blockSize) % blockSize;
  const padLen = zerosAfterSentinel + 1; // +1 for the sentinel itself

  const out = new Uint8Array(inputLen + padLen);
  out.set(inputBytes, 0);
  out[inputLen] = padByte;
  // The remaining `zerosAfterSentinel` bytes stay at 0x00 by
  // Uint8Array's default zero-initialization. No explicit fill needed.

  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const padWithByteDoc: StepDocumentation = {
  name: "Pad with sentinel byte",
  summary:
    "Append a sentinel byte, then zero bytes until output length reaches `padTarget` modulo `blockSize`. Always adds ≥1 byte.",
  detail: `# Pad with sentinel byte

A generic Merkle–Damgård-family padding primitive. Appends a single
sentinel byte \`padByte\` (typically \`0x80\`) followed by enough
\`0x00\` bytes so that the output length lands at \`padTarget\` modulo
\`blockSize\`.

## Math

\`\`\`
pos       = inputLen mod blockSize
padLen    = ((padTarget - pos - 1) mod blockSize) + 1
outputLen = inputLen + padLen
\`\`\`

The minimum amount of padding is **1 byte** (the sentinel itself); the
maximum is \`blockSize\` bytes when the input already sits at
\`padTarget\`. Even an empty input gets padded — the sentinel is
always present.

## Where it fits

| Scheme                  | \`padByte\` | \`blockSize\` | \`padTarget\` |
| ----------------------- | ----------- | ------------- | ------------- |
| SHA-256 / SHA-224 / MD5 |     \`0x80\` |          \`64\` |          \`56\` |
| SHA-512 / SHA-384       |     \`0x80\` |         \`128\` |         \`112\` |
| ISO 7816-4 (full-block) |     \`0x80\` |           \`N\` |           \`0\` |

For SHA-256 specifically, the padded output is **not** yet a complete
SHA-256-preprocessing block — the message-length suffix must still be
appended by \`append-be64-length@1\`. The two primitives together
implement FIPS 180-4 §5.1.1.

## Example (SHA-256 padding of "abc")

\`\`\`
input:    61 62 63
output:   61 62 63 80 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
          00 00 00 00 00 00 00 00
                                  └── 56 bytes total ──┘
\`\`\`

After \`append-be64-length@1\` adds the 8-byte BE encoding of
\`24\` bits (\`= 3 bytes × 8\`), the full 64-byte SHA-256 block is
ready for the compression function.

## Where it does NOT fit

This is **not** PKCS#7 padding (which records the padding length in the pad
byte's value rather than using a sentinel) or zero-padding (which has no
sentinel and can't be unambiguously removed). Use the **PKCS#7** or
**Zero-pad** steps for those.`,
  params: new Map([
    [
      "padByte",
      "Sentinel byte appended first. Integer in [0, 255]. Typically `0x80` for SHA-2 family / ISO 7816-4.",
    ],
    [
      "blockSize",
      "Alignment block size in bytes. Positive integer. 64 for SHA-256, 128 for SHA-512.",
    ],
    [
      "padTarget",
      "Target offset within block for the output's final length. Integer in `[0, blockSize)`. 56 for SHA-256 (leaving 8 bytes for the BE64 length suffix); 0 for full-block ISO 7816-4.",
    ],
  ]),
  references: [
    "FIPS 180-4 §5.1.1 (SHA-256 preprocessing — padding scheme)",
    "ISO/IEC 7816-4 §5.4.1 (sentinel-padding origin)",
    "RFC 1321 §3.1 (MD5 padding, same shape)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract. The state-shape-contracts test skips `kind: "ported"`
  // registrations without a `legacy` field.
};
