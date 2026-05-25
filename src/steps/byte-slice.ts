/**
 * byte-slice — port-native byte-range extraction primitive (universal-port
 * plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * Reads one input port `input` (byteLength = `params.sourceByteLength`)
 * and emits one output port `output` (byteLength = `params.length`)
 * carrying the contiguous range `input[offset .. offset + length]`.
 *
 * **Why this primitive exists.** Phase 2's port-native chain can compose
 * N-way concat / N-way xor / N-way add over fixed-size word streams, but
 * had no primitive for extracting a contiguous sub-range from a larger
 * byte stream at an arbitrary offset. SHA-256's decomposed compression
 * rounds need this to extract the 4-byte `K_t` (round constant for round
 * `t`) from the 256-byte K-table at offset `4 * roundIndex`, and the
 * 4-byte `W_t` from the 256-byte W-table at the same offset. Under the
 * user-picked Slice 2.6d topology (Q1 = (b) "W in aux entirely"),
 * `byte-slice@1` is the runtime workhorse for per-round K_t / W_t reads.
 *
 * **Pair with `split-bytes@1`.** Both extract sub-ranges, but at
 * different granularities:
 *   - `byte-slice@1` — single sub-range at an arbitrary offset. Use when
 *     the consumer wants ONE slice from a long buffer at a known offset
 *     (e.g., K_t from K, W_t from W).
 *   - `split-bytes@1` — N symmetric sub-ranges starting at offset 0. Use
 *     when extracting N adjacent words from a packed structure (e.g., the
 *     8 working variables a..h from a 32-byte working_vars buffer).
 *
 * User pick Q-2.6c-1 (2026-05-25): ship BOTH primitives. Each has a use
 * case the other handles awkwardly — `split-bytes` for symmetric extraction
 * (the working-vars case), `byte-slice` for arbitrary-offset extraction
 * (the K_t / W_t case). Rejected alternatives: (a) split-only forces
 * awkward width arrays for single-slice use cases; (b) byte-slice-only
 * loses the concat/split symmetry and adds ~448 compression frames.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract uses function form on both sides
 * because `byteLength` depends on params (per the Slice 2.1b rule
 * "function form when varies on THIS side"). Layout `"raw"` on both
 * ports — byte-slice operates on byte-flat values.
 *
 * **Param validation is strict.** Unlike padding primitives (which
 * gracefully handle authoring-state mismatches), byte-slice throws on
 * any invalid offset/length combination at run-time. The visual editor
 * uses the PortContract's declared byteLengths to surface coercion
 * warnings on misconfigured leaves.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly sourceByteLength: number;
  readonly offset: number;
  readonly length: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("byte-slice: params must be an object");
  }
  const p = params as Record<string, Json>;
  const sourceByteLength = p.sourceByteLength;
  if (
    typeof sourceByteLength !== "number" ||
    !Number.isInteger(sourceByteLength) ||
    sourceByteLength < 1
  ) {
    throw new Error(
      `byte-slice: params.sourceByteLength must be a positive integer (≥ 1), got ${String(sourceByteLength)}`,
    );
  }
  const offset = p.offset;
  if (typeof offset !== "number" || !Number.isInteger(offset) || offset < 0) {
    throw new Error(
      `byte-slice: params.offset must be a non-negative integer (≥ 0), got ${String(offset)}`,
    );
  }
  const length = p.length;
  if (typeof length !== "number" || !Number.isInteger(length) || length < 1) {
    throw new Error(
      `byte-slice: params.length must be a positive integer (≥ 1), got ${String(length)}`,
    );
  }
  if (offset + length > sourceByteLength) {
    throw new Error(
      `byte-slice: offset + length (${offset} + ${length} = ${offset + length}) exceeds sourceByteLength (${sourceByteLength})`,
    );
  }
  return { sourceByteLength, offset, length };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * One input port `input` (byteLength = params.sourceByteLength) and one
 * output port `output` (byteLength = params.length). Both layouts `"raw"`.
 * Function form on both sides because byteLength varies with params on
 * each side independently (the input side could carry 32 bytes for
 * extracting `a`, or 256 bytes for extracting `K_t` — declared exactly
 * per leaf instance).
 */
export const byteSlicePortContract: PortContract = {
  inputs: (params: Json) => {
    const { sourceByteLength } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength: sourceByteLength };
    return new Map([["input", shape]]);
  },
  outputs: (params: Json) => {
    const { length } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength: length };
    return new Map([["output", shape]]);
  },
};

export const byteSlice: PortedExecutor = (inputs, params, _ctx) => {
  const { offset, length } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("byte-slice: missing required input port 'input'");
  }
  // The runtime's port-length coercion (Slice 1.12) has already aligned
  // inputBytes.length to params.sourceByteLength when they differed, so
  // the offset+length range is guaranteed in-bounds by the readParams
  // validation. Fresh Uint8Array — outputs own their buffers (every
  // port-native primitive's convention).
  const out = new Uint8Array(length);
  out.set(inputBytes.subarray(offset, offset + length));
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const byteSliceDoc: StepDocumentation = {
  name: "Byte Slice",
  summary:
    "Extract a contiguous byte range from the input port. One in, one out; output length = params.length.",
  detail: `# Byte Slice

Reads bytes from the \`input\` port and emits a contiguous sub-range
\`input[offset .. offset + length]\` on the \`output\` port. The
input's declared byteLength is \`params.sourceByteLength\`; the output's
declared byteLength is \`params.length\`.

## Math

For input \`a\` of length \`L\`:

\`\`\`
output = a[offset .. offset + length]    (length: params.length)
\`\`\`

Validation:
- \`0 ≤ offset\`
- \`length ≥ 1\`
- \`offset + length ≤ sourceByteLength\`

Throws on any violation at param-validation time (before the executor
runs).

## Where it fits

- **SHA-256 K_t extraction.** Each compression round reads the 256-byte
  K-table via \`aux-load-bytes@1\`, then a \`byte-slice@1\` with
  \`params: { sourceByteLength: 256, offset: 4*roundIndex, length: 4 }\`
  extracts \`K_t\`.
- **SHA-256 W_t extraction.** Under user pick Q1 = (b) (W in aux), same
  pattern as K_t but reading from \`aux["W"]\`.
- **HMAC inner/outer key padding.** Extracting the leading 64-byte block
  from a hashed key for HMAC's ipad/opad XOR.
- **AEAD nonce vs. ciphertext split.** Extracting the nonce from a
  composite AEAD input (when AEAD ships).

## Pair with \`split-bytes@1\`

For symmetric N-way extraction starting at offset 0 (e.g., extracting 8
× 4-byte working variables from a 32-byte working_vars buffer), prefer
\`split-bytes@1\` — it emits N outputs in one leaf instead of N separate
byte-slice instances.

## Authoring shape

\`\`\`json
{
  "kind": "step",
  "id": "round.5.K_t",
  "type": "byte-slice@1",
  "params": { "sourceByteLength": 256, "offset": 20, "length": 4 },
  "portInputs": {
    "input": { "node": "fetch-K", "port": "output" }
  }
}
\`\`\`

This leaf extracts the 4 bytes at offset 20–23 from the K-table
(equivalent to \`K_5\` in big-endian word form).

## Errors

- Throws if \`params.sourceByteLength\` is missing, not an integer, or < 1.
- Throws if \`params.offset\` is missing, not a non-negative integer.
- Throws if \`params.length\` is missing, not an integer, or < 1.
- Throws if \`offset + length > sourceByteLength\`.
- Throws at run-time if the \`input\` port is missing.

## Phase status

Shipped in Slice 2.6d of the universal-port-dataflow plan as the
**second of three** new primitives. First consumer: the decomposed
SHA-256 spec's per-round \`K_t\` and (under user pick Q1 = (b)) \`W_t\`
reads.`,
  params: new Map([
    [
      "sourceByteLength",
      "Declared length of the input port. Positive integer (≥ 1). Drives the input PortContract's byteLength.",
    ],
    [
      "offset",
      "Starting byte offset into the input. Non-negative integer; must satisfy offset + length ≤ sourceByteLength.",
    ],
    [
      "length",
      "Number of bytes to emit on the output port. Positive integer (≥ 1). Drives the output PortContract's byteLength.",
    ],
  ]),
  references: [
    "docs/plans/universal-port-phase-2-slices.md (Slice 2.6c design D.2 + Slice 2.6d ship)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
