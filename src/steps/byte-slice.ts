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
    "Pulls out one contiguous run of bytes from the input, starting at the offset you choose.",
  detail: `# Byte Slice

Pulls out a single contiguous run of bytes from its input — the \`length\`
bytes starting at position \`offset\`, counting from zero.

## Math

For input \`a\`:

\`\`\`
output = a[offset .. offset + length]
\`\`\`

The slice must lie inside the input, i.e. \`offset + length\` cannot run past
the input's end.

## Where it fits

- **Selecting one round's constant or key from a table** — where a cipher or
  hash keeps a long table of per-round values, this pulls out the few bytes
  for the current round. SHA-256, for instance, reads its round constant for
  round *t* from a 256-byte table by slicing 4 bytes at offset \`4 × t\`.
- **Separating a combined value into a wanted piece** — e.g. taking a nonce
  or a header off the front of a larger input.

To cut an input into *several* pieces at once (rather than pull out one), use
**Split Bytes**. Byte Slice is the tool when you want a single range that may
start anywhere.`,
  params: new Map([
    ["sourceByteLength", "The length of the incoming value, in bytes."],
    [
      "offset",
      "Where the slice starts, counting bytes from zero. The slice must stay within the input.",
    ],
    ["length", "How many bytes to pull out."],
  ]),
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
