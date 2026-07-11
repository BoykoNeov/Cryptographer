/**
 * split-bytes — port-native N-way byte-range partitioning primitive
 * (universal-port plan Phase 2 Slice 2.6d, 2026-05-25).
 *
 * Symmetric inverse of `concat@1`. Reads one input port `input`
 * (byteLength = sum of widths) and emits N output ports `output0`,
 * `output1`, …, `output{N-1}` carrying contiguous sub-ranges of widths
 * `params.widths[0]`, `params.widths[1]`, …, `params.widths[N-1]`.
 *
 * **Why this primitive exists.** SHA-256's decomposed compression rounds
 * need to extract the 8 working variables a..h from a 32-byte
 * working_vars buffer in ONE leaf instead of 8 separate `byte-slice@1`
 * leaves. The final-add step extracts H_0..H_7 from the 32-byte H-table
 * the same way. `split-bytes@1` makes the symmetric N-way case ergonomic;
 * `byte-slice@1` (its sibling primitive) handles the asymmetric
 * single-range-at-arbitrary-offset case.
 *
 * **Pair with `concat@1`.** Both share the dynamic-port-count contract
 * shape:
 *   - `concat@1` — N input ports → 1 output port. Output byteLength = sum
 *     of input byteLengths.
 *   - `split-bytes@1` — 1 input port → N output ports. Input byteLength
 *     = sum of output byteLengths.
 *
 * Output ports are named `output0`, `output1`, …, `output{N-1}`,
 * paralleling `concat@1`'s `input0`, `input1`, …, `input{N-1}`.
 *
 * **`widths` array minimum is 1 entry.** Symmetric with `concat@1`'s N≥1
 * floor. N=1 is the identity (single output equal to input) — useful
 * during incremental wiring; N=0 would have no meaningful outputs and is
 * rejected.
 *
 * Each `widths[i]` must be ≥ 1. Slice 2.6c's Q1 user pick = (b) (W in
 * aux entirely) eliminates the zero-width edge cases the original A.2
 * compression-round topology would have produced (at roundIndex = 0,
 * the "skip 4*0 = 0 bytes" slot collapsed; at roundIndex = 63, the
 * trailing "rest" slot did). Under (b), all widths are statically known
 * positive integers — no zero-width slot is ever needed in the
 * SHA-256 spec.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract uses function form on both sides —
 * input.byteLength varies with sum(widths); output port count varies
 * with widths.length. Layout `"raw"` on all ports.
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
  readonly widths: readonly number[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("split-bytes: params must be an object");
  }
  const p = params as Record<string, Json>;
  const widths = p.widths;
  if (!Array.isArray(widths)) {
    throw new Error("split-bytes: params.widths must be an array of positive integers");
  }
  if (widths.length < 1) {
    throw new Error("split-bytes: params.widths must contain at least one entry (≥ 1)");
  }
  for (let i = 0; i < widths.length; i++) {
    const w = widths[i];
    if (typeof w !== "number" || !Number.isInteger(w) || w < 1) {
      throw new Error(
        `split-bytes: params.widths[${i}] must be a positive integer (≥ 1), got ${String(w)}`,
      );
    }
  }
  return { widths: widths as readonly number[] };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Build the canonical port name for the i-th output. Exported so tests
 * and spec-builder helpers reference the same string everywhere.
 * Parallels `concatInputPortName` from `concat.ts`.
 */
export const splitBytesOutputPortName = (i: number): string => `output${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form PortContract on both sides. Input side: a single port
 * `input` whose byteLength is the sum of widths (declared exactly at
 * spec-edit time). Output side: N ports named `output0`..`output{N-1}`,
 * each declaring its own byteLength from the corresponding widths entry.
 *
 * Symmetric with `concat@1`'s contract — one is N→1, the other is 1→N.
 */
export const splitBytesPortContract: PortContract = {
  inputs: (params: Json) => {
    const { widths } = readParams(params);
    const total = widths.reduce((s, w) => s + w, 0);
    const shape: PortShape = { layout: "raw", byteLength: total };
    return new Map([["input", shape]]);
  },
  outputs: (params: Json) => {
    const { widths } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < widths.length; i++) {
      const w = widths[i] as number;
      entries.push([splitBytesOutputPortName(i), { layout: "raw", byteLength: w }]);
    }
    return new Map(entries);
  },
};

export const splitBytes: PortedExecutor = (inputs, params, _ctx) => {
  const { widths } = readParams(params);
  const inputBytes = inputs.get("input");
  if (inputBytes === undefined) {
    throw new Error("split-bytes: missing required input port 'input'");
  }
  // The runtime's port-length coercion (Slice 1.12) has already aligned
  // inputBytes.length to sum(widths) when they differed. Walk widths in
  // declaration order, slicing the running-sum offsets.
  const outputs = new Map<string, Uint8Array>();
  let offset = 0;
  for (let i = 0; i < widths.length; i++) {
    const w = widths[i] as number;
    // Fresh Uint8Array per output port — outputs own their buffers (every
    // port-native primitive's convention).
    const out = new Uint8Array(w);
    out.set(inputBytes.subarray(offset, offset + w));
    outputs.set(splitBytesOutputPortName(i), out);
    offset += w;
  }
  return outputs;
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const splitBytesDoc: StepDocumentation = {
  name: "Split Bytes",
  summary: "Cuts one byte string into several contiguous pieces of the widths you choose.",
  detail: `# Split Bytes

Cuts a single input into several contiguous pieces, laid out left to right.
It reads the \`input\` and emits N outputs — \`output0\`, \`output1\`, …,
\`output{N-1}\` — where the i-th piece is \`widths[i]\` bytes long. It is the
exact reverse of **Concat**: concat joins pieces into one value, split-bytes
cuts one value back into pieces.

## Math

For input \`a\` cut with widths \`[w0, w1, w2, …]\` (so \`a\` is \`w0 + w1 +
w2 + …\` bytes long):

\`\`\`
output0 = a[0 .. w0]
output1 = a[w0 .. w0+w1]
output2 = a[w0+w1 .. w0+w1+w2]
...
\`\`\`

Each width must be at least 1, and the widths add up to the input's length.

## Where it fits

- **Splitting a block into halves for a Feistel round** — Blowfish and DES
  begin each round by cutting the block into a left half and a right half
  (for Blowfish's 8-byte block, \`widths: [4, 4]\`); the round then transforms
  the halves and concatenates them back.
- **Unpacking words for hashing** — SHA-256 cuts its 32-byte working state
  into eight 4-byte words (\`widths: [4,4,4,4,4,4,4,4]\`) so each word can be
  fed through the round arithmetic on its own.

To pull out a single range that does **not** start at the beginning (for
example, one round's key from the middle of a key table), use **Byte Slice**
instead; split-bytes always cuts from the start.`,
  params: new Map([
    [
      "widths",
      "The lengths of the pieces to cut, in order (e.g. [4, 4] for two 4-byte halves). Each is a whole number, 1 or more, and together they add up to the input's length.",
    ],
  ]),
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
