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
  summary:
    "N-way byte-range partitioning of one input port into output0..output{N-1}. Symmetric inverse of concat.",
  detail: `# Split Bytes

Reads bytes from the \`input\` port and emits N contiguous sub-ranges on
output ports \`output0\`, \`output1\`, …, \`output{N-1}\` where the i-th
output carries \`params.widths[i]\` bytes. Symmetric inverse of
\`concat@1\` — concat takes N inputs and joins; split-bytes takes one
input and partitions.

## Math

For input \`a\` of length \`L = sum(widths)\`:

\`\`\`
output0 = a[0 .. widths[0]]
output1 = a[widths[0] .. widths[0]+widths[1]]
output2 = a[widths[0]+widths[1] .. widths[0]+widths[1]+widths[2]]
...
\`\`\`

Each \`widths[i]\` must be ≥ 1; the array must contain at least one
entry. Output port count = \`widths.length\`. Input byteLength = sum of
widths (declared at spec-edit time, validated by the runtime's
port-length coercion at run-time).

## Where it fits

- **SHA-256 working-variable extraction.** Per-round compression splits
  the 32-byte working_vars buffer into 8 × 4-byte words a..h via
  \`params: { widths: [4, 4, 4, 4, 4, 4, 4, 4] }\`.
- **SHA-256 initial hash extraction.** Final-add splits the 32-byte
  H-table read from aux into H_0..H_7 the same way.
- **HMAC, BLAKE2, future hashes.** Wherever a packed multi-word buffer
  needs to be unpacked into per-word ports for parallel arithmetic.

## Pair with \`byte-slice@1\`

For arbitrary-offset single-range extraction (e.g., the per-round K_t
at offset 4*roundIndex from a 256-byte K-table), prefer
\`byte-slice@1\`. \`split-bytes@1\` is for symmetric N-way extraction
starting at offset 0.

## Authoring shape

\`\`\`json
{
  "kind": "step",
  "id": "extract-working-vars",
  "type": "split-bytes@1",
  "params": { "widths": [4, 4, 4, 4, 4, 4, 4, 4] },
  "portInputs": {
    "input": { "node": "state-to-bytes-of-working-vars", "port": "output" }
  }
}
\`\`\`

This leaf emits 8 outputs (output0..output7) each carrying 4 bytes,
ready to be wired to the per-word arithmetic chains for SHA-256's
Σ0/Σ1/Ch/Maj.

## Errors

- Throws if \`params.widths\` is missing or not an array.
- Throws if \`params.widths\` is empty (N ≥ 1 floor).
- Throws if any \`widths[i]\` is missing, not an integer, or < 1.
- Throws at run-time if the \`input\` port is missing.

## Phase status

Shipped in Slice 2.6d of the universal-port-dataflow plan as the
**third of three** new primitives. First consumers: the decomposed
SHA-256 spec's compression-round working-variable extraction and the
final-add step's H-table extraction.`,
  params: new Map([
    [
      "widths",
      "Array of output port byteLengths. Each entry must be a positive integer (≥ 1); the array must have at least one entry. Output port N is named output{N-1}; input port byteLength = sum(widths).",
    ],
  ]),
  references: [
    "docs/plans/universal-port-phase-2-slices.md (Slice 2.6c design D.3 + Slice 2.6d ship)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
