/**
 * Concatenate per-block ciphertext (or keystream-XOR'd) MatrixStates into
 * a single BytesState. The post-loop boundary that mirrors `split-blocks`.
 *
 * Reads `aux[blocksAux]: MatrixState[]` (written by the iterate runtime as
 * it accumulates each iteration's final state) and emits a BytesState of
 * `blocks.length * 16` bytes, with each block flattened in the same
 * column-major order `load-block` / `split-blocks` use.
 *
 * The `state` argument is ignored — the runtime leaves `state` as the
 * last iteration's final MatrixState after the loop, but the real output
 * is the concatenation of ALL iterations' outputs (sitting in aux).
 */

import type {
  BytesState,
  Json,
  PortContract,
  ProjectionMetadata,
  State,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const concatBlocks: StepExecutor = (_state, params, ctx) => {
  const blocksAux = readBlocksAux(params);
  const blocks = ctx.aux.get(blocksAux);
  if (!Array.isArray(blocks)) {
    throw new Error(
      `concat-blocks: aux["${blocksAux}"] must be an array of State, got ${typeof blocks}`,
    );
  }
  // Cast through `readonly State[]` is safe — AuxValue includes it and we
  // checked Array.isArray above. Per-element shape validation below.
  const blockArr = blocks as readonly State[];

  // All blocks must be MatrixState (16 bytes each). The iterate's contract
  // guarantees this for the AES round body output, but defensive validation
  // catches spec misconfigurations during development.
  const out = new Uint8Array(blockArr.length * 16);
  for (let i = 0; i < blockArr.length; i++) {
    const block = blockArr[i];
    if (!block || block.shape !== "matrix4x4-bytes") {
      throw new Error(
        `concat-blocks: aux["${blocksAux}"][${i}] must be MatrixState, got ${block ? block.shape : "undefined"}`,
      );
    }
    if (block.bytes.length !== 16) {
      throw new Error(
        `concat-blocks: aux["${blocksAux}"][${i}].bytes.length must be 16, got ${block.bytes.length}`,
      );
    }
    out.set(block.bytes, i * 16);
  }

  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result, auxReads: [blocksAux] };
};

export const concatBlocksDoc: StepDocumentation = {
  name: "Concat Blocks",
  summary: "Flatten the per-block ciphertext matrices back into a single byte sequence.",
  detail: `## Concat Blocks

The mirror of \`split-blocks\`. After the \`iterate\` loop finishes,
\`aux[blocksAux]\` holds the per-iteration output: an array of 4×4
\`MatrixState\` blocks, one per plaintext block that was encrypted. This
step walks that array, flattens each matrix back to 16 bytes in column-
major order, and concatenates them into a single \`BytesState\`.

\`\`\`
aux blocks:  [ MatrixState_0 ] [ MatrixState_1 ]
output:      [c0 c1 .. c15]    [c16 c17 .. c31]   ← one BytesState (32)
\`\`\`

The runtime leaves \`state\` as the *last* iteration's final matrix after
the loop, but the cipher output is the full concatenation — that's why this
step ignores the incoming \`state\` and reads everything from aux.

For unpadded modes (CTR), a subsequent \`truncate-to-length\` step trims
the keystream-extended output back to the original plaintext length.`,
  params: new Map([
    [
      "blocksAux",
      "Aux key to read the MatrixState[] from. Matches the iterate node's `outBlocksAux` field.",
    ],
  ]),
  references: ["NIST SP 800-38A §6"],
  shapeContract: { input: "matrix4x4-bytes", output: "bytes" },
};

// ─── Universal port-dataflow metadata (Phase 2 Slice 2.0b-ii) ───────────
// `concatBlocksMeta`: shape-transforming step — input state is whatever
// the legacy `iterate` left behind (typically `matrix4x4-bytes` for AES
// modes, since iterate clones the last block's final state into the
// runtime's `state` variable), output state is a `BytesState` of
// `blocks.length * 16` bytes. The executor IGNORES `_state`; all data
// flows through `aux[blocksAux]: MatrixState[]`.
//
// **Why `stateLayout: "bytes"` works here despite the shape mismatch on
// the input side:** Slice 2.0b-ii (user pick option C) relaxes
// `stateToBytes` so that `expected === "bytes"` accepts any non-bigint
// State variant by reading `.bytes` directly. The 16 bytes flowing in
// from the matrix variant are encoded as raw bytes, reconstructed as a
// length-16 BytesState the executor ignores, then the executor returns
// its real BytesState output which encodes cleanly with the same
// `"bytes"` layout. No asymmetric `stateInputLayout`/`stateOutputLayout`
// widening required this slice — that widening still lands when
// `load-block` / `store-block` lift in a later slice.
//
// One aux read port: `"blocks"` → `params.blocksAux`, decoded as
// `MatrixState[]` via `auxPortBytesToValue`'s `"matrix-cm-4x4-array"`
// branch... BUT in practice the runtime aliases the live `MatrixState[]`
// directly into the synthetic `portedAuxRead` (variant preserved across
// the call), so the legacy executor's `ctx.aux.get(blocksAux)` returns
// the same `MatrixState[]` reference legacy dispatch would yield. The
// port-bytes encoding/decoding still runs for coercion accounting; the
// declared layout is honored even if the lifted-executor pathway never
// observes the decoded result.
export const concatBlocksMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (params: Json) => {
    const blocksAux = readBlocksAux(params);
    return new Map([["blocks", blocksAux]]);
  },
};

/**
 * Declared port surface. State ports polymorphic (input length is 16
 * matrix bytes from iterate; output length is `blocks.length * 16`).
 * The `"blocks"` input port carries the concatenated MatrixState[]
 * bytes under the new `"matrix-cm-4x4-array"` layout — same layout
 * `split-blocks` declares on its output port, so the producer/consumer
 * shapes line up exactly.
 */
export const concatBlocksPortContract: PortContract = {
  inputs: new Map([
    ["state", { layout: "raw" }],
    ["blocks", { layout: "matrix-cm-4x4-array" }],
  ]),
  outputs: new Map([["state", { layout: "raw" }]]),
};

const readBlocksAux = (params: Json): string => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("concat-blocks requires params.blocksAux");
  }
  const v = (params as { blocksAux?: unknown }).blocksAux;
  if (typeof v !== "string" || v.length === 0) {
    throw new Error("concat-blocks: blocksAux must be a non-empty string");
  }
  return v;
};
