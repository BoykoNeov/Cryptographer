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

import type { BytesState, Json, State, StepDocumentation, StepExecutor } from "../core/types";

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
