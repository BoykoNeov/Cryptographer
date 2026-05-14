/**
 * Split a BytesState into per-block MatrixStates and stash them in aux.
 *
 * The boundary between the variable-length padding chain and the per-block
 * iterate loop. Walks the input bytes in `blockSize` chunks, packs each
 * chunk into a column-major 4×4 MatrixState (reusing `matrixFromBytes`),
 * and writes the resulting array into `aux[outBlocksAux]` so the
 * `iterate` runtime can read `state = blocks[i]` per iteration.
 *
 * State is passthrough (BytesState → BytesState, same bytes). The "real"
 * output lives in aux. We keep the state passthrough so subsequent
 * non-iterating steps (e.g. `compute-block-count`) can still see the full
 * BytesState if they want to.
 *
 * Generic in name but currently AES-shaped (blockSize=16 → 4×4 matrix).
 * A future block cipher with non-matrix geometry will need a sibling
 * `split-blocks-bytes@1` that produces `BytesState[]` instead.
 */

import { matrixFromBytes } from "../core/state/matrix";
import type {
  AuxValue,
  BytesState,
  Json,
  MatrixState,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const splitBlocks: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("split-blocks expects bytes state");
  }
  const { blockSize, outBlocksAux } = readParams(params);
  if (state.bytes.length % blockSize !== 0) {
    throw new Error(
      `split-blocks: input length ${state.bytes.length} is not a multiple of blockSize ${blockSize}. Did the padding step run?`,
    );
  }
  if (blockSize !== 16) {
    // Same reasoning as `load-block`: we only support the AES 4×4 packing
    // today. A future block cipher with different geometry needs a sibling.
    throw new Error(`split-blocks: only blockSize=16 (AES) is supported, got ${blockSize}`);
  }

  const blocks: MatrixState[] = [];
  for (let off = 0; off < state.bytes.length; off += blockSize) {
    // matrixFromBytes copies the slice — safe to advance the offset without
    // worrying about shared buffers.
    blocks.push(matrixFromBytes(state.bytes.subarray(off, off + blockSize)));
  }

  const out: BytesState = { shape: "bytes", bytes: state.bytes };
  const auxWrites = new Map<string, AuxValue>([[outBlocksAux, blocks]]);
  return { state: out, auxWrites };
};

export const splitBlocksDoc: StepDocumentation = {
  name: "Split Blocks",
  summary: "Slice the padded input into per-block matrices for the iterate loop to consume.",
  detail: `## Split Blocks

Multi-block cipher modes (ECB, CBC, CTR) run the AES round function once
per **block** of the input. This step is the boundary that turns a padded
\`BytesState\` (variable length, always a clean multiple of 16) into an
array of 4×4 \`MatrixState\` blocks that the \`iterate\` node walks one at
a time.

\`\`\`
input bytes (32):  [b0 b1 b2 .. b15] [b16 b17 .. b31]
output (aux):      [ MatrixState_0 ] [ MatrixState_1 ]
\`\`\`

The packing for each 16-byte chunk is the same column-major AES order as
\`load-block\` (FIPS-197 §3.4): bytes 0..3 become column 0 (top to bottom),
4..7 become column 1, and so on.

**Why state is passthrough.** The real output lives in
\`aux[outBlocksAux]\`. The state stays as the original \`BytesState\` so
subsequent non-iterating steps can still see it (e.g.
\`compute-block-count\` reads \`state.bytes.length\`). Once the \`iterate\`
node begins, the runtime sets \`state = blocks[i]\` for each iteration.

**Reusable across block ciphers** in spirit, but currently AES-shaped: it
only supports \`blockSize = 16\` because the matrix shape is hard-coded.
A future cipher with different geometry would register a sibling step
(e.g. \`generic.split-blocks-bytes@1\`) that produces \`BytesState[]\`.`,
  params: new Map([
    ["blockSize", "Bytes per block. AES = 16. Today this is the only supported value."],
    [
      "outBlocksAux",
      "Aux key to write the resulting MatrixState[] under. The matching iterate node reads from this same key via its `blocksFromAux` field.",
    ],
  ]),
  references: ["FIPS-197 §3.4 (State)", "NIST SP 800-38A §6 (Modes of Operation)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

const readParams = (params: Json): { blockSize: number; outBlocksAux: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("split-blocks requires params.blockSize + params.outBlocksAux");
  }
  const p = params as { blockSize?: unknown; outBlocksAux?: unknown };
  if (typeof p.blockSize !== "number" || !Number.isInteger(p.blockSize) || p.blockSize < 1) {
    throw new Error("split-blocks: blockSize must be a positive integer");
  }
  if (typeof p.outBlocksAux !== "string" || p.outBlocksAux.length === 0) {
    throw new Error("split-blocks: outBlocksAux must be a non-empty string");
  }
  return { blockSize: p.blockSize, outBlocksAux: p.outBlocksAux };
};
