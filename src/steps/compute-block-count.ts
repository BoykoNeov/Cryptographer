/**
 * Compute the per-block iteration count and write it to aux for the
 * `iterate` node to read.
 *
 * Trivial arithmetic — `count = bytes.length / blockSize` — but kept as
 * its own step on educational grounds: the user sees a labelled frame
 * "Block Count = 2" in the trace, which makes the multi-block expansion
 * concrete. Cost is one trace frame per Run.
 *
 * Passthrough on state. Reads BytesState's length, writes `aux[countAux]`.
 */

import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";

export const computeBlockCount: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("compute-block-count expects bytes state");
  }
  const { blockSize, countAux } = readParams(params);
  if (state.bytes.length % blockSize !== 0) {
    throw new Error(
      `compute-block-count: input length ${state.bytes.length} is not a multiple of blockSize ${blockSize}`,
    );
  }
  const count = state.bytes.length / blockSize;
  const auxWrites = new Map<string, AuxValue>([[countAux, count]]);
  return { state, auxWrites };
};

export const computeBlockCountDoc: StepDocumentation = {
  name: "Compute Block Count",
  summary: "Derive how many cipher-block iterations the multi-block loop will run.",
  detail: `## Compute Block Count

In multi-block cipher modes (ECB, CBC, CTR), the AES round function runs
once per **block** of the (padded) input. This step computes that
iteration count:

\`\`\`
count = input.length / blockSize
\`\`\`

For example, a 5-byte plaintext padded to 16 bytes runs **1** iteration; a
26-byte plaintext padded to 32 bytes runs **2**. The result is stashed in
\`aux[countAux]\` so the downstream \`iterate\` node can read it as its
loop bound.

**Why a separate step?** Cleanly separating "decide how many blocks" from
"slice the bytes into block matrices" (\`split-blocks\`) keeps each step
trivially understandable in the trace. A user scrubbing through the run
sees \`blockCount = 2\` materialize as its own frame — a small but real
educational beat. The cost is one extra leaf in the spec and one extra
frame in the trace per Run.`,
  params: new Map([
    ["blockSize", "Bytes per block. AES = 16. Must evenly divide the input length."],
    [
      "countAux",
      "Aux key to write the integer block count under. The matching iterate node reads from this same key via its `countFromAux` field.",
    ],
  ]),
  references: ["NIST SP 800-38A §6"],
};

const readParams = (params: Json): { blockSize: number; countAux: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("compute-block-count requires params.blockSize + params.countAux");
  }
  const p = params as { blockSize?: unknown; countAux?: unknown };
  if (typeof p.blockSize !== "number" || !Number.isInteger(p.blockSize) || p.blockSize < 1) {
    throw new Error("compute-block-count: blockSize must be a positive integer");
  }
  if (typeof p.countAux !== "string" || p.countAux.length === 0) {
    throw new Error("compute-block-count: countAux must be a non-empty string");
  }
  return { blockSize: p.blockSize, countAux: p.countAux };
};
