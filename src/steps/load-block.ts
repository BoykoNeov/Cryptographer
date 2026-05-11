/**
 * BytesState → MatrixState boundary step. Takes a 16-byte sequence and
 * packs it into the AES 4×4 column-major state matrix. This is the bridge
 * between the padding chain (which works on variable-length byte sequences)
 * and the AES round function (which works on the 4×4 matrix).
 *
 * Generic in name (`generic.load-block@1`), AES-shaped in practice — we
 * only support the 16-byte → 4×4 packing today. A future block cipher with
 * a different state geometry (e.g. Speck-128's 2×64-bit words) would need a
 * sibling load step, not a generalization of this one.
 */

import { matrixFromBytes } from "../core/state/matrix";
import type { Json, StepDocumentation, StepExecutor } from "../core/types";

export const loadBlock: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("load-block expects bytes state");
  }
  const blockSize = readBlockSize(params);
  if (state.bytes.length !== blockSize) {
    throw new Error(
      `load-block: expected exactly ${blockSize} bytes, got ${state.bytes.length}. Did the padding step run?`,
    );
  }
  if (blockSize !== 16) {
    // Today we only support the AES 4×4 packing. Other block sizes would
    // need a different state shape; flag explicitly rather than silently
    // packing bytes into a misshapen matrix.
    throw new Error(`load-block: only blockSize=16 (AES) is supported, got ${blockSize}`);
  }
  return { state: matrixFromBytes(state.bytes) };
};

export const loadBlockDoc: StepDocumentation = {
  name: "Load Block",
  summary: "Pack a 16-byte sequence into the AES 4×4 column-major state matrix.",
  detail: `## Load Block

AES does its work on a **4×4 byte matrix in column-major order** (FIPS-197
§3.4) — byte at row \`r\`, column \`c\` lives at index \`r + 4*c\`. The
first 4 bytes of the input go into column 0 (top-to-bottom), the next 4
into column 1, and so on.

\`\`\`
bytes index:   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
matrix cell:  (0,0)(1,0)(2,0)(3,0)(0,1)(1,1)...           (3,3)
\`\`\`

This step is the **bridge** between the variable-length padding chain
(BytesState) and the fixed-shape AES round function (MatrixState). The
padding step ensures we have exactly 16 bytes before \`load-block\` packs
them into the matrix.

**Why it's its own step** (rather than folded into the runtime entry):
keeping the conversion visible in the trace means the user can scrub to
this frame and see *exactly* how their input bytes get arranged into the
matrix — a common source of confusion ("which byte is at position (0,1)?").
The trace shows BytesState before and MatrixState after.`,
  params: new Map([
    [
      "blockSize",
      "Bytes per block. AES = 16. Today this is the only supported value; future block ciphers with non-matrix geometry will use sibling load-X steps.",
    ],
  ]),
  references: ["FIPS-197 §3.4 (State)"],
};

const readBlockSize = (params: Json): number => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("load-block requires params.blockSize");
  }
  const bs = (params as { blockSize?: unknown }).blockSize;
  if (typeof bs !== "number" || !Number.isInteger(bs) || bs < 1) {
    throw new Error("load-block: blockSize must be a positive integer");
  }
  return bs;
};
