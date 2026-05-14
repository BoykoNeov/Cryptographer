/**
 * MatrixState → BytesState boundary step. The inverse of load-block: takes
 * the AES 4×4 matrix and emits its 16 bytes as a flat BytesState, ready for
 * the unpad chain on the decrypt path.
 *
 * Pure copy — the matrix's underlying bytes are already in column-major
 * order, so we just hand them back as a Uint8Array of length 16. No
 * params; the shape is fully implied by the input.
 */

import type { BytesState, StepDocumentation, StepExecutor } from "../core/types";

export const storeBlock: StepExecutor = (state) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("store-block expects matrix4x4-bytes state");
  }
  // Copy rather than alias: the runtime already clones, but allocating a
  // fresh array here makes the BytesState's invariant (owned buffer)
  // explicit at the call site.
  const out: BytesState = { shape: "bytes", bytes: new Uint8Array(state.bytes) };
  return { state: out };
};

export const storeBlockDoc: StepDocumentation = {
  name: "Store Block",
  summary: "Unpack the AES 4×4 matrix back into a 16-byte sequence.",
  detail: `## Store Block

The inverse of \`load-block\`: takes the AES state matrix and serializes it
back into a flat 16-byte sequence in column-major order. This is the bridge
between the AES round function (MatrixState) and the unpad chain (BytesState).

Since AES stores its state as a column-major \`Uint8Array(16)\` internally,
this step is a structural cast — the bytes are already in the right order,
we just relabel the shape from \`matrix4x4-bytes\` to \`bytes\` so downstream
steps (like \`pkcs7-unpad\`) can consume it.

The trace shows MatrixState before and BytesState after. The byte values
are identical on both sides; only the shape changes.`,
  references: ["FIPS-197 §3.4 (State)"],
  shapeContract: { input: "matrix4x4-bytes", output: "bytes" },
};
