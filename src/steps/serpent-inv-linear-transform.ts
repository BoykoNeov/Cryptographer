/**
 * Serpent Inverse Linear Transform — standard-form (table-based) version.
 *
 * Each of the 128 input (= LT's output) bits gets reconstructed by XOR-ing
 * a small set of LT-output bits per the inverse table. Functionally:
 * `applyInverseLT(applyLT(x)) === x` for every 128-bit state `x`.
 *
 * Used in 31 of decryption's 32 inverse rounds. The first inverse round
 * (which undoes encryption's irregular final round) has no LT to invert.
 */

import { SERPENT_INV_LT_TABLE } from "../ciphers/serpent-constants";
import type {
  BytesState,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";
import { readBit, writeBit } from "./serpent-bit-ops";

export const serpentInvLinearTransform: StepExecutor = (state) => {
  if (state.shape !== "bytes") {
    throw new Error("serpent.inv-linear-transform expects bytes state");
  }
  if (state.bytes.length !== 16) {
    throw new Error(
      `serpent.inv-linear-transform expects 16-byte state; got ${state.bytes.length} bytes`,
    );
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 128; i++) {
    const sources = SERPENT_INV_LT_TABLE[i] ?? [];
    let bit = 0;
    for (const src of sources) {
      bit ^= readBit(state.bytes, src);
    }
    writeBit(out, i, bit);
  }

  const result: BytesState = { shape: "bytes", bytes: out };
  return { state: result };
};

export const serpentInvLinearTransformDoc: StepDocumentation = {
  name: "Inverse Linear Transform (Serpent)",
  summary: "Reverse the LT: each output bit is a XOR-sum per the inverse table.",
  detail: `## Inverse Linear Transform (Serpent, standard form)

Mirror of \`serpent.linear-transform@1\`. Each of the 128 output bits is
the XOR of a small set of input bits, per the *inverse* LT table:

\`\`\`
output_bit[i]  =  XOR over j in INV_LT_TABLE[i] of  input_bit[j]
\`\`\`

The inverse table is constructed so that the round-trip
\`applyLT(applyInverseLT(x)) === x\` holds for every 128-bit state.
A property test in \`tests/serpent-lt-roundtrip.test.ts\` pins this fact.

**Used in 31 of 32 inverse rounds.** Decryption's first inverse round
undoes encryption's irregular final round, which had no LT — so there's
no inverse LT to apply there. All subsequent inverse rounds (30, 29, …, 0)
start with this step.`,
  params: new Map(),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Inverse Linear Transformation L^-1), Appendix C (inverse LT table)",
    "Serpent NIST submission, tstsubmtl/serpref.c (LTInverse() function, LTTableInverse[])",
  ],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.7) ───────────────
// Pure bytes→bytes 16-byte fixed transform with no aux and no params.
// Mirror of `serpent.linear-transform@1`.

export const serpentInvLinearTransformMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const serpentInvLinearTransformPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 16, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 16, layout: "raw" }]]),
};
