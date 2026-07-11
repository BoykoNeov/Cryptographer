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
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";
import { readBit, writeBit } from "./serpent-bit-ops";

// Port-native executor (scaffolding-suppression Phase B, slice B3, 2026-05-30).
// Consumes and emits ONLY `Uint8Array` — the 128-bit block on the `state` port,
// projected by the runtime from the threaded state via `meta.stateInputPort`.
export const serpentInvLinearTransform: PortedExecutor = (inputs) => {
  const stateBytes = inputs.get("state");
  if (stateBytes === undefined) {
    throw new Error(
      "serpent.inv-linear-transform: 'state' input port is not wired (the runtime projects the carried block onto it via meta.stateInputPort)",
    );
  }
  if (stateBytes.length !== 16) {
    throw new Error(
      `serpent.inv-linear-transform expects 16-byte state; got ${stateBytes.length} bytes`,
    );
  }

  const out = new Uint8Array(16);
  for (let i = 0; i < 128; i++) {
    const sources = SERPENT_INV_LT_TABLE[i] ?? [];
    let bit = 0;
    for (const src of sources) {
      bit ^= readBit(stateBytes, src);
    }
    writeBit(out, i, bit);
  }

  return new Map([["state", out]]);
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

The inverse table is built so that applying the linear transform and then
this inverse returns the original state exactly, for any 128-bit value.

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
