/**
 * DES Expansion (E). FIPS 46-3 Table E (Bit-Selection Table).
 *
 * Expands the 32-bit right half R from 32 bits to 48 bits by duplicating
 * 16 input bits across two output positions. The 48-bit result is then
 * XORed with the round key K_i (also 48 bits) inside the F function.
 *
 * The expansion provides DES's diffusion: each input bit influences at
 * least one S-box (often two), so a single-bit change in R propagates
 * across multiple S-boxes after the round-key XOR + substitution.
 *
 * **Shape transition.** Input is 4 bytes (32 bits); output is 6 bytes
 * (48 bits). This is the first of two shape-changing steps inside the
 * F function — the other is `des.s-boxes@1` which collapses 6 → 4 bytes.
 * `StepShapeContract.input/output` declares `"bytes"` but cannot today
 * carry byte counts; the executor's runtime length check is the gate.
 *
 * Params: `{ table: number[48] }`. Standard `DES_E` lives in
 * `src/ciphers/des-constants.ts`.
 */

import type {
  BytesState,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";
import { fipsPermute } from "./des-bit-ops";

export const desExpandR: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("des.expand-R expects bytes state");
  }
  if (state.bytes.length !== 4) {
    throw new Error(`des.expand-R expects 4-byte (32-bit) state; got ${state.bytes.length} bytes`);
  }
  const table = readTable(params);
  const next: BytesState = { shape: "bytes", bytes: fipsPermute(state.bytes, table, 48) };
  return { state: next };
};

export const desExpandRDoc: StepDocumentation = {
  name: "Expansion (E)",
  summary: "Expand R from 32 to 48 bits by duplicating 16 input bits.",
  detail: `## Expansion (E)

Maps the 32-bit right half R to a 48-bit value by selecting bits from R
according to the 48-entry \`table\` parameter:

\`\`\`
output_bit[i]  =  input_bit[table[i - 1]]      for i in 1..48
\`\`\`

**Why expand?** The XOR with the 48-bit round key K_i (the next step inside
F) needs 48 bits of input. The expansion is what lets DES use a 48-bit
round key while operating on a 32-bit half — and it does that *with
diffusion* by repeating 16 bits across two output positions each, so each
input bit influences either one or two adjacent S-boxes.

Half of the table is the input bits in order (positions 2, 3, 4, 5 — the
"middle" four of each 6-bit S-box input come from one input bit each); the
other half duplicates the boundary bits (positions 1 and 6 — the "row
selectors" of each S-box come from neighboring input bits).

**Output shape.** Input is 32 bits (4 bytes); output is 48 bits (6 bytes).
This is one of two shape-changing steps inside F.`,
  params: new Map([
    ["table", "48-entry expansion table (FIPS 1-indexed, MSB-first). DES_E in des-constants.ts."],
  ]),
  references: ["FIPS 46-3 §3 (E Bit-Selection Table)"],
  shapeContract: { input: "bytes", output: "bytes" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.8) ───────────────
// **The first lifted step in any slice where `input.byteLength !==
// output.byteLength` on the state port.** DES E maps 4 bytes (32 bits)
// → 6 bytes (48 bits). Both ports share `stateLayout: "bytes"` — the
// `bytes`-shape codec in `port-projection.ts` (`stateToBytes` line 286)
// copies bytes without a length check, so the asymmetric declaration
// works without runtime contract changes. The length asymmetry is
// honest information for the editor + future palette wiring (telling
// the user "this step expands its input"); the runtime relies on the
// executor's own length assertions to catch wiring errors.

export const desExpandRMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const desExpandRPortContract: PortContract = {
  // 4-byte input, 6-byte output — the first asymmetric state-port
  // declaration in the universal-port migration.
  inputs: new Map([["state", { byteLength: 4, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 6, layout: "raw" }]]),
};

const readTable = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.expand-R requires params.table");
  }
  const p = params as { table?: unknown };
  if (!Array.isArray(p.table) || p.table.length !== 48) {
    throw new Error("des.expand-R: table must be a 48-entry array");
  }
  return p.table as readonly number[];
};
