import { matAt, setMatAt } from "../core/state/matrix";
import type {
  Json,
  MatrixState,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

/**
 * Cyclically shift each row of the 4x4 state to the left by `shifts[r]` columns.
 * Standard AES uses [0, 1, 2, 3]; inverse uses [0, 3, 2, 1] (or equivalently
 * a right shift of [0, 1, 2, 3]).
 *
 * params: { shifts: [number, number, number, number] }
 */
export const shiftRows: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("shift-rows expects matrix4x4-bytes state");
  }
  const shifts = readShifts(params);
  const next = new Uint8Array(16);
  for (let r = 0; r < 4; r++) {
    const shift = shifts[r] ?? 0;
    for (let c = 0; c < 4; c++) {
      const srcCol = (c + shift) % 4;
      setMatAt(next, r, c, matAt(state, r, srcCol));
    }
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

// ─── Documentation ────────────────────────────────────────────────────────

export const shiftRowsDoc: StepDocumentation = {
  name: "Shift Rows",
  summary: "Cyclically rotate each row of the 4×4 state by a fixed amount.",
  detail: `## Shift Rows

Each row \`r\` of the 4×4 state matrix is cyclically shifted **left** by
\`shifts[r]\` columns. In standard AES forward this is \`[0, 1, 2, 3]\`
(row 0 unchanged, row 1 shifted by 1, etc.). The inverse direction is
\`[0, 3, 2, 1]\` (equivalent to shifting right by \`[0, 1, 2, 3]\`).

**Why it matters:** the cipher state is column-oriented (MixColumns mixes
within columns). ShiftRows is what spreads bytes across columns so a
single byte's influence eventually reaches every output byte. Without it,
each column would evolve independently and the cipher would be 4× weaker.

This step is **purely a permutation** — no byte values change, only their
positions. Combined with SubBytes (also byte-local) it provides
*confusion*; combined with MixColumns (column-local) it provides
*diffusion*. SubBytes and ShiftRows commute (try swapping them — the
output is unchanged) because both are byte-position operations.`,
  params: new Map([
    [
      "shifts",
      "Array of 4 left-shift counts, one per row. AES uses [0,1,2,3] forward, [0,3,2,1] inverse.",
    ],
  ]),
  references: ["FIPS-197 §5.1.2 (ShiftRows)", "FIPS-197 §5.3.1 (InvShiftRows)"],
  shapeContract: { input: "matrix4x4-bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.4) ───────────────
// Pure state-only step — matrix in, matrix out, no aux. Same shape as
// `byteSubstitution`.

export const shiftRowsMeta: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const shiftRowsPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
  outputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
};

const readShifts = (params: Json): readonly number[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("shifts" in params)
  ) {
    throw new Error("shift-rows requires params.shifts");
  }
  const shifts = (params as { shifts: unknown }).shifts;
  if (!Array.isArray(shifts) || shifts.length !== 4) {
    throw new Error("shifts must be an array of 4 numbers");
  }
  return shifts as readonly number[];
};
