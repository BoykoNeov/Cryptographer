import type {
  Json,
  MatrixState,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

/**
 * Generic byte substitution: replace every byte b with sbox[b].
 * AES uses this for both SubBytes (forward) and InvSubBytes (with the inverse table).
 *
 * params: { sbox: number[] } — length 256, values 0..255.
 */
export const byteSubstitution: StepExecutor = (state, params) => {
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error("byte-substitution expects matrix4x4-bytes state");
  }
  const sbox = readSbox(params);
  const next = new Uint8Array(state.bytes);
  for (let i = 0; i < next.length; i++) {
    const b = next[i] ?? 0;
    next[i] = sbox[b] ?? 0;
  }
  const result: MatrixState = { shape: "matrix4x4-bytes", bytes: next };
  return { state: result };
};

// ─── Documentation ────────────────────────────────────────────────────────
// Generic explanation of what byte substitution does. Intentionally not
// AES-specific — this same step type is used for SubBytes and InvSubBytes
// in AES, and any future cipher that does table-driven byte substitution
// can plug in its own S-box and reuse all of this.

export const byteSubstitutionDoc: StepDocumentation = {
  name: "Byte Substitution",
  summary: "Replace every byte using a 256-entry lookup table.",
  detail: `## Byte Substitution

Each byte \`b\` of the state is replaced with \`sbox[b]\`, where \`sbox\` is a
256-entry permutation provided as a parameter. The substitution is applied
**independently** to every byte, so this step is purely position-preserving
and purely byte-local.

**Why it matters:** when the lookup table is *non-linear* (i.e. the function
\`b → sbox[b]\` is not affine over GF(2)), this is the only step in many
modern ciphers that resists differential and linear cryptanalysis. The
non-linearity is what makes the cipher resemble a random function rather
than a structured algebraic one.

In **AES** this step is called **SubBytes** (FIPS-197 §5.1.1). The AES S-box
is constructed from the multiplicative inverse in GF(2^8) followed by an
affine transformation over GF(2). Swapping it for the identity permutation
(try it!) breaks the cipher's security entirely while leaving the structure
intact.`,
  params: new Map([
    [
      "sbox",
      "256-entry array of bytes (0..255). Indexing it must produce a permutation for the cipher to be invertible.",
    ],
  ]),
  references: ["FIPS-197 §5.1.1 (SubBytes)", "FIPS-197 §5.3.2 (InvSubBytes)"],
  shapeContract: { input: "matrix4x4-bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.4) ───────────────
// `byteSubstitutionMeta` + `byteSubstitutionPortContract` colocate the
// projection metadata next to the executor that owns it per Decision C.
// (Originally lived in the throw-away Phase-0 `PROJECTION_METADATA`
// side-map in `core/port-projection.ts`; moved here in Slice 1.4,
// side-map deleted in Slice 1.9 per Decision A.)
//
// Pure state-only: a 4×4 column-major matrix in, same shape out, no aux.

export const byteSubstitutionMeta: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const byteSubstitutionPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
  outputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
};

const readSbox = (params: Json): readonly number[] => {
  if (
    typeof params !== "object" ||
    params === null ||
    Array.isArray(params) ||
    !("sbox" in params)
  ) {
    throw new Error("byte-substitution requires params.sbox");
  }
  const sbox = (params as { sbox: unknown }).sbox;
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    throw new Error("sbox must be an array of 256 numbers");
  }
  return sbox as readonly number[];
};
