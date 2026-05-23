/**
 * DES Initial Permutation (IP). FIPS 46-3 Table 1.
 *
 * Permutes the 64 bits of the 8-byte input block according to the IP table
 * (passed as `params.table`). Applied once at the start of encryption (and
 * at the end of decryption — DES is symmetric under key-reversal, so the
 * same IP/FP pair brackets both directions).
 *
 * The permutation has no cryptographic purpose; it was added in the
 * original DES design to align bits for the era's bit-serial hardware. In
 * software implementations it adds a frame the user can scrub to.
 *
 * Convention (FIPS 46-3): bits are 1-indexed and MSB-first. Output bit `i`
 * (1-indexed) reads input bit `table[i-1]`. See `src/steps/des-bit-ops.ts`
 * for the helpers.
 *
 * Params: `{ table: number[64] }`. The standard IP table lives in
 * `src/ciphers/des-constants.ts` as `DES_IP` — the cipher spec passes a
 * copy as `params.table` so saved JSON documents are self-contained.
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

export const desInitialPermutation: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("des.initial-permutation expects bytes state");
  }
  if (state.bytes.length !== 8) {
    throw new Error(
      `des.initial-permutation expects 8-byte state; got ${state.bytes.length} bytes`,
    );
  }
  const table = readTable(params);
  const next: BytesState = { shape: "bytes", bytes: fipsPermute(state.bytes, table, 64) };
  return { state: next };
};

export const desInitialPermutationDoc: StepDocumentation = {
  name: "Initial Permutation (IP)",
  summary: "Shuffle the 64 bits of the plaintext block per FIPS 46-3 Table 1.",
  detail: `## Initial Permutation (IP)

Each bit of the output reads from a specific position in the input, per the
64-entry \`table\` parameter (1-indexed, MSB-first):

\`\`\`
output_bit[i]  =  input_bit[table[i - 1]]      for i in 1..64
\`\`\`

IP has **no cryptographic purpose** — it was an artifact of bit-serial
hardware in the 1970s. Inverting it is the Final Permutation (FP), applied
just before output. Together IP and FP cancel out (FP ∘ IP = identity), so
the cipher's security would be unchanged if both were removed; the modern
DES is "DES the round structure + the S-boxes" with the IP/FP wrapper
preserved for backward compatibility with the original standard.

For example, IP's first three entries are 58, 50, 42 — meaning output bit 1
comes from input bit 58 (the second bit of byte 7's MSB region), output
bit 2 from input bit 50, and so on. The full table interleaves the input
bytes so that every output byte mixes bits from 4 input bytes.`,
  params: new Map([
    [
      "table",
      "64-entry permutation table (FIPS 1-indexed, MSB-first). DES_IP in des-constants.ts.",
    ],
  ]),
  references: ["FIPS 46-3 §3 (Initial Permutation, Table 1)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.8) ───────────────
// Pure bytes→bytes 8-byte fixed transform with no aux. The cleanest lift
// in Slice 1.8 — same shape as Slice 1.7's `serpent.bit-permutation@1`
// pure transform, just at 8 bytes instead of 16. byteLength: 8 honest
// declaration on both ports (DES block size is fixed by FIPS 46-3; no
// variant). Matches the Slice 1.7 "honest fixed when no variant" posture.

export const desInitialPermutationMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
};

export const desInitialPermutationPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 8, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 8, layout: "raw" }]]),
};

const readTable = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.initial-permutation requires params.table");
  }
  const p = params as { table?: unknown };
  if (!Array.isArray(p.table) || p.table.length !== 64) {
    throw new Error("des.initial-permutation: table must be a 64-entry array");
  }
  return p.table as readonly number[];
};
