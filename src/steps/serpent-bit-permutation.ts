/**
 * Serpent bit permutation step. Applies a 128-entry bit-permutation table to
 * a 16-byte (128-bit) state.
 *
 * Used twice in the cipher: as the Initial Permutation (IP) at the start of
 * encryption (and the end of decryption), and as the Final Permutation (FP)
 * at the end of encryption (and the start of decryption). FP is the inverse
 * of IP — applying both in sequence is the identity on the state.
 *
 * The two permutations exist to align bits across the four 32-bit words of
 * the state so the bitsliced S-box layer can be applied column-wise. In
 * bitslice implementations the IP/FP are folded into the key schedule
 * during a pre-pass; in this educational implementation they are visible
 * steps the user can scrub to.
 *
 * Convention (matches the reference C source in the Serpent NIST submission):
 *   `output_bit[i] = input_bit[table[i]]`
 *
 * For IP: bit 0 of the output state is plaintext bit 0; bit 1 is plaintext
 * bit 32; bit 2 is plaintext bit 64; bit 3 is plaintext bit 96; bit 4 is
 * plaintext bit 1; and so on. This interleaving is what makes the four
 * state words "share columns" after permutation.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";
import { applyBitPermutation } from "./serpent-bit-ops";

export const serpentBitPermutation: StepExecutor = (state, params) => {
  if (state.shape !== "bytes") {
    throw new Error("serpent.bit-permutation expects bytes state");
  }
  if (state.bytes.length !== 16) {
    throw new Error(
      `serpent.bit-permutation expects 16-byte state; got ${state.bytes.length} bytes`,
    );
  }
  const table = readTable(params);
  const next: BytesState = { shape: "bytes", bytes: applyBitPermutation(state.bytes, table) };
  return { state: next };
};

export const serpentBitPermutationDoc: StepDocumentation = {
  name: "Bit Permutation",
  summary: "Shuffle the 128 bits of the state according to a fixed permutation table.",
  detail: `## Bit Permutation (Serpent IP / FP)

Each bit of the output state is read from a specific bit position in the
input state, per the 128-entry \`table\` parameter:

\`\`\`
output_bit[i]  =  input_bit[table[i]]
\`\`\`

Serpent uses two such permutations:

- **Initial Permutation (IP)** — applied to the plaintext at the start of
  encryption. Interleaves bits across the four 32-bit words of the state so
  that the bitsliced S-box layer in each round can operate column-wise.
- **Final Permutation (FP)** — applied to the state at the end of encryption,
  immediately before output. FP is the inverse of IP; applying both in
  sequence returns the original state byte-for-byte.

Decryption uses these same two tables but in reverse order: IP is applied
first (to undo encryption's final FP), and FP is applied last (to undo
encryption's initial IP).

**Why pull this out of bitslice form?** Production Serpent implementations
absorb IP/FP into the key schedule and never touch the state with them at
run time. We keep them visible here so a user scrubbing the trace can
watch the bit interleaving happen explicitly — the price is two extra
trace frames per Run.

**Bit numbering.** The 128-bit state is stored as 16 bytes; state bit \`b\`
is bit \`b % 8\` of byte \`b >> 3\`, LSB-first within each byte. So state
bit 0 = LSB of byte 0; state bit 8 = LSB of byte 1; state bit 127 = MSB
of byte 15.`,
  params: new Map([
    [
      "table",
      "128-entry permutation table. table[i] is the source bit position in the input for output bit i.",
    ],
    [
      "label",
      'Optional human-readable name for the permutation, e.g. "IP" or "FP". Display-only; the executor ignores it.',
    ],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, 'Serpent: A Proposal for the Advanced Encryption Standard', §2 (Initial and Final Permutations)",
    "Serpent NIST submission, tstsubmtl/serpref.c (InitialPermutation, FinalPermutation tables)",
  ],
};

const readTable = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.bit-permutation requires params.table");
  }
  const p = params as { table?: unknown };
  if (!Array.isArray(p.table) || p.table.length !== 128) {
    throw new Error("serpent.bit-permutation: table must be a 128-entry array");
  }
  return p.table as readonly number[];
};
