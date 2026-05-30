/**
 * DES Final Permutation (FP = IP^-1). FIPS 46-3 Table 2.
 *
 * Inverse of the Initial Permutation: applied once after the last Feistel
 * round, just before the ciphertext is emitted (and at the start of
 * decryption). Like IP, FP has no cryptographic purpose; FP ∘ IP = identity.
 *
 * Same convention as IP: bits are 1-indexed, MSB-first. Output bit `i`
 * reads input bit `table[i-1]`. The standard FP table lives in
 * `src/ciphers/des-constants.ts` as `DES_FP`.
 *
 * The pre-FP input is the round-16 rejoin output. The plan uses
 * `combineKind: "feistel-no-swap"` for round 16, so the rejoin produces
 * `(L_in ⊕ R_out) || R_in` — equivalent to the textbook description's
 * "no swap on the last round, then apply FP."
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { fipsPermute } from "./des-bit-ops";

/**
 * Port-native since B4 (universal-port Phase 4d DES rebuild). Reads the
 * 8-byte round-16 output from the `state` input port and emits the permuted
 * ciphertext block on the `state` output port (the spec's `outputFrom`).
 */
export const desFinalPermutation: PortedExecutor = (inputs, params) => {
  const bytes = inputs.get("state");
  if (bytes === undefined) {
    throw new Error("des.final-permutation: missing required input port 'state'");
  }
  if (bytes.length !== 8) {
    throw new Error(`des.final-permutation expects 8-byte state; got ${bytes.length} bytes`);
  }
  const table = readTable(params);
  return new Map([["state", fipsPermute(bytes, table, 64)]]);
};

export const desFinalPermutationDoc: StepDocumentation = {
  name: "Final Permutation (FP)",
  summary: "Inverse of IP. Shuffles the 64 bits per FIPS 46-3 Table 2.",
  detail: `## Final Permutation (FP)

The inverse of the Initial Permutation. Applied once after the 16 Feistel
rounds, immediately before the ciphertext is output. The two permutations
cancel — applying IP then FP to any 64-bit value yields the original
value byte-for-byte.

\`\`\`
output_bit[i]  =  input_bit[table[i - 1]]      for i in 1..64
\`\`\`

**Note on the round-16 input to FP.** Textbook DES descriptions say "skip
the swap on the last round, then apply FP." Equivalently — and the
formulation this app uses — the 16th Feistel round uses
\`combineKind: "feistel-no-swap"\` so its rejoin output is
\`(L_in ⊕ R_out) || R_in\` directly. FP then permutes those 64 bits into
the ciphertext.

**No cryptographic purpose.** FP exists for symmetry with IP, which exists
as a relic of bit-serial hardware. Removing both would not weaken the
cipher; preserving them keeps the FIPS standard intact.`,
  params: new Map([
    [
      "table",
      "64-entry permutation table (FIPS 1-indexed, MSB-first). DES_FP in des-constants.ts.",
    ],
  ]),
  references: ["FIPS 46-3 §3 (Inverse Initial Permutation, Table 2)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Port contract (B4 — pure port-native, no projection meta) ──────────
// Pure bytes→bytes 8-byte fixed transform with no aux. Same shape as
// `des.initial-permutation@1` — IP and FP are exact inverses applied at
// the cipher boundary. B4 dropped the projection meta (bytes arrive on the
// `state` port via portInputs). byteLength: 8 honest declaration; no variant.

export const desFinalPermutationPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 8, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 8, layout: "raw" }]]),
};

const readTable = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.final-permutation requires params.table");
  }
  const p = params as { table?: unknown };
  if (!Array.isArray(p.table) || p.table.length !== 64) {
    throw new Error("des.final-permutation: table must be a 64-entry array");
  }
  return p.table as readonly number[];
};
