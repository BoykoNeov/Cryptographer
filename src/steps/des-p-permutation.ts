/**
 * DES Post-S-box Permutation (P). FIPS 46-3 Table P.
 *
 * Permutes the 32 bits of the S-box output. Applied as the last step of
 * the F function, between the S-boxes and the rejoin XOR (`L ⊕ F(R)`).
 *
 * Unlike IP/FP, P has real cryptographic value: it spreads each S-box's
 * 4-bit output across multiple input bits of the *next* round's S-boxes
 * (via the next round's expansion E). Without P, each S-box would only
 * influence itself across rounds; with P, after ~5 rounds every output bit
 * depends on every input bit (the "avalanche" property).
 *
 * Same convention as IP/FP/E: bits 1-indexed, MSB-first. Output bit `i`
 * reads input bit `table[i-1]`. The standard `DES_P` lives in
 * `src/ciphers/des-constants.ts`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { fipsPermute } from "./des-bit-ops";

/**
 * Port-native since B4 (universal-port Phase 4d DES rebuild). Reads the
 * 4-byte S-box output from the `state` input port and emits the permuted
 * F-function result on the `state` output port (consumed by the round's
 * `L ⊕ F` xor leaf).
 */
export const desPPermutation: PortedExecutor = (inputs, params) => {
  const bytes = inputs.get("state");
  if (bytes === undefined) {
    throw new Error("des.p-permutation: missing required input port 'state'");
  }
  if (bytes.length !== 4) {
    throw new Error(`des.p-permutation expects 4-byte (32-bit) state; got ${bytes.length} bytes`);
  }
  const table = readTable(params);
  return new Map([["state", fipsPermute(bytes, table, 32)]]);
};

export const desPPermutationDoc: StepDocumentation = {
  name: "P Permutation",
  summary: "Permute the 32 S-box output bits per FIPS 46-3 Table P.",
  detail: `## P Permutation

Permutes the 32 bits of the S-box output:

\`\`\`
output_bit[i]  =  input_bit[table[i - 1]]      for i in 1..32
\`\`\`

**Cryptographic purpose.** Unlike IP/FP (which exist for hardware-era
reasons), P does real work. It spreads each S-box's 4-bit output across
the next round's S-box inputs via the round's expansion E. After about
5 rounds, every output bit depends on every input bit — the "avalanche"
effect that makes DES resistant to differential cryptanalysis when the
key is unknown.

The full F function is therefore: \`F(R, K) = P(S(E(R) ⊕ K))\`. P is its last
step, just before the result is XORed into the other half of the block.`,
  params: new Map([
    [
      "table",
      "The 32-entry permutation: for each output bit, which S-box output bit it comes from.",
    ],
  ]),
  references: ["FIPS 46-3 §3 (Permutation Function P, Table P)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Port contract (B4 — pure port-native, no projection meta) ──────────
// Pure bytes→bytes 4-byte fixed transform with no aux. Runs at the end of
// F, mapping the 32-bit S-box output back to 32 permuted bits before the
// `L ⊕ F` xor. B4 dropped the projection meta (bytes arrive on the `state`
// port via portInputs). byteLength: 4 honest declaration; no variant.

export const desPPermutationPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 4, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 4, layout: "raw" }]]),
};

const readTable = (params: Json): readonly number[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.p-permutation requires params.table");
  }
  const p = params as { table?: unknown };
  if (!Array.isArray(p.table) || p.table.length !== 32) {
    throw new Error("des.p-permutation: table must be a 32-entry array");
  }
  return p.table as readonly number[];
};
