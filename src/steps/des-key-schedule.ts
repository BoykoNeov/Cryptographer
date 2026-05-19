/**
 * DES Key Schedule. FIPS 46-3 §5 (Key Schedule Calculation).
 *
 * Expands the 64-bit master key into 16 round keys (each 48 bits) and
 * writes them to aux as `${outputPrefix}.0` … `${outputPrefix}.15` —
 * matching the convention `aes.key-expansion@1` and `serpent.key-expansion@1`
 * use, so the downstream UI (RoundKeyPanel) finds them by the same prefix.
 *
 * Algorithm:
 *   1. PC-1 applied to the 64-bit master key drops the 8 parity bits
 *      (positions 8, 16, …, 64) and reorders the remaining 56 into two
 *      28-bit halves C_0 and D_0.
 *   2. For each round r = 1..16:
 *      • C_r = left-rotate(C_{r-1}, SHIFTS[r-1])
 *      • D_r = left-rotate(D_{r-1}, SHIFTS[r-1])
 *      • K_r = PC-2(C_r || D_r)   — picks 48 of 56 bits
 *   3. Write K_r as `Uint8Array(6)` (the 48 bits packed MSB-first into 6
 *      bytes; trailing 0 in the last byte).
 *
 * State passthrough — the executor writes only to aux. Param `keyAuxName`
 * names the 8-byte master-key aux entry the runtime seeded before the
 * cipher ran; the App's input-seeding path puts the user's typed key under
 * the conventional name "key".
 *
 * Note on parity bits. PC-1 never references positions 8, 16, …, 64, so
 * flipping any of those 8 bits in the user-typed key produces an identical
 * key schedule. The cipher is "really" keyed on 56 bits; the 64-bit
 * presentation is FIPS-historical.
 */

import type { AuxValue, Json, StepContext, StepDocumentation, StepExecutor } from "../core/types";
import { bitsToFipsBytes, fipsBytesToBits, fipsPermute, rotateBitsLeft } from "./des-bit-ops";

type Params = {
  readonly keyAuxName: string;
  readonly outputPrefix: string;
  readonly pc1: readonly number[];
  readonly pc2: readonly number[];
  readonly shifts: readonly number[];
};

export const desKeySchedule: StepExecutor = (state, params, ctx: StepContext) => {
  const p = readParams(params);
  const key = ctx.aux.get(p.keyAuxName);
  if (!(key instanceof Uint8Array) || key.length !== 8) {
    throw new Error(
      `des.key-schedule: aux['${p.keyAuxName}'] must be an 8-byte Uint8Array (64-bit key)`,
    );
  }

  // PC-1: 64 → 56 bits. The result fits in 7 bytes (with 0 trailing bit).
  const cd = fipsPermute(key, p.pc1, 56);
  const cdBits = fipsBytesToBits(cd, 56);
  let C = cdBits.slice(0, 28);
  let D = cdBits.slice(28, 56);

  const auxWrites = new Map<string, AuxValue>();
  for (let r = 0; r < 16; r++) {
    const shift = p.shifts[r];
    if (shift === undefined) throw new Error(`des.key-schedule: shifts[${r}] missing`);
    C = rotateBitsLeft(C, shift, 28);
    D = rotateBitsLeft(D, shift, 28);
    // Concatenate C | D back into a 56-bit buffer (7 bytes), then PC-2 to 48.
    const cdConcat = bitsToFipsBytes([...C, ...D]);
    const K = fipsPermute(cdConcat, p.pc2, 48);
    auxWrites.set(`${p.outputPrefix}.${r}`, K);
  }

  return {
    state,
    auxWrites,
    auxReads: [p.keyAuxName],
  };
};

export const desKeyScheduleDoc: StepDocumentation = {
  name: "DES Key Schedule",
  summary: "Expand the 64-bit key into 16 × 48-bit round keys via PC-1, 16 shifts, PC-2.",
  detail: `## DES Key Schedule

Produces the 16 round keys K_1..K_16 from the 64-bit master key. State
passes through unchanged; every effect is in aux.

**Pipeline.**

1. **PC-1** (Permuted Choice 1): 64-bit key → 56-bit value, dropping the 8
   parity bits (positions 8, 16, 24, 32, 40, 48, 56, 64) and reordering
   the remaining 56 into two 28-bit halves C_0 and D_0.
2. **Per-round shifts**: for round r = 1..16, both halves rotate left by
   \`SHIFTS[r-1]\` bits. The cumulative shift total is 28, so C_16 = C_0
   (the schedule cycles back).
3. **PC-2** (Permuted Choice 2): 56-bit C_r || D_r → 48-bit round key K_r
   by picking 48 of the 56 bits in a fixed order.

**Output.** Each K_r is written to aux as a \`Uint8Array(6)\` under the
name \`\${outputPrefix}.{r-1}\`, e.g. \`roundKey.0\` … \`roundKey.15\`.
The 48 bits are MSB-first; the trailing 0 in the last byte is unused.

**Note on parity bits.** PC-1 never references positions 8, 16, 24, 32,
40, 48, 56, 64 — the standard's 8 "parity bits." Flipping any of them in
the user-typed master key produces an identical key schedule. DES is
"really" a 56-bit cipher; the 64-bit presentation is historical.

**Decrypt.** The same schedule produces the same K_1..K_16; decryption
consumes them in *reverse* order (K_16, K_15, …, K_1). The decrypt spec
references the same aux names but routes them backwards through the
rounds — see \`src/ciphers/des-decrypt.ts\`.`,
  params: new Map([
    ["keyAuxName", "Aux key holding the 8-byte master key. Conventionally 'key'."],
    [
      "outputPrefix",
      "Prefix for the 16 emitted round-key aux entries. Convention: 'roundKey' → roundKey.0..15.",
    ],
    ["pc1", "PC-1 table, 56 entries (FIPS 1-indexed). DES_PC1 in des-constants.ts."],
    ["pc2", "PC-2 table, 48 entries (FIPS 1-indexed). DES_PC2 in des-constants.ts."],
    ["shifts", "16-entry array of per-round left-shift amounts (1 or 2). DES_SHIFTS."],
  ]),
  references: ["FIPS 46-3 §5 (Key Schedule Calculation, Tables PC-1, PC-2)"],
  shapeContract: { input: "any", output: "preserveInput" },
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.key-schedule requires an object params");
  }
  const p = params as {
    keyAuxName?: unknown;
    outputPrefix?: unknown;
    pc1?: unknown;
    pc2?: unknown;
    shifts?: unknown;
  };
  if (typeof p.keyAuxName !== "string" || p.keyAuxName.length === 0) {
    throw new Error("des.key-schedule: keyAuxName must be a non-empty string");
  }
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("des.key-schedule: outputPrefix must be a non-empty string");
  }
  if (!Array.isArray(p.pc1) || p.pc1.length !== 56) {
    throw new Error("des.key-schedule: pc1 must be a 56-entry array");
  }
  if (!Array.isArray(p.pc2) || p.pc2.length !== 48) {
    throw new Error("des.key-schedule: pc2 must be a 48-entry array");
  }
  if (!Array.isArray(p.shifts) || p.shifts.length !== 16) {
    throw new Error("des.key-schedule: shifts must be a 16-entry array");
  }
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    pc1: p.pc1 as readonly number[],
    pc2: p.pc2 as readonly number[],
    shifts: p.shifts as readonly number[],
  };
};
