/**
 * DES Key Schedule. FIPS 46-3 §5 (Key Schedule Calculation).
 *
 * Expands the 64-bit master key into 16 round keys (each 48 bits). Port-native
 * `PortedExecutor` (Slice 5.2 — universal-port Phase 5): the master key
 * arrives on the `masterKey` input port and each round key leaves on an output
 * port `key0` … `key15`. The registration KEEPS `meta` (NOT a lift adapter):
 * the runtime projects `aux[keyAuxName] → masterKey` and `key${r} →
 * aux[${outputPrefix}.${r}]`, matching the convention `aes.key-expansion@1`
 * and `serpent.key-expansion@1` use — so the downstream UI (RoundKeyPanel)
 * finds the round keys by the same prefix and the emitted frame's
 * `auxRead`/`auxWritten` stay byte-identical to the former lifted path.
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
 * No state port — the work product is the 16 round keys on the `key*` output
 * ports. Param `keyAuxName` names the 8-byte master-key aux entry the runtime
 * projects onto the `masterKey` input port (via `meta.auxReadPorts`); the
 * App's input-seeding path puts the user's typed key under the conventional
 * name "key".
 *
 * Note on parity bits. PC-1 never references positions 8, 16, …, 64, so
 * flipping any of those 8 bits in the user-typed key produces an identical
 * key schedule. The cipher is "really" keyed on 56 bits; the 64-bit
 * presentation is FIPS-historical.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";
import { bitsToFipsBytes, fipsBytesToBits, fipsPermute, rotateBitsLeft } from "./des-bit-ops";

type Params = {
  readonly keyAuxName: string;
  readonly outputPrefix: string;
  readonly pc1: readonly number[];
  readonly pc2: readonly number[];
  readonly shifts: readonly number[];
};

export const desKeySchedule: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  // Port-native (Slice 5.2): the master key arrives on the `masterKey` input
  // port, projected from `aux[keyAuxName]` via `meta.auxReadPorts`.
  const key = inputs.get("masterKey");
  if (!(key instanceof Uint8Array) || key.length !== 8) {
    throw new Error(
      "des.key-schedule: 'masterKey' port must carry an 8-byte (64-bit) master key (projected from aux[keyAuxName] via meta.auxReadPorts)",
    );
  }

  // PC-1: 64 → 56 bits. The result fits in 7 bytes (with 0 trailing bit).
  const cd = fipsPermute(key, p.pc1, 56);
  const cdBits = fipsBytesToBits(cd, 56);
  let C = cdBits.slice(0, 28);
  let D = cdBits.slice(28, 56);

  // One round key per output port (`key0` … `key15`); the runtime maps
  // `key${r}` → `aux[${outputPrefix}.${r}]` via `meta.auxWritePorts`, so
  // `frame.auxWritten` still carries the `roundKey.*` entries.
  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r < 16; r++) {
    const shift = p.shifts[r];
    if (shift === undefined) throw new Error(`des.key-schedule: shifts[${r}] missing`);
    C = rotateBitsLeft(C, shift, 28);
    D = rotateBitsLeft(D, shift, 28);
    // Concatenate C | D back into a 56-bit buffer (7 bytes), then PC-2 to 48.
    const cdConcat = bitsToFipsBytes([...C, ...D]);
    const K = fipsPermute(cdConcat, p.pc2, 48);
    outputs.set(`key${r}`, K);
  }

  return outputs;
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

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.8) ───────────────
// DES key-schedule is the FOURTH one-to-many writer in the universal-port
// migration (after AES key-expansion in 1.4, Speck key-schedule in 1.6,
// and Serpent key-expansion in 1.7). Same Decision B shape — one output
// port per round key — applied to DES's 16 round keys (K_1 … K_16,
// 0-indexed as K_0 … K_15 in our aux convention). The count is FIXED at
// 16 across the algorithm — DES has no key-size variant (the 64-bit
// master key reduces to 56 effective bits via PC-1 regardless).
//
// **Function form despite the fixed count** — kept for uniformity with
// the AES/Speck/Serpent precedents and so `outputPrefix` (the per-spec
// aux name prefix) still threads through `auxWritePorts(params)` cleanly.
//
// **byteLength absent on output ports** per user pick 2026-05-23 —
// matches Slice 1.6 Speck + Slice 1.7 Serpent posture uniformly across
// the round-key port batch ("absent everywhere unless a fixed reason"),
// even though DES round-key length is fixed at 6 bytes (48 bits each).
//
// **Aux-only**: `stateInputPort` and `stateOutputPort` are intentionally
// OMITTED. DES key-schedule's `shapeContract` is
// `input: "any", output: "preserveInput"` — the executor returns state
// unmodified (`return { state, auxWrites, auxReads }`). Matches the
// aux-only lift pattern from Slice 1.2 (iv-load, aux-load, …) +
// Slice 1.4 (AES key-expansion) + Slice 1.6 (Speck key-schedule) +
// Slice 1.7 (Serpent key-expansion). The lift adapter creates a sentinel
// zero-length `bytes`-shape state for the legacy executor and discards
// its passthrough return; the runtime preserves the caller's actual
// state across the ported call so the subsequent leaf (typically the
// first `des.initial-permutation@1` of the spec) sees its incoming
// 8-byte block unchanged.
//
// **Master-key input port `masterKey`** — disambiguates from the per-
// round output ports `key0`, `key1`, …, `key15`. Same convention as
// AES/Speck/Serpent key-schedules. **byteLength: 8** because DES has
// NO variant — the master key is always 64 bits per FIPS 46-3. This
// is different from AES (variant 16/24/32) and Serpent (variant 16/24/32)
// which leave master-key byteLength absent; it matches the AES Slice
// 1.4 + Serpent Slice 1.7 posture "honest fixed declaration when no
// variant" for state ports, extended to the master-key input port here
// since DES is the first fixed-key-size cipher to land.

const DES_ROUND_KEY_COUNT = 16;

const desKeyScheduleOutputPorts = (_params: Json) => {
  // Output count is hardcoded at 16 in the executor (the K_0 … K_15 loop).
  // Function-form contract for uniformity with the AES/Speck/Serpent
  // precedents even though _params is unused here. Map iteration is
  // insertion-ordered in JS — bindings emerge in r = 0 … 15 order,
  // matching the legacy executor's auxWrites insertion order. The
  // frame-parity test pins this.
  const m = new Map<string, PortShape>();
  for (let i = 0; i < DES_ROUND_KEY_COUNT; i++) {
    m.set(`key${i}`, { layout: "raw" });
  }
  return m;
};

const desKeyScheduleAuxWritePorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.key-schedule auxWritePorts: params must be an object");
  }
  const p = params as { outputPrefix?: unknown };
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error(
      "des.key-schedule auxWritePorts: params.outputPrefix: non-empty string required",
    );
  }
  const bindings = new Map<string, string>();
  for (let i = 0; i < DES_ROUND_KEY_COUNT; i++) {
    bindings.set(`key${i}`, `${p.outputPrefix}.${i}`);
  }
  return bindings;
};

const desKeyScheduleAuxReadPorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.key-schedule auxReadPorts: params must be an object");
  }
  const p = params as { keyAuxName?: unknown };
  if (typeof p.keyAuxName !== "string" || p.keyAuxName.length === 0) {
    throw new Error("des.key-schedule auxReadPorts: params.keyAuxName: non-empty string required");
  }
  return new Map([["masterKey", p.keyAuxName]]);
};

export const desKeyScheduleMeta: ProjectionMetadata = {
  // Aux-only step — no state ports. `stateLayout: "bytes"` is the
  // ceremonial value the type requires; the lift adapter never consults
  // it because neither `stateInputPort` nor `stateOutputPort` is
  // declared. Same pattern as AES/Speck/Serpent key-schedules.
  stateLayout: "bytes",
  auxReadPorts: desKeyScheduleAuxReadPorts,
  auxWritePorts: desKeyScheduleAuxWritePorts,
};

export const desKeySchedulePortContract: PortContract = {
  // Static `inputs`: just the master key. No state input port —
  // shapeContract is `input: "any"`. byteLength: 8 — DES's master key
  // is fixed at 64 bits; no variant exists. Honest declaration.
  inputs: new Map<string, PortShape>([["masterKey", { byteLength: 8, layout: "raw" }]]),
  // Dynamic outputs: 16 ports (`key0` … `key15`), function-form for
  // uniformity with AES/Speck/Serpent precedents. byteLength absent per
  // user pick (uniform with the round-key port batch posture, even
  // though DES round keys are fixed at 6 bytes).
  outputs: desKeyScheduleOutputPorts,
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
