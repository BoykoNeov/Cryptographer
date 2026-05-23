/**
 * DES XOR with round key K_i. Inside F, between the expansion (E) and the
 * S-boxes. The 48-bit expanded R is XORed against the 48-bit round key
 * read from `aux[params.roundKeyAux]`.
 *
 * The round key was placed into aux by `des.key-schedule@1` (executed once
 * at the top of the cipher) as a `Uint8Array(6)` per round, keyed
 * `${outputPrefix}.0` … `${outputPrefix}.15`. The spec hard-codes which
 * round-key slot each round's XOR consumes via the `roundKeyAux` param.
 *
 * **Why a DES-specific step instead of reusing `generic.aux-xor@1`?**
 * `aux-xor` operates on the aux map (its result is an aux change, not a
 * state change); this step operates on STATE (the 6-byte R after E).
 * Different contract.
 */

import type {
  BytesState,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const desXorWithK: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "bytes") {
    throw new Error("des.xor-with-K expects bytes state");
  }
  if (state.bytes.length !== 6) {
    throw new Error(`des.xor-with-K expects 6-byte (48-bit) state; got ${state.bytes.length}`);
  }
  const auxName = readAuxName(params);
  const key = ctx.aux.get(auxName);
  if (!(key instanceof Uint8Array) || key.length !== 6) {
    throw new Error(
      `des.xor-with-K: aux['${auxName}'] must be a 6-byte Uint8Array (48-bit round key)`,
    );
  }
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) out[i] = (state.bytes[i] ?? 0) ^ (key[i] ?? 0);
  const next: BytesState = { shape: "bytes", bytes: out };
  return { state: next, auxReads: [auxName] };
};

export const desXorWithKDoc: StepDocumentation = {
  name: "XOR with K_i",
  summary: "XOR the 48-bit expanded R against the round key.",
  detail: `## XOR with K_i

The middle step of the F function: takes the 48-bit expansion of R (from
\`des.expand-R@1\`) and XORs it against the round key K_i, which is read
from \`aux[params.roundKeyAux]\`.

\`\`\`
output[i]  =  input[i]  XOR  K_i[i]      for i in 0..5
\`\`\`

The round key was produced once by \`des.key-schedule@1\` and stored in
aux under names like \`roundKey.0\` … \`roundKey.15\`. Each round's spec
node sets \`params.roundKeyAux\` to one of those names.

**Pedagogical note.** XOR is the cipher's "mix the secret into the data"
operation. The expansion before this step ensures the key bits influence
the S-box layer below in a *diffuse* way: each S-box's 6-bit input is
itself a mix of expanded data bits and round-key bits.`,
  params: new Map([
    [
      "roundKeyAux",
      "Aux key holding the 6-byte (48-bit) round key. Conventionally 'roundKey.{N}' for round N.",
    ],
  ]),
  references: ["FIPS 46-3 §3 (Cipher Function f)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.8) ───────────────
// State-bearing single-aux-read step. Direct analog of `aes.add-round-
// key@1` (Slice 1.4) and `serpent.add-round-key@1` (Slice 1.7), but on
// a 6-byte (48-bit, post-E expansion) `bytes`-shape state with a 6-byte
// round key. Same lift adapter handles all three: stateLayout encodes/
// decodes via the `bytes` codec; the aux-read binding is identical in
// shape (one named port → one named aux key, function form because the
// param names the round-specific aux key per-leaf).
//
// **byteLength: 6 honest declaration** on both state ports and the
// aux-read port — DES has no variant; expanded R is always 48 bits and
// round keys are always 48 bits. Matches the Serpent Slice 1.7 +
// AES Slice 1.4 posture.

export const desXorWithKMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (params: Json) => {
    const auxName = readAuxName(params);
    return new Map([["roundKey", auxName]]);
  },
};

export const desXorWithKPortContract: PortContract = {
  inputs: new Map([
    ["state", { byteLength: 6, layout: "raw" }],
    ["roundKey", { byteLength: 6, layout: "raw" }],
  ]),
  outputs: new Map([["state", { byteLength: 6, layout: "raw" }]]),
};

const readAuxName = (params: Json): string => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.xor-with-K requires params.roundKeyAux");
  }
  const p = params as { roundKeyAux?: unknown };
  if (typeof p.roundKeyAux !== "string" || p.roundKeyAux.length === 0) {
    throw new Error("des.xor-with-K: roundKeyAux must be a non-empty string");
  }
  return p.roundKeyAux;
};
