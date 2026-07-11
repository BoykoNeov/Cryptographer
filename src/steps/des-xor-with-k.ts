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
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

/**
 * Port-native hybrid since B4 (universal-port Phase 4d DES rebuild) — the
 * `xor-with-aux@1` shape applied to DES. The 6-byte expanded R arrives on
 * the `state` input port (wired from `des.expand-R@1`); the 6-byte round key
 * is auto-projected onto the `roundKey` port by the runtime from
 * `aux[params.roundKeyAux]` (declared in `meta.auxReadPorts`) — which also
 * records the key-schedule → round fan-out as a `frame.auxRead`. Emits
 * `state ⊕ roundKey` on the `state` output port. Like the B2/B3 native
 * rounds, the executor returns ONLY state; the auxRead is recorded from meta.
 */
export const desXorWithK: PortedExecutor = (inputs, params) => {
  readAuxName(params); // validate params.roundKeyAux is present + well-formed
  const stateBytes = inputs.get("state");
  if (stateBytes === undefined) {
    throw new Error("des.xor-with-K: missing required input port 'state'");
  }
  if (stateBytes.length !== 6) {
    throw new Error(`des.xor-with-K expects 6-byte (48-bit) state; got ${stateBytes.length}`);
  }
  const key = inputs.get("roundKey");
  if (key === undefined) {
    throw new Error(
      "des.xor-with-K: operand port 'roundKey' not available — the runtime projects aux[params.roundKeyAux] onto the 'roundKey' port via meta.auxReadPorts; check that aux[roundKeyAux] is populated by des.key-schedule@1",
    );
  }
  if (key.length !== 6) {
    throw new Error(
      `des.xor-with-K: roundKey (aux value) must be 6 bytes (48-bit round key); got ${key.length}`,
    );
  }
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) out[i] = (stateBytes[i] ?? 0) ^ (key[i] ?? 0);
  return new Map([["state", out]]);
};

export const desXorWithKDoc: StepDocumentation = {
  name: "XOR with K_i",
  summary: "XOR the 48-bit expanded R against the round key.",
  detail: `## XOR with K_i

The middle step of the F function: takes the 48-bit expansion of R and XORs
it against this round's key K_i.

\`\`\`
output[i]  =  input[i]  XOR  K_i[i]      for i in 0..5
\`\`\`

The round keys were produced once by the DES key schedule and stored under
names \`roundKey.0\` … \`roundKey.15\`; each round picks the one it needs.

**Pedagogical note.** XOR is the cipher's "mix the secret into the data"
operation. The expansion before this step ensures the key bits influence
the S-box layer below in a *diffuse* way: each S-box's 6-bit input is
itself a mix of expanded data bits and round-key bits.`,
  params: new Map([
    [
      "roundKeyAux",
      "The name of the slot holding this round's 48-bit key — conventionally 'roundKey.N' for round N.",
    ],
  ]),
  references: ["FIPS 46-3 §3 (Cipher Function f)"],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Projection metadata (B4 — hybrid port-native, aux-read only) ───────
// B4 dropped `stateInputPort`/`stateOutputPort`: the 6-byte expanded R now
// arrives on the `state` PORT via the spec's `portInputs` (wired from
// `des.expand-R@1`), not the legacy state thread. What REMAINS is
// `auxReadPorts` — the runtime projects `aux[roundKeyAux]` onto the
// `roundKey` port before the executor runs AND records it in
// `frame.auxRead`, preserving the key-schedule → round fan-out edge. This
// is exactly the `xor-with-aux@1` hybrid shape (meta present, no legacy, no
// stateInputPort). `stateLayout: "bytes"` is the defensive default the
// runtime's projection contract requires of any meta-bearing ported
// registration. byteLength: 6 honest declaration; DES has no variant.

export const desXorWithKMeta: ProjectionMetadata = {
  stateLayout: "bytes",
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
