/**
 * byte-substitute — port-native S-box substitution primitive
 * (scaffolding-suppression plan Phase B Slice B1.1, 2026-05-29).
 *
 * `output[i] = sbox[input[i]]` for every byte of the input port. One raw
 * input port `input`, one raw output port `output`, polymorphic byteLength
 * (the substitution is position-preserving, so output length == input
 * length). The 256-entry table rides in `params.sbox`.
 *
 * **The byte-native replacement for `generic.byte-substitution@1`.** The
 * legacy step consumed/emitted a `MatrixState` (its PortContract declared
 * `layout: "matrix-cm-4x4"`), which is exactly the scaffolding the
 * scaffolding-suppression plan exists to remove (A4 anti-creep allowlist).
 * This primitive does the identical math on a flat `Uint8Array` — SubBytes
 * is purely byte-local, so the column-major 4×4 interpretation never
 * mattered to the computation, only to the (deferred, Phase C2) rendering.
 *
 * **Forward AND inverse.** AES SubBytes uses the forward S-box; InvSubBytes
 * uses `AES_INV_SBOX`. Same primitive, table differs — proof the registry
 * abstraction holds (no separate "inverse" step type). The cross-mode
 * mirror (class-2 inverse) operates on `params.sbox`, re-pointed here from
 * `generic.byte-substitution@1` in Slice B1.2.
 *
 * **Why `sbox` is a param, not a wired aux input (B1 scope decision).**
 * `aes.key-expansion@1` also consumes the forward S-box (SubWord) and stays
 * monolithic in B1, so moving only the round-body S-box to `cipherConstants`
 * would let an edit change SubBytes but not SubWord — the divergence the A1
 * lockstep lesson forbids. Keeping it a param matches today's behaviour (the
 * round S-box and the key-expansion S-box are already independent params).
 * The single-aux-cell unification waits for the key-expansion decomposition
 * slice, which can move both consumers together.
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * omit `meta`, omit `shapeContract`. Static port maps with `layout:"raw"`
 * (no param dependence) so the A4 anti-creep contract's kitchen-sink param
 * resolution never needs an `sbox` entry. Same posture as `xor.ts`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly sbox: readonly number[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("byte-substitute: params must be an object");
  }
  const p = params as Record<string, Json>;
  const sbox = p.sbox;
  if (!Array.isArray(sbox) || sbox.length !== 256) {
    throw new Error("byte-substitute: params.sbox must be an array of 256 numbers (0..255)");
  }
  return { sbox: sbox as readonly number[] };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Static maps on both sides — the port COUNT and layout are fixed (one raw
 * input, one raw output); only the values flow at run time. Polymorphic
 * byteLength: SubBytes preserves length, and the actual length is fixed by
 * the consumer's wiring (16 for AES). `layout:"raw"` keeps the leaf off the
 * A4 `NON_BYTES_ALLOWLIST` — the whole point of the rebuild.
 */
export const byteSubstitutePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const byteSubstitute: PortedExecutor = (inputs, params, _ctx) => {
  const { sbox } = readParams(params);
  const input = inputs.get("input");
  if (input === undefined) {
    throw new Error('byte-substitute: input port "input" is not wired');
  }
  // Fresh buffer — outputs own their bytes (the runtime treats them as
  // freshly-owned; sharing would couple downstream mutation back to the
  // wired source).
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) {
    out[i] = sbox[input[i] as number] ?? 0;
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const byteSubstituteDoc: StepDocumentation = {
  name: "Byte Substitute",
  summary:
    "Replace every input byte b with sbox[b] using a 256-entry lookup table. Port-native, byte-flat.",
  detail: `# Byte Substitute

Port-native S-box substitution. Each byte \`b\` on the \`input\` port is
replaced with \`sbox[b]\`, where \`sbox\` is a 256-entry permutation supplied
in \`params.sbox\`. The substitution is applied **independently** to every
byte, so the step is purely position-preserving and purely byte-local.

## Math

For each byte position \`i\`:

\`\`\`
output[i] = sbox[input[i]]
\`\`\`

## Why it matters

When the lookup table is **non-linear** (the map \`b → sbox[b]\` is not
affine over GF(2)), this is the only step in many modern ciphers that
resists differential and linear cryptanalysis — the non-linearity is what
makes the cipher resemble a random function rather than a structured
algebraic one.

In **AES** this is **SubBytes** (FIPS-197 §5.1.1); the inverse round uses
the same primitive with the inverse table (**InvSubBytes**, §5.3.2). The
AES S-box is the multiplicative inverse in GF(2⁸) followed by an affine
transform over GF(2). Swapping it for the identity permutation (try it!)
breaks the cipher's security entirely while leaving the structure intact.

## Where it fits

- **AES SubBytes / InvSubBytes** — forward table vs \`AES_INV_SBOX\`.
- Any cipher doing table-driven byte substitution can reuse this with its
  own table (Serpent's 4-bit S-boxes use a different, bit-sliced step).

## Errors

- Throws if \`params.sbox\` is missing or not a 256-element array.
- Throws if the \`input\` port is not wired.`,
  params: new Map([
    [
      "sbox",
      "256-entry array of bytes (0..255). Must be a permutation for the cipher to be invertible.",
    ],
  ]),
  references: ["FIPS-197 §5.1.1 (SubBytes)", "FIPS-197 §5.3.2 (InvSubBytes)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
