/**
 * Serpent AddRoundKey. XOR a 16-byte round key (read from aux) into the
 * 16-byte state, byte-wise.
 *
 * Distinct from `generic.add-round-key@1` because AES's add-round-key
 * operates on a `MatrixState` (4×4 column-major) while Serpent's state is
 * a flat `BytesState`. Keeping the two as separate step types lets each
 * carry shape-specific validation and means a future "load AES round key
 * into a Serpent spec" mistake fails the executor's shape check loudly
 * instead of producing silently-wrong output.
 *
 * Round keys are read from `aux[roundKeyAux]` (typically
 * `roundKey.0`..`roundKey.32`, produced by the Serpent key-expansion step).
 * Each is a 16-byte Uint8Array already in IP'd ("permuted") domain so the
 * XOR aligns with the IP'd state inside the round body.
 */

import type { BytesState, Json, StepDocumentation, StepExecutor } from "../core/types";

export const serpentAddRoundKey: StepExecutor = (state, params, ctx) => {
  if (state.shape !== "bytes") {
    throw new Error("serpent.add-round-key expects bytes state");
  }
  if (state.bytes.length !== 16) {
    throw new Error(`serpent.add-round-key expects 16-byte state; got ${state.bytes.length} bytes`);
  }
  const roundKeyAux = readRoundKeyAux(params);
  const rk = ctx.aux.get(roundKeyAux);
  if (!(rk instanceof Uint8Array) || rk.length !== 16) {
    throw new Error(`serpent.add-round-key: aux '${roundKeyAux}' must be a 16-byte Uint8Array`);
  }
  const next = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    next[i] = (state.bytes[i] ?? 0) ^ (rk[i] ?? 0);
  }
  const result: BytesState = { shape: "bytes", bytes: next };
  return { state: result, auxReads: [roundKeyAux] };
};

export const serpentAddRoundKeyDoc: StepDocumentation = {
  name: "Add Round Key (Serpent)",
  summary: "XOR a 16-byte round key into the 128-bit state.",
  detail: `## Add Round Key (Serpent)

The 128-bit state is bitwise-XORed with the 128-bit round key read from
the named aux entry. Round keys are produced by the Serpent key-expansion
step and named \`roundKey.0\` … \`roundKey.32\` (33 of them, one more
than the round count).

**Why a separate step from AES's AddRoundKey?** They are conceptually
identical — XOR a key into the state. They differ in *state shape*:
AES uses a 4×4 byte matrix (column-major); Serpent uses a flat 16-byte
buffer. Keeping the two step types separate gives each a shape-correct
validation path, and means the cipher type at each leaf is self-documenting.

**Position in the round.** In a normal Serpent round, AddRoundKey comes
FIRST: \`AK → S-box → LT\`. The last round drops the LT and adds a second
AddRoundKey at the end: \`AK_31 → S_7 → AK_32\` — Serpent therefore consumes
33 round keys (K_0 … K_32) for 32 rounds.

**Inverse.** XOR is its own inverse. Decryption uses the same AddRoundKey
step, just consuming the round keys in reverse order.

**Permuted domain.** Round keys are stored in the same permuted
("IP-applied") domain as the state inside the round body. The key-expansion
step applies IP to each round key once at expansion time so the XOR aligns
naturally — see \`serpent.key-expansion@1\` for the why.`,
  params: new Map([
    [
      "roundKeyAux",
      'Aux entry holding this round\'s 16-byte key. Typically "roundKey.0" through "roundKey.32".',
    ],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Round function K_i XOR)",
    "Serpent NIST submission, tstsubmtl/serpref.c (keying() function)",
  ],
};

const readRoundKeyAux = (params: Json): string => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.add-round-key requires params.roundKeyAux");
  }
  const p = params as { roundKeyAux?: unknown };
  if (typeof p.roundKeyAux !== "string" || p.roundKeyAux.length === 0) {
    throw new Error("serpent.add-round-key: roundKeyAux must be a non-empty string");
  }
  return p.roundKeyAux;
};
