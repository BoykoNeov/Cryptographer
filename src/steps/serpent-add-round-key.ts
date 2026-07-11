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

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// Port-native executor (scaffolding-suppression Phase B, slice B3, 2026-05-30).
// Consumes and emits ONLY `Uint8Array`. Two input ports:
//   - `state`    — the carried 128-bit block, projected by the runtime from the
//                  threaded state via `meta.stateInputPort` (the Serpent specs
//                  are flat pipelines; no `portInputs` wiring).
//   - `roundKey` — this round's 16-byte key, projected by the runtime from
//                  `aux[params.roundKeyAux]` via `meta.auxReadPorts` (the
//                  still-lifted `serpent.key-expansion@1` writes those aux
//                  values). The runtime records the aux read on the frame from
//                  the same meta binding, so the executor no longer touches
//                  `ctx.aux` or returns `auxReads` — mirrors the B2 Speck round.
export const serpentAddRoundKey: PortedExecutor = (inputs) => {
  const stateBytes = inputs.get("state");
  if (stateBytes === undefined) {
    throw new Error(
      "serpent.add-round-key: 'state' input port is not wired (the runtime projects the carried block onto it via meta.stateInputPort)",
    );
  }
  if (stateBytes.length !== 16) {
    throw new Error(`serpent.add-round-key expects 16-byte state; got ${stateBytes.length} bytes`);
  }
  const rk = inputs.get("roundKey");
  if (!(rk instanceof Uint8Array) || rk.length !== 16) {
    throw new Error(
      "serpent.add-round-key: 'roundKey' port must carry a 16-byte word (projected from aux[roundKeyAux] via meta.auxReadPorts)",
    );
  }
  const next = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    next[i] = (stateBytes[i] ?? 0) ^ (rk[i] ?? 0);
  }
  return new Map([["state", next]]);
};

export const serpentAddRoundKeyDoc: StepDocumentation = {
  name: "Add Round Key (Serpent)",
  summary: "XOR a 16-byte round key into the 128-bit state.",
  detail: `## Add Round Key (Serpent)

The 128-bit state is XORed with the 128-bit round key stored under the named
slot. Round keys come from the Serpent key expansion and are named
\`roundKey.0\` … \`roundKey.32\` (33 of them, one more than the round count).

**Position in the round.** In a normal Serpent round, AddRoundKey comes
FIRST: \`AK → S-box → LT\`. The last round drops the LT and adds a second
AddRoundKey at the end: \`AK_31 → S_7 → AK_32\` — Serpent therefore consumes
33 round keys (K_0 … K_32) for 32 rounds.

**Inverse.** XOR is its own inverse. Decryption uses the same AddRoundKey
step, just consuming the round keys in reverse order.

**Permuted domain.** Round keys are held in the same permuted ("IP-applied")
arrangement as the state inside the round body — the key expansion applies IP
to each round key once, up front, so this XOR lines up bit-for-bit.`,
  params: new Map([
    [
      "roundKeyAux",
      'The name of the slot holding this round\'s 16-byte key — typically "roundKey.0" through "roundKey.32".',
    ],
  ]),
  references: [
    "Anderson, Biham, Knudsen 1998, §2 (Round function K_i XOR)",
    "Serpent NIST submission, tstsubmtl/serpref.c (keying() function)",
  ],
  shapeContract: { input: "bytes", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.7) ───────────────
// State-bearing single-aux-read step. Direct analog of AES's
// `generic.add-round-key@1` (Slice 1.4), but on a flat `bytes`-shape
// state (16 bytes for Serpent) rather than a `matrix4x4-bytes` state.
// Same lift adapter handles both: stateLayout encodes/decodes via the
// `bytes` codec; the aux-read binding is identical in shape (one named
// port → one named aux key, function form because the param names the
// round-specific aux key per-leaf).
//
// **byteLength: 16 honest declaration** — Serpent's state is always 128
// bits and round keys are always 128 bits across all three key sizes;
// no variant exists. Matches the AES Slice 1.4 posture for fixed-length
// cipher contracts (`aes.add-round-key@1` declares 16 on both ports).

export const serpentAddRoundKeyMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxReadPorts: (params: Json) => {
    const roundKeyAux = readRoundKeyAux(params);
    return new Map([["roundKey", roundKeyAux]]);
  },
};

export const serpentAddRoundKeyPortContract: PortContract = {
  inputs: new Map([
    ["state", { byteLength: 16, layout: "raw" }],
    ["roundKey", { byteLength: 16, layout: "raw" }],
  ]),
  outputs: new Map([["state", { byteLength: 16, layout: "raw" }]]),
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
