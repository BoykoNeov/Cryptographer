/**
 * Serpent publish-round-keys — the meta-bearing aux-publish tail of the
 * decomposed Serpent key schedule (key-schedule-decomposition slice K3a,
 * 2026-06-02).
 *
 * Parallel to `aes.publish-round-keys@1` (K1a) and `speck.publish-round-keys@1`
 * (K2a) — same B-minimal pattern: the decomposed schedule above this step
 * computes every round key as VISIBLE port-native primitive frames
 * (recurrence → per-group S-box+IP), then this one tail leaf publishes the
 * finished round keys into `aux["roundKey.0..32"]` — byte-identical to what the
 * monolithic `serpent.key-expansion@1` wrote. So the round-body consumers
 * (`serpent.add-round-key@1` reading `aux[roundKeyAux]` via `meta.auxReadPorts`)
 * stay UNTOUCHED.
 *
 * **Why a separate step type, not reuse `aes.publish-round-keys@1`.** Two
 * structural differences:
 *
 *   1. **Round-key count.** AES emits `rounds + 1` round keys (varies with the
 *      AES variant / duplicate-round count); Speck emits `rounds`. Serpent
 *      emits a FIXED 33 round keys (K₀ … K₃₂) for ALL three key sizes — there
 *      is no `rounds` param to thread. The count is hardcoded 33 (overridable
 *      via an optional `count` param for symmetry with the siblings, but the
 *      builder always passes 33).
 *   2. **Round-key byte width.** Serpent round keys are always 16 bytes (the
 *      128-bit block). The port shape leaves `byteLength` polymorphic, matching
 *      the legacy `serpent.key-expansion@1` output-port posture.
 *
 * Contract: 33 input ports `key0`…`key32` (each wired from a `serpent.key-sbox`
 * producer) → identity passthrough to 33 output ports `key0`…`key32`;
 * `meta.auxWritePorts` mirrors `key${r} → aux[${outputPrefix}.${r}]`. No state
 * ports (aux-only — the carried block is preserved across the call, same as the
 * legacy `serpent.key-expansion@1`).
 *
 * params: {
 *   outputPrefix: string,   // e.g. "roundKey" → aux["roundKey.0..32"]
 *   count?: number,         // round-key count; defaults to 33 (Serpent's
 *                           // fixed K₀ … K₃₂). The builder passes 33 explicitly.
 * }
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

/** Serpent's fixed round-key count: K₀ … K₃₂ (33 keys) for every key size.
 *  Local (not exported) — the builder passes 33 explicitly via the `count`
 *  param; only this step's default resolution needs the constant. */
const SERPENT_ROUND_KEY_COUNT = 33;

type Params = {
  readonly outputPrefix: string;
  readonly count: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("serpent.publish-round-keys: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("serpent.publish-round-keys: params.outputPrefix must be a non-empty string");
  }
  // `count` defaults to 33 (Serpent's fixed K₀…K₃₂). Honored if supplied so
  // the param shape stays symmetric with the AES/Speck publish siblings.
  let count = SERPENT_ROUND_KEY_COUNT;
  if (p.count !== undefined) {
    if (typeof p.count !== "number" || !Number.isInteger(p.count) || p.count < 1) {
      throw new Error("serpent.publish-round-keys: params.count must be a positive integer (≥ 1)");
    }
    count = p.count;
  }
  return { outputPrefix: p.outputPrefix, count };
};

/**
 * Canonical input/output port name for round key `r`. Exported so the Serpent
 * key-schedule builder + tests reference the same string. Matches the
 * `aes`/`speck` publish-round-keys convention.
 */
export const serpentRoundKeyPortName = (r: number): string => `key${r}`;

/**
 * Identity passthrough: read each `key${r}` round key off its input port and
 * re-emit it on the same-named output port. The runtime's `meta.auxWritePorts`
 * step then mirrors every output port into `aux[${outputPrefix}.${r}]`.
 */
export const serpentPublishRoundKeys: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r < p.count; r++) {
    const name = serpentRoundKeyPortName(r);
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `serpent.publish-round-keys: input port "${name}" must carry a round key (wire from the schedule's key-sbox producers)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Both sides expose the same 33 round-key ports. Function form so a non-default
// `count` resolves. `byteLength` ABSENT — polymorphic, matching the legacy
// `serpent.key-expansion@1` output-port posture (Serpent round keys are always
// 16 bytes, but the legacy step left it undeclared and we match it).

const SERPENT_ROUND_KEY_PORT_SHAPE: PortShape = { layout: "raw" };

const serpentRoundKeyPortMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const p = readParams(params);
  const m = new Map<string, PortShape>();
  for (let r = 0; r < p.count; r++) {
    m.set(serpentRoundKeyPortName(r), SERPENT_ROUND_KEY_PORT_SHAPE);
  }
  return m;
};

export const serpentPublishRoundKeysPortContract: PortContract = {
  inputs: serpentRoundKeyPortMap,
  outputs: serpentRoundKeyPortMap,
};

// ─── Projection metadata (the one surviving meta in the Serpent schedule) ───
// Aux-only: no `stateInputPort` / `stateOutputPort` — the carried block is
// preserved across the call. `auxWritePorts` maps each output port to its
// `aux[${outputPrefix}.${r}]` key. Same exact fan-out the legacy
// `serpent.key-expansion@1` produced, so untouched `serpent.add-round-key@1`
// consumers read identical round keys.

export const serpentPublishRoundKeysMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const p = readParams(params);
    const bindings = new Map<string, string>();
    for (let r = 0; r < p.count; r++) {
      bindings.set(serpentRoundKeyPortName(r), `${p.outputPrefix}.${r}`);
    }
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const serpentPublishRoundKeysDoc: StepDocumentation = {
  name: "Publish round keys (Serpent)",
  summary: "Stores the finished Serpent round keys under names so each round can look up its key.",
  detail: `## Publish round keys (Serpent)

The last step of the Serpent key schedule. The recurrence and per-group
S-box/IP above it have already computed every round key; this step collects
them and stores each under a name — \`roundKey.0\` … \`roundKey.32\` — so each
round's AddRoundKey can look up its key. The 16-byte block being encrypted is
untouched; this step only files the round keys away.

**Serpent's fixed 33 round keys.** Serpent always uses exactly 33 round keys
(K₀ … K₃₂) for all three key sizes — 32 for the per-round AddRoundKey, plus one
extra (K₃₂) for the final round's second AddRoundKey.`,
  params: new Map([
    [
      "outputPrefix",
      'The name prefix for the round keys. With "roundKey", they are stored as roundKey.0 … roundKey.32.',
    ],
    ["count", "How many round keys to store — 33 for Serpent (K₀ … K₃₂)."],
  ]),
  references: ["Anderson, Biham, Knudsen 1998, §2 (Key Schedule — 33 round keys K₀ … K₃₂)"],
  shapeContract: { input: "any", output: "preserveInput" },
};
