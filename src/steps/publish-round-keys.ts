/**
 * Publish round keys — the meta-bearing aux-publish tail of the decomposed
 * AES key schedule (key-schedule-decomposition plan, Slice K1a, 2026-06-01).
 *
 * B-minimal design: the decomposed key schedule computes the round keys with
 * VISIBLE port-native primitive frames (RotWord/SubWord/Rcon/word-XOR →
 * concat → byte-slice), then this one tail leaf publishes the finished round
 * keys into `aux["roundKey.0".."roundKey.N"]` — byte-identical to what the
 * monolithic `aes.key-expansion@1` wrote. So the round-body consumers
 * (`xor-with-aux@1` AddRoundKeys) and `aes-round-builder-native.ts` stay
 * UNTOUCHED; only the producer is decomposed.
 *
 * This is deliberately the ONLY surviving `meta` in the key schedule — the
 * recurrence math above it is all pure port-native. It reuses the existing
 * `meta.auxWritePorts` aux-write path (the same one the monolith used) rather
 * than a new pure-port aux-writer primitive, keeping the slice's runtime risk
 * at zero. The full meta retirement (each round key on an explicit output
 * port, consumers rewired) is the gated option-A follow-on, not this step.
 *
 * Contract: N+1 input ports `key0`…`keyN` (each a 16-byte round key, wired
 * from the repack `byte-slice@1` leaves) → identity passthrough to N+1 output
 * ports `key0`…`keyN`; `meta.auxWritePorts` mirrors `key${r} →
 * aux[${outputPrefix}.${r}]`. No state ports (aux-only — the carried block is
 * preserved across the call, same as the monolith).
 *
 * params: {
 *   outputPrefix: string,   // e.g. "roundKey" → aux["roundKey.0".."roundKey.N"]
 *   rounds: number,         // Nr; emits rounds+1 round keys (key0..key{rounds})
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

type Params = {
  readonly outputPrefix: string;
  readonly rounds: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aes.publish-round-keys: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string") {
    throw new Error("aes.publish-round-keys: params.outputPrefix must be a string");
  }
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("aes.publish-round-keys: params.rounds must be a positive integer (≥ 1)");
  }
  return { outputPrefix: p.outputPrefix, rounds: p.rounds };
};

/** Canonical input/output port name for round key `r`. Exported so the
 *  key-schedule builder + tests reference the same string. */
export const roundKeyPortName = (r: number): string => `key${r}`;

/**
 * Identity passthrough: read each `key${r}` round key off its input port and
 * re-emit it on the same-named output port. The runtime's `meta.auxWritePorts`
 * step then mirrors every output port into `aux[${outputPrefix}.${r}]`.
 */
export const publishRoundKeys: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r <= p.rounds; r++) {
    const name = roundKeyPortName(r);
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `aes.publish-round-keys: input port "${name}" must carry a round key (wire it from the repack byte-slice)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Both sides are the same N+1 round-key ports (16 bytes each). Function form
// because the count grows with `params.rounds` — same posture as the
// monolithic key-expansion's per-round-key outputs.

const ROUND_KEY_PORT_SHAPE: PortShape = { byteLength: 16, layout: "raw" };

const roundKeyPortMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const p = readParams(params);
  const m = new Map<string, PortShape>();
  for (let r = 0; r <= p.rounds; r++) {
    m.set(roundKeyPortName(r), ROUND_KEY_PORT_SHAPE);
  }
  return m;
};

export const publishRoundKeysPortContract: PortContract = {
  inputs: roundKeyPortMap,
  outputs: roundKeyPortMap,
};

// ─── Projection metadata (the one surviving meta in the key schedule) ─────────
// Aux-only: no `stateInputPort` / `stateOutputPort` (the carried block is
// preserved across the call). `auxWritePorts` maps each output port to its
// `aux[${outputPrefix}.${r}]` key — the exact fan-out the monolith produced,
// so the untouched round-body consumers read identical round keys.

export const publishRoundKeysMeta: ProjectionMetadata = {
  // Ceremonial — the type requires it but the runtime never consults it for an
  // aux-only step (no state ports). Matches `keyExpansionMeta`.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const p = readParams(params);
    const bindings = new Map<string, string>();
    for (let r = 0; r <= p.rounds; r++) {
      bindings.set(roundKeyPortName(r), `${p.outputPrefix}.${r}`);
    }
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const publishRoundKeysDoc: StepDocumentation = {
  name: "Publish round keys",
  summary: "Write the derived round keys into the aux map (roundKey.0 … roundKey.Nr).",
  detail: `## Publish round keys

The tail of the decomposed AES key schedule. The recurrence above this step
has already computed every round key as visible port-native frames; this leaf
takes the finished round keys on its input ports \`key0\` … \`keyN\` and
publishes them into the aux map as \`${"`"}\${outputPrefix}.0${"`"}\` …
\`${"`"}\${outputPrefix}.Nr${"`"}\` (typically \`roundKey.0\` … \`roundKey.Nr\`).

The per-round AddRoundKey steps read those aux entries unchanged — so
decomposing the key schedule into visible math did not touch the round body
at all. The state (the carried block) passes through this step untouched; the
work product lives entirely in the aux map.`,
  params: new Map([
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With "roundKey", outputs are roundKey.0 … roundKey.Nr.',
    ],
    ["rounds", "Number of cipher rounds Nr. Emits rounds+1 round keys (key0 … key{rounds})."],
  ]),
  references: ["FIPS-197 §5.2 (Key Expansion — round-key derivation)"],
  shapeContract: { input: "any", output: "preserveInput" },
};
