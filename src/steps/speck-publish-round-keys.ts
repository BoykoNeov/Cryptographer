/**
 * Speck publish-round-keys — the meta-bearing aux-publish tail of the
 * decomposed Speck32/64 key schedule (key-schedule-decomposition K2a,
 * 2026-06-01).
 *
 * Parallel to `aes.publish-round-keys@1` (the K1a tail) — same B-minimal
 * pattern: the decomposed schedule above this step computes every round-key
 * word as VISIBLE port-native primitive frames, then this one tail leaf
 * publishes the finished round keys into `aux["roundKey.0..rounds-1"]` —
 * byte-identical to what the monolithic `speck.key-schedule@1` wrote. So
 * the round-body consumers (`speck.round@1` reading `aux[roundKeyAux]` via
 * `meta.auxReadPorts`) stay UNTOUCHED.
 *
 * **Why a separate step type, not reuse `aes.publish-round-keys@1`.** Two
 * load-bearing structural differences flagged by the K2 advisor pass
 * (2026-06-01):
 *
 *   1. **Round-key count.** AES emits `rounds + 1` round keys (an initial
 *      AddRoundKey plus one per round); Speck emits exactly `rounds` (each
 *      round consumes one round-key word, no initial pre-round key). The
 *      loop bound differs by one: AES iterates `r in 0..rounds`, Speck
 *      iterates `r in 0..rounds-1`. The aux-key index range correspondingly
 *      shifts.
 *   2. **Round-key byte width.** AES round keys are always 16 bytes (the
 *      block size — `byteLength: 16` is hardcoded in the AES tail's port
 *      shape). Speck32/64 round keys are 2 bytes; larger Speck variants
 *      vary (Speck64/128 = 4 bytes, Speck128/256 = 8 bytes). The port
 *      shape declares no fixed `byteLength` — polymorphic across Speck
 *      variants, matching the existing legacy `speck.key-schedule@1` and
 *      `speck.round@1` polymorphic-byteLength convention.
 *
 * Reusing the AES step type would require either (a) adding a "mode" flag
 * for the count delta or (b) loosening the AES port shape — both would
 * confuse the palette and obscure the parallel-name pattern that K3/K4
 * will continue.
 *
 * Contract: N input ports `key0`…`key{rounds-1}` (each wired from a
 * round-key producer — typically `g{i-1}.new-k` for `i ≥ 1` or the
 * master-key first word for `i = 0`) → identity passthrough to N
 * output ports `key0`…`key{rounds-1}`; `meta.auxWritePorts` mirrors
 * `key${r} → aux[${outputPrefix}.${r}]`. No state ports (aux-only — the
 * carried block is preserved across the call, same as the legacy
 * `speck.key-schedule@1`).
 *
 * params: {
 *   outputPrefix: string,   // e.g. "roundKey" → aux["roundKey.0..rounds-1"]
 *   rounds: number,         // Total round-key count; emits rounds keys
 *                           // (key0..key{rounds-1}). Speck32/64 = 22.
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
    throw new Error("speck.publish-round-keys: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string") {
    throw new Error("speck.publish-round-keys: params.outputPrefix must be a string");
  }
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("speck.publish-round-keys: params.rounds must be a positive integer (≥ 1)");
  }
  return { outputPrefix: p.outputPrefix, rounds: p.rounds };
};

/**
 * Canonical input/output port name for round key `r`. Exported so the
 * Speck key-schedule builder + tests reference the same string. Matches
 * `aes.publish-round-keys@1`'s `roundKeyPortName` convention.
 */
export const speckRoundKeyPortName = (r: number): string => `key${r}`;

/**
 * Identity passthrough: read each `key${r}` round-key word off its input
 * port and re-emit it on the same-named output port. The runtime's
 * `meta.auxWritePorts` step then mirrors every output port into
 * `aux[${outputPrefix}.${r}]`. Identical executor shape to the AES tail,
 * with `r in [0, rounds)` instead of `[0, rounds]` — the off-by-one is
 * the structural difference.
 */
export const speckPublishRoundKeys: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  // Speck loop bound: r < rounds. AES iterates r <= rounds (Nr + 1 keys);
  // Speck has no initial pre-round key, so emits exactly `rounds` keys
  // (key0..key{rounds-1}).
  for (let r = 0; r < p.rounds; r++) {
    const name = speckRoundKeyPortName(r);
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `speck.publish-round-keys: input port "${name}" must carry a round-key word (wire from the schedule's new-k producers)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Both sides expose the same N round-key ports. Function form because the
// count varies with `params.rounds`. `byteLength` ABSENT — polymorphic across
// Speck variants (Speck32/64 = 2 bytes per round key; Speck64/128 = 4 bytes;
// Speck128/256 = 8 bytes). Same convention as the legacy `speck.key-schedule@1`
// and `speck.round@1` port shapes.

const SPECK_ROUND_KEY_PORT_SHAPE: PortShape = { layout: "raw" };

const speckRoundKeyPortMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const p = readParams(params);
  const m = new Map<string, PortShape>();
  for (let r = 0; r < p.rounds; r++) {
    m.set(speckRoundKeyPortName(r), SPECK_ROUND_KEY_PORT_SHAPE);
  }
  return m;
};

export const speckPublishRoundKeysPortContract: PortContract = {
  inputs: speckRoundKeyPortMap,
  outputs: speckRoundKeyPortMap,
};

// ─── Projection metadata (the one surviving meta in the Speck schedule) ─────
// Aux-only: no `stateInputPort` / `stateOutputPort` — the carried block is
// preserved across the call. `auxWritePorts` maps each output port to its
// `aux[${outputPrefix}.${r}]` key. Same exact fan-out the legacy
// `speck.key-schedule@1` produced, so untouched `speck.round@1` consumers
// read identical round keys.

export const speckPublishRoundKeysMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only
  // step (no state ports).
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const p = readParams(params);
    const bindings = new Map<string, string>();
    for (let r = 0; r < p.rounds; r++) {
      bindings.set(speckRoundKeyPortName(r), `${p.outputPrefix}.${r}`);
    }
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const speckPublishRoundKeysDoc: StepDocumentation = {
  name: "Publish round keys (Speck)",
  summary:
    "Stores the finished Speck round-key words under names so each round can look up its key.",
  detail: `## Publish round keys (Speck)

The last step of the Speck key schedule. The ARX recurrence above it has
already computed every round-key word; this step collects them and stores
each under a name — \`roundKey.0\` … \`roundKey.{rounds-1}\` — so each round
can look up the key word it needs. The 2-word block being encrypted is
untouched; this step only files the round keys away.

**How many keys.** Speck has no initial pre-round key: each round uses exactly
one round-key word, so the schedule produces one key per round (22 for
Speck32/64). \`roundKey.0\` is the first word of the master key; each later key
is the result of one more step of the schedule.`,
  params: new Map([
    [
      "outputPrefix",
      'The name prefix for the round keys. With "roundKey", they are stored as roundKey.0, roundKey.1, and so on.',
    ],
    ["rounds", "How many round keys to store (22 for Speck32/64) — one per round."],
  ]),
  references: [
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers' (key-schedule output convention)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};
