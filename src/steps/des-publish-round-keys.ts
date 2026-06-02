/**
 * DES publish-round-keys — the meta-bearing aux-publish tail of the
 * decomposed DES key schedule (key-schedule-decomposition slice K4a,
 * 2026-06-02).
 *
 * Parallel to `aes`/`speck`/`serpent.publish-round-keys@1` — the same
 * B-minimal pattern: the decomposed schedule above this step computes every
 * round key as VISIBLE port-native primitive frames (PC-1 → 16×
 * rotate-halves → PC-2), then this one tail leaf publishes the finished
 * round keys into `aux["roundKey.0..15"]` — byte-identical to what the
 * monolithic `des.key-schedule@1` wrote. So the round-body consumers
 * (`des.xor-with-K@1` reading `aux[roundKeyAux]`) and both shipped DES specs'
 * round arrangement stay UNTOUCHED.
 *
 * **Why a separate step type, not reuse `serpent.publish-round-keys@1`.**
 * Functionally the byteLength-agnostic Serpent tail would work with
 * `count: 16`, but reusing it would weld a `serpent.*` step type into every
 * saved DES document's JSON forever — cross-cipher coupling in the persisted
 * spec. A thin `des.publish-round-keys@1` keeps the per-cipher convention
 * (matching the AES / Speck / Serpent siblings). The structural specifics:
 *
 *   1. **Round-key count.** DES emits a FIXED 16 round keys (K₁ … K₁₆,
 *      0-indexed K₀ … K₁₅ in our aux convention) for the single 64-bit key
 *      size — there is no key-size variant. The count is hardcoded 16
 *      (overridable via an optional `count` param for symmetry with the
 *      siblings; the builder always passes 16).
 *   2. **Round-key byte width.** DES round keys are always 6 bytes (48 bits,
 *      which packs exactly into 6 bytes). The port shape leaves `byteLength`
 *      polymorphic, matching the legacy `des.key-schedule@1` output-port
 *      posture.
 *
 * Contract: 16 input ports `key0`…`key15` (each wired from a PC-2 producer)
 * → identity passthrough to 16 output ports `key0`…`key15`;
 * `meta.auxWritePorts` mirrors `key${r} → aux[${outputPrefix}.${r}]`. No
 * state ports (aux-only — the carried block is preserved across the call,
 * same as the legacy `des.key-schedule@1`).
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

/** DES's fixed round-key count: K₀ … K₁₅ (16 keys). DES has no key-size
 *  variant. Local (not exported) — the builder passes 16 explicitly via the
 *  `count` param; only this step's default resolution needs the constant. */
const DES_ROUND_KEY_COUNT = 16;

type Params = {
  readonly outputPrefix: string;
  readonly count: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.publish-round-keys: params must be an object");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.outputPrefix !== "string" || p.outputPrefix.length === 0) {
    throw new Error("des.publish-round-keys: params.outputPrefix must be a non-empty string");
  }
  // `count` defaults to 16 (DES's fixed K₀…K₁₅). Honored if supplied so the
  // param shape stays symmetric with the AES/Speck/Serpent publish siblings.
  let count = DES_ROUND_KEY_COUNT;
  if (p.count !== undefined) {
    if (typeof p.count !== "number" || !Number.isInteger(p.count) || p.count < 1) {
      throw new Error("des.publish-round-keys: params.count must be a positive integer (≥ 1)");
    }
    count = p.count;
  }
  return { outputPrefix: p.outputPrefix, count };
};

/**
 * Canonical input/output port name for round key `r`. Exported so the DES
 * key-schedule builder + tests reference the same string. Matches the
 * `aes`/`speck`/`serpent` publish-round-keys convention.
 */
export const desRoundKeyPortName = (r: number): string => `key${r}`;

/**
 * Identity passthrough: read each `key${r}` round key off its input port and
 * re-emit it on the same-named output port. The runtime's `meta.auxWritePorts`
 * step then mirrors every output port into `aux[${outputPrefix}.${r}]`.
 */
export const desPublishRoundKeys: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r < p.count; r++) {
    const name = desRoundKeyPortName(r);
    const v = inputs.get(name);
    if (!(v instanceof Uint8Array)) {
      throw new Error(
        `des.publish-round-keys: input port "${name}" must carry a round key (wire from the schedule's PC-2 producers)`,
      );
    }
    outputs.set(name, v);
  }
  return outputs;
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Both sides expose the same 16 round-key ports. Function form so a non-default
// `count` resolves. `byteLength` ABSENT — polymorphic, matching the legacy
// `des.key-schedule@1` output-port posture (DES round keys are always 6 bytes,
// but the legacy step left it undeclared and we match it).

const DES_ROUND_KEY_PORT_SHAPE: PortShape = { layout: "raw" };

const desRoundKeyPortMap = (params: Json): ReadonlyMap<string, PortShape> => {
  const p = readParams(params);
  const m = new Map<string, PortShape>();
  for (let r = 0; r < p.count; r++) {
    m.set(desRoundKeyPortName(r), DES_ROUND_KEY_PORT_SHAPE);
  }
  return m;
};

export const desPublishRoundKeysPortContract: PortContract = {
  inputs: desRoundKeyPortMap,
  outputs: desRoundKeyPortMap,
};

// ─── Projection metadata (the one surviving meta in the DES schedule) ───────
// Aux-only: no `stateInputPort` / `stateOutputPort` — the carried block is
// preserved across the call. `auxWritePorts` maps each output port to its
// `aux[${outputPrefix}.${r}]` key. Same exact fan-out the legacy
// `des.key-schedule@1` produced, so untouched `des.xor-with-K@1` consumers
// read identical round keys.

export const desPublishRoundKeysMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const p = readParams(params);
    const bindings = new Map<string, string>();
    for (let r = 0; r < p.count; r++) {
      bindings.set(desRoundKeyPortName(r), `${p.outputPrefix}.${r}`);
    }
    return bindings;
  },
};

// ─── Documentation ────────────────────────────────────────────────────────────

export const desPublishRoundKeysDoc: StepDocumentation = {
  name: "Publish round keys (DES)",
  summary: "Write the derived DES round keys into the aux map (roundKey.0 … roundKey.15).",
  detail: `## Publish round keys (DES)

The tail of the decomposed DES key schedule. The PC-1 → 16 rotations → PC-2
stages above this step have already computed every round key as visible
port-native frames; this leaf takes the finished round keys on its input
ports \`key0\` … \`key15\` and publishes them into the aux map as
\`\${outputPrefix}.0\` … \`\${outputPrefix}.15\` (typically \`roundKey.0\` …
\`roundKey.15\`).

The per-round DES key-mixing step (\`des.xor-with-K@1\`) reads those aux
entries unchanged — so decomposing the key schedule into visible math did
not touch the round body at all. The state (the carried 8-byte block) passes
through this step untouched; the work product lives entirely in the aux map.

**DES's fixed 16 round keys.** DES has no key-size variant — the 64-bit
master key always reduces to 56 effective bits via PC-1 and yields exactly
16 round keys (K₁ … K₁₆), each 48 bits (6 bytes). Decryption consumes the
SAME 16 keys in reverse order.`,
  params: new Map([
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With "roundKey", outputs are roundKey.0 … roundKey.15.',
    ],
    [
      "count",
      "Round-key count. Defaults to 16 (DES's fixed K₁ … K₁₆). The builder always passes 16.",
    ],
  ]),
  references: ["FIPS 46-3 §5 (Key Schedule — 16 round keys K₁ … K₁₆)"],
  shapeContract: { input: "any", output: "preserveInput" },
};
