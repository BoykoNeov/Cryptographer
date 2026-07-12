/**
 * twofish.publish-subkeys@1 — the aux-publish tail of the VISIBLE half of the
 * Twofish key schedule.
 *
 * The 20 pseudo-Hadamard-transform (PHT) blocks above this step compute the 40
 * subkeys `K_0..K_39` out of ordinary `add-mod-32@1` / `rotate-bits-right@1`
 * frames and hand them here on 40 input ports. This step mirrors each into the
 * aux map so the rounds + whitening can read them back:
 *   - `k{n}` → `aux[${prefix}.K.${n}]`  (4 bytes each)
 *
 * **Why a tail at all.** Port-flow can't cross a group scope — the PHT frames
 * live inside the `key-schedule` group, but the rounds are top-level siblings.
 * Publishing the subkeys to aux is the honest cross-scope channel (exactly the
 * AES / Speck / Serpent / DES decomposed-schedule shape). This step is an
 * identity passthrough with no per-frame math worth narrating — the interesting
 * work is the visible PHT frames feeding it — so it sits on the narration
 * allowlist, like the four `*.publish-round-keys@1` tails.
 *
 * B-minimal aux-publish posture: `kind: "ported"` + `meta.auxWritePorts`, no
 * `legacy`.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

const K_COUNT = 40; // K_0..K_39
const WORD_BYTES = 4;

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux-namespace prefix (default "twofish"). Consumers read `${prefix}.K.{n}`. */
  readonly outputPrefix: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("twofish.publish-subkeys: params must be an object");
  }
  const p = params as Record<string, Json>;
  const outputPrefix = p.outputPrefix;
  if (outputPrefix !== undefined && typeof outputPrefix !== "string") {
    throw new Error("twofish.publish-subkeys: params.outputPrefix must be a string");
  }
  return { outputPrefix: (outputPrefix as string | undefined) ?? "twofish" };
};

// ─── Port names ──────────────────────────────────────────────────────────────

const kInPort = (n: number): string => `k${n}`;
const kOutPort = (n: number): string => `kout${n}`;

// ─── Port contract ──────────────────────────────────────────────────────────
//
// 40 input ports (wired from the PHT frames) and 40 mirrored output ports;
// `meta.auxWritePorts` maps each output into aux. Static maps — Twofish has no
// key-size variant in v1, so the port set is fixed at 40.

const buildPorts = (which: (n: number) => string): Map<string, PortShape> => {
  const m = new Map<string, PortShape>();
  for (let n = 0; n < K_COUNT; n++) m.set(which(n), { layout: "raw", byteLength: WORD_BYTES });
  return m;
};

export const twofishPublishSubkeysPortContract: PortContract = {
  inputs: buildPorts(kInPort),
  outputs: buildPorts(kOutPort),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const twofishPublishSubkeys: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const outputs = new Map<string, Uint8Array>();
  for (let n = 0; n < K_COUNT; n++) {
    const k = inputs.get(kInPort(n));
    if (k === undefined) {
      throw new Error(
        `twofish.publish-subkeys: input port '${kInPort(n)}' is not wired (wire it from PHT subkey K[${n}])`,
      );
    }
    if (k.length !== WORD_BYTES) {
      throw new Error(
        `twofish.publish-subkeys: '${kInPort(n)}' must be ${WORD_BYTES} bytes, got ${k.length}`,
      );
    }
    outputs.set(kOutPort(n), Uint8Array.from(k));
  }
  return outputs;
};

// ─── Projection metadata ──────────────────────────────────────────────────────

export const twofishPublishSubkeysMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { outputPrefix } = readParams(params);
    const m = new Map<string, string>();
    for (let n = 0; n < K_COUNT; n++) m.set(kOutPort(n), `${outputPrefix}.K.${n}`);
    return m;
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const twofishPublishSubkeysDoc: StepDocumentation = {
  name: "Publish subkeys (Twofish)",
  summary:
    "Collects the 40 subkeys from the PHT blocks and stores them in aux for the rounds and whitening to read.",
  detail: `# Publish subkeys

The 20 pseudo-Hadamard-transform blocks above computed the 40 subkeys
\`K_0 … K_39\`. This step gathers them and stores each under a name the rest of
the cipher can look up:

\`\`\`
K[n]  →  aux["{prefix}.K.{n}"]
\`\`\`

## Where the subkeys go

- \`K_0 … K_3\` — **input whitening**, XORed into the plaintext before round 0.
- \`K_4 … K_7\` — **output whitening**, XORed into the state after round 15.
- \`K_8 … K_39\` — **round keys**, two per round (\`K_{2r+8}\`, \`K_{2r+9}\`),
  added inside each round's F function.

## Why this step exists

The subkey math (the PHT blocks) lives inside the key-setup group, but the
rounds are outside it. Values can't flow directly across that boundary, so the
subkeys are published to the shared aux store here and read back where they are
needed. This step just moves them across — it does no arithmetic of its own.`,
  params: new Map([
    [
      "outputPrefix",
      'The name prefix under which the subkeys are stored (default "twofish"), so the rounds and whitening can find them as "{prefix}.K.0 … {prefix}.K.39".',
    ],
  ]),
  references: ["Twofish specification §4 (subkey generation)"],
  shapeContract: { input: "any", output: "preserveInput" },
};
