/**
 * blowfish.key-schedule@1 — the opaque 521-encryption loop of the Blowfish
 * key schedule (Schneier 1993). The ONE deliberately-monolithic step in the
 * Blowfish spec.
 *
 * **Why a monolith here, against the project's decompose-everything grain.**
 * Phases 2–5 decomposed every other key schedule (AES / Speck / Serpent / DES)
 * into visible port-native frames — because those are non-iterative
 * bit-plumbing that decompose to ~50 legible frames. Blowfish's schedule is
 * qualitatively different: it regenerates the P-array + all four S-boxes by
 * **running Blowfish on itself 521 times**, with a hard data-dependency chain
 * (each self-encryption uses the P/S the previous one just mutated). There is
 * no decomposition that yields a legible frame count — a full unroll would be
 * tens of thousands of frames. The project's real rule is "decompose what
 * decomposes legibly," and this doesn't. So the 521-loop stays opaque.
 *
 * **What IS visible.** The user chose "visible key-mix + opaque loop": the
 * `key ⊕ P` mixing (how a variable-length key enters the cipher) is expressed
 * in the spec as ~18 real `xor@1` frames, whose `concat@1` produces the
 * 72-byte **key-mixed P** this step reads on its `keyMixedP` input port. This
 * step then runs only the 521-loop (`runBlowfishLoop`), using the π S-box
 * seeds from module constants — never spec params (they are 4 KB of
 * incompressible π digits; see `blowfish-constants.ts`).
 *
 * **B-minimal aux-publish posture.** Same shape as the four
 * `*.publish-round-keys@1` tails + `rsa.publish-key-params@1`: `kind:
 * "ported"` + `meta.auxWritePorts`, no `legacy`. The executor computes the
 * final P (18 words) + S0..S3 (256 words each) and emits them on output ports;
 * `meta.auxWritePorts` mirrors each port into the aux map:
 *   - `p{i}` → `aux[${prefix}.P.${i}]`  (4 bytes, consumed by each round's
 *     `xor-with-aux@1` as `L ⊕ P[i]`)
 *   - `s{b}` → `aux[${prefix}.S${b}]`   (1024 bytes, consumed by the round F
 *     function's four `blowfish.sbox-lookup@1` leaves)
 *
 * **Doubles as the KAT oracle.** Precedent: the kept `*.key-expansion@1`
 * oracles + `mod-inverse@1`. `runBlowfishLoop` + the full `blowfishKeySchedule`
 * live in `blowfish-constants.ts` and are cross-checked against pycryptodome
 * in `tests/blowfish-vectors.test.ts`.
 */

import { bytesBEToU32, runBlowfishLoop, u32ToBytesBE } from "../ciphers/blowfish-constants";
import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Shape constants ──────────────────────────────────────────────────────────

const P_COUNT = 18; // P[0..17]
const S_BOX_COUNT = 4; // S0..S3
const S_BOX_WORDS = 256;
const KEY_MIXED_P_BYTES = P_COUNT * 4; // 72
const S_BOX_BYTES = S_BOX_WORDS * 4; // 1024

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux-namespace prefix for the published key material (default "blowfish").
   *  Round consumers read `${prefix}.P.{i}` and `${prefix}.S{b}`. */
  readonly outputPrefix: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("blowfish.key-schedule: params must be an object");
  }
  const p = params as Record<string, Json>;
  const outputPrefix = p.outputPrefix;
  if (outputPrefix !== undefined && typeof outputPrefix !== "string") {
    throw new Error("blowfish.key-schedule: params.outputPrefix must be a string");
  }
  return { outputPrefix: (outputPrefix as string | undefined) ?? "blowfish" };
};

// ─── Port names ──────────────────────────────────────────────────────────────

const pPort = (i: number): string => `p${i}`;
const sPort = (b: number): string => `s${b}`;

// ─── Port contract ──────────────────────────────────────────────────────────
//
// One input port `keyMixedP` (72 bytes, wired from the visible key-mix's
// concat). 18 + 4 output ports carrying the computed P words + S-boxes;
// `meta.auxWritePorts` mirrors each into aux. Static maps — Blowfish has no
// key-size variant, so the port set is fixed.

const buildOutputPorts = (): Map<string, PortShape> => {
  const m = new Map<string, PortShape>();
  for (let i = 0; i < P_COUNT; i++) m.set(pPort(i), { layout: "raw", byteLength: 4 });
  for (let b = 0; b < S_BOX_COUNT; b++) m.set(sPort(b), { layout: "raw", byteLength: S_BOX_BYTES });
  return m;
};

export const blowfishKeySchedulePortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["keyMixedP", { layout: "raw", byteLength: KEY_MIXED_P_BYTES }],
  ]),
  outputs: buildOutputPorts(),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const blowfishKeySchedule: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const keyMixedP = inputs.get("keyMixedP");
  if (keyMixedP === undefined) {
    throw new Error(
      "blowfish.key-schedule: input port 'keyMixedP' is not wired (wire it from the visible key-mix's concat — the 72-byte key-mixed P-array)",
    );
  }
  if (keyMixedP.length !== KEY_MIXED_P_BYTES) {
    throw new Error(
      `blowfish.key-schedule: 'keyMixedP' must be ${KEY_MIXED_P_BYTES} bytes (18 words), got ${keyMixedP.length}`,
    );
  }
  // Decode the 18 key-mixed P words, then run the opaque 521-encryption loop.
  const words: number[] = [];
  for (let i = 0; i < P_COUNT; i++) words.push(bytesBEToU32(keyMixedP, i * 4));
  const { P, S } = runBlowfishLoop(words);

  // Serialize the final P + S onto the output ports; the runtime mirrors each
  // into aux via meta.auxWritePorts.
  const outputs = new Map<string, Uint8Array>();
  for (let i = 0; i < P_COUNT; i++) {
    outputs.set(pPort(i), u32ToBytesBE(P[i] ?? 0));
  }
  for (let b = 0; b < S_BOX_COUNT; b++) {
    const box = S[b] ?? [];
    const bytes = new Uint8Array(S_BOX_BYTES);
    for (let w = 0; w < S_BOX_WORDS; w++) bytes.set(u32ToBytesBE(box[w] ?? 0), w * 4);
    outputs.set(sPort(b), bytes);
  }
  return outputs;
};

// ─── Projection metadata (the one meta in the Blowfish key setup) ───────────
//
// Aux-only publish: `auxWritePorts` maps each computed output port into the
// aux map so the round bodies (in a different… well, same top-level scope, but
// the aux channel keeps the fan-out edges honest) read the key material back.
// No `stateInputPort` / `stateOutputPort` — the carried block passes through.

export const blowfishKeyScheduleMeta: ProjectionMetadata = {
  // Ceremonial — required by the type but never consulted for an aux-only step.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { outputPrefix } = readParams(params);
    const m = new Map<string, string>();
    for (let i = 0; i < P_COUNT; i++) m.set(pPort(i), `${outputPrefix}.P.${i}`);
    for (let b = 0; b < S_BOX_COUNT; b++) m.set(sPort(b), `${outputPrefix}.S${b}`);
    return m;
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const blowfishKeyScheduleDoc: StepDocumentation = {
  name: "Key schedule (Blowfish — 521 self-encryptions)",
  summary:
    "Regenerate the P-array + four S-boxes by encrypting Blowfish on itself 521 times. The one opaque step.",
  detail: `# Key schedule — the 521-encryption loop

This step performs the heart of Blowfish's key setup: it takes the **key-mixed
P-array** (72 bytes, produced by the visible \`key ⊕ P\` XOR frames above it)
and the π-digit S-box seeds, then regenerates the **final** P-array and all
four S-boxes by running Blowfish encryption on itself:

1. Encrypt the all-zero 64-bit block with the current P/S. The two output words
   become \`P[0], P[1]\`.
2. Encrypt that output; it becomes \`P[2], P[3]\`. Continue through \`P[16],
   P[17]\` — **9 encryptions** fill the 18-word P-array.
3. Keep going, filling \`S0[0], S0[1], … S3[254], S3[255]\` — **512 more
   encryptions**, for **521 total**. Each encryption uses the P/S produced so
   far.

The result becomes the cipher's working key material: \`P[0] … P[17]\`
(each round's \`L ⊕ P[i]\` subkey) and the four S-boxes \`S0 … S3\` (read by
the round F function's four lookups).

## Why this step is shown as one block

Blowfish builds its subkeys by running the cipher on itself 521 times in a
row, where each encryption depends on the P/S the previous one just produced.
Written out step by step, that would be tens of thousands of near-identical
operations — no clearer than a single block. So this explorer shows the loop
as one step and instead makes the *interesting* part visible: how the key
enters, which is the \`key ⊕ P\` mixing (the XOR steps just above) that feeds
this step's key-mixed P-array.

## Cost of a key change

Because the entire P-array and all four S-boxes are re-derived from scratch,
changing the key means re-running all 521 encryptions. This is deliberate:
Blowfish's slow key setup was a design goal (it frustrates brute-force key
search). In this explorer the cost is microseconds — 521 encryptions is
trivial for a CPU, though it was significant for 1993 hardware.`,
  params: new Map([
    [
      "outputPrefix",
      'The name prefix under which the derived key material is stored (default "blowfish"), so the rounds can find it — the P-array as "{prefix}.P.0…17" and the S-boxes as "{prefix}.S0…S3".',
    ],
  ]),
  references: [
    "Schneier 1993 — Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};
