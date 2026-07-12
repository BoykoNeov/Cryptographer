/**
 * twofish.h-expand@1 — the opaque half of the Twofish key schedule.
 *
 * **Why a monolith here (Twofish's partial-visibility split).** The Twofish key
 * schedule has two halves. The *subkey-mixing* half (the pseudo-Hadamard
 * transform combining A_i and B_i into K_{2i}/K_{2i+1}) decomposes cleanly into
 * `add`/`rotate` frames and IS shown as visible PHT blocks in the spec. The
 * *h-function* half does not: the RS S-vector (a 4×8 GF(0x14D) multiply), the
 * q-permutation S-box construction, and the 40 h-evaluations are a dense tangle
 * of nested table lookups with no legible per-frame decomposition. Per the
 * user's 2026-07-12 decision, that half stays ONE opaque frame — but, unlike
 * Blowfish's fully-silent key-schedule tail, it carries a rich value-prose
 * narrator (`twofishHExpandNarration`) that discloses its hidden stages with
 * the real per-key values this run produced.
 *
 * **What it publishes.** Same B-minimal aux-publish posture as the other
 * schedule tails (`meta.auxWritePorts`, `kind: "ported"`, no `legacy`). The
 * executor calls the pure `twofishKeySchedule` oracle and mirrors:
 *   - `a{i}`  → `aux[${prefix}.A.${i}]`  (4 BE bytes; the 20 A_i)
 *   - `b{i}`  → `aux[${prefix}.B.${i}]`  (4 BE bytes; the 20 B_i, already ROL 8)
 *   - `s{b}`  → `aux[${prefix}.S${b}]`   (256 raw bytes; the byte→byte S-boxes)
 * The 20 visible PHT blocks read the A_i/B_i back and combine them into the 40
 * subkeys; the round F-function's `twofish.sbox-lookup@1` leaves read the four
 * S-boxes.
 *
 * **Display-only output ports.** `svec0`/`svec1` (the S-vector words) and
 * `m0..m3` (the master-key words) are declared in the PortContract outputs but
 * DELIBERATELY NOT in `meta.auxWritePorts` — so they ride in
 * `frame.portOutputs` for the narrator to surface, without producing a spurious
 * unused-write graph warning (nothing downstream consumes them).
 */

import { TWOFISH_KEY_BYTES, twofishKeySchedule, u32ToBytesBE } from "../ciphers/twofish-constants";
import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Shape constants ──────────────────────────────────────────────────────────

const AB_COUNT = 20; // A_0..A_19 and B_0..B_19
const S_BOX_COUNT = 4; // S0..S3
const S_BOX_BYTES = 256; // byte→byte S-boxes (no endianness — pure byte→byte)
const WORD_BYTES = 4;

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux-namespace prefix for the published material (default "twofish"). */
  readonly outputPrefix: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("twofish.h-expand: params must be an object");
  }
  const p = params as Record<string, Json>;
  const outputPrefix = p.outputPrefix;
  if (outputPrefix !== undefined && typeof outputPrefix !== "string") {
    throw new Error("twofish.h-expand: params.outputPrefix must be a string");
  }
  return { outputPrefix: (outputPrefix as string | undefined) ?? "twofish" };
};

// ─── Port names ──────────────────────────────────────────────────────────────

const aPort = (i: number): string => `a${i}`;
const bPort = (i: number): string => `b${i}`;
const sPort = (b: number): string => `s${b}`;

// ─── Port contract ──────────────────────────────────────────────────────────

const buildOutputPorts = (): Map<string, PortShape> => {
  const m = new Map<string, PortShape>();
  for (let i = 0; i < AB_COUNT; i++) {
    m.set(aPort(i), { layout: "raw", byteLength: WORD_BYTES });
    m.set(bPort(i), { layout: "raw", byteLength: WORD_BYTES });
  }
  for (let b = 0; b < S_BOX_COUNT; b++) m.set(sPort(b), { layout: "raw", byteLength: S_BOX_BYTES });
  // Display-only outputs (NOT in auxWritePorts): S-vector + master-key words.
  m.set("svec0", { layout: "raw", byteLength: WORD_BYTES });
  m.set("svec1", { layout: "raw", byteLength: WORD_BYTES });
  for (let i = 0; i < 4; i++) m.set(`m${i}`, { layout: "raw", byteLength: WORD_BYTES });
  return m;
};

export const twofishHExpandPortContract: PortContract = {
  inputs: new Map<string, PortShape>([["key", { layout: "raw", byteLength: TWOFISH_KEY_BYTES }]]),
  outputs: buildOutputPorts(),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const twofishHExpand: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const key = inputs.get("key");
  if (key === undefined) {
    throw new Error(
      "twofish.h-expand: input port 'key' is not wired (wire it from the 16-byte key loader)",
    );
  }
  if (key.length !== TWOFISH_KEY_BYTES) {
    throw new Error(
      `twofish.h-expand: 'key' must be ${TWOFISH_KEY_BYTES} bytes (128-bit key, v1), got ${key.length}`,
    );
  }
  const { A, B, S, Svec, M } = twofishKeySchedule(key);

  const outputs = new Map<string, Uint8Array>();
  for (let i = 0; i < AB_COUNT; i++) {
    outputs.set(aPort(i), u32ToBytesBE(A[i] ?? 0));
    outputs.set(bPort(i), u32ToBytesBE(B[i] ?? 0));
  }
  for (let b = 0; b < S_BOX_COUNT; b++) {
    // S-boxes are pure byte→byte; copy into a fresh owned buffer.
    const box = S[b] ?? new Uint8Array(S_BOX_BYTES);
    outputs.set(sPort(b), Uint8Array.from(box));
  }
  // Display-only outputs.
  outputs.set("svec0", u32ToBytesBE(Svec[0] ?? 0));
  outputs.set("svec1", u32ToBytesBE(Svec[1] ?? 0));
  for (let i = 0; i < 4; i++) outputs.set(`m${i}`, u32ToBytesBE(M[i] ?? 0));
  return outputs;
};

// ─── Projection metadata ──────────────────────────────────────────────────────
//
// Aux-only publish of A / B / S (the display-only svec/m ports are omitted, so
// they stay in frame.portOutputs without an aux fan-out edge). No state
// threading — the carried block passes through untouched.

export const twofishHExpandMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { outputPrefix } = readParams(params);
    const m = new Map<string, string>();
    for (let i = 0; i < AB_COUNT; i++) {
      m.set(aPort(i), `${outputPrefix}.A.${i}`);
      m.set(bPort(i), `${outputPrefix}.B.${i}`);
    }
    for (let b = 0; b < S_BOX_COUNT; b++) m.set(sPort(b), `${outputPrefix}.S${b}`);
    return m;
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const twofishHExpandDoc: StepDocumentation = {
  name: "h-expand (Twofish key schedule — opaque half)",
  summary:
    "Runs Twofish's h-function machinery — RS S-vector, key-dependent S-box construction, and the 40 h evaluations — in one step.",
  detail: `# h-expand — the opaque half of the Twofish key schedule

Twofish's key setup has two halves. The **pseudo-Hadamard transform** that
combines the h-outputs into subkeys is shown step by step just below this one
(the visible PHT blocks). This step performs the other half — the dense
h-function machinery that resists a legible per-frame breakdown:

## What happens inside

1. **RS S-vector.** The 16 key bytes are run through a Reed–Solomon code — a
   4×8 matrix multiply over GF(2⁸) with reduction polynomial \`0x14D\` — to
   produce two 32-bit words \`S_0, S_1\`. These key the S-boxes. The S-box key
   list reverses the word order: \`L = (S_1, S_0)\` — a classic gotcha an
   endpoint test can't catch.

2. **Key-dependent S-boxes.** Each of the four byte→byte S-boxes composes the
   fixed q0/q1 permutations with XORs of the S-vector bytes. Because they depend
   on the key, the S-boxes (and therefore the whole g function) are different
   for every key — the attacker doesn't even know the substitution tables.

3. **Forty h-evaluations.** \`A_i = h(2i·ρ, M_even)\` and
   \`B_i = ROL(h((2i+1)·ρ, M_odd), 8)\` for \`i = 0..19\`, where h is the same
   q-box + MDS chain the S-boxes use, ρ = \`0x01010101\`.

## Why this step is shown as one block

Written out, the RS multiply, the four 256-entry S-box constructions, and the
40 nested q-box/MDS evaluations are hundreds of near-identical table lookups —
no clearer than a single block. So the explorer keeps it as one step and, in
the linear view, discloses its stages annotated with the concrete numbers this
key produced. The **interesting, learnable** part — how the h-outputs become
subkeys — is made fully visible as the PHT blocks below.

## What it hands off

The step publishes the 20 \`A_i\` and 20 \`B_i\` (which the PHT blocks combine
into the 40 subkeys \`K_0..K_39\`) and the four key-dependent S-boxes (which the
round's g function reads). Change the key and all of it changes.`,
  params: new Map([
    [
      "outputPrefix",
      'The name prefix under which the derived material is published (default "twofish"): the A/B intermediates as "{prefix}.A.0…19" / "{prefix}.B.0…19" and the S-boxes as "{prefix}.S0…S3".',
    ],
  ]),
  references: [
    "Twofish specification §4 (key schedule, h function, RS + MDS matrices)",
    "Schneier et al. 1998 — Twofish: A 128-Bit Block Cipher (AES submission)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};
