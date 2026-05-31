/**
 * Speck key schedule. Beaulieu et al. 2013 §3.
 *
 * Given an `m`-word master key `K = (l_{m-2}, l_{m-3}, …, l_0, k_0)`,
 * produces a sequence of `rounds` round-key words by iterating:
 *
 *     l_{i+m-1} = (k_i + ROR(l_i, alpha)) XOR i
 *     k_{i+1}   = ROL(k_i, beta) XOR l_{i+m-1}
 *
 * for `i = 0 … rounds-2`. The `k_i` sequence is the round-key stream
 * consumed by the round function. Note the key schedule shares the SAME
 * ARX kernel as the round function — that's the cipher's defining
 * elegance, and a major contrast with AES's S-box-driven schedule.
 *
 * Port-native `PortedExecutor` (Slice 5.2 — universal-port Phase 5). The
 * master key arrives on the `masterKey` input port and each round-key word
 * leaves on an output port `key0` … `key{rounds-1}` as a `Uint8Array` of
 * length `wordBits/8`, byte-encoded per the spec's `byteOrder` so the round
 * step decodes it consistently. State is unchanged (no `state` port). The
 * registration KEEPS `meta` (NOT a lift adapter): the runtime projects
 * `aux[keyAuxName] → masterKey` and `key${i} → aux[${outputPrefix}.${i}]`, so
 * the emitted frame's `auxRead`/`auxWritten` stay byte-identical to the former
 * lifted path — just like AES key expansion.
 *
 * For Speck32/64: wordBits=16, m=4, rounds=22, alpha=7, beta=2. Larger
 * Speck variants tune these constants; the executor itself is generic.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";
import { type SpeckByteOrder, decodeKey, encodeWord, readByteOrder } from "./speck-word-codec";

export const speckKeySchedule: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  // Port-native (Slice 5.2): the master key arrives on the `masterKey` input
  // port. The runtime projects it from `aux[params.keyAuxName]` via
  // `meta.auxReadPorts`, so the emitted frame's `auxRead` still records the
  // master-key aux dependency.
  const key = inputs.get("masterKey");
  if (!(key instanceof Uint8Array)) {
    throw new Error(
      "speck.key-schedule: 'masterKey' port must carry the master-key bytes (projected from aux[keyAuxName] via meta.auxReadPorts)",
    );
  }
  const expectedBytes = p.m * (p.wordBits / 8);
  if (key.length !== expectedBytes) {
    throw new Error(
      `speck.key-schedule: key must be ${expectedBytes} bytes for m=${p.m}, wordBits=${p.wordBits}; got ${key.length}`,
    );
  }

  // Decode the master key into m logical words `[k_0, l_0, …, l_{m-2}]`.
  // The codec absorbs byteOrder so the rest of the executor is convention-
  // agnostic.
  const logical = decodeKey(key, p.m, p.wordBits, p.byteOrder);
  const k = new Array<number>(p.rounds);
  // `l` indices 0..rounds+m-2 (we'll only write up to rounds+m-3, but
  // sizing for clarity).
  const l = new Array<number>(p.rounds + p.m - 1);
  k[0] = logical[0] ?? 0;
  for (let j = 0; j < p.m - 1; j++) {
    l[j] = logical[j + 1] ?? 0;
  }

  // Iterate the schedule. ROR/ROL operate on wordBits-wide values; we
  // mask back into range after each modular addition to keep JS's 32-bit
  // bitwise math from poisoning subsequent rotations.
  const mask = wordMask(p.wordBits);
  for (let i = 0; i < p.rounds - 1; i++) {
    const ki = k[i] ?? 0;
    const li = l[i] ?? 0;
    const rotLi = ror(li, p.alpha, p.wordBits);
    const newL = (((ki + rotLi) & mask) ^ i) & mask;
    l[i + p.m - 1] = newL;
    k[i + 1] = (rol(ki, p.beta, p.wordBits) ^ newL) & mask;
  }

  // Serialize the round keys back to bytes per the same byteOrder so the
  // round step decodes them as single words via decodeWord(.., 0, ..). One
  // round key per output port (`key0` … `key{rounds-1}`); the runtime maps
  // `key${i}` → `aux[${outputPrefix}.${i}]` via `meta.auxWritePorts`, so
  // `frame.auxWritten` still carries the `roundKey.*` entries.
  const outputs = new Map<string, Uint8Array>();
  const wb = p.wordBits / 8;
  for (let i = 0; i < p.rounds; i++) {
    const buf = new Uint8Array(wb);
    encodeWord(buf, 0, p.wordBits, p.byteOrder, k[i] ?? 0);
    outputs.set(`key${i}`, buf);
  }

  return outputs;
};

// ─── Documentation ────────────────────────────────────────────────────────

export const speckKeyScheduleDoc: StepDocumentation = {
  name: "Speck Key Schedule",
  summary:
    "Derive `rounds` round-key words from the m-word master key using the cipher's own ARX kernel.",
  detail: `## Speck Key Schedule

The Speck key schedule reuses the cipher's own round function on the master
key, with the round counter \`i\` injected as the "constant" XOR. That's the
cipher's defining elegance — a single ARX kernel does double duty for both
encryption and key expansion, in stark contrast to AES which has an entirely
separate \`SubWord/RotWord/Rcon\` schedule.

**Master key.** \`m\` words wide: \`K = (l_{m-2}, l_{m-3}, …, l_0, k_0)\`.
For Speck32/64, \`m = 4\`.

**Iteration.** For \`i = 0, 1, …, rounds-2\`:

\`\`\`
l_{i+m-1}  =  (k_i + ROR(l_i, alpha)) XOR i
k_{i+1}    =  ROL(k_i, beta) XOR l_{i+m-1}
\`\`\`

The output is the sequence \`k_0, k_1, …, k_{rounds-1}\` — one round-key
word per round, stored in aux as \`outputPrefix.0\` … \`outputPrefix.rounds-1\`.

**Byte order.** The master key bytes and round-key bytes are encoded per
the step's \`byteOrder\` param. Two conventions are common:

- **BE-paper** — bytes left-to-right are the words \`(l_{m-2}, …, l_0, k_0)\`,
  each big-endian. Matches the visual display in the Beaulieu et al. paper.
- **LE-NSA**  — bytes left-to-right are \`(k_0, l_0, …, l_{m-2})\`, each
  little-endian. Matches the NSA reference C and SUPERCOP.

Both conventions compute the IDENTICAL word-level schedule; only the
serialization at the boundary differs.

**Speck32/64 constants** (verified against Beaulieu et al. Table 4.1):
\`wordBits = 16, m = 4, rounds = 22, alpha = 7, beta = 2\`.`,
  params: new Map([
    [
      "keyAuxName",
      "Name of the aux entry containing the master-key bytes. Length must be m * (wordBits/8).",
    ],
    [
      "outputPrefix",
      'Prefix for round-key aux entries. With "roundKey", outputs are roundKey.0 … roundKey.rounds-1.',
    ],
    ["rounds", "Number of rounds. Speck32/64 = 22; Speck64/128 = 27; etc."],
    [
      "wordBits",
      "Word width in bits. Speck32/64 = 16. Today only 16-bit words are tested; the executor allows up to 30.",
    ],
    ["m", "Number of words in the master key. Speck32/64 = 4."],
    ["alpha", "Right-rotation amount applied to l_i. Speck32/64 = 7; larger variants = 8."],
    ["beta", "Left-rotation amount applied to k_i. Speck32/64 = 2; larger variants = 3."],
    ["byteOrder", "How master-key and round-key bytes are serialized. 'be-paper' or 'le-nsa'."],
  ]),
  references: [
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers', §3 (Key Schedule)",
    "Beaulieu et al. 2013, Table 4.1 (Speck32/64 test vector)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

// ─── Helpers ──────────────────────────────────────────────────────────────

// Word-size-parameterized rotations. For wordBits ≤ 30 these stay in JS's
// safe-integer range. Speck32/64 uses 16-bit words, well inside the safe
// zone; larger Speck variants (24/32/48/64-bit words) would need BigInt
// support, deferred.
const wordMask = (bits: number): number => (bits === 32 ? 0xffffffff : (1 << bits) - 1);

const rol = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm << n) | (xm >>> (bits - n))) & mask;
};

const ror = (x: number, n: number, bits: number): number => {
  const mask = wordMask(bits);
  const xm = x & mask;
  return ((xm >>> n) | (xm << (bits - n))) & mask;
};

type Params = {
  keyAuxName: string;
  outputPrefix: string;
  rounds: number;
  wordBits: number;
  m: number;
  alpha: number;
  beta: number;
  byteOrder: SpeckByteOrder;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.key-schedule requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.keyAuxName !== "string")
    throw new Error("speck.key-schedule: keyAuxName must be string");
  if (typeof p.outputPrefix !== "string")
    throw new Error("speck.key-schedule: outputPrefix must be string");
  for (const k of ["rounds", "wordBits", "m", "alpha", "beta"] as const) {
    const v = p[k];
    if (typeof v !== "number" || !Number.isInteger(v) || v < 1) {
      throw new Error(`speck.key-schedule: ${k} must be a positive integer`);
    }
  }
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    rounds: p.rounds as number,
    wordBits: p.wordBits as number,
    m: p.m as number,
    alpha: p.alpha as number,
    beta: p.beta as number,
    byteOrder: readByteOrder(params, "speck.key-schedule"),
  };
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.6) ───────────────
// Speck key-schedule is the SECOND one-to-many writer in the universal-
// port migration (after AES key-expansion in Slice 1.4). Same Decision B
// shape — one output port per round key — sized by `params.rounds`. For
// Speck32/64 that's 22 ports (`key0` … `key21`), vs AES-128's 11 ports
// (`key0` … `key10`). The dynamic-N PortContract.outputs function form
// already validated in Slice 1.4 carries over verbatim.
//
// **Aux-only**: `stateInputPort` and `stateOutputPort` are intentionally
// OMITTED. Speck key-schedule's `shapeContract` is `input: "any", output:
// "preserveInput"` — the executor doesn't touch state. Matches the
// aux-only lift pattern from Slice 1.2 (iv-load, aux-load, …) + Slice
// 1.4 (AES key-expansion): the lift adapter creates a sentinel
// zero-length `bytes`-shape state to pass to the legacy executor and
// discards its passthrough return. The runtime preserves the caller's
// actual `bytes`-shape state (Speck32/64's 4-byte block) across the
// ported call so the subsequent `speck.round` leaf sees its incoming
// shape unchanged.
//
// **Port naming convention** — `masterKey` for the aux read disambiguates
// it from the per-round output ports `key0`, `key1`, …, `keyN`. Same
// convention Slice 1.4 picked for AES key-expansion.
//
// **byteLength absent on the round-key output ports** — Speck variants
// vary the word width (Speck32/64 = 16-bit words → 2-byte round keys;
// Speck64/128 = 32-bit words → 4-byte round keys; etc.). Today only
// Speck32/64 ships, but the executor is generic. Polymorphic byteLength
// (Slice 1.2 user pick) covers exactly this case without baking a
// variant-specific number into the contract. Same reasoning applies to
// `masterKey` — `m * wordBits / 8` bytes (8 for Speck32/64).

const speckKeyScheduleOutputPorts = (params: Json) => {
  // Identical params validation to readParams above; we re-validate here
  // because the contract callback may be invoked outside the executor's
  // own validation path (e.g., during PortContract resolution at editor
  // time). Throws keep the error surface descriptive.
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.key-schedule contract: params must be an object");
  }
  const p = params as { rounds?: unknown };
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("speck.key-schedule contract: params.rounds: positive integer required");
  }
  const m = new Map<string, PortShape>();
  // Speck writes EXACTLY `rounds` round keys (k_0 … k_{rounds-1}). Unlike
  // AES which writes Nr+1 (the initial AddRoundKey's key + one per
  // round), Speck has no initial AddRoundKey — each round consumes
  // exactly one round-key word. So the loop bound is `< rounds`, not
  // `<= rounds`.
  for (let i = 0; i < p.rounds; i++) {
    // byteLength absent — polymorphic across Speck variants. layout
    // "raw" → decode as Uint8Array (the round step reads via
    // `decodeWord(rkBytes, 0, wordBits, byteOrder)`, which works on a
    // Uint8Array of the right length).
    m.set(`key${i}`, { layout: "raw" });
  }
  return m;
};

const speckKeyScheduleAuxWritePorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.key-schedule auxWritePorts: params must be an object");
  }
  const p = params as { outputPrefix?: unknown; rounds?: unknown };
  if (typeof p.outputPrefix !== "string") {
    throw new Error("speck.key-schedule auxWritePorts: params.outputPrefix: string required");
  }
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("speck.key-schedule auxWritePorts: params.rounds: positive integer required");
  }
  // Map iteration is insertion-ordered in JS — bindings emerge in
  // i = 0 … rounds-1 order, matching the legacy executor's `auxWrites`
  // insertion order. The frame-parity test pins this.
  const bindings = new Map<string, string>();
  for (let i = 0; i < p.rounds; i++) {
    bindings.set(`key${i}`, `${p.outputPrefix}.${i}`);
  }
  return bindings;
};

const speckKeyScheduleAuxReadPorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("speck.key-schedule auxReadPorts: params must be an object");
  }
  const p = params as { keyAuxName?: unknown };
  if (typeof p.keyAuxName !== "string") {
    throw new Error("speck.key-schedule auxReadPorts: params.keyAuxName: string required");
  }
  return new Map([["masterKey", p.keyAuxName]]);
};

export const speckKeyScheduleMeta: ProjectionMetadata = {
  // Aux-only step — no state ports. `stateLayout: "bytes"` is the
  // ceremonial value the type requires; the lift adapter never consults
  // it because neither `stateInputPort` nor `stateOutputPort` is
  // declared. Same pattern as AES key-expansion's meta (see
  // `key-expansion.ts`).
  stateLayout: "bytes",
  auxReadPorts: speckKeyScheduleAuxReadPorts,
  auxWritePorts: speckKeyScheduleAuxWritePorts,
};

export const speckKeySchedulePortContract: PortContract = {
  // Static `inputs`: just the master key. No state input port —
  // shapeContract is `input: "any"`. byteLength absent — varies with
  // `m * wordBits / 8` across Speck variants.
  inputs: new Map<string, PortShape>([["masterKey", { layout: "raw" }]]),
  // Dynamic outputs: one port per round key, sized by `params.rounds`.
  // Function form because the port count grows with the param. No state
  // output port; the runtime preserves the caller's state across the
  // ported call.
  outputs: speckKeyScheduleOutputPorts,
};
