import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

/**
 * AES key expansion. FIPS-197 §5.2.
 *
 * Port-native `PortedExecutor` (Slice 5.2 — universal-port Phase 5). Reads
 * the 16-, 24-, or 32-byte key from the `masterKey` input port (AES-128 /
 * 192 / 256) and emits Nr+1 round keys (each Uint8Array(16)) on output ports
 * `key0` … `keyN`. The registration keeps `meta` (NOT a lift adapter): the
 * runtime projects `aux[keyAuxName] → masterKey` and `key${r} →
 * aux[${outputPrefix}.${r}]`, so the emitted frame's `auxRead`/`auxWritten`
 * are byte-identical to the former lifted path. State is unchanged (no
 * `state` port); the work product lives entirely in the round-key ports.
 *
 * Nk (32-bit words in the key) is derived from the actual key length: 4 / 6 / 8
 * for AES-128 / 192 / 256. The standard relation Nr = Nk + 6 is asserted so a
 * mismatched spec (e.g. a 24-byte key paired with rounds=10) throws an explicit
 * error instead of silently deriving garbage round keys.
 *
 * AES-256 adds one extra subtlety: when Nk > 6, every word at index `i` where
 * `i % Nk === 4` passes through SubWord (forward S-box) WITHOUT RotWord and
 * WITHOUT an Rcon XOR. The branch only fires for Nk=8; AES-128 and AES-192
 * are unaffected.
 *
 * params: {
 *   keyAuxName: string,        // e.g. "key"
 *   outputPrefix: string,      // e.g. "roundKey"
 *   sbox: number[256],         // forward S-box used for SubWord
 *   rcon: number[],            // Rcon[i/Nk]; index 0 unused, 1..max(i/Nk)
 *   rounds: number,            // 10 / 12 / 14 for AES-128 / 192 / 256
 * }
 */
export const keyExpansion: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  // Port-native (Slice 5.2): the master key arrives on the `masterKey`
  // input port. The runtime projects it from `aux[params.keyAuxName]` via
  // `meta.auxReadPorts` — the same projection the lift adapter drove, so
  // the emitted frame's `auxRead` still records the `key` aux dependency.
  const key = inputs.get("masterKey");
  if (
    !(key instanceof Uint8Array) ||
    (key.length !== 16 && key.length !== 24 && key.length !== 32)
  ) {
    throw new Error(
      "aes.key-expansion: 'masterKey' port must carry a 16-, 24-, or 32-byte key (projected from aux[keyAuxName] via meta.auxReadPorts)",
    );
  }

  // Derive Nk from the key bytes themselves (the runtime gives us whatever the
  // user provided), then double-check against the spec-declared `rounds`.
  // Mismatched (key length, rounds) would silently produce wrong-shaped round
  // keys without this assertion.
  const Nk = key.length / 4; // 4, 6, or 8
  const Nb = 4; // AES block size in 32-bit words (always 16 bytes)
  if (p.rounds !== Nk + 6) {
    throw new Error(
      `rounds (${p.rounds}) must equal Nk+6 (${Nk + 6}) for a ${key.length}-byte key`,
    );
  }
  const totalWords = Nb * (p.rounds + 1);

  // Expanded key as words; each word is a Uint8Array(4).
  const w: Uint8Array[] = new Array(totalWords);
  for (let i = 0; i < Nk; i++) {
    w[i] = new Uint8Array([
      key[4 * i] ?? 0,
      key[4 * i + 1] ?? 0,
      key[4 * i + 2] ?? 0,
      key[4 * i + 3] ?? 0,
    ]);
  }

  for (let i = Nk; i < totalWords; i++) {
    let temp: Uint8Array = new Uint8Array(w[i - 1] as Uint8Array);
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp), p.sbox);
      const rc = p.rcon[i / Nk] ?? 0;
      temp[0] = (temp[0] ?? 0) ^ rc;
    } else if (Nk > 6 && i % Nk === 4) {
      // AES-256-only branch (FIPS-197 §5.2): extra SubWord pass at the
      // mid-word position with no RotWord and no Rcon XOR. Fires solely
      // for Nk=8 — never reached for AES-128 or AES-192.
      temp = subWord(temp, p.sbox);
    }
    const prev = w[i - Nk] as Uint8Array;
    w[i] = new Uint8Array([
      (prev[0] ?? 0) ^ (temp[0] ?? 0),
      (prev[1] ?? 0) ^ (temp[1] ?? 0),
      (prev[2] ?? 0) ^ (temp[2] ?? 0),
      (prev[3] ?? 0) ^ (temp[3] ?? 0),
    ]);
  }

  // Pack words into 16-byte round keys — one per output port (`key0` …
  // `keyN`). The runtime maps `key${r}` → `aux[${outputPrefix}.${r}]` via
  // `meta.auxWritePorts`, so `frame.auxWritten` still carries `roundKey.*`.
  // No `state` output port — key expansion leaves the carried block alone.
  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r <= p.rounds; r++) {
    const rk = new Uint8Array(16);
    for (let word = 0; word < 4; word++) {
      const src = w[r * 4 + word] as Uint8Array;
      rk[word * 4 + 0] = src[0] ?? 0;
      rk[word * 4 + 1] = src[1] ?? 0;
      rk[word * 4 + 2] = src[2] ?? 0;
      rk[word * 4 + 3] = src[3] ?? 0;
    }
    outputs.set(`key${r}`, rk);
  }

  return outputs;
};

// ─── Documentation ────────────────────────────────────────────────────────

export const keyExpansionDoc: StepDocumentation = {
  name: "Key Expansion",
  summary: "Derive Nr+1 round keys (each 16 bytes) from the cipher key.",
  detail: `## Key Expansion (AES)

The cipher key is expanded into **Nr+1 round keys** of 16 bytes each — one
for the initial AddRoundKey, plus one per round. The number of rounds depends
on the key size:

| Variant  | Key bytes | Nk (words) | Rounds (Nr) | Round keys |
|----------|-----------|------------|-------------|------------|
| AES-128  | 16        | 4          | 10          | 11         |
| AES-192  | 24        | 6          | 12          | 13         |
| AES-256  | 32        | 8          | 14          | 15         |

Round keys are written to aux as \`roundKey.0\` through \`roundKey.Nr\`. The
state itself is unchanged by this step; the work product lives entirely in
the aux map.

The expansion is iterative. For most word indices \`i\`, the new word is
\`w[i] = w[i-Nk] XOR w[i-1]\`. Every Nk-th word receives extra processing:

1. **RotWord** — cyclic byte rotation of the previous word
2. **SubWord** — apply the (forward) S-box to each byte
3. **XOR with Rcon[i/Nk]** — round constant, defined as \`x^(i-1)\` in GF(2^8)

**AES-256 has one extra wrinkle.** When \`Nk > 6\`, every word at \`i % Nk == 4\`
gets an extra **SubWord** pass — no RotWord, no Rcon. This branch fires only
for AES-256; AES-128 and AES-192 are unaffected.

This guarantees the round keys differ from each other in nontrivial ways
even when the original key has structure (e.g. all zeros).

**Notable detail:** key expansion uses the **forward** S-box even when
we're decrypting. The inverse cipher consumes the same round keys in
reverse order, but it does *not* re-derive them with the inverse S-box.
That's why our forward and decryption specs share this step verbatim
across all three key sizes.`,
  params: new Map([
    [
      "keyAuxName",
      "Name of the aux entry containing the input cipher key. Length must be 16, 24, or 32 bytes (AES-128 / 192 / 256).",
    ],
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With prefix "roundKey", outputs are roundKey.0 … roundKey.Nr.',
    ],
    [
      "sbox",
      "Forward S-box used by the SubWord sub-step. Always the forward AES S-box, even when decrypting.",
    ],
    [
      "rcon",
      "Round-constant table. Index 0 is unused; indices 1..rounds carry the round constants.",
    ],
    [
      "rounds",
      "Number of cipher rounds: 10 (AES-128), 12 (AES-192), or 14 (AES-256). Must equal Nk+6.",
    ],
  ]),
  references: [
    "FIPS-197 §5.2 (Key Expansion)",
    "FIPS-197 Appendix A.1 (AES-128 example)",
    "FIPS-197 Appendix A.2 (AES-192 example)",
    "FIPS-197 Appendix A.3 (AES-256 example, illustrates the Nk>6 SubWord branch)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

const rotWord = (w: Uint8Array): Uint8Array =>
  new Uint8Array([w[1] ?? 0, w[2] ?? 0, w[3] ?? 0, w[0] ?? 0]);

const subWord = (w: Uint8Array, sbox: readonly number[]): Uint8Array =>
  new Uint8Array([
    sbox[w[0] ?? 0] ?? 0,
    sbox[w[1] ?? 0] ?? 0,
    sbox[w[2] ?? 0] ?? 0,
    sbox[w[3] ?? 0] ?? 0,
  ]);

// ─── @2: relaxed-rounds variant (drives "duplicate round") ────────────────
//
// Two differences from @1:
//   1. The `rounds === Nk + 6` assertion is relaxed to `rounds >= Nk + 1`.
//      That admits non-canonical AES variants the duplicate-round mutator
//      produces ("what would AES-128 look like with 11 rounds?"). The lower
//      bound still rules out degenerate cases that can't even derive an
//      initial AddRoundKey's round key.
//   2. The user-supplied `rcon` array is treated as a seed. If a needed
//      index is missing or zero past the seeded prefix, the executor
//      extends on the fly via the FIPS-197 recurrence `Rcon[i] = xtime(Rcon[i-1])`
//      over GF(2^8) with reduction polynomial 0x11b. The seed wins where
//      it's present, so users can still inspect / edit the canonical Rcon
//      values in ParamEditor; the auto-extension only fills holes.
//
// Param shape is identical to @1, so the existing `KeyExpansionBlock` in
// ParamEditor.tsx renders both with no code branch beyond a type match.

/**
 * Multiply by x in GF(2^8) with reduction polynomial 0x11b. The standard
 * AES Rcon recurrence: `Rcon[i] = xtime(Rcon[i-1])` with Rcon[1] = 0x01.
 */
const xtime = (n: number): number => {
  const shifted = (n << 1) & 0xff;
  return (n & 0x80) === 0 ? shifted : shifted ^ 0x1b;
};

/**
 * AES key expansion (@2). Drop-in replacement for @1 at canonical round
 * counts (10 / 12 / 14) — produces byte-identical round keys — but accepts
 * arbitrary `rounds >= Nk + 1` and extends a short user-supplied Rcon table
 * via xtime on the fly. Used by the duplicate-round feature to express
 * non-standard variants ("AES with 11 rounds").
 */
export const keyExpansionV2: PortedExecutor = (inputs, params, _ctx) => {
  const p = readParams(params);
  // Port-native (Slice 5.2): the master key arrives on the `masterKey`
  // input port. The runtime projects it from `aux[params.keyAuxName]` via
  // `meta.auxReadPorts` — the same projection the lift adapter drove, so
  // the emitted frame's `auxRead` still records the `key` aux dependency.
  const key = inputs.get("masterKey");
  if (
    !(key instanceof Uint8Array) ||
    (key.length !== 16 && key.length !== 24 && key.length !== 32)
  ) {
    throw new Error(
      "aes.key-expansion: 'masterKey' port must carry a 16-, 24-, or 32-byte key (projected from aux[keyAuxName] via meta.auxReadPorts)",
    );
  }
  const Nk = key.length / 4;
  const Nb = 4;
  // Lower bound: `rounds >= 1` guarantees at least one round key past the
  // initial AddRoundKey's key.0 — below that the cipher has no rounds at
  // all and the spec is degenerate. Upper bound is unbounded; duplicate-
  // round produces arbitrarily large values (the user can keep clicking).
  if (!Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error(`rounds (${p.rounds}) must be an integer >= 1`);
  }
  const totalWords = Nb * (p.rounds + 1);

  // Resolve the Rcon table on first miss, lazily, so we don't allocate when
  // the seed already covers the round count. Higher indices fill via the
  // FIPS-197 recurrence; lower indices honor whatever the user supplied
  // (including zeros — that's how `@1`'s table is shaped at index 0).
  const maxRconIdx = Math.floor((totalWords - 1) / Nk);
  const rcon: number[] = [...p.rcon];
  while (rcon.length <= maxRconIdx) {
    const prev = rcon[rcon.length - 1] ?? 0;
    // Seed chain from index 1 = 0x01 if the user supplied nothing useful.
    // Canonical AES_RCON has Rcon[0]=0, Rcon[1]=0x01, so this branch fires
    // only when the user truncated the table below index 1.
    rcon.push(rcon.length === 1 ? 0x01 : xtime(prev));
  }

  const w: Uint8Array[] = new Array(totalWords);
  for (let i = 0; i < Nk; i++) {
    w[i] = new Uint8Array([
      key[4 * i] ?? 0,
      key[4 * i + 1] ?? 0,
      key[4 * i + 2] ?? 0,
      key[4 * i + 3] ?? 0,
    ]);
  }

  for (let i = Nk; i < totalWords; i++) {
    let temp: Uint8Array = new Uint8Array(w[i - 1] as Uint8Array);
    if (i % Nk === 0) {
      temp = subWord(rotWord(temp), p.sbox);
      const rc = rcon[i / Nk] ?? 0;
      temp[0] = (temp[0] ?? 0) ^ rc;
    } else if (Nk > 6 && i % Nk === 4) {
      // AES-256-only branch (FIPS-197 §5.2); fires for Nk=8 only.
      temp = subWord(temp, p.sbox);
    }
    const prev = w[i - Nk] as Uint8Array;
    w[i] = new Uint8Array([
      (prev[0] ?? 0) ^ (temp[0] ?? 0),
      (prev[1] ?? 0) ^ (temp[1] ?? 0),
      (prev[2] ?? 0) ^ (temp[2] ?? 0),
      (prev[3] ?? 0) ^ (temp[3] ?? 0),
    ]);
  }

  const outputs = new Map<string, Uint8Array>();
  for (let r = 0; r <= p.rounds; r++) {
    const rk = new Uint8Array(16);
    for (let word = 0; word < 4; word++) {
      const src = w[r * 4 + word] as Uint8Array;
      rk[word * 4 + 0] = src[0] ?? 0;
      rk[word * 4 + 1] = src[1] ?? 0;
      rk[word * 4 + 2] = src[2] ?? 0;
      rk[word * 4 + 3] = src[3] ?? 0;
    }
    outputs.set(`key${r}`, rk);
  }

  return outputs;
};

export const keyExpansionV2Doc: StepDocumentation = {
  name: "Key Expansion (v2)",
  summary:
    "Derive `rounds + 1` round keys from the cipher key. Accepts non-canonical round counts.",
  detail: `## Key Expansion v2 (AES)

Same FIPS-197 §5.2 procedure as the v1 step, with two relaxations that let
this executor power non-standard AES variants (e.g. "AES-128 with 11
rounds"):

1. **No \`rounds === Nk + 6\` assertion.** v1 enforced the FIPS-197 standard
   relation; v2 accepts any \`rounds >= Nk + 1\`. The other branches
   (RotWord/SubWord on \`i % Nk == 0\`, the Nk>6 extra SubWord) still fire
   exactly as the standard prescribes — only the count of derived words
   changes.

2. **Rcon table is extended on the fly.** If the user-supplied
   \`rcon\` array is shorter than \`floor(totalWords / Nk) + 1\`, the
   executor appends entries using \`Rcon[i] = xtime(Rcon[i-1])\` in
   GF(2^8). Standard Rcon values seeded by the canonical spec stay
   visible and editable in the ParamEditor; the auto-extension only
   fills slots the user didn't provide.

At canonical round counts (10 / 12 / 14) v2 produces byte-identical round
keys to v1 — pinned by a parity test against \`aes.key-expansion@1\`.`,
  params: new Map([
    [
      "keyAuxName",
      "Name of the aux entry containing the input cipher key. Length must be 16, 24, or 32 bytes (AES-128 / 192 / 256).",
    ],
    [
      "outputPrefix",
      'Prefix for the round-key aux entries. With prefix "roundKey", outputs are roundKey.0 … roundKey.{rounds}.',
    ],
    [
      "sbox",
      "Forward S-box used by the SubWord sub-step. Always the forward AES S-box, even when decrypting.",
    ],
    [
      "rcon",
      "Round-constant seed table. Entries past the seed are extended via Rcon[i] = xtime(Rcon[i-1]).",
    ],
    [
      "rounds",
      "Number of cipher rounds. Standard values: 10 / 12 / 14 for AES-128 / 192 / 256. Non-standard counts produce non-standard ciphers.",
    ],
  ]),
  references: [
    "FIPS-197 §5.2 (Key Expansion)",
    "FIPS-197 Appendix A (canonical round-key examples — v2 matches at canonical rounds)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

type Params = {
  keyAuxName: string;
  outputPrefix: string;
  sbox: readonly number[];
  rcon: readonly number[];
  rounds: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("key-expansion requires object params");
  }
  const p = params as Record<string, unknown>;
  if (typeof p.keyAuxName !== "string") throw new Error("keyAuxName must be string");
  if (typeof p.outputPrefix !== "string") throw new Error("outputPrefix must be string");
  if (!Array.isArray(p.sbox) || p.sbox.length !== 256) {
    throw new Error("sbox must be 256 numbers");
  }
  if (!Array.isArray(p.rcon)) throw new Error("rcon must be array");
  if (typeof p.rounds !== "number") throw new Error("rounds must be number");
  return {
    keyAuxName: p.keyAuxName,
    outputPrefix: p.outputPrefix,
    sbox: p.sbox as readonly number[],
    rcon: p.rcon as readonly number[],
    rounds: p.rounds,
  };
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.4) ───────────────
// AES key-expansion is the FIRST one-to-many writer in the universal-
// port migration — Decision B (port-per-roundkey). The output port
// count is `params.rounds + 1` (one for the pre-round AddRoundKey plus
// one per round), so both `ProjectionMetadata.auxWritePorts` and
// `PortContract.outputs` use their function-form variants — the latter
// landing as the user-picked Slice 1.4 contract evolution (PortShapeMap).
//
// The same metadata shape applies to both `aes.key-expansion@1` (the
// canonical FIPS-197 §5.2 procedure asserting `rounds === Nk + 6`) and
// `aes.key-expansion@2` (the relaxed-rounds variant driving the
// duplicate-round feature). Both register with this shared meta + port
// contract because their PARAM surface is identical — the only
// difference is the executor's relaxed `rounds >= Nk + 1` assertion +
// on-the-fly Rcon extension.
//
// **Aux-only**: `stateInputPort` and `stateOutputPort` are intentionally
// OMITTED. Key-expansion's `shapeContract` is `input: "any", output:
// "preserveInput"` — the executor doesn't touch state. Declaring no
// state ports matches the iv-load / aux-load / aux-xor / aux-copy
// pattern from Slice 1.2: the lift adapter creates a sentinel state to
// pass to the legacy executor and discards its passthrough return;
// the runtime preserves the caller's actual state across the ported
// call (so the next step — typically AddRoundKey on a matrix4x4-bytes
// state — sees its own incoming shape, not a key-expansion artifact).
//
// **Port naming convention** — `masterKey` (NOT `key`) for the aux
// read disambiguates it from the per-round output ports `key0`,
// `key1`, …, `keyN`. The aux-key the input port reads from (i.e.,
// the leaf's `params.keyAuxName`, typically `"key"`) is preserved in
// the layout-tag `auxInputBindings` sidecar for round-trip
// reconstruction.

const KEY_EXPANSION_ROUND_KEY_PORT_SHAPE: PortShape = {
  byteLength: 16,
  layout: "raw",
};

/**
 * Compute the per-leaf round-key port surface for the contract's
 * `outputs(params)` callback. Ports are `key0` … `keyN` where N =
 * `params.rounds`. No state output port — key-expansion is aux-only.
 *
 * Reused by both @1 and @2 — the param shape is identical between the
 * two versions; only the executor's round-count assertion differs.
 */
const keyExpansionOutputPorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aes.key-expansion contract: params must be an object");
  }
  const p = params as { rounds?: unknown };
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("aes.key-expansion contract: params.rounds: positive integer required");
  }
  const m = new Map<string, PortShape>();
  for (let r = 0; r <= p.rounds; r++) {
    m.set(`key${r}`, KEY_EXPANSION_ROUND_KEY_PORT_SHAPE);
  }
  return m;
};

/**
 * Port-name → aux-key bindings for the per-round-key outputs.
 * `outputPrefix` is typically `"roundKey"` so port `key3` binds to
 * `auxWritten["roundKey.3"]`. Map iteration is insertion-ordered, so
 * the bindings emerge in `r = 0..rounds` order — matches the legacy
 * executor's `auxWrites` insertion order, which the frame-parity test
 * pins.
 */
const keyExpansionAuxWritePorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aes.key-expansion auxWritePorts: params must be an object");
  }
  const p = params as { outputPrefix?: unknown; rounds?: unknown };
  if (typeof p.outputPrefix !== "string") {
    throw new Error("aes.key-expansion auxWritePorts: params.outputPrefix: string required");
  }
  if (typeof p.rounds !== "number" || !Number.isInteger(p.rounds) || p.rounds < 1) {
    throw new Error("aes.key-expansion auxWritePorts: params.rounds: positive integer required");
  }
  const bindings = new Map<string, string>();
  for (let r = 0; r <= p.rounds; r++) {
    bindings.set(`key${r}`, `${p.outputPrefix}.${r}`);
  }
  return bindings;
};

/**
 * Aux-read bindings — one `masterKey` input port bound to whichever aux
 * key the leaf names (typically `"key"`). Function form is mandatory
 * because every leaf could conceivably choose a different
 * `keyAuxName`; the binding can only be resolved with `params` in hand.
 */
const keyExpansionAuxReadPorts = (params: Json) => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aes.key-expansion auxReadPorts: params must be an object");
  }
  const p = params as { keyAuxName?: unknown };
  if (typeof p.keyAuxName !== "string") {
    throw new Error("aes.key-expansion auxReadPorts: params.keyAuxName: string required");
  }
  return new Map([["masterKey", p.keyAuxName]]);
};

export const keyExpansionMeta: ProjectionMetadata = {
  // Aux-only step — no state ports. `stateLayout: "bytes"` is the
  // ceremonial value the type requires; the lift adapter never
  // consults it because neither `stateInputPort` nor `stateOutputPort`
  // is declared. See `iv-load.ts` for the same pattern.
  stateLayout: "bytes",
  auxReadPorts: keyExpansionAuxReadPorts,
  auxWritePorts: keyExpansionAuxWritePorts,
};

export const keyExpansionPortContract: PortContract = {
  // Static `inputs`: just the master key. No state input port —
  // key-expansion's shapeContract is `input: "any"`. The length of the
  // master key varies across AES variants (16 / 24 / 32 B for AES-128 /
  // 192 / 256), so `masterKey.byteLength` is intentionally absent —
  // the polymorphic-port semantic (user pick 2026-05-23 Slice 1.2)
  // covers exactly this case without a sentinel value.
  inputs: new Map<string, PortShape>([["masterKey", { layout: "raw" }]]),
  // Dynamic outputs: function form because the port count grows with
  // `params.rounds`. No state output port; the runtime preserves the
  // caller's actual state across the ported call. Shared between @1
  // and @2 via the `keyExpansionV2PortContract` alias below.
  outputs: keyExpansionOutputPorts,
};

// `@2` shares the meta + contract verbatim. Param shape is identical
// to `@1`; only the executor's assertions differ. A single set of
// exports keeps the two registrations from drifting.
export const keyExpansionV2Meta: ProjectionMetadata = keyExpansionMeta;
export const keyExpansionV2PortContract: PortContract = keyExpansionPortContract;
