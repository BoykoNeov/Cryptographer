/**
 * blowfish.sbox-lookup@1 — aux-fed 32-bit word lookup (Blowfish F function).
 *
 * **Why this primitive exists.** Blowfish's F function reads four
 * key-DERIVED S-boxes (`S0..S3`, 256 × 32-bit words each) that the key
 * schedule computes at run time and publishes into the aux map. Every other
 * substitution primitive in the codebase reads its table from spec *params*
 * (AES `byte-substitute@1`, DES `des.s-boxes@1`) — but those tables are fixed
 * cipher constants. Blowfish's are key-dependent, so the table MUST come from
 * aux, and the entries are 32-bit *words*, not bytes. Neither existing
 * substitution step fits, hence this new one.
 *
 * **How it works.** Hybrid registration shape — `kind: "ported"` with
 * `meta.auxReadPorts` present and NO `legacy` executor (the same shape
 * `aux-load-bytes@1` / `xor-with-aux@1` set the precedent for). Two input
 * ports:
 *   - `index` — a single byte (0..255), wired via the spec's `portInputs`
 *     (one of the four bytes of the F-function input word).
 *   - `table` — projected by the runtime from `aux[params.sboxName]` (1024
 *     bytes = 256 big-endian words) BEFORE the executor runs.
 * One output port `output` carries the 4-byte big-endian word
 * `table[index]` (i.e. `table.slice(index*4, index*4 + 4)`).
 *
 * The lookup is the point where Blowfish's key material re-enters every round:
 * the S-boxes were derived from the key by the schedule, so a `sbox-lookup`
 * frame is where "the key affects this block" becomes concrete in the trace.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux key holding the 1024-byte (256-word) S-box, e.g. `blowfish.S0`. */
  readonly sboxName: string;
};

const S_BOX_BYTES = 256 * 4; // 256 words × 4 bytes = 1024
const WORD_BYTES = 4;

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("blowfish.sbox-lookup: params must be an object");
  }
  const p = params as Record<string, Json>;
  const sboxName = p.sboxName;
  if (sboxName !== undefined && typeof sboxName !== "string") {
    throw new Error("blowfish.sbox-lookup: params.sboxName must be a string");
  }
  return { sboxName: (sboxName as string | undefined) ?? "" };
};

// ─── Port contract ──────────────────────────────────────────────────────────
//
// `index` (1 byte, wired via portInputs) + `table` (1024 bytes, aux-projected
// via meta.auxReadPorts) → `output` (4 bytes). Exact byteLengths on all three
// so the editor's coercion-warning glyph can surface a mis-wire before Run.

export const blowfishSboxLookupPortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["index", { layout: "raw", byteLength: 1 }],
    ["table", { layout: "raw", byteLength: S_BOX_BYTES }],
  ]),
  outputs: new Map<string, PortShape>([["output", { layout: "raw", byteLength: WORD_BYTES }]]),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const blowfishSboxLookup: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const index = inputs.get("index");
  const table = inputs.get("table");
  if (index === undefined) {
    throw new Error(
      "blowfish.sbox-lookup: input port 'index' is not wired (declare it in the spec node's `portInputs` — it carries the single byte selecting the S-box entry)",
    );
  }
  if (table === undefined) {
    throw new Error(
      "blowfish.sbox-lookup: 'table' port not available — the runtime projects aux[params.sboxName] onto it via meta.auxReadPorts; check that the key schedule published aux[sboxName] and that params.sboxName is set",
    );
  }
  if (index.length !== 1) {
    throw new Error(
      `blowfish.sbox-lookup: 'index' port must be exactly 1 byte, got ${index.length}`,
    );
  }
  if (table.length !== S_BOX_BYTES) {
    throw new Error(
      `blowfish.sbox-lookup: 'table' port must be ${S_BOX_BYTES} bytes (256 words), got ${table.length}`,
    );
  }
  const i = index[0] ?? 0;
  const off = i * WORD_BYTES;
  // Fresh buffer — outputs own their bytes (the port-native convention).
  const out = new Uint8Array(WORD_BYTES);
  out.set(table.subarray(off, off + WORD_BYTES));
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────────
//
// `auxReadPorts` projects `aux[sboxName]` onto the `table` input port BEFORE
// the executor runs (the same mechanism `aux-load-bytes@1` / `xor-with-aux@1`
// use), AND records the read in `frame.auxRead` so the key-schedule → F-lookup
// fan-out edge is drawn in the graph. Emitted unconditionally (even for the
// empty-string default) so a half-wired leaf surfaces an orphan-read glyph.
//
// `stateLayout: "bytes"` is the defensive default required for any
// `kind: "ported"` registration carrying `meta`. State is NOT threaded — the
// index arrives on the `index` port via portInputs, not the state thread.

export const blowfishSboxLookupMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { sboxName } = readParams(params);
    return new Map([["table", sboxName]]);
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const blowfishSboxLookupDoc: StepDocumentation = {
  name: "S-box lookup (Blowfish)",
  summary:
    "Look up a 32-bit word in a key-derived Blowfish S-box, indexed by one byte. Reads the table from aux.",
  detail: `# S-box lookup (Blowfish)

Reads a single byte on the \`index\` port (0..255) and emits the 4-byte
big-endian word \`S[index]\`, where \`S\` is the 256-word Blowfish S-box held in
\`aux[params.sboxName]\` (auto-projected onto the \`table\` port by the runtime
via \`meta.auxReadPorts\`):

\`\`\`
output  =  aux[sboxName][index]      (a 32-bit word, big-endian)
\`\`\`

## Where it fits — the F function

Blowfish's F function splits its 32-bit input into four bytes \`a b c d\` and
combines four S-box lookups:

\`\`\`
F(x) = ((S0[a] + S1[b]) XOR S2[c]) + S3[d]      (adds mod 2^32)
\`\`\`

Each of \`S0[a]\`, \`S1[b]\`, \`S2[c]\`, \`S3[d]\` is one of these lookup steps,
with \`sboxName\` set to \`blowfish.S0\` … \`blowfish.S3\`. The four results are
then combined by \`add-mod-32@1\` and \`xor@1\` leaves.

## Why the table comes from aux, not params

Unlike AES's or DES's S-boxes (fixed cipher constants baked into leaf params),
Blowfish's four S-boxes are **derived from the key** by the key schedule (via
521 self-encryptions) and published into the aux map. So the lookup must read
its table at run time from aux — this step is the point where the key's effect
re-enters every round.

## Errors

- Throws if \`params.sboxName\` is not a string.
- Throws if the \`index\` port is unwired or not exactly 1 byte.
- Throws if the \`table\` port (aux value) is missing or not 1024 bytes — the
  editor's orphan-read glyph is the first line of defense; this throw is the
  second.`,
  params: new Map([
    [
      "sboxName",
      "Aux key holding the 256-word (1024-byte) S-box, e.g. `blowfish.S0`. Empty string is allowed at authoring time — the editor surfaces an orphan-read glyph until it is wired.",
    ],
  ]),
  references: ["Schneier 1993 — Description of a New Variable-Length Key, 64-Bit Block Cipher"],
  // No `shapeContract` — port-native steps describe their surface via the
  // PortContract.
};
