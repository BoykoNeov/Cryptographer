/**
 * twofish.sbox-lookup@1 — aux-fed byte→byte lookup (Twofish g function).
 *
 * **Why a new primitive.** Twofish's g function reads four key-DERIVED S-boxes
 * (`S0..S3`) that the key schedule builds at run time and publishes to aux.
 * Blowfish's aux-fed lookup (`blowfish.sbox-lookup@1`) is close but wrong-typed:
 * Blowfish's entries are 32-bit *words* (byte→word), whereas Twofish's are pure
 * **byte→byte** substitutions (the MDS multiply that widens them to a word is a
 * separate, later step). So this lookup takes a 1-byte index and returns a
 * 1-byte value.
 *
 * **How it works.** Hybrid registration shape — `kind: "ported"` with
 * `meta.auxReadPorts` and no `legacy`. Two input ports:
 *   - `index` — one byte (0..255), wired from one byte of the g-function input.
 *   - `table` — projected by the runtime from `aux[params.sboxName]` (256 bytes)
 *     BEFORE the executor runs.
 * One output port `output` carrying `table[index]` (one byte).
 *
 * A `sbox-lookup` frame is where Twofish's key material re-enters every round:
 * the S-boxes were derived from the key, so the substitution — and thus the
 * whole g function — is key-dependent.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

const S_BOX_BYTES = 256; // byte→byte table

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux key holding the 256-byte byte→byte S-box, e.g. `twofish.S0`. */
  readonly sboxName: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("twofish.sbox-lookup: params must be an object");
  }
  const p = params as Record<string, Json>;
  const sboxName = p.sboxName;
  if (sboxName !== undefined && typeof sboxName !== "string") {
    throw new Error("twofish.sbox-lookup: params.sboxName must be a string");
  }
  return { sboxName: (sboxName as string | undefined) ?? "" };
};

// ─── Port contract ──────────────────────────────────────────────────────────

export const twofishSboxLookupPortContract: PortContract = {
  inputs: new Map<string, PortShape>([
    ["index", { layout: "raw", byteLength: 1 }],
    ["table", { layout: "raw", byteLength: S_BOX_BYTES }],
  ]),
  outputs: new Map<string, PortShape>([["output", { layout: "raw", byteLength: 1 }]]),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const twofishSboxLookup: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const index = inputs.get("index");
  const table = inputs.get("table");
  if (index === undefined) {
    throw new Error(
      "twofish.sbox-lookup: input port 'index' is not wired (declare it in the spec node's `portInputs` — one byte of the g-function input)",
    );
  }
  if (table === undefined) {
    throw new Error(
      "twofish.sbox-lookup: 'table' port not available — the runtime projects aux[params.sboxName] via meta.auxReadPorts; check that h-expand published aux[sboxName] and that params.sboxName is set",
    );
  }
  if (index.length !== 1) {
    throw new Error(
      `twofish.sbox-lookup: 'index' port must be exactly 1 byte, got ${index.length}`,
    );
  }
  if (table.length !== S_BOX_BYTES) {
    throw new Error(
      `twofish.sbox-lookup: 'table' port must be ${S_BOX_BYTES} bytes, got ${table.length}`,
    );
  }
  const i = index[0] ?? 0;
  // Fresh buffer — outputs own their bytes (the port-native convention).
  return new Map([["output", new Uint8Array([table[i] ?? 0])]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────────

export const twofishSboxLookupMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { sboxName } = readParams(params);
    return new Map([["table", sboxName]]);
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const twofishSboxLookupDoc: StepDocumentation = {
  name: "S-box lookup (Twofish)",
  summary: "Substitutes one byte through one of Twofish's four key-derived byte→byte S-boxes.",
  detail: `# S-box lookup (Twofish)

Takes a single byte on the \`index\` (0–255) and returns the byte stored at that
position of one of Twofish's four S-boxes. The S-box is a 256-byte table the key
schedule built and left in a named slot; this step reads the table named by
\`sboxName\`:

\`\`\`
output = S[index]      (one byte → one byte)
\`\`\`

## Where it fits — the g function

Twofish's **g** function splits its 32-bit input into four bytes and runs each
through a *different* S-box, then multiplies the four results by the **MDS
matrix** to get back a 32-bit word:

\`\`\`
g(X) = MDS · ( S0[x0], S1[x1], S2[x2], S3[x3] )
\`\`\`

Each of \`S0[x0]\` … \`S3[x3]\` is one of these lookup steps (with \`sboxName\`
set to \`twofish.S0\` … \`twofish.S3\`); the MDS multiply that follows is a
separate step.

## Why the table comes from aux, not params

Unlike AES's fixed S-box, Twofish's four S-boxes are **key-dependent** — built
from the key during key setup (through the RS S-vector and the q-permutation
construction). So the lookup reads its table fresh each run. Change the key and
every one of these 256 entries changes — that key-dependent substitution is a
large part of what makes Twofish's g function hard to analyze.`,
  params: new Map([
    [
      "sboxName",
      "Which of Twofish's four S-boxes to read (e.g. `twofish.S0`), by the name the key schedule stored it under. Left blank on a freshly added step; the editor flags it until you connect it.",
    ],
  ]),
  references: ["Twofish specification §4.3.2 (the g function and key-dependent S-boxes)"],
};
