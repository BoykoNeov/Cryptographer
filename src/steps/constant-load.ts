/**
 * Constant-load — port-native constant emitter (universal-port plan
 * Phase 2 Slice 2.4, 2026-05-24).
 *
 * Zero input ports. One output port `output` carrying the bytes declared
 * in `params.bytes`. The bytes are a compile-time-known constant (from
 * the spec author's perspective) — typical use is for cryptographic
 * round constants (e.g., SHA-256 K_0..K_63, initial hash values
 * H_0..H_7, AES Rcon table) or any literal byte sequence the spec needs
 * to inject into its dataflow.
 *
 * **Why a primitive at all (vs. embedding constants as leaf params on
 * the consumer).** User pick at Slice 2.4 start (2026-05-24) per Open
 * #N2: option **(b) constant-load@1 at 72 leaves** (one leaf per SHA-256
 * constant). The advisor framing flagged that the Slice 2.3 "(b)
 * Compositions" precedent applies — every cryptographic constant becomes
 * a visible chip in the graph, addressable by spec authors and editors,
 * decoupled from the consumer's leaf-params shape. Spec is more verbose
 * (8 H-leaves + 64 K-leaves for SHA-256), but the cost is small
 * relative to the pedagogical win.
 *
 * **Granularity = one constant per leaf** (Slice 2.4 user pick). For
 * SHA-256, this means 8 leaves outputting 4 bytes each for H_0..H_7
 * (e.g., H_0 = `[0x6a, 0x09, 0xe6, 0x67]`) and 64 leaves outputting 4
 * bytes each for K_0..K_63 (e.g., K_0 = `[0x42, 0x8a, 0x2f, 0x98]`).
 *
 * **Output byteLength is KNOWN at spec time** (from `params.bytes.length`).
 * This is the first port-native primitive that can advertise an exact
 * byteLength on its output port — `rotate-bits-right@1` / `xor@1` /
 * `add-mod-32@1` / `and@1` / `not@1` are all polymorphic (output
 * length = input length). Constant-load resolves output byteLength at
 * spec time, which the editor can use for coercion-warning glyphs.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract: empty static input map, function-
 * form output map (the output port's byteLength is a function of
 * params).
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly bytes: readonly number[];
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("constant-load: params must be an object");
  }
  const p = params as Record<string, Json>;
  const bytes = p.bytes;
  if (!Array.isArray(bytes)) {
    throw new Error("constant-load: params.bytes must be an array of integers in [0, 255]");
  }
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (typeof b !== "number" || !Number.isInteger(b) || b < 0 || b > 0xff) {
      throw new Error(
        `constant-load: params.bytes[${i}] must be an integer in [0, 255] (got ${String(b)})`,
      );
    }
  }
  return { bytes: bytes as readonly number[] };
};

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Empty input map (constant emitter — no inputs). Function-form output
 * because the output port's `byteLength` is a function of
 * `params.bytes.length`. Per advisor's Slice 2.1b rule, "function form
 * only when N varies on THAT side" — the OUTPUT side varies (the
 * byteLength changes with the params; though the count stays at 1), so
 * function form is appropriate.
 *
 * Note: the count of output ports is fixed at 1 — only the byteLength
 * is a function of params. We use function form so the byteLength is
 * declared honestly to the editor at spec time, enabling coercion-
 * warning glyphs to use the exact length.
 */
export const constantLoadPortContract: PortContract = {
  inputs: new Map(),
  outputs: (params: Json) => {
    const { bytes } = readParams(params);
    const shape: PortShape = { layout: "raw", byteLength: bytes.length };
    return new Map([["output", shape]]);
  },
};

export const constantLoad: PortedExecutor = (_inputs, params, _ctx) => {
  const { bytes } = readParams(params);
  // Fresh Uint8Array — downstream mutation must not leak back into the
  // shared params object (it's a `readonly number[]` at the type level,
  // but JS arrays are mutable at runtime).
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[i] as number;
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const constantLoadDoc: StepDocumentation = {
  name: "Load constant",
  summary:
    "Produces a fixed byte sequence that you type in — a round constant, an IV, or any literal value.",
  detail: `# Load constant

Produces a fixed sequence of bytes that you supply directly. It has no
inputs — it simply hands the value you typed into \`bytes\` to whatever reads
it. This is how a cipher injects the fixed, published numbers it needs.

## Where it fits

- **Round constants** — many hashes and ciphers mix in a fixed constant each
  round to break up symmetry. SHA-256 uses 64 such constants (K₀…K₆₃) and
  eight starting values (H₀…H₇); AES's key schedule uses its Rcon constants.
- **Initialization vectors, nonces, counters** — a CBC IV or a CTR starting
  counter is a fixed value fed in at the start of a mode of operation.
- **Fixed tables** — any published table a cipher references (a permutation
  table, a starting S-box) can be loaded this way.

These values are part of the cipher's published definition. Changing one is a
good way to *see* how much a cipher depends on its constants — but it no
longer matches the standard, so it won't interoperate with other
implementations.`,
  params: new Map([
    [
      "bytes",
      "The exact byte values to produce, in order — each a number 0–255. The output is as long as this list.",
    ],
  ]),
  references: [
    "FIPS 180-4 §4.2.2 (SHA-256 round constants K_0..K_63)",
    "FIPS 180-4 §5.3.3 (SHA-256 initial hash values H_0..H_7)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
