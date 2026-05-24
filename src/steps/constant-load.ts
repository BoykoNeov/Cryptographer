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
    "Emit a declared byte sequence on the output port. Zero inputs. Used for cryptographic round constants and IVs.",
  detail: `# Load constant

Emits the byte sequence declared in \`params.bytes\` on the single
output port \`output\`. No input ports. The output byteLength is known
at spec-edit time (from \`params.bytes.length\`), unlike most port-
native primitives whose output length depends on run-time input length.

## Where it fits

- **SHA-256 round constants (K_0..K_63)**: 64 leaves, each a 4-byte BE
  constant per FIPS 180-4 §4.2.2. E.g.:
  - K_0 = \`6 b: 42 8a 2f 98\`
  - K_1 = \`6 b: 71 37 44 91\`
  - …
- **SHA-256 initial hash values (H_0..H_7)**: 8 leaves, each a 4-byte
  BE constant per FIPS 180-4 §5.3.3. E.g.:
  - H_0 = \`6 b: 6a 09 e6 67\`
- **AES Rcon table**: 10 / 12 / 14 constants per key size (future
  Phase 3 AES rebuild from medium primitives).
- **DES initial / final permutation tables**: when DES rebuilds from
  medium primitives (Phase 4 future), the per-round S-box tables would
  ride along as \`constant-load@1\` leaves.
- **Any IV / nonce / fixed counter**: CBC IV, CTR initial counter, GCM
  J_0 — each a literal byte sequence the spec needs to inject.

## Why one constant per leaf

User pick at Slice 2.4 start (universal-port plan Phase 2, 2026-05-24)
per Open #N2: option **(b) constant-load@1 at 72 leaves** for SHA-256.
The Slice 2.3 "(b) Compositions" precedent — every cryptographic
sub-operation visible as a chip in the graph — extends to constants.
The cost is verbosity in the spec (8 + 64 = 72 leaves just for SHA-256
preprocessing), but each constant becomes individually addressable,
inspectable, and editable. Spec authors who prefer compact bundles
(e.g., one 256-byte K-table leaf, one 32-byte H-table leaf) can still
do so by setting \`params.bytes\` to a longer array — the primitive
doesn't enforce the granularity, just provides it.

## Example

\`\`\`json
{
  "kind": "step",
  "id": "h0",
  "type": "constant-load@1",
  "params": { "bytes": [0x6a, 0x09, 0xe6, 0x67] }
}
\`\`\`

At execute time, the output port carries the 4 bytes
\`6a 09 e6 67\` — SHA-256's initial hash value H_0.

## Output byteLength is exact

Unlike \`rotate-bits-right@1\` / \`xor@1\` / \`add-mod-32@1\` (whose
output byteLength is polymorphic — it equals the input byteLength),
\`constant-load@1\` declares an EXACT output byteLength on its
PortContract. The editor can use this to surface coercion-warning
glyphs at the wiring boundary when a consumer expects a different
length.

## Phase status

Shipped in Slice 2.4 of the universal-port-dataflow plan as the third
of three SHA-256-preprocessing primitives (alongside
\`pad-with-byte@1\` and \`append-be64-length@1\`). Slice 2.6's SHA-256
spec wires 72 instances (8 for H, 64 for K).`,
  params: new Map([
    [
      "bytes",
      "Array of integers in [0, 255] — the byte sequence to emit. Output port's byteLength = bytes.length.",
    ],
  ]),
  references: [
    "FIPS 180-4 §4.2.2 (SHA-256 round constants K_0..K_63)",
    "FIPS 180-4 §5.3.3 (SHA-256 initial hash values H_0..H_7)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
