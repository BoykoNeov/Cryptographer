/**
 * Add-mod-32 — port-native N-way modular addition over 32-bit
 * big-endian word arrays (universal-port plan Phase 2 Slice 2.1b,
 * 2026-05-24).
 *
 * Reads N input ports (`operand0`, `operand1`, …, `operand{N-1}`) per
 * the same S3-sharpened convention as `xor@1`. Each operand is a
 * `Uint8Array` whose length must be a multiple of 4 bytes; the runtime
 * decodes each 4-byte chunk as one big-endian 32-bit word, sums all
 * operands' words at each word position modulo 2^32, and re-encodes
 * the result. Output port `output` carries the resulting bytes.
 *
 * **Why N-way (not 2-way) from the start.** Plan literally specifies
 * `{ inputCount: 2 }` for Slice 2.1b ("always 2 for SHA-256; future
 * additions can widen"). User pick 2026-05-24 (Fork 2) chose option (b)
 * — N-way from the start, symmetric with `xor@1`. SHA-256's
 * compression-function update reads cleanly as a single 5-operand
 * node: `T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]` becomes one
 * `add-mod-32@1` leaf with `inputCount: 5` instead of four chained
 * 2-way adds, much closer to how the FIPS pseudocode reads. Modular
 * addition is associative so the math is byte-identical regardless of
 * chunking — the choice is purely pedagogical.
 *
 * **Why 32-bit word width (not configurable).** SHA-2 family splits
 * cleanly: SHA-256/224 use 32-bit words; SHA-512/384 use 64-bit. The
 * plan reserves a separate `add-mod-64@1` for the latter rather than
 * folding wordBits into params. This matches how `rotate-bits-right@1`
 * carries `wordBits` as a param while the addition primitives keep it
 * in the step type — addition cares about carry semantics (where carry
 * wraps depends on word width), making the operation fundamentally
 * different per width; rotation is a pure bit shuffle that abstracts
 * cleanly across widths. Future `add-mod-64@1` ships when SHA-512
 * lands.
 *
 * **`inputCount` minimum is 2.** Different from `xor@1`'s N≥1 floor:
 * a single-operand addition is the identity, indistinguishable from
 * passthrough, and there's no SHA-256 use case where authoring
 * partially through a multi-add would land on a 1-operand intermediate
 * state worth surfacing. Reject it now; revisit if a real use case
 * appears.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. Same posture as `rotate-bits-right.ts` /
 * `xor.ts`.
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";
import { decodeBE32, encodeBE32 } from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly inputCount: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("add-mod-32: params must be an object");
  }
  const p = params as Record<string, Json>;
  const inputCount = p.inputCount;
  if (typeof inputCount !== "number" || !Number.isInteger(inputCount) || inputCount < 2) {
    throw new Error("add-mod-32: params.inputCount must be an integer ≥ 2");
  }
  return { inputCount };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Same convention as `xor`'s operand port names (`operand0`,
 * `operand1`, …). Exported for tests + future spec-builder helpers.
 */
export const addMod32OperandPortName = (i: number): string => `operand${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form PortContract on the input side ONLY — same posture as
 * `xor`'s contract. The output side is a fixed single `output` port,
 * so static form there matches the rotate-bits-right (Slice 2.1a)
 * precedent and the "function form only when N varies on THIS side"
 * rule pinned at Slice 1.4. Polymorphic `byteLength` on every port;
 * the executor enforces the "must be a multiple of 4" invariant at
 * execute time and equal length across operands.
 */
export const addMod32PortContract: PortContract = {
  inputs: (params: Json) => {
    const { inputCount } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < inputCount; i++) {
      entries.push([addMod32OperandPortName(i), { layout: "raw" }]);
    }
    return new Map(entries);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

// BE 32-bit word codec consolidated into `src/core/word-codec.ts` in
// Slice 2.2 (2026-05-24). `decodeBE32` / `encodeBE32` are imported above
// alongside rotate-bits-right (Slice 2.1a)'s former inline helpers — the
// two files were the load-bearing duplication that Slice 2.2 closed.

export const addMod32: PortedExecutor = (inputs, params, _ctx) => {
  const { inputCount } = readParams(params);

  // Collect operands in port-name order. Mirror `xor`'s explicit
  // missing-port error so the editor surfaces the exact unwired arrow.
  const operands: Uint8Array[] = [];
  for (let i = 0; i < inputCount; i++) {
    const name = addMod32OperandPortName(i);
    const bytes = inputs.get(name);
    if (bytes === undefined) {
      throw new Error(`add-mod-32: missing required input port "${name}"`);
    }
    operands.push(bytes);
  }

  const byteLength = (operands[0] as Uint8Array).length;
  if (byteLength % 4 !== 0) {
    throw new Error(
      `add-mod-32: operand byteLength ${byteLength} is not a multiple of 4 (required for 32-bit word arithmetic)`,
    );
  }
  for (let i = 1; i < inputCount; i++) {
    const op = operands[i] as Uint8Array;
    if (op.length !== byteLength) {
      throw new Error(
        `add-mod-32: operand${i} length ${op.length} does not match operand0 length ${byteLength}`,
      );
    }
  }

  const out = new Uint8Array(byteLength);
  // Word-wise sum. JS numbers are IEEE doubles with 53 mantissa bits;
  // summing N 32-bit values into a single accumulator stays safe up to
  // N around 2^21 — well beyond any realistic SHA-256 / cipher use case
  // (5-operand T1 is the worst we currently expect). `>>> 0` at the end
  // collapses the running sum to mod 2^32.
  for (let off = 0; off < byteLength; off += 4) {
    let sum = 0;
    for (let i = 0; i < inputCount; i++) {
      sum += decodeBE32(operands[i] as Uint8Array, off);
    }
    encodeBE32(out, off, sum >>> 0);
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const addMod32Doc: StepDocumentation = {
  name: "Add (mod 2³²)",
  summary:
    "Adds two or more values as 32-bit words, wrapping around at 2³² (ordinary computer addition).",
  detail: `# Add (mod 2³²)

Adds two or more inputs together as 32-bit words. Each input is read as a
sequence of 32-bit words (4 bytes each, big-endian), and the words at each
position are summed. Any carry past the top bit is dropped — the sum "wraps
around" at 2³², exactly the way addition works in a 32-bit CPU register.

## Math

At each word position \`w\`:

\`\`\`
output_w = (operand0_w + operand1_w + … + operand{N-1}_w) mod 2³²
\`\`\`

All inputs must be the same length (a whole number of 4-byte words).
Addition is commutative and associative, so the order of the inputs does not
matter. Because the carry is discarded rather than growing the number, this
addition is **not** reversible on its own — that non-linearity is exactly
why ciphers mix it with XOR and rotation.

## Where it fits

- **The "A" in ARX ciphers** — Addition, Rotation, XOR is a whole cipher
  family (Speck, ChaCha20, BLAKE2). This step is the Addition: mixing values
  in a way that XOR alone cannot, because its carries let one bit affect the
  bits above it.
- **Blowfish's F-function** — combines the four S-box lookups with two
  additions mod 2³² (interleaved with an XOR): \`((S0 + S1) ⊕ S2) + S3\`.
- **SHA-256** — the compression step \`T1 = h + Σ1(e) + Ch(e,f,g) + K + W\`
  is a single 5-input add mod 2³²; the message schedule adds four words to
  form each new word.`,
  params: new Map([
    [
      "inputCount",
      "How many inputs to add. A whole number, 2 or more (adding a single value would change nothing). All inputs must be the same length.",
    ],
  ]),
  references: [
    "FIPS 180-4 §6.2.2 (SHA-256 compression function, working-variable update)",
    "FIPS 180-4 §6.2.2 (SHA-256 message schedule recurrence)",
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers' (ARX primitives)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
