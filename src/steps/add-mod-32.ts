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
    "N-way modular addition over 32-bit big-endian word arrays. Output word at each position = sum of all operands' words at that position, mod 2³².",
  detail: `# Add (mod 2³²)

Universal port-native modular-addition primitive. Takes N input ports
named \`operand0\`, \`operand1\`, …, \`operand{N-1}\` (where N is set
by \`params.inputCount\`), produces one output port \`output\` carrying
the byte-wise representation of the sum.

## Math

Each operand is a sequence of K big-endian 32-bit words (K =
byteLength / 4). At each word position \`w\`:

\`\`\`
output_w = (operand0_w + operand1_w + … + operand{N-1}_w) mod 2³²
\`\`\`

Addition is commutative and associative — order does not affect the
result, and chunking two operands at a time vs all N at once gives the
same answer. Carries beyond bit 31 are dropped; this is the standard
behavior of unsigned 32-bit arithmetic in C / FIPS pseudocode notation.

## Word width

Fixed at 32 bits. SHA-512 / Argon2 / BLAKE2b will get their own
\`add-mod-64@1\` primitive when those land — the carry-wrap point is
fundamentally different between 32-bit and 64-bit additions, so
folding both into one step type with a \`wordBits\` param would hide
the semantic difference. (Compare: \`rotate-bits-right@1\` DOES carry
\`wordBits\` as a param because rotation is a pure bit shuffle that
abstracts cleanly across widths.)

## Where it fits

- **SHA-256 compression function**: the working-variable update
  \`T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]\` is one 5-operand
  add-mod-32, and \`T2 = Σ0(a) + Maj(a,b,c)\` is one 2-operand add
  (FIPS 180-4 §6.2.2).
- **SHA-256 message schedule**: each new \`W_t\` for t ≥ 16 is a
  4-operand add of σ1, σ0, and two earlier W words.
- **ARX primitives generally**: SipHash, BLAKE2s, ChaCha20 (in 32-bit
  word form) all do 32-bit modular addition as their A in A-R-X. The
  shipped \`speck.round@1\` step inlines its 16/32/64-bit addition
  against the wider 2-word state; this primitive isolates the
  addition itself so future ARX rebuilds from medium primitives can
  compose it.

## Why N-way from the start

The plan's literal Slice 2.1b text reads 2-way, but the implementation
ships N-way because (a) addition mod 2³² is associative so the math is
identical, and (b) SHA-256 reads cleanly with multi-operand adds —
flatening the 5-operand T1 update into one node beats the same
expression as four chained 2-way adds. Mirrors \`xor@1\`'s N-way
shape. Decided 2026-05-24 (Fork 2).

## Errors

- Throws if \`params.inputCount\` is missing, not an integer, or < 2.
- Throws if any expected operand port is missing on the input map.
- Throws if any operand's length is not a multiple of 4 (cannot be
  decoded as a sequence of 32-bit words).
- Throws if operands disagree on length — coercion is an editor /
  edge-projection concern per Q2, NOT a step-level concern.

## Phase status

Shipped in Slice 2.1b of the universal-port-dataflow plan, alongside
\`xor@1\`. Not yet wired into any cipher spec — Slice 2.6's SHA-256
build is the first consumer.`,
  params: new Map([
    [
      "inputCount",
      "Number of input operand ports. Integer ≥ 2 (single-operand addition would be the identity, indistinguishable from passthrough).",
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
