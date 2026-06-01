/**
 * Add-mod-16 — port-native N-way modular addition over 16-bit
 * big-endian word arrays (key-schedule-decomposition K2a, 2026-06-01).
 *
 * Exact dual of `add-mod-32@1` (Slice 2.1b, 2026-05-24): same N-way
 * operand-port convention, same `inputCount` param, same fixed-width
 * posture — only the word width changes (16 → decoded/encoded via
 * `decodeBE16` / `encodeBE16` from `src/core/word-codec.ts`) and the
 * length invariant tightens from "multiple of 4" to "multiple of 2".
 *
 * **Why a NEW fixed-width step type, not widening `add-mod-32@1` to a
 * parameterized `add-mod@1`.** `add-mod-32`'s own doc spells out the
 * precedent: "the carry-wrap point is fundamentally different between
 * 32-bit and 64-bit additions, so folding both into one step type with
 * a `wordBits` param would hide the semantic difference." The same
 * argument applies to 16-bit. Speck32/64's key schedule (the K2a
 * consumer) needs 16-bit modular addition; we ship a sibling step type
 * matching `add-mod-32@1`'s shape. Future `add-mod-64@1` will ship when
 * SHA-512 lands, completing the family at the four canonical widths the
 * shared word-codec already supports.
 *
 * **`inputCount` minimum is 2.** Same as `add-mod-32@1`: a 1-operand
 * addition is the identity, indistinguishable from passthrough, and
 * there's no realistic ARX use case where authoring partially through a
 * multi-add lands on a 1-operand intermediate state worth surfacing.
 * Reject it now; revisit if a real use case appears.
 *
 * **Where K2a uses it.** One leaf per iteration in
 * `buildSpeck32_64KeyScheduleNative`: `g{i}.sum = add-mod-16@1(2)` of
 * `k_i + ROR(l_i, alpha)` — the modular addition step of Speck's ARX
 * key-schedule recurrence (Beaulieu et al. 2013 §3).
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. Same posture as `add-mod-32.ts` / `xor.ts` /
 * `rotate-bits-right.ts`. `PortContract.inputs` is function-form
 * (varies with `params.inputCount`); `outputs` is static (one
 * `output` port).
 */

import type {
  Json,
  PortContract,
  PortShape,
  PortedExecutor,
  StepDocumentation,
} from "../core/types";
import { decodeBE16, encodeBE16 } from "../core/word-codec";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  readonly inputCount: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("add-mod-16: params must be an object");
  }
  const p = params as Record<string, Json>;
  const inputCount = p.inputCount;
  if (typeof inputCount !== "number" || !Number.isInteger(inputCount) || inputCount < 2) {
    throw new Error("add-mod-16: params.inputCount must be an integer ≥ 2");
  }
  return { inputCount };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Same convention as `add-mod-32@1` / `xor@1` (`operand0`, `operand1`,
 * …). Exported so tests and future spec-builder helpers reference the
 * same string everywhere — a typo against the executor would silently
 * break wiring.
 */
export const addMod16OperandPortName = (i: number): string => `operand${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form `inputs` (port count varies with `params.inputCount`),
 * static `outputs` (one fixed `output` port). Polymorphic `byteLength`
 * on every port — wiring at the consumer determines actual length;
 * executor enforces the "multiple of 2" invariant and equal-length
 * across operands at execute time. Identical posture to
 * `add-mod-32PortContract`.
 */
export const addMod16PortContract: PortContract = {
  inputs: (params: Json) => {
    const { inputCount } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < inputCount; i++) {
      entries.push([addMod16OperandPortName(i), { layout: "raw" }]);
    }
    return new Map(entries);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const addMod16: PortedExecutor = (inputs, params, _ctx) => {
  const { inputCount } = readParams(params);

  // Collect operands in port-name order. Mirror `add-mod-32`'s explicit
  // missing-port error so the editor surfaces the exact unwired arrow.
  const operands: Uint8Array[] = [];
  for (let i = 0; i < inputCount; i++) {
    const name = addMod16OperandPortName(i);
    const bytes = inputs.get(name);
    if (bytes === undefined) {
      throw new Error(`add-mod-16: missing required input port "${name}"`);
    }
    operands.push(bytes);
  }

  const byteLength = (operands[0] as Uint8Array).length;
  if (byteLength % 2 !== 0) {
    throw new Error(
      `add-mod-16: operand byteLength ${byteLength} is not a multiple of 2 (required for 16-bit word arithmetic)`,
    );
  }
  for (let i = 1; i < inputCount; i++) {
    const op = operands[i] as Uint8Array;
    if (op.length !== byteLength) {
      throw new Error(
        `add-mod-16: operand${i} length ${op.length} does not match operand0 length ${byteLength}`,
      );
    }
  }

  const out = new Uint8Array(byteLength);
  // Word-wise sum. The accumulator is a plain JS number — 16-bit
  // operands stay safely below 2^31 even when N piles up (the IEEE-double
  // accumulator is safe up to ~2^21 distinct N-way operands at 16-bit
  // width, far beyond any realistic ARX use case). `& 0xffff` at the
  // end collapses the running sum to mod 2^16.
  for (let off = 0; off < byteLength; off += 2) {
    let sum = 0;
    for (let i = 0; i < inputCount; i++) {
      sum += decodeBE16(operands[i] as Uint8Array, off);
    }
    encodeBE16(out, off, sum & 0xffff);
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const addMod16Doc: StepDocumentation = {
  name: "Add (mod 2¹⁶)",
  summary:
    "N-way modular addition over 16-bit big-endian word arrays. Output word at each position = sum of all operands' words at that position, mod 2¹⁶.",
  detail: `# Add (mod 2¹⁶)

Universal port-native modular-addition primitive at 16-bit word width.
Takes N input ports named \`operand0\`, \`operand1\`, …, \`operand{N-1}\`
(where N is set by \`params.inputCount\`), produces one output port
\`output\` carrying the byte-wise representation of the sum.

## Math

Each operand is a sequence of K big-endian 16-bit words (K =
byteLength / 2). At each word position \`w\`:

\`\`\`
output_w = (operand0_w + operand1_w + … + operand{N-1}_w) mod 2¹⁶
\`\`\`

Addition is commutative and associative — order does not affect the
result, and chunking two operands at a time vs all N at once gives the
same answer. Carries beyond bit 15 are dropped; this is the standard
behavior of unsigned 16-bit arithmetic in ARX cipher pseudocode.

## Word width

Fixed at 16 bits, matching how \`add-mod-32@1\` is fixed at 32 bits.
The carry-wrap point is fundamentally different between widths, so
folding multiple widths into one step type with a \`wordBits\` param
would hide the semantic difference. (Compare: \`rotate-bits-right@1\`
DOES carry \`wordBits\` as a param because rotation is a pure bit
shuffle that abstracts cleanly across widths.) Future \`add-mod-64@1\`
will ship when SHA-512 / Blake2b / Argon2 land.

## Where it fits

- **Speck32/64 key schedule (the K2a consumer)**: the
  \`l_{i+m-1} = (k_i + ROR(l_i, alpha)) ⊕ i\` recurrence's modular
  addition step is one \`add-mod-16@1\` leaf per iteration.
- **Speck32/64 round function**: the \`x ← (ROR(x, alpha) + y) mod 2^n\`
  step is the same primitive at 16-bit width. Today's
  \`speck.round@1\` step inlines its 16-bit addition; a future
  port-native Speck round rebuild from medium primitives composes this
  primitive directly.
- **Byte-level encodings**: any cipher or hash that performs
  word-level modular addition on a flat byte buffer where the words
  are 16 bits each.

## Errors

- Throws if \`params.inputCount\` is missing, not an integer, or < 2.
- Throws if any expected operand port is missing on the input map.
- Throws if any operand's length is not a multiple of 2 (cannot be
  decoded as a sequence of 16-bit words).
- Throws if operands disagree on length — coercion is an editor /
  edge-projection concern per Q2 of the universal-port plan, NOT a
  step-level concern.

## Phase status

Shipped in K2a of the key-schedule-decomposition plan as the sibling
of \`add-mod-32@1\` (Phase 2 Slice 2.1b). Used by the Speck32/64
decomposed key-schedule builder. The fixed-width family extends to
\`add-mod-64@1\` when SHA-512 lands.`,
  params: new Map([
    [
      "inputCount",
      "Number of input operand ports. Integer ≥ 2 (single-operand addition would be the identity, indistinguishable from passthrough).",
    ],
  ]),
  references: [
    "Beaulieu et al. 2013, 'The SIMON and SPECK Families of Lightweight Block Ciphers' (ARX primitives, 16-bit modular addition in Speck32/64)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead.
};
