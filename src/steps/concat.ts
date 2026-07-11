/**
 * Concat — port-native N-way byte concatenation primitive (universal-port
 * plan Phase 2 Slice 2.6b, 2026-05-25).
 *
 * Reads N input ports (`input0`, `input1`, …, `input{N-1}`) and emits one
 * output port `output` carrying the byte-wise concatenation of all inputs
 * in order. Input port count varies with `params.inputCount`; output
 * byteLength = sum of input byteLengths.
 *
 * **Why this primitive exists.** Phase 2's port-native primitives produce
 * bytes on output ports, but there's no built-in way to combine two or
 * more byte streams into one. SHA-256 needs this in two places:
 *
 *  1. **Assembling the working-variable state** at the boundary between
 *     message schedule and compression: state = H_concat || W_concat
 *     (32 + 256 = 288 bytes), feeding the compression rounds with both
 *     the initial working variables AND the message schedule's per-round
 *     W_t lookup table.
 *  2. **Final hash assembly** (deferred — the lifted-legacy
 *     `sha2.final-add@1` handles this internally in 2.6b's coarse path).
 *
 * Future hash and HMAC builds will also need concat:
 *  - **HMAC**: inner-hash output concatenated with outer-key for the
 *    second compression pass.
 *  - **SHA-3 sponge**: state bytes assembled across absorb/squeeze.
 *  - **BLAKE2/3 finalization**: per-block output bytes assembled.
 *
 * **`inputCount` minimum is 1.** Matches `xor@1`'s pick — N=1 is the
 * identity (passthrough), useful during incremental wiring; N=0 is
 * rejected because output byteLength would be 0 with no meaningful
 * source. Asymmetric with `add-mod-32@1`'s ≥ 2 floor — but the floors
 * follow the math: xor/concat have meaningful identities at N=1, addition
 * at N=1 is indistinguishable from passthrough.
 *
 * **Length-polymorphic per-port.** Unlike `xor@1`'s same-length invariant,
 * concat does not require operands to share length — each operand
 * contributes its own bytes verbatim. The output byteLength is the sum,
 * not a uniform single value.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. PortContract uses function form on both sides —
 * input port count varies with `params.inputCount`; output is a single
 * port but its byteLength is dynamic per the input byteLengths. However,
 * we don't know input byteLengths at spec time (they're polymorphic),
 * so the output port's byteLength is left undefined (polymorphic),
 * matching the runtime behavior.
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
  readonly inputCount: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("concat: params must be an object");
  }
  const p = params as Record<string, Json>;
  const inputCount = p.inputCount;
  if (typeof inputCount !== "number" || !Number.isInteger(inputCount) || inputCount < 1) {
    throw new Error("concat: params.inputCount must be a positive integer (≥ 1)");
  }
  return { inputCount };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Build the canonical port name for the i-th input. Exported so tests
 * and spec-builder helpers reference the same string everywhere.
 */
export const concatInputPortName = (i: number): string => `input${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form PortContract on the input side — port count varies with
 * `params.inputCount`. Output side is a fixed single `output` port;
 * function form is used so output `byteLength` could materialize once
 * the upstream byteLengths resolve (today they're polymorphic, so output
 * stays polymorphic too).
 *
 * Layout `"raw"` on all ports — concat operates on byte-flat values
 * without structural interpretation.
 */
export const concatPortContract: PortContract = {
  inputs: (params: Json) => {
    const { inputCount } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < inputCount; i++) {
      entries.push([concatInputPortName(i), { layout: "raw" }]);
    }
    return new Map(entries);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const concat: PortedExecutor = (inputs, params, _ctx) => {
  const { inputCount } = readParams(params);

  // Collect input buffers in port-name order. Missing port → loud throw
  // with the exact port name so the editor can flag the unwired arrow.
  const operands: Uint8Array[] = [];
  let totalLen = 0;
  for (let i = 0; i < inputCount; i++) {
    const name = concatInputPortName(i);
    const bytes = inputs.get(name);
    if (bytes === undefined) {
      throw new Error(`concat: missing required input port "${name}"`);
    }
    operands.push(bytes);
    totalLen += bytes.length;
  }

  // Allocate fresh output, fill in order.
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const op of operands) {
    out.set(op, offset);
    offset += op.length;
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const concatDoc: StepDocumentation = {
  name: "Concat",
  summary: "Joins two or more byte strings end to end, in order, into one longer value.",
  detail: `# Concat

Joins several byte strings end to end into one. It takes N inputs —
\`input0\`, \`input1\`, …, \`input{N-1}\` (N is set by \`inputCount\`) — and
produces a single output that is all of them laid out one after another, in
order.

## Math

For inputs \`a, b, c\` of lengths \`L_a, L_b, L_c\`:

\`\`\`
output = a || b || c    (length L_a + L_b + L_c)
\`\`\`

The inputs do **not** have to be the same length — each one contributes its
bytes verbatim, and the output length is their sum. (This is the difference
from XOR, which combines equal-length inputs position by position.)

## Where it fits

Concatenation is how a cipher or hash reassembles a larger value out of
smaller pieces:

- **Rejoining the halves of a Feistel round** — Blowfish, DES and other
  Feistel ciphers split the block into a left and right half, transform them,
  then concatenate them back into one block. The *order* of the two inputs is
  what encodes the round's left/right **swap**.
- **SHA-256 state assembly** — the eight initial hash words \`H_0..H_7\` are
  concatenated with the message schedule \`W_0..W_63\` into the single value
  the compression rounds read.
- **HMAC** — the inner-hash output is concatenated with the outer key before
  the second hashing pass.
- **Sponge and tree hashes (SHA-3, BLAKE2/3)** — state and per-block outputs
  are assembled by concatenation.

With a single input (\`inputCount = 1\`) concat simply passes it through
unchanged — occasionally useful as a placeholder while wiring a cipher up.`,
  params: new Map([
    [
      "inputCount",
      "How many inputs to join. A whole number, 1 or more. With 1 input, concat passes it through unchanged.",
    ],
  ]),
};
