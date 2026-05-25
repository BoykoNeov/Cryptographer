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
  summary:
    "N-way byte concatenation of input0..input{N-1}. Output byteLength = sum of input byteLengths.",
  detail: `# Concat

Universal port-native byte-concatenation primitive. Takes N input ports
named \`input0\`, \`input1\`, …, \`input{N-1}\` (N set by
\`params.inputCount\`), produces one output port \`output\` carrying the
byte-wise concatenation of all inputs in declaration order.

## Math

For inputs \`a, b, c\` of lengths \`L_a, L_b, L_c\`:

\`\`\`
output = a || b || c    (length L_a + L_b + L_c)
\`\`\`

Unlike \`xor@1\`, operands do NOT have to share length — each contributes
its bytes verbatim, and the output is the concatenation.

## Where it fits

- **Boundary state assembly**: combine the SHA-256 initial hash values
  \`H_0..H_7\` (32 bytes) with the message schedule's \`W_0..W_63\`
  (256 bytes) into a 288-byte composite state that compression rounds
  can read for both their working variables AND their per-round W lookup.
- **HMAC**: concatenate the inner-hash output with the outer-key for the
  second compression-function pass.
- **SHA-3 sponge**: assemble state bytes across absorb/squeeze.
- **BLAKE2/3 finalization**: per-block output assembly.
- **Identity passthrough** (N=1): useful as a wiring placeholder during
  incremental spec authoring.

## Errors

- Throws if \`params.inputCount\` is missing, not an integer, or < 1.
- Throws if any expected input port is missing on the input map.

## Phase status

Shipped in Slice 2.6b of the universal-port-dataflow plan as one of three
port-native bridges (alongside \`state-to-bytes@1\` and \`bytes-to-state@1\`).
First consumer: the SHA-256 spec's H||W state assembly between message
schedule and compression rounds.`,
  params: new Map([
    [
      "inputCount",
      "Number of input ports to concatenate. Positive integer (≥ 1). N=1 is identity passthrough.",
    ],
  ]),
  references: ["docs/plans/universal-port-phase-2-slices.md (Slice 2.6b)"],
};
