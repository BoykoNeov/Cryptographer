/**
 * Xor — port-native N-way bitwise XOR primitive (universal-port plan
 * Phase 2 Slice 2.1b, 2026-05-24).
 *
 * Reads N input ports (`operand0`, `operand1`, …, `operand{N-1}`) per
 * the plan's S3 sharpening — each operand is wired in from the spec's
 * sink-only edge graph, NOT from `aux`. Output port `output` carries
 * the byte-wise XOR of all operands. All operands must share the same
 * length (no implicit truncation or zero-padding inside the executor —
 * coercion is an EDGE-projection concern per Q2, surfaced as a visible
 * trace step at the wiring boundary).
 *
 * **Why a NEW step type vs widening `aux-xor` / `xor-aux-into-state`.**
 * Today's `generic.aux-xor@1` is a 2-way XOR keyed against a single aux
 * value (state-bearing variant: `state ⊕= aux[name]`). That shape is
 * narrowly tied to the legacy single-state-thread contract — the aux
 * read is implicit, not a wireable port. `xor@1` ships under the
 * port-native contract instead: every operand is an explicit input
 * port, the editor can wire any source to any operand, and N
 * generalizes from 2 to whatever the consumer needs (SHA-256's
 * message-schedule expansion uses 4-way XOR; AES MixColumns rebuild
 * from medium primitives uses 4-way XOR; a custom cipher might wire
 * 7-way for fun). The two coexist: aux-xor stays for legacy specs that
 * read from the aux map; xor@1 is the universal port-native primitive.
 *
 * **`inputCount` minimum is 1.** Advisor pick 2026-05-24 (Fork 1) — N=1
 * is the identity (passthrough); N=0 is rejected because the output
 * byteLength would be undefined. The degenerate N=1 case lets a spec
 * compose cleanly while only one operand has been wired during
 * authoring; the eventual N≥2 wiring is what cryptographic specs need.
 *
 * **Why this is part of the Slice 2.1b batch.** SHA-256's compression
 * function relies on XOR in σ0/σ1 (3-way), in the message schedule
 * W_t = σ1(W_{t-2}) ⊕ W_{t-7} ⊕ σ0(W_{t-15}) ⊕ W_{t-16} (4-way), and
 * in Σ0/Σ1 (3-way against rotated copies). Ships alongside
 * `add-mod-32@1` so the message-schedule + compression-function
 * arithmetic surface is complete for the Slice 2.5 SHA-256 build.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. Same posture as `rotate-bits-right.ts`
 * (Slice 2.1a). PortContract uses function form on both sides because
 * the input-port count varies with `params.inputCount`; output is
 * always a one-port map (`output`).
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
    throw new Error("xor: params must be an object");
  }
  const p = params as Record<string, Json>;
  const inputCount = p.inputCount;
  if (typeof inputCount !== "number" || !Number.isInteger(inputCount) || inputCount < 1) {
    // N=0 rejected: output byteLength would be undefined (no operand to
    // derive it from). N=1 allowed as identity — useful during spec
    // authoring before all operands are wired.
    throw new Error("xor: params.inputCount must be a positive integer (≥ 1)");
  }
  return { inputCount };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Build the canonical port name for the i-th operand. Exported so tests
 * (and future spec-builder helpers) reference the same string everywhere
 * — a typo here against the executor would silently break wiring.
 */
export const xorOperandPortName = (i: number): string => `operand${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form PortContract on the input side ONLY — the input port
 * count varies with `params.inputCount`, so inputs need params to
 * materialize. The output side is a fixed single `output` port; static
 * form there matches the rotate-bits-right (Slice 2.1a) precedent and
 * the broader "function form only when N varies on THIS side" rule
 * pinned at Slice 1.4 (key-expansion: outputs vary, inputs do not).
 *
 * Polymorphic `byteLength` on every port — the consumer's wiring
 * determines the actual length at edit time, and the executor enforces
 * the same-length invariant at execute time.
 */
export const xorPortContract: PortContract = {
  inputs: (params: Json) => {
    const { inputCount } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < inputCount; i++) {
      entries.push([xorOperandPortName(i), { layout: "raw" }]);
    }
    return new Map(entries);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const xor: PortedExecutor = (inputs, params, _ctx) => {
  const { inputCount } = readParams(params);

  // Collect operands in port-name order. `inputs.get(name)` is the
  // contract — if any expected port is missing, throw with the exact
  // missing name so the editor can flag the unwired arrow precisely.
  const operands: Uint8Array[] = [];
  for (let i = 0; i < inputCount; i++) {
    const name = xorOperandPortName(i);
    const bytes = inputs.get(name);
    if (bytes === undefined) {
      throw new Error(`xor: missing required input port "${name}"`);
    }
    operands.push(bytes);
  }

  // Same-length invariant — coercion at port boundaries is an editor /
  // edge-projection concern per Q2, NOT a step concern. A length
  // mismatch inside the executor is a wiring bug we should surface
  // loudly; silently truncating or zero-extending would hide it.
  const byteLength = (operands[0] as Uint8Array).length;
  for (let i = 1; i < inputCount; i++) {
    const op = operands[i] as Uint8Array;
    if (op.length !== byteLength) {
      throw new Error(
        `xor: operand${i} length ${op.length} does not match operand0 length ${byteLength}`,
      );
    }
  }

  // N=1 identity: copy operand0 to output. (Returning the same
  // Uint8Array would couple downstream mutations back to the wired
  // source; the runtime treats outputs as freshly-owned arrays.)
  const out = new Uint8Array(byteLength);
  if (inputCount === 1) {
    out.set(operands[0] as Uint8Array);
    return new Map([["output", out]]);
  }

  // N ≥ 2: byte-wise XOR all operands into the output buffer.
  // Initialize with operand0; XOR in operands 1..N-1.
  out.set(operands[0] as Uint8Array);
  for (let i = 1; i < inputCount; i++) {
    const op = operands[i] as Uint8Array;
    for (let j = 0; j < byteLength; j++) {
      out[j] = (out[j] as number) ^ (op[j] as number);
    }
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const xorDoc: StepDocumentation = {
  name: "XOR",
  summary:
    "N-way byte-wise XOR of operand0..operand{N-1}. All operands must share the same length; output carries the XOR.",
  detail: `# XOR

Universal port-native bitwise-XOR primitive. Takes N input ports named
\`operand0\`, \`operand1\`, …, \`operand{N-1}\` (where N is set by
\`params.inputCount\`), produces one output port \`output\` carrying the
byte-wise XOR of all operands.

## Math

For each byte position \`j\`:

\`\`\`
output[j] = operand0[j] ⊕ operand1[j] ⊕ … ⊕ operand{N-1}[j]
\`\`\`

XOR is commutative and associative, so operand order does not affect
the result. XOR with itself is zero, and zero is the identity — so
\`xor(a, a) = 0\` and \`xor(a, 0...0) = a\`.

## Where it fits

- **SHA-256 σ0 / σ1**: 3-way XOR of rotated and shifted copies of a
  message word (FIPS 180-4 §4.1.2).
- **SHA-256 message schedule**: 4-way XOR in the W_t recurrence
  \`W_t = σ1(W_{t-2}) ⊕ W_{t-7} ⊕ σ0(W_{t-15}) ⊕ W_{t-16}\`.
- **AES MixColumns rebuild from primitives**: each output cell is a
  4-way XOR of GF(2^8)-multiplied state bytes — a future Phase 3+
  rebuild composes \`gf-matrix-multiply\` + \`xor\` instead of the
  monolithic legacy \`generic.mix-columns@1\`.
- **Block-cipher chaining modes**: CBC's plaintext ⊕ previous-
  ciphertext is a 2-way XOR; OFB / CFB feedback structure same. The
  port-native variant lets the user wire chaining math entirely from
  primitives, no implicit aux reads.
- **Identity passthrough**: N=1 is the identity, useful as a wiring
  placeholder during incremental spec authoring.

## Why not widen \`generic.aux-xor@1\`

Today's \`generic.aux-xor@1\` reads one operand from the aux map by
name — that aux read is implicit and not wireable. \`xor@1\` ships
under the port-native contract where every operand is an explicit
input port; the two coexist because they serve different mental
models (legacy aux-typed flow vs universal port-typed flow).

## Errors

- Throws if \`params.inputCount\` is missing, not an integer, or < 1.
- Throws if any expected operand port is missing on the input map.
- Throws if operands disagree on length — coercion is an editor /
  edge-projection concern per the universal-port plan's Q2, NOT a
  step-level concern.

## Phase status

Shipped in Slice 2.1b of the universal-port-dataflow plan, alongside
\`add-mod-32@1\`. Not yet wired into any cipher spec — Slice 2.6's
SHA-256 build is the first consumer; AES + DES rebuilds in Phases 3/4
follow.`,
  params: new Map([
    [
      "inputCount",
      "Number of input operand ports. Positive integer (≥ 1). N=1 is identity; N≥2 is the usual cryptographic case.",
    ],
  ]),
  references: [
    "FIPS 180-4 §4.1.2 (SHA-256 helper functions σ0, σ1 and message schedule)",
    "FIPS 197 §5.1.4 (AES AddRoundKey — XOR variant)",
  ],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead. The state-shape-contracts test skips
  // `kind: "ported"` registrations that lack a `legacy` field.
};
