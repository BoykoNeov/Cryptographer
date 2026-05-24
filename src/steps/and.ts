/**
 * And — port-native N-way bitwise AND primitive (universal-port plan
 * Phase 2 Slice 2.3, 2026-05-24).
 *
 * Reads N input ports (`operand0`, `operand1`, …, `operand{N-1}`)
 * mirroring `xor@1`'s S3-sharpened convention — each operand is wired
 * in from the spec's sink-only edge graph, NOT from `aux`. Output port
 * `output` carries the byte-wise AND of all operands. All operands
 * must share the same length (coercion is an EDGE-projection concern
 * per Q2, surfaced as a visible trace step at the wiring boundary).
 *
 * **Why a NEW step type vs widening anything existing.** No legacy
 * step type expresses bitwise AND — the closest cousin
 * (`generic.aux-xor@1`) reads from `aux`, not from explicit ports.
 * `and@1` ships under the port-native contract: every operand is an
 * explicit input port, the editor can wire any source to any operand,
 * and N generalizes from 2 to whatever the consumer needs (SHA-256
 * Ch/Maj use 2-way; future Threefish/SHA-3 χ steps could push higher).
 *
 * **Where it fits.** SHA-256's Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z) and
 * Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z) (FIPS 180-4 §4.1.2)
 * are the first port-native consumers. With `xor@1` (Slice 2.1b) and
 * `not@1` (this slice), Ch/Maj decompose into three primitives that
 * have nothing SHA-256-specific about them. Under the universal-port
 * plan's thesis this is the right answer — cipher-specific step types
 * (the rejected Open #N3 option (a)) would walk back Phase 1's
 * elimination work.
 *
 * **`inputCount` minimum is 1.** Mirrors `xor@1`'s N≥1 floor (Fork 1
 * pinned 2026-05-24). N=1 is the identity (passthrough); N=0 is
 * rejected because the output byteLength would be undefined. The
 * degenerate N=1 case lets a spec compose cleanly while only one
 * operand has been wired during authoring; the eventual N≥2 wiring
 * is what cryptographic specs need.
 *
 * **Authoring conventions.** Port-native: omit `legacy`, omit `meta`,
 * omit `shapeContract`. Same posture as `rotate-bits-right.ts` (Slice
 * 2.1a) and `xor.ts` / `add-mod-32.ts` (Slice 2.1b). PortContract uses
 * function form on the input side because the port count varies with
 * `params.inputCount`; output is always a one-port map (`output`).
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
    throw new Error("and: params must be an object");
  }
  const p = params as Record<string, Json>;
  const inputCount = p.inputCount;
  if (typeof inputCount !== "number" || !Number.isInteger(inputCount) || inputCount < 1) {
    // N=0 rejected: output byteLength would be undefined (no operand to
    // derive it from). N=1 allowed as identity — useful during spec
    // authoring before all operands are wired.
    throw new Error("and: params.inputCount must be a positive integer (≥ 1)");
  }
  return { inputCount };
};

// ─── Port naming helper ───────────────────────────────────────────────────

/**
 * Build the canonical port name for the i-th operand. Same convention
 * as `xor`'s operand port names (`operand0`, `operand1`, …). Exported
 * for tests + future spec-builder helpers — a typo against the executor
 * would silently break wiring.
 */
export const andOperandPortName = (i: number): string => `operand${i}`;

// ─── Port contract + executor ─────────────────────────────────────────────

/**
 * Function-form PortContract on the input side ONLY — same posture as
 * `xor`'s contract. The output side is a fixed single `output` port, so
 * static form there matches the rotate-bits-right precedent and the
 * "function form only when N varies on THIS side" rule pinned at Slice
 * 1.4. Polymorphic `byteLength` on every port — the consumer's wiring
 * determines the actual length at edit time, and the executor enforces
 * the same-length invariant at execute time.
 */
export const andPortContract: PortContract = {
  inputs: (params: Json) => {
    const { inputCount } = readParams(params);
    const entries: [string, PortShape][] = [];
    for (let i = 0; i < inputCount; i++) {
      entries.push([andOperandPortName(i), { layout: "raw" }]);
    }
    return new Map(entries);
  },
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const and: PortedExecutor = (inputs, params, _ctx) => {
  const { inputCount } = readParams(params);

  // Collect operands in port-name order. Mirror `xor`'s explicit
  // missing-port error so the editor surfaces the exact unwired arrow.
  const operands: Uint8Array[] = [];
  for (let i = 0; i < inputCount; i++) {
    const name = andOperandPortName(i);
    const bytes = inputs.get(name);
    if (bytes === undefined) {
      throw new Error(`and: missing required input port "${name}"`);
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
        `and: operand${i} length ${op.length} does not match operand0 length ${byteLength}`,
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

  // N ≥ 2: byte-wise AND all operands into the output buffer.
  // Initialize with operand0; AND in operands 1..N-1.
  out.set(operands[0] as Uint8Array);
  for (let i = 1; i < inputCount; i++) {
    const op = operands[i] as Uint8Array;
    for (let j = 0; j < byteLength; j++) {
      out[j] = (out[j] as number) & (op[j] as number);
    }
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const andDoc: StepDocumentation = {
  name: "AND",
  summary:
    "N-way byte-wise bitwise AND of operand0..operand{N-1}. All operands must share the same length; output carries the conjunction.",
  detail: `# AND

Universal port-native bitwise-AND primitive. Takes N input ports named
\`operand0\`, \`operand1\`, …, \`operand{N-1}\` (where N is set by
\`params.inputCount\`), produces one output port \`output\` carrying
the byte-wise AND of all operands.

## Math

For each byte position \`j\`:

\`\`\`
output[j] = operand0[j] ∧ operand1[j] ∧ … ∧ operand{N-1}[j]
\`\`\`

AND is commutative and associative, so operand order does not affect
the result. AND with all-ones is the identity, AND with zero is zero,
and AND of any value with itself is itself (\`a ∧ a = a\`).

## Where it fits

- **SHA-256 Ch(x, y, z) = (x ∧ y) ⊕ (¬x ∧ z)** (FIPS 180-4 §4.1.2):
  one 2-way \`and@1\` on \`(x, y)\`, one \`not@1\` on \`x\`, one 2-way
  \`and@1\` on \`(¬x, z)\`, then \`xor@1\` to combine. The "choice"
  function selects bit-by-bit from \`y\` when \`x\` is 1 and from \`z\`
  when \`x\` is 0.
- **SHA-256 Maj(x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)** (FIPS
  180-4 §4.1.2): three 2-way \`and@1\` leaves and one 3-way \`xor@1\`.
  The XOR-form of majority avoids needing \`or@1\` — picked
  intentionally so SHA-256 ships with two new primitives, not three.
- **Bit masking generally**: any spec that needs to zero out bit
  ranges (e.g., DES key parity-bit strip, future SHA-3 χ step) does so
  with an \`and@1\` against a literal mask wired in from \`aux-load\`
  or a constant primitive.
- **Identity passthrough**: N=1 is the identity, useful as a wiring
  placeholder during incremental spec authoring.

## Why not widen \`generic.aux-xor@1\` or similar

The closest cousin \`generic.aux-xor@1\` reads one operand from the
aux map by name — that aux read is implicit and not wireable. \`and@1\`
ships under the port-native contract where every operand is an
explicit input port. There is no existing step type that does AND
under either contract, so no widening question arises.

## Errors

- Throws if \`params.inputCount\` is missing, not an integer, or < 1.
- Throws if any expected operand port is missing on the input map.
- Throws if operands disagree on length — coercion is an editor /
  edge-projection concern per the universal-port plan's Q2, NOT a
  step-level concern.

## Phase status

Shipped in Slice 2.3 of the universal-port-dataflow plan, alongside
\`not@1\`. Not yet wired into any cipher spec — Slice 2.6's SHA-256
build is the first consumer (Ch and Maj).`,
  params: new Map([
    [
      "inputCount",
      "Number of input operand ports. Positive integer (≥ 1). N=1 is identity; N=2 is the SHA-256 Ch/Maj case; higher N is unusual but algebraically valid.",
    ],
  ]),
  references: ["FIPS 180-4 §4.1.2 (SHA-256 helper functions Ch and Maj)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract instead. The state-shape-contracts test skips
  // `kind: "ported"` registrations that lack a `legacy` field.
};
