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

Combines two or more equal-length byte strings by exclusive-OR. It takes N
inputs — \`operand0\`, \`operand1\`, …, \`operand{N-1}\` (N is set by
\`inputCount\`) — and produces one output that is their bitwise XOR.

## Math

For each byte position \`j\`:

\`\`\`
output[j] = operand0[j] ⊕ operand1[j] ⊕ … ⊕ operand{N-1}[j]
\`\`\`

All inputs must be the **same length** — XOR combines them position by
position. It is commutative and associative, so the order of the inputs does
not change the result. A value XOR'd with itself is zero, and XOR with zero
leaves a value unchanged: \`xor(a, a) = 0\` and \`xor(a, 0…0) = a\`. That
self-inverse property is why the same XOR undoes itself, which is what makes
it the workhorse of key mixing and chaining.

## Where it fits

- **Adding a key to data** — XOR is how nearly every cipher folds key
  material into the block: AES's AddRoundKey, Blowfish's \`L ⊕ P[i]\` at the
  start of each round, and the key-mixing that seeds Blowfish's key schedule.
- **Feistel round combination** — the output of the round's F-function is
  XOR'd into the other half of the block.
- **SHA-256 helper functions** — σ0/σ1 XOR three rotated/shifted copies of a
  word; the message schedule XORs four words together
  (\`W_t = σ1(W_{t-2}) ⊕ W_{t-7} ⊕ σ0(W_{t-15}) ⊕ W_{t-16}\`).
- **Chaining modes** — CBC XORs each plaintext block with the previous
  ciphertext; OFB and CFB feed the keystream in the same way.

With a single input (\`inputCount = 1\`) XOR just passes it through — handy as
a placeholder while wiring a cipher up; the useful cases XOR two or more.`,
  params: new Map([
    [
      "inputCount",
      "How many inputs to combine. A whole number, 1 or more; 2 or more is the usual case. All inputs must be the same length.",
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
