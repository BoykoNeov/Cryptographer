/**
 * XOR one aux byte sequence into another.
 *
 * Reads `aux[from]` and `aux[into]`; writes the byte-wise XOR back to
 * `aux[into]`. State is passthrough. The second of three Slice 10 aux
 * primitives that, together with `aux-load` and `aux-copy`, let a user
 * compose block-cipher chaining modes (CBC, OFB, CFB) inside the visual
 * editor without writing a custom executor.
 *
 * ## Missing-aux semantics — graceful, NOT throwing
 *
 * The whole point of this step shipping in the same slice as the visual
 * editor's palette is that users will drop it onto a graph and wire it up
 * one click at a time. Half-wired specs are the normal authoring state;
 * the step needs to survive them.
 *
 *  - If EITHER \`aux[from]\` or \`aux[into]\` is undefined, this step
 *    returns passthrough with NO \`auxWrites\`. It still DECLARES both
 *    keys in \`auxReads\` so the runtime records the request — Slice 9's
 *    \`validateGraph\` reads \`TraceFrame.auxReadMissing\` to surface an
 *    "orphaned-read" warning on the node.
 *
 *  - If BOTH operands are present but their values are malformed
 *    (non-Uint8Array, or length mismatch), the step THROWS. That's a
 *    programmer/spec error — the kind of mistake a warning glyph
 *    wouldn't help with, because the spec has the wrong shape.
 *
 * The distinction the runtime cares about is "missing key" (a wiring
 * decision the user is still making) vs "malformed value" (a structural
 * bug). The first becomes a soft warning; the second halts the run.
 *
 * ## Why XOR
 *
 * XOR is self-inverse: applying the same operand twice cancels out, which
 * is why every block-cipher chaining mode that uses feedback reduces to a
 * pair of XORs at the start and end of the chain. Surfacing XOR as a
 * standalone aux primitive lets students see the structure plainly,
 * separate from a specific cipher's round function.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

export const auxXor: PortedExecutor = (inputs, _params, _ctx) => {
  // Port-native (Slice 5.2): the two operands arrive on the `from`/`into`
  // input ports, projected from `aux[from]`/`aux[into]` via meta.auxReadPorts.
  // When an aux read is missing, the runtime omits that input port AND records
  // the miss in `frame.auxReadMissing` (from the same meta bindings) — so the
  // graceful "either operand missing → no output" branch below preserves the
  // Slice 9 orphan-read warning behavior without the executor touching the aux
  // map. Empty-string params route the same way (aux.get("") is undefined).
  const from = inputs.get("from");
  const into = inputs.get("into");

  // Missing-key path: no output → no aux write. validateGraph picks up the
  // orphan from `frame.auxReadMissing` and renders a warning glyph.
  if (from === undefined || into === undefined) {
    return new Map();
  }

  // Both present. Port projection always yields Uint8Array, so the only
  // structural error left is a length mismatch (raw ports opt out of
  // coercion) — a spec authoring bug; throw loudly.
  if (from.length !== into.length) {
    throw new Error(
      `aux-xor: length mismatch — from=${from.length} bytes, into=${into.length} bytes`,
    );
  }

  const out = new Uint8Array(from.length);
  for (let i = 0; i < out.length; i++) {
    out[i] = (from[i] ?? 0) ^ (into[i] ?? 0);
  }
  // Single `result` output port; the runtime maps it to `aux[into]` (the
  // in-place accumulator) via meta.auxWritePorts.
  return new Map([["result", out]]);
};

export const auxXorDoc: StepDocumentation = {
  name: "Aux XOR",
  summary: "XOR aux[from] into aux[into], writing the result back to aux[into].",
  detail: `## Aux XOR

Byte-wise XOR of two aux values, with the result replacing one of them:

\`\`\`
state                       → state (passthrough)
aux[from], aux[into]        → aux[into] := aux[from] ⊕ aux[into]
\`\`\`

The operation is symmetric in its inputs (XOR is commutative), but the
asymmetric \`from\`/\`into\` naming captures the intent: \`into\` is the
running accumulator (e.g. CBC's feedback buffer), \`from\` is the new
contribution being mixed in (e.g. the current plaintext block).

**Self-inverse property.** \`A ⊕ B ⊕ B = A\`. Applying the same step twice
with the same \`from\` (and an unchanged \`aux[from]\`) cancels out — which
is why decryption in feedback modes reuses the same XOR with the previous
ciphertext, no separate "unmix" step needed.

**Graceful when wires aren't connected yet.** If either operand's aux key
hasn't been written by an upstream step at the time this step runs, the
step is a passthrough — no error, no write. The visual editor's
validation overlay flags such missing reads with an orange \`!\` glyph on
the node. This lets users build half-wired specs incrementally and see
exactly which connection is still missing.

**Structural errors still throw.** If both operands are present but they
aren't Uint8Arrays, or their lengths don't match, the step halts with a
descriptive error. That's a different class of mistake — a wiring problem
becomes a soft warning; a shape problem stops the run so it can't quietly
produce wrong output.`,
  params: new Map([
    [
      "from",
      "Aux key whose value is the XOR operand to mix IN. Read-only — this step does not modify aux[from].",
    ],
    [
      "into",
      "Aux key whose value is BOTH read (as the second operand) and overwritten with the result.",
    ],
  ]),
  references: [
    "NIST SP 800-38A §6.2 (CBC mode)",
    "NIST SP 800-38A §6.5 (CFB mode)",
    "NIST SP 800-38A §6.4 (OFB mode)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.2) ───────────────
// `auxXorMeta`: aux-only step (no state ports). Two input ports (`from`,
// `into`) project the two operand aux values; one output port (`result`)
// receives the XOR if both operands were present at execution time.
//
// **Iteration order is load-bearing.** The legacy executor declares
// `auxReads: [from, into]`. The ported runtime's `auxReadMissing` array
// iterates the binding Map. JS Maps preserve insertion order, so
// constructing the Map as `[["from", from], ["into", into]]` matches the
// legacy order. Any other ordering breaks frame-parity tests.
//
// Empty-param handling: the legacy executor declares the reads regardless
// of whether `from` / `into` are unset, so the binding Map declares them
// too. `aux.get("")` is undefined → the runtime records `""` in
// `auxReadMissing`, identical to the legacy path.
//
// Write side: the legacy executor only writes to `aux[into]` when both
// reads succeeded. The ported runtime walks `auxWritePorts(params)`
// AFTER the lift adapter returns; missing port outputs silently skip.
// So we can safely declare the `into` binding for any non-empty `into`;
// the runtime stays consistent with the executor's no-write branches.
// Empty `into` returns an empty write binding for the same reason
// `aux-copy` does.

export const auxXorMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { from, into } = readParams(params);
    // Order matches `auxReads: [from, into]` in the legacy executor.
    return new Map([
      ["from", from],
      ["into", into],
    ]);
  },
  auxWritePorts: (params: Json) => {
    const { into } = readParams(params);
    if (into === "") return new Map();
    return new Map([["result", into]]);
  },
};

export const auxXorPortContract: PortContract = {
  inputs: new Map([
    ["from", { layout: "raw" }],
    ["into", { layout: "raw" }],
  ]),
  outputs: new Map([["result", { layout: "raw" }]]),
};

/**
 * Read `from`/`into` params with the lenient authoring contract:
 *  - undefined / absent → "" (treated as unset by the executor)
 *  - empty string       → "" (same)
 *  - non-empty string   → use it
 *  - anything else      → THROW (programmer/spec error; users can only
 *    produce strings via the text inputs, so a non-string here means a
 *    malformed JSON spec)
 *
 * The throw-vs-graceful split mirrors the executor's own missing-vs-
 * malformed distinction. A fresh palette drop arrives with `params: {}`,
 * which lands in the lenient branch and lets the step run as a passthrough
 * so the orphan-read warning surfaces on the node.
 */
const readParams = (params: Json): { from: string; into: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aux-xor: params must be an object");
  }
  const p = params as { from?: unknown; into?: unknown };
  if (p.from !== undefined && typeof p.from !== "string") {
    throw new Error("aux-xor: from must be a string");
  }
  if (p.into !== undefined && typeof p.into !== "string") {
    throw new Error("aux-xor: into must be a string");
  }
  return { from: p.from ?? "", into: p.into ?? "" };
};
