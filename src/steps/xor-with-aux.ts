/**
 * xor-with-aux — port-native "XOR a named aux value into the port-flowing
 * bytes" primitive (scaffolding-suppression Phase B, Finding F3, 2026-05-30).
 *
 * **Why this primitive exists.** Byte-native AddRoundKey was two leaves: an
 * `aux-load-bytes@1` (`fetch-rk`) that exposes `aux["roundKey.N"]` on a port,
 * followed by a 2-way `xor@1` that XORs that port into the carried state —
 * the SHA-256 fetch-then-combine idiom. FIPS-197 §5.1.4 AddRoundKey is a
 * SINGLE operation, and the user asked it to READ as one step in the graph.
 * This primitive fuses the fetch + XOR: it reads its second operand directly
 * from the aux map (declared via `meta.auxReadPorts`, exactly like
 * `aux-load-bytes@1`) and XORs it into the port input, all in one leaf.
 *
 * **How it works.** Hybrid registration shape — `kind: "ported"` with
 * `meta.auxReadPorts` present and NO `legacy` executor (the same shape
 * `aux-load-bytes@1` and `state-to-bytes@1` set the precedent for). Two
 * input ports:
 *   - `input`  — the carried bytes, wired via the spec's `portInputs` (the
 *     cipher state coming into AddRoundKey).
 *   - `operand` — projected by the runtime from `aux[params.auxName]` BEFORE
 *     the executor runs (the round key written by `aes.key-expansion@1`).
 * One output port `output` carries `input ⊕ operand`. Because the aux read is
 * declared in `auxReadPorts`, the runtime records it in `frame.auxRead`, which
 * is what preserves the key-expansion → AddRoundKey fan-out edge in the graph
 * (the fan-out simply lands on this leaf now instead of on the old `fetch-rk`).
 *
 * **Generic, not AES-specific.** This is `xor-with-aux@1` (bare name = the
 * port-native vocabulary), not `aes.add-round-key@1`. AES leaves carry a
 * `narrationOverride` so the inspector still reads "AddRoundKey", but the
 * primitive itself is reusable: DES's `XOR with K_i` and Serpent's AddRoundKey
 * are the same operation and could adopt it in their Phase-4d rebuilds. The
 * param is the generic `auxName` (matching the sibling aux primitives
 * `aux-load-bytes@1` / `xor-aux-into-state@1`), not the cipher-flavored
 * `roundKeyAux`.
 *
 * **Variant-agnostic.** No `byteLength` on the ports: AES round keys are 16
 * bytes, DES round keys 6 bytes, and a custom cipher whatever it wires. The
 * runtime's port-length coercion opts out of polymorphic (byteLength-absent)
 * ports, so the executor enforces the same-length invariant at run time
 * instead. A length mismatch is a wiring bug surfaced loudly, never silently
 * padded or truncated.
 *
 * **Missing-aux semantics mirror `aux-load-bytes@1`.** The `auxReadPorts`
 * binding is emitted UNCONDITIONALLY — even when `auxName === ""` (the
 * fresh-palette-drop default) — so the runtime records the miss in
 * `frame.auxReadMissing` and the editor surfaces an orphan-read warning glyph.
 * If the operand port is then unfilled at execute time the executor THROWS
 * (the warning glyph is the first line of defense; the throw is the second) —
 * the same posture the two-leaf `fetch-rk` had.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

// ─── Params ───────────────────────────────────────────────────────────────

type Params = {
  /** Aux key whose value is XORed into the `input` port. Conventionally
   *  `roundKey.{N}` for AES/DES round keys. Empty string is the
   *  fresh-palette-drop default — allowed so the orphan-read glyph can
   *  surface, but the executor throws if the operand stays unwired. */
  readonly auxName: string;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("xor-with-aux: params must be an object");
  }
  const p = params as Record<string, Json>;
  const auxName = p.auxName;
  if (auxName !== undefined && typeof auxName !== "string") {
    throw new Error("xor-with-aux: params.auxName must be a string");
  }
  return { auxName: (auxName as string | undefined) ?? "" };
};

// ─── Port contract ──────────────────────────────────────────────────────────
//
// `input` is wired via the spec's `portInputs` (the carried bytes). `operand`
// is filled by the runtime from `aux[auxName]` via `meta.auxReadPorts`. Both
// `raw` and polymorphic (no `byteLength`) — the length is wiring-determined,
// and the executor enforces the input == operand invariant. Output `output`
// carries the XOR; the leaf id stays `*.add-round-key`, so downstream
// `port(*.add-round-key, "output")` references are unchanged from the old
// two-leaf shape.

export const xorWithAuxPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["operand", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

// ─── Executor ────────────────────────────────────────────────────────────────

export const xorWithAux: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const input = inputs.get("input");
  const operand = inputs.get("operand");
  if (input === undefined) {
    throw new Error(
      "xor-with-aux: input port 'input' is not wired (declare it in the spec node's `portInputs` map — it carries the bytes the aux value is XORed into)",
    );
  }
  if (operand === undefined) {
    throw new Error(
      "xor-with-aux: operand port not available — the runtime projects aux[params.auxName] onto the 'operand' port via meta.auxReadPorts; check that aux[auxName] is populated by an earlier leaf (e.g. the key schedule) and that params.auxName is set",
    );
  }
  // Same-length invariant — coercion at port boundaries is an editor concern,
  // not a step concern; silently padding/truncating would hide a wiring bug.
  if (input.length !== operand.length) {
    throw new Error(
      `xor-with-aux: length mismatch — input port = ${input.length} bytes, operand (aux value) = ${operand.length} bytes`,
    );
  }
  // Fresh buffer — outputs own their bytes (the port-native convention); the
  // `?? 0` fallbacks never trigger (i < length) but satisfy
  // noUncheckedIndexedAccess.
  const out = new Uint8Array(input.length);
  for (let i = 0; i < out.length; i++) {
    out[i] = (input[i] ?? 0) ^ (operand[i] ?? 0);
  }
  return new Map([["output", out]]);
};

// ─── Projection metadata ──────────────────────────────────────────────────────
//
// `auxReadPorts` is what makes this primitive load-bearing: the runtime reads
// the binding `Map([["operand", auxName]])` and fills `inputs.get("operand")`
// with the bytes encoding of `aux[auxName]` BEFORE the executor runs, AND
// records the read in `frame.auxRead` (which preserves the key-expansion →
// AddRoundKey graph fan-out). The binding is emitted unconditionally — even
// for `auxName === ""` — so the runtime records `frame.auxReadMissing` and the
// editor surfaces an orphan-read warning glyph on a half-wired leaf.
//
// `stateLayout: "bytes"` is the defensive default required by the runtime's
// projection contract for any `kind: "ported"` registration with `meta`
// present. State is NOT threaded through this step (no `stateInputPort` /
// `stateOutputPort`) — the carried bytes arrive on the `input` PORT via
// `portInputs`, not the legacy state thread.

export const xorWithAuxMeta: ProjectionMetadata = {
  stateLayout: "bytes",
  auxReadPorts: (params: Json) => {
    const { auxName } = readParams(params);
    return new Map([["operand", auxName]]);
  },
};

// ─── Doc ──────────────────────────────────────────────────────────────────────

export const xorWithAuxDoc: StepDocumentation = {
  name: "XOR with Aux",
  summary:
    "XOR a named aux value into the port input. The single-step form of fetch-then-XOR (AES AddRoundKey, DES XOR-with-K).",
  detail: `# XOR with Aux

Reads the bytes on the \`input\` port and XORs them, byte-for-byte, with the
value held in \`aux[params.auxName]\`:

\`\`\`
output  =  input  ⊕  aux[auxName]
\`\`\`

The aux value is auto-projected onto the \`operand\` input port by the runtime
(via \`meta.auxReadPorts\`) before this step runs — the same mechanism
\`aux-load-bytes@1\` uses — so it also shows up as an aux-read edge in the
graph, preserving the key-schedule → AddRoundKey fan-out.

## Where it fits

- **AES AddRoundKey (FIPS-197 §5.1.4).** Each round reads its 16-byte
  \`roundKey.N\` and XORs it into the state. The single-step replacement for
  the old \`aux-load-bytes@1\` + \`xor@1\` pair.
- **DES XOR with K_i, Serpent AddRoundKey.** The same operation on a
  different-width state and key — this primitive is variant-agnostic (no fixed
  \`byteLength\`), so those rebuilds can adopt it too.

## Self-inverse

XOR cancels under repetition (\`A ⊕ B ⊕ B = A\`), which is why decryption
re-applies the same round keys in reverse order with this same step — no
separate "unmix" operation.

## Errors

- Throws if \`params.auxName\` is not a string.
- Throws if the \`input\` port is unwired, or if \`aux[auxName]\` is missing at
  execute time (the editor's orphan-read glyph is the first line of defense;
  this throw is the second).
- Throws if the input and the aux operand disagree on length — a wiring bug
  surfaced loudly, never silently padded or truncated.`,
  params: new Map([
    [
      "auxName",
      "Aux key holding the XOR operand (e.g. `roundKey.N`). Must decode to bytes the same length as the input port. Empty string is allowed at authoring time — the editor surfaces an orphan-read glyph until it is wired.",
    ],
  ]),
  references: ["FIPS-197 §5.1.4 (AddRoundKey)", "FIPS 46-3 §3 (DES f-function XOR with K)"],
  // No `shapeContract` — port-native steps describe their surface via the
  // PortContract. The state-shape / narration / provenance coverage contracts
  // all skip `kind: "ported"` registrations that declare no `shapeContract`.
};
