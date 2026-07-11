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
  summary: "XORs a round key (or other key-schedule value) into the block in one step.",
  detail: `# XOR with Aux

XORs the bytes on the \`input\` byte-for-byte with a key-schedule value —
typically a round key. The value is not wired in directly; it is read from a
**named slot** (the \`auxName\`) that an earlier step, usually the key
schedule, filled in:

\`\`\`
output  =  input  ⊕  the value stored under auxName
\`\`\`

This is the everyday way a cipher folds its key material into the data one
round at a time. Keeping the key value in a named slot is what lets a single
key schedule feed the same round key to whichever rounds need it.

## Where it fits

- **Blowfish** starts each round by XORing the round subkey \`P[i]\` into the
  left half of the block (\`L ⊕ P[i]\`); the \`auxName\` names that subkey.
- **AES AddRoundKey** XORs the 16-byte round key into the state each round
  (FIPS-197 §5.1.4).
- **DES and Serpent** do the same at their own block and key sizes — this is
  one general step, not tied to a particular cipher.

## Why the same step decrypts

XOR undoes itself: \`A ⊕ B ⊕ B = A\`. So decryption removes each round key by
XORing the very same value back in (with the round keys applied in reverse
order) — there is no separate "un-XOR" operation. The two inputs must be the
same length.`,
  params: new Map([
    [
      "auxName",
      "The name of the key-schedule slot to XOR in (e.g. `roundKey.N` for AES, a P-array entry for Blowfish). Its value must be the same length as the input. Left blank on a freshly added step, and the editor flags it until you connect it.",
    ],
  ]),
  references: ["FIPS-197 §5.1.4 (AddRoundKey)", "FIPS 46-3 §3 (DES f-function XOR with K)"],
  // No `shapeContract` — port-native steps describe their surface via the
  // PortContract. The state-shape / narration / provenance coverage contracts
  // all skip `kind: "ported"` registrations that declare no `shapeContract`.
};
