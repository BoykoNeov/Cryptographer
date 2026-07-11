/**
 * Load a literal byte sequence into an aux slot.
 *
 * The simplest of the three Slice 10 aux primitives: a step that has no
 * dataflow inputs at all — its output (the value to publish) lives entirely
 * in `params.value`. Used for placing an IV, a counter starting value, a
 * tweak, or any other constant the user wants to thread into the cipher
 * via aux without writing a custom executor.
 *
 * No state port. Port-native `PortedExecutor` (Slice 5.2): the output is the
 * byte sequence on the `value` output port, which the runtime maps to
 * `aux[auxName]` (via meta.auxWritePorts). Downstream consumers (e.g.
 * `aux-xor`, `aux-copy`, or a cipher-specific step) read it from there.
 *
 * Why a number[] in params rather than a hex string or base64:
 *  - The shape matches every other byte-table param shipped today (S-box,
 *    rcon, MixColumns matrix); JSON-portable; survives the document
 *    round-trip and stable-key-order saves without special handling.
 *  - The existing `ByteCellInput` + `rcon-row` pattern in `ParamEditor.tsx`
 *    drops in directly for editing.
 *  - The executor doesn't need to parse anything — it just copies values
 *    into a fresh Uint8Array.
 *
 * Composition: paired with `aux-xor`/`aux-copy`, this is enough to build
 * CBC's chaining math from primitives (load IV, copy into a feedback slot,
 * xor each plaintext block into feedback, copy out per-block). See the
 * "compose your own mode" recipe in `src/steps/CLAUDE.md`.
 */

import type {
  Json,
  PortContract,
  PortedExecutor,
  ProjectionMetadata,
  StepDocumentation,
} from "../core/types";

export const auxLoad: PortedExecutor = (_inputs, params, _ctx) => {
  const { auxName, value } = readParams(params);
  // Unset auxName (freshly palette-dropped state) → no output port. The
  // runtime's meta.auxWritePorts also returns an empty binding for an unset
  // auxName, so nothing is published and the user can still click the node
  // and edit params normally.
  if (auxName === "") {
    return new Map();
  }
  // Fresh Uint8Array per call — never alias the params array. The runtime
  // may persist this value across many frames; sharing the backing storage
  // with a JSON literal in params would break the immutability the trace
  // depends on for `before`/`after` snapshots.
  const bytes = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const v = value[i] ?? 0;
    if (!Number.isInteger(v) || v < 0 || v > 255) {
      throw new Error(`aux-load: value[${i}] must be an integer in [0, 255], got ${v}`);
    }
    bytes[i] = v;
  }
  // Single `value` output port; the runtime maps it to `aux[auxName]` via
  // meta.auxWritePorts, so `frame.auxWritten` still carries the loaded literal.
  return new Map([["value", bytes]]);
};

export const auxLoadDoc: StepDocumentation = {
  name: "Aux Load",
  summary: "Publish a literal byte sequence under an aux key (IV, counter, tweak, …).",
  detail: `## Aux Load

Writes a fixed byte sequence — taken straight from the step's \`value\`
parameter — into \`aux[auxName]\`. The step has no data inputs; the value is
a constant baked into the spec.

\`\`\`
state → state (passthrough)
aux   → aux ∪ { [auxName]: Uint8Array(value) }
\`\`\`

**When to use:** any time the cipher needs a value that doesn't come from
the plaintext, key, or another step's output. Canonical examples:

- An **initialization vector (IV)** for CBC, OFB, CFB.
- A **counter starting value** for CTR.
- A **tweak** for tweakable modes (XEX, XTS).
- A **per-mode constant** baked into a hand-built compound cipher.

**Building a mode of operation.** Together with **Aux XOR** and **Aux Copy**,
this lets you build chaining modes (CBC, OFB, CFB) by hand instead of picking
one from a list. CBC, for instance, is:

\`\`\`
Aux Load  IV         → feedback
[per block]
  Aux XOR  P_i, feedback     → feedback   (P_i ⊕ previous ciphertext)
  <cipher core on feedback>               (e.g. AES round body)
  Aux Copy feedback → C_i                 (record the ciphertext block)
\`\`\`

**The point:** the trace shows the loaded value as just another named piece
of data — the same shape every round key has — so an IV reads as ordinary
data fed in, not a special kind of input.`,
  params: new Map([
    [
      "auxName",
      "The name to store the value under, so later steps can find it. Any non-empty label.",
    ],
    [
      "value",
      "The fixed byte sequence to store, as numbers 0–255. Its length is up to you; the steps that read it decide what length they need.",
    ],
  ]),
  references: [
    "NIST SP 800-38A §6 (Modes of Operation — IV requirements)",
    "RFC 3686 §4 (CTR mode counter block formatting)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.2) ───────────────
// `auxLoadMeta` lets the runtime project this leaf's `auxWrites` into a
// named output port when running under `portedDispatchEnabled: true`.
// Aux-only step: no state ports declared (state passes through unchanged,
// matching `shapeContract: { input: "any", output: "preserveInput" }`).
//
// `auxWritePorts({ auxName: "" })` returns an EMPTY Map so the
// fresh-palette-drop case (auxName unset) doesn't emit a binding to the
// empty string — that would diverge from the legacy executor's no-write
// passthrough and surface as a frame-parity miss. Same discipline as
// `auxXorMeta` / `auxCopyMeta` / `ivLoadMeta` below.

export const auxLoadMeta: ProjectionMetadata = {
  // No state ports — state is passthrough. `stateLayout` is unused here
  // but the field is required; pick `"bytes"` as the no-op convention.
  stateLayout: "bytes",
  auxWritePorts: (params: Json) => {
    const { auxName } = readParams(params);
    if (auxName === "") return new Map();
    // Single output port named `"value"` (the natural noun for an
    // aux-load — the value it published). Binds to whatever aux key the
    // user picked.
    return new Map([["value", auxName]]);
  },
};

/**
 * Declared port surface for the universal-port editor / inspector.
 * `byteLength` is absent (polymorphic — user picks the literal length).
 */
export const auxLoadPortContract: PortContract = {
  inputs: new Map(),
  outputs: new Map([["value", { layout: "raw" }]]),
};

/**
 * Lenient param reader. Undefined/empty `auxName` collapses to `""` (the
 * executor treats that as "unset"). Undefined `value` collapses to `[]`.
 * Non-string `auxName` or non-array `value` throw (users can't produce
 * those via the UI; their presence means a malformed JSON spec).
 */
const readParams = (params: Json): { auxName: string; value: readonly number[] } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aux-load: params must be an object");
  }
  const p = params as { auxName?: unknown; value?: unknown };
  if (p.auxName !== undefined && typeof p.auxName !== "string") {
    throw new Error("aux-load: auxName must be a string");
  }
  if (p.value !== undefined && !Array.isArray(p.value)) {
    throw new Error("aux-load: value must be an array of integers");
  }
  return {
    auxName: (p.auxName as string | undefined) ?? "",
    value: (p.value as readonly number[] | undefined) ?? [],
  };
};
