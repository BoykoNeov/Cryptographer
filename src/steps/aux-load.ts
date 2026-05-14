/**
 * Load a literal byte sequence into an aux slot.
 *
 * The simplest of the three Slice 10 aux primitives: a step that has no
 * dataflow inputs at all — its output (the value to publish) lives entirely
 * in `params.value`. Used for placing an IV, a counter starting value, a
 * tweak, or any other constant the user wants to thread into the cipher
 * via aux without writing a custom executor.
 *
 * State is passthrough. The "real" output is the byte sequence written into
 * `aux[auxName]`. Downstream consumers (e.g. `aux-xor`, `aux-copy`, or a
 * cipher-specific step) read it from there.
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

import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";

export const auxLoad: StepExecutor = (state, params) => {
  const { auxName, value } = readParams(params);
  // Unset auxName (freshly palette-dropped state) → passthrough, no write.
  // No orphan warning fires (aux-load has no reads), but the user can
  // still click the node and edit params normally. The Slice 9 validator
  // will flag the empty `auxName` only once it lands in a real graph
  // edge — for an unwired aux-load it's just inert.
  if (auxName === "") {
    return { state };
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
  const auxWrites = new Map<string, AuxValue>([[auxName, bytes]]);
  return { state, auxWrites };
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

**Composition.** This is one of three Slice 10 primitives (\`aux-load\`,
\`aux-xor\`, \`aux-copy\`) that together let a user *build* block-cipher
modes inside the visual editor instead of choosing from a fixed list. CBC,
for instance, factors as:

\`\`\`
aux-load   IV         → aux[feedback]
[per block]
  aux-xor  P_i, feedback     → aux[feedback]   (P_i ⊕ prev-cipher)
  <cipher core on feedback>                    (e.g. AES round body)
  aux-copy feedback → C_i                       (publish ciphertext)
\`\`\`

Today only the aux side is wired; once a state↔aux bridge step lands the
composition will extend to drive the cipher state through real AES.

**Educational hook:** the trace shows the loaded value as the step's
\`auxWritten\` entry — exactly the same shape every key-expansion frame
produces — so students see "an IV is just another piece of named data"
rather than a privileged input.`,
  params: new Map([
    ["auxName", "Aux key to write the value under. Any non-empty string."],
    [
      "value",
      "The byte sequence to publish, as an array of integers 0..255. Length is unconstrained by this step; consumers (e.g. aux-xor) impose any shape requirements.",
    ],
  ]),
  references: [
    "NIST SP 800-38A §6 (Modes of Operation — IV requirements)",
    "RFC 3686 §4 (CTR mode counter block formatting)",
  ],
  shapeContract: { input: "any", output: "preserveInput" },
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
