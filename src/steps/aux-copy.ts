/**
 * Copy an aux value verbatim from one key to another.
 *
 * Reads `aux[from]`, writes the same value (Uint8Array deep-copied; other
 * shapes referenced through) to `aux[to]`. State is passthrough. The third
 * of the Slice 10 aux primitives.
 *
 * ## Use cases
 *
 *  - **Snapshotting a feedback value.** CBC's chain destroys its previous
 *    ciphertext on every iteration (the XOR overwrites \`aux[feedback]\`).
 *    A \`aux-copy feedback → C_i\` step preserves the per-block output
 *    before the next \`aux-xor\` clobbers it.
 *
 *  - **Renaming an aux value to wire it elsewhere.** A user composing a
 *    custom mode in the visual editor can drag an \`aux-copy\` to route
 *    \`key-expansion\`'s \`roundKey.0\` into a slot a later step reads
 *    under a different name — no need to edit the upstream step's params.
 *
 *  - **Initializing a chain.** \`aux-copy IV → feedback\` at the start of a
 *    CBC composition preserves the IV separately from the running
 *    accumulator (so a second decrypt pass that re-reads \`aux[IV]\` still
 *    finds the original).
 *
 * ## Missing-aux semantics — graceful, NOT throwing
 *
 * If \`aux[from]\` is undefined at read time, the step returns passthrough
 * with no \`auxWrites\`. \`auxReads: [from]\` is still declared so the
 * runtime records the miss in \`TraceFrame.auxReadMissing\` and Slice 9's
 * \`validateGraph\` surfaces an orphaned-read warning on the node. Same
 * authoring-time discipline as \`aux-xor\`.
 *
 * ## Why a fresh allocation for Uint8Array
 *
 * The runtime mutates aux values via fresh assignments, not in-place edits,
 * so technically two aux entries could safely share a Uint8Array reference.
 * But the very next \`aux-xor\` step that writes into one of them would
 * silently mutate the other if any future executor stops being careful.
 * The cost is one allocation per copy; the win is "every aux value owns
 * its bytes" as an invariant.
 *
 * Non-byte aux shapes (State, State[], number, bigint) pass through by
 * reference — those are deeply immutable by construction (State.bytes is
 * never mutated in place once published; State[] is built fresh per
 * iterate accumulation). Adding deep copies there would just burn cycles.
 */

import type { AuxValue, Json, StepDocumentation, StepExecutor } from "../core/types";

export const auxCopy: StepExecutor = (state, params, ctx) => {
  const { from, to } = readParams(params);
  // Declare the read regardless of presence so the runtime can record a
  // missing key in `frame.auxReadMissing` (which surfaces as a Slice 9
  // orphan-read warning glyph on the node). Empty `from` is by
  // construction missing — `ctx.aux.get("")` is undefined.
  const auxReads: readonly string[] = [from];

  const value = from === "" ? undefined : ctx.aux.get(from);
  if (value === undefined) {
    // Missing-key path: passthrough, no write.
    return { state, auxReads };
  }

  // No `to` to write to → still passthrough; the read was successful, so
  // no orphan warning fires either. This is the "half-wired forward"
  // authoring state and isn't surfaced specially.
  if (to === "") {
    return { state, auxReads };
  }

  // Defensive copy of Uint8Array; other AuxValue shapes pass through by
  // reference (see file header for the reasoning).
  const copied: AuxValue = value instanceof Uint8Array ? new Uint8Array(value) : value;
  const auxWrites = new Map<string, AuxValue>([[to, copied]]);
  return { state, auxReads, auxWrites };
};

export const auxCopyDoc: StepDocumentation = {
  name: "Aux Copy",
  summary: "Copy aux[from] verbatim into aux[to] (no state change).",
  detail: `## Aux Copy

A straight assignment between aux slots:

\`\`\`
state          → state (passthrough)
aux[from]      → aux[to] := aux[from]   (Uint8Array deep-copied)
\`\`\`

\`aux[from]\` is left unchanged. If the value is a \`Uint8Array\`, the
written copy is a fresh allocation — \`aux[to]\` does not share storage
with \`aux[from]\`. Non-byte aux shapes (State, State[], integers, bigints)
pass through by reference, since the architecture treats those as
immutable once published.

**Use cases.** Three patterns dominate:

- **Snapshot before destructive update.** Chaining modes XOR over their
  feedback buffer, overwriting the previous ciphertext. \`aux-copy
  feedback → C_i\` preserves the per-block output before the next
  iteration's XOR clobbers it.
- **Rename to bridge two steps.** Re-route an upstream step's output to
  a downstream step that reads under a different key — without editing
  either step's params.
- **Initialize a chain.** \`aux-copy IV → feedback\` at the head of a CBC
  composition so the original IV stays available later in the trace.

**Graceful when not yet wired.** If \`aux[from]\` is undefined at read
time, the step is a passthrough — no error, no write. The visual editor
flags the missing read with a warning glyph on the node so a half-built
spec is debuggable in place.`,
  params: new Map([
    ["from", "Aux key to read. Read-only — this step does not modify aux[from]."],
    [
      "to",
      "Aux key to write to. The value is a fresh copy when source is a Uint8Array; other shapes pass through by reference.",
    ],
  ]),
  references: ["NIST SP 800-38A §6 (Modes of Operation)"],
  shapeContract: { input: "any", output: "preserveInput" },
};

/**
 * Lenient param reader — undefined/absent and empty string both map to
 * `""` (the executor's "unset" sentinel). Non-string values throw because
 * users can't type one through the text input; a non-string is a
 * malformed JSON spec, not an in-progress authoring state.
 */
const readParams = (params: Json): { from: string; to: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("aux-copy: params must be an object");
  }
  const p = params as { from?: unknown; to?: unknown };
  if (p.from !== undefined && typeof p.from !== "string") {
    throw new Error("aux-copy: from must be a string");
  }
  if (p.to !== undefined && typeof p.to !== "string") {
    throw new Error("aux-copy: to must be a string");
  }
  return { from: p.from ?? "", to: p.to ?? "" };
};
