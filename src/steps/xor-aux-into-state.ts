/**
 * Byte-wise XOR an aux MatrixState into the current state.
 *
 * The chaining mode XOR. CBC encrypts each plaintext block as
 * `AES(P_i ⊕ C_{i-1})`; the running `C_{i-1}` (or `IV` for the first
 * iteration) lives in an aux entry, and this step folds it into the
 * state in place at the top of each iteration:
 *
 *     state ⊕= aux[auxName]
 *
 * State shape preserved (MatrixState in → MatrixState out, same bytes
 * XORed). The companion step is `state-to-aux`, which snapshots the
 * post-round state back into the aux entry so the NEXT iteration's XOR
 * has the updated feedback. Together with `iv-load` they let a spec
 * compose any feedback-XOR chaining mode (CBC, OFB, CFB) inside the
 * iterate body.
 *
 * Pairs with `xor-aux-into-state` on the decrypt side too: CBC decryption
 * XORs the previous ciphertext block AFTER the AES inverse, with the same
 * step (decrypt body uses `state-to-aux` to snapshot the input ciphertext
 * first, then runs inverse rounds, then this XOR, then advances the chain
 * via `aux-copy`).
 *
 * Self-inverse on a fixed `aux[auxName]`: applying the step twice with
 * the same aux entry cancels out. That's intrinsic to XOR, not a
 * convenience — it's why feedback modes use XOR rather than addition.
 *
 * Today the executor is AES-shaped: state and aux value must both be
 * `MatrixState`. A future BytesState-based cipher would register a
 * sibling. The narrow contract keeps the error messages crisp.
 */

import { cloneMatrix } from "../core/state/matrix";
import type { Json, StepDocumentation, StepExecutor } from "../core/types";

export const xorAuxIntoState: StepExecutor = (state, params, ctx) => {
  const { auxName } = readParams(params);

  // Always declare the read so the runtime records misses for the
  // orphan-warning overlay (Slice 9), even when the param is the empty
  // sentinel from a fresh palette drop.
  const auxReads: readonly string[] = [auxName];

  const operand = auxName === "" ? undefined : ctx.aux.get(auxName);

  // Missing-key path: passthrough, no XOR. The user is mid-wiring; the
  // visual editor will flash an orange `!` on the node.
  if (operand === undefined) {
    return { state, auxReads };
  }

  // Structural validation: state and operand must both be MatrixStates of
  // the same shape. Anything else means a spec authoring bug; throw with
  // a descriptive message so the App's error banner can point at the
  // offending key.
  if (state.shape !== "matrix4x4-bytes") {
    throw new Error(`xor-aux-into-state: state must be matrix4x4-bytes, got ${state.shape}`);
  }
  if (typeof operand !== "object" || !("shape" in operand)) {
    throw new Error(
      `xor-aux-into-state: aux["${auxName}"] must be a MatrixState, got ${describeValue(operand)}`,
    );
  }
  if (operand.shape !== "matrix4x4-bytes") {
    throw new Error(
      `xor-aux-into-state: aux["${auxName}"] must be matrix4x4-bytes, got ${operand.shape}`,
    );
  }
  if (operand.bytes.length !== state.bytes.length) {
    throw new Error(
      `xor-aux-into-state: length mismatch — state=${state.bytes.length} bytes, aux["${auxName}"]=${operand.bytes.length} bytes`,
    );
  }

  // Allocate a fresh matrix for the output — never mutate `state.bytes`
  // in place. The runtime's clone in `before` would otherwise reflect
  // the post-XOR bytes and the trace's `before` snapshot would be a lie.
  const out = cloneMatrix(state);
  for (let i = 0; i < out.bytes.length; i++) {
    // Non-null assertions avoided per the project's
    // `noUncheckedIndexedAccess` settings; the `?? 0` fallback can never
    // trigger because i < length, but the type system can't see that.
    out.bytes[i] = (state.bytes[i] ?? 0) ^ (operand.bytes[i] ?? 0);
  }

  return { state: out, auxReads };
};

export const xorAuxIntoStateDoc: StepDocumentation = {
  name: "XOR Aux Into State",
  summary: "XOR an aux MatrixState into the current state (the chaining XOR used by CBC, CFB, …).",
  detail: `## XOR Aux Into State

Byte-wise XOR of the current cipher state with a value held in aux:

\`\`\`
state           ← state ⊕ aux[auxName]
\`\`\`

Both operands must be \`matrix4x4-bytes\` MatrixStates with the same byte
length (16). The operation is per-byte XOR — identical to the chaining
XOR called out in NIST SP 800-38A §6.2 for CBC and §6.3 for CFB.

**Where it lives in a spec.** Inside the per-block iterate body of any
feedback-chaining mode:

- **CBC encrypt** — runs FIRST in the body so the plaintext block gets
  XOR'd with the previous ciphertext (or the IV for block 0) before AES.
- **CBC decrypt** — runs LAST in the body so the post-inverse-AES state
  gets XOR'd with the previous ciphertext (or the IV) to recover the
  plaintext.

\`\`\`
iterate {
  xor-aux-into-state  auxName=chain   ← encrypt: state ⊕= prev-ciphertext
  …AES round body…
  state-to-aux         auxName=chain  ← encrypt: snapshot ciphertext for next iter
}
\`\`\`

**Self-inverse property.** XOR cancels under repetition: \`A ⊕ B ⊕ B =
A\`. That property is why feedback modes use XOR — encryption mixes in
the feedback, decryption mixes the same feedback back out.

**Graceful when not wired yet.** If \`aux[auxName]\` isn't present, the
step is a passthrough — no state change, no error, no write. The visual
editor's overlay flags the missing read with an orange \`!\`.

**Today's contract.** State and operand must both be the AES 4×4 byte
matrix. A future block cipher with a different state shape would
register a sibling step.`,
  params: new Map([
    [
      "auxName",
      "Aux key to read the XOR operand from. Must reference a MatrixState (16 bytes, 4×4). Typically `chain` for CBC.",
    ],
  ]),
  references: [
    "NIST SP 800-38A §6.2 (CBC mode)",
    "NIST SP 800-38A §6.3 (CFB mode)",
    "NIST SP 800-38A §6.4 (OFB mode)",
  ],
  shapeContract: { input: "matrix4x4-bytes", output: "preserveInput" },
};

const readParams = (params: Json): { auxName: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("xor-aux-into-state: params must be an object");
  }
  const p = params as { auxName?: unknown };
  if (p.auxName !== undefined && typeof p.auxName !== "string") {
    throw new Error("xor-aux-into-state: auxName must be a string");
  }
  return { auxName: (p.auxName as string | undefined) ?? "" };
};

const describeValue = (v: unknown): string => {
  if (v === null || v === undefined) return String(v);
  if (typeof v === "number") return `number (${v})`;
  if (typeof v === "bigint") return "bigint";
  if (Array.isArray(v)) return `State[] (length ${v.length})`;
  if (v instanceof Uint8Array) return `Uint8Array (length ${v.length})`;
  return typeof v;
};
