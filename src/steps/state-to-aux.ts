/**
 * Snapshot the current state into an aux entry.
 *
 * The state↔aux bridge step that `CLAUDE.md` flagged as a future need
 * once the aux primitives shipped. Writes a deep clone of the current
 * state into `aux[auxName]`; state itself passes through unchanged.
 *
 * The companion of `xor-aux-into-state`: encrypt's CBC body XORs the
 * previous ciphertext (aux[chain]) into state before AES, then this step
 * snapshots the post-AES state back into aux[chain] so the NEXT
 * iteration's XOR has the freshly-produced ciphertext block.
 *
 * Decrypt uses it differently: at the TOP of each iteration it snapshots
 * the input ciphertext (aux[next-chain]) BEFORE the AES inverse alters
 * state — so when the post-inverse XOR is done, an `aux-copy` can
 * advance `chain := next-chain` for the next iteration.
 *
 * Always allocates a fresh clone via `cloneState`. Aliasing the live
 * state would let a later mutation (or the next iterate iteration's
 * `state = cloneState(blocks[i])` swap) silently corrupt the snapshot.
 *
 * Generic in shape: any State type round-trips through it. The typical
 * use is MatrixState (CBC chain) but a future Speck-CBC composition
 * could use BytesState.
 */

import { cloneState } from "../core/state/clone";
import type {
  AuxValue,
  Json,
  PortContract,
  ProjectionMetadata,
  StepDocumentation,
  StepExecutor,
} from "../core/types";

export const stateToAux: StepExecutor = (state, params) => {
  const { auxName } = readParams(params);

  // Empty auxName is the freshly-palette-dropped sentinel. No write, no
  // declared read — the step has nothing to read FROM, so an orphan
  // warning wouldn't apply; the user's signal that the step is unwired
  // is just "no auxWritten on the frame," which the inspector already
  // shows. (No glyph fires today; could be added later as a "this step
  // does nothing" hint.)
  if (auxName === "") {
    return { state };
  }

  // Defensive clone — never alias the live state. The runtime's
  // before/after snapshots depend on each frame owning its bytes; aux
  // entries that survive across many frames must be even more
  // carefully decoupled from the running state.
  const snapshot = cloneState(state);
  const auxWrites = new Map<string, AuxValue>([[auxName, snapshot]]);
  return { state, auxWrites };
};

export const stateToAuxDoc: StepDocumentation = {
  name: "State To Aux",
  summary: "Snapshot the current state into an aux entry (deep clone). State is unchanged.",
  detail: `## State To Aux

The state↔aux bridge — the missing inverse of \`load-block\` /
\`split-blocks\`. Takes the current cipher state and copies it (deep
clone) into a named aux entry, so a later step can read it back as
plain aux data.

\`\`\`
state                  → state (passthrough)
aux                    → aux ∪ { [auxName]: clone(state) }
\`\`\`

**Where it lives in a spec.**

Anywhere a downstream step needs the state's CURRENT value preserved
across an in-place mutation (a round, an XOR, the next iterate
iteration's state-swap). The canonical example is CBC's chain update:

\`\`\`
CBC encrypt body:
  xor-aux-into-state(chain)   ← state ⊕= prev-ciphertext
  …AES rounds…                ← state := AES(state) = current ciphertext
  state-to-aux(chain)         ← snapshot ciphertext for next iter

CBC decrypt body:
  state-to-aux(next-chain)    ← save current ciphertext BEFORE AES alters state
  …AES inverse rounds…
  xor-aux-into-state(chain)
  aux-copy(next-chain → chain)
\`\`\`

**Always clones.** Aux entries can survive across many frames and many
iterate iterations; sharing a buffer with the running state would let a
subsequent mutation silently overwrite the snapshot. The clone is
unconditional.

**State-shape agnostic.** Today's specs use it with MatrixState (CBC
chain). A future BytesState-based block cipher with a chain mode would
reuse the same step with no change.

**No orphan-read warning.** This step has no aux *inputs* — it only
writes. An unwired version is inert rather than warning-flagged. The
inspector still shows the empty \`auxWritten\` map, which is enough
authoring-time feedback.`,
  params: new Map([
    [
      "auxName",
      "Aux key to write the state snapshot under. The value is a fresh deep clone — mutating the live state afterward does not alter the snapshot.",
    ],
  ]),
  references: ["NIST SP 800-38A §6.2 (CBC mode chaining variable)"],
  shapeContract: { input: "any", output: "preserveInput" },
};

// ─── Universal port-dataflow metadata (Phase 1 Slice 1.5) ───────────────
// `stateToAuxMeta`: snapshots current state into an aux entry. State
// input/output ports declared (the executor passes state through but the
// snapshot bytes come FROM state). Aux write produces a MatrixState —
// the output port's `layout: "matrix-cm-4x4"` drives the runtime decode
// so `aux[auxName]` lands as a `MatrixState`, matching legacy executor's
// `cloneState(state)` shape.
//
// **stateLayout pinned to `matrix4x4-bytes` despite shapeContract.input
// === "any"`** — these two fields are decoupled. `shapeContract` is
// editor-UX (palette chip, drop-anchor, pre-Run validation); `stateLayout`
// is runtime port encoding. Today the only shipping use is AES-CBC where
// state inside the iterate body is always `matrix4x4-bytes`. A future
// Speck-CBC composition with `bytes`-shape state would register a sibling
// step type, or this slice's `stateLayout` would widen to consult the
// PortContract input port's layout — same shape-transforming question
// Slice 1.3 deferred for `load-block`/`store-block`. Pinning today is
// safe because `portedDispatchEnabled` defaults to false; the runtime
// throws loudly if a flag-on user drags `state-to-aux` into a non-AES
// spec.
//
// **Empty-auxName binding skipped** — legacy early-returns with no
// auxWrites when `auxName === ""`. The metadata mirrors: empty Map from
// `auxWritePorts(params)` so the runtime doesn't try to `aux.set("",
// ...)` on an empty target. Same pattern as `iv-load`'s outAuxName.

export const stateToAuxMeta: ProjectionMetadata = {
  stateLayout: "matrix4x4-bytes",
  stateInputPort: "state",
  stateOutputPort: "state",
  auxWritePorts: (params: Json) => {
    const { auxName } = readParams(params);
    if (auxName === "") return new Map();
    return new Map([["snapshot", auxName]]);
  },
};

/**
 * Declared port surface. `snapshot` output declares layout
 * `matrix-cm-4x4` so the runtime reconstructs the AuxValue as a
 * MatrixState (matching legacy's `cloneState(state)` shape). State ports
 * also matrix-cm-4x4 — AES block today. `byteLength: 16` everywhere.
 */
export const stateToAuxPortContract: PortContract = {
  inputs: new Map([["state", { byteLength: 16, layout: "matrix-cm-4x4" }]]),
  outputs: new Map([
    ["state", { byteLength: 16, layout: "matrix-cm-4x4" }],
    ["snapshot", { byteLength: 16, layout: "matrix-cm-4x4" }],
  ]),
};

const readParams = (params: Json): { auxName: string } => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("state-to-aux: params must be an object");
  }
  const p = params as { auxName?: unknown };
  if (p.auxName !== undefined && typeof p.auxName !== "string") {
    throw new Error("state-to-aux: auxName must be a string");
  }
  return { auxName: (p.auxName as string | undefined) ?? "" };
};
