/**
 * Port-native Feistel-round shape analysis (Phase 5 Slice 5.3d).
 *
 * **Why this exists.** When DES went port-native in B4 (universal-port Phase
 * 4d) it stopped using the `feistel-round` branching primitive. Each round
 * became a plain port-mode `group` whose body wires the F function and the
 * recombine from generic primitives:
 *
 * ```
 * split-bytes[4,4]  → L (output0), R (output1)
 * …F function…       (expand-R → xor-K → s-boxes → p-permute, on R)
 * xor               L ⊕ F
 * concat            the round output  ← argument order IS the Feistel swap
 * ```
 *
 * The old `feistel-round`-keyed visualizations went dark because they keyed off
 * the runtime's `branchPath` / synthetic `:rejoin` frame, neither of which a
 * port-native group produces. This module recovers the Feistel structure
 * **purely from the round group's real wiring** — no spec annotation, no
 * `feistel-round` kind. Critically, **the swap is read from the `recombine`
 * concat's argument order, never hardcoded**, so the derived picture stays
 * correct across encrypt / decrypt (which reverse the key order) and across
 * arbitrary user edits — the whole point of an experimentation tool.
 *
 * Cipher-agnostic: any port-mode group shaped as
 *   `split-bytes[a,b] → …F… → xor(L, F) → concat(R, L⊕F)`  (or the no-swap
 *   `concat(L⊕F, R)`) is recognized. DES is the only shipped consumer today; a
 * future TEA/XTEA/Twofish built the same way renders for free.
 *
 * The three derivations:
 *   - `analyzeFeistelRound(group)` — pure, spec-only. Returns the structural
 *     descriptor (or null) by following `bodyOutput → recombine(concat) →
 *     {split, fxor}` and classifying the wiring.
 *   - `findActiveFeistelRound(frame, spec)` — walk `frame.path` for the
 *     innermost group ancestor that `analyzeFeistelRound` accepts.
 *   - `resolveFeistelRoundBytes(shape, frames, blockIndex)` — read the round's
 *     L/R/F/L⊕F/new_L/new_R bytes from the child frames' captured port I/O
 *     (`portInputs`/`portOutputs`, populated since Slice 2.9a for every
 *     `kind:"ported"` + `legacy===undefined` leaf — all of split/xor/concat
 *     and the DES F-leaves qualify).
 */

import { findStepAndParent } from "./spec-mutations";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, TraceFrame } from "./types";

// The generic primitive type strings the Feistel shape is built from. Matched
// by value so the analyzer is decoupled from the DES-specific F-leaves (which
// vary — expand-R / s-boxes / p-permute / xor-K are all just "the F stack").
const SPLIT_TYPE = "split-bytes@1";
const XOR_TYPE = "xor@1";
const CONCAT_TYPE = "concat@1";

/**
 * Structural descriptor of a port-native Feistel round. Every field is derived
 * from the group's real child wiring (no hardcoded port names beyond the
 * generic primitive input-port vocabulary), so it survives user rewires.
 */
export type FeistelRoundShape = {
  /** The round group's id, e.g. "round.5". */
  readonly roundId: string;
  /** The `split-bytes@1` leaf that produces the two halves. */
  readonly splitId: string;
  /** The `xor@1` leaf that mixes L with F (output = L⊕F). */
  readonly fxorId: string;
  /** The `concat@1` leaf that recombines the halves (= `bodyOutput` target). */
  readonly recombineId: string;
  /** F-function leaves (step children minus split/fxor/recombine), spec order. */
  readonly fStackIds: readonly string[];
  /** Split output port read as L (by the fxor). DES: "output0". */
  readonly splitLPort: string;
  /** Split output port read as R (by the recombine). DES: "output1". */
  readonly splitRPort: string;
  /** Fxor output port (read by the recombine) — carries L⊕F. DES: "output". */
  readonly fxorOutPort: string;
  /** Fxor INPUT port carrying F (the operand that is NOT L). DES: "operand1". */
  readonly fxorFInPort: string;
  /** Recombine output port (= `group.bodyOutput.port`) — the round output. */
  readonly recombineOutPort: string;
  /**
   * Derived from the recombine's argument order, NOT hardcoded:
   *   - `true`  → textbook swap: `concat(R, L⊕F)` → new_L=R, new_R=L⊕F → the
   *     halves CROSS. Rounds 1..15 in DES.
   *   - `false` → no-swap exception: `concat(L⊕F, R)` → new_L=L⊕F, new_R=R →
   *     straight down. Round 16 in DES (what makes the cipher self-inverse).
   */
  readonly swap: boolean;
  /**
   * The `roundKeyAux` aux name (e.g. "roundKey.4") from the first F-stack leaf
   * that declares one — the round-key the F function consumes. Null when no
   * F-stack leaf reads a round key (degenerate/edited specs).
   */
  readonly roundKeyAux: string | null;
};

/** Step (leaf) children of a group, in spec order. */
const leafChildren = (group: StepGroup): readonly StepLeaf[] =>
  group.children.filter((c): c is StepLeaf => c.kind === "step");

/** Narrow a `Json` params value to a string-keyed record, or null. */
const asRecord = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

/** Read a numeric leaf param, or undefined. */
const paramNumber = (leaf: StepLeaf, key: string): number | undefined => {
  const v = asRecord(leaf.params)?.[key];
  return typeof v === "number" ? v : undefined;
};

/**
 * Analyze a `group` and return its Feistel structure, or null if the wiring
 * doesn't match the split→F→xor→concat shape. Pure (spec-only — no trace).
 *
 * Returns null (gracefully, no throw) for AES rounds (bodyOutput → an
 * add-round-key leaf, not a concat), SHA rounds, the outer DES `rounds` group
 * (bodyOutput → a child GROUP, absent from the leaf map), and any half-edited
 * round whose recombine/fxor/split links no longer line up.
 */
export const analyzeFeistelRound = (group: StepGroup): FeistelRoundShape | null => {
  if (group.kind !== "group") return null;
  const bodyOutput = group.bodyOutput;
  if (!bodyOutput) return null;

  const leaves = leafChildren(group);
  const byId = new Map(leaves.map((l) => [l.id, l] as const));
  const typeOf = (binding: PortBinding): string | undefined => byId.get(binding.node)?.type;

  // 1. recombine = the bodyOutput target leaf; must be a 2-input concat.
  const recombine = byId.get(bodyOutput.node);
  if (!recombine || recombine.type !== CONCAT_TYPE) return null;
  if (paramNumber(recombine, "inputCount") !== 2) return null;
  const rInput0 = recombine.portInputs?.input0;
  const rInput1 = recombine.portInputs?.input1;
  if (!rInput0 || !rInput1) return null;

  // 2. Classify the recombine's two inputs: one references a split child, the
  //    other an xor child. THE ARGUMENT ORDER IS THE SWAP — input0 pointing at
  //    the split (= R) means the textbook crossing; input0 pointing at the xor
  //    (= L⊕F) means the no-swap exception.
  let splitInput: PortBinding;
  let fxorInput: PortBinding;
  let swap: boolean;
  if (typeOf(rInput0) === SPLIT_TYPE && typeOf(rInput1) === XOR_TYPE) {
    splitInput = rInput0;
    fxorInput = rInput1;
    swap = true;
  } else if (typeOf(rInput1) === SPLIT_TYPE && typeOf(rInput0) === XOR_TYPE) {
    splitInput = rInput1;
    fxorInput = rInput0;
    swap = false;
  } else {
    return null;
  }
  const splitId = splitInput.node;
  const splitRPort = splitInput.port;
  const fxorId = fxorInput.node;
  const fxorOutPort = fxorInput.port;

  // 3. The split must be a 2-way split (two halves).
  const split = byId.get(splitId);
  if (!split || split.type !== SPLIT_TYPE) return null;
  const widths = asRecord(split.params)?.widths;
  if (!Array.isArray(widths) || widths.length !== 2) return null;

  // 4. The fxor must be a 2-input xor; one operand reads the SAME split (= L),
  //    the other carries F. The F input-port name is whichever operand is NOT L
  //    (derived, not assumed) — so a cipher wiring F on operand0 works too.
  const fxor = byId.get(fxorId);
  if (!fxor || fxor.type !== XOR_TYPE) return null;
  if (paramNumber(fxor, "inputCount") !== 2) return null;
  const fOperand0 = fxor.portInputs?.operand0;
  const fOperand1 = fxor.portInputs?.operand1;
  if (!fOperand0 || !fOperand1) return null;
  let lOperand: PortBinding;
  let fxorFInPort: string;
  if (fOperand0.node === splitId) {
    lOperand = fOperand0;
    fxorFInPort = "operand1";
  } else if (fOperand1.node === splitId) {
    lOperand = fOperand1;
    fxorFInPort = "operand0";
  } else {
    return null;
  }
  const splitLPort = lOperand.port;
  // L and R must read DIFFERENT split outputs (else it's not a two-half split).
  if (splitLPort === splitRPort) return null;

  // 5. F-stack = step children minus {split, fxor, recombine}, in spec order.
  const reserved = new Set([splitId, fxorId, recombine.id]);
  const fStack = leaves.filter((l) => !reserved.has(l.id));
  const roundKeyAux = fStack.reduce<string | null>((acc, l) => {
    if (acc !== null) return acc;
    const v = asRecord(l.params)?.roundKeyAux;
    return typeof v === "string" ? v : null;
  }, null);

  return {
    roundId: group.id,
    splitId,
    fxorId,
    recombineId: recombine.id,
    fStackIds: fStack.map((l) => l.id),
    splitLPort,
    splitRPort,
    fxorOutPort,
    fxorFInPort,
    recombineOutPort: bodyOutput.port,
    swap,
    roundKeyAux,
  };
};

/**
 * Resolve the Feistel round group containing the active frame. Walks the
 * frame's group-ancestor `path` innermost → outermost; the first ancestor that
 * resolves to a Feistel-shaped group wins. Robust to whether `frame.path`
 * includes the leaf id (a non-group id simply fails `analyzeFeistelRound`).
 *
 * `spec` is the active-mode spec (encrypt or decrypt) — `useSpec()` in the UI.
 */
export const findActiveFeistelRound = (
  frame: TraceFrame,
  spec: CipherSpec,
): { group: StepGroup; shape: FeistelRoundShape } | null => {
  const activeLeaf = canonicalStepId(frame.stepId);
  for (let i = frame.path.length - 1; i >= 0; i--) {
    const id = frame.path[i];
    if (id === undefined) continue;
    const located = findStepAndParent(spec, id);
    if (!located) continue;
    const node = located.node;
    if (node.kind !== "group") continue;
    const shape = analyzeFeistelRound(node);
    if (!shape) continue;
    // The active frame must actually be a leaf OF this round. This guards
    // against a transient spec/trace mismatch during a cipher switch: every
    // cipher names its rounds `round.N`, so the DES spec's Feistel-shaped
    // `round.9` would otherwise match an AES frame whose `path` also contains
    // `round.9` — rendering DES structure on a non-DES frame. Requiring the
    // frame's leaf to be one of this round's children rejects that.
    const members = new Set<string>([
      shape.splitId,
      shape.fxorId,
      shape.recombineId,
      ...shape.fStackIds,
    ]);
    if (!members.has(activeLeaf)) continue;
    return { group: node, shape };
  }
  return null;
};

/**
 * The round's byte values, read from the captured port I/O of its child
 * frames. Each role is null when its frame/port is absent (mid-edit specs, or
 * a leaf that didn't run) — callers render defensively.
 */
export type FeistelRoundBytes = {
  readonly L_in: Uint8Array | null;
  readonly R_in: Uint8Array | null;
  readonly F: Uint8Array | null;
  readonly LxorF: Uint8Array | null;
  readonly new_L: Uint8Array | null;
  readonly new_R: Uint8Array | null;
};

/**
 * Find the trace frame for a round leaf in the active block. Matches the
 * canonical (suffix-stripped) stepId and the `blockIndex` (undefined for
 * single-block ciphers like DES). Mirrors the old `findLeafFrameIndex` scan.
 */
const findRoundLeafFrame = (
  frames: readonly TraceFrame[],
  leafId: string,
  blockIndex: number | undefined,
): TraceFrame | null => {
  for (const f of frames) {
    if (canonicalStepId(f.stepId) !== leafId) continue;
    if (blockIndex === undefined ? f.blockIndex !== undefined : f.blockIndex !== blockIndex) {
      continue;
    }
    return f;
  }
  return null;
};

/**
 * Read the round's L/R/F/L⊕F/new_L/new_R bytes from the split / fxor /
 * recombine frames' port maps. F is read from the fxor frame's `portInputs`
 * (its non-L operand) rather than walking to the F-source leaf — one frame
 * fewer, and it keeps the value tied to exactly what the xor consumed.
 *
 * The round output is split into new_L / new_R at the L_in length (the half
 * boundary); the split POSITION is swap-independent (only the CONTENT of each
 * half differs between swap and no-swap), so the same pivot is correct for
 * both. Balanced-Feistel assumption (equal halves) — true for DES.
 */
export const resolveFeistelRoundBytes = (
  shape: FeistelRoundShape,
  frames: readonly TraceFrame[],
  blockIndex: number | undefined,
): FeistelRoundBytes => {
  const splitFrame = findRoundLeafFrame(frames, shape.splitId, blockIndex);
  const fxorFrame = findRoundLeafFrame(frames, shape.fxorId, blockIndex);
  const recombineFrame = findRoundLeafFrame(frames, shape.recombineId, blockIndex);

  const L_in = splitFrame?.portOutputs?.get(shape.splitLPort) ?? null;
  const R_in = splitFrame?.portOutputs?.get(shape.splitRPort) ?? null;
  const F = fxorFrame?.portInputs?.get(shape.fxorFInPort) ?? null;
  const LxorF = fxorFrame?.portOutputs?.get(shape.fxorOutPort) ?? null;

  const output = recombineFrame?.portOutputs?.get(shape.recombineOutPort) ?? null;
  let new_L: Uint8Array | null = null;
  let new_R: Uint8Array | null = null;
  if (output && L_in && output.length >= L_in.length) {
    new_L = output.slice(0, L_in.length);
    new_R = output.slice(L_in.length);
  }

  return { L_in, R_in, F, LxorF, new_L, new_R };
};
