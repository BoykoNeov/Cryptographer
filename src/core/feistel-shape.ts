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
 * Cipher-agnostic AND orientation-agnostic: any port-mode group shaped as
 *   `split-bytes[a,b] → …F… → xor(half, F) → concat(…)` is recognized, in
 * either orientation (DES mixes F into the LEFT half → `mixedHalf: "L"`, the
 * combined value is `L⊕F`; Blowfish mirrors it, mixing F into the RIGHT half →
 * `mixedHalf: "R"`, combined value `R⊕F`). The carried half may be the raw split
 * output (DES) OR a **pass-through rail** of single-input nodes (Blowfish's
 * `L ⊕ P[i]` key mix); those rail nodes are surfaced in `railNodeIds` and kept
 * out of the F stack. `swap` stays byte-honest — derived from which split half
 * the recombine's `input0` (→ new_L) descends from — so it is correct across
 * encrypt / decrypt, both orientations, and arbitrary user rewires. DES and
 * Blowfish are the shipped consumers; a future TEA/XTEA built the same way
 * renders for free. (Twofish's 4-rail / PHT shape is NOT this 2-way form.)
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
  /** The `xor@1` leaf that mixes a split half with F (output = that half ⊕ F). */
  readonly fxorId: string;
  /** The `concat@1` leaf that recombines the halves (= `bodyOutput` target). */
  readonly recombineId: string;
  /**
   * F-function leaves (step children minus split/fxor/recombine AND the
   * pass-through `railNodeIds`), spec order. For DES this is
   * expand-R/xor-K/s-boxes/p-permute; for Blowfish it is the split→S-boxes→adds
   * that compute F (the key-mix `xorP` rail node is excluded — it's carried, not
   * F).
   */
  readonly fStackIds: readonly string[];
  /**
   * The F-stack leaves grouped into DEPENDENCY LAYERS: leaf ids at the same
   * topological depth within the F cone (a leaf's depth = 1 + the max depth of
   * any F-stack leaf it reads; leaves reading only split/rail/aux are depth 0).
   * Spec order is preserved within each layer. Consumed by the layout so that
   * PARALLEL F leaves (Blowfish's four independent S-box lookups) render
   * side-by-side in one row instead of a tall vertical stack, while a purely
   * SEQUENTIAL F chain (DES's expand→xor-K→s-boxes→p-permute) stays one-per-row
   * exactly as before. Always a partition of `fStackIds`.
   *
   * Optional only so hand-built test shapes can omit it; `analyzeFeistelRound`
   * always populates it, and the layout falls back to one-leaf-per-layer (the
   * pre-layering single-column behavior) when it is absent.
   */
  readonly fStackLayers?: readonly (readonly string[])[];
  /**
   * The pass-through rail: single-port-input nodes between a split half and the
   * recombine's carried input, in split→recombine order. **Empty for DES** (its
   * carried half is the raw split output); **`[xorP]` for Blowfish** (the
   * `L ⊕ P[i]` key mix sits on the carried rail before it both feeds F and
   * passes down to the recombine). Excluded from `fStackIds`.
   */
  readonly railNodeIds: readonly string[];
  /**
   * Which GEOMETRIC half the fxor mixes F into — i.e. which half becomes the
   * "combined" value:
   *   - `"L"` → F is mixed into the left half (output0). DES: `L⊕F`.
   *   - `"R"` → F is mixed into the right half (output1). Blowfish: `R⊕F`.
   * F is computed FROM the *other* (carried) half. This is the orientation flag
   * every consumer keys off so the picture isn't DES-specific.
   */
  readonly mixedHalf: "L" | "R";
  /** Which recombine `concat` input carries the fxor (combined) value. The
   *  other input carries the pass-through half. */
  readonly mixedRecombineInput: "input0" | "input1";
  /** Geometric left-half split output port (always the first half). DES/BF: "output0". */
  readonly splitLPort: string;
  /** Geometric right-half split output port (always the second half). DES/BF: "output1". */
  readonly splitRPort: string;
  /** Fxor output port (read by the recombine) — carries the combined half. */
  readonly fxorOutPort: string;
  /** Fxor INPUT port carrying F (the operand that is NOT the mixed split half). */
  readonly fxorFInPort: string;
  /** Recombine output port (= `group.bodyOutput.port`) — the round output. */
  readonly recombineOutPort: string;
  /**
   * Byte-honest swap flag: does the LEFT input half's content end up in the new
   * RIGHT half (and vice-versa)? Derived purely from the wiring — which split
   * half the recombine's `input0` (→ new_L) descends from:
   *   - `true`  → the halves CROSS (new_L carries the old R lineage). DES rounds
   *     1..15; every Blowfish round.
   *   - `false` → straight down (new_L carries the old L lineage). DES round 16
   *     (the no-swap exception that makes the cipher self-inverse).
   * Editing the recombine's argument order flips this live.
   */
  readonly swap: boolean;
  /**
   * The `roundKeyAux` aux name (e.g. "roundKey.4") from the first F-stack leaf
   * that declares one — the round-key the F function consumes. Null when no
   * F-stack leaf reads a round key (Blowfish's subkey rides the `xorP` rail
   * node, not an F-stack leaf, so its rounds report null here).
   */
  readonly roundKeyAux: string | null;
};

/**
 * Human-facing value labels for a round's two rails, derived from the
 * orientation so no consumer hardcodes DES's "L⊕F". The `mixed` label names the
 * combined half (`${mixedHalf}⊕F`); `carry` names the pass-through half's
 * lineage (its geometric half letter — the ⊕P / key-mix detail lives in the
 * rail node itself, mirroring how DES labels its raw carried half plainly "R").
 */
export const feistelValueLabels = (
  shape: FeistelRoundShape,
): { readonly mixed: string; readonly carry: string; readonly carryHalf: "L" | "R" } => {
  const carryHalf = shape.mixedHalf === "L" ? "R" : "L";
  return { mixed: `${shape.mixedHalf}⊕F`, carry: carryHalf, carryHalf };
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

/** The port-input bindings of a leaf, or an empty record. */
const portInputsOf = (leaf: StepLeaf): Record<string, PortBinding> => leaf.portInputs ?? {};

/** True iff the binding reads a 2-way `split-bytes@1` half directly. */
const isRawSplitHalf = (binding: PortBinding, byId: Map<string, StepLeaf>): boolean => {
  const node = byId.get(binding.node);
  if (!node || node.type !== SPLIT_TYPE) return false;
  const widths = asRecord(node.params)?.widths;
  return Array.isArray(widths) && widths.length === 2;
};

/**
 * Walk a pass-through rail backward from `binding` toward `splitId`, hopping
 * only through SINGLE-port-input nodes (an `xor-with-aux@1` key-mix has one port
 * input plus an aux read — still single-port, so it qualifies). Returns the
 * split output port the rail roots at plus the rail nodes in split→tail order,
 * or null if the chain doesn't terminate at `splitId` (a multi-input node, a
 * dead end, or a different split breaks it — that's not a Feistel carry rail).
 * DES's carried half hits the split on the first hop (`railNodeIds: []`);
 * Blowfish's carried half passes through `xorP` first (`railNodeIds: [xorP]`).
 */
const railToSplit = (
  binding: PortBinding,
  splitId: string,
  byId: Map<string, StepLeaf>,
): { port: string; railNodeIds: string[] } | null => {
  const rail: string[] = [];
  let current = binding;
  // Bounded by the round's leaf count; the visited guard rejects any cycle.
  const visited = new Set<string>();
  for (;;) {
    if (current.node === splitId) return { port: current.port, railNodeIds: rail };
    if (visited.has(current.node)) return null;
    visited.add(current.node);
    const node = byId.get(current.node);
    if (!node) return null;
    // The split itself is handled above; a rail node must have exactly one
    // port input to be an unambiguous pass-through.
    const inputs = portInputsOf(node);
    const keys = Object.keys(inputs);
    if (keys.length !== 1) return null;
    const next = inputs[keys[0] as string];
    if (!next) return null;
    rail.unshift(current.node); // split→tail order
    current = next;
  }
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

  // 1. recombine = the bodyOutput target leaf; must be a 2-input concat.
  const recombine = byId.get(bodyOutput.node);
  if (!recombine || recombine.type !== CONCAT_TYPE) return null;
  if (paramNumber(recombine, "inputCount") !== 2) return null;
  const rInput0 = recombine.portInputs?.input0;
  const rInput1 = recombine.portInputs?.input1;
  if (!rInput0 || !rInput1) return null;

  // 2. Try each recombine input as the FXOR (the `xor@1` that mixes one split
  //    half with F); the OTHER is the pass-through carried half. The fxor reads
  //    a RAW split half on one operand directly — true for BOTH DES (fxor mixes
  //    L, F rides the other operand) and Blowfish (fxor `xorR` mixes R, F rides
  //    the other operand); only the CARRIED input differs: raw split for DES,
  //    the `xorP` rail for Blowfish. So we generalize the carried side to a rail
  //    walk while the fxor test is unchanged.
  for (const [fxorBind, passBind] of [
    [rInput0, rInput1],
    [rInput1, rInput0],
  ] as const) {
    const fxor = byId.get(fxorBind.node);
    if (!fxor || fxor.type !== XOR_TYPE) continue;
    if (paramNumber(fxor, "inputCount") !== 2) continue;
    const op0 = fxor.portInputs?.operand0;
    const op1 = fxor.portInputs?.operand1;
    if (!op0 || !op1) continue;

    // One fxor operand must read a raw 2-way split half; the other carries F.
    let mixedOperand: PortBinding;
    let fxorFInPort: string;
    if (isRawSplitHalf(op0, byId)) {
      mixedOperand = op0;
      fxorFInPort = "operand1";
    } else if (isRawSplitHalf(op1, byId)) {
      mixedOperand = op1;
      fxorFInPort = "operand0";
    } else {
      continue;
    }
    const splitId = mixedOperand.node;
    const mixedPort = mixedOperand.port; // "output0" (L) or "output1" (R)

    // The carried recombine input must trace back (through 0+ single-input rail
    // nodes) to the SAME split, on the OTHER half.
    const rail = railToSplit(passBind, splitId, byId);
    if (!rail || rail.port === mixedPort) continue;
    const carryPort = rail.port;

    // 3. Orientation + byte-honest swap, both derived from the wiring.
    //    mixedHalf = which geometric half the fxor combined (output0→L, else R).
    const mixedHalf: "L" | "R" = mixedPort === "output0" ? "L" : "R";
    const mixedRecombineInput: "input0" | "input1" = fxorBind === rInput0 ? "input0" : "input1";
    //    swap := does new_L (= recombine.input0's value) carry the R lineage?
    //    input0 is either the fxor (→ its mixedPort) or the carried rail (→ its
    //    carryPort); the halves cross iff that port is the RIGHT half (output1).
    const input0Port = rInput0.node === fxor.id ? mixedPort : carryPort;
    const swap = input0Port === "output1";

    // 4. F-stack = leaves minus {split, fxor, recombine, rail nodes}, spec order.
    const reserved = new Set([splitId, fxor.id, recombine.id, ...rail.railNodeIds]);
    const fStack = leaves.filter((l) => !reserved.has(l.id));
    const roundKeyAux = fStack.reduce<string | null>((acc, l) => {
      if (acc !== null) return acc;
      const v = asRecord(l.params)?.roundKeyAux;
      return typeof v === "string" ? v : null;
    }, null);

    // 4b. Layer the F stack by dependency depth so the layout can render
    //     parallel leaves (Blowfish's 4 S-boxes) in one row. A leaf's depth is
    //     1 + the deepest F-stack leaf it reads; leaves that read only the
    //     split / rail / aux are depth 0. Spec order is preserved within a layer.
    const fSet = new Set(fStack.map((l) => l.id));
    const depthMemo = new Map<string, number>();
    const fDepth = (id: string): number => {
      const cached = depthMemo.get(id);
      if (cached !== undefined) return cached;
      depthMemo.set(id, 0); // cycle guard (round wiring is a DAG; be safe anyway)
      const leaf = byId.get(id);
      let d = 0;
      if (leaf) {
        for (const b of Object.values(portInputsOf(leaf))) {
          if (fSet.has(b.node)) d = Math.max(d, fDepth(b.node) + 1);
        }
      }
      depthMemo.set(id, d);
      return d;
    };
    const byDepth = new Map<number, string[]>();
    let maxDepth = 0;
    for (const l of fStack) {
      const d = fDepth(l.id);
      maxDepth = Math.max(maxDepth, d);
      const bucket = byDepth.get(d) ?? [];
      bucket.push(l.id);
      byDepth.set(d, bucket);
    }
    const fStackLayers: string[][] = [];
    for (let d = 0; d <= maxDepth; d++) {
      const bucket = byDepth.get(d);
      if (bucket && bucket.length > 0) fStackLayers.push(bucket);
    }

    return {
      roundId: group.id,
      splitId,
      fxorId: fxor.id,
      recombineId: recombine.id,
      fStackIds: fStack.map((l) => l.id),
      fStackLayers,
      railNodeIds: rail.railNodeIds,
      mixedHalf,
      mixedRecombineInput,
      // Geometric half ports (first half = L = output0, second = R = output1).
      splitLPort: "output0",
      splitRPort: "output1",
      fxorOutPort: fxorBind.port,
      fxorFInPort,
      recombineOutPort: bodyOutput.port,
      swap,
      roundKeyAux,
    };
  }
  return null;
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
      ...shape.railNodeIds,
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
