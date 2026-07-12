/**
 * Port-native **Twofish** round-shape analysis — the 4-rail sibling of
 * `feistel-shape.ts`.
 *
 * **Why a separate module.** DES and Blowfish are 2-way Feistel: one split into
 * two halves, one F function, one xor, a 2-input concat. `analyzeFeistelRound`
 * captures exactly that shape. Twofish's round is a genuinely different,
 * *4-rail* structure that the 2-way analyzer cannot express, so it gets its own
 * `TwofishRoundShape` + `analyzeTwofishRound` rather than a strained
 * discriminated union — the DES/Blowfish path stays byte-identical (zero
 * regression). The round (see `twofish-spec-builder.ts::buildRound`):
 *
 * ```
 * split-bytes[4,4,4,4] → R0, R1, R2, R3
 * g(R0) = T0          (split→S0..S3→concat→MDS→perm)
 * g(ROL(R1,8)) = T1   (rolR1 → the same g stack)
 * PHT: F0 = T0+T1+K0 (add-mod-32, 3-in) ; F1 = T0 + 2·T1 + K1 (3-in)
 * R2 mix: R2 ⊕ F0 with a 1-bit rotation ; R3 mix: R3 with a 1-bit rotation ⊕ F1
 * concat(r2', r3', R0, R1)   ← the argument order IS the 4-way swap
 * ```
 *
 * **Recognition is wiring-derived, never leaf-id based** — encrypt and decrypt
 * differ only in the two rotation leaves (`r2x`/`r2r`, `r3r`/`r3x`) and their
 * order; the recombine wiring `concat(r2', r3', R0, R1)` is identical for both.
 * We anchor **backward from the PHT** (the two `add-mod-32@1` leaves with
 * `inputCount: 3` are unique to this shape) rather than forward from the split:
 * each split output has **fanout 2** (it feeds a g function AND a carried
 * recombine input), so a forward cone from the split would leak into the
 * recombine. Every leaf is classified by TYPE/STRUCTURE, not operand position,
 * so the encrypt and decrypt rounds recognize identically.
 *
 * The two derivations mirror `feistel-shape.ts`:
 *   - `analyzeTwofishRound(group)` — pure, spec-only. Returns the structural
 *     descriptor (or null) by anchoring on the recombine + PHT and coning out.
 *   - `findActiveTwofishRound(frame, spec)` — walk `frame.path` for the
 *     innermost group ancestor that `analyzeTwofishRound` accepts.
 */

import { findStepAndParent } from "./spec-mutations";
import { canonicalStepId } from "./step-id";
import type { CipherSpec, PortBinding, StepGroup, StepLeaf, TraceFrame } from "./types";

// The generic primitive type strings the Twofish shape is built from. Matched
// by value so recognition is decoupled from the Twofish-specific leaf ids.
const SPLIT_TYPE = "split-bytes@1";
const CONCAT_TYPE = "concat@1";
const ADD_TYPE = "add-mod-32@1";
const AUX_LOAD_TYPE = "aux-load-bytes@1";

/**
 * Structural descriptor of a port-native Twofish round. Every field is derived
 * from the group's real child wiring, so it survives user rewires and is the
 * same for encrypt and decrypt (which reverse the two 1-bit rotations).
 */
export type TwofishRoundShape = {
  /** The round group's id, e.g. "round.5". */
  readonly roundId: string;
  /** The 4-way `split-bytes@1` leaf producing R0..R3. */
  readonly splitId: string;
  /** The 4-input `concat@1` leaf that recombines with the swap (= `bodyOutput`). */
  readonly recombineId: string;
  /** Recombine output port (= `group.bodyOutput.port`) — the round output. */
  readonly recombineOutPort: string;
  /**
   * R0's g stack (`g0.split → … → g0.perm`), spec order. The dashed "g" box
   * wraps exactly these leaves.
   */
  readonly g0Ids: readonly string[];
  /**
   * ROL(R1,8)'s g stack (`g1.split → … → g1.perm`), spec order — the `rolR1`
   * rail is EXCLUDED (it's a rail atop the box, see `rolNodeId`).
   */
  readonly g1Ids: readonly string[];
  /**
   * The `ROL(R1,8)` rotate leaf feeding g1. It sits atop the g1 column but
   * OUTSIDE the g decoration box — a learner must not read the 8-bit rotation
   * as part of g (g0 has no such rotation). Mirrors how Blowfish's `xorP` key
   * mix rides the carried rail, outside the F box.
   */
  readonly rolNodeId: string;
  /** The pseudo-Hadamard transform leaves: loadK0, loadK1, f0, dbl2T1, f1. */
  readonly phtIds: readonly string[];
  /** The f0/f1 PHT-output add leaves (the two 3-input adds), [f0, f1]. */
  readonly fIds: readonly [string, string];
  /** The `2·T1` doubling leaf (the 2-input add feeding f1). */
  readonly dblId: string;
  /** The two subkey-load leaves feeding f0/f1, [loadK0, loadK1]. */
  readonly loadIds: readonly [string, string];
  /** R2's Feistel-mix rail cone (feeding `recombine.input0`), spec order. */
  readonly r2MixIds: readonly string[];
  /** R3's Feistel-mix rail cone (feeding `recombine.input1`), spec order. */
  readonly r3MixIds: readonly string[];
  /**
   * The recombine input ports that carry the two MIXED words (produced on the
   * R2/R3 rails), left→right. Twofish: `["input0", "input1"]`.
   */
  readonly mixedInputPorts: readonly [string, string];
  /**
   * The recombine input ports that carry the two RAW-carried words (the split's
   * R0/R1), left→right. Twofish: `["input2", "input3"]`.
   */
  readonly carriedInputPorts: readonly [string, string];
  /**
   * The split output ports the carried inputs read, aligned with
   * `carriedInputPorts`. Twofish: `["output0", "output1"]` (R0, R1). Used by the
   * swap wires to draw the carried pair back to the correct next-round slots.
   */
  readonly carriedSplitPorts: readonly [string, string];
};

// ─── Local helpers (re-declared from feistel-shape.ts so that module stays
// untouched — they are trivial pure narrowers). ──────────────────────────────

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

/** Step (leaf) children of a group, in spec order. */
const leafChildren = (group: StepGroup): readonly StepLeaf[] =>
  group.children.filter((c): c is StepLeaf => c.kind === "step");

/** True iff the binding reads a half of a 4-way `split-bytes@1` (widths len 4). */
const isRawFourWaySplitHalf = (
  binding: PortBinding | undefined,
  byId: Map<string, StepLeaf>,
): boolean => {
  if (!binding) return false;
  const node = byId.get(binding.node);
  if (!node || node.type !== SPLIT_TYPE) return false;
  const widths = asRecord(node.params)?.widths;
  return Array.isArray(widths) && widths.length === 4;
};

/**
 * Collect the backward reachability cone of `startId` — every leaf whose output
 * (transitively) feeds `startId` — stopping at (and NOT entering) any node in
 * `stop`. Records which ports of each stop node were reached, so callers can
 * tell which split half a g cone roots at. The cone includes `startId`. Bounded
 * by the round's leaf count; the `seen` guard rejects cycles.
 */
const backwardCone = (
  startId: string,
  byId: Map<string, StepLeaf>,
  stop: ReadonlySet<string>,
): { cone: string[]; reached: Map<string, Set<string>> } => {
  const cone: string[] = [];
  const seen = new Set<string>();
  const reached = new Map<string, Set<string>>();
  const visit = (id: string): void => {
    if (seen.has(id)) return;
    seen.add(id);
    const leaf = byId.get(id);
    if (!leaf) return;
    cone.push(id);
    for (const binding of Object.values(portInputsOf(leaf))) {
      if (stop.has(binding.node)) {
        const ports = reached.get(binding.node) ?? new Set<string>();
        ports.add(binding.port);
        reached.set(binding.node, ports);
      } else {
        visit(binding.node);
      }
    }
  };
  visit(startId);
  return { cone, reached };
};

/** Return leaves' ids in spec order, filtered to a membership set. */
const inSpecOrder = (leaves: readonly StepLeaf[], ids: ReadonlySet<string>): string[] =>
  leaves.filter((l) => ids.has(l.id)).map((l) => l.id);

/**
 * Analyze a `group` and return its Twofish round structure, or null if the
 * wiring doesn't match. Pure (spec-only — no trace). Returns null gracefully
 * (no throw) for DES/Blowfish 2-way rounds (2-input concat), AES/SHA rounds,
 * and any half-edited round whose PHT/recombine links no longer line up.
 */
export const analyzeTwofishRound = (group: StepGroup): TwofishRoundShape | null => {
  if (group.kind !== "group") return null;
  const bodyOutput = group.bodyOutput;
  if (!bodyOutput) return null;

  const leaves = leafChildren(group);
  const byId = new Map(leaves.map((l) => [l.id, l] as const));

  // 1. recombine = the bodyOutput target; must be a 4-input concat.
  const recombine = byId.get(bodyOutput.node);
  if (!recombine || recombine.type !== CONCAT_TYPE) return null;
  if (paramNumber(recombine, "inputCount") !== 4) return null;
  const rin = [0, 1, 2, 3].map((i) => recombine.portInputs?.[`input${i}`]);
  if (rin.some((b) => b === undefined)) return null;
  const [in0, in1, in2, in3] = rin as [PortBinding, PortBinding, PortBinding, PortBinding];

  // 2. input2/input3 must read RAW halves of the SAME 4-way split; input0/input1
  //    must NOT (they are the mixed rails). Try-and-verify discipline.
  if (!isRawFourWaySplitHalf(in2, byId) || !isRawFourWaySplitHalf(in3, byId)) return null;
  if (in2.node !== in3.node) return null;
  if (isRawFourWaySplitHalf(in0, byId) || isRawFourWaySplitHalf(in1, byId)) return null;
  const splitId = in2.node;

  // 3. The PHT anchor: exactly two 3-input add-mod-32 leaves = {f0, f1}.
  const add3 = leaves.filter((l) => l.type === ADD_TYPE && paramNumber(l, "inputCount") === 3);
  if (add3.length !== 2) return null;
  // f1 is the one whose operands include a 2-input add-mod-32 (the `2·T1`
  // double); f0 is the other. Classify by structure, not operand position.
  const isDbl = (b: PortBinding | undefined): boolean => {
    if (!b) return false;
    const n = byId.get(b.node);
    return !!n && n.type === ADD_TYPE && paramNumber(n, "inputCount") === 2;
  };
  const operandsOf = (l: StepLeaf): PortBinding[] => Object.values(portInputsOf(l));
  const f1Cands = add3.filter((l) => operandsOf(l).some(isDbl));
  if (f1Cands.length !== 1) return null;
  const f1 = f1Cands[0] as StepLeaf;
  const f0 = add3.find((l) => l.id !== f1.id) as StepLeaf | undefined;
  if (!f0) return null;

  // 4. From f0: the two non-aux-load operands are the g heads; the aux-load is
  //    loadK0. dbl2T1 = f1's 2-input-add operand; loadK1 = f1's aux-load.
  const isAuxLoad = (b: PortBinding): boolean => byId.get(b.node)?.type === AUX_LOAD_TYPE;
  const f0Ops = operandsOf(f0);
  const gHeadBindings = f0Ops.filter((b) => !isAuxLoad(b));
  const loadK0 = f0Ops.find(isAuxLoad);
  if (gHeadBindings.length !== 2 || !loadK0) return null;
  const f1Ops = operandsOf(f1);
  const dblBinding = f1Ops.find(isDbl);
  const loadK1 = f1Ops.find(isAuxLoad);
  if (!dblBinding || !loadK1) return null;

  // 5. Cone each g head down to the split; classify by which split half it
  //    roots at (g0 → output0 raw; g1 → output1 through the ROL rail).
  const stopSplit = new Set([splitId]);
  const cone0 = backwardCone(gHeadBindings[0]?.node as string, byId, stopSplit);
  const cone1 = backwardCone(gHeadBindings[1]?.node as string, byId, stopSplit);
  const rootsAt = (c: { reached: Map<string, Set<string>> }): Set<string> =>
    c.reached.get(splitId) ?? new Set<string>();
  const c0roots = rootsAt(cone0);
  const c1roots = rootsAt(cone1);
  // Exactly one cone roots at output0 (g0), the other at output1 (g1).
  const cone0IsG0 = c0roots.has("output0") && !c0roots.has("output1");
  const cone1IsG0 = c1roots.has("output0") && !c1roots.has("output1");
  let gConeForR0: string[];
  let gConeForR1: string[];
  if (cone0IsG0 && c1roots.has("output1") && !cone1IsG0) {
    gConeForR0 = cone0.cone;
    gConeForR1 = cone1.cone;
  } else if (cone1IsG0 && c0roots.has("output1") && !cone0IsG0) {
    gConeForR0 = cone1.cone;
    gConeForR1 = cone0.cone;
  } else {
    return null;
  }

  // g1's cone includes the ROL rail (the one member reading the split directly);
  // split it out so the g box wraps only the g stack.
  const rolNodeId = gConeForR1.find((id) => {
    const leaf = byId.get(id);
    if (!leaf) return false;
    return Object.values(portInputsOf(leaf)).some((b) => b.node === splitId);
  });
  if (!rolNodeId) return null;
  const g0Set = new Set(gConeForR0);
  const g1Set = new Set(gConeForR1.filter((id) => id !== rolNodeId));

  // 6. The R2/R3 mix rails: cones of recombine.input0/input1, bounded so they
  //    don't swallow the PHT or the split.
  const stopMix = new Set([splitId, f0.id, f1.id]);
  const r2MixSet = new Set(backwardCone(in0.node, byId, stopMix).cone);
  const r3MixSet = new Set(backwardCone(in1.node, byId, stopMix).cone);

  // 7. Assemble. PHT = the five leaves; ordered by spec position.
  const phtSet = new Set([f0.id, f1.id, dblBinding.node, loadK0.node, loadK1.node]);

  return {
    roundId: group.id,
    splitId,
    recombineId: recombine.id,
    recombineOutPort: bodyOutput.port,
    g0Ids: inSpecOrder(leaves, g0Set),
    g1Ids: inSpecOrder(leaves, g1Set),
    rolNodeId,
    phtIds: inSpecOrder(leaves, phtSet),
    fIds: [f0.id, f1.id],
    dblId: dblBinding.node,
    loadIds: [loadK0.node, loadK1.node],
    r2MixIds: inSpecOrder(leaves, r2MixSet),
    r3MixIds: inSpecOrder(leaves, r3MixSet),
    mixedInputPorts: ["input0", "input1"],
    carriedInputPorts: ["input2", "input3"],
    carriedSplitPorts: [in2.port, in3.port],
  };
};

/**
 * Resolve the Twofish round group containing the active frame. Walks the
 * frame's group-ancestor `path` innermost → outermost; the first ancestor that
 * resolves to a Twofish-shaped group whose members include the active leaf
 * wins. The membership guard rejects a transient spec/trace mismatch during a
 * cipher switch (every cipher names its rounds `round.N`), exactly as
 * `findActiveFeistelRound` does.
 */
export const findActiveTwofishRound = (
  frame: TraceFrame,
  spec: CipherSpec,
): { group: StepGroup; shape: TwofishRoundShape } | null => {
  const activeLeaf = canonicalStepId(frame.stepId);
  for (let i = frame.path.length - 1; i >= 0; i--) {
    const id = frame.path[i];
    if (id === undefined) continue;
    const located = findStepAndParent(spec, id);
    if (!located) continue;
    const node = located.node;
    if (node.kind !== "group") continue;
    const shape = analyzeTwofishRound(node);
    if (!shape) continue;
    const members = new Set<string>([
      shape.splitId,
      shape.recombineId,
      shape.rolNodeId,
      ...shape.g0Ids,
      ...shape.g1Ids,
      ...shape.phtIds,
      ...shape.r2MixIds,
      ...shape.r3MixIds,
    ]);
    if (!members.has(activeLeaf)) continue;
    return { group: node, shape };
  }
  return null;
};
