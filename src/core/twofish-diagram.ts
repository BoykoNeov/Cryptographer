/**
 * Pure presentation model for the **Twofish linear-view abstract diagram** —
 * the 4-rail sibling of `feistelValueLabels` in `feistel-shape.ts`.
 *
 * **Why this module exists (and why it is separate from `twofish-shape.ts`).**
 * `analyzeTwofishRound` answers "what IS this round?" — the structural facts the
 * graph's canonical 4-rail layout needs (which leaves form g0, which form the
 * PHT, which recombine input carries a raw half). The linear diagram needs a
 * second, smaller set of facts on top of those: *which input word* each rail
 * carries, *which rotation* each mix node applies, and — the payload — *where
 * each of the four words lands after the swap*. Deriving those here keeps
 * `twofish-shape.ts` (which the shipped graph layout depends on) byte-identical,
 * and keeps the component presentational.
 *
 * **The swap is the point — and the linear view is the only place it fits.**
 * A Twofish round ends with `concat(R2′, R3′, R0, R1)`: the two *mixed* words
 * move to the front and the two *carried* words move to the back. That 4-way
 * rotation is the exact analogue of the 2-way Feistel crossing, and it is the
 * one thing the per-step chain hides. The graph view deliberately does NOT draw
 * it (`docs/plans/polished-imagining-bird.md`): Twofish rounds lay out
 * horizontally as top-level steps, so a `recombine → next split` swap spans
 * ~2000px and reads as a tangle, not an X. A single compact round diagram has no
 * such problem — the four wires are ~50px long — so the linear view is where the
 * swap picture gets told honestly.
 *
 * Everything below is derived from the round group's real wiring, so it stays
 * correct for encrypt AND decrypt (which differ only in the two 1-bit rotations
 * and their order on the rails), and it follows a user rewire.
 */

import type { TwofishRoundShape } from "./twofish-shape";
import type { PortBinding, StepGroup, StepLeaf } from "./types";

// Primitive type strings the mix rails are built from. Matched by value so the
// model is decoupled from the Twofish-specific leaf ids.
const XOR_TYPE = "xor@1";
const ROTATE_TYPE = "rotate-bits-right@1";

/** One node on a mix rail — an `⊕ F` combine or a 1-bit rotation. */
export type TwofishRailNode = {
  /** The leaf id, so the diagram can accent it and click-to-scrub to its frame. */
  readonly id: string;
  readonly kind: "xor" | "rotate";
  /** Display label, e.g. "⊕ F0" or "ROL 1". */
  readonly label: string;
};

/** A Feistel-mix rail: the input word it mixes, and its nodes in spec order. */
export type TwofishMixRail = {
  /** Which input word this rail carries — the split output index (2 or 3). */
  readonly railIndex: number;
  /**
   * Which PHT output this rail's `⊕` consumes — 0 for F0, 1 for F1, null if the
   * rail was rewired to read neither. Derived (not assumed from rail order) so
   * the F wires land on the rail that genuinely mixes them.
   */
  readonly fIndex: 0 | 1 | null;
  /** The rail's leaves top→bottom (spec order): `⊕ F` and the 1-bit rotation. */
  readonly nodes: readonly TwofishRailNode[];
};

export type TwofishDiagramModel = {
  readonly roundId: string;
  readonly splitId: string;
  readonly recombineId: string;
  readonly rolNodeId: string;
  /** The `ROL(R1,8)` rail's label, derived from its rotate params. */
  readonly rolLabel: string;
  readonly g0Ids: readonly string[];
  readonly g1Ids: readonly string[];
  readonly phtIds: readonly string[];
  /** The two PHT output adds, [f0, f1] — for the F0/F1 stub labels. */
  readonly fIds: readonly [string, string];
  /** The two mix rails, aligned with the recombine's `mixedInputPorts`. */
  readonly mixRails: readonly [TwofishMixRail, TwofishMixRail];
  /**
   * For each of the four output slots (concat argument order), the INPUT rail
   * index its value descends from. Twofish: `[2, 3, 0, 1]` — the swap. Drawn as
   * four wires; slot i's wire starts at rail `swapSources[i]`.
   */
  readonly swapSources: readonly [number, number, number, number];
  /** Output slot labels, e.g. `["R2′", "R3′", "R0", "R1"]`. */
  readonly outputLabels: readonly [string, string, string, string];
};

// ─── Local narrowers (mirrors of twofish-shape.ts's — trivial + pure) ────────

const asRecord = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;

const paramNumber = (leaf: StepLeaf, key: string): number | undefined => {
  const v = asRecord(leaf.params)?.[key];
  return typeof v === "number" ? v : undefined;
};

const portInputsOf = (leaf: StepLeaf): Record<string, PortBinding> => leaf.portInputs ?? {};

/**
 * Parse a `split-bytes@1` output port name to its word index — `"output2"` → 2.
 * Returns null for anything else, so a rewired round degrades to "no diagram"
 * rather than mislabelling a rail.
 */
const railOfSplitPort = (port: string): number | null => {
  const m = /^output(\d+)$/.exec(port);
  if (!m || m[1] === undefined) return null;
  const n = Number.parseInt(m[1], 10);
  return Number.isInteger(n) ? n : null;
};

/**
 * Render a `rotate-bits-right@1` leaf's params as the rotation a reader expects.
 * The builder expresses every LEFT rotation as its right-rotation complement
 * (ROL 8 = ROR 24 on a 32-bit word), so showing the raw `bits` param would make
 * the diagram say "ROR 24" where the Twofish paper says "ROL 8". We name
 * whichever direction is the shorter turn, which recovers the paper's wording.
 */
const rotateLabel = (leaf: StepLeaf): string => {
  const bits = paramNumber(leaf, "bits");
  const wordBits = paramNumber(leaf, "wordBits") ?? 32;
  if (bits === undefined) return "rotate";
  const left = wordBits - bits;
  return left < bits ? `ROL ${left}` : `ROR ${bits}`;
};

/**
 * Build one mix rail's model: the word it mixes (found by walking to the leaf
 * that reads the split directly) and its nodes in spec order.
 *
 * `fIds` names which PHT output each `⊕` consumes, so the label reads "⊕ F0"
 * rather than a bare "⊕" — on a 4-rail picture, *which* F lands on *which* rail
 * is exactly the detail a learner needs.
 */
const buildMixRail = (
  coneIds: readonly string[],
  byId: ReadonlyMap<string, StepLeaf>,
  splitId: string,
  fIds: readonly [string, string],
): TwofishMixRail | null => {
  let railIndex: number | null = null;
  let fIndex: 0 | 1 | null = null;
  const nodes: TwofishRailNode[] = [];

  for (const id of coneIds) {
    const leaf = byId.get(id);
    if (!leaf) continue;
    const bindings = Object.values(portInputsOf(leaf));

    // The rail's root: the one leaf reading a raw half of the round's split.
    for (const b of bindings) {
      if (b.node !== splitId) continue;
      const rail = railOfSplitPort(b.port);
      if (rail !== null) railIndex = rail;
    }

    if (leaf.type === XOR_TYPE) {
      // Name the F this xor consumes by matching its operands against the PHT
      // outputs — position-independent, so operand order can't mislabel it.
      const readsF0 = bindings.some((b) => b.node === fIds[0]);
      const readsF1 = bindings.some((b) => b.node === fIds[1]);
      if (readsF0) fIndex = 0;
      else if (readsF1) fIndex = 1;
      const fLabel = readsF0 ? "F0" : readsF1 ? "F1" : null;
      nodes.push({ id, kind: "xor", label: fLabel ? `⊕ ${fLabel}` : "⊕" });
    } else if (leaf.type === ROTATE_TYPE) {
      nodes.push({ id, kind: "rotate", label: rotateLabel(leaf) });
    }
  }

  if (railIndex === null || nodes.length === 0) return null;
  return { railIndex, fIndex, nodes };
};

/**
 * Derive the linear diagram's model from a recognized Twofish round, or null if
 * the round's wiring no longer supports an honest picture (a hand-rewired mix
 * rail that reads no split half, say). Null means the diagram simply doesn't
 * render — the generic per-step views still do.
 */
export const twofishDiagramModel = (
  shape: TwofishRoundShape,
  group: StepGroup,
): TwofishDiagramModel | null => {
  const leaves = group.children.filter((c): c is StepLeaf => c.kind === "step");
  const byId = new Map(leaves.map((l) => [l.id, l] as const));

  const rol = byId.get(shape.rolNodeId);
  if (!rol) return null;

  const rail2 = buildMixRail(shape.r2MixIds, byId, shape.splitId, shape.fIds);
  const rail3 = buildMixRail(shape.r3MixIds, byId, shape.splitId, shape.fIds);
  if (!rail2 || !rail3) return null;

  // The carried words: the split halves the recombine reads raw.
  const carried = shape.carriedSplitPorts.map(railOfSplitPort);
  const [c0, c1] = carried;
  if (c0 === null || c0 === undefined || c1 === null || c1 === undefined) return null;

  // The swap, read straight off the concat argument order: the two mixed rails
  // land in slots 0/1, the two carried words in slots 2/3.
  const swapSources: [number, number, number, number] = [rail2.railIndex, rail3.railIndex, c0, c1];
  const outputLabels: [string, string, string, string] = [
    `R${rail2.railIndex}′`,
    `R${rail3.railIndex}′`,
    `R${c0}`,
    `R${c1}`,
  ];

  return {
    roundId: shape.roundId,
    splitId: shape.splitId,
    recombineId: shape.recombineId,
    rolNodeId: shape.rolNodeId,
    rolLabel: rotateLabel(rol),
    g0Ids: shape.g0Ids,
    g1Ids: shape.g1Ids,
    phtIds: shape.phtIds,
    fIds: shape.fIds,
    mixRails: [rail2, rail3],
    swapSources,
    outputLabels,
  };
};
