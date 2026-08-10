/**
 * Port-native **NTT butterfly** shape analysis — the fourth member of the
 * canonical-layout family, after `feistel-shape.ts` (2-way), `twofish-shape.ts`
 * (4-rail) and `arx-round-shape.ts` (ChaCha20 / Salsa20 double rounds).
 *
 * **The container is an `iterate`, not a `group` — and that is the one genuinely
 * new thing here.** All three predecessors recognize a `StepGroup`, and
 * `layoutNode`'s three canonical branches each gate on
 * `container.kind === "group"`. An NTT layer is a port-mode `iterate` whose body
 * runs once per butterfly group (1 group in layer 1, 64 in layer 7), so this
 * analyzer takes an `IterateGroup` and the layout branch gates on
 * `kind === "iterate"`. That is safe because an expanded iterate renders its
 * body leaves: `expandCollapsedIterates` swaps a body for per-block chips only
 * when the iterate is COLLAPSED, so a cell and a chip row are mutually
 * exclusive by construction.
 *
 * **What the generic layout does today, measured rather than guessed.** Each of
 * the seven layers is eight leaves in a horizontal ribbon ~1,650 px wide, and
 * the seven ribbons sit end to end: the whole forward-NTT canvas measures
 * 12,752 × 546. Nothing about the butterfly is visible in that — the two rails,
 * the twiddle multiply feeding both of them, and the sum/difference pair are
 * strung out in one line with the wires running the full width.
 *
 * ## The two butterflies are different shapes, not a sign flip
 *
 * ```
 * forward  (Cooley–Tukey, FIPS 203 Alg. 9)     inverse (Gentleman–Sande, Alg. 10)
 *   t   = ζ · hi                                 lo′ = lo + hi
 *   lo′ = lo + t                                 hi′ = ζ · (hi − lo)
 *   hi′ = lo − t
 * ```
 *
 * The forward multiplies BEFORE combining, the inverse AFTER. So the walk
 * derives a `kind` discriminator — does the multiply consume the subtraction's
 * output, or does the subtraction consume the multiply's? — and every id role,
 * every label and the layout's whole slot table is keyed on that, never on
 * position and never on a leaf id.
 *
 * That rule is not stylistic caution. `ntt-3329-256.ts`'s own header records the
 * bug it exists to prevent: the inverse spec runs its layers in the opposite
 * order, and a first draft that derived the layer number from the pairing
 * distance printed the wrong layer on every inverse frame.
 *
 * ## Recognition is wiring-derived, with a partition gate
 *
 * No spec tag, no id matching, no cipher name. The eight leaves are found by
 * their primitive types and their bindings — the split that reads the iterate's
 * own `in` port, the split that reads its `chain` port, the `aux-load-bytes@1`
 * all three arithmetic leaves take their modulus from — and the walk must tile
 * the body's children EXACTLY once. A user who rewires one operand drops the
 * whole layer to the generic vertical/horizontal stack rather than getting a
 * cell with a silently orphaned leaf. That is the ARX partition gate, and it is
 * the reason a half-edited body degrades honestly.
 *
 * Recognition is deliberately strict about the body being all leaves and
 * numbering exactly eight: this shape has no optional members, so anything else
 * is not (or is no longer) a canonical butterfly.
 */

import {
  type ArxOpBase,
  asRecord,
  paramNumber,
  portInputsOf,
  sameBinding,
} from "./arx-round-shape";
import type { CipherSpec, IterateGroup, PortBinding, StepLeaf, StepNode } from "./types";

// Primitive type strings the shape is built from. Matched by value so
// recognition is decoupled from the NTT's leaf ids.
const SPLIT_TYPE = "split-bytes@1";
const CONCAT_TYPE = "concat@1";
const AUX_LOAD_TYPE = "aux-load-bytes@1";
const ADD_TYPE = "zq-vec-add@1";
const SUB_TYPE = "zq-vec-sub@1";
const MUL_TYPE = "zq-vec-mul-scalar@1";

/** The body's own ports, as the runtime seeds them into an iterate's scope. */
const IN_PORT = "in";
const CHAIN_PORT = "chain";

/**
 * `split-bytes@1` names its outputs `output0`, `output1`, … in widths order, so
 * the FIRST is the low half of the coefficients. Reading that is reading the
 * primitive's own contract, the way this module already reads `"a"`, `"b"`,
 * `"modulus"` and `"input0"` — it is not a dependence on the NTT's node ids.
 *
 * It is the anchor that tells "low" from "high" without asking the addition,
 * which is what lets the addition be checked as an unordered pair.
 */
const SPLIT_LOW_PORT = "output0";
const SPLIT_HIGH_PORT = "output1";
/** Every `zq-vec-*@1` publishes its single result on `output`. */
const MUL_OUT_PORT = "output";

/** Leaves in one butterfly body. No optional members — see the header. */
export const NTT_BUTTERFLY_LEAVES = 8;

/**
 * Which butterfly this layer runs, derived from whether the twiddle multiply
 * feeds the add/sub pair or consumes the subtraction's output.
 *
 * Named after the algorithms rather than after "forward"/"inverse" because the
 * shape is a property of the wiring: an inverse spec whose butterfly were
 * rewired into Cooley–Tukey form would (correctly) report `cooley-tukey`.
 */
export type NttButterflyKind = "cooley-tukey" | "gentleman-sande";

/** One classified leaf of the butterfly, for the layout's slot table. */
export type NttButterflyOp = ArxOpBase & {
  /**
   * The leaf's role, derived from wiring. `twist` is the twiddle multiply
   * wherever it sits; `lo`/`hi` are the leaves producing the two output halves,
   * whichever primitive that turns out to be (for Gentleman–Sande `hi` IS the
   * multiply, and `diff` is the subtraction that feeds it).
   */
  readonly role: NttButterflyRole;
};

export type NttButterflyRole =
  | "split"
  | "zeta"
  | "modulus"
  | "twist"
  | "diff"
  | "lo"
  | "hi"
  | "recombine"
  | "advance";

/**
 * Structural descriptor of one NTT layer's butterfly body. Every field is
 * derived from real child wiring, so it survives a rewire and distinguishes the
 * two directions without consulting the spec's name or the layer's id.
 */
export type NttButterflyShape = {
  /** The layer iterate's id, e.g. `layer3` or `keygen.ntt-s0.layer3`. */
  readonly layerId: string;
  /** Which butterfly — the discriminator every label and slot is keyed on. */
  readonly kind: NttButterflyKind;
  /** `split-bytes@1` cutting the group into a low and a high half (reads `in`). */
  readonly splitId: string;
  /** `split-bytes@1` taking this group's ζ off the rotating table (reads `chain`). */
  readonly zetaId: string;
  /** `aux-load-bytes@1` publishing `q` into the body scope. */
  readonly modulusId: string;
  /** `zq-vec-mul-scalar@1` — the twiddle multiply, whichever side of the pair. */
  readonly twistId: string;
  /** `zq-vec-add@1` — always the low output half, in both butterflies. */
  readonly addId: string;
  /** `zq-vec-sub@1` — the high half (Cooley–Tukey) or the twist's operand (G–S). */
  readonly subId: string;
  /** The leaf producing the HIGH output half: `subId` (C–T) or `twistId` (G–S). */
  readonly hiProducerId: string;
  /** `concat@1` rejoining the halves — the iterate's `bodyOutput`. */
  readonly recombineId: string;
  /** `concat@1` rotating the consumed ζ to the other end of the table. */
  readonly advanceId: string;
  /** All eight member leaves, in spec order. */
  readonly memberIds: readonly string[];
  /** Each member with its derived role, for the layout and the diagram. */
  readonly ops: readonly NttButterflyOp[];
};

// ─── Local narrowing helpers ────────────────────────────────────────────────

/** Step (leaf) children of an iterate, in spec order. */
const leafChildrenOf = (nodes: readonly StepNode[]): readonly StepLeaf[] =>
  nodes.filter((c): c is StepLeaf => c.kind === "step");

/** A named port input of a leaf, or undefined. */
const inputAt = (leaf: StepLeaf, name: string): PortBinding | undefined => portInputsOf(leaf)[name];

/** True iff `binding` names any output of `nodeId`. */
const comesFrom = (binding: PortBinding | undefined, nodeId: string): boolean =>
  binding !== undefined && binding.node === nodeId;

/** True iff `binding` is exactly `want` (node and port both). */
const bindingEquals = (binding: PortBinding | undefined, want: PortBinding): boolean =>
  binding !== undefined && sameBinding(binding, want);

/**
 * True iff a two-operand leaf reads exactly `x` and `y`, in EITHER order.
 *
 * Used for the additions only. `zq-vec-add@1` is commutative, so swapping its
 * two operands is a legal no-op edit and must not make the layer stop being a
 * butterfly; the subtractions are checked positionally, because reversing them
 * is not a no-op.
 */
const readsUnorderedPair = (leaf: StepLeaf, x: PortBinding, y: PortBinding): boolean => {
  const a = inputAt(leaf, "a");
  const b = inputAt(leaf, "b");
  if (a === undefined || b === undefined) return false;
  return (sameBinding(a, x) && sameBinding(b, y)) || (sameBinding(a, y) && sameBinding(b, x));
};

/** True iff the leaf is a `split-bytes@1` cutting its input into two pieces. */
const isTwoWaySplit = (leaf: StepLeaf): boolean => {
  if (leaf.type !== SPLIT_TYPE) return false;
  const widths = asRecord(leaf.params)?.widths;
  return Array.isArray(widths) && widths.length === 2;
};

/** True iff the leaf is a two-input `concat@1`. */
const isTwoWayConcat = (leaf: StepLeaf): boolean =>
  leaf.type === CONCAT_TYPE && paramNumber(leaf, "inputCount") === 2;

/** The sole leaf of `type` among `leaves`, or undefined when not exactly one. */
const sole = (leaves: readonly StepLeaf[], type: string): StepLeaf | undefined => {
  const hits = leaves.filter((l) => l.type === type);
  return hits.length === 1 ? hits[0] : undefined;
};

// ─── The analyzer ───────────────────────────────────────────────────────────

/**
 * Analyze a layer `iterate` and return its butterfly structure, or null if the
 * wiring doesn't match. Pure (spec-only — no trace, no DOM), which is what lets
 * the tests drive this exact function rather than a paraphrase of it.
 *
 * Returns null gracefully for every other cipher's iterate (ECB's block loop,
 * SHA-256's compression fold, the PRNG generators) and for a half-edited
 * butterfly, so the caller falls back to the generic layout.
 */
export const analyzeNttButterfly = (node: IterateGroup): NttButterflyShape | null => {
  if (node.kind !== "iterate") return null;
  // Port mode only: an aux-mode iterate seeds no `in`/`chain` for the splits to
  // read, so the bindings below could not exist.
  if (node.seedInput === undefined) return null;
  const bodyOutput = node.bodyOutput;
  if (bodyOutput === undefined) return null;

  // The body is exactly eight leaves — no groups, no nested iterates, no
  // optional members. Anything else is not this shape.
  const leaves = leafChildrenOf(node.children);
  if (leaves.length !== node.children.length) return null;
  if (leaves.length !== NTT_BUTTERFLY_LEAVES) return null;
  const byId = new Map(leaves.map((l) => [l.id, l] as const));

  // 1. The three arithmetic leaves, one of each. Their presence alone rules out
  //    every non-lattice iterate in the app.
  const add = sole(leaves, ADD_TYPE);
  const sub = sole(leaves, SUB_TYPE);
  const mul = sole(leaves, MUL_TYPE);
  if (!add || !sub || !mul) return null;

  // 2. The modulus: one `aux-load-bytes@1`, and all three arithmetic leaves
  //    must take their `modulus` port from it. (`q` reaches the body through
  //    aux because port flow cannot cross an iterate's scope — see
  //    `ntt-3329-256.ts`'s header.)
  const modulus = sole(leaves, AUX_LOAD_TYPE);
  if (!modulus) return null;
  for (const leaf of [add, sub, mul]) {
    if (!comesFrom(inputAt(leaf, "modulus"), modulus.id)) return null;
  }

  // 3. The two splits, told apart by which of the body's own ports they read:
  //    the coefficients arrive on `in`, the rotating ζ table on `chain`.
  const splits = leaves.filter(isTwoWaySplit);
  if (splits.length !== 2) return null;
  const readsBodyPort = (leaf: StepLeaf, portName: string): boolean => {
    const binding = inputAt(leaf, "input");
    return binding !== undefined && binding.node === node.id && binding.port === portName;
  };
  const split = splits.find((l) => readsBodyPort(l, IN_PORT));
  const zeta = splits.find((l) => readsBodyPort(l, CHAIN_PORT));
  if (!split || !zeta || split.id === zeta.id) return null;

  // 4. The twiddle factor is the multiply's scalar, and it comes off the ζ
  //    split. (WHICH of the two ζ outputs differs by direction — the forward
  //    consumes from the front of the table, the inverse from the back — so
  //    this deliberately checks the node, not the port.)
  if (!comesFrom(inputAt(mul, "scalar"), zeta.id)) return null;

  // 5. THE DISCRIMINATOR. Cooley–Tukey forms `t = ζ·hi` first and both the sum
  //    and the difference read it; Gentleman–Sande forms `hi − lo` first and
  //    the multiply reads THAT. Exactly one can hold, and everything below is
  //    keyed on the answer rather than on any leaf's id or position.
  const subConsumesMul =
    comesFrom(inputAt(sub, "a"), mul.id) || comesFrom(inputAt(sub, "b"), mul.id);
  const mulConsumesSub = comesFrom(inputAt(mul, "a"), sub.id);
  if (subConsumesMul === mulConsumesSub) return null; // neither, or a cycle
  const kind: NttButterflyKind = subConsumesMul ? "cooley-tukey" : "gentleman-sande";

  const loHalf: PortBinding = { node: split.id, port: SPLIT_LOW_PORT };
  const hiHalf: PortBinding = { node: split.id, port: SPLIT_HIGH_PORT };

  if (kind === "cooley-tukey") {
    // t = ζ·hi ; lo′ = lo + t ; hi′ = lo − t.
    if (!bindingEquals(inputAt(mul, "a"), hiHalf)) return null;
    // The SUBTRACTION is checked positionally, because it has to be: `lo − t`
    // reversed is `t − lo`, which negates every high coefficient.
    if (!bindingEquals(inputAt(sub, "a"), loHalf)) return null;
    if (!comesFrom(inputAt(sub, "b"), mul.id)) return null;
    // The ADDITION is checked as an unordered pair, because it has to be:
    // addition commutes, so swapping its operands is a legal no-op edit and
    // must not drop the layer to the generic layout. (The Salsa20 walk records
    // the same reasoning; `partitionOperands` there does the same job.)
    if (!readsUnorderedPair(add, loHalf, { node: mul.id, port: MUL_OUT_PORT })) return null;
    // Both combining steps must read the SAME original low half — the wire that
    // makes `hi′ = lo + 2t` inexpressible (see the `hi` step's narration).
  } else {
    // lo′ = lo + hi ; hi′ = ζ·(hi − lo).
    if (!comesFrom(inputAt(mul, "a"), sub.id)) return null;
    // Strict, and for the same reason: `hi − lo`, not `lo − hi`.
    if (!bindingEquals(inputAt(sub, "a"), hiHalf)) return null;
    if (!bindingEquals(inputAt(sub, "b"), loHalf)) return null;
    // Unordered, and for the same reason.
    if (!readsUnorderedPair(add, loHalf, hiHalf)) return null;
  }

  // 6. The recombine is the iterate's `bodyOutput`: low half then high half,
  //    in that order. Unlike a Feistel round there is no swap hidden here.
  const recombine = byId.get(bodyOutput.node);
  if (!recombine || !isTwoWayConcat(recombine)) return null;
  const hiProducerId = kind === "cooley-tukey" ? sub.id : mul.id;
  if (!comesFrom(inputAt(recombine, "input0"), add.id)) return null;
  if (!comesFrom(inputAt(recombine, "input1"), hiProducerId)) return null;

  // 7. The advance is the OTHER two-input concat, and it rotates the ζ table:
  //    both its operands come off the ζ split, on opposite ports.
  const advance = leaves.find((l) => l.id !== recombine.id && isTwoWayConcat(l));
  if (!advance) return null;
  const advA = inputAt(advance, "input0");
  const advB = inputAt(advance, "input1");
  if (!advA || !advB) return null;
  if (advA.node !== zeta.id || advB.node !== zeta.id) return null;
  if (advA.port === advB.port) return null;

  // 8. PARTITION GATE. The eight roles must tile the body exactly once. With a
  //    fixed body size this can only fail by two roles resolving to one leaf,
  //    but it is the check that makes "recognized" mean "fully accounted for"
  //    rather than "eight things happened to match".
  const roles: readonly { readonly id: string; readonly role: NttButterflyRole }[] = [
    { id: split.id, role: "split" },
    { id: zeta.id, role: "zeta" },
    { id: modulus.id, role: "modulus" },
    { id: mul.id, role: kind === "cooley-tukey" ? "twist" : "hi" },
    { id: add.id, role: "lo" },
    { id: sub.id, role: kind === "cooley-tukey" ? "hi" : "diff" },
    { id: recombine.id, role: "recombine" },
    { id: advance.id, role: "advance" },
  ];
  const claimed = new Set<string>();
  for (const { id } of roles) {
    if (claimed.has(id)) return null;
    claimed.add(id);
  }
  if (claimed.size !== leaves.length) return null;
  for (const leaf of leaves) {
    if (!claimed.has(leaf.id)) return null;
  }

  const roleById = new Map(roles.map((r) => [r.id, r.role] as const));
  return {
    layerId: node.id,
    kind,
    splitId: split.id,
    zetaId: zeta.id,
    modulusId: modulus.id,
    twistId: mul.id,
    addId: add.id,
    subId: sub.id,
    hiProducerId,
    recombineId: recombine.id,
    advanceId: advance.id,
    // Spec order, so a consumer that just wants "the leaves" reads them the
    // way the file writes them.
    memberIds: leaves.map((l) => l.id),
    ops: leaves.map((l) => ({
      nodeId: l.id,
      role: roleById.get(l.id) as NttButterflyRole,
    })),
  };
};

// ─── Spec-wide derivations ──────────────────────────────────────────────────
//
// These live HERE rather than in `GraphView.tsx` so the tests can import the
// real functions the component calls. A test that re-creates the composition
// locally is not a test of it — narrowing the shipped guard would leave every
// assertion green while the browser cell fell apart (the lesson
// `core/arx-group.ts` was extracted for).
//
// There is no `ntt-group.ts` sibling: `arx-group.ts` exists only because TWO
// analyzers import the shared ARX envelope, so calling them from it would be a
// genuine import cycle. One analyzer here means no cycle and no extra module.

/** Visit every iterate in a spec's step tree, outermost first. */
const forEachIterate = (nodes: readonly StepNode[], visit: (node: IterateGroup) => void): void => {
  for (const node of nodes) {
    if (node.kind === "step") continue;
    if (node.kind === "iterate") visit(node);
    if ("children" in node) forEachIterate(node.children, visit);
  }
};

/**
 * Every recognized NTT butterfly in a spec, keyed by its layer-iterate id — the
 * canonical-layout map. An id present here lays out as the butterfly cell (see
 * `ntt-layout.ts`) instead of an eight-chip horizontal ribbon.
 *
 * Walks nested containers because ML-KEM embeds these transforms inside groups:
 * K-PKE key generation alone contains several, at `keygen.ntt-*.layerN`.
 */
export const nttButterfliesById = (spec: CipherSpec): ReadonlyMap<string, NttButterflyShape> => {
  const byId = new Map<string, NttButterflyShape>();
  forEachIterate(spec.steps, (node) => {
    const shape = analyzeNttButterfly(node);
    if (shape !== null) byId.set(node.id, shape);
  });
  return byId;
};

/**
 * Per-node replication overrides marking every butterfly member `"never"` — the
 * guard that keeps the cell intact.
 *
 * **Measured, not assumed.** `replicateHighFanoutSources` counts DISTINCT
 * CONSUMER NODES per source and fires on `count > threshold`, strictly. At the
 * default threshold of 3 no butterfly member qualifies: the Cooley–Tukey split
 * and the modulus each feed exactly three consumers (`{twist, lo, hi}`), the
 * Gentleman–Sande split feeds two, and the ζ split feeds two. So unlike the ARX
 * and Twofish cells — where the split is five to eight times over the line and
 * the cell provably shatters without a guard — nothing here breaks by default.
 *
 * The guard exists because the threshold is a user-facing control that goes
 * down to 1. At a threshold of 2 the modulus and the C–T split both cross it,
 * get DELETED from the graph and scatter into per-consumer chips, and the cell
 * loses its two most connected nodes. Marking members `"never"` costs nothing
 * (an explicit per-source override still wins on top, since `GraphView` spreads
 * the user's modes last) and matches the Twofish and ARX precedent.
 */
export const nttButterflyNeverModes = (spec: CipherSpec): Record<string, "never"> => {
  const modes: Record<string, "never"> = {};
  for (const shape of nttButterfliesById(spec).values()) {
    for (const id of shape.memberIds) modes[id] = "never";
  }
  return modes;
};
