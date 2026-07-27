/**
 * **ARX double-round recognition, at the spec level** — the one place that
 * knows "a group is an ARX double round if *either* ARX analyzer claims it."
 *
 * **Why this is its own module.** Three consumers need exactly this composition
 * — the graph view's canonical-layout map, the graph view's replication guard,
 * and the two replication tests that pin that guard — and there was nowhere for
 * it to live that all three could reach:
 *
 *   - `arx-round-shape.ts` owns the shared envelope, but it is imported BY
 *     `chacha-shape.ts` and `salsa-shape.ts`, so calling them from there would
 *     be a genuine import cycle.
 *   - `GraphView.tsx` is where it started life, but it is a large Solid
 *     component; a node-environment test cannot import one helper out of it
 *     without dragging the whole component tree along.
 *
 * So the tests each grew a local copy of the composition, and a local copy of
 * the guard is not a test of the guard — narrowing `GraphView`'s version back
 * to one cipher would have left every assertion green while the browser cell
 * fell apart. That is precisely the failure mode
 * `tests/salsa-graph-replication.test.ts` exists to prevent, so the shared
 * function moved here and the copies are gone.
 *
 * Everything in this module is pure and spec-only (no trace, no DOM), which is
 * what lets the tests drive the real code path rather than a paraphrase of it.
 */

import type { ArxDoubleRoundShape } from "./arx-round-shape";
import { analyzeChaChaDoubleRound } from "./chacha-shape";
import { analyzeSalsaDoubleRound } from "./salsa-shape";
import type { CipherSpec, StepGroup, StepNode } from "./types";

/**
 * Recognize a group as ANY cipher's ARX double round.
 *
 * ChaCha20 and Salsa20 share the double-round envelope and therefore share the
 * canonical layout — only the twelve-op walk inside differs, which is why there
 * are two analyzers rather than one. Asking both here (rather than keeping a
 * per-cipher map, or worse a hardcoded id list) is what makes every downstream
 * consumer — the layout AND the replication guard — generalize with the shape
 * family instead of with the cipher list. A third ARX cipher adds one line.
 *
 * The two analyzers are mutually exclusive by construction: they anchor on
 * different rotation constants (`<<< 7` vs `<<< 18`) and their walks reject each
 * other's dependency graphs, so at most one can match. (Non-obviously, the
 * anchor alone does NOT separate them — a Salsa double round does contain eight
 * `<<< 7` rotations, so ChaCha's anchor filter passes and it is the walk that
 * declines, because the rotate's sole input reaches an add rather than an xor.)
 */
export const analyzeArxGroup = (group: StepGroup): ArxDoubleRoundShape | null =>
  analyzeChaChaDoubleRound(group) ?? analyzeSalsaDoubleRound(group);

/** Visit every group in a spec's step tree, outermost first. */
const forEachGroup = (nodes: readonly StepNode[], visit: (group: StepGroup) => void): void => {
  for (const node of nodes) {
    if (node.kind === "step") continue;
    if (node.kind === "group") visit(node);
    forEachGroup(node.children, visit);
  }
};

/**
 * Every recognized ARX double round in a spec, keyed by its group id — the
 * canonical-layout map. A group id present here lays out as the two-tier
 * quarter-round grid (see `arx-round-layout.ts`) instead of a 98-chip vertical
 * ribbon.
 */
export const arxDoubleRoundsById = (spec: CipherSpec): ReadonlyMap<string, ArxDoubleRoundShape> => {
  const byId = new Map<string, ArxDoubleRoundShape>();
  forEachGroup(spec.steps, (group) => {
    const shape = analyzeArxGroup(group);
    if (shape !== null) byId.set(group.id, shape);
  });
  return byId;
};

/**
 * Per-node replication overrides marking every member of every ARX double round
 * `"never"` — the guard that keeps the canonical cell intact.
 *
 * **Why it is needed, measured rather than reasoned.**
 * `replicateHighFanoutSources` counts distinct consumers per source NODE, not
 * per output PORT. Each of the 16-way split's ports has exactly one consumer,
 * so a per-port rule would never fire — but per node the split feeds sixteen
 * consumers over twenty edges in ChaCha20, and twenty-four over twenty-eight in
 * Salsa20 (only Salsa's XORs write back, so a word stays "original" across
 * three of four written lines instead of two). Both are multiples of the
 * threshold, so without this the split would be DELETED from the graph and
 * scattered into per-consumer chips, destroying the cell — the failure that
 * shipped with Twofish's 4-rail round and was found by opening a browser.
 *
 * No other round member comes close: every ARX operation feeds at most two
 * others. We mark every member anyway, matching the Twofish and Feistel
 * precedent.
 */
export const arxRoundNeverModes = (spec: CipherSpec): Record<string, "never"> => {
  const modes: Record<string, "never"> = {};
  forEachGroup(spec.steps, (group) => {
    const shape = analyzeArxGroup(group);
    if (shape === null) return;
    for (const id of [
      shape.splitId,
      shape.concatId,
      ...shape.quarterRounds.flatMap((qr) => qr.memberIds),
    ]) {
      modes[id] = "never";
    }
  });
  return modes;
};
