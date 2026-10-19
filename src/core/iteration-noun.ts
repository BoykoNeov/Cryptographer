/**
 * What one pass of an `iterate` loop is CALLED in the UI — "block" or
 * "attempt".
 *
 * Every loop the app shipped before ML-DSA walked a known amount of data: a
 * mode's message blocks, a hash's message blocks, a generator's output words,
 * an NTT layer's butterfly groups. "Block i of N" read correctly for all of
 * them. ML-DSA signing is different in kind: its loop does not walk data at
 * all. It TRIES a candidate signature, checks it against four bounds, and tries
 * again until one passes (FIPS 204 Algorithm 7's rejection loop). Calling those
 * passes "blocks" tells a learner the wrong story — it suggests the message was
 * chopped into pieces, when every pass actually signs the whole message again
 * with a fresh mask.
 *
 * The noun is derived from the loop's SHAPE, not from the cipher's name: a loop
 * with `stopWhen` decides on its own when to finish, which is exactly what
 * makes its passes attempts rather than a walk through data. So any future
 * repeat-until loop gets the right word for free, and no surface has to keep a
 * list of which algorithms retry.
 */

import type { StepNode } from "./types";

/** The two words a loop pass can be called. */
export type IterationNoun = "block" | "attempt";

/** The noun for one loop. `stopWhen` present ⇒ a repeat-until loop ⇒ attempts. */
export const iterationNounOf = (iterate: { readonly stopWhen?: unknown }): IterationNoun =>
  iterate.stopWhen !== undefined ? "attempt" : "block";

/** `"block"` → `"blocks"`, `"attempt"` → `"attempts"` — both nouns are regular. */
export const pluralNoun = (noun: IterationNoun): string => `${noun}s`;

/** Capitalized for sentence starts ("Attempt 2 of 3"). */
export const capitalNoun = (noun: IterationNoun): string =>
  noun.charAt(0).toUpperCase() + noun.slice(1);

/**
 * Every `iterate` in a spec tree, by id, mapped to its noun. Walks every
 * container kind so an iterate nested inside a group (ML-KEM's, ML-DSA's) is
 * found too.
 */
export const iterationNounsById = (
  nodes: readonly StepNode[],
): ReadonlyMap<string, IterationNoun> => {
  const out = new Map<string, IterationNoun>();
  const walk = (list: readonly StepNode[]): void => {
    for (const node of list) {
      if (node.kind === "step") continue;
      if (node.kind === "iterate") out.set(node.id, iterationNounOf(node));
      walk(node.children);
    }
  };
  walk(nodes);
  return out;
};

/**
 * The noun for the loop a frame was emitted in. A frame's `path` is its
 * container chain, outermost first, so the NEAREST enclosing iterate is the
 * last path element that names one. (A frame inside a group inside an iterate —
 * DES's `rounds` — skips past the group to its loop.) Falls back to `"block"`
 * when no enclosing iterate is known.
 */
export const iterationNounForPath = (
  path: readonly string[],
  nouns: ReadonlyMap<string, IterationNoun>,
): IterationNoun => {
  for (let i = path.length - 1; i >= 0; i--) {
    const noun = nouns.get(path[i] as string);
    if (noun !== undefined) return noun;
  }
  return "block";
};
