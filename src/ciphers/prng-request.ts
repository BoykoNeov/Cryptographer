/**
 * The one thing every generator in the app needs and no cipher does: a way to
 * say **how much output you want**.
 *
 * A cipher learns how much work to do from its message. A generator has no
 * message — the seed selects *which* sequence, never *how much of it* — so the
 * requested length has to enter the spec on its own. Every PRNG spec therefore
 * opens with the same leaf: a `zero-fill@1` whose bytes are never read and whose
 * **width** is bound to an iterate's `seedInput`, making the iteration count
 * `ceil(N / blockWidth)`.
 *
 * This module holds the two things that must agree across every generator:
 * the leaf's id, and the function that reads the length back out of a built
 * spec. They live here rather than in any one generator's file because a third
 * family member (`chacha20-csprng.ts` alongside `lcg.ts`) must not have to
 * import from a sibling generator to learn the convention — and because
 * `stores/spec.ts` needs one reader for all of them, not one per variant.
 *
 * See `docs/plans/iterative-dancing-ocean.md` for why the length is a
 * *structural* rebuild rather than a param edit: it changes the spec's contents,
 * which `editStepParams` cannot express.
 */

import type { CipherSpec } from "../core/types";

/**
 * The id of the `zero-fill@1` leaf carrying the requested output length.
 *
 * Shared by every generator, and load-bearing: `readPrngOutputLength` addresses
 * it by name, so a variant that renamed its request leaf would round-trip a
 * saved document with the length silently reset to the default.
 */
export const PRNG_REQUEST_ID = "request";

/**
 * Read the requested output length back out of a built generator spec.
 *
 * Used when loading a saved or shared document so the app's output-length
 * control lands on the document's value rather than the default. Without it a
 * round-trip silently loses the length: the trace would show 137 bytes while the
 * stepper read 42.
 *
 * Variant-agnostic by construction — it keys on the request leaf, which every
 * generator carries at the same id in the same position, whatever its word or
 * block width. Mirrors `readShakeOutputLength` in `ciphers/shake.ts`.
 *
 * @returns the length, or `undefined` if the spec has no recognizable request
 *          leaf (a hand-edited document, in which case the caller keeps its
 *          current value rather than guessing)
 */
export const readPrngOutputLength = (spec: CipherSpec): number | undefined => {
  for (const node of spec.steps) {
    if (node.kind === "step" && node.id === PRNG_REQUEST_ID) {
      const len = (node.params as Record<string, unknown>).byteLength;
      if (typeof len === "number" && Number.isInteger(len) && len >= 1) return len;
    }
  }
  return undefined;
};
