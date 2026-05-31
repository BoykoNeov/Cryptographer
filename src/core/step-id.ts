/**
 * Step-id canonicalization — the single source of truth for stripping
 * runtime-context suffixes off a TraceFrame's stepId to recover the
 * spec-leaf id the UI references.
 *
 * Suffix vocabulary today:
 *
 *   - `:b{i}` — block index inside an `iterate`.
 *   - `:r{i}` — round index inside a `for-each-subgraph` (Slice 2.0a of
 *     `docs/plans/universal-port-phase-2-slices.md`). The new kind threads
 *     state across iterations rather than seeding from an aux array;
 *     SHA-256's 64-round compression loop is the first shipped consumer.
 *
 * Note: `:coerce:{portName}` (synthetic frames from Slice 1.12's port-
 * length coercion path) is **deliberately NOT stripped** — the coerce
 * frame stands on its own in the scrubber, distinct from the consumer
 * leaf it precedes (precedent: it has its own stateBefore/stateAfter
 * pair just like a real leaf). Stripping it would collapse coerce frames
 * into their consumers under `setTrace`'s stepId-matching, which is the
 * opposite of the "morph is visible" design.
 *
 * Composition rule (see `runtime.ts::composeStepId`): **fixed type order**
 * `:b` < `:r`, with **outer-first walk order within a type**. So a leaf
 * inside an iterate inside a for-each-subgraph emits `<leafId>:b3:r7`:
 * `:b3` (iterate is outer-of-:b), then `:r7` (for-each-subgraph is
 * outer-of-:r).
 *
 * Canonical form: every suffix stripped. So:
 *   - `compress.body:b0:r17` → `compress.body`
 *   - `aes.sub-bytes:b0` → `aes.sub-bytes`
 *
 * Why one util: prior to Phase 2 the canonicalization lived in two
 * places (`src/ui/stores/trace.ts:48` using `indexOf(":b")`; and
 * `src/core/edge-value-lookup.ts:182` using `/:b\d+$/`). With multiple
 * suffix families now, the two drifting implementations would each need
 * extending; centralizing here prevents the drift.
 */

// The regex matches any suffix repeatedly until none remain — order of
// alternatives within the group does not affect match correctness. We
// strip from the right because suffixes are appended at the rightmost
// position by `composeStepId` under the type-order + walk-order rule
// documented above.
const SUFFIX_PATTERN = /(?::b\d+|:r\d+)+$/;

/**
 * Strip all runtime-context suffixes off a stepId. Returns the spec-leaf
 * id. Pure.
 */
export const canonicalStepId = (frameStepId: string): string =>
  frameStepId.replace(SUFFIX_PATTERN, "");
