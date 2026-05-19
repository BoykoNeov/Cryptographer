/**
 * Step-id canonicalization — the single source of truth for stripping
 * runtime-context suffixes off a TraceFrame's stepId to recover the
 * spec-leaf id the UI references.
 *
 * Suffixes (in their innermost-first append order; see `runtime.ts`):
 *
 *   - `:t{name}` — track membership inside a `feistel-round`. Innermost.
 *     `{name}` is the `BranchTrack.name` (default: stringified index).
 *   - `:b{i}` — block index inside an `iterate`. Outer.
 *   - `:rejoin` — synthetic rejoin frame for a `feistel-round`; spec-leaf
 *     resolves to the round's id (the FeistelRoundGroup node, not a leaf).
 *   - `:swap` — reserved for future "post-swap" frames. Not emitted today;
 *     the swap is baked into the `feistel-standard` combine.
 *
 * Canonical form: every suffix stripped. So:
 *   - `round.1.expand-R:tR:b3` → `round.1.expand-R`
 *   - `round.1:rejoin` → `round.1`
 *   - `round.1:rejoin:b3` → `round.1`
 *   - `aes.sub-bytes:b0` → `aes.sub-bytes`
 *
 * Why one util: prior to Phase 2 the canonicalization lived in two
 * places (`src/ui/stores/trace.ts:48` using `indexOf(":b")`; and
 * `src/core/edge-value-lookup.ts:182` using `/:b\d+$/`). With three
 * suffix families now, the two drifting implementations would each need
 * extending; centralizing here prevents the drift.
 */

// Order matters only for documentation — the regex matches any suffix
// repeatedly until none remain. We strip from the right because suffixes
// are appended innermost-first at the rightmost position.
const SUFFIX_PATTERN = /(?::b\d+|:t[\w-]+|:rejoin|:swap)+$/;

/**
 * Strip all runtime-context suffixes off a stepId. Returns the spec-leaf
 * id (or the FeistelRoundGroup id for `:rejoin` frames). Pure.
 */
export const canonicalStepId = (frameStepId: string): string =>
  frameStepId.replace(SUFFIX_PATTERN, "");
