/**
 * Pure helpers for validating + repairing user-edited S-box tables.
 *
 * An S-box used by a substitution cipher must be a **permutation** of
 * 0..N-1 — each value appears exactly once — so the inverse table is
 * well-defined. AES uses N=256 (8-bit bytes); Serpent uses N=16 (4-bit
 * nibbles). The helpers are size-parameterized so the same logic works
 * for either, driven by `values.length`.
 *
 * The editor surfaces these in two ways:
 *   - `findDuplicateIndices` highlights cells participating in a
 *     collision so the user sees which entries are clashing.
 *   - `repairToPermutation` fills missing values into the redundant
 *     duplicate slots (leftmost wins; rightmost duplicates get
 *     reassigned in ascending-missing-value order). Deterministic, and
 *     a no-op when the input is already a permutation.
 *
 * Kept pure (no Solid imports) so they're testable in vitest's node
 * environment — the duplicate-finder doesn't need a DOM.
 */

/**
 * Returns the set of indices whose value collides with at least one
 * other index in `values`. Length must equal the expected range size
 * (the table is implicitly an `0..length-1` permutation candidate).
 *
 * Example: `[3, 5, 3, 0]` → `{0, 2}` (the two indices both holding `3`).
 */
export function findDuplicateIndices(values: readonly number[]): Set<number> {
  // Bucket by value so we can find groups of size >= 2 in one pass.
  const buckets = new Map<number, number[]>();
  for (let i = 0; i < values.length; i++) {
    const v = values[i] ?? 0;
    const list = buckets.get(v);
    if (list) list.push(i);
    else buckets.set(v, [i]);
  }

  const dupes = new Set<number>();
  for (const list of buckets.values()) {
    if (list.length > 1) {
      for (const i of list) dupes.add(i);
    }
  }
  return dupes;
}

/**
 * Returns the number of "redundant" duplicate cells — i.e. cells that
 * would need to change to make the table a permutation. For each
 * collision group of size k, k-1 cells are redundant.
 *
 * This is what we show in the banner ("S-box has N duplicate values")
 * because it matches the user's mental model: "how many cells do I need
 * to fix?", not "how many cells are highlighted?".
 */
export function countRedundantDuplicates(values: readonly number[]): number {
  const seen = new Set<number>();
  let extra = 0;
  for (let i = 0; i < values.length; i++) {
    const v = values[i] ?? 0;
    if (seen.has(v)) extra++;
    else seen.add(v);
  }
  return extra;
}

/**
 * Returns the collision-group indices for each value that appears more
 * than once. Used to build per-cell tooltips like
 * "Duplicated at indices 0x1f, 0x44, 0x9c".
 */
export function collisionGroupsByIndex(values: readonly number[]): Map<number, readonly number[]> {
  const buckets = new Map<number, number[]>();
  for (let i = 0; i < values.length; i++) {
    const v = values[i] ?? 0;
    const list = buckets.get(v);
    if (list) list.push(i);
    else buckets.set(v, [i]);
  }

  // For each index that's part of a duplicate group, record the whole group.
  const out = new Map<number, readonly number[]>();
  for (const group of buckets.values()) {
    if (group.length > 1) {
      const frozen = group.slice();
      for (const i of group) out.set(i, frozen);
    }
  }
  return out;
}

/**
 * Returns the inverse permutation of `values`: a new array `inv` such
 * that `inv[values[i]] === i` for all i. Equivalently: if `values` is
 * the forward S-box, `invertSbox(values)` is the inverse S-box.
 *
 * Preconditions: `values` must be a permutation of `0..length-1`. The
 * caller is responsible for the bijection check (see
 * `countRedundantDuplicates` — the UI gates the Sync-inverse button on
 * a zero count). When the precondition is violated, the result is
 * still a length-N array but undefined entries may be filled with 0,
 * which is not what you want algorithmically.
 *
 * Involutive: `invertSbox(invertSbox(x)) === x` for any permutation
 * x. So the same operation works in either direction — call it on the
 * forward table to get the inverse, or on the inverse to get the
 * forward. The UI relies on this for "Sync inverse to decrypt" and
 * "Sync inverse to encrypt" being the same algorithm with a different
 * label.
 */
export function invertSbox(values: readonly number[]): number[] {
  const n = values.length;
  const out = new Array<number>(n).fill(0);
  for (let i = 0; i < n; i++) {
    const v = values[i] ?? 0;
    // Out-of-range entries are skipped — they can't index into a
    // length-N inverse table. The bijection precondition rules this
    // out in practice; the guard is defensive only.
    if (v >= 0 && v < n) out[v] = i;
  }
  return out;
}

/**
 * Returns a new array that is a permutation of `0..values.length-1`,
 * derived from `values` by:
 *   1. Keeping the *first* occurrence of each value (leftmost wins).
 *   2. Replacing later duplicate occurrences with the missing values,
 *      consumed in ascending numeric order.
 *
 * Properties:
 *   - Deterministic for any given input.
 *   - Identity when the input is already a permutation.
 *   - Always returns a fresh array (callers can rely on reference
 *     identity to detect change).
 *
 * Example:
 *   input:  [0, 0, 2, 3]          (length 4)
 *   missing: {1}                   (since 0 already present)
 *   output: [0, 1, 2, 3]           (the second 0 → 1, the smallest missing)
 */
export function repairToPermutation(values: readonly number[]): number[] {
  const n = values.length;
  const out = new Array<number>(n);
  for (let i = 0; i < n; i++) out[i] = values[i] ?? 0;

  // Pass 1: collect the set of values present in [0, n) and ignore any
  // out-of-range entries (those count as "missing" too, since they
  // can't appear in a 0..n-1 permutation).
  const present = new Set<number>();
  for (let i = 0; i < n; i++) {
    const v = out[i] ?? 0;
    if (v >= 0 && v < n) present.add(v);
  }

  // Pass 2: build the missing list in ascending order.
  const missing: number[] = [];
  for (let v = 0; v < n; v++) {
    if (!present.has(v)) missing.push(v);
  }

  // Pass 3: walk left-to-right; first occurrence wins, later duplicates
  // (or out-of-range entries) get the next missing value.
  const used = new Set<number>();
  let mi = 0;
  for (let i = 0; i < n; i++) {
    const v = out[i] ?? 0;
    const inRange = v >= 0 && v < n;
    if (inRange && !used.has(v)) {
      used.add(v);
      continue;
    }
    // Either a duplicate or out-of-range — replace with a missing value.
    const nv = missing[mi++];
    if (nv === undefined) {
      // Shouldn't happen if counts balance, but be defensive: leave
      // the cell as-is rather than corrupt the array.
      continue;
    }
    out[i] = nv;
    used.add(nv);
  }

  return out;
}
