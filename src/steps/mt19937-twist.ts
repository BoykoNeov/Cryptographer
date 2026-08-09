/**
 * MT19937's twist — the recurrence that advances all 624 words at once.
 *
 * Takes the 624-word state and produces the next one (Matsumoto & Nishimura
 * 1998; `mt19937ar.c`, the block inside `genrand_int32` that refills `mt`):
 *
 * ```
 * for i = 0 … 623:
 *     y     = (mt[i] & 0x80000000) | (mt[(i+1) mod 624] & 0x7fffffff)
 *     mt[i] = mt[(i+397) mod 624] ^ (y >> 1) ^ (y & 1 ? 0x9908b0df : 0)
 * ```
 *
 * One input port `input` (2496 bytes), one output port `output` (2496
 * bytes), both 624 big-endian words.
 *
 * ## Why this is one frame and not 624
 *
 * A **deliberate monolith**, and — like `mt19937.seed@1` beside it —
 * structurally inexpressible as a port-mode `iterate` rather than merely
 * large. Two independent blockers, either one sufficient:
 *
 *  1. **A body cannot reach its neighbours.** The runtime hands an iterate's
 *     body exactly that iteration's own block plus the value carried between
 *     iterations. This recurrence reads THREE words — `mt[i]`, `mt[i+1]` and
 *     `mt[i+397]` — so 624 passes over a 4-byte block cannot see what they
 *     need. Expressing it would require indexed random access into a carried
 *     array, which is a runtime capability this app does not have.
 *  2. **It does not vectorize into slice arithmetic either.** The obvious
 *     escape — treat it as one wide operation over three shifted views of
 *     the array — fails because the update is IN PLACE and sequential: from
 *     `i = 227` onward, `mt[i+397]` wraps to `mt[i−227]`, a word this same
 *     loop has ALREADY overwritten. The first 227 steps read only old
 *     values; the remaining 397 read a mixture. Any "parallel" reading of
 *     this loop is a different, wrong generator.
 *
 * ## What the recurrence actually does
 *
 * It is a **twisted generalized feedback shift register**. The `y` above is
 * a splice: the top bit of `mt[i]` concatenated with the low 31 bits of
 * `mt[i+1]`. That 31/1 split is why the period is 2^19937−1 rather than
 * 2^19968−1 — the state is 624×32 = 19968 bits, but one word contributes
 * only its top bit, so 31 bits never participate.
 *
 * `0x9908b0df` is the "twist" itself: the coefficient vector of a primitive
 * polynomial over GF(2), XORed in exactly when the shifted-out bit was 1.
 * That conditional XOR is a multiplication by a companion matrix, and its
 * primitivity is what makes the period maximal. It is also why the whole
 * construction is **linear over GF(2)** — every output bit is a fixed XOR of
 * state bits, which is the property that makes MT19937 breakable by linear
 * algebra once you have seen enough output, and the reason it fails the
 * MatrixRank and LinearComplexity tests in the statistical batteries it
 * otherwise passes.
 *
 * ## Called once
 *
 * The real generator twists lazily — every 624 words drawn, it refills. This
 * app's output ceiling keeps a run inside the first 624 words, so the spec
 * contains exactly one twist and `mt19937.ts`'s builder refuses a request
 * that would need a second rather than silently emitting a wrong stream.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { MT_N, MT_STATE_BYTES, bytesToWordsBE, wordsToBytesBE } from "./mt19937-seed";

/** The offset word — `m` of the published parameter set. */
export const MT_M = 397;

/** The twist coefficient vector: a primitive polynomial over GF(2). */
export const MT_MATRIX_A = 0x9908b0df;

/** Top bit of a word — the only bit `mt[i]` contributes to the splice. */
export const MT_UPPER_MASK = 0x80000000;

/** Low 31 bits — what `mt[i+1]` contributes to the splice. */
export const MT_LOWER_MASK = 0x7fffffff;

/**
 * The twist in plain numbers, sharing nothing with the port machinery.
 * Exported so the KAT can drive it directly across many refills without
 * building a trace.
 *
 * Operates on a COPY: in the reference implementation the update is in
 * place, and the second half of the loop deliberately reads words the first
 * half has already rewritten. Copying the input preserves that behaviour
 * while leaving the caller's array untouched (the runtime's immutability
 * contract).
 */
export const twist = (state: Uint32Array): Uint32Array => {
  const mt = Uint32Array.from(state);
  for (let i = 0; i < MT_N; i++) {
    // The splice: top bit of mt[i], low 31 bits of its successor. The
    // successor wraps — and from i = 227 the mt[i+397] read below wraps too,
    // reaching a word THIS loop has already overwritten. That is the
    // algorithm, not a bug: the update is sequential and in place.
    const y =
      (((mt[i] as number) & MT_UPPER_MASK) | ((mt[(i + 1) % MT_N] as number) & MT_LOWER_MASK)) >>>
      0;
    mt[i] =
      ((mt[(i + MT_M) % MT_N] as number) ^ (y >>> 1) ^ ((y & 1) === 1 ? MT_MATRIX_A : 0)) >>> 0;
  }
  return mt;
};

const readParams = (params: Json): void => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("mt19937.twist: params must be an object");
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const mt19937TwistPortContract: PortContract = {
  // State in, state out — both fixed at the algorithm's 624 words.
  inputs: new Map([["input", { layout: "raw", byteLength: MT_STATE_BYTES }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: MT_STATE_BYTES }]]),
};

export const mt19937Twist: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const stateBytes = inputs.get("input");
  if (stateBytes === undefined) {
    throw new Error("mt19937.twist: missing required input port 'input'");
  }
  if (stateBytes.length !== MT_STATE_BYTES) {
    throw new Error(
      `mt19937.twist: state must be exactly ${MT_STATE_BYTES} bytes (${MT_N} words), got ${stateBytes.length}`,
    );
  }
  return new Map([["output", wordsToBytesBE(twist(bytesToWordsBE(stateBytes)))]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const mt19937TwistDoc: StepDocumentation = {
  name: "Twist the state",
  summary:
    "Advances all 624 words at once, splicing each word with its neighbour and folding in a GF(2) polynomial.",
  detail: `# The twist

MT19937 does not advance one word at a time. It advances **all 624 at
once**, and then hands them out one by one until they run out:

\`\`\`
y     = (mt[i] & 0x80000000) | (mt[i+1] & 0x7fffffff)
mt[i] = mt[i+397] ^ (y >> 1) ^ (y & 1 ? 0x9908b0df : 0)
\`\`\`

## The 31/1 splice, and where the missing bit went

\`y\` takes **one bit** from \`mt[i]\` — its top — and **31 bits** from the
next word. That is the whole reason the period is 2^19937−1 and not
2^19968−1: the state holds 624 × 32 = 19,968 bits, but one word only ever
contributes its highest, so 31 bits never take part. The name says it: 19937
is a Mersenne exponent, and the period is the Mersenne prime 2^19937−1.

## 0x9908b0df

The twist constant is the coefficient vector of a **primitive polynomial
over GF(2)**, XORed in exactly when the bit shifted off \`y\` was a 1. That
conditional XOR is a matrix multiplication in disguise, and the polynomial's
primitivity is precisely what makes the period maximal.

It is also the source of the generator's defining weakness: **every
operation here is linear over GF(2)**. Each bit of the state is a fixed
exclusive-or of earlier bits — no addition, no multiplication, no carry
anywhere. That is why MT19937 sails through most statistical batteries and
still fails the ones that look for linear structure, and why observing
enough output lets you solve for the state with linear algebra rather than
search.

## Why one frame

Two reasons, either one sufficient. A loop body in this app receives its own
block and the value carried between iterations — but this recurrence reads
**three** words, \`mt[i]\`, \`mt[i+1]\` and \`mt[i+397]\`, so it cannot be
expressed as a visible loop here at all.

And it is not secretly parallel either: the update happens **in place**, so
from \`i = 227\` onward the \`mt[i+397]\` term wraps around and reads a word
this very loop already rewrote. The first 227 steps see only old values; the
rest see a mixture. Treating the twist as one wide operation over shifted
copies of the array produces a different generator that happens to look
similar.

## It happens again every 624 words

The real generator refills whenever the 624 words are used up. This app's
output ceiling keeps you inside the first batch, so you are looking at the
only twist this run performs — ask for more than 2496 bytes and the app
tells you so rather than quietly showing you the wrong stream.`,
  params: new Map(),
  references: [
    "Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §2–3",
    "mt19937ar.c — the reference implementation, genrand_int32()",
  ],
};
