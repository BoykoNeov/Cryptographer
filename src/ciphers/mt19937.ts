/**
 * MT19937 — the Mersenne Twister, and the PRNG family's fifth generator.
 *
 * Plan: `docs/plans/validated-growing-dongarra.md` (P4 of the family plan
 * `docs/plans/iterative-dancing-ocean.md`).
 *
 * ## Why this generator is here
 *
 * The family already ships generators at both extremes. The three LCGs are
 * trivially predictable and *visibly* so. The ChaCha20 CSPRNG is
 * unpredictable and structurally a stream cipher with the message deleted.
 * MT19937 belongs to neither category, and that is exactly its value:
 *
 *  - Its period is 2^19937 − 1, and it passes statistical batteries the LCGs
 *    fail outright. By the standards a learner would naturally apply after
 *    meeting the LCGs, it looks *good*.
 *  - It is nevertheless **completely predictable**. Its output function is a
 *    bijection, so untempering 624 consecutive outputs recovers the entire
 *    internal state, handing over the whole future of the stream — and, since
 *    every operation in it is invertible, the past as well.
 *
 * It is therefore the app's only generator that **separates "passes
 * statistical tests" from "unpredictable"**. A learner who has met only the
 * LCGs and the CSPRNG will reasonably conclude those are the same property.
 * They are not, and this is the counterexample — sitting one dropdown entry
 * away from the CSPRNG that does not share the flaw. It is also, by a wide
 * margin, the generator they are most likely to have already used: Python's
 * `random`, C++'s `std::mt19937`, MATLAB, Ruby and PHP all ship it.
 *
 * ## Structure of the spec
 *
 * ```
 *   $input (the 4-byte seed)
 *      │
 *      ▼
 *   seed-state  mt19937.seed@1     → 2496 B   ← MONOLITH (624 words)
 *      │
 *      ▼
 *   twist       mt19937.twist@1    → 2496 B   ← MONOLITH (624 words)
 *      │
 *   request     zero-fill@1 { byteLength: N }       (its WIDTH sets the count)
 *      │
 *   words       byte-slice@1 { 0 .. 4·ceil(N/4) }
 *      │
 *      └─► iterate "temper"  blockByteLength 4      ← NO carry between passes
 *              y ^= y >> 11
 *              y ^= (y << 7)  & 0x9d2c5680
 *              y ^= (y << 15) & 0xefc60000
 *              y ^= y >> 18
 *      │
 *   emit        truncate-to-reference@1 (iterate.out, ref = request)
 * ```
 *
 * ### Three things here are firsts, and all three are load-bearing
 *
 * **1. The temper loop carries NOTHING between iterations.** Every other
 * port-mode `iterate` in this app threads a value through the loop — CBC's
 * chain, CTR's counter, SHA-256's running hash, the LCGs' `x`. This one has
 * no `chainInput` and no `chainFeedback` at all, because MT's extraction is a
 * pure **map over the state array**: output word `i` depends on state word
 * `i` and nothing else. All the sequential dependence in this generator lives
 * inside the twist, which already happened.
 *
 * **2. The state travels on a PORT, not through aux.** It is the iterate's
 * `seedInput`. The ChaCha20 CSPRNG had to route its seed through aux because
 * its block function lives *inside* the loop and a body's scope cannot see
 * `$input` — but nothing crosses a scope here, so the honest wiring is the
 * visible one. Aux would hide the app's single most interesting wire: 2496
 * bytes of state flowing into a loop that reads one word per pass.
 *
 * **3. The trim is a SIBLING of the loop, not part of its body.** Every other
 * ragged-tail trim in the app (CTR, CFB, OFB, ChaCha20, Salsa20, the LCGs)
 * sits inside the body and references the iterate's per-block `in` port. That
 * is unavailable here: `in` is always a full 4-byte state word, so there is no
 * short reference to trim against — the shortness belongs to the *request*,
 * not to any block. So `words` rounds the request UP to a whole number of
 * words, and `emit` cuts the concatenated result back down to `N` after the
 * loop. This was spiked before anything else was written
 * (`tests/mt19937-kat.test.ts`'s first suite), because the whole design rests
 * on it.
 *
 * ## One twist, and the app says so
 *
 * The real generator refills every 624 words = 2496 bytes. The output ceiling
 * keeps every run inside the first batch, so this spec contains exactly one
 * twist — and `buildMt19937Spec` **throws** above 2496 bytes rather than
 * silently emitting a stream that omits a refill. This is the one place the
 * app is a strict subset of the algorithm, which is why it is an error and a
 * narration paragraph rather than an implicit assumption.
 *
 * ## Seeding — and a deliberate divergence from the rest of the family
 *
 * `lcg.ts` records the family convention as "x_0 is the seed verbatim, no
 * scrambling, no `init_by_array`, no discarded warm-up". **MT19937 cannot
 * honor it.** An LCG's state IS one word, so a one-word seed can simply be
 * it; MT19937's state is 624 words and a 32-bit seed cannot fill them. The
 * expansion (`init_genrand`) is mandatory and part of the published
 * generator. Two consequences, both stated on screen:
 *
 *  - only 2³² of the 2^19937 states are reachable from a 32-bit seed;
 *  - `init_genrand(s)` and `init_by_array([s])` produce **different streams**,
 *    and real libraries disagree about which they use for an integer seed.
 *    This app ships `init_genrand` only — C++'s and numpy-legacy's convention.
 *
 * ## Verification
 *
 * ISO/IEC 14882 §rand.predef states normatively that the 10000th consecutive
 * value of a default-constructed `std::mt19937` (seed 5489) is **4123659995**.
 * That value was reproduced independently before any of this shipped, by
 * pushing a hand-written `init_genrand` into numpy's MT19937 state and reading
 * `random_raw()` — so it is measured here, not quoted. `tests/mt19937-kat.test.ts`
 * carries it plus a second anchor (CPython's `init_by_array` reproducing the
 * published `mt19937ar.out`), the per-stage state vectors, and the
 * state-recovery attack as an executable test.
 *
 * The default seed is 5489 — `std::mt19937`'s `default_seed` — so the app's
 * first paint reproduces a published sequence, the property AES-128 gets from
 * FIPS-197 §C.1 and ChaCha20 from RFC 8439 §2.4.2.
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { MT_N, MT_STATE_BYTES } from "../steps/mt19937-seed";
import { port } from "./block-cipher-core";
import { PRNG_REQUEST_ID, readPrngOutputLength } from "./prng-request";

// ─── Constants ────────────────────────────────────────────────────────────

/** The generator's word width in bytes. Every MT19937 value is 32 bits. */
export const MT_WORD_BYTES = 4;

/** Seed width — one word, as `init_genrand` takes. */
export const MT_SEED_BYTES = MT_WORD_BYTES;

/**
 * The most output one twist can supply: 624 words. Requesting more would need
 * a second twist, which this spec does not contain — so the builder refuses
 * rather than quietly producing a stream that skips the refill.
 */
export const MT_MAX_OUTPUT_BYTES = MT_STATE_BYTES;

/**
 * The tempering parameters (Matsumoto & Nishimura 1998 §3), named as the paper
 * names them. These are the values the spec's `constant-load@1` and shift
 * leaves carry, and — unlike the two monoliths above them — every one is
 * reachable and editable in the app.
 */
export const MT_TEMPER_U = 11;
export const MT_TEMPER_S = 7;
export const MT_TEMPER_B = 0x9d2c5680;
export const MT_TEMPER_T = 15;
export const MT_TEMPER_C = 0xefc60000;
export const MT_TEMPER_L = 18;

const DISPLAY_NAME = "MT19937 (Mersenne Twister)";

// ─── Node ids ─────────────────────────────────────────────────────────────
//
// Exported because the KAT addresses nodes by id, and a silent rename would
// break it in ways the type checker cannot see.

export const MT_REQUEST_ID = PRNG_REQUEST_ID;
export const MT_SEED_ID = "seed-state";
export const MT_TWIST_ID = "twist";
export const MT_WORDS_ID = "words";
export const MT_TEMPER_ID = "temper";
export const MT_EMIT_ID = "emit";

/** Body leaf ids, in execution order. `y1`…`y4` are the four values the paper
 *  writes as successive assignments to `y`. */
export const MT_SHIFT_U_ID = "shift-u";
export const MT_Y1_ID = "y1";
export const MT_MASK_B_ID = "mask-b";
export const MT_SHIFT_S_ID = "shift-s";
export const MT_AND_B_ID = "and-b";
export const MT_Y2_ID = "y2";
export const MT_MASK_C_ID = "mask-c";
export const MT_SHIFT_T_ID = "shift-t";
export const MT_AND_C_ID = "and-c";
export const MT_Y3_ID = "y3";
export const MT_SHIFT_L_ID = "shift-l";
export const MT_Y4_ID = "y4";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Encode a 32-bit value as big-endian bytes — the shape `constant-load@1`'s
 *  `bytes` param wants. */
const wordBytes = (value: number): number[] => [
  (value >>> 24) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 8) & 0xff,
  value & 0xff,
];

const hex32 = (v: number): string => `0x${(v >>> 0).toString(16).padStart(8, "0")}`;

// ─── Narration ────────────────────────────────────────────────────────────

const narrRequest = (outputLength: number): StepDocumentation => ({
  name: `Request ${outputLength} bytes`,
  summary: "How much output you asked for — and therefore how many words get tempered.",
  detail: `## Nothing here says "how much" except you

A cipher learns how much work to do from its message. A generator has no
message: the seed picks *which* sequence, never *how much of it*. So the
requested length has to enter the spec on its own, and this is where it does.

\`\`\`
words = ceil(${outputLength} / 4) = ${Math.ceil(outputLength / MT_WORD_BYTES)}
\`\`\`

**This step plays a different role here than in the other generators.** In an
LCG this width drives the loop *count*, because each pass manufactures its own
next value. MT19937 has already manufactured all 624 words by the time you get
here — the twist above did it in one go. So this width selects how many of them
to hand out, and the loop below is not a generator at all but a **filter** the
state words pass through one at a time.

That difference is worth pausing on: it is why asking for one byte still costs a
full 624-word twist, and why asking for 2496 costs no more.`,
  references: [],
});

const narrSeed: StepDocumentation = {
  name: "Expand the seed into 624 words",
  summary: "Fills MT19937's whole internal state from your 32-bit seed, using a small LCG.",
  detail: `## 19,937 bits from 32

MT19937's state is **624 words**. Your seed is one. This step manufactures the
other 623 (Matsumoto & Nishimura's \`init_genrand\`):

\`\`\`
mt[0] = seed
mt[i] = 1812433253 · (mt[i−1] ^ (mt[i−1] >> 30)) + i     (mod 2³²)
\`\`\`

That recurrence is itself a **linear congruential generator** — the family the
three other generators in this app belong to, and one nobody would use for
randomness today. It is used here for a job it *is* adequate for: spreading one
word of information across the state so the twist has something non-degenerate
to work with. The multiplier is Knuth's; the \`^ (mt[i−1] >> 30)\` term folds
each word's top two bits down before multiplying, because a plain LCG leaves the
high bits of consecutive words visibly correlated.

## What it costs, permanently

Only **2³² distinct states** are reachable this way, out of 2^19937. The period
of the resulting sequence is astronomical; the number of *different* sequences
you can ask for is about four billion. When a program seeds from the clock, the
attacker's search space is not the state space — it is the set of plausible
timestamps.

## Why this is one step and not 623

Look at the \`+ i\`: that is the **loop index**. Nothing in this app produces
one — a loop body receives its own block of data and the value carried between
iterations, never a counter. So this stage cannot be drawn as a visible loop
here at all, and it runs as a single step rather than being faked as 623.

## Seeding conventions differ, and it matters

\`init_genrand(s)\` is not the only way MT19937 gets seeded. The reference
implementation also ships \`init_by_array\`, which CPython's \`random\` and
numpy's modern generators use for integer seeds — and it produces an entirely
different stream from the same number. This app implements \`init_genrand\`
only, the convention of C++'s \`std::mt19937\`.

A generator seeded under the wrong convention produces output that is perfectly
self-consistent, passes every statistical test, and matches no other
implementation on earth.`,
  references: [
    "Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §2",
    "mt19937ar.c — init_genrand()",
    "Knuth, TAOCP Vol. 2 §3.3.4",
  ],
};

const narrTwist: StepDocumentation = {
  name: "Twist all 624 words",
  summary: "Advances the entire state in one pass — the recurrence the generator is named for.",
  detail: `## The twist

MT19937 does not advance one word at a time. It advances **all 624 at once**,
then hands them out one by one until they run out:

\`\`\`
y     = (mt[i] & 0x80000000) | (mt[i+1] & 0x7fffffff)
mt[i] = mt[i+397] ^ (y >> 1) ^ (y & 1 ? 0x9908b0df : 0)
\`\`\`

## Where the name comes from

\`y\` splices **one bit** from \`mt[i]\` — its top — with **31 bits** from the
next word. That 31/1 split is the whole reason the period is 2^19937 − 1 and not
2^19968 − 1: the state holds 624 × 32 = 19,968 bits, but one word contributes
only its highest, so 31 bits never take part. 19937 is a Mersenne exponent, and
the period is the Mersenne prime 2^19937 − 1 — hence *Mersenne* Twister.

\`0x9908b0df\` is the *twist*: the coefficient vector of a primitive polynomial
over GF(2), XORed in exactly when the bit shifted off \`y\` was 1.

## And here is the defining weakness

**Every operation above is linear over GF(2).** XOR, shift, and a conditional
XOR — no addition, no multiplication, no carry anywhere. Each bit of the new
state is a fixed exclusive-or of old bits. That is why MT19937 sails through
most statistical batteries and still fails the ones that look for linear
structure, and why enough observed output lets you solve for the state with
linear algebra rather than search.

## Why this is one step and not 624

Each step reads **three** words — \`mt[i]\`, \`mt[i+1]\` and \`mt[i+397]\` — and
a loop body in this app can only see its own block. Nor is the loop secretly
parallel: the update happens **in place**, so from \`i = 227\` onward the
\`mt[i+397]\` term wraps around and reads a word this very loop already
rewrote. Treating the twist as one wide operation over shifted copies of the
array gives a different generator that merely looks similar.

## It happens again every 624 words

The real generator refills whenever its words are used up. This app keeps you
inside the first batch, so this is the only twist this run performs — ask for
more than ${MT_MAX_OUTPUT_BYTES} bytes and the app says so rather than quietly
showing you a stream with a refill missing.`,
  references: ["Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §2–3", "mt19937ar.c"],
};

const narrWords = (outputLength: number): StepDocumentation => {
  const wordCount = Math.ceil(outputLength / MT_WORD_BYTES);
  return {
    name: `Take the first ${wordCount} state words`,
    summary: "Selects the words that will be handed out, rounded up to a whole word.",
    detail: `## Selecting from a state that is already finished

The twist produced all ${MT_N} words. You asked for ${outputLength} bytes, which
is ${wordCount} word${wordCount === 1 ? "" : "s"}, so this step takes the first
${wordCount * MT_WORD_BYTES} bytes of the state and leaves the rest untouched.

**Rounded UP, deliberately.** ${
      outputLength % MT_WORD_BYTES === 0
        ? `${outputLength} happens to be a whole number of words, so nothing is rounded here today. Ask for a length that is not a multiple of 4 and this step will still take a whole word, with the surplus trimmed after the loop.`
        : `${outputLength} is not a multiple of 4, so this takes ${wordCount * MT_WORD_BYTES} bytes — one word more than you asked for. Tempering operates on whole 32-bit words, so the final word has to arrive intact; the surplus is cut off after the loop instead.`
    }

That is the one structural difference from the stream ciphers in this app. They
trim *inside* the loop, because each pass knows how much of its own block is
wanted. Here the loop's passes are all identical whole words, and the shortness
belongs to the request rather than to any block — so the trim waits until the
end.`,
    references: [],
  };
};

const narrShift = (bits: number, direction: "right" | "left"): StepDocumentation => ({
  name: `y ${direction === "right" ? ">>" : "<<"} ${bits}`,
  summary: `Shifts the word ${direction} by ${bits} positions, dropping the bits that fall off.`,
  detail: `## A shift, not a rotation

\`\`\`
y ${direction === "right" ? ">>" : "<<"} ${bits}
\`\`\`

The bits pushed off the ${direction === "right" ? "bottom" : "top"} are **lost**
and the ${direction === "right" ? "top" : "bottom"} zero-fills. A rotation would
have wrapped them around instead, and that is a different operation.

${
  direction === "left"
    ? `**Worth knowing, because it looks like a distinction without a difference
here.** This shifted value is about to be masked, and the mask's low bits are
zero — precisely the positions a rotation would have wrapped into. So for
MT19937's published constants a rotation would give an identical answer. That is
a coincidence of these particular constants, not a property of the algorithm:
edit the mask below to keep a low bit and the two stop agreeing immediately.`
    : `Tempering's two right shifts need no mask: on the way down, the bits that
matter are already in place.`
}`,
  references: ["Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §3"],
});

const narrMask = (value: number, which: "b" | "c"): StepDocumentation => ({
  name: `Mask ${hex32(value)}`,
  summary: "One of the two tempering constants — the bits allowed through after the left shift.",
  detail: `## ${hex32(value)}

The ${which === "b" ? "first" : "second"} of tempering's two magic constants
(the paper calls ${which === "b" ? "it `b`" : "it `c`"}). It selects which bits
of the shifted word are allowed to affect the result.

**These constants are chosen, not arbitrary.** Tempering exists because the raw
twist output is *equidistributed* only in a weak sense — its bits are not
uniformly mixed across the word. Matsumoto and Nishimura searched for shift
amounts and masks giving 623-dimensional equidistribution to 32-bit accuracy,
which is the property the generator's name advertises and the reason it beats
its contemporaries on statistical tests.

**And it is editable.** Change it and watch: the stream stays superficially
random-looking, because tempering is a bijection for *any* mask — every distinct
state still maps to a distinct output. What you break is the distribution, and
that is precisely the kind of damage no casual inspection reveals.

**A curiosity worth trying.** The low ${which === "b" ? "7" : "15"} bits of this
constant are zero, and the shift above is a left shift by ${
    which === "b" ? MT_TEMPER_S : MT_TEMPER_T
  }
— so those bits can never be reached anyway. Setting them changes nothing at
all. That is why a *rotation* would work equally well here, and why it would
stop working the moment you set one of them.`,
  references: ["Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §3 and Table II"],
});

const narrXor = (step: 1 | 2 | 3 | 4): StepDocumentation => {
  const lines = [
    "y ^= y >> 11",
    "y ^= (y << 7) & 0x9d2c5680",
    "y ^= (y << 15) & 0xefc60000",
    "y ^= y >> 18",
  ];
  return {
    name: lines[step - 1] as string,
    summary: `Tempering step ${step} of 4 — folds the shifted copy back into the word.`,
    detail: `## Tempering, step ${step} of 4

\`\`\`
${lines.map((l, i) => (i === step - 1 ? `${l}      ← this step` : l)).join("\n")}
\`\`\`

Tempering is the generator's **output function**: the state word never leaves
the machine unaltered, it leaves through this. Its job is distribution, not
secrecy — it fixes the twist's weak equidistribution and nothing else.

${
  step === 4
    ? `## This is the step that makes MT19937 predictable

Not this step specifically — all four, and the fact that each one is
**invertible**. \`y ^= y >> 18\` can be undone by anyone who knows the rule,
because the top 18 bits pass through untouched and the rest can be recovered
from them. The same is true of the other three.

So the four together are a **bijection**, and undoing them turns an emitted word
back into the exact internal state word it came from. Collect 624 consecutive
outputs, undo the tempering on each, and you have reconstructed the entire
internal state — from which every future output follows by running the twist,
and every past one by running it backwards.

**No search, no statistics, no knowledge of the seed.** That is the difference
between this generator and the ChaCha20 CSPRNG in the same menu: the CSPRNG's
output function is a one-way permutation over a state you never see. Both pass
the statistical tests. Only one is unpredictable — and *that* is the property
that matters when randomness is protecting something.`
    : ""
}`,
    references: ["Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §3"],
  };
};

const narrEmit = (outputLength: number): StepDocumentation => {
  const remainder = outputLength % MT_WORD_BYTES;
  return {
    name: "Cut to the requested length",
    summary:
      remainder === 0
        ? "Passes the tempered words through — the request was a whole number of words."
        : `Trims the last word to ${remainder} byte${remainder === 1 ? "" : "s"}.`,
    detail: `## The ragged tail

${
  remainder === 0
    ? `${outputLength} bytes is exactly ${outputLength / MT_WORD_BYTES} words, so
nothing is trimmed today and this step is a passthrough. Ask for a length that is
not a multiple of 4 and it will start cutting.`
    : `${outputLength} is not a multiple of 4, so the loop above produced
${Math.ceil(outputLength / MT_WORD_BYTES) * MT_WORD_BYTES} bytes for
${outputLength} bytes of output. This step cuts the surplus, so the stream ends
exactly where you asked.`
}

**Why this sits outside the loop.** Every other generator and stream mode in
this app trims *inside* its loop, matching each pass's output to the width of
the block that pass was handed. That works because those loops are fed the
message, whose last block really is short. Here the loop is fed the generator's
own state, and every word of it is a full 4 bytes — the shortness is a property
of your request, not of any block. So the cut happens once, at the end, where
the request actually lives.`,
    references: [],
  };
};

// ─── The spec ─────────────────────────────────────────────────────────────

/**
 * Build an MT19937 spec producing `outputLength` bytes.
 *
 * @param outputLength bytes of output requested; any integer in
 *                     `[1, MT_MAX_OUTPUT_BYTES]`, and deliberately need not be
 *                     a multiple of the 4-byte word
 * @throws if the request would need a second twist — see the file header
 */
export const buildMt19937Spec = (outputLength: number): CipherSpec => {
  if (!Number.isInteger(outputLength) || outputLength < 1) {
    throw new Error(`mt19937: output length must be a positive integer, got ${outputLength}`);
  }
  if (outputLength > MT_MAX_OUTPUT_BYTES) {
    // Refused rather than silently wrong: past 624 words the real generator
    // twists again, and this spec contains exactly one twist.
    throw new Error(
      `mt19937: output length ${outputLength} exceeds one twist's ${MT_MAX_OUTPUT_BYTES} bytes (${MT_N} words); a longer stream would need a second twist, which this spec does not contain`,
    );
  }

  const wordCount = Math.ceil(outputLength / MT_WORD_BYTES);
  const sliceBytes = wordCount * MT_WORD_BYTES;

  // The twelve tempering leaves, in the order the paper writes them. `y1`…`y4`
  // are the four successive values of `y`; everything else feeds one of them.
  const temperBody: StepNode[] = [
    {
      kind: "step",
      id: MT_SHIFT_U_ID,
      type: "shift-bits-right@1",
      params: { bits: MT_TEMPER_U, wordBits: 32 },
      portInputs: { input: port(MT_TEMPER_ID, "in") },
      narrationOverride: narrShift(MT_TEMPER_U, "right"),
    },
    {
      kind: "step",
      id: MT_Y1_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_TEMPER_ID, "in"),
        operand1: port(MT_SHIFT_U_ID, "output"),
      },
      narrationOverride: narrXor(1),
    },
    {
      kind: "step",
      id: MT_MASK_B_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(MT_TEMPER_B) },
      narrationOverride: narrMask(MT_TEMPER_B, "b"),
    },
    {
      kind: "step",
      id: MT_SHIFT_S_ID,
      type: "shift-bits-left@1",
      params: { bits: MT_TEMPER_S, wordBits: 32 },
      portInputs: { input: port(MT_Y1_ID, "output") },
      narrationOverride: narrShift(MT_TEMPER_S, "left"),
    },
    {
      kind: "step",
      id: MT_AND_B_ID,
      type: "and@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_SHIFT_S_ID, "output"),
        operand1: port(MT_MASK_B_ID, "output"),
      },
    },
    {
      kind: "step",
      id: MT_Y2_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_Y1_ID, "output"),
        operand1: port(MT_AND_B_ID, "output"),
      },
      narrationOverride: narrXor(2),
    },
    {
      kind: "step",
      id: MT_MASK_C_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(MT_TEMPER_C) },
      narrationOverride: narrMask(MT_TEMPER_C, "c"),
    },
    {
      kind: "step",
      id: MT_SHIFT_T_ID,
      type: "shift-bits-left@1",
      params: { bits: MT_TEMPER_T, wordBits: 32 },
      portInputs: { input: port(MT_Y2_ID, "output") },
      narrationOverride: narrShift(MT_TEMPER_T, "left"),
    },
    {
      kind: "step",
      id: MT_AND_C_ID,
      type: "and@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_SHIFT_T_ID, "output"),
        operand1: port(MT_MASK_C_ID, "output"),
      },
    },
    {
      kind: "step",
      id: MT_Y3_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_Y2_ID, "output"),
        operand1: port(MT_AND_C_ID, "output"),
      },
      narrationOverride: narrXor(3),
    },
    {
      kind: "step",
      id: MT_SHIFT_L_ID,
      type: "shift-bits-right@1",
      params: { bits: MT_TEMPER_L, wordBits: 32 },
      portInputs: { input: port(MT_Y3_ID, "output") },
      narrationOverride: narrShift(MT_TEMPER_L, "right"),
    },
    {
      kind: "step",
      id: MT_Y4_ID,
      type: "xor@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: port(MT_Y3_ID, "output"),
        operand1: port(MT_SHIFT_L_ID, "output"),
      },
      narrationOverride: narrXor(4),
    },
  ];

  return {
    id: "mt19937@1",
    name: DISPLAY_NAME,
    stateShape: "bytes",
    inputs: {
      // The seed is the generator's only input. Generators are keyless in the
      // symmetric sense, so the key field is zero-width and the UI hides it —
      // the posture the hash, RSA and LCG families all take.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    steps: [
      {
        kind: "step",
        id: MT_SEED_ID,
        type: "mt19937.seed@1",
        params: {},
        portInputs: { input: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT) },
        narrationOverride: narrSeed,
      },
      {
        kind: "step",
        id: MT_TWIST_ID,
        type: "mt19937.twist@1",
        params: {},
        portInputs: { input: port(MT_SEED_ID, "output") },
        narrationOverride: narrTwist,
      },
      {
        kind: "step",
        id: MT_REQUEST_ID,
        type: "zero-fill@1",
        params: { byteLength: outputLength },
        narrationOverride: narrRequest(outputLength),
      },
      {
        // Round UP to a whole number of words: tempering needs intact 32-bit
        // words, so the surplus is cut after the loop instead of before it.
        kind: "step",
        id: MT_WORDS_ID,
        type: "byte-slice@1",
        params: { sourceByteLength: MT_STATE_BYTES, offset: 0, length: sliceBytes },
        portInputs: { input: port(MT_TWIST_ID, "output") },
        narrationOverride: narrWords(outputLength),
      },
      {
        kind: "iterate",
        id: MT_TEMPER_ID,
        label: `${DISPLAY_NAME} — temper ${wordCount} word${wordCount === 1 ? "" : "s"}`,
        // The state itself drives the loop: each pass is handed one word of it.
        seedInput: port(MT_WORDS_ID, "output"),
        blockByteLength: MT_WORD_BYTES,
        // NO chainInput and NO chainFeedback. Tempering is a pure map over the
        // state array — word i depends on word i and nothing else. This is the
        // app's only carry-free port-mode iterate; read the file header before
        // adding one.
        bodyOutput: port(MT_Y4_ID, "output"),
        outputPorts: ["out"],
        children: temperBody,
      },
      {
        // The trim, OUTSIDE the loop — see the file header for why it cannot
        // live inside it as every other trim in this app does.
        kind: "step",
        id: MT_EMIT_ID,
        type: "truncate-to-reference@1",
        params: {},
        portInputs: {
          input: port(MT_TEMPER_ID, "out"),
          reference: port(MT_REQUEST_ID, "output"),
        },
        narrationOverride: narrEmit(outputLength),
      },
    ],
    outputFrom: port(MT_EMIT_ID, "output"),
  };
};

/**
 * Read the requested output length back out of a built MT19937 spec.
 *
 * The family-wide reader — it keys on the request leaf's id, which every
 * generator carries. Named here so MT call sites read in their own vocabulary.
 */
export const readMt19937OutputLength = readPrngOutputLength;
