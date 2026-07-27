/**
 * Linear congruential generators — the app's pseudo-random generators.
 * `docs/plans/iterative-dancing-ocean.md` Phases P1 (MINSTD) and P2 (ANSI C).
 *
 * ## The whole algorithm
 *
 * ```
 * x_{i+1} = (a · x_i + c) mod m
 * ```
 *
 * That is it. There is no key schedule, no round function, no S-box — one
 * multiply, one add, one remainder, repeated. Three variants ship, and all three
 * have their constants fixed by an ISO document, which is unusual enough to be
 * worth saying out loud:
 *
 * | variant        | a          | c     | m      | provenance |
 * |----------------|-----------:|------:|--------|------------|
 * | `minstd-rand0` | 16807      | 0     | 2³¹−1  | Lehmer 1951; Park & Miller's 1988 "minimal standard". ISO/IEC 14882 §rand.predef |
 * | `minstd-rand`  | 48271      | 0     | 2³¹−1  | Park, Miller & Stockmeyer 1993, better spectral behaviour. Same clause |
 * | `ansi-c-lcg`   | 1103515245 | 12345 | 2³¹    | The sample `rand()` in ISO/IEC 9899 §7.22.2.2; POSIX `rand_r` |
 *
 * **`c = 0` is a form, not just a value.** The two MINSTD variants are
 * *multiplicative* generators: they have no addition step at all, and
 * `buildLcgSpec` omits both the increment constant and the `add-mod@1` leaf for
 * them. The ANSI C variant is *mixed* (affine). One leaf is the entire
 * structural difference between the two families.
 *
 * **The ANSI C variant is deliberately not called "glibc `rand()`".** glibc's
 * default is a TYPE_3 additive-feedback generator producing a completely
 * different stream; only its `rand_r` is this recurrence. Naming it after glibc
 * would be a lie a learner would eventually catch.
 *
 * ## Why generators this weak are the most valuable objects in the app
 *
 * Every cipher here consumes randomness it does not produce, and the question
 * "where did those bytes come from" has ended more real cryptosystems than any
 * weakness in a round function. An LCG is the shortest honest answer to "what
 * does a generator actually do", and — critically — it is weak in ways a learner
 * can *watch* rather than take on faith.
 *
 * The multiplier, the modulus, and (in the mixed form) the increment are
 * ordinary `constant-load@1` params. Edit them in place and the trace re-runs.
 * Experiments worth doing, all visible within a handful of frames:
 *
 *  - **Read the last byte of consecutive ANSI C words.** Odd, even, odd, even —
 *    bit 0 has period 2, bit 1 has period 4, and so on up. With a power-of-two
 *    modulus a carry can only travel upward, so the low bits form their own tiny
 *    generator. This is why real code never takes an LCG's low bits, and why C's
 *    own `rand()` discards the bottom 16 before returning a number.
 *  - **Set the ANSI C modulus to `7fffffff`** — MINSTD's prime — and watch that
 *    alternation vanish.
 *  - **Set the multiplier to an even number.** With a prime modulus this wrecks
 *    the period; with a power-of-two modulus it kills the low bits outright,
 *    because a factor of 2 in `a` can never be undone by a modulus that is
 *    itself a power of 2.
 *  - **Set the seed to 0.** `0` is a fixed point of `x ← a·x mod m`: MINSTD
 *    emits zeros forever. The mixed form does not — `0 → c` — which is one of
 *    the two things the increment buys.
 *
 * ## Structure of the spec
 *
 * ```
 *   $input (the seed)  ──────────────────────────┐
 *   request  zero-fill@1 { byteLength: N }       │  (its WIDTH sets the count)
 *      │                                         │
 *      └─► iterate "words"  blockByteLength 4  ◄──┘ chainInput = seed
 *              mult   constant-load@1  a         ← editable
 *              incr   constant-load@1  c         ← editable   (MIXED FORM ONLY)
 *              modu   constant-load@1  m         ← editable
 *              prod   mod-mul@1 (chain · mult mod modu)       (MIXED FORM ONLY)
 *              state  add-mod@1 (prod + incr mod modu)
 *                     …or, multiplicative form: state IS the mod-mul above
 *              emit   truncate-to-reference@1 (state, ref = this block's width)
 *          chainFeedback = state.output   (UNTRIMMED — see below)
 *          bodyOutput    = emit.output    (TRIMMED)
 * ```
 *
 * `LCG_STATE_ID` always names whichever node produces the next state, so the
 * `chainFeedback` and `emit` wirings are identical across both forms.
 *
 * **The one wire that matters: `chainFeedback` reads the UNTRIMMED state.**
 *
 * A generator has no message, so nothing in the spec says how many words to
 * produce — `zero-fill@1`'s width does, and the iterate divides it by 4. When
 * the requested length is not a multiple of 4 the final iteration gets a short
 * block, and `emit` trims that word so the stream comes out at exactly the
 * length asked for. The recurrence, however, is defined on whole 32-bit words:
 * feeding a truncated value back would corrupt the state.
 *
 * So the two bindings deliberately read different nodes — `chainFeedback` takes
 * `state` (always 4 bytes), `bodyOutput` takes `emit` (short on the last pass).
 *
 * **Be precise about what that buys.** Only the FINAL block is ever short, and
 * the final iteration's feedback is discarded — so binding `chainFeedback` to
 * the trimmed `emit` would be byte-indistinguishable at every output length.
 * This is exactly OFB's situation, recorded in `CLAUDE.md` as "deliberately the
 * UNTRIMMED `keystream.output`, not `ofb-trim.output` — byte-indistinguishable
 * … but the recurrence is defined on whole blocks and the trace should say so."
 * The wiring here is chosen for the same reason: it is what the recurrence
 * means, and a learner reading the graph should see the state advance whole.
 * `tests/lcg-kat.test.ts` PERTURBS the binding and asserts the outputs match,
 * so the claim of indistinguishability is measured rather than assumed — and so
 * that a future topology in which it *does* matter (a generator whose every
 * block can be short) fails loudly instead of silently.
 *
 * ## Verification
 *
 * The oracle is standards-track. ISO/IEC 14882 (C++) §rand.predef requires that
 * the 10000th consecutive invocation of a default-constructed generator (seed 1)
 * produces:
 *
 *  - `std::minstd_rand0` (a = 16807) → **1043618065**
 *  - `std::minstd_rand`  (a = 48271) → **399268537**
 *
 * Both are pinned in `tests/lcg-kat.test.ts`. Note that at 4 bytes per word,
 * reaching the 10000th value through the traced runtime would mean a 40 KB
 * request and ~10,000 iterations of frames — so the test drives the *executors*
 * for the long run and the full runtime for short ones, asserting the two agree.
 *
 * The ANSI C variant has no conformance clause, so it is pinned two ways: its
 * opening states from seed 1 (`1103527590, 377401575, 662824084, …`) and the
 * numbers C's `rand()` derives from them (`16838, 5758, 10113, 17515, 31051`),
 * which are the most widely republished fingerprint of that generator.
 *
 * **This app emits the raw 32-bit STATE, where C's `rand()` returns
 * `(state / 65536) % 32768`.** That is deliberate: the top-15-bit extraction is
 * C's *workaround* for the low-bit weakness, so performing it here would conceal
 * the one defect the variant exists to demonstrate. The `emit` narration says so
 * on screen, with both number sequences, so the discrepancy reads as the lesson
 * rather than as a bug.
 *
 * **Seeding convention, written down deliberately.** `x_0` is the seed exactly
 * as supplied, with no scrambling, no `init_by_array`, no discard of leading
 * outputs; the first emitted word is `(a · seed + c) mod m`. Every conformance
 * value above is under seed = 1 — which is also what C guarantees an unseeded
 * `rand()` behaves as (`srand(1)`). Recording this matters more than it looks:
 * PRNGs differ from each other mainly in how they *seed*, and a mismatched
 * convention produces a stream that is perfectly self-consistent and matches
 * nothing else in the world — the same failure class as ChaCha20's counter
 * starting at 1 while Salsa20's starts at 0.
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";

// ─── Variants ─────────────────────────────────────────────────────────────

/**
 * The three generators this builder produces. Two multiplicative (MINSTD, the
 * multipliers the C++ standard names) and one mixed (the C standard's sample
 * `rand`). They differ in three numbers and nothing else, which is the reason
 * they share a builder rather than a family resemblance.
 */
export type LcgVariant = "minstd-rand0" | "minstd-rand" | "ansi-c-lcg";

/** m = 2³¹ − 1 = 2147483647, a Mersenne prime. Shared by both MINSTD variants:
 *  it is the modulus's primality that makes the period the full m − 1. */
export const MINSTD_MODULUS = 0x7fffffff;

/** m = 2³¹ = 2147483648 for the ANSI C sample generator — a power of two, and
 *  the source of every one of that generator's problems. */
export const ANSI_C_MODULUS = 0x80000000;

/**
 * The complete definition of each variant: `x ← (a·x + c) mod m`.
 *
 * `c === 0` is not merely a value — it is the **form**. A multiplicative
 * generator (c = 0) needs no addition step at all, so `buildLcgSpec` omits both
 * the increment constant and the `add-mod@1` leaf for those variants, and the
 * trace shows a strictly shorter loop. The two forms are genuinely different
 * algorithms sharing a template, not one algorithm with a zero in it.
 */
export type LcgParams = {
  /** multiplier */ readonly a: number;
  /** increment; 0 means the multiplicative form */ readonly c: number;
  /** modulus */ readonly m: number;
};

export const LCG_PARAMS: Record<LcgVariant, LcgParams> = {
  // Lehmer 1951 / Park–Miller 1988
  "minstd-rand0": { a: 16807, c: 0, m: MINSTD_MODULUS },
  // Park–Miller–Stockmeyer 1993
  "minstd-rand": { a: 48271, c: 0, m: MINSTD_MODULUS },
  // ISO/IEC 9899 §7.22.2.2's sample rand()/srand(), and POSIX's rand_r.
  // Deliberately NOT labelled "glibc rand()": glibc's default is a TYPE_3
  // additive-feedback generator and produces an entirely different stream.
  "ansi-c-lcg": { a: 1103515245, c: 12345, m: ANSI_C_MODULUS },
};

/** True for the mixed (affine) form — the variants that carry a "+ c".
 *  `buildLcgSpec` routes through this rather than testing `c !== 0` inline, so
 *  there is exactly one place that decides which form a variant is. */
export const isMixedLcg = (variant: LcgVariant): boolean => LCG_PARAMS[variant].c !== 0;

/** The generator's word width in bytes. Every modulus here fits in 32 bits, so
 *  every state value and every emitted word is 4 bytes big-endian. */
export const LCG_WORD_BYTES = 4;

/** Seed width — one word. */
export const LCG_SEED_BYTES = LCG_WORD_BYTES;

const DISPLAY_NAME: Record<LcgVariant, string> = {
  "minstd-rand0": "MINSTD (minstd_rand0)",
  "minstd-rand": "MINSTD (minstd_rand)",
  "ansi-c-lcg": "ANSI C LCG (rand_r)",
};

// ─── Node ids ─────────────────────────────────────────────────────────────
//
// Exported because both the KAT and `readLcgOutputLength` address nodes by id,
// and a silent rename would break them in ways a type checker cannot see.
//
// `LCG_STATE_ID` always names **the node whose output is the next state** — the
// `mod-mul@1` in the multiplicative form, the `add-mod@1` in the mixed one. That
// invariant is what lets `chainFeedback` bind to one id for both forms.

export const LCG_REQUEST_ID = "request";
export const LCG_ITERATE_ID = "words";
export const LCG_MULTIPLIER_ID = "mult";
export const LCG_INCREMENT_ID = "incr";
export const LCG_MODULUS_ID = "modu";
/** The mixed form's `mod-mul@1`, whose product then gets `+ c` added. Unused by
 *  the multiplicative form, where the multiply IS the state node. */
export const LCG_PRODUCT_ID = "prod";
export const LCG_STATE_ID = "state";
export const LCG_EMIT_ID = "emit";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Encode a non-negative integer as `LCG_WORD_BYTES` big-endian bytes, as a
 *  plain number array (the shape `constant-load@1`'s `bytes` param wants). */
const wordBytes = (value: number): number[] => [
  (value >>> 24) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 8) & 0xff,
  value & 0xff,
];

/**
 * The opening states of the ANSI C generator from seed 1, and the numbers C's
 * `rand()` derives from them. Quoted in the narration below because they are
 * the values a learner will find everywhere the sample generator is discussed,
 * and because the app emits the STATES — see `narrEmitAnsiC` on why.
 */
const ANSI_C_OPENING_STATES = "1103527590, 377401575, 662824084, 1147902781, 2035015474";
const ANSI_C_OPENING_RANDS = "16838, 5758, 10113, 17515, 31051";

// ─── Narration ────────────────────────────────────────────────────────────

const narrRequest = (outputLength: number): StepDocumentation => ({
  name: `Request ${outputLength} bytes`,
  summary: "How much output you asked for — and therefore how many times the generator runs.",
  detail: `## Nothing here says "how much" except you

A cipher learns how much work to do from its message. A generator has no
message: the seed picks *which* sequence, never *how much of it*. So the
requested length has to enter the spec on its own, and this is where it does.

The loop below divides this width by the 4-byte word size:

\`\`\`
words = ceil(${outputLength} / 4) = ${Math.ceil(outputLength / LCG_WORD_BYTES)}
\`\`\`

Each pass is handed its own 4-byte slice of these zeros and **ignores it
completely** — a generator builds its next value from its own state and nothing
else. The single exception is the last slice when the length does not divide
evenly: its width is read, so the final word can be trimmed and you get back
exactly the number of bytes you asked for.`,
  references: [],
});

// Each narrator below is split MINSTD / ANSI-C rather than woven into one
// text with conditionals. Two reasons, in order of importance: the prose says
// genuinely different things about a prime and a power-of-two modulus, and
// keeping the MINSTD strings physically untouched is what makes the shipped
// MINSTD spec byte-identical across this generalization — which
// `tests/lcg-kat.test.ts` pins by hash, because spec-only saves are byte-stable
// and a drifted string silently changes every shared URL.

const narrMultiplierMinstd = (variant: LcgVariant): StepDocumentation => {
  const a = LCG_PARAMS[variant].a;
  return {
    name: `Multiplier a = ${a}`,
    summary:
      "The constant every state is multiplied by. This one number is essentially the whole generator.",
    detail: `## a = ${a}

${
  variant === "minstd-rand0"
    ? `Lehmer's original 1951 multiplier, which Park and Miller proposed in 1988 as a
"minimal standard" — a baseline any generator ought to at least match.`
    : `Park, Miller and Stockmeyer's 1993 revision. Same modulus, same structure,
different constant: 48271 scores better on the spectral test, which measures how
badly consecutive outputs fall onto a small number of parallel planes.`
}

**This is the parameter to experiment with.** The modulus is prime, so the
period is the full m − 1 = 2147483646 only when \`a\` is a *primitive root*
modulo m. Most numbers are not. Try:

- \`a = 1\` — every output equals the seed. The generator stops generating.
- an even value, or a small one like 2 or 3 — the sequence becomes visibly
  structured within the first few words, long before any statistical test would
  be needed to notice.

That a single badly-chosen constant reduces this to a counter, with no error and
no warning, is the reason generator constants are published and audited rather
than invented.`,
    references: [
      "Lehmer, D. H. (1951), 'Mathematical methods in large-scale computing units'",
      "Park & Miller (1988), 'Random number generators: good ones are hard to find', CACM 31(10)",
      "ISO/IEC 14882 §rand.predef (std::minstd_rand0 / std::minstd_rand)",
    ],
  };
};

const narrMultiplierAnsiC: StepDocumentation = {
  name: "Multiplier a = 1103515245",
  summary:
    "The constant every state is multiplied by — chosen, with the increment, so the generator's period is the full 2³¹.",
  detail: `## a = 1103515245

Published in the ANSI C standard's sample \`rand()\` and carried into POSIX's
\`rand_r\`. It is not arbitrary: with a power-of-two modulus, the Hull–Dobell
theorem says the period is the full m exactly when the increment \`c\` is odd,
\`a − 1\` is divisible by every prime factor of m, and — since m is divisible by
4 — by 4 as well.

Check it: a − 1 = 1103515244 = 4 × 275878811, and m's only prime factor is 2. So
the conditions hold, and this generator does visit all 2147483648 states before
repeating.

**And a full period is worth much less than it sounds.** Every value appears
exactly once per cycle, and the sequence is still catastrophically structured —
watch the last byte of consecutive outputs. Period length is the weakest useful
property a generator can have.

**Things to try.** Break a Hull–Dobell condition and see how fast it shows:

- \`a = 1103515246\` (a − 1 no longer divisible by 4) — the period collapses.
- \`a = 1\` — the generator becomes a counter stepping by \`c\`.
- an even \`a\` — with a power-of-two modulus this is the classic disaster: the
  low bits die completely, because a factor of 2 in \`a\` can never be undone by
  a modulus that is itself a power of 2.`,
  references: [
    "ISO/IEC 9899 §7.22.2.2 — the standard's sample rand()/srand()",
    "Hull & Dobell (1962), 'Random number generators', SIAM Review 4(3)",
    "Knuth, TAOCP Vol. 2 §3.2.1.2 — choice of modulus and multiplier",
  ],
};

const narrIncrement: StepDocumentation = {
  name: "Increment c = 12345",
  summary:
    "The constant added after the multiply. Its presence is what makes this a 'mixed' generator rather than a 'multiplicative' one.",
  detail: `## c = 12345

MINSTD has no such step — it computes \`a·x mod m\` and stops. Adding a constant
turns the *multiplicative* form into the **mixed** (or affine) form, and buys two
concrete things with one addition:

- **Zero stops being a fixed point.** In MINSTD, seed 0 emits zeros forever.
  Here, \`0 → c\`, and the sequence carries on normally. Try it: set the seed to
  \`00000000\` under both generators.
- **The full period becomes reachable.** A multiplicative generator can never
  visit 0, so it tops out at m − 1 states. A mixed one can visit all m — but only
  when \`c\` is **odd** (a Hull–Dobell condition). 12345 is odd.

**Set \`c\` to an even number** — 12344, or 0 — and the period drops immediately,
with nothing to announce it. That an off-by-one in a constant silently halves or
worse the period, while the output still looks like noise, is why these constants
are published rather than chosen at the keyboard.`,
  references: ["Hull & Dobell (1962), SIAM Review 4(3)", "Knuth, TAOCP Vol. 2 §3.2.1.2"],
};

const narrModulusMinstd: StepDocumentation = {
  name: "Modulus m = 2³¹ − 1",
  summary:
    "2147483647 — a Mersenne prime. Its primality is what makes a full-length period possible.",
  detail: `## m = 2³¹ − 1 = 2147483647

A **Mersenne prime**, and the choice is not incidental.

Because m is prime, the non-zero values mod m form a group under multiplication,
so repeatedly multiplying by a well-chosen \`a\` cycles through *every* one of
them before returning to the start — a period of m − 1 = 2147483646.

Had m been a power of two instead (as in the ANSI-C generator), the arithmetic
would be cheaper — a bitmask rather than a division — but the low bits would
carry almost no randomness: bit 0 of a power-of-two LCG alternates with period 2,
bit 1 with period 4, and so on. That difference between a prime and a
power-of-two modulus is the single most consequential design choice in this
family.

**0 is a fixed point.** It is the one value outside the group: \`a · 0 mod m\`
is 0 forever. Set the seed to zero and watch.`,
  references: ["Park & Miller (1988), CACM 31(10)"],
};

const narrModulusAnsiC: StepDocumentation = {
  name: "Modulus m = 2³¹",
  summary:
    "2147483648 — a power of two. Cheap to reduce, and the reason this generator's low bits are worthless.",
  detail: `## m = 2³¹ = 2147483648

Compare MINSTD's 2³¹ − 1. One less, and an entirely different generator.

A power-of-two modulus is chosen because it is **free**: reducing mod 2³¹ is
discarding the bits above position 31, which on real hardware is not an operation
at all. A division by 2147483647 is.

## What that costs

Reducing mod 2³¹ leaves bit *k* of the state depending only on bits 0…k of what
came before — the higher bits can never influence the lower ones, because carries
only travel upward. So the low bits form their own tiny generator, running mod
2^(k+1):

| bit | period |
|---|---|
| 0 | 2 |
| 1 | 4 |
| 2 | 8 |
| … | … |

**Bit 0 simply alternates.** Look at the last byte of consecutive outputs in the
trace: odd, even, odd, even, forever. That is not a subtle statistical defect you
would need a test suite to find — it is visible in the first four words.

This is why the C standard's sample \`rand()\` returns
\`(state / 65536) % 32768\` rather than the state: it throws away the bottom 16
bits, the ones it knows are bad. And it is why "\`rand() % 2\` for a coin flip"
was, for a generation of programs, a coin that always landed alternately.

**Try it.** Set this constant to \`7fffffff\` — MINSTD's prime — and watch the
alternation in the last byte disappear.`,
  references: [
    "ISO/IEC 9899 §7.22.2.2",
    "Knuth, TAOCP Vol. 2 §3.2.1.1 — the modulus",
    "Park & Miller (1988), CACM 31(10)",
  ],
};

const narrStateMinstd = (variant: LcgVariant): StepDocumentation => ({
  name: "x ← a · x mod m",
  summary: `The entire generator: multiply the current state by ${LCG_PARAMS[variant].a}, take the remainder mod 2³¹ − 1.`,
  detail: `## The recurrence

\`\`\`
x_{i+1} = ${LCG_PARAMS[variant].a} · x_i mod 2147483647
\`\`\`

One multiply, one remainder. This single step is the complete algorithm — there
is no round function, no key schedule, and nothing else in this loop does any
work.

The value arriving on \`chain\` is the previous state (the seed itself on the
first pass); the value leaving is both the next state **and** this pass's
output. That the internal state *is* the output is precisely what makes this
generator unusable where randomness must be unpredictable: anyone who sees one
output knows the entire future of the sequence, and — since multiplication mod a
prime is invertible — its entire past as well.

## Why the product is taken in full precision

\`${LCG_PARAMS[variant].a} · x\` overflows 32 bits for almost every state. This
step computes the exact product before reducing, so no bits are lost. Doing it
the other way round — letting the product wrap and then reducing — silently
produces a different, much worse sequence, and is a classic implementation bug in
this family.`,
  references: ["ISO/IEC 14882 §rand.predef"],
});

/** The mixed form's `mod-mul@1` — a·x, before the "+ c". Not the state. */
const narrProductAnsiC: StepDocumentation = {
  name: "a · x mod m",
  summary: "Multiplies the current state by 1103515245 and reduces. The increment is added next.",
  detail: `## Half of the recurrence

\`\`\`
x_{i+1} = (1103515245 · x_i + 12345) mod 2147483648
           └──────── this step ────┘
\`\`\`

The value arriving on \`chain\` is the previous state — the seed itself on the
first pass. This step produces the product; the \`+ 12345\` happens in the next
one, and *that* is what becomes the new state.

Splitting them across two frames is deliberate: it is exactly where this
generator differs from MINSTD, and the difference should be a step you can point
at rather than a term hidden inside one.

## Why the product is taken in full precision

\`1103515245 · x\` overflows 32 bits for almost every state. This step computes
the exact product before reducing, so nothing is lost. Letting the product wrap
first and reducing after produces a different, worse sequence — a classic
implementation bug in this family, and one that still passes casual inspection
because the output looks equally random either way.`,
  references: ["ISO/IEC 9899 §7.22.2.2"],
};

const narrStateAnsiC: StepDocumentation = {
  name: "x ← (a·x + c) mod m",
  summary:
    "Adds the increment to the product and reduces. This value is both the next state and this pass's output.",
  detail: `## The state advances

\`\`\`
x_{i+1} = (1103515245 · x_i + 12345) mod 2147483648
\`\`\`

The product arrives from the step above; adding \`c\` here completes the
recurrence. From seed 1 the states run:

\`\`\`
${ANSI_C_OPENING_STATES}, …
\`\`\`

## The state is the output — and it should not be

Anyone who sees one output knows the whole sequence forwards, and — because the
map is invertible — backwards too. Every generator in this family shares that,
which is what separates them from a CSPRNG regardless of how good their
statistical properties are.

Here it is worse than in MINSTD, because a power-of-two modulus makes even a
*partial* observation enough: the low bits are their own self-contained
generator, so seeing only the bottom byte of a few outputs is enough to predict
the bottom byte of the next.`,
  references: ["ISO/IEC 9899 §7.22.2.2", "Hull & Dobell (1962), SIAM Review 4(3)"],
};

const narrEmitMinstd = (outputLength: number): StepDocumentation => {
  const remainder = outputLength % LCG_WORD_BYTES;
  return {
    name: "Emit the word",
    summary:
      remainder === 0
        ? "Passes the 4-byte state through as this pass's output."
        : `Passes the state through, trimming the final word to ${remainder} byte${remainder === 1 ? "" : "s"}.`,
    detail: `## Output = state

An MINSTD generator has no output function: the state is handed out as-is. (This
is unusual — most modern generators scramble the state before emitting it,
precisely so that seeing an output does not hand over the state. PCG's
"permuted congruential" name refers to exactly that extra step.)

## The trim

${
  remainder === 0
    ? `${outputLength} bytes is a whole number of 4-byte words, so nothing is trimmed on
any pass and this step is a passthrough. Ask for a length that is *not* a
multiple of 4 and the final pass will cut its word short.`
    : `${outputLength} is not a multiple of 4, so the last pass produces
${Math.ceil(outputLength / LCG_WORD_BYTES)} words for only ${outputLength} bytes
of output. This step matches the final word to the width still wanted —
${remainder} byte${remainder === 1 ? "" : "s"} — so the stream ends exactly where
you asked, with nothing padded and nothing spare.`
}

**What is trimmed is the output, never the state.** The next state is taken from
the untrimmed word above; a truncated value fed back would break the recurrence.
Because the fault would only ever show up on a request whose length is not a
multiple of 4, it is the kind of bug that survives a whole test suite.`,
    references: [],
  };
};

/**
 * The ANSI-C variant emits the RAW 32-BIT STATE, where C's `rand()` returns
 * `(state / 65536) % 32768`. A learner will compare the two and find they
 * disagree, so this narration says so outright rather than leaving a
 * discrepancy to be discovered as an apparent bug.
 *
 * Emitting the raw state is the deliberate choice: the top-15-bit extraction
 * IS the C library's workaround for the low-bit weakness, so performing it here
 * would hide the exact defect this variant exists to demonstrate.
 */
const narrEmitAnsiC = (outputLength: number): StepDocumentation => {
  const remainder = outputLength % LCG_WORD_BYTES;
  return {
    name: "Emit the word",
    summary:
      remainder === 0
        ? "Passes the full 4-byte state through — including the low bits C's rand() throws away."
        : `Passes the state through, trimming the final word to ${remainder} byte${remainder === 1 ? "" : "s"}.`,
    detail: `## Output = the whole state

This generator hands out its state unchanged, all 31 bits of it.

**C's \`rand()\` does not.** The standard's sample implementation returns:

\`\`\`c
return (unsigned)(next / 65536) % 32768;
\`\`\`

— the top 15 bits, discarding the bottom 16. So from seed 1 this app shows the
states

\`\`\`
${ANSI_C_OPENING_STATES}, …
\`\`\`

while a C program calling \`rand()\` prints

\`\`\`
${ANSI_C_OPENING_RANDS}, …
\`\`\`

Those are the same numbers: 1103527590 ÷ 65536 = 16838. Nothing here disagrees
with C — you are seeing one step earlier in the pipeline.

## Why show the state instead of matching rand()

Because that division is the *fix*, and applying it would hide the thing worth
seeing. The low 16 bits are discarded precisely because they are bad; keep them
on screen and you can watch them be bad — the last byte of consecutive words
alternates odd, even, odd, even, and no statistics are needed to see it.

## The trim

${
  remainder === 0
    ? `${outputLength} bytes is a whole number of 4-byte words, so nothing is trimmed on
any pass and this step is a passthrough. Ask for a length that is *not* a
multiple of 4 and the final pass will cut its word short.`
    : `${outputLength} is not a multiple of 4, so the last pass produces
${Math.ceil(outputLength / LCG_WORD_BYTES)} words for only ${outputLength} bytes
of output. This step matches the final word to the width still wanted —
${remainder} byte${remainder === 1 ? "" : "s"} — so the stream ends exactly where
you asked, with nothing padded and nothing spare.`
}

**What is trimmed is the output, never the state.** The next state is taken from
the untrimmed word above; a truncated value fed back would break the recurrence.`,
    references: ["ISO/IEC 9899 §7.22.2.2"],
  };
};

// ─── Narration dispatch ───────────────────────────────────────────────────
//
// One switch per role. Written as explicit dispatchers rather than conditionals
// woven through shared prose so that the MINSTD strings above are reachable by
// exactly the same code path they were before the ANSI-C variant existed.

const narrMultiplier = (variant: LcgVariant): StepDocumentation =>
  variant === "ansi-c-lcg" ? narrMultiplierAnsiC : narrMultiplierMinstd(variant);

const narrModulus = (variant: LcgVariant): StepDocumentation =>
  variant === "ansi-c-lcg" ? narrModulusAnsiC : narrModulusMinstd;

const narrState = (variant: LcgVariant): StepDocumentation =>
  variant === "ansi-c-lcg" ? narrStateAnsiC : narrStateMinstd(variant);

const narrEmit = (variant: LcgVariant, outputLength: number): StepDocumentation =>
  variant === "ansi-c-lcg" ? narrEmitAnsiC(outputLength) : narrEmitMinstd(outputLength);

// ─── The spec ─────────────────────────────────────────────────────────────

/** The iterate's header line — the recurrence, written out. */
const iterateLabel = (variant: LcgVariant): string => {
  const { a, c } = LCG_PARAMS[variant];
  return c === 0
    ? `${DISPLAY_NAME[variant]} — x ← ${a}·x mod 2³¹−1`
    : `${DISPLAY_NAME[variant]} — x ← (${a}·x + ${c}) mod 2³¹`;
};

/**
 * Build an LCG spec producing `outputLength` bytes.
 *
 * The two forms differ by exactly two nodes. A multiplicative generator
 * (`c === 0`) runs `mult → modu → state(mod-mul) → emit`; a mixed one inserts an
 * `incr` constant and splits the arithmetic into `prod(mod-mul) → state(add-mod)`.
 * Everything else — the request, the iterate, the seeding, the trim — is shared,
 * which is the honest picture: these are the same generator template under
 * different constants.
 *
 * **The multiplicative branch must stay byte-identical** to what shipped before
 * the mixed form existed, because spec-only saves are byte-stable and feed the
 * URL-share hash. `tests/lcg-kat.test.ts` pins it by hash.
 *
 * @param variant       which published generator to build
 * @param outputLength  bytes of output requested; any positive integer, and
 *                      deliberately need not be a multiple of the 4-byte word
 */
export const buildLcgSpec = (variant: LcgVariant, outputLength: number): CipherSpec => {
  const { a, c, m } = LCG_PARAMS[variant];
  const mixed = isMixedLcg(variant);

  // In the mixed form the multiply is only half the recurrence, so it takes the
  // `prod` id and the `add-mod@1` below becomes the state node. In the
  // multiplicative form the multiply IS the state. Either way `LCG_STATE_ID`
  // names whatever `chainFeedback` should read.
  const productId = mixed ? LCG_PRODUCT_ID : LCG_STATE_ID;

  const children: StepNode[] = [
    {
      kind: "step",
      id: LCG_MULTIPLIER_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(a) },
      narrationOverride: narrMultiplier(variant),
    },
    // The increment exists ONLY in the mixed form — a multiplicative generator
    // does not add zero, it does not add at all, and the trace should not
    // suggest otherwise.
    ...(mixed
      ? [
          {
            kind: "step" as const,
            id: LCG_INCREMENT_ID,
            type: "constant-load@1",
            params: { bytes: wordBytes(c) },
            narrationOverride: narrIncrement,
          },
        ]
      : []),
    {
      kind: "step",
      id: LCG_MODULUS_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(m) },
      narrationOverride: narrModulus(variant),
    },
    {
      // The arithmetic. `chain` is the previous state — bootstrapped from the
      // seed by the iterate's `chainInput`, then advanced by `chainFeedback`
      // below.
      kind: "step",
      id: productId,
      type: "mod-mul@1",
      params: {},
      portInputs: {
        a: port(LCG_ITERATE_ID, "chain"),
        b: port(LCG_MULTIPLIER_ID, "output"),
        modulus: port(LCG_MODULUS_ID, "output"),
      },
      narrationOverride: mixed ? narrProductAnsiC : narrState(variant),
    },
    // The "+ c" that turns multiplicative into mixed. One leaf — which is
    // precisely what the step up from MINSTD to the ANSI C generator costs.
    ...(mixed
      ? [
          {
            kind: "step" as const,
            id: LCG_STATE_ID,
            type: "add-mod@1",
            params: {},
            portInputs: {
              a: port(LCG_PRODUCT_ID, "output"),
              b: port(LCG_INCREMENT_ID, "output"),
              modulus: port(LCG_MODULUS_ID, "output"),
            },
            narrationOverride: narrState(variant),
          },
        ]
      : []),
    {
      // Trims THIS PASS'S OUTPUT to the width of the block the iterate handed
      // us — full 4 bytes on every pass but the last, and only then when the
      // requested length is not a multiple of 4. The state above is untouched.
      kind: "step",
      id: LCG_EMIT_ID,
      type: "truncate-to-reference@1",
      params: {},
      portInputs: {
        input: port(LCG_STATE_ID, "output"),
        reference: port(LCG_ITERATE_ID, "in"),
      },
      narrationOverride: narrEmit(variant, outputLength),
    },
  ];

  return {
    id: `${variant}@1`,
    name: DISPLAY_NAME[variant],
    stateShape: "bytes",
    inputs: {
      // The seed is the generator's only input. Generators are keyless in the
      // symmetric sense, so the key field is zero-width and the UI hides it —
      // the same posture the hash and RSA families take.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    steps: [
      {
        kind: "step",
        id: LCG_REQUEST_ID,
        type: "zero-fill@1",
        params: { byteLength: outputLength },
        narrationOverride: narrRequest(outputLength),
      },
      {
        kind: "iterate",
        id: LCG_ITERATE_ID,
        label: iterateLabel(variant),
        // The request's WIDTH is what drives the loop; its bytes are ignored.
        seedInput: port(LCG_REQUEST_ID, "output"),
        blockByteLength: LCG_WORD_BYTES,
        // Any positive output length is legal, so the final block may be short.
        allowPartialFinalBlock: true,
        // x_0 = the seed, verbatim. No scrambling, no discard — see the file
        // header's note on seeding conventions.
        chainInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        // UNTRIMMED. Read the file header before changing this line.
        chainFeedback: port(LCG_STATE_ID, "output"),
        // TRIMMED — so the stream is exactly `outputLength` bytes long.
        bodyOutput: port(LCG_EMIT_ID, "output"),
        outputPorts: ["out"],
        children,
      },
    ],
    outputFrom: port(LCG_ITERATE_ID, "out"),
  };
};

/**
 * Read the requested output length back out of a built LCG spec (the `request`
 * leaf's `byteLength`). Used when loading a saved or shared document so the
 * app's output-length control lands on the document's value rather than the
 * default — without this, a round-trip silently resets the length.
 *
 * Variant-agnostic by construction: it keys on the request leaf, which every
 * variant carries at the same id in the same position.
 *
 * Mirrors `readShakeOutputLength` in `ciphers/shake.ts`.
 */
export const readLcgOutputLength = (spec: CipherSpec): number | undefined => {
  for (const node of spec.steps) {
    if (node.kind === "step" && node.id === LCG_REQUEST_ID) {
      const len = (node.params as Record<string, unknown>).byteLength;
      if (typeof len === "number" && Number.isInteger(len) && len >= 1) return len;
    }
  }
  return undefined;
};
