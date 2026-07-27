/**
 * MINSTD — the multiplicative congruential generator (Lehmer, 1951;
 * Park & Miller, 1988). The app's first pseudo-random generators.
 * `docs/plans/iterative-dancing-ocean.md` Phase P1.
 *
 * ## The whole algorithm
 *
 * ```
 * x_{i+1} = a · x_i mod m        m = 2³¹ − 1 (a Mersenne prime)
 * ```
 *
 * That is it. There is no key schedule, no round function, no S-box — one
 * multiply and one remainder, repeated. Two multipliers ship, and they are the
 * two the C++ standard names:
 *
 * | variant         | a     | provenance |
 * |-----------------|-------|------------|
 * | `minstd-rand0`  | 16807 | Lehmer's original; Park & Miller's 1988 "minimal standard" |
 * | `minstd-rand`   | 48271 | Park, Miller & Stockmeyer's 1993 revision, better spectral behaviour |
 *
 * ## Why a generator this weak is the most valuable object in the app
 *
 * Every cipher here consumes randomness it does not produce, and the question
 * "where did those bytes come from" has ended more real cryptosystems than any
 * weakness in a round function. MINSTD is the shortest honest answer to "what
 * does a generator actually do", and — critically — it is weak in ways a learner
 * can *watch* rather than take on faith.
 *
 * The multiplier, the modulus, and (in the mixed form, Phase P2) the increment
 * are ordinary `constant-load@1` params. Edit them in place and the trace
 * re-runs. Two experiments worth doing, both visible within a handful of frames:
 *
 *  - **Set the multiplier to an even number.** With a prime modulus this wrecks
 *    the period; with a power-of-two modulus (P2's ANSI-C variant) it does
 *    something far more legible — the low bits of every output collapse to a
 *    fixed pattern, because a factor of 2 in `a` can never be undone by a
 *    modulus that is itself a power of 2. This is the reason real code never
 *    takes an LCG's low bits.
 *  - **Set the seed to 0.** `0` is a fixed point of `x ← a·x mod m`: the
 *    generator emits zeros forever. A generator whose entire output is decided
 *    by one badly-chosen starting value is the point.
 *
 * ## Structure of the spec
 *
 * ```
 *   $input (the seed)  ──────────────────────────┐
 *   request  zero-fill@1 { byteLength: N }       │  (its WIDTH sets the count)
 *      │                                         │
 *      └─► iterate "words"  blockByteLength 4  ◄──┘ chainInput = seed
 *              mult   constant-load@1  a         ← editable
 *              modu   constant-load@1  m         ← editable
 *              state  mod-mul@1 (chain · mult mod modu)
 *              emit   truncate-to-reference@1 (state, ref = this block's width)
 *          chainFeedback = state.output   (UNTRIMMED — see below)
 *          bodyOutput    = emit.output    (TRIMMED)
 * ```
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
 * **Seeding convention, written down deliberately.** `x_0` is the seed exactly
 * as supplied, with no scrambling, no `init_by_array`, no discard of leading
 * outputs; the first emitted word is `a · seed mod m`. Both conformance values
 * above are under seed = 1. Recording this matters more than it looks: PRNGs
 * differ from each other mainly in how they *seed*, and a mismatched convention
 * produces a stream that is perfectly self-consistent and matches nothing else
 * in the world — the same failure class as ChaCha20's counter starting at 1
 * while Salsa20's starts at 0.
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { INPUT_SOURCE_ID, INPUT_SOURCE_PORT } from "../core/types";
import { port } from "./block-cipher-core";

// ─── Variants ─────────────────────────────────────────────────────────────

/** The two multipliers the C++ standard names. Both share the modulus. */
export type McgVariant = "minstd-rand0" | "minstd-rand";

/** m = 2³¹ − 1 = 2147483647, a Mersenne prime. Shared by both variants: it is
 *  the modulus's primality that makes the period the full m − 1. */
export const MINSTD_MODULUS = 0x7fffffff;

/** Per-variant multiplier `a`. */
export const MCG_MULTIPLIER: Record<McgVariant, number> = {
  "minstd-rand0": 16807, // Lehmer 1951 / Park–Miller 1988
  "minstd-rand": 48271, // Park–Miller–Stockmeyer 1993
};

/** The generator's word width in bytes. The modulus fits in 31 bits, so every
 *  state value and every emitted word is 4 bytes big-endian. */
export const MCG_WORD_BYTES = 4;

/** Seed width — one word. */
export const MCG_SEED_BYTES = MCG_WORD_BYTES;

const DISPLAY_NAME: Record<McgVariant, string> = {
  "minstd-rand0": "MINSTD (minstd_rand0)",
  "minstd-rand": "MINSTD (minstd_rand)",
};

// ─── Node ids ─────────────────────────────────────────────────────────────
//
// Exported because both the KAT and `readMcgOutputLength` address nodes by id,
// and a silent rename would break them in ways a type checker cannot see.

export const MCG_REQUEST_ID = "request";
export const MCG_ITERATE_ID = "words";
export const MCG_MULTIPLIER_ID = "mult";
export const MCG_MODULUS_ID = "modu";
export const MCG_STATE_ID = "state";
export const MCG_EMIT_ID = "emit";

// ─── Helpers ──────────────────────────────────────────────────────────────

/** Encode a non-negative integer as `MCG_WORD_BYTES` big-endian bytes, as a
 *  plain number array (the shape `constant-load@1`'s `bytes` param wants). */
const wordBytes = (value: number): number[] => [
  (value >>> 24) & 0xff,
  (value >>> 16) & 0xff,
  (value >>> 8) & 0xff,
  value & 0xff,
];

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
words = ceil(${outputLength} / 4) = ${Math.ceil(outputLength / MCG_WORD_BYTES)}
\`\`\`

Each pass is handed its own 4-byte slice of these zeros and **ignores it
completely** — a generator builds its next value from its own state and nothing
else. The single exception is the last slice when the length does not divide
evenly: its width is read, so the final word can be trimmed and you get back
exactly the number of bytes you asked for.`,
  references: [],
});

const narrMultiplier = (variant: McgVariant): StepDocumentation => {
  const a = MCG_MULTIPLIER[variant];
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

const narrModulus: StepDocumentation = {
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

const narrState = (variant: McgVariant): StepDocumentation => ({
  name: "x ← a · x mod m",
  summary: `The entire generator: multiply the current state by ${MCG_MULTIPLIER[variant]}, take the remainder mod 2³¹ − 1.`,
  detail: `## The recurrence

\`\`\`
x_{i+1} = ${MCG_MULTIPLIER[variant]} · x_i mod 2147483647
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

\`${MCG_MULTIPLIER[variant]} · x\` overflows 32 bits for almost every state. This
step computes the exact product before reducing, so no bits are lost. Doing it
the other way round — letting the product wrap and then reducing — silently
produces a different, much worse sequence, and is a classic implementation bug in
this family.`,
  references: ["ISO/IEC 14882 §rand.predef"],
});

const narrEmit = (outputLength: number): StepDocumentation => {
  const remainder = outputLength % MCG_WORD_BYTES;
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
${Math.ceil(outputLength / MCG_WORD_BYTES)} words for only ${outputLength} bytes
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

// ─── The spec ─────────────────────────────────────────────────────────────

/**
 * Build a MINSTD spec producing `outputLength` bytes.
 *
 * @param variant       which published multiplier to use
 * @param outputLength  bytes of output requested; any positive integer, and
 *                      deliberately need not be a multiple of the 4-byte word
 */
export const buildMcgSpec = (variant: McgVariant, outputLength: number): CipherSpec => {
  const children: StepNode[] = [
    {
      kind: "step",
      id: MCG_MULTIPLIER_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(MCG_MULTIPLIER[variant]) },
      narrationOverride: narrMultiplier(variant),
    },
    {
      kind: "step",
      id: MCG_MODULUS_ID,
      type: "constant-load@1",
      params: { bytes: wordBytes(MINSTD_MODULUS) },
      narrationOverride: narrModulus,
    },
    {
      // The one line of arithmetic in the whole cipher. `chain` is the
      // previous state — bootstrapped from the seed by the iterate's
      // `chainInput`, then advanced by `chainFeedback` below.
      kind: "step",
      id: MCG_STATE_ID,
      type: "mod-mul@1",
      params: {},
      portInputs: {
        a: port(MCG_ITERATE_ID, "chain"),
        b: port(MCG_MULTIPLIER_ID, "output"),
        modulus: port(MCG_MODULUS_ID, "output"),
      },
      narrationOverride: narrState(variant),
    },
    {
      // Trims THIS PASS'S OUTPUT to the width of the block the iterate handed
      // us — full 4 bytes on every pass but the last, and only then when the
      // requested length is not a multiple of 4. The state above is untouched.
      kind: "step",
      id: MCG_EMIT_ID,
      type: "truncate-to-reference@1",
      params: {},
      portInputs: {
        input: port(MCG_STATE_ID, "output"),
        reference: port(MCG_ITERATE_ID, "in"),
      },
      narrationOverride: narrEmit(outputLength),
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
        id: MCG_REQUEST_ID,
        type: "zero-fill@1",
        params: { byteLength: outputLength },
        narrationOverride: narrRequest(outputLength),
      },
      {
        kind: "iterate",
        id: MCG_ITERATE_ID,
        label: `${DISPLAY_NAME[variant]} — x ← ${MCG_MULTIPLIER[variant]}·x mod 2³¹−1`,
        // The request's WIDTH is what drives the loop; its bytes are ignored.
        seedInput: port(MCG_REQUEST_ID, "output"),
        blockByteLength: MCG_WORD_BYTES,
        // Any positive output length is legal, so the final block may be short.
        allowPartialFinalBlock: true,
        // x_0 = the seed, verbatim. No scrambling, no discard — see the file
        // header's note on seeding conventions.
        chainInput: port(INPUT_SOURCE_ID, INPUT_SOURCE_PORT),
        // UNTRIMMED. Read the file header before changing this line.
        chainFeedback: port(MCG_STATE_ID, "output"),
        // TRIMMED — so the stream is exactly `outputLength` bytes long.
        bodyOutput: port(MCG_EMIT_ID, "output"),
        outputPorts: ["out"],
        children,
      },
    ],
    outputFrom: port(MCG_ITERATE_ID, "out"),
  };
};

/**
 * Read the requested output length back out of a built MINSTD spec (the
 * `request` leaf's `byteLength`). Used when loading a saved or shared document
 * so the app's output-length control lands on the document's value rather than
 * the default — without this, a round-trip silently resets the length.
 *
 * Mirrors `readShakeOutputLength` in `ciphers/shake.ts`.
 */
export const readMcgOutputLength = (spec: CipherSpec): number | undefined => {
  for (const node of spec.steps) {
    if (node.kind === "step" && node.id === MCG_REQUEST_ID) {
      const len = (node.params as Record<string, unknown>).byteLength;
      if (typeof len === "number" && Number.isInteger(len) && len >= 1) return len;
    }
  }
  return undefined;
};
