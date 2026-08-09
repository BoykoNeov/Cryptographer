/**
 * MT19937 state initialization — `init_genrand`, as one frame.
 *
 * Expands a 32-bit seed into the generator's full 624-word internal state
 * (Matsumoto & Nishimura 1998; the reference implementation `mt19937ar.c`,
 * function `init_genrand`):
 *
 * ```
 * mt[0] = s
 * mt[i] = 1812433253 · (mt[i−1] ^ (mt[i−1] >> 30)) + i        for i = 1 … 623
 * ```
 *
 * all arithmetic mod 2³². One input port `input` (4 bytes, big-endian seed),
 * one output port `output` (2496 bytes = 624 big-endian words).
 *
 * ## Why this is one frame and not 623
 *
 * This is a **deliberate monolith** — the escape hatch this repo has taken
 * twice before, for `blowfish.key-schedule@1` (which runs the cipher on
 * itself 521 times) and `twofish.h-expand@1`. Unlike those two, the reason
 * here is not merely volume: the recurrence is **structurally inexpressible**
 * as a port-mode `iterate`.
 *
 * Look at the `+ i`. That is the loop index, and **no leaf in this app
 * produces the iteration index** — the runtime does not expose one to a
 * body. Every other unrolled-or-looped construction in the app either needs
 * no counter (the LCGs, OFB, the sponge) or has one built at spec time by an
 * unroller (SHA-256's round constants, RSA's ladder rungs). Neither escape
 * applies to a 624-step loop whose every step needs its own index and whose
 * spec must stay a fixed size.
 *
 * So the honest options were one frame with a narrator that shows the real
 * numbers, or 623 spec nodes. The plan
 * (`docs/plans/validated-growing-dongarra.md`) took the first, and the frame
 * carries value-prose disclosure rows rather than a static description — the
 * `twofish.h-expand@1` posture.
 *
 * ## The seeding convention, and the family divergence
 *
 * `lcg.ts`'s header states the PRNG family's convention as "x_0 is the seed
 * verbatim, no scrambling, no `init_by_array`, no discarded warm-up". **This
 * generator cannot honor that**, and the difference is not incidental: an
 * LCG's state IS one word, so a one-word seed can simply be it, while
 * MT19937's state is 624 words and a 32-bit seed cannot fill it. The
 * expansion above is mandatory, published, and part of the generator's
 * identity. Two consequences worth stating plainly:
 *
 *  - **Only 2³² of the 2^19937 possible states are reachable** from a 32-bit
 *    seed. The period is astronomically long; the number of distinct
 *    sequences you can actually ask for is not.
 *  - **`init_genrand(s)` and `init_by_array([s])` produce different
 *    streams**, and real libraries disagree about which they use for an
 *    integer seed — CPython and numpy's modern `Generator` scramble, while
 *    C++'s `std::mt19937(s)` and numpy's legacy `RandomState(s)` call
 *    `init_genrand`. This app ships `init_genrand` ONLY. That is the same
 *    class of trap as ChaCha20's counter starting at 1 while Salsa20's
 *    starts at 0: a mismatched convention yields a stream that is perfectly
 *    self-consistent and matches nothing else in the world.
 *
 * The multiplier 1812433253 is Knuth's, from *The Art of Computer
 * Programming* Vol. 2 §3.3.4 — it is itself an LCG multiplier, which makes
 * this initializer a small linear congruential generator used to seed a much
 * better one. The `^ (mt[i−1] >> 30)` term exists because a plain LCG would
 * leave the high bits of consecutive words highly correlated; XORing in the
 * top two bits before multiplying is what breaks that up.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";

/** Words in MT19937's state vector. The `n` of the published parameter set. */
export const MT_N = 624;

/** The state's width in bytes — 624 words × 4. */
export const MT_STATE_BYTES = MT_N * 4;

/** Knuth's LCG multiplier (TAOCP Vol. 2 §3.3.4), used by `init_genrand`. */
export const MT_INIT_MULTIPLIER = 1812433253;

/**
 * `init_genrand` in plain numbers — the reference form, sharing nothing with
 * the port machinery. Exported so the KAT can drive it directly for long runs
 * (reaching the 10000th output through the traced runtime would mean ~10000
 * iterations of frames).
 *
 * @param seed the 32-bit seed
 * @returns the 624-word state, as unsigned 32-bit numbers
 */
export const initGenrand = (seed: number): Uint32Array => {
  const mt = new Uint32Array(MT_N);
  mt[0] = seed >>> 0;
  for (let i = 1; i < MT_N; i++) {
    const prev = mt[i - 1] as number;
    // Math.imul is the only way to get a correct 32-bit product in JS: a
    // plain `*` on two 32-bit values exceeds 2^53 and silently loses low
    // bits — which is the classic implementation bug in this family, and one
    // that still produces random-LOOKING output.
    mt[i] = (Math.imul(MT_INIT_MULTIPLIER, prev ^ (prev >>> 30)) + i) >>> 0;
  }
  return mt;
};

/** Encode a word array as big-endian bytes. The app's port convention. */
export const wordsToBytesBE = (words: Uint32Array): Uint8Array => {
  const out = new Uint8Array(words.length * 4);
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as number;
    out[i * 4] = (w >>> 24) & 0xff;
    out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff;
    out[i * 4 + 3] = w & 0xff;
  }
  return out;
};

/** Decode big-endian bytes back into a word array. */
export const bytesToWordsBE = (bytes: Uint8Array): Uint32Array => {
  const out = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < out.length; i++) {
    out[i] =
      (((bytes[i * 4] as number) << 24) |
        ((bytes[i * 4 + 1] as number) << 16) |
        ((bytes[i * 4 + 2] as number) << 8) |
        (bytes[i * 4 + 3] as number)) >>>
      0;
  }
  return out;
};

const readParams = (params: Json): void => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("mt19937.seed: params must be an object");
  }
};

// ─── Port contract + executor ─────────────────────────────────────────────

export const mt19937SeedPortContract: PortContract = {
  // Both widths are fixed by the algorithm, so both are static: a 32-bit seed
  // in, the whole state out. Nothing here is polymorphic in the way the
  // generic primitives are.
  inputs: new Map([["input", { layout: "raw", byteLength: 4 }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: MT_STATE_BYTES }]]),
};

export const mt19937Seed: PortedExecutor = (inputs, params, _ctx) => {
  readParams(params);
  const seedBytes = inputs.get("input");
  if (seedBytes === undefined) {
    throw new Error("mt19937.seed: missing required input port 'input'");
  }
  if (seedBytes.length !== 4) {
    throw new Error(
      `mt19937.seed: seed must be exactly 4 bytes (one 32-bit word), got ${seedBytes.length}`,
    );
  }
  const seed =
    (((seedBytes[0] as number) << 24) |
      ((seedBytes[1] as number) << 16) |
      ((seedBytes[2] as number) << 8) |
      (seedBytes[3] as number)) >>>
    0;
  return new Map([["output", wordsToBytesBE(initGenrand(seed))]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const mt19937SeedDoc: StepDocumentation = {
  name: "Initialize the state",
  summary:
    "Expands the 32-bit seed into MT19937's 624-word internal state, using Knuth's small LCG.",
  detail: `# init_genrand — filling 19,937 bits from 32

MT19937's state is **624 words**, and the seed is one. Something has to
manufacture the other 623, and this step is that something:

\`\`\`
mt[0] = seed
mt[i] = 1812433253 · (mt[i−1] ^ (mt[i−1] >> 30)) + i     (mod 2³²)
\`\`\`

That recurrence is itself a **linear congruential generator** — the family
this app's other generators belong to, and one nobody would use for
randomness today. It is used here for a job it *is* good enough for:
spreading one word's worth of information over the state so the twist has
something non-degenerate to work on.

The multiplier is Knuth's (TAOCP Vol. 2 §3.3.4). The \`^ (mt[i−1] >> 30)\`
term matters: a plain LCG leaves the high bits of consecutive words strongly
correlated, so the top two bits are folded down into the multiply to break
that up.

## What this step costs you, permanently

Only **2³² distinct states** are reachable from a 32-bit seed, out of
2^19937. The period of the resulting sequence is astronomical; the number of
*different* sequences you can ask for is about four billion. If a program
seeds from the clock, an attacker's search space is not the state space — it
is the set of plausible timestamps.

## Why one frame

Every other loop in this app is a visible \`iterate\`. This one cannot be:
the \`+ i\` term is the **loop index**, and no element in this app produces
one. A body only ever receives its own block of data and the value carried
between iterations. So the choice was one frame with real numbers in its
narration, or 623 nodes in the spec — and 623 nodes would not have been more
honest, only longer.

## Seeding conventions differ, and it matters

\`init_genrand(s)\` is **not** the only way MT19937 gets seeded in the wild.
The reference implementation also ships \`init_by_array\`, which CPython's
\`random\` and numpy's modern generators use for integer seeds, and it
produces an entirely different stream from the same number.

This app implements \`init_genrand\` only — the convention of C++'s
\`std::mt19937\` and numpy's legacy \`RandomState\`. A generator seeded under
the wrong convention produces output that is perfectly self-consistent,
passes every statistical test, and matches no other implementation on
earth.`,
  params: new Map(),
  references: [
    "Matsumoto & Nishimura (1998), ACM TOMACS 8(1) §2",
    "mt19937ar.c — the reference implementation, function init_genrand()",
    "Knuth, TAOCP Vol. 2 §3.3.4 — the multiplier 1812433253",
    "ISO/IEC 14882 §rand.predef — std::mt19937 and its default_seed of 5489",
  ],
};
