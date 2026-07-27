/**
 * ChaCha20 as a cryptographically secure pseudo-random generator — the app's
 * fourth generator, and the one the other three exist to be compared against.
 * `docs/plans/iterative-dancing-ocean.md` Phase P3.
 *
 * ## What this is, and why it is a GENERATOR rather than a cipher
 *
 * The shipped ChaCha20 cipher (`chacha20.ts`) builds a keystream from
 * (key, nonce, counter) and XORs it with a message. The keystream is the whole
 * cipher; the XOR is an afterthought that takes one step.
 *
 * Delete the message and the XOR, and what is left **is already a generator**:
 * a function from a seed to an arbitrarily long stream of bytes. That is not an
 * analogy or a repurposing — it is what a stream cipher literally is, and it is
 * how real CSPRNGs are built. Linux's `getrandom()` and BSD's `arc4random()`
 * both run ChaCha20 in exactly this configuration.
 *
 * So this spec is the ChaCha20 spec with two things removed:
 *
 * ```
 *   cipher:     state → 20 rounds → feed-forward → keystream → ⊕ message → ciphertext
 *   generator:  state → 20 rounds → feed-forward → keystream → output
 *                                                              └── no message, no XOR
 * ```
 *
 * The twenty rounds are not re-implemented here. `buildDoubleRoundGroups` is
 * imported from `chacha20.ts`, so the rounds are the same code, the same node
 * ids and the same shapes — which is what makes the graph view's canonical ARX
 * cell and `<ChaChaQuarterRoundDiagram />` light up for this generator with no
 * work at all. Those surfaces recognize a double round by its WIRING
 * (`core/arx-group.ts`), never by the cipher, and this is the first consumer to
 * prove that from outside `chacha20.ts`.
 *
 * ## The lesson this variant carries
 *
 * The three LCGs demonstrate a defect: their state IS their output, and the
 * recurrence is invertible, so **one output word hands an attacker the entire
 * sequence, forwards and backwards**. Their narration says so repeatedly.
 *
 * This generator is the answer to "what does it take to fix that", and the fix
 * is a specific, pointable step: the feed-forward addition after the rounds
 * (`final-add`). The twenty rounds are built from addition, rotation and XOR
 * and every one of those is reversible — run them backwards and the seed comes
 * out. Adding the pre-round state back in is what destroys the inverse. Scrub to
 * that frame under both families and the difference between "predictable" and
 * "cryptographically secure" is one leaf.
 *
 * The cost is equally visible: an LCG spends 4 or 5 frames per output word, this
 * spends roughly a thousand per 64-byte block. That ratio is the honest reason
 * `rand()` still exists.
 *
 * ──────────────────────────────────────────────────────────────────────────
 * ## Three configuration choices, all of which have a wrong answer
 *
 * **1. The seed arrives through `aux["seed"]`, not through a port.**
 *
 * The generator's seed is its `inputs.plaintext` (the family convention — the
 * field is labelled "seed" and the key field is hidden). But the block function
 * lives INSIDE the iterate, and port flow cannot cross a container scope: the
 * runtime seeds a body's scope with only the iterate's own `in`/`chain` ports,
 * so `$input` is simply not reachable from in there.
 *
 * Aux is the documented cross-scope channel, and `App.tsx` publishes the seed
 * bytes to `aux["seed"]` for every generator, one line beside the one that
 * publishes the IV for CBC. The body then reads it with `aux-load-bytes@1` —
 * structurally the identical leaf ChaCha20 uses to fetch its key, which is the
 * point: to this construction the seed *is* the key.
 *
 * The alternative — carrying the seed on the iterate's chain beside the counter
 * — was rejected: it would put an invariant on the one wire the trace exists to
 * show changing, and it would break the "the counter rides `chain`" story this
 * generator inherits from CTR intact.
 *
 * **2. The nonce is twelve zero bytes, and that is safe HERE only.**
 *
 * In the cipher, reusing a (key, nonce) pair across two messages is
 * catastrophic — the keystreams are identical, and XORing the two ciphertexts
 * cancels the keystream and leaves the plaintexts XORed together. A fixed
 * all-zero nonce would be exactly that bug.
 *
 * A generator has no second message. One seed means one stream, always read from
 * the beginning, so the nonce has no work to do and a constant is honest. The
 * seed is playing the role the (key, nonce) pair plays in the cipher.
 *
 * Note also that an all-zero nonce needs no endianness crossing: reversing the
 * bytes of a zero word gives a zero word, so unlike the seed there is no
 * `permute@1` here. Emitting a provably-identity reversal frame would be noise
 * in a trace whose whole purpose is that every frame means something.
 *
 * **3. The counter starts at 0, not 1.**
 *
 * RFC 8439's §2.4.2 encryption vectors start their counter at 1, and the
 * shipped cipher follows them. A generator has no such convention to match, so
 * it starts at the beginning: block 0.
 *
 * That choice is what makes the default configuration reproduce a PUBLISHED
 * vector on first paint. With an all-zero 32-byte seed this generator emits
 *
 * ```
 * 76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28 …
 * ```
 *
 * which is RFC 8439 Appendix A.1's first test vector for the ChaCha20 block
 * function (key = 0, nonce = 0, block counter = 0) — the same "the app's first
 * impression IS a test vector" property MINSTD gets from seed 1 and AES-128 from
 * FIPS-197 §C.1.
 *
 * An initial-counter off-by-one is the classic ChaCha implementation bug, and
 * this repo has been bitten by the ChaCha-1-vs-Salsa-0 version of it twice, so
 * the value is pinned by `tests/chacha20-csprng-kat.test.ts` against
 * `node:crypto` rather than trusted.
 *
 * ## Verification
 *
 * Unlike the LCGs — which have no live oracle and lean on an ISO conformance
 * value — this generator has the best oracle in the repo. `node:crypto`'s
 * `chacha20` encrypting a buffer of zeros returns its keystream verbatim
 * (`0 ⊕ k === k`), so the app's output is compared byte-for-byte against a
 * different implementation on every requested length. See
 * `tests/chacha20-csprng-kat.test.ts`.
 */

import type { CipherSpec, StepDocumentation, StepNode } from "../core/types";
import { port } from "./block-cipher-core";
import { CHACHA20_BLOCK_BYTES, CHACHA20_CONSTANTS, buildDoubleRoundGroups } from "./chacha20";
import { PRNG_REQUEST_ID } from "./prng-request";

// ─── Constants ────────────────────────────────────────────────────────────

/**
 * The seed width: 32 bytes, because the seed occupies the state's key region
 * and RFC 8439 fixes ChaCha20's key at 256 bits.
 *
 * This is the first generator whose seed is not one machine word, which is why
 * `stores/cipher.ts` carries a per-variant `SEED_BYTES_BY_PRNG` rather than the
 * single `LCG_WORD_BYTES` the family shipped with.
 */
export const CHACHA20_CSPRNG_SEED_BYTES = 32;

/** The nonce region: twelve bytes, all zero. See the file header's point 2. */
const NONCE_BYTES = 12;

// ─── Node ids ─────────────────────────────────────────────────────────────
//
// Exported because the KAT addresses nodes by id, and a silent rename would
// break it in ways the type checker cannot see.

export const CSPRNG_ITERATE_ID = "blocks";
export const CSPRNG_COUNTER_INIT_ID = "counter-init";
export const CSPRNG_SEED_LOAD_ID = "seed-bytes";
export const CSPRNG_STATE_INIT_ID = "state-init";
export const CSPRNG_FINAL_ADD_ID = "final-add";
export const CSPRNG_KEYSTREAM_ID = "keystream";
export const CSPRNG_EMIT_ID = "emit";
export const CSPRNG_ADVANCE_ID = "advance";

/** The aux slot `App.tsx` publishes the generator's seed into. */
export const PRNG_SEED_AUX = "seed";

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * `permute@1` indices reversing the bytes of every 32-bit word — the LE↔BE
 * crossing. Duplicated from `chacha20.ts` rather than exported from it: it is
 * three lines, and widening that file's public surface for it would imply the
 * two specs share more machinery than they do (they share the rounds, and the
 * rounds are the claim worth making).
 */
const wordReverseIndices = (byteLength: number): number[] => {
  const indices: number[] = [];
  for (let w = 0; w < byteLength / 4; w++) {
    indices.push(4 * w + 3, 4 * w + 2, 4 * w + 1, 4 * w);
  }
  return indices;
};

// ─── Narration ────────────────────────────────────────────────────────────

const narrRequest = (outputLength: number): StepDocumentation => {
  const blocks = Math.ceil(outputLength / CHACHA20_BLOCK_BYTES);
  return {
    name: `Request ${outputLength} bytes`,
    summary: "How much output you asked for — and therefore how many blocks the generator runs.",
    detail: `## Nothing here says "how much" except you

A cipher learns how much work to do from its message. A generator has no
message: the seed picks *which* stream, never *how much of it*. So the requested
length has to enter the spec on its own, and this is where it does.

The loop below divides this width by the 64-byte block:

\`\`\`
blocks = ceil(${outputLength} / 64) = ${blocks}
\`\`\`

Each pass runs the **whole** ChaCha20 block function — twenty rounds — to
produce 64 bytes. Compare an LCG, which spends one multiply per four bytes. That
ratio is what security costs here, and it is why the weak generators have not
gone away.

Each pass is handed its own slice of these zeros and ignores it completely; the
bytes are never read. Only the final slice's **width** matters, so the last
block can be trimmed and you get back exactly the number of bytes you asked
for.`,
    references: [],
  };
};

const narrConstants: StepDocumentation = {
  name: "Load the constants",
  summary: 'The four fixed words "expand 32-byte k" that begin every ChaCha20 state.',
  detail: `## The constants

\`\`\`
"expa"  "nd 3"  "2-by"  "te k"
\`\`\`

The first four of the state's sixteen words are always these — for every seed,
every counter, and in the cipher for every message. They spell the ASCII string
\`expand 32-byte k\`.

This is a **nothing-up-my-sleeve number**: a value so obviously arbitrary that
its designer could not plausibly have chosen it to hide a weakness. A constant
that looked random would invite the question "why *that* one?"; an English
sentence does not.

They also do real work here. A quarter of the state is fixed at a value nobody
can influence — not even whoever chooses the seed — so no choice of input can
drive the whole state to a value of an attacker's choosing.

Contrast the LCGs, whose constants are the entire generator and are chosen for
arithmetic properties (a primitive root, an odd increment). These are chosen for
the opposite reason: to be visibly *not* chosen.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrCounterInit: StepDocumentation = {
  name: "Block counter = 0",
  summary: "The generator starts at the beginning of its stream: block zero.",
  detail: `## Starting at zero

The counter is the only part of the state that changes from block to block, and
this is where it starts.

**The cipher starts at 1; this generator starts at 0.** RFC 8439's encryption
test vectors happen to begin their counter at 1, and the ChaCha20 cipher in this
explorer follows them. A generator has no such convention to match — it is
producing a stream from its beginning, so it begins at block 0.

That is not a free choice in general. An initial-counter off-by-one produces a
perfectly plausible stream that simply does not match any other implementation,
and it is the single most common ChaCha bug. Here it is pinned: with an all-zero
seed this generator's first bytes are \`76 b8 e0 ad …\`, which is RFC 8439
Appendix A.1's published block-function vector for key 0, nonce 0, counter 0.

Because the counter is just a number the generator is told, this stream is
**seekable**: to read the thousandth block you set the counter to 1000 and run
the block function once. No generator built on a chained recurrence — an LCG,
or OFB — can do that.`,
  references: ["RFC 8439 §2.3 (ChaCha20 block function)", "RFC 8439 §A.1 (test vector)"],
};

const narrSeedLoad: StepDocumentation = {
  name: "Load the seed",
  summary: "Fetches the 32-byte seed, which occupies the state's key region.",
  detail: `## The seed is the key

ChaCha20's state has a 256-bit region reserved for a key. This generator has no
key — it has a seed — and the seed goes exactly there.

That is not a trick. A stream cipher's keystream is already a function from
(key, nonce, counter) to bytes; calling the key a seed and dropping the message
is the whole difference between the cipher and the generator. Real systems do
precisely this: Linux's \`getrandom()\` and BSD's \`arc4random()\` are ChaCha20
run in this configuration.

**Why the seed arrives through storage rather than a wire.** Everything in this
loop runs inside a container, and a container's contents cannot reach back out
to the generator's input — data flows in through the loop's own ports only. So
the seed is published to a named slot before the loop starts and read back here,
the same way the ChaCha20 cipher fetches its key. Follow the dashed arrow.

**32 bytes, and all of them matter.** Unlike the LCGs — whose 4-byte seed
leaves only 2³² possible streams, a space small enough to search exhaustively on
a laptop — this seed selects one of 2²⁵⁶.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrSeedBe: StepDocumentation = {
  name: "Seed → words",
  summary: "Reads the 32-byte seed as eight 32-bit words, reversing each word's bytes.",
  detail: `## A byte-order boundary

ChaCha20 works on 32-bit words and reads them **little-endian**: the first byte
of each group of four is the word's *lowest* 8 bits, not its highest.

This explorer moves words between steps big-endian, so each group of four bytes
is reversed here. Every byte of the seed is still present and still in its own
word; only the order within each word changes.

There are exactly two such boundaries in this generator — this one and the
keystream on the way out — and nothing between them touches byte order again.
(The cipher has four; this one needs no nonce or counter crossing, because both
are zero here and a reversed zero is a zero.)`,
  references: ["RFC 8439 §2.3"],
};

const narrNonce: StepDocumentation = {
  name: "Nonce = 0",
  summary: "Twelve zero bytes — safe for a generator, and catastrophic for a cipher.",
  detail: `## A constant nonce, on purpose

In the ChaCha20 **cipher** this would be a critical bug. A nonce is a "number
used once", and reusing one across two messages under the same key gives both
the same keystream — XOR the two ciphertexts and the keystream cancels, leaving
the two plaintexts XORed with each other. That is recoverable, and it has broken
real systems.

A **generator** has no second message. One seed means one stream, always read
from its beginning, so there is nothing for a nonce to distinguish and a
constant is the honest choice. The seed alone is doing the job the (key, nonce)
pair does in the cipher.

The distinction is worth holding on to, because it is the sort of thing that
gets copied across a boundary where it stops being true. If you ever wire this
generator's output back into an encryption scheme, the nonce becomes load-bearing
again.`,
  references: ["RFC 8439 §2.3", "RFC 8439 §4 (security considerations)"],
};

const narrStateInit: StepDocumentation = {
  name: "Assemble the state",
  summary: "Constants, seed, counter and nonce concatenated into the 16-word state.",
  detail: `## The 4×4 state

ChaCha20's entire working state is sixteen 32-bit words, conventionally drawn as
a 4×4 matrix, assembled from four regions:

| words | contents |
|---|---|
| 0–3   | the constants \`"expand 32-byte k"\` |
| 4–11  | the 256-bit **seed** |
| 12    | the block counter |
| 13–15 | the nonce (zero here) |

Only word 12 differs between one block and the next. The seed and nonce are
fixed for the whole stream, so every block's state differs from the previous one
in a single word — and the twenty rounds that follow have to turn that one-word
difference into 64 bytes that look unrelated.

That is the property the whole design rests on, and it is worth testing
directly: change the seed by one bit and compare the output. Nothing about it
will resemble what it was.`,
  references: ["RFC 8439 §2.3 (ChaCha20 state)"],
};

const narrFinalAdd: StepDocumentation = {
  name: "Add the original state",
  summary:
    "Adds the pre-round state to the post-round state. THIS is the step that makes the generator unpredictable.",
  detail: `## The one step that separates this from an LCG

\`\`\`
output[i] = initial[i] + mixed[i]   (mod 2³², for each of the 16 words)
\`\`\`

Every LCG in this explorer carries the same warning: its state *is* its output,
and its recurrence is invertible, so anyone who sees one output word knows the
entire sequence — forwards and backwards. That is what "not cryptographically
secure" means, concretely.

**This step is the fix, and it is worth understanding why it is needed at all.**

The twenty rounds above are built from addition, rotation and XOR. Every one of
those operations is reversible. Run the rounds backwards and the state that
entered them comes back out — including the seed sitting in words 4–11. So
without this addition the generator would be *worse* than an LCG: 64 bytes of
output would hand over the seed directly.

Adding the original state back in destroys that. To invert the rounds you would
need the mixed state; to recover the mixed state from the output you would need
the initial state — which is the secret you were trying to find. The function
becomes one-way, and one-way is the whole difference between a generator you can
predict and one you cannot.

The same trick — mix reversibly, then add the input back — is what makes SHA-2's
compression function a hash rather than a permutation. Scrub between this frame
and an LCG's \`x ← a·x mod m\` frame: those two steps are the entire distance
between the two families.`,
  references: ["RFC 8439 §2.3 (ChaCha20 block function)"],
};

const narrKeystream: StepDocumentation = {
  name: "Serialize the block",
  summary: "Writes the 16 finished words out as 64 little-endian bytes of random output.",
  detail: `## Out to bytes

The second and last byte-order boundary. The sixteen finished words are written
out four bytes at a time, lowest byte first, giving 64 bytes.

In the ChaCha20 cipher these bytes are the keystream, and a message would meet
them at an XOR in the next step. Here there is no message and no XOR: **these
bytes are the output**. That is the entire difference between the cipher and the
generator, and this is where you can see it — the trace simply stops after this
where the cipher's continues.

Nothing about these bytes depended on anything but the seed and the counter, so
this block could have been computed in any order, or in parallel with any other.`,
  references: ["RFC 8439 §2.3 (ChaCha20 block function)"],
};

const narrEmit = (outputLength: number): StepDocumentation => {
  const remainder = outputLength % CHACHA20_BLOCK_BYTES;
  return {
    name: "Emit this block",
    summary:
      remainder === 0
        ? "Passes the 64-byte block through as this pass's output."
        : `Passes the block through, trimming the final one to ${remainder} byte${remainder === 1 ? "" : "s"}.`,
    detail: `## Exactly as much as you asked for

${
  remainder === 0
    ? `${outputLength} bytes is a whole number of 64-byte blocks, so nothing is trimmed on
any pass and this step is a passthrough. Ask for a length that is *not* a
multiple of 64 and the final pass will cut its block short.`
    : `${outputLength} is not a multiple of 64, so the last pass generates a full
64-byte block for only ${remainder} byte${remainder === 1 ? "" : "s"} of
remaining output. This step cuts it to the width still wanted, so the stream ends
exactly where you asked — no padding, ever.`
}

**The discarded bytes are simply never used.** They are not secret and nothing is
hiding them; they are the tail of a block that had to be computed whole because
the block function has no smaller unit. Nor are they wasted in any way that
matters: the next block is a different counter value and an entirely different
64 bytes.

Note what is NOT trimmed — the counter. It advances by one whole step regardless,
because blocks are counted, not bytes.`,
    references: ["RFC 8439 §2.4"],
  };
};

const narrAdvance: StepDocumentation = {
  name: "Advance the counter",
  summary: "Adds one to the block counter so the next block is different.",
  detail: `## Counting blocks

\`\`\`
counter_{i+1} = counter_i + 1
\`\`\`

The counter is the only input to the block function that changes, and this is
what changes it. Without it every block would be identical and the generator
would emit the same 64 bytes forever.

Notice where this reads from: the counter **as it arrived**, in parallel with the
block function rather than downstream of it. Nothing about block *i+1* depends on
the output of block *i*. That independence is what makes the stream seekable, and
it is the structural opposite of an LCG, where each value is computed from the
previous one and block 1000 can only be reached by taking 1000 steps.

The counter is 32 bits, so one seed yields 2³² blocks — 256 GiB — before it would
wrap and repeat. Past that a real system reseeds.`,
  references: ["RFC 8439 §2.4"],
};

// ─── The spec ─────────────────────────────────────────────────────────────

/**
 * Build the ChaCha20-CSPRNG spec producing `outputLength` bytes.
 *
 * Structurally this is `chacha20.ts`'s spec with the message removed: the
 * iterate is driven by a `zero-fill@1` request rather than by the plaintext,
 * the state's key region is fed from `aux["seed"]` rather than `aux["key"]`,
 * the nonce is a constant, and the body ends at the serialized keystream
 * instead of continuing into an XOR.
 *
 * @param outputLength bytes of output requested; any positive integer, and
 *                     deliberately need not be a multiple of the 64-byte block
 */
export const buildChaCha20CsprngSpec = (outputLength: number): CipherSpec => {
  const counterIn = port(CSPRNG_ITERATE_ID, "chain");

  const body: StepNode[] = [
    // ── The four state regions ──────────────────────────────────────────
    // Loaded INSIDE the loop because port flow cannot cross the container
    // scope — and honest for the same reason it is in the cipher: ChaCha20 has
    // no key schedule, so the seed really does enter every block afresh.
    {
      kind: "step",
      id: "constants",
      type: "constant-load@1",
      params: { bytes: [...CHACHA20_CONSTANTS] },
      narrationOverride: narrConstants,
    },
    {
      kind: "step",
      id: CSPRNG_SEED_LOAD_ID,
      type: "aux-load-bytes@1",
      params: { auxName: PRNG_SEED_AUX, byteLength: CHACHA20_CSPRNG_SEED_BYTES },
      narrationOverride: narrSeedLoad,
    },
    {
      kind: "step",
      id: "seed-be",
      type: "permute@1",
      params: { indices: wordReverseIndices(CHACHA20_CSPRNG_SEED_BYTES) },
      portInputs: { input: port(CSPRNG_SEED_LOAD_ID, "output") },
      narrationOverride: narrSeedBe,
    },
    {
      // No `permute@1` after this: a reversed zero word is a zero word, so an
      // endianness crossing here would be a provably-identity frame.
      kind: "step",
      id: "nonce",
      type: "constant-load@1",
      params: { bytes: Array.from({ length: NONCE_BYTES }, () => 0) },
      narrationOverride: narrNonce,
    },
    // constants ‖ seed ‖ counter ‖ nonce — the RFC's four regions, in order.
    {
      kind: "step",
      id: CSPRNG_STATE_INIT_ID,
      type: "concat@1",
      params: { inputCount: 4 },
      portInputs: {
        input0: port("constants", "output"),
        input1: port("seed-be", "output"),
        input2: counterIn,
        input3: port("nonce", "output"),
      },
      narrationOverride: narrStateInit,
    },
  ];

  // ── Ten double rounds — the SAME builder the cipher uses ──────────────
  const rounds = buildDoubleRoundGroups(port(CSPRNG_STATE_INIT_ID, "output"));
  body.push(...rounds.nodes);

  body.push(
    {
      kind: "step",
      id: CSPRNG_FINAL_ADD_ID,
      type: "add-mod-32@1",
      params: { inputCount: 2 },
      portInputs: {
        operand0: rounds.output,
        operand1: port(CSPRNG_STATE_INIT_ID, "output"),
      },
      narrationOverride: narrFinalAdd,
    },
    {
      kind: "step",
      id: CSPRNG_KEYSTREAM_ID,
      type: "permute@1",
      params: { indices: wordReverseIndices(CHACHA20_BLOCK_BYTES) },
      portInputs: { input: port(CSPRNG_FINAL_ADD_ID, "output") },
      narrationOverride: narrKeystream,
    },
    {
      // Trims THIS PASS'S OUTPUT to the width of the block the iterate handed
      // us — full 64 bytes on every pass but the last. The counter below is
      // untouched by the trim: blocks are counted, not bytes.
      kind: "step",
      id: CSPRNG_EMIT_ID,
      type: "truncate-to-reference@1",
      params: {},
      portInputs: {
        input: port(CSPRNG_KEYSTREAM_ID, "output"),
        reference: port(CSPRNG_ITERATE_ID, "in"),
      },
      narrationOverride: narrEmit(outputLength),
    },
    {
      // Reads the counter AS IT ARRIVED, parallel to the block function — which
      // is why the blocks are independent and the stream is seekable.
      kind: "step",
      id: CSPRNG_ADVANCE_ID,
      type: "increment-counter@1",
      params: {},
      portInputs: { counter: counterIn },
      narrationOverride: narrAdvance,
    },
  );

  return {
    id: "chacha20-csprng@1",
    name: "ChaCha20 CSPRNG",
    stateShape: "bytes",
    inputs: {
      // The seed is the generator's only input. It rides `plaintext` (the PRNG
      // family convention — the field is labelled "seed") and the key is
      // zero-width so the UI hides that field. `App.tsx` also publishes these
      // bytes to `aux["seed"]`, which is how they reach inside the loop.
      plaintext: { shape: "bytes" },
      key: { byteLength: 0 },
    },
    steps: [
      {
        kind: "step",
        id: PRNG_REQUEST_ID,
        type: "zero-fill@1",
        params: { byteLength: outputLength },
        narrationOverride: narrRequest(outputLength),
      },
      {
        // Big-endian zero — the counter travels the ports big-endian (the
        // convention the rounds are written in) and is reversed only when the
        // whole state is serialized.
        kind: "step",
        id: CSPRNG_COUNTER_INIT_ID,
        type: "constant-load@1",
        params: { bytes: [0, 0, 0, 0] },
        narrationOverride: narrCounterInit,
      },
      {
        kind: "iterate",
        id: CSPRNG_ITERATE_ID,
        label: "ChaCha20 blocks (keystream = output)",
        // The request's WIDTH is what drives the loop; its bytes are ignored.
        seedInput: port(PRNG_REQUEST_ID, "output"),
        blockByteLength: CHACHA20_BLOCK_BYTES,
        // Any positive output length is legal, so the final block may be short.
        allowPartialFinalBlock: true,
        chainInput: port(CSPRNG_COUNTER_INIT_ID, "output"),
        chainFeedback: port(CSPRNG_ADVANCE_ID, "output"),
        bodyOutput: port(CSPRNG_EMIT_ID, "output"),
        outputPorts: ["out"],
        children: body,
      },
    ],
    outputFrom: port(CSPRNG_ITERATE_ID, "out"),
  };
};
